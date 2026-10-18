// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The sound device of the screen: a virtio-snd device with one playback stream, whose samples
//! go to the renderer (the sink plays them) on the GPU device's connection as `SP_AUDIO`.
//!
//! It takes the place of the QEMU source's Intel HDA card on QEMU's `none` backend: the stream
//! is played at playback speed by a timer of 5 ms (the trial's `timer-period=5000`), with the
//! same rate control as that backend (`audio_rate_get_bytes` in QEMU's `audio/audio.c`: the bytes
//! due since the start, less those played, at most what the guest has queued; reset when more
//! than 65536 frames are due). Each 5 ms the bytes played are sent as one unreliable message,
//! as the QEMU source sends what its backend "plays". A buffer of the guest is returned when
//! its last byte has been played, so the guest's clock runs at playback speed. The guest's
//! bytes are read when they are played: the driver queues regions of its ring buffer that the
//! program fills while earlier ones play.
//!
//! The stream offers only what the sink plays and the trial used: 48 kHz, 2 channels, signed
//! 16 bit little endian. No jacks; one channel map (front left, front right).

use std::collections::VecDeque;
use std::fmt::Debug;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use event_manager::{EventOps, Events, MutEventSubscriber};
use serde::{Deserialize, Serialize};
use utils::time::TimerFd;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::Gpu;
use super::link::now_us;
use crate::devices::virtio::ActivateError;
use crate::devices::virtio::device::{ActiveState, DeviceState, VirtioDevice, VirtioDeviceType};
use crate::devices::virtio::generated::virtio_config::VIRTIO_F_VERSION_1;
use crate::devices::virtio::persist::{PersistError as VirtioStateError, VirtioDeviceState};
use crate::devices::virtio::queue::{
    FIRECRACKER_MAX_QUEUE_SIZE, InvalidAvailIdx, Queue, QueueConfig, QueueError,
};
use crate::devices::virtio::transport::{VirtioInterrupt, VirtioInterruptType};
use crate::impl_device_type;
use crate::logger::{error, warn};
use crate::snapshot::Persist;
use crate::vstate::memory::{Bytes, GuestAddress, GuestMemoryMmap};

pub const SOUND_DEV_ID: &str = "gpu-sound";

const CONTROL_QUEUE: usize = 0;
const EVENT_QUEUE: usize = 1;
const TX_QUEUE: usize = 2;
const RX_QUEUE: usize = 3;
const NUM_QUEUES: usize = 4;

// virtio-snd (virtio 1.2, 5.14), `include/uapi/linux/virtio_snd.h`.
const R_JACK_INFO: u32 = 1;
const R_JACK_REMAP: u32 = 2;
const R_PCM_INFO: u32 = 0x0100;
const R_PCM_SET_PARAMS: u32 = 0x0101;
const R_PCM_PREPARE: u32 = 0x0102;
const R_PCM_RELEASE: u32 = 0x0103;
const R_PCM_START: u32 = 0x0104;
const R_PCM_STOP: u32 = 0x0105;
const R_CHMAP_INFO: u32 = 0x0200;
pub(crate) const S_OK: u32 = 0x8000;
pub(crate) const S_BAD_MSG: u32 = 0x8001;
pub(crate) const S_NOT_SUPP: u32 = 0x8002;
const D_OUTPUT: u8 = 0;
pub(crate) const PCM_FMT_S16: u8 = 5;
pub(crate) const PCM_RATE_48000: u8 = 7;
const CHMAP_FL: u8 = 3;
const CHMAP_FR: u8 = 4;
/// `struct virtio_snd_pcm_info`.
const PCM_INFO_LEN: usize = 32;
/// `struct virtio_snd_chmap_info`.
const CHMAP_INFO_LEN: usize = 24;
/// `struct virtio_snd_pcm_status`: le32 status, le32 latency_bytes.
const PCM_STATUS_LEN: usize = 8;
/// `struct virtio_snd_pcm_xfer`: le32 stream_id, before the samples.
const PCM_XFER_LEN: usize = 4;

pub(crate) const RATE: u32 = 48_000;
pub(crate) const CHANNELS: u32 = 2;
const CHANNELS_U8: u8 = 2;
const FRAME: u64 = 4;
const BYTES_PER_SECOND: u64 = RATE as u64 * FRAME;
/// The pacing period, as the trial's `-audiodev none,timer-period=5000`.
pub(crate) const PERIOD: Duration = Duration::from_millis(5);
/// More frames due than this: the rate control starts again (QEMU's `audio_rate_peek_bytes`).
const MAX_DUE_FRAMES: u64 = 65536;
/// The largest control request taken.
const MAX_CTRL: usize = 4096;

/// Where the samples go: the GPU device's connection, or a test.
pub trait AudioOut: Send + Debug {
    /// `samples` were played now; `short` bytes were due but the guest had not queued them.
    fn audio(&mut self, rate: u32, channels: u32, samples: &[u8], short: u64);
}

/// The GPU device's connection.
#[derive(Debug)]
pub struct GpuAudioOut(pub Arc<Mutex<Gpu>>);

impl AudioOut for GpuAudioOut {
    fn audio(&mut self, rate: u32, channels: u32, samples: &[u8], short: u64) {
        self.0
            .lock()
            .expect("Poisoned lock")
            .send_audio(rate, channels, samples, short);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamState {
    /// No parameters set yet, or released.
    Idle,
    /// Parameters set.
    Set,
    Prepared,
    Running,
    Stopped,
}

/// A buffer of samples of the guest, played from `next`.
#[derive(Debug)]
struct TxBuf {
    head: u16,
    /// The readable parts after the transfer header: (guest address, length).
    data: Vec<(GuestAddress, u32)>,
    len: u64,
    next: u64,
    status: Option<GuestAddress>,
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct SoundCounters {
    pub buffers: u64,
    pub played_bytes: u64,
    pub short_bytes: u64,
    pub resets: u64,
}

#[derive(Debug)]
pub struct Sound {
    avail_features: u64,
    acked_features: u64,
    activate_event: EventFd,
    device_state: DeviceState,
    pub(crate) queues: Vec<Queue>,
    queue_events: Vec<EventFd>,
    pub(crate) runtime_events_registered: bool,
    /// `struct virtio_snd_config`: jacks, streams, chmaps.
    config: [u8; 12],
    out: Box<dyn AudioOut>,
    pub(crate) timer: TimerFd,

    state: StreamState,
    buffers: VecDeque<TxBuf>,
    /// The rate control: when it started, and the bytes played since then.
    t_start: i64,
    sent: u64,
    pub(crate) counters: SoundCounters,
}

fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
}

impl Sound {
    pub fn new(out: Box<dyn AudioOut>) -> std::io::Result<Self> {
        let queue_events = (0..NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<Result<Vec<_>, _>>()?;
        let mut config = [0u8; 12];
        config[4..8].copy_from_slice(&le32(1)); // streams
        config[8..12].copy_from_slice(&le32(1)); // chmaps
        Ok(Sound {
            avail_features: 1 << VIRTIO_F_VERSION_1,
            acked_features: 0,
            activate_event: EventFd::new(libc::EFD_NONBLOCK)?,
            device_state: DeviceState::Inactive,
            queues: vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); NUM_QUEUES],
            queue_events,
            runtime_events_registered: false,
            config,
            out,
            timer: TimerFd::new(),
            state: StreamState::Idle,
            buffers: VecDeque::new(),
            t_start: 0,
            sent: 0,
            counters: SoundCounters::default(),
        })
    }

    fn mem(&self) -> Option<GuestMemoryMmap> {
        self.device_state.active_state().map(|s| s.mem.clone())
    }

    fn signal(&mut self, q: usize) {
        self.queues[q].advance_used_ring_idx();
        if let Some(s) = self.device_state.active_state()
            && let Err(err) = s
                .interrupt
                .trigger(VirtioInterruptType::Queue(u16::try_from(q).unwrap()))
        {
            error!("sound: cannot signal queue {q}: {err:?}");
        }
    }

    // ---- the control queue -------------------------------------------------------------

    /// The answer to one control request: the status and what follows it.
    pub(crate) fn control(&mut self, req: &[u8]) -> Vec<u8> {
        let Some(code) = u32_at(req, 0) else {
            return le32(S_BAD_MSG).to_vec();
        };
        match code {
            R_PCM_INFO | R_CHMAP_INFO | R_JACK_INFO => {
                // struct virtio_snd_query_info: hdr, start_id, count, size.
                let (Some(start), Some(count), Some(size)) =
                    (u32_at(req, 4), u32_at(req, 8), u32_at(req, 12))
                else {
                    return le32(S_BAD_MSG).to_vec();
                };
                let (n, item): (u32, Vec<u8>) = match code {
                    R_PCM_INFO => (1, Self::pcm_info()),
                    R_CHMAP_INFO => (1, Self::chmap_info()),
                    _ => (0, Vec::new()),
                };
                if u64::from(start) + u64::from(count) > u64::from(n)
                    || (size as usize) < item.len()
                {
                    return le32(S_BAD_MSG).to_vec();
                }
                let mut r = le32(S_OK).to_vec();
                for _ in 0..count {
                    let mut it = item.clone();
                    it.resize(size as usize, 0);
                    r.extend_from_slice(&it);
                }
                r
            }
            R_JACK_REMAP => le32(S_BAD_MSG).to_vec(),
            R_PCM_SET_PARAMS => le32(self.set_params(req)).to_vec(),
            R_PCM_PREPARE | R_PCM_RELEASE | R_PCM_START | R_PCM_STOP => {
                if u32_at(req, 4) != Some(0) {
                    return le32(S_BAD_MSG).to_vec();
                }
                le32(self.transition(code)).to_vec()
            }
            _ => le32(S_NOT_SUPP).to_vec(),
        }
    }

    fn pcm_info() -> Vec<u8> {
        let mut i = vec![0u8; PCM_INFO_LEN];
        // hda_fn_nid 0, features 0
        i[8..16].copy_from_slice(&(1u64 << PCM_FMT_S16).to_le_bytes());
        i[16..24].copy_from_slice(&(1u64 << PCM_RATE_48000).to_le_bytes());
        i[24] = D_OUTPUT;
        i[25] = CHANNELS_U8; // channels_min
        i[26] = CHANNELS_U8; // channels_max
        i
    }

    fn chmap_info() -> Vec<u8> {
        let mut i = vec![0u8; CHMAP_INFO_LEN];
        i[4] = D_OUTPUT;
        i[5] = CHANNELS_U8;
        i[6] = CHMAP_FL;
        i[7] = CHMAP_FR;
        i
    }

    /// `struct virtio_snd_pcm_set_params`: hdr, stream_id, buffer_bytes, period_bytes, features,
    /// channels, format, rate.
    fn set_params(&mut self, req: &[u8]) -> u32 {
        if req.len() < 24 || u32_at(req, 4) != Some(0) {
            return S_BAD_MSG;
        }
        let buffer = u32_at(req, 8).unwrap();
        let period = u32_at(req, 12).unwrap();
        let features = u32_at(req, 16).unwrap();
        let (channels, format, rate) = (req[20], req[21], req[22]);
        if !matches!(
            self.state,
            StreamState::Idle | StreamState::Set | StreamState::Prepared | StreamState::Stopped
        ) {
            return S_BAD_MSG;
        }
        if features != 0 || u32::from(channels) != CHANNELS {
            return S_NOT_SUPP;
        }
        if format != PCM_FMT_S16 || rate != PCM_RATE_48000 {
            return S_NOT_SUPP;
        }
        if period == 0 || buffer < period {
            return S_BAD_MSG;
        }
        self.state = StreamState::Set;
        S_OK
    }

    fn transition(&mut self, code: u32) -> u32 {
        use StreamState::*;
        match (code, self.state) {
            (R_PCM_PREPARE, Set | Prepared | Stopped) => self.state = Prepared,
            (R_PCM_START, Prepared | Stopped) => {
                self.state = Running;
                self.t_start = now_us();
                self.sent = 0;
                self.timer.arm(PERIOD, Some(PERIOD));
            }
            (R_PCM_STOP, Running) => {
                self.state = Stopped;
                self.timer.arm(Duration::ZERO, None);
            }
            (R_PCM_RELEASE, Prepared | Stopped | Set) => {
                // The device completes what it still has of the stream.
                self.state = Set;
                self.complete_all();
            }
            _ => return S_BAD_MSG,
        }
        S_OK
    }

    fn process_control_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let Some(mem) = self.mem() else {
            return Ok(());
        };
        let mut used = false;
        while let Some(head) = self.queues[CONTROL_QUEUE].pop()? {
            let mut req = Vec::new();
            let mut writable = Vec::new();
            let mut next = Some(head);
            while let Some(d) = next {
                if d.is_write_only() {
                    writable.push((d.addr, d.len));
                } else if req.len() + d.len as usize <= MAX_CTRL {
                    let start = req.len();
                    req.resize(start + d.len as usize, 0);
                    if mem.read_slice(&mut req[start..], d.addr).is_err() {
                        req.truncate(start);
                    }
                }
                next = d.next_descriptor();
            }
            let resp = self.control(&req);
            let mut done = 0usize;
            for (addr, len) in writable {
                if done == resp.len() {
                    break;
                }
                let n = (len as usize).min(resp.len() - done);
                if mem.write_slice(&resp[done..done + n], addr).is_err() {
                    break;
                }
                done += n;
            }
            if let Err(err) =
                self.queues[CONTROL_QUEUE].add_used(head.index, u32::try_from(done).unwrap())
            {
                error!("sound: cannot add a used element: {err}");
            }
            used = true;
        }
        if used {
            self.signal(CONTROL_QUEUE);
        }
        Ok(())
    }

    // ---- the samples ---------------------------------------------------------------------

    fn process_tx_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let mut used = false;
        while let Some(head) = self.queues[TX_QUEUE].pop()? {
            let mut skip = PCM_XFER_LEN as u64;
            let mut data = Vec::new();
            let mut status = None;
            let mut next = Some(head);
            while let Some(d) = next {
                if d.is_write_only() {
                    if d.len as usize >= PCM_STATUS_LEN {
                        status = Some(d.addr);
                    }
                } else {
                    let len = u64::from(d.len);
                    if skip >= len {
                        skip -= len;
                    } else {
                        data.push((
                            GuestAddress(d.addr.0 + skip),
                            u32::try_from(len - skip).unwrap(),
                        ));
                        skip = 0;
                    }
                }
                next = d.next_descriptor();
            }
            let len = data.iter().map(|d| u64::from(d.1)).sum();
            let buf = TxBuf {
                head: head.index,
                data,
                len,
                next: 0,
                status,
            };
            self.counters.buffers += 1;
            if self.state == StreamState::Idle {
                // No stream to play it: returned at once.
                self.complete(&buf, S_BAD_MSG);
                used = true;
            } else {
                self.buffers.push_back(buf);
            }
        }
        if used {
            self.signal(TX_QUEUE);
        }
        Ok(())
    }

    /// Return a buffer to the guest with its status.
    fn complete(&mut self, buf: &TxBuf, status: u32) {
        let mut st = [0u8; PCM_STATUS_LEN];
        st[0..4].copy_from_slice(&le32(status));
        let mut len = 0;
        if let (Some(addr), Some(mem)) = (buf.status, self.mem())
            && mem.write_slice(&st, addr).is_ok()
        {
            len = u32::try_from(PCM_STATUS_LEN).unwrap();
        }
        if let Err(err) = self.queues[TX_QUEUE].add_used(buf.head, len) {
            error!("sound: cannot add a used element: {err}");
        }
    }

    fn complete_all(&mut self) {
        let bufs: Vec<TxBuf> = self.buffers.drain(..).collect();
        for b in &bufs {
            self.complete(b, S_OK);
        }
        if !bufs.is_empty() {
            self.signal(TX_QUEUE);
        }
    }

    /// The timer: play what is due (`no_write` of QEMU's `none` backend).
    pub(crate) fn tick(&mut self, now: i64) {
        if self.state != StreamState::Running {
            return;
        }
        let elapsed = u64::try_from(now - self.t_start).unwrap_or(0);
        let due_bytes = elapsed * BYTES_PER_SECOND / 1_000_000;
        let mut frames = due_bytes.saturating_sub(self.sent) / FRAME;
        if due_bytes < self.sent || frames > MAX_DUE_FRAMES {
            self.t_start = now;
            self.sent = 0;
            self.counters.resets += 1;
            frames = 0;
        }
        let due = frames * FRAME;
        let Some(mem) = self.mem() else {
            return;
        };
        let mut out = Vec::with_capacity(usize::try_from(due).unwrap_or(0));
        let mut done = Vec::new();
        while (out.len() as u64) < due {
            let Some(b) = self.buffers.front_mut() else {
                break;
            };
            let want = (due - out.len() as u64).min(b.len - b.next);
            // Read `want` bytes from offset `next` of the buffer's parts.
            let mut off = b.next;
            let mut left = want;
            for &(addr, len) in &b.data {
                if left == 0 {
                    break;
                }
                let len = u64::from(len);
                if off >= len {
                    off -= len;
                    continue;
                }
                let n = (len - off).min(left);
                let start = out.len();
                out.resize(start + usize::try_from(n).unwrap(), 0);
                if mem
                    .read_slice(&mut out[start..], GuestAddress(addr.0 + off))
                    .is_err()
                {
                    out[start..].fill(0);
                }
                left -= n;
                off = 0;
            }
            b.next += want;
            if b.next >= b.len {
                done.push(self.buffers.pop_front().unwrap());
            }
        }
        // QEMU's rate control counts only the bytes taken; the rest stays due.
        let played = out.len() as u64;
        self.sent += played;
        self.counters.played_bytes += played;
        let short = due - played;
        self.counters.short_bytes += short;
        if !out.is_empty() || short != 0 {
            self.out.audio(RATE, CHANNELS, &out, short);
        }
        if !done.is_empty() {
            for b in &done {
                self.complete(b, S_OK);
            }
            self.signal(TX_QUEUE);
        }
    }

    /// Buffers of capture (there is no capture stream) and of events are not used: those of
    /// capture are returned at once, those of events kept.
    fn process_rx_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let mut used = false;
        while let Some(head) = self.queues[RX_QUEUE].pop()? {
            if let Err(err) = self.queues[RX_QUEUE].add_used(head.index, 0) {
                error!("sound: cannot add a used element: {err}");
            }
            used = true;
        }
        if used {
            self.signal(RX_QUEUE);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn queued(&self) -> usize {
        self.buffers.len()
    }
}

impl VirtioDevice for Sound {
    impl_device_type!(VirtioDeviceType::Sound);

    fn id(&self) -> &str {
        SOUND_DEV_ID
    }

    fn num_queues(&self) -> usize {
        self.queues.len()
    }

    fn queue_config(&self, index: usize) -> Option<&QueueConfig> {
        self.queues.get(index).map(|queue| &queue.config)
    }

    fn queue_config_mut(&mut self, index: usize) -> Option<&mut QueueConfig> {
        self.queues.get_mut(index).map(|queue| &mut queue.config)
    }

    fn queue_event(&self, index: usize) -> Option<&EventFd> {
        self.queue_events.get(index)
    }

    fn reset_queues(&mut self) {
        self.queues.iter_mut().for_each(Queue::reset);
    }

    fn mark_queue_memory_dirty(&mut self, mem: &GuestMemoryMmap) -> Result<(), QueueError> {
        for queue in &mut self.queues {
            queue.initialize(mem)?;
        }
        Ok(())
    }

    fn interrupt_trigger(&self) -> &dyn VirtioInterrupt {
        self.device_state
            .active_state()
            .expect("Device is not initialized")
            .interrupt
            .deref()
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn config_as_bytes(&self) -> &[u8] {
        &self.config
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {}

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn deactivate(&mut self) {
        self.device_state = DeviceState::Inactive;
    }

    fn _reset(&mut self) -> bool {
        self.timer.arm(Duration::ZERO, None);
        self.state = StreamState::Idle;
        self.buffers.clear();
        true
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: Arc<dyn VirtioInterrupt>,
    ) -> Result<(), ActivateError> {
        for q in self.queues.iter_mut() {
            q.initialize(&mem)
                .map_err(ActivateError::QueueMemoryError)?;
        }
        self.activate_event
            .write(1)
            .map_err(|_| ActivateError::EventFd)?;
        self.device_state = DeviceState::Activated(ActiveState { mem, interrupt });
        Ok(())
    }
}

impl Sound {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_TIMER: u32 = 1;
    /// Queue `q` is source `PROCESS_QUEUE + q`.
    const PROCESS_QUEUE: u32 = 2;

    fn register_queue_events(&mut self, ops: &mut EventOps) {
        if self.runtime_events_registered {
            return;
        }
        for q in [CONTROL_QUEUE, EVENT_QUEUE, TX_QUEUE, RX_QUEUE] {
            if let Err(err) = ops.add(Events::with_data(
                &self.queue_events[q],
                Self::PROCESS_QUEUE + u32::try_from(q).unwrap(),
                EventSet::IN,
            )) {
                error!("sound: failed to register a queue event: {err}");
            }
        }
        self.runtime_events_registered = true;
    }

    fn process_queues(&mut self) -> Result<(), InvalidAvailIdx> {
        self.process_control_queue()?;
        self.process_tx_queue()?;
        self.process_rx_queue()
    }
}

impl MutEventSubscriber for Sound {
    fn init(&mut self, ops: &mut EventOps) {
        let r = ops
            .add(Events::with_data(
                &self.activate_event,
                Self::PROCESS_ACTIVATE,
                EventSet::IN,
            ))
            .and_then(|()| {
                ops.add(Events::with_data(
                    &self.timer,
                    Self::PROCESS_TIMER,
                    EventSet::IN,
                ))
            });
        if let Err(err) = r {
            error!("sound: failed to register an event: {err}");
        }
        if self.is_activated() {
            self.register_queue_events(ops);
        }
    }

    fn process(&mut self, events: Events, ops: &mut EventOps) {
        let source = events.data();
        if !events.event_set().contains(EventSet::IN) {
            warn!("sound: unknown event from source {source}");
            return;
        }
        let r = match source {
            Self::PROCESS_ACTIVATE => {
                if let Err(err) = self.activate_event.read() {
                    error!("sound: failed to consume the activate event: {err}");
                }
                self.register_queue_events(ops);
                self.process_queues()
            }
            Self::PROCESS_TIMER => {
                self.timer.read();
                self.tick(now_us());
                Ok(())
            }
            s if s >= Self::PROCESS_QUEUE && ((s - Self::PROCESS_QUEUE) as usize) < NUM_QUEUES => {
                let q = (s - Self::PROCESS_QUEUE) as usize;
                if let Err(err) = self.queue_events[q].read() {
                    error!("sound: failed to read a queue event: {err}");
                }
                if !self.is_activated() {
                    return;
                }
                match q {
                    CONTROL_QUEUE => self.process_control_queue(),
                    TX_QUEUE => self.process_tx_queue(),
                    RX_QUEUE => self.process_rx_queue(),
                    // Buffers kept for events that never come (no jacks).
                    EVENT_QUEUE => Ok(()),
                    _ => Ok(()),
                }
            }
            _ => {
                warn!("sound: unknown event source {source}");
                Ok(())
            }
        };
        if let Err(err) = r {
            error!("sound: {err}");
        }
    }
}

/// The sound device in a snapshot: the virtio state, the stream's state, and the guest's
/// buffers the device holds (their descriptor chains are the guest's until they are given
/// back). The pacing starts again at the restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoundState {
    pub virtio_state: VirtioDeviceState,
    pub config: [u8; 12],
    pub stream: StreamState,
    /// (head, readable parts, length, next byte to play, status address).
    pub buffers: Vec<SoundBufState>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SoundBufState {
    pub head: u16,
    pub data: Vec<(u64, u32)>,
    pub len: u64,
    pub next: u64,
    pub status: Option<u64>,
}

#[derive(Debug)]
pub struct SoundConstructorArgs {
    pub mem: GuestMemoryMmap,
    pub out: Box<dyn AudioOut>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SoundPersistError {
    /// Virtio state: {0}
    VirtioState(#[from] VirtioStateError),
    /// The sound device cannot be made: {0}
    Create(#[from] std::io::Error),
    /// The sound device's state is not valid
    Invalid,
}

impl Persist<'_> for Sound {
    type State = SoundState;
    type ConstructorArgs = SoundConstructorArgs;
    type Error = SoundPersistError;

    fn save(&self) -> Self::State {
        SoundState {
            virtio_state: VirtioDeviceState::from_device(self, &self.queues),
            config: self.config,
            stream: self.state,
            buffers: self
                .buffers
                .iter()
                .map(|b| SoundBufState {
                    head: b.head,
                    data: b.data.iter().map(|(a, l)| (a.0, *l)).collect(),
                    len: b.len,
                    next: b.next,
                    status: b.status.map(|a| a.0),
                })
                .collect(),
        }
    }

    fn restore(args: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
        let mut dev = Sound::new(args.out)?;
        if state.virtio_state.avail_features != dev.avail_features {
            return Err(SoundPersistError::Invalid);
        }
        dev.queues = state.virtio_state.build_queues_checked(
            &args.mem,
            VirtioDeviceType::Sound,
            NUM_QUEUES,
            FIRECRACKER_MAX_QUEUE_SIZE,
        )?;
        dev.acked_features = state.virtio_state.acked_features;
        dev.config = state.config;
        dev.state = state.stream;
        dev.buffers = state
            .buffers
            .iter()
            .map(|b| TxBuf {
                head: b.head,
                data: b.data.iter().map(|&(a, l)| (GuestAddress(a), l)).collect(),
                len: b.len,
                next: b.next,
                status: b.status.map(GuestAddress),
            })
            .collect();
        if dev.state == StreamState::Running {
            dev.t_start = now_us();
            dev.sent = 0;
            dev.timer.arm(PERIOD, Some(PERIOD));
        }
        Ok(dev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt};
    use crate::test_utils::single_region_mem;
    use crate::vstate::memory::Address;

    /// One message: the samples and the short bytes.
    type Message = (Vec<u8>, u64);

    /// What the device sent.
    #[derive(Debug, Default, Clone)]
    struct Collect(Arc<Mutex<Vec<Message>>>);

    impl AudioOut for Collect {
        fn audio(&mut self, rate: u32, channels: u32, samples: &[u8], short: u64) {
            assert_eq!((rate, channels), (48_000, 2));
            self.0.lock().unwrap().push((samples.to_vec(), short));
        }
    }

    fn query(code: u32, start: u32, count: u32, size: u32) -> Vec<u8> {
        [code, start, count, size]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect()
    }

    fn params(buffer: u32, period: u32, channels: u8, format: u8, rate: u8) -> Vec<u8> {
        let mut r: Vec<u8> = [R_PCM_SET_PARAMS, 0, buffer, period, 0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        r.extend_from_slice(&[channels, format, rate, 0]);
        r
    }

    fn pcm(code: u32) -> Vec<u8> {
        [code, 0].iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    fn status(r: &[u8]) -> u32 {
        u32_at(r, 0).unwrap()
    }

    #[test]
    fn test_control_answers() {
        let mut s = Sound::new(Box::new(Collect::default())).unwrap();
        // The config: no jacks, one stream, one channel map.
        let mut c = [0u8; 12];
        s.read_config(0, &mut c);
        assert_eq!(c, [0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0]);

        let r = s.control(&query(R_PCM_INFO, 0, 1, 32));
        assert_eq!(status(&r), S_OK);
        assert_eq!(r.len(), 4 + 32);
        let info = &r[4..];
        assert_eq!(u64::from_le_bytes(info[8..16].try_into().unwrap()), 1 << 5); // S16
        assert_eq!(u64::from_le_bytes(info[16..24].try_into().unwrap()), 1 << 7); // 48000
        assert_eq!(&info[24..27], &[0, 2, 2]); // output, 2..2 channels
        // A larger item size is padded; a smaller one or a range past the streams is refused.
        assert_eq!(s.control(&query(R_PCM_INFO, 0, 1, 40)).len(), 4 + 40);
        assert_eq!(status(&s.control(&query(R_PCM_INFO, 0, 1, 16))), S_BAD_MSG);
        assert_eq!(status(&s.control(&query(R_PCM_INFO, 1, 1, 32))), S_BAD_MSG);
        assert_eq!(status(&s.control(&query(R_PCM_INFO, 0, 2, 32))), S_BAD_MSG);
        let r = s.control(&query(R_CHMAP_INFO, 0, 1, 24));
        assert_eq!(status(&r), S_OK);
        assert_eq!(&r[4 + 4..4 + 8], &[0, 2, 3, 4]); // output, 2 channels, FL, FR
        // No jacks.
        assert_eq!(status(&s.control(&query(R_JACK_INFO, 0, 0, 24))), S_OK);
        assert_eq!(status(&s.control(&query(R_JACK_INFO, 0, 1, 24))), S_BAD_MSG);
        assert_eq!(status(&s.control(&[1, 2])), S_BAD_MSG);
        assert_eq!(status(&s.control(&le32(0x0300))), S_NOT_SUPP);

        // Only what the sink plays.
        assert_eq!(
            status(&s.control(&params(8192, 2048, 1, PCM_FMT_S16, 7))),
            S_NOT_SUPP
        );
        assert_eq!(status(&s.control(&params(8192, 2048, 2, 6, 7))), S_NOT_SUPP);
        assert_eq!(
            status(&s.control(&params(8192, 2048, 2, PCM_FMT_S16, 6))),
            S_NOT_SUPP
        );
        assert_eq!(
            status(&s.control(&params(1024, 2048, 2, PCM_FMT_S16, 7))),
            S_BAD_MSG
        );
        // Start before prepare is refused; the order set, prepare, start, stop, release.
        assert_eq!(status(&s.control(&pcm(R_PCM_PREPARE))), S_BAD_MSG);
        assert_eq!(
            status(&s.control(&params(8192, 2048, 2, PCM_FMT_S16, 7))),
            S_OK
        );
        assert_eq!(status(&s.control(&pcm(R_PCM_START))), S_BAD_MSG);
        assert_eq!(status(&s.control(&pcm(R_PCM_PREPARE))), S_OK);
        assert_eq!(status(&s.control(&pcm(R_PCM_START))), S_OK);
        assert!(s.timer.is_armed());
        assert_eq!(
            status(&s.control(&params(8192, 2048, 2, PCM_FMT_S16, 7))),
            S_BAD_MSG
        );
        assert_eq!(status(&s.control(&pcm(R_PCM_RELEASE))), S_BAD_MSG);
        assert_eq!(status(&s.control(&pcm(R_PCM_STOP))), S_OK);
        assert!(!s.timer.is_armed());
        assert_eq!(status(&s.control(&pcm(R_PCM_START))), S_OK);
        assert_eq!(status(&s.control(&pcm(R_PCM_STOP))), S_OK);
        assert_eq!(status(&s.control(&pcm(R_PCM_RELEASE))), S_OK);
        // Stream 1 does not exist.
        let mut bad = pcm(R_PCM_PREPARE);
        bad[4] = 1;
        assert_eq!(status(&s.control(&bad)), S_BAD_MSG);
    }

    #[test]
    fn test_persistence() {
        let mem = single_region_mem(0x10_0000);
        let n = FIRECRACKER_MAX_QUEUE_SIZE;
        let ctrl = VirtQueue::new(GuestAddress(0), &mem, n);
        let ev = VirtQueue::new(ctrl.end().unchecked_align_up(16), &mem, n);
        let tx = VirtQueue::new(ev.end().unchecked_align_up(16), &mem, n);
        let rx = VirtQueue::new(tx.end().unchecked_align_up(16), &mem, n);
        let mut s = Sound::new(Box::new(Collect::default())).unwrap();
        s.queues = vec![
            ctrl.create_queue(),
            ev.create_queue(),
            tx.create_queue(),
            rx.create_queue(),
        ];
        s.activate(mem.clone(), default_interrupt()).unwrap();
        s.control(&params(8192, 1920, 2, PCM_FMT_S16, 7));
        s.control(&pcm(R_PCM_PREPARE));
        s.control(&pcm(R_PCM_START));
        // a buffer that the device holds, half played
        s.buffers.push_back(TxBuf {
            head: 3,
            data: vec![(GuestAddress(0x2_0004), 1920)],
            len: 1920,
            next: 960,
            status: Some(GuestAddress(0x2_0784)),
        });
        let st = s.save();
        let st: SoundState = bitcode::deserialize(&bitcode::serialize(&st).unwrap()).unwrap();
        assert_eq!(st, s.save());
        let r = Sound::restore(
            SoundConstructorArgs {
                mem: mem.clone(),
                out: Box::new(Collect::default()),
            },
            &st,
        )
        .unwrap();
        assert_eq!(r.state, StreamState::Running);
        assert!(r.timer.is_armed());
        assert_eq!(r.buffers.len(), 1);
        assert_eq!(
            (r.buffers[0].head, r.buffers[0].next, r.buffers[0].status),
            (3, 960, Some(GuestAddress(0x2_0784)))
        );
        assert_eq!(r.acked_features(), s.acked_features());
        assert_eq!(r.config, s.config);
        // A stopped stream is not paced after the restore.
        s.control(&pcm(R_PCM_STOP));
        let r = Sound::restore(
            SoundConstructorArgs {
                mem,
                out: Box::new(Collect::default()),
            },
            &s.save(),
        )
        .unwrap();
        assert_eq!(r.state, StreamState::Stopped);
        assert!(!r.timer.is_armed());
    }

    #[test]
    fn test_pacing() {
        let mem = single_region_mem(0x10_0000);
        let ctrl = VirtQueue::new(GuestAddress(0), &mem, 16);
        let ev = VirtQueue::new(ctrl.end().unchecked_align_up(16), &mem, 16);
        let tx = VirtQueue::new(ev.end().unchecked_align_up(16), &mem, 16);
        let rx = VirtQueue::new(tx.end().unchecked_align_up(16), &mem, 16);
        let out = Collect::default();
        let mut s = Sound::new(Box::new(out.clone())).unwrap();
        s.queues = vec![
            ctrl.create_queue(),
            ev.create_queue(),
            tx.create_queue(),
            rx.create_queue(),
        ];
        s.activate(mem.clone(), default_interrupt()).unwrap();
        s.control(&params(8192, 1920, 2, PCM_FMT_S16, 7));
        s.control(&pcm(R_PCM_PREPARE));

        // Two buffers of 10 ms (1920 bytes) each: the header, the samples, the status. The
        // samples are a ramp, so that their order can be checked.
        const PERIOD_BYTES: u32 = 1920;
        for i in 0..2u16 {
            let base = 0x2_0000 + u64::from(i) * 0x1000;
            mem.write_slice(&0u32.to_le_bytes(), GuestAddress(base))
                .unwrap();
            let samples: Vec<u8> = (0..PERIOD_BYTES)
                .map(|k| ((u32::from(i) * PERIOD_BYTES + k) % 251) as u8)
                .collect();
            mem.write_slice(&samples, GuestAddress(base + 0x100))
                .unwrap();
            let d = i * 3;
            tx.dtable[usize::from(d)].set(base, 4, VIRTQ_DESC_F_NEXT, d + 1);
            tx.dtable[usize::from(d + 1)].set(base + 0x100, PERIOD_BYTES, VIRTQ_DESC_F_NEXT, d + 2);
            tx.dtable[usize::from(d + 2)].set(base + 0x900, 8, VIRTQ_DESC_F_WRITE, 0);
            tx.avail.ring[usize::from(i)].set(d);
        }
        tx.avail.idx.set(2);
        s.process_tx_queue().unwrap();
        assert_eq!(s.queued(), 2);

        s.control(&pcm(R_PCM_START));
        let t0 = s.t_start;
        // 5 ms: 960 bytes due and played; no buffer returned yet.
        s.tick(t0 + 5_000);
        assert_eq!(out.0.lock().unwrap()[0].0.len(), 960);
        assert_eq!(tx.used.idx.get(), 0);
        // 10 ms: the first buffer is done and returned with its status.
        s.tick(t0 + 10_000);
        assert_eq!(tx.used.idx.get(), 1);
        assert_eq!(tx.used.ring[0].get().id, 0);
        assert_eq!(tx.used.ring[0].get().len, 8);
        let mut st = [0u8; 8];
        mem.read_slice(&mut st, GuestAddress(0x2_0900)).unwrap();
        assert_eq!(u32::from_le_bytes(st[0..4].try_into().unwrap()), S_OK);
        // A late timer: 7.5 ms since the last one, 1440 bytes, across the buffers' border.
        s.tick(t0 + 17_500);
        // 20 ms: 3840 bytes due in all, 3840 queued: everything played, the second returned.
        s.tick(t0 + 20_000);
        assert_eq!(tx.used.idx.get(), 2);
        let sent: Vec<Message> = out.0.lock().unwrap().clone();
        let all: Vec<u8> = sent.iter().flat_map(|m| m.0.clone()).collect();
        assert_eq!(
            sent.iter().map(|m| m.0.len()).collect::<Vec<_>>(),
            [960, 960, 1440, 480]
        );
        let want: Vec<u8> = (0..2 * PERIOD_BYTES).map(|k| (k % 251) as u8).collect();
        assert_eq!(all, want);
        assert_eq!(sent.iter().map(|m| m.1).sum::<u64>(), 0);
        // Nothing queued: what is due is short, and stays due (QEMU's rate control).
        s.tick(t0 + 25_000);
        assert_eq!(out.0.lock().unwrap().last().unwrap(), &(Vec::new(), 960));
        s.tick(t0 + 30_000);
        assert_eq!(out.0.lock().unwrap().last().unwrap(), &(Vec::new(), 1920));
        assert_eq!(s.counters.short_bytes, 960 + 1920);
        // More than 65536 frames due: the rate control starts again.
        s.tick(t0 + 2_000_000);
        assert_eq!(s.counters.resets, 1);
        assert_eq!(s.t_start, t0 + 2_000_000);

        // A buffer queued and released before it is played is returned.
        tx.avail.ring[2].set(0);
        tx.avail.idx.set(3);
        s.process_tx_queue().unwrap();
        assert_eq!(s.queued(), 1);
        s.control(&pcm(R_PCM_STOP));
        s.tick(t0 + 2_100_000); // stopped: nothing plays
        assert_eq!(s.queued(), 1);
        s.control(&pcm(R_PCM_RELEASE));
        assert_eq!(s.queued(), 0);
        assert_eq!(tx.used.idx.get(), 3);
    }
}
