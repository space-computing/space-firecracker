// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The input devices of the screen: a virtio-input keyboard and a virtio-input tablet (absolute
//! axes), fed by the sink's input (`SP_INPUT`), which the GPU device receives.
//!
//! They answer like QEMU's `virtio-keyboard` and `virtio-tablet` (`hw/input/virtio-input-hid.c`):
//! the sink sends QEMU's input events (a `QKeyCode`, an `InputButton`, an absolute axis scaled to
//! 0..0x7FFF of its window, and a sync), and each becomes the Linux event that QEMU's device makes
//! of it. Two differences: the tablet also has the side and extra buttons and both wheels, each
//! with its high-resolution form (`REL_WHEEL_HI_RES`, 120 to a notch); and a report that finds too
//! few buffers in the guest's event queue waits for them (QEMU drops it), up to
//! [`MAX_PENDING`] events.

use std::collections::VecDeque;
use std::ops::Deref;
use std::sync::Arc;

use event_manager::{EventOps, Events, MutEventSubscriber};
use serde::{Deserialize, Serialize};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use super::keymap::QCODE_TO_LINUX;
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
use crate::vstate::memory::{Bytes, GuestMemoryMmap};

pub const KEYBOARD_DEV_ID: &str = "gpu-keyboard";
pub const TABLET_DEV_ID: &str = "gpu-tablet";

const EVENT_QUEUE: usize = 0;
const STATUS_QUEUE: usize = 1;
const NUM_QUEUES: usize = 2;

/// Events that wait for buffers of the guest; a report beyond this is dropped.
pub(crate) const MAX_PENDING: usize = 1024;

// `struct virtio_input_config`: select, subsel, size, reserved[5], then 128 bytes.
const CONFIG_LEN: usize = 136;
const CFG_UNSET: u8 = 0x00;
const CFG_ID_NAME: u8 = 0x01;
const CFG_ID_SERIAL: u8 = 0x02;
const CFG_ID_DEVIDS: u8 = 0x03;
const CFG_PROP_BITS: u8 = 0x10;
const CFG_EV_BITS: u8 = 0x11;
const CFG_ABS_INFO: u8 = 0x12;

// Linux input event codes (`include/uapi/linux/input-event-codes.h`).
pub(crate) const EV_SYN: u16 = 0x00;
pub(crate) const EV_KEY: u16 = 0x01;
pub(crate) const EV_REL: u16 = 0x02;
pub(crate) const EV_ABS: u16 = 0x03;
const EV_LED: u16 = 0x11;
const EV_REP: u16 = 0x14;
pub(crate) const SYN_REPORT: u16 = 0;
pub(crate) const BTN_LEFT: u16 = 0x110;
pub(crate) const BTN_RIGHT: u16 = 0x111;
pub(crate) const BTN_MIDDLE: u16 = 0x112;
pub(crate) const BTN_SIDE: u16 = 0x113;
pub(crate) const BTN_EXTRA: u16 = 0x114;
pub(crate) const REL_HWHEEL: u16 = 0x06;
pub(crate) const REL_WHEEL: u16 = 0x08;
pub(crate) const REL_WHEEL_HI_RES: u16 = 0x0b;
pub(crate) const REL_HWHEEL_HI_RES: u16 = 0x0c;
pub(crate) const ABS_X: u16 = 0x00;
pub(crate) const ABS_Y: u16 = 0x01;
const LED_NUML: u16 = 0;
const LED_CAPSL: u16 = 1;
const LED_SCROLLL: u16 = 2;
const BUS_VIRTUAL: u16 = 0x06;
/// The axes' range, QEMU's `INPUT_EVENT_ABS_MAX` (the sink scales to it).
pub(crate) const ABS_MAX: u32 = 0x7fff;
/// One notch of a wheel in the high-resolution event.
const HI_RES_NOTCH: i32 = 120;

// QEMU's `InputButton`, by ordinal (qapi/ui.json).
const BUTTON_LEFT: u32 = 0;
const BUTTON_MIDDLE: u32 = 1;
const BUTTON_RIGHT: u32 = 2;
const BUTTON_WHEEL_UP: u32 = 3;
const BUTTON_WHEEL_DOWN: u32 = 4;
const BUTTON_SIDE: u32 = 5;
const BUTTON_EXTRA: u32 = 6;
const BUTTON_WHEEL_LEFT: u32 = 7;
const BUTTON_WHEEL_RIGHT: u32 = 8;

/// Which of the two devices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Keyboard,
    Tablet,
}

/// `struct virtio_input_event`: le16 type, le16 code, le32 value.
pub(crate) type Event = [u8; 8];

pub(crate) fn event(typ: u16, code: u16, value: i32) -> Event {
    let mut e = [0u8; 8];
    e[0..2].copy_from_slice(&typ.to_le_bytes());
    e[2..4].copy_from_slice(&code.to_le_bytes());
    e[4..8].copy_from_slice(&value.to_le_bytes());
    e
}

/// The events that one input of the sink becomes: (device, events); an empty list for what
/// has no event (a release of a wheel button, an unmapped key). `SP_INPUT`'s `SpInput`: kind 1
/// key (a = `QKeyCode`, b = down), 2 button (a = `InputButton`, b = down), 3 relative and 4
/// absolute (a = axis, b = value); kind 0 (sync) is handled by the caller.
pub(crate) fn translate(kind: u32, a: u32, b: i32) -> Option<(InputKind, Vec<Event>)> {
    match kind {
        1 => {
            let code = QCODE_TO_LINUX.get(a as usize).copied().unwrap_or(0);
            (code != 0).then(|| {
                (
                    InputKind::Keyboard,
                    vec![event(EV_KEY, code, i32::from(b != 0))],
                )
            })
        }
        2 => {
            let key = |code| vec![event(EV_KEY, code, i32::from(b != 0))];
            let wheel = |code, hi, v: i32| {
                if b != 0 {
                    vec![event(EV_REL, code, v), event(EV_REL, hi, v * HI_RES_NOTCH)]
                } else {
                    Vec::new()
                }
            };
            let ev = match a {
                BUTTON_LEFT => key(BTN_LEFT),
                BUTTON_MIDDLE => key(BTN_MIDDLE),
                BUTTON_RIGHT => key(BTN_RIGHT),
                BUTTON_SIDE => key(BTN_SIDE),
                BUTTON_EXTRA => key(BTN_EXTRA),
                BUTTON_WHEEL_UP => wheel(REL_WHEEL, REL_WHEEL_HI_RES, 1),
                BUTTON_WHEEL_DOWN => wheel(REL_WHEEL, REL_WHEEL_HI_RES, -1),
                BUTTON_WHEEL_LEFT => wheel(REL_HWHEEL, REL_HWHEEL_HI_RES, -1),
                BUTTON_WHEEL_RIGHT => wheel(REL_HWHEEL, REL_HWHEEL_HI_RES, 1),
                _ => return None,
            };
            Some((InputKind::Tablet, ev))
        }
        // The tablet has no relative axes; the sink sends absolute positions only.
        4 if a <= 1 => Some((
            InputKind::Tablet,
            vec![event(EV_ABS, if a == 0 { ABS_X } else { ABS_Y }, b)],
        )),
        _ => None,
    }
}

fn bitmap(codes: &[u16]) -> Vec<u8> {
    let mut b = Vec::new();
    for &c in codes {
        let byte = usize::from(c / 8);
        if b.len() <= byte {
            b.resize(byte + 1, 0);
        }
        b[byte] |= 1 << (c % 8);
    }
    b
}

/// The answer of the config space to a select and subselect: the bytes of `u` (its `size`).
pub(crate) fn config_answer(kind: InputKind, select: u8, subsel: u8) -> Vec<u8> {
    let tablet = kind == InputKind::Tablet;
    match (select, subsel) {
        (CFG_ID_NAME, 0) => {
            let name: &[u8] = if tablet {
                b"Spacebox Virtio Tablet"
            } else {
                b"Spacebox Virtio Keyboard"
            };
            name.to_vec()
        }
        (CFG_ID_SERIAL, 0) => b"spacebox".to_vec(),
        (CFG_ID_DEVIDS, 0) => {
            // QEMU's ids for its HID devices: vendor 0x0627, product 1 keyboard, 3 tablet.
            let product: u16 = if tablet { 3 } else { 1 };
            [BUS_VIRTUAL, 0x0627, product, 1]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect()
        }
        (CFG_EV_BITS, s) => {
            let codes: Vec<u16> = match (kind, u16::from(s)) {
                (InputKind::Keyboard, EV_KEY) => {
                    QCODE_TO_LINUX.iter().copied().filter(|&c| c != 0).collect()
                }
                // Autorepeat by the guest's kernel, as QEMU's keyboard: the bit is set by an
                // answer of one empty byte.
                (InputKind::Keyboard, EV_REP) => return vec![0],
                (InputKind::Keyboard, EV_LED) => vec![LED_NUML, LED_CAPSL, LED_SCROLLL],
                (InputKind::Tablet, EV_KEY) => {
                    vec![BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA]
                }
                (InputKind::Tablet, EV_REL) => {
                    vec![REL_HWHEEL, REL_WHEEL, REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES]
                }
                (InputKind::Tablet, EV_ABS) => vec![ABS_X, ABS_Y],
                _ => Vec::new(),
            };
            bitmap(&codes)
        }
        (CFG_ABS_INFO, s) if tablet && (u16::from(s) == ABS_X || u16::from(s) == ABS_Y) => {
            // min, max, fuzz, flat, res
            [0, ABS_MAX, 0, 0, 0]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect()
        }
        // CFG_UNSET, CFG_PROP_BITS (none) and everything else: size 0.
        _ => Vec::new(),
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct InputCounters {
    pub delivered: u64,
    pub dropped: u64,
}

#[derive(Debug)]
pub struct Input {
    kind: InputKind,
    avail_features: u64,
    acked_features: u64,
    activate_event: EventFd,
    device_state: DeviceState,
    pub(crate) queues: Vec<Queue>,
    queue_events: Vec<EventFd>,
    pub(crate) runtime_events_registered: bool,
    config: [u8; CONFIG_LEN],
    /// Events of complete reports (ending with `SYN_REPORT`) not given to the guest yet.
    pending: VecDeque<Event>,
    /// The report being built, until the next sync.
    report: Vec<Event>,
    pub(crate) counters: InputCounters,
}

impl Input {
    pub fn new(kind: InputKind) -> std::io::Result<Self> {
        let queue_events = (0..NUM_QUEUES)
            .map(|_| EventFd::new(libc::EFD_NONBLOCK))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Input {
            kind,
            avail_features: 1 << VIRTIO_F_VERSION_1,
            acked_features: 0,
            activate_event: EventFd::new(libc::EFD_NONBLOCK)?,
            device_state: DeviceState::Inactive,
            queues: vec![Queue::new(FIRECRACKER_MAX_QUEUE_SIZE); NUM_QUEUES],
            queue_events,
            runtime_events_registered: false,
            config: [0; CONFIG_LEN],
            pending: VecDeque::new(),
            report: Vec::new(),
            counters: InputCounters::default(),
        })
    }

    pub fn kind(&self) -> InputKind {
        self.kind
    }

    /// Add events to the report being built. Input that comes while the guest's driver is not
    /// up is not kept: old input would only confuse.
    pub(crate) fn queue_events_of_report(&mut self, events: &[Event]) {
        if self.is_activated() {
            self.report.extend_from_slice(events);
        }
    }

    /// End the report being built (a sync) and give what waits to the guest. A report with no
    /// events is nothing.
    pub(crate) fn sync(&mut self) {
        if self.report.is_empty() {
            return;
        }
        self.report.push(event(EV_SYN, SYN_REPORT, 0));
        if self.pending.len() + self.report.len() > MAX_PENDING {
            self.counters.dropped += self.report.len() as u64;
            self.report.clear();
            warn!("{}: the guest takes no input, a report dropped", self.id());
            return;
        }
        self.pending.extend(self.report.drain(..));
        if let Err(err) = self.process_event_queue() {
            error!("{}: event queue: {err}", self.id());
        }
    }

    /// Fill the guest's buffers with the waiting events.
    pub(crate) fn process_event_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let Some(mem) = self.device_state.active_state().map(|s| s.mem.clone()) else {
            return Ok(());
        };
        let mut used = false;
        while !self.pending.is_empty() {
            let Some(head) = self.queues[EVENT_QUEUE].pop()? else {
                break;
            };
            let ev = self.pending.pop_front().unwrap();
            let mut done = 0usize;
            let mut next = Some(head);
            while let Some(d) = next {
                if done == ev.len() {
                    break;
                }
                if d.is_write_only() {
                    let n = (d.len as usize).min(ev.len() - done);
                    if mem.write_slice(&ev[done..done + n], d.addr).is_err() {
                        break;
                    }
                    done += n;
                }
                next = d.next_descriptor();
            }
            if done == ev.len() {
                self.counters.delivered += 1;
            } else {
                self.counters.dropped += 1;
            }
            if let Err(err) =
                self.queues[EVENT_QUEUE].add_used(head.index, u32::try_from(done).unwrap())
            {
                error!("{}: cannot add a used element: {err}", self.id());
            }
            used = true;
        }
        if used {
            self.signal(EVENT_QUEUE);
        }
        Ok(())
    }

    /// The guest's status messages (the keyboard's LEDs): taken and returned.
    fn process_status_queue(&mut self) -> Result<(), InvalidAvailIdx> {
        let mut used = false;
        while let Some(head) = self.queues[STATUS_QUEUE].pop()? {
            if let Err(err) = self.queues[STATUS_QUEUE].add_used(head.index, 0) {
                error!("{}: cannot add a used element: {err}", self.id());
            }
            used = true;
        }
        if used {
            self.signal(STATUS_QUEUE);
        }
        Ok(())
    }

    fn signal(&mut self, q: usize) {
        self.queues[q].advance_used_ring_idx();
        if let Some(s) = self.device_state.active_state()
            && let Err(err) = s
                .interrupt
                .trigger(VirtioInterruptType::Queue(u16::try_from(q).unwrap()))
        {
            error!("{}: cannot signal queue {q}: {err:?}", self.id());
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

impl VirtioDevice for Input {
    impl_device_type!(VirtioDeviceType::Input);

    fn id(&self) -> &str {
        match self.kind {
            InputKind::Keyboard => KEYBOARD_DEV_ID,
            InputKind::Tablet => TABLET_DEV_ID,
        }
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

    /// The driver writes `select` (offset 0) and `subsel` (offset 1); the device then shows the
    /// answer's size at offset 2 and the answer from offset 8.
    fn write_config(&mut self, offset: u64, data: &[u8]) {
        let Ok(off) = usize::try_from(offset) else {
            return;
        };
        if off >= 2 || data.is_empty() {
            return;
        }
        let n = data.len().min(2 - off);
        self.config[off..off + n].copy_from_slice(&data[..n]);
        let (select, subsel) = (self.config[0], self.config[1]);
        let answer = if select == CFG_UNSET || select == CFG_PROP_BITS {
            Vec::new()
        } else {
            config_answer(self.kind, select, subsel)
        };
        let size = answer.len().min(CONFIG_LEN - 8);
        self.config[2] = u8::try_from(size).unwrap();
        self.config[3..].fill(0);
        self.config[8..8 + size].copy_from_slice(&answer[..size]);
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn deactivate(&mut self) {
        self.device_state = DeviceState::Inactive;
    }

    fn _reset(&mut self) -> bool {
        self.pending.clear();
        self.report.clear();
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

impl Input {
    const PROCESS_ACTIVATE: u32 = 0;
    const PROCESS_EVENT_QUEUE: u32 = 1;
    const PROCESS_STATUS_QUEUE: u32 = 2;

    fn register_queue_events(&mut self, ops: &mut EventOps) {
        if self.runtime_events_registered {
            return;
        }
        for (q, data) in [
            (EVENT_QUEUE, Self::PROCESS_EVENT_QUEUE),
            (STATUS_QUEUE, Self::PROCESS_STATUS_QUEUE),
        ] {
            if let Err(err) = ops.add(Events::with_data(&self.queue_events[q], data, EventSet::IN))
            {
                error!("{}: failed to register a queue event: {err}", self.id());
            }
        }
        self.runtime_events_registered = true;
    }
}

impl MutEventSubscriber for Input {
    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::with_data(
            &self.activate_event,
            Self::PROCESS_ACTIVATE,
            EventSet::IN,
        )) {
            error!(
                "{}: failed to register the activate event: {err}",
                self.id()
            );
        }
        if self.is_activated() {
            self.register_queue_events(ops);
        }
    }

    fn process(&mut self, events: Events, ops: &mut EventOps) {
        let source = events.data();
        if !events.event_set().contains(EventSet::IN) {
            warn!("{}: unknown event from source {source}", self.id());
            return;
        }
        let r = match source {
            Self::PROCESS_ACTIVATE => {
                if let Err(err) = self.activate_event.read() {
                    error!("{}: failed to consume the activate event: {err}", self.id());
                }
                self.register_queue_events(ops);
                self.process_event_queue()
                    .and_then(|()| self.process_status_queue())
            }
            Self::PROCESS_EVENT_QUEUE | Self::PROCESS_STATUS_QUEUE => {
                let q = if source == Self::PROCESS_EVENT_QUEUE {
                    EVENT_QUEUE
                } else {
                    STATUS_QUEUE
                };
                if let Err(err) = self.queue_events[q].read() {
                    error!("{}: failed to read a queue event: {err}", self.id());
                }
                if !self.is_activated() {
                    return;
                }
                if q == EVENT_QUEUE {
                    self.process_event_queue()
                } else {
                    self.process_status_queue()
                }
            }
            _ => {
                warn!("{}: unknown event source {source}", self.id());
                Ok(())
            }
        };
        if let Err(err) = r {
            error!("{}: {err}", self.id());
        }
    }
}

/// An input device in a snapshot: the virtio state, the config space the driver selected, and
/// the events not given to the guest yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputState {
    pub virtio_state: VirtioDeviceState,
    pub tablet: bool,
    pub config: Vec<u8>,
    pub pending: Vec<Event>,
    pub report: Vec<Event>,
}

#[derive(Debug)]
pub struct InputConstructorArgs {
    pub mem: GuestMemoryMmap,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum InputPersistError {
    /// Virtio state: {0}
    VirtioState(#[from] VirtioStateError),
    /// The input device cannot be made: {0}
    Create(#[from] std::io::Error),
    /// The input device's state is not valid
    Invalid,
}

impl Persist<'_> for Input {
    type State = InputState;
    type ConstructorArgs = InputConstructorArgs;
    type Error = InputPersistError;

    fn save(&self) -> Self::State {
        InputState {
            virtio_state: VirtioDeviceState::from_device(self, &self.queues),
            tablet: self.kind == InputKind::Tablet,
            config: self.config.to_vec(),
            pending: self.pending.iter().copied().collect(),
            report: self.report.clone(),
        }
    }

    fn restore(args: Self::ConstructorArgs, state: &Self::State) -> Result<Self, Self::Error> {
        let kind = if state.tablet {
            InputKind::Tablet
        } else {
            InputKind::Keyboard
        };
        let mut dev = Input::new(kind)?;
        if state.config.len() != CONFIG_LEN
            || state.virtio_state.avail_features != dev.avail_features
        {
            return Err(InputPersistError::Invalid);
        }
        dev.queues = state.virtio_state.build_queues_checked(
            &args.mem,
            VirtioDeviceType::Input,
            NUM_QUEUES,
            FIRECRACKER_MAX_QUEUE_SIZE,
        )?;
        dev.acked_features = state.virtio_state.acked_features;
        dev.config.copy_from_slice(&state.config);
        dev.pending = state.pending.iter().copied().collect();
        dev.report.clone_from(&state.report);
        Ok(dev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::virtio::queue::VIRTQ_DESC_F_WRITE;
    use crate::devices::virtio::test_utils::{VirtQueue, default_interrupt};
    use crate::test_utils::single_region_mem;
    use crate::vstate::memory::{Address, GuestAddress};

    fn select(dev: &mut Input, select: u8, subsel: u8) -> Vec<u8> {
        dev.write_config(0, &[select]);
        dev.write_config(1, &[subsel]);
        let mut size = [0u8];
        dev.read_config(2, &mut size);
        let mut u = vec![0u8; usize::from(size[0])];
        dev.read_config(8, &mut u);
        u
    }

    fn has_bit(map: &[u8], bit: u16) -> bool {
        map.get(usize::from(bit / 8))
            .is_some_and(|b| b & (1 << (bit % 8)) != 0)
    }

    #[test]
    fn test_persistence() {
        let mem = single_region_mem(0x10_0000);
        let n = FIRECRACKER_MAX_QUEUE_SIZE;
        let ev = VirtQueue::new(GuestAddress(0), &mem, n);
        let st = VirtQueue::new(ev.end().unchecked_align_up(16), &mem, n);
        let mut d = Input::new(InputKind::Tablet).unwrap();
        d.queues = vec![ev.create_queue(), st.create_queue()];
        d.activate(mem.clone(), default_interrupt()).unwrap();
        // the driver selected the axis info of X; two reports wait (no buffers yet), and one
        // is being built
        select(&mut d, CFG_ABS_INFO, 0);
        d.queue_events_of_report(&[event(3, 0, 100)]);
        d.sync();
        d.queue_events_of_report(&[event(3, 1, 200)]);
        assert_eq!(d.pending.len(), 2);
        let s = d.save();
        let s: InputState = bitcode::deserialize(&bitcode::serialize(&s).unwrap()).unwrap();
        let r = Input::restore(InputConstructorArgs { mem }, &s).unwrap();
        assert_eq!(r.kind(), InputKind::Tablet);
        assert_eq!(r.config, d.config);
        assert_eq!(r.pending, d.pending);
        assert_eq!(r.report, d.report);
        assert_eq!(r.acked_features(), d.acked_features());
        assert!(!r.is_activated());
    }

    #[test]
    fn test_key_map() {
        // QKeyCode ordinals of qapi/ui.json (the keyboard's rows: q w e ..., a s d ..., z x c
        // ...) and the Linux codes of input-event-codes.h.
        assert_eq!(QCODE_TO_LINUX[0], 0); // unmapped
        assert_eq!(QCODE_TO_LINUX[1], 42); // shift -> KEY_LEFTSHIFT
        assert_eq!(QCODE_TO_LINUX[2], 54); // shift_r -> KEY_RIGHTSHIFT
        assert_eq!(QCODE_TO_LINUX[23], 16); // q -> KEY_Q
        assert_eq!(QCODE_TO_LINUX[36], 30); // a -> KEY_A
        assert_eq!(QCODE_TO_LINUX[49], 44); // z -> KEY_Z
        assert_eq!(QCODE_TO_LINUX[53], 48); // b -> KEY_B
        let a = 36;
        let mapped = QCODE_TO_LINUX.iter().filter(|&&c| c != 0).count();
        assert_eq!(mapped, 161);
        assert_eq!(
            translate(1, u32::try_from(a).unwrap(), 1),
            Some((InputKind::Keyboard, vec![event(EV_KEY, 30, 1)]))
        );
        assert_eq!(translate(1, 0, 1), None);
        assert_eq!(translate(1, 10_000, 1), None);
    }

    #[test]
    fn test_translate_pointer() {
        assert_eq!(
            translate(2, BUTTON_LEFT, 1),
            Some((InputKind::Tablet, vec![event(EV_KEY, BTN_LEFT, 1)]))
        );
        assert_eq!(
            translate(2, BUTTON_RIGHT, 0),
            Some((InputKind::Tablet, vec![event(EV_KEY, BTN_RIGHT, 0)]))
        );
        assert_eq!(
            translate(2, BUTTON_WHEEL_DOWN, 1),
            Some((
                InputKind::Tablet,
                vec![
                    event(EV_REL, REL_WHEEL, -1),
                    event(EV_REL, REL_WHEEL_HI_RES, -120)
                ]
            ))
        );
        assert_eq!(
            translate(2, BUTTON_WHEEL_RIGHT, 1),
            Some((
                InputKind::Tablet,
                vec![
                    event(EV_REL, REL_HWHEEL, 1),
                    event(EV_REL, REL_HWHEEL_HI_RES, 120)
                ]
            ))
        );
        assert_eq!(
            translate(2, BUTTON_WHEEL_UP, 0),
            Some((InputKind::Tablet, vec![]))
        );
        assert_eq!(translate(2, 9, 1), None); // touch
        assert_eq!(
            translate(4, 1, 0x4000),
            Some((InputKind::Tablet, vec![event(EV_ABS, ABS_Y, 0x4000)]))
        );
        assert_eq!(translate(3, 0, 5), None);
    }

    #[test]
    fn test_config_space() {
        let mut kbd = Input::new(InputKind::Keyboard).unwrap();
        let mut tab = Input::new(InputKind::Tablet).unwrap();
        assert_eq!(
            select(&mut kbd, CFG_ID_NAME, 0),
            b"Spacebox Virtio Keyboard"
        );
        assert_eq!(select(&mut tab, CFG_ID_NAME, 0), b"Spacebox Virtio Tablet");
        assert_eq!(select(&mut tab, CFG_ID_SERIAL, 0), b"spacebox");
        assert_eq!(
            select(&mut tab, CFG_ID_DEVIDS, 0),
            [6, 0, 0x27, 0x06, 3, 0, 1, 0]
        );
        assert!(select(&mut kbd, CFG_UNSET, 0).is_empty());
        assert!(select(&mut tab, CFG_PROP_BITS, 0).is_empty());
        // Subselect matters: no name at subsel 1.
        assert!(select(&mut kbd, CFG_ID_NAME, 1).is_empty());

        let keys = select(&mut kbd, CFG_EV_BITS, u8::try_from(EV_KEY).unwrap());
        assert!(has_bit(&keys, 30) && has_bit(&keys, 42) && !has_bit(&keys, 0));
        assert_eq!(select(&mut kbd, CFG_EV_BITS, 0x14), [0]); // EV_REP
        assert_eq!(select(&mut kbd, CFG_EV_BITS, 0x11), [0b111]); // EV_LED
        assert!(select(&mut kbd, CFG_EV_BITS, u8::try_from(EV_ABS).unwrap()).is_empty());
        assert!(select(&mut kbd, CFG_ABS_INFO, 0).is_empty());

        let btn = select(&mut tab, CFG_EV_BITS, u8::try_from(EV_KEY).unwrap());
        for b in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA] {
            assert!(has_bit(&btn, b));
        }
        assert!(!has_bit(&btn, 30));
        let rel = select(&mut tab, CFG_EV_BITS, u8::try_from(EV_REL).unwrap());
        assert_eq!(rel, [0b0100_0000, 0b0001_1001]);
        assert_eq!(
            select(&mut tab, CFG_EV_BITS, u8::try_from(EV_ABS).unwrap()),
            [0b11]
        );
        let abs = select(&mut tab, CFG_ABS_INFO, 1);
        assert_eq!(abs.len(), 20);
        assert_eq!(u32::from_le_bytes(abs[4..8].try_into().unwrap()), 0x7fff);
        assert!(select(&mut tab, CFG_ABS_INFO, 2).is_empty());
        // A read past the answer gives zeros.
        tab.write_config(0, &[CFG_ID_NAME, 0]);
        let mut b = [0xffu8; 4];
        tab.read_config(8 + 22, &mut b);
        assert_eq!(b, [0; 4]);
    }

    #[test]
    fn test_event_queueing() {
        let mem = single_region_mem(0x4_0000);
        let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
        let sq = VirtQueue::new(vq.end().unchecked_align_up(16), &mem, 16);
        let mut dev = Input::new(InputKind::Tablet).unwrap();
        dev.queues[EVENT_QUEUE] = vq.create_queue();
        dev.queues[STATUS_QUEUE] = sq.create_queue();

        // Before the driver is up, input is not kept.
        dev.queue_events_of_report(&[event(EV_ABS, ABS_X, 5)]);
        dev.sync();
        assert_eq!(dev.pending_len(), 0);

        dev.activate(mem.clone(), default_interrupt()).unwrap();
        // Two buffers of the guest; a report of four events (three and the sync).
        for i in 0..2u16 {
            vq.avail.ring[usize::from(i)].set(i);
            vq.dtable[usize::from(i)].set(
                0x2_0000 + u64::from(i) * 0x100,
                8,
                VIRTQ_DESC_F_WRITE,
                0,
            );
        }
        vq.avail.idx.set(2);
        dev.queue_events_of_report(&[
            event(EV_ABS, ABS_X, 0x100),
            event(EV_ABS, ABS_Y, 0x200),
            event(EV_KEY, BTN_LEFT, 1),
        ]);
        // Nothing goes before the sync.
        dev.process_event_queue().unwrap();
        assert_eq!(vq.used.idx.get(), 0);
        dev.sync();
        assert_eq!(vq.used.idx.get(), 2);
        assert_eq!(dev.pending_len(), 2);
        let mut e = [0u8; 8];
        mem.read_slice(&mut e, GuestAddress(0x2_0000)).unwrap();
        assert_eq!(e, event(EV_ABS, ABS_X, 0x100));
        mem.read_slice(&mut e, GuestAddress(0x2_0100)).unwrap();
        assert_eq!(e, event(EV_ABS, ABS_Y, 0x200));
        assert_eq!(vq.used.ring[0].get().len, 8);

        // The guest adds buffers: the rest of the report follows, in order.
        for i in 2..4u16 {
            vq.avail.ring[usize::from(i)].set(i);
            vq.dtable[usize::from(i)].set(
                0x2_0000 + u64::from(i) * 0x100,
                8,
                VIRTQ_DESC_F_WRITE,
                0,
            );
        }
        vq.avail.idx.set(4);
        dev.process_event_queue().unwrap();
        assert_eq!(vq.used.idx.get(), 4);
        mem.read_slice(&mut e, GuestAddress(0x2_0200)).unwrap();
        assert_eq!(e, event(EV_KEY, BTN_LEFT, 1));
        mem.read_slice(&mut e, GuestAddress(0x2_0300)).unwrap();
        assert_eq!(e, event(EV_SYN, SYN_REPORT, 0));
        assert_eq!(dev.counters.delivered, 4);

        // An empty report is nothing.
        dev.sync();
        assert_eq!(dev.pending_len(), 0);

        // With no buffers, reports wait up to MAX_PENDING events; the next one is dropped.
        let per = 4; // three events and the sync
        for _ in 0..MAX_PENDING / per {
            dev.queue_events_of_report(&[event(EV_REL, REL_WHEEL, 1); 3]);
            dev.sync();
        }
        assert_eq!(dev.pending_len(), MAX_PENDING);
        dev.queue_events_of_report(&[event(EV_REL, REL_WHEEL, 1)]);
        dev.sync();
        assert_eq!(dev.pending_len(), MAX_PENDING);
        assert_eq!(dev.counters.dropped, 2);

        // A reset forgets what waits.
        dev._reset();
        assert_eq!(dev.pending_len(), 0);
    }
}
