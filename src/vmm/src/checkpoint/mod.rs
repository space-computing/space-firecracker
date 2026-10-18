// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints of a running guest to a receiving place on another server (`/space/checkpoint`).
//!
//! At each checkpoint the guest stops for a moment on the VMM thread, which also freezes every
//! device: the vCPUs pause; each device is readied for a checkpoint (a drive ends its requests in
//! flight with no `fsync`; the network device rewinds the receive buffers that it parsed); the
//! hook of the disk is told `epoch N`; the state goes into bytes (Firecracker's state file); the
//! pages that changed since the checkpoint before (KVM's dirty log and Firecracker's own bitmap,
//! which the devices mark) are copied into a buffer, and then both are reset, in this order,
//! because the network device marks a receive buffer when it parses it; the pages of every active
//! queue are marked as changed again (a device writes its used ring with no mark); the held
//! output gets its mark; the vCPUs run again. Then the sender thread sends the buffer, reads the
//! answer and tells the hook `commit N`, and the VMM thread releases the frames up to the mark,
//! when the lease runs. At most one checkpoint is on its way.
//!
//! A new stream begins with the full copy, which the sender reads while the guest runs, with the
//! tracking on; checkpoint 0 then closes it with the pages that changed meanwhile. A stream that
//! continues the stream of another VMM (after a move, or a give) begins with `SBCC` or `SBCI`
//! and its first checkpoint is taken at once.
//!
//! The next checkpoint begins by the clock (`interval-ms` after the begin of the one before), or
//! in the mode by need when a rule asks for it (`need.rs`). A checkpoint goes out only when its
//! state is the state of the guest at its stop: the saved clock of a guest that runs is the clock
//! of now (within 50 ms; a guest that a command stopped holds the clock of its stop), the CPU
//! registers are ones that a CPU can have, and a guest in an internal error is not copied. A
//! check that fails is tried again with a new save, three times; then the checkpoint is not
//! sent, and none after it.
//!
//! An answer does one thing: it releases the frames of a checkpoint that the receiving place has
//! whole, when the lease runs at the moment at which it is read. The lease (`lease.rs`) is kept
//! by the signal (`signal.rs`) and by nothing else. When it is over, the guest stops
//! (`paused_reason: lease`), no answer releases anything, no checkpoint is taken and a resume is
//! refused; only a release ends this. What is held leaves in two ways only: by an answer while
//! the lease runs, and by a release. Each other end throws it away, and the hold stays on.
//!
//! A guest that a command stopped keeps its checkpoints, its releases and its lease: the loop of
//! the VMM thread that serves a stopped guest also serves the events of this module.
//!
//! The behaviour is the one of the checkpoint loop of the QEMU fork of the host programs
//! (`ckpt/README.md` of the product repository).

pub mod hold;
pub mod lease;
pub mod need;
pub mod sender;
pub mod signal;
pub mod stream;

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use utils::time::TimerFd;
use vm_memory::{GuestAddress, GuestMemoryBackend, GuestMemoryRegion};

use self::hold::HOLD;
use self::lease::{Lease, host_us, monotonic_ms};
use self::need::{Decision, NeedConfig, NeedState};
use self::sender::{
    CopyRange, Event, Hook, HookAnswer, Job, Sender, SharedHook, StartKind, hook_answer, hook_fd,
    hook_say,
};
use self::signal::Signal;
use self::stream::{ID_LEN, PAGE, RegionDesc};
use crate::Vmm;
use crate::devices::virtio::gpu::GpuSideState;
use crate::logger::{error, info, warn};
use crate::persist::{MicrovmState, VmInfo};
use crate::seccomp::BpfProgram;
use crate::snapshot::Snapshot;
use crate::vmm_config::checkpoint::{
    CheckpointFinish, CheckpointFirst, CheckpointInfo, CheckpointSetParams, CheckpointTrackParams,
};
use crate::vmm_config::instance_info::PausedReason;
use crate::vstate::memory::{Bitmap, GuestMemoryExtension};

/// The saved clock of a guest that runs may be at most this far behind the clock of now.
const CLOCK_BEHIND_NS: u64 = 50 * 1_000_000;
/// The time between two stamps of the main loop while the signal runs.
const BEAT_MS: u64 = 100;
/// The tries of a save whose check fails.
const SAVE_TRIES: u32 = 3;
/// The error of a finish with no answer in its limit.
const NO_ANSWER: &str =
    "The receiving place did not answer the last checkpoint: the mode is as it was";

/// An error of a `/space/checkpoint` call.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum CheckpointError {
    /// {0}
    Refused(String),
}

fn refused<T>(why: impl Into<String>) -> Result<T, CheckpointError> {
    Err(CheckpointError::Refused(why.into()))
}

/// The pages that the balloon (or a virtio-mem unplug) gave back while the tracking runs: they
/// are sent as zeros in the next checkpoint and do not count as written by the guest. One for
/// the process, as the hold.
static DISCARDED: Mutex<Option<Vec<(u64, u64)>>> = Mutex::new(None);

/// Notes a range of guest memory (guest address, length) that was given back.
pub fn note_discarded(addr: GuestAddress, len: usize) {
    if let Some(list) = DISCARDED.lock().expect("Poisoned lock").as_mut() {
        list.push((addr.0, len as u64));
    }
}

fn discarded_start() {
    *DISCARDED.lock().expect("Poisoned lock") = Some(Vec::new());
}

fn discarded_take() -> Vec<(u64, u64)> {
    DISCARDED
        .lock()
        .expect("Poisoned lock")
        .as_mut()
        .map(std::mem::take)
        .unwrap_or_default()
}

fn discarded_stop() {
    *DISCARDED.lock().expect("Poisoned lock") = None;
}

/// Waits for `time` on the VMM thread: `poll` on no descriptor, with the time left as its limit.
/// The seccomp filter of the VMM thread allows `poll`; it does not allow `clock_nanosleep`, which
/// `std::thread::sleep` uses.
fn wait_on_vmm_thread(time: Duration) {
    let end = std::time::Instant::now() + time;
    loop {
        let left = end.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return;
        }
        let ms = i32::try_from(left.as_micros().div_ceil(1000)).unwrap_or(i32::MAX);
        // SAFETY: no descriptor is given; a signal only ends the wait early.
        unsafe { libc::poll(std::ptr::null_mut(), 0, ms) };
    }
}

/// A fault of the tests (`fault` of `PUT /space/checkpoint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    /// The clock of the state is the clock that the checkpoint before saved.
    StaleClock,
    /// The registers of the saved state are zeros, as when the host has turned virtualization
    /// off under the guest.
    ZeroCpu,
    /// The guest stops with an internal error.
    InternalError,
    /// The lease clock does not count a time of 1 s or more in which it was not read.
    LeaseClockHeld,
    /// The stop of the next checkpoint lasts two times the lease and 2 s.
    StopHeld,
}

impl Fault {
    fn parse(name: &str) -> Option<Fault> {
        Some(match name {
            "stale-clock" => Fault::StaleClock,
            "zero-cpu" => Fault::ZeroCpu,
            "internal-error" => Fault::InternalError,
            "lease-clock-held" => Fault::LeaseClockHeld,
            "stop-held" => Fault::StopHeld,
            _ => return None,
        })
    }
}

/// The settings of the mode (`PUT /space/checkpoint`).
#[derive(Debug, Clone, Default)]
struct Config {
    on: bool,
    interval_ms: u32,
    lost_ms: u32,
    hold: bool,
    lease_ms: u32,
    signal_ms: u32,
    cont: bool,
    cont_epoch: u64,
    id: Option<[u8; ID_LEN]>,
    need: Option<NeedConfig>,
}

/// Where a stream is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The sender connects, and sends the full copy or the begin of a continued stream.
    Starting,
    /// The loop runs.
    Active,
}

/// A checkpoint that went out and waits for its answer: what its line says.
#[derive(Debug, Clone)]
struct OnItsWay {
    epoch: u64,
    t_begin: i64,
    stop_us: i64,
    pages: u64,
    bytes: u64,
    written: u64,
    run_state: &'static str,
    reason: &'static str,
    waited_us: i64,
    covered: u64,
    busy: i32,
    account_before: i64,
    account_after: i64,
    t_sent: Option<i64>,
}

/// The stop of a checkpoint whose hook has been told `epoch N` and has not answered yet: the
/// guest stays stopped and its state is not copied until the answer. Only a finish leaves such
/// a stop open, at its limit; every other wait for the hook has no limit.
#[derive(Debug, Clone)]
struct OpenStop {
    epoch: u64,
    reason: &'static str,
    busy: i32,
    t_begin: i64,
    account_before: i64,
    was_running: bool,
    run_state: &'static str,
    leased: bool,
    first_of_new: bool,
    /// The line could not be written: the hook is gone.
    hook_gone: bool,
}

/// A stream that runs.
#[derive(Debug)]
struct Run {
    generation: u64,
    phase: Phase,
    /// The newest checkpoint that was taken.
    epoch: u64,
    on_its_way: Option<OnItsWay>,
    broken: bool,
    /// The begin of the last checkpoint (host clock, us); 0 at a continued stream.
    t_begin: i64,
    first_pending: bool,
    need: Option<NeedState>,
    leased: bool,
    stats: Option<File>,
    addrs: Option<(SocketAddr, SocketAddr)>,
    /// The clock that the last checkpoint saved (the fault `stale-clock`).
    #[cfg(target_arch = "x86_64")]
    last_clock: Option<kvm_bindings::kvm_clock_data>,
    finishing: bool,
    /// The next checkpoint is checkpoint 0 of a new stream, which closes the full copy.
    zero_next: bool,
}

/// What `GET /space/checkpoint` says, besides the settings and the lease.
#[derive(Debug, Default)]
struct Status {
    active: bool,
    sent: u64,
    acked: u64,
    have_ack: bool,
    lost: bool,
    why: Option<String>,
    last_ack_ms: i64,
    stop_us: i64,
    ack_us: i64,
    pages: u64,
    bytes: u64,
    count: u64,
    total_pages: u64,
    total_bytes: u64,
    total_stop_us: u64,
    final_epoch: Option<u64>,
    account_us: i64,
    /// A checkpoint was begun and its answer has not counted: its begin (monotonic, ms).
    unanswered: Option<i64>,
}

/// The checkpoint loop of one VMM, on the VMM thread.
#[derive(Debug)]
pub struct Checkpointer {
    sender: Option<Sender>,
    signal: Option<Signal>,
    lease: Arc<Lease>,
    hook: SharedHook,
    loop_timer: TimerFd,
    lease_timer: TimerFd,
    beat_timer: TimerFd,
    config: Config,
    fault: Option<Fault>,
    stop_held_done: bool,
    run: Option<Run>,
    generation: u64,
    st: Status,
    /// The tracking of changed pages runs with no stream (`PUT /space/checkpoint/track`), or a
    /// continued stream runs.
    tracking: bool,
    /// KVM's dirty log is on for the mode or the tracking.
    logging: bool,
    /// The guest is in an internal error (the fault of the tests).
    internal_error: bool,
    /// The end of the lease stopped a guest that ran: a release continues it.
    lease_stopped: bool,
    /// The reason of the stop of a guest that a command had stopped when its lease ended.
    reason_before_lease: Option<PausedReason>,
    /// A release ended the mode.
    end_released: bool,
    spare: Option<Vec<u8>>,
    /// The stop of a checkpoint that waits for the hook's answer after a finish ended.
    open_stop: Option<OpenStop>,
}

impl Default for Checkpointer {
    fn default() -> Checkpointer {
        Checkpointer::with_threads(None, Lease::new())
    }
}

impl Checkpointer {
    /// The loop with its sender and signal threads, which set `filter` (thread category
    /// `checkpoint`). They are started before the seccomp filter of the VMM thread is set.
    pub fn spawn(filter: Arc<BpfProgram>) -> std::io::Result<Checkpointer> {
        let lease = Lease::new();
        let hook: SharedHook = Arc::new(Mutex::new(None));
        let sender = Sender::spawn(filter.clone(), lease.clone(), hook.clone())?;
        let signal = Signal::spawn(filter, lease.clone())?;
        let mut c = Checkpointer::with_threads(Some((sender, signal)), lease);
        c.hook = hook;
        Ok(c)
    }

    fn with_threads(threads: Option<(Sender, Signal)>, lease: Arc<Lease>) -> Checkpointer {
        let (sender, signal) = match threads {
            Some((s, g)) => (Some(s), Some(g)),
            None => (None, None),
        };
        Checkpointer {
            sender,
            signal,
            lease,
            hook: Arc::new(Mutex::new(None)),
            loop_timer: TimerFd::new(),
            lease_timer: TimerFd::new(),
            beat_timer: TimerFd::new(),
            config: Config::default(),
            fault: None,
            stop_held_done: false,
            run: None,
            generation: 0,
            st: Status::default(),
            tracking: false,
            logging: false,
            internal_error: false,
            lease_stopped: false,
            reason_before_lease: None,
            end_released: false,
            spare: None,
            open_stop: None,
        }
    }

    /// The descriptors that wake the loop: the timers and the events of the sender, and the
    /// hook while a stop waits for its answer.
    pub fn fds(&self) -> Vec<RawFd> {
        let mut fds = vec![
            self.loop_timer.as_raw_fd(),
            self.lease_timer.as_raw_fd(),
            self.beat_timer.as_raw_fd(),
        ];
        if let Some(s) = &self.sender {
            fds.push(s.evt().as_raw_fd());
        }
        if self.open_stop.is_some()
            && let Some(fd) = hook_fd(&self.hook)
        {
            fds.push(fd);
        }
        fds
    }

    /// Whether `fd` is one of the descriptors of the loop (the wake of the hold included).
    pub fn owns(&self, fd: RawFd) -> bool {
        fd == HOLD.wake.as_raw_fd() || self.fds().contains(&fd)
    }

    /// Clears each descriptor, so that a level-triggered one does not wake the loop again.
    fn clear_fds(&mut self) {
        self.loop_timer.read();
        self.lease_timer.read();
        self.beat_timer.read();
        if let Some(s) = &self.sender {
            let _ = s.evt().read();
        }
        let _ = HOLD.wake.read();
    }

    fn fault_on(&self, fault: Fault) -> bool {
        self.fault == Some(fault)
    }

    fn arm(timer: &mut TimerFd, us: i64) {
        // A time of 0 would disarm the timer.
        let us = u64::try_from(us.max(1)).unwrap();
        timer.arm(Duration::from_micros(us), None);
    }

    fn disarm(timer: &mut TimerFd) {
        timer.arm(Duration::ZERO, None);
    }

    fn lost(&mut self, why: &str) {
        if !self.st.lost {
            warn!("The checkpoints are lost: {}", why);
            self.st.lost = true;
            self.st.why = Some(why.to_string());
        }
    }

    fn need_config(params: &CheckpointSetParams) -> NeedConfig {
        NeedConfig {
            interval_us: i64::from(params.interval_ms) * 1000,
            budget_pct: params.budget_pct.unwrap_or(10),
            cap_us: i64::from(params.cap_ms.unwrap_or(200)) * 1000,
            page_ns: u64::from(params.page_ns.unwrap_or(2000)),
            first_budget: params.first == Some(CheckpointFirst::Budget),
            look_us: i64::from(params.look_us.unwrap_or(200)),
            busy_us: i64::from(params.busy_us.unwrap_or(1000)),
        }
    }

    /// What `GET /space/checkpoint` gives.
    pub fn info(&self) -> CheckpointInfo {
        let counts = HOLD.counts();
        let lease = self.lease.info();
        let need = self.config.on && self.config.need.is_some();
        let mut info = CheckpointInfo {
            enabled: self.config.on,
            interval_ms: self.config.interval_ms,
            hold: self.config.hold,
            packets_held: counts
                .held
                .saturating_sub(counts.released + counts.discarded),
            packets_dropped: counts.dropped,
            packets_discarded: counts.discarded,
            holding: HOLD.holding(),
            lease_ms: lease.lease_ms,
            lease_over: lease.over,
            lease_left_ms: lease.left_ms,
            late: lease.late,
            since_echo_ms: lease.since_echo_ms,
            need,
            first: self.config.need.filter(|_| need).map(|n| {
                if n.first_budget {
                    CheckpointFirst::Budget
                } else {
                    CheckpointFirst::Time
                }
            }),
            tracking: self.tracking,
            stream_id: self.config.id.as_ref().map(stream::id_hex),
            signal_ms: if self.config.on {
                self.config.signal_ms
            } else {
                0
            },
            checkpoints: self.st.count,
            total_pages: self.st.total_pages,
            total_bytes: self.st.total_bytes,
            total_stop_us: self.st.total_stop_us,
            final_epoch: self.st.final_epoch,
            ..Default::default()
        };
        if !self.st.active && self.st.sent == 0 && !self.st.have_ack && !self.st.lost {
            return info;
        }
        info.active = self.st.active;
        info.sent = self.st.sent;
        info.acked = self.st.have_ack.then_some(self.st.acked);
        info.lost = self.st.lost;
        info.reason = self.st.why.clone();
        info.since_ack_ms = self
            .st
            .have_ack
            .then(|| host_us() / 1000 - self.st.last_ack_ms);
        if self.st.active {
            info.unanswered_ms = self.st.unanswered.map(|t| monotonic_ms() - t);
        }
        info.stop_us = self.st.stop_us;
        info.ack_us = self.st.ack_us;
        info.pages = self.st.pages;
        info.bytes = self.st.bytes;
        if need {
            info.account_us = Some(self.st.account_us);
        }
        info
    }

    /// Whether the mode runs.
    pub fn running(&self) -> bool {
        self.run.is_some()
    }

    /// Whether the mode or the tracking runs: the dirty bitmaps belong to the loop.
    pub fn owns_dirty_pages(&self) -> bool {
        self.run.is_some() || self.tracking
    }
}

/// The checks of a saved state: the clock of a guest that runs, and the CPU registers.
#[cfg(target_arch = "x86_64")]
fn verify(state: &MicrovmState, running: bool, now: Option<u64>) -> Result<(), String> {
    if running && let Some(now) = now {
        let saved = state.vm_state.clock().clock;
        if saved > now || now - saved > CLOCK_BEHIND_NS {
            #[allow(clippy::cast_possible_wrap)]
            let behind = (now as i64 - saved as i64) / 1_000_000;
            return Err(format!(
                "kvmclock: the saved clock is {behind} ms behind the clock of the guest"
            ));
        }
    }
    // Three facts hold for each CPU that ran: bit 1 of the flags is set, CR0 has ET, and in
    // protected mode the code segment is present. KVM gives zeros, and no error, when the host
    // kernel has turned virtualization off under the guest.
    for (i, cpu) in state.vcpu_states.iter().enumerate() {
        let flags = cpu.regs.rflags;
        let cr0 = cpu.sregs.cr0;
        let cs = cpu.sregs.cs.present;
        if flags & 0x2 == 0 || cr0 & 0x10 == 0 || (cr0 & 0x1 != 0 && cs == 0) {
            return Err(format!(
                "CPU {i}: the registers are not those of a CPU that ran (flags {flags:x}, CR0 \
                 {cr0:x}, code segment present {cs})"
            ));
        }
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn verify(_state: &MicrovmState, _running: bool, _now: Option<u64>) -> Result<(), String> {
    Ok(())
}

/// A run of pages for a frame: its offset in the memory file, where it lies in the process, its
/// pages, and whether it is data.
struct PageRun {
    offset: u64,
    host: usize,
    pages: u64,
    data: bool,
}

impl Vmm {
    fn kvm_vm_arc(&self) -> Option<Arc<crate::vstate::vm::KvmVm>> {
        self.vm.as_kvm().cloned()
    }

    /// The stop for the tracking: the vCPUs pause, each device is readied (a network device
    /// rewinds what it parsed), the dirty log of KVM is turned on (with nothing in it), the
    /// bitmap of Firecracker is reset, and the pages that must be in the next checkpoint with no
    /// write of the guest are marked: the rings of the active queues, and the pages that a load
    /// writes (the wall clock of kvmclock, VMGenID, VMClock).
    fn begin_tracking(&mut self) -> Result<(), String> {
        let kvm_vm = self.kvm_vm_arc().ok_or("the guest is not a KVM guest")?;
        let was_running = !self.is_stopped();
        if was_running {
            kvm_vm.pause_vcpus().map_err(|e| e.to_string())?;
        }
        self.device_manager.quiesce_virtio_devices();
        let _ = self.device_manager.save_checkpoint();
        if self.checkpoint.logging {
            kvm_vm.reset_dirty_bitmap();
        } else {
            kvm_vm.set_dirty_log(true).map_err(|e| e.to_string())?;
            self.checkpoint.logging = true;
        }
        let mem = kvm_vm.guest_memory();
        mem.reset_dirty();
        discarded_start();
        self.device_manager.mark_virtio_queue_memory_dirty(mem);
        // The pages that KVM and the VMM write at a load, with no write of the guest.
        #[cfg(target_arch = "x86_64")]
        if let Ok(cpus) = kvm_vm.save_vcpu_states() {
            for cpu in &cpus {
                for msrs in &cpu.saved_msrs {
                    for msr in msrs.as_slice() {
                        // MSR_KVM_WALL_CLOCK_NEW and MSR_KVM_WALL_CLOCK: 12 bytes of the wall clock.
                        if (msr.index == 0x4b56_4d00 || msr.index == 0x11) && msr.data & !1 != 0 {
                            mem.mark_dirty(GuestAddress(msr.data & !1), 12);
                        }
                    }
                }
            }
        }
        for (addr, len) in self.device_manager.acpi_devices.written_at_load() {
            mem.mark_dirty(addr, len);
        }
        if was_running {
            self.device_manager.resume_virtio_devices_after_checkpoint();
            kvm_vm.resume_vcpus().map_err(|e| e.to_string())?;
            self.device_manager.kick_net_receive();
        }
        Ok(())
    }

    /// The dirty log of KVM goes off when neither the mode nor the tracking runs (unless the
    /// machine was set to track dirty pages from its start).
    fn end_tracking_if_idle(&mut self) {
        if self.checkpoint.run.is_some() || self.checkpoint.tracking {
            return;
        }
        discarded_stop();
        if self.checkpoint.logging {
            self.checkpoint.logging = false;
            if !self.machine_config.track_dirty_pages
                && let Some(kvm_vm) = self.kvm_vm_arc()
                && let Err(err) = kvm_vm.set_dirty_log(false)
            {
                error!("Failed to turn KVM's dirty log off: {}", err);
            }
        }
    }

    /// `PUT /space/checkpoint` (the members of `x-checkpoint-set`, and `uri`: the receiving
    /// place, `tcp:ADDRESS:PORT`).
    pub fn checkpoint_set(&mut self, p: &CheckpointSetParams) -> Result<(), CheckpointError> {
        let running = self.checkpoint.run.is_some();
        let cont = p.cont == Some(true);
        let need = p.need == Some(true);
        let need_more = p.budget_pct.is_some()
            || p.cap_ms.is_some()
            || p.page_ns.is_some()
            || p.first.is_some()
            || p.look_us.is_some()
            || p.busy_us.is_some();

        if let Some(fault) = &p.fault {
            let fault = if fault.is_empty() {
                None
            } else {
                Some(
                    Fault::parse(fault)
                        .ok_or_else(|| CheckpointError::Refused(format!("no fault {fault}")))?,
                )
            };
            self.checkpoint.fault = fault;
            self.checkpoint.stop_held_done = false;
            self.checkpoint
                .lease
                .set_held_fault(fault == Some(Fault::LeaseClockHeld));
            self.checkpoint_service();
        }
        let c = &self.checkpoint;
        if running
            && ((p.interval_ms != 0) != c.config.on
                || p.hook.is_some()
                || p.stats.is_some()
                || p.packets.is_some()
                || p.cpus_only.is_some()
                || p.cont.is_some()
                || p.epoch.is_some()
                || p.stream_id.is_some()
                || p.lease_ms.is_some()
                || p.need.is_some()
                || need_more
                || p.signal_ms.is_some()
                || p.uri.is_some()
                || p.hold.is_some_and(|h| h != c.config.hold))
        {
            // (The hold does not change: to turn it off would let go what no answer covers; a
            // release does that, and ends the mode.)
            return refused("A migration runs: only the interval and the limit can change");
        }
        if c.lease.over() && p.interval_ms != 0 {
            return refused("The lease of the checkpoints is over: release first");
        }
        if cont && p.interval_ms == 0 {
            return refused("A stream is continued with an interval");
        }
        if cont && !c.tracking {
            return refused(
                "A stream is continued only with the tracking on (PUT /space/checkpoint/track)",
            );
        }
        if cont && p.epoch.is_none() {
            return refused("A stream is continued from a checkpoint: give its number (epoch)");
        }
        let id = match &p.stream_id {
            Some(text) => Some(stream::parse_id(text).ok_or_else(|| {
                CheckpointError::Refused("stream-id is 32 hex characters".into())
            })?),
            None => None,
        };
        if p.interval_ms > 60000 {
            return refused("The interval is at most 60000 ms");
        }
        let signal_ms = p.signal_ms.unwrap_or(500);
        if p.interval_ms != 0 && !running {
            let held = p.hold.unwrap_or(true);
            let lease_ms = p.lease_ms.unwrap_or_else(|| c.lease.current_lease_ms());
            if signal_ms > 60000 {
                return refused("signal-ms is at most 60000");
            }
            if held && lease_ms != 0 && (signal_ms == 0 || lease_ms / 4 < signal_ms) {
                // (A lease with no signal, or with too few, ends by itself.)
                return refused(
                    "The lease is kept by the signal: lease-ms is 4 times signal-ms or more, \
                     and signal-ms is not 0",
                );
            }
        }
        if need_more && !need {
            return refused(
                "budget-pct, cap-ms, page-ns, first, look-us and busy-us are members of the \
                 mode by need",
            );
        }
        if need {
            if p.interval_ms == 0 {
                return refused(
                    "The mode by need has an interval: the time between two checkpoints when \
                     nothing waits",
                );
            }
            if p.budget_pct.is_some_and(|b| !(1..=100).contains(&b))
                || p.look_us.is_some_and(|l| !(20..=20000).contains(&l))
            {
                return refused("budget-pct is 1 to 100, look-us is 20 to 20000");
            }
        }

        if running {
            let c = &mut self.checkpoint;
            c.config.interval_ms = p.interval_ms;
            if let Some(n) = c.config.need.as_mut() {
                n.interval_us = i64::from(p.interval_ms) * 1000;
            }
            if let Some(lost_ms) = p.lost_ms {
                c.config.lost_ms = lost_ms;
                if let Some(s) = &c.sender {
                    s.send(Job::LostMs(lost_ms));
                }
            }
            self.checkpoint_service();
            return Ok(());
        }
        if p.interval_ms == 0 {
            self.checkpoint.config.on = false;
            return Ok(());
        }
        let Some(uri) = &p.uri else {
            return refused(
                "uri: the address of the receiving place, tcp:ADDRESS:PORT, starts the mode",
            );
        };
        let addr: SocketAddr = uri
            .strip_prefix("tcp:")
            .and_then(|a| a.parse().ok())
            .ok_or_else(|| {
                CheckpointError::Refused(format!(
                    "uri is tcp:ADDRESS:PORT with an IP address, not {uri}"
                ))
            })?;
        if self.checkpoint.sender.is_none() {
            return refused("The checkpoint loop has no thread");
        }
        let kvm_vm = self
            .kvm_vm_arc()
            .ok_or_else(|| CheckpointError::Refused("the guest is not a KVM guest".into()))?;

        let lease_ms = p
            .lease_ms
            .unwrap_or_else(|| self.checkpoint.lease.current_lease_ms());
        let hold = p.hold.unwrap_or(true);
        let stats = match &p.stats {
            Some(path) => Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| CheckpointError::Refused(format!("stats {path}: {e}")))?,
            ),
            None => None,
        };
        let packets = match &p.packets {
            Some(path) => Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| CheckpointError::Refused(format!("packets {path}: {e}")))?,
            ),
            None => None,
        };
        // A new stream makes its own set of changed pages from the begin of its full copy (a
        // tracking that a load began ends); a continued one goes on with the tracking.
        let kind = if cont {
            StartKind::Continue {
                epoch: p.epoch.unwrap_or(0),
                id,
            }
        } else {
            if let Err(why) = self.begin_tracking() {
                return refused(format!("The tracking of changed pages: {why}"));
            }
            self.checkpoint.tracking = false;
            let mut regions = Vec::new();
            let mut ranges = Vec::new();
            let mut offset = 0;
            for region in kvm_vm.guest_memory().iter() {
                regions.push(RegionDesc {
                    guest_addr: region.start_addr().0,
                    size: region.len(),
                    offset,
                });
                for slot in region.plugged_slots() {
                    ranges.push(CopyRange {
                        host: slot.slice.ptr_guard().as_ptr() as usize,
                        len: slot.slice.len(),
                        offset: offset + (slot.guest_addr.0 - region.start_addr().0),
                    });
                }
                offset += region.len();
            }
            StartKind::New { regions, ranges }
        };
        if packets.is_some() {
            HOLD.set_log(packets);
        }
        {
            let c = &mut self.checkpoint;
            c.st.sent = 0;
            c.st.acked = 0;
            c.st.have_ack = false;
            c.st.lost = false;
            c.st.why = None;
            c.st.final_epoch = None;
            c.st.unanswered = None;
            if !c.tracking {
                c.st.count = 0;
                c.st.total_pages = 0;
                c.st.total_bytes = 0;
                c.st.total_stop_us = 0;
            }
            c.config = Config {
                on: true,
                interval_ms: p.interval_ms,
                lost_ms: p.lost_ms.unwrap_or(1000),
                hold,
                lease_ms,
                signal_ms,
                cont,
                cont_epoch: if cont { p.epoch.unwrap_or(0) } else { 0 },
                id,
                need: need.then(|| Checkpointer::need_config(p)),
            };
            c.end_released = false;
            c.internal_error = false;
        }
        self.checkpoint.generation += 1;
        let generation = self.checkpoint.generation;
        let leased = hold && lease_ms != 0;
        let now = host_us();
        self.checkpoint.run = Some(Run {
            generation,
            phase: Phase::Starting,
            epoch: self.checkpoint.config.cont_epoch,
            on_its_way: None,
            broken: false,
            t_begin: if cont { 0 } else { now },
            first_pending: cont,
            need: self
                .checkpoint
                .config
                .need
                .map(|n| NeedState::start(&n, now)),
            leased,
            stats,
            addrs: None,
            #[cfg(target_arch = "x86_64")]
            last_clock: None,
            finishing: false,
            zero_next: !cont,
        });
        if let Some(path) = &p.hook {
            match Hook::open(path) {
                Ok(hook) => *self.checkpoint.hook.lock().expect("Poisoned lock") = Some(hook),
                Err(err) => {
                    error!("The hook {} of the checkpoints: {}", path, err);
                    self.checkpoint.lost("the hook gives no answer");
                    self.checkpoint.run.as_mut().unwrap().broken = true;
                }
            }
        }
        if cont {
            // What the tracking holds stays held: the next mark covers it. A continued stream
            // has the lease of the tracking, from the resume of the guest.
            if hold {
                HOLD.set(true, self.checkpoint.config.cont_epoch + 1);
            }
            self.checkpoint.st.active = true;
            self.checkpoint.st.sent = self.checkpoint.config.cont_epoch;
            self.checkpoint.st.acked = self.checkpoint.config.cont_epoch;
        }
        info!(
            "The checkpoint mode starts: {} stream to {}",
            if cont { "a continued" } else { "a new" },
            addr
        );
        let lost_ms = self.checkpoint.config.lost_ms;
        if let Some(s) = &self.checkpoint.sender {
            s.send(Job::Start {
                generation,
                addr,
                lost_ms,
                leased,
                kind,
            });
        }
        Ok(())
    }

    /// `PUT /space/checkpoint/track` (`x-checkpoint-track`).
    pub fn checkpoint_track(&mut self, p: &CheckpointTrackParams) -> Result<(), CheckpointError> {
        if self.checkpoint.run.is_some() {
            return refused("The checkpoint mode runs");
        }
        if !p.enable {
            // What is held stays held: a release lets it go.
            self.checkpoint.tracking = false;
            self.end_tracking_if_idle();
            return Ok(());
        }
        if !self.is_stopped() {
            return refused(
                "The tracking starts on a guest that is stopped or paused, with its state loaded",
            );
        }
        if !self.checkpoint.tracking {
            if let Err(why) = self.begin_tracking() {
                return refused(format!("The tracking of changed pages: {why}"));
            }
            self.checkpoint.tracking = true;
            let st = &mut self.checkpoint.st;
            st.count = 0;
            st.total_pages = 0;
            st.total_bytes = 0;
            st.total_stop_us = 0;
            st.final_epoch = None;
        }
        if p.hold == Some(true) {
            HOLD.set(true, 1);
            let lease = &self.checkpoint.lease;
            if let Some(lease_ms) = p.lease_ms.filter(|ms| *ms != 0)
                && !lease.any()
            {
                // The first lease: from the resume of the guest.
                lease.arm(lease_ms);
            }
        }
        Ok(())
    }

    /// `PUT /space/checkpoint/release` (`x-checkpoint-release`): the management program has the
    /// guest for good. The held frames go out, the hold and the lease end, the mode ends (the
    /// hook is told `end N`), the tracking ends (KVM's dirty log goes off), and a guest that the
    /// end of the lease stopped continues.
    pub fn checkpoint_release(&mut self) -> Result<(), CheckpointError> {
        self.checkpoint.end_released = true;
        HOLD.set(false, 1);
        self.device_manager.release_held(u64::MAX);
        Checkpointer::disarm(&mut self.checkpoint.lease_timer);
        let was_over = self.checkpoint.lease.over();
        self.checkpoint.lease.end();
        if was_over {
            self.refuse_resume(None);
        }
        if let Some(run) = self.checkpoint.run.take() {
            let epoch = run.epoch;
            self.end_stream(Some(epoch));
            self.checkpoint.config.on = false;
            self.checkpoint.config.cont = false;
        }
        // The tracking ends too, with or without a stream.
        self.checkpoint.tracking = false;
        self.end_tracking_if_idle();
        if self.checkpoint.lease_stopped {
            self.checkpoint.lease_stopped = false;
            if self.is_stopped() {
                self.resume_vm()
                    .map_err(|e| CheckpointError::Refused(format!("the resume: {e}")))?;
            }
        } else if let Some(reason) = self.checkpoint.reason_before_lease.take()
            && self.instance_info.paused_reason == Some(PausedReason::Lease)
        {
            self.instance_info.set_paused(reason);
        }
        self.checkpoint.reason_before_lease = None;
        Ok(())
    }

    /// `PUT /space/checkpoint/finish` (`x-checkpoint-finish`): on a guest that the caller
    /// stopped, a checkpoint on its way is answered first (its frames are released when the
    /// lease runs), the last checkpoint is taken in place and answered, and the mode ends; the
    /// hold stays on. One limit for all of it: two times `lost-ms` and 1 s. With no answer in it
    /// the call fails and the mode is as it was. That holds for the answer of the hook too: a
    /// stop whose hook has not answered `epoch N` in the limit stays open after the call, the
    /// guest stopped, and the checkpoint goes on when the hook answers (a hook that is gone
    /// makes the mode lost); every other call waits for the end of that stop, as it waits while
    /// a stop runs.
    pub fn checkpoint_finish(&mut self) -> Result<CheckpointFinish, CheckpointError> {
        let active = self.checkpoint.st.active
            && self
                .checkpoint
                .run
                .as_ref()
                .is_some_and(|r| r.phase == Phase::Active);
        if !active {
            return refused("No checkpoint mode is active");
        }
        if !self.is_stopped() {
            return refused("The guest runs: stop it first");
        }
        if self.checkpoint.lease.over() {
            return refused("The lease of the checkpoints is over");
        }
        if self.checkpoint.st.lost {
            return refused(format!(
                "The checkpoint mode is lost: {}",
                self.checkpoint.st.why.clone().unwrap_or_default()
            ));
        }
        let limit = Duration::from_millis(2 * u64::from(self.checkpoint.config.lost_ms) + 1000);
        let deadline = std::time::Instant::now() + limit;
        self.checkpoint.run.as_mut().unwrap().finishing = true;
        let result = self.finish_steps(deadline);
        if let Some(run) = self.checkpoint.run.as_mut() {
            run.finishing = false;
        }
        let epoch = match result {
            Ok(epoch) => epoch,
            Err(why) => {
                self.checkpoint_service();
                return refused(why);
            }
        };
        self.checkpoint.st.final_epoch = Some(epoch);
        self.checkpoint.run = None;
        // What waits is thrown away (the guest, stopped, sent nothing after the last mark), and
        // the hold stays on.
        self.end_stream(None);
        self.checkpoint.config.on = false;
        self.checkpoint.config.cont = false;
        self.checkpoint.tracking = false;
        self.end_tracking_if_idle();
        info!(
            "The checkpoint mode ends with checkpoint {} (finish)",
            epoch
        );
        Ok(CheckpointFinish { epoch, acked: true })
    }

    fn finish_steps(&mut self, deadline: std::time::Instant) -> Result<u64, String> {
        // (0) The stop that a finish before left open: the answer of its hook. The rest of that
        // checkpoint then goes as the loop's.
        if !self.continue_stop(Some(deadline)) {
            return Err(NO_ANSWER.into());
        }
        // (1) A checkpoint on its way: its answer, read here directly.
        self.wait_answer(deadline)?;
        // (2) The last checkpoint, in place: the guest is stopped.
        let reason = if self.checkpoint.config.need.is_some() {
            "finish"
        } else {
            "interval"
        };
        let busy = if self.checkpoint.config.need.is_some() {
            0
        } else {
            -1
        };
        self.take_checkpoint_until(reason, busy, Some(deadline));
        if self.checkpoint.open_stop.is_some() {
            // The hook has not answered: the stop stays open.
            return Err(NO_ANSWER.into());
        }
        let run = self.checkpoint.run.as_ref().ok_or("the mode ended")?;
        if run.broken || run.on_its_way.is_none() {
            return Err(format!(
                "The last checkpoint could not be taken: {}",
                self.checkpoint.st.why.clone().unwrap_or_default()
            ));
        }
        let epoch = run.epoch;
        // (3) Its answer.
        self.wait_answer(deadline)?;
        if self.checkpoint.st.have_ack && self.checkpoint.st.acked == epoch {
            Ok(epoch)
        } else {
            Err(NO_ANSWER.into())
        }
    }

    /// Waits until no checkpoint is on its way, handling the events of the sender here.
    fn wait_answer(&mut self, deadline: std::time::Instant) -> Result<(), String> {
        loop {
            let Some(run) = self.checkpoint.run.as_ref() else {
                return Err("the mode ended".into());
            };
            if run.broken {
                return Err(format!(
                    "The checkpoint mode is lost: {}",
                    self.checkpoint.st.why.clone().unwrap_or_default()
                ));
            }
            if run.on_its_way.is_none() {
                return Ok(());
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(NO_ANSWER.into());
            }
            let event = self
                .checkpoint
                .sender
                .as_ref()
                .and_then(|s| s.wait_event(deadline - now));
            if let Some((generation, event)) = event {
                let late = matches!(event, Event::Late { .. });
                self.handle_event(generation, event);
                if late {
                    return Err("The answer came after the lease ended".into());
                }
            }
        }
    }

    /// Ends a stop that waits for the hook (a finish left it open), waiting for the hook with
    /// no limit, as every stop does: a call other than a finish runs only after it.
    pub fn checkpoint_end_open_stop(&mut self) {
        if self.checkpoint.open_stop.is_some() {
            self.continue_stop(None);
        }
    }

    /// Reads the hook's answer to the open stop, until `deadline` or with no limit, and ends
    /// the stop when it came (or when the hook is gone). False: the stop is still open.
    fn continue_stop(&mut self, deadline: Option<std::time::Instant>) -> bool {
        let Some(stop) = self.checkpoint.open_stop.as_ref() else {
            return true;
        };
        let gone = stop.hook_gone
            || match hook_answer(&self.checkpoint.hook, deadline) {
                HookAnswer::Ok => false,
                HookAnswer::Gone => true,
                HookAnswer::Waiting => return false,
            };
        let stop = self.checkpoint.open_stop.take().unwrap();
        self.end_stop(stop, gone);
        true
    }

    /// Ends the stream: no further signal; the sender closes the connection and tells the hook
    /// `end N` with `Some(N)`, else closes it with no line. With no release, what waits is
    /// thrown away.
    fn end_stream(&mut self, tell_end: Option<u64>) {
        if let Some(signal) = self.checkpoint.signal.as_mut() {
            signal.stop();
        }
        Checkpointer::disarm(&mut self.checkpoint.beat_timer);
        Checkpointer::disarm(&mut self.checkpoint.loop_timer);
        // The hook of this stream goes with its end (a commit that the sender tells now ends
        // first).
        let hook = self.checkpoint.hook.lock().expect("Poisoned lock").take();
        if let Some(s) = &self.checkpoint.sender {
            s.cancel();
            s.send(Job::End { tell_end, hook });
        }
        if !self.checkpoint.end_released {
            self.device_manager.discard_held();
        }
        HOLD.set_log(None);
        self.checkpoint.st.active = false;
        self.checkpoint.st.unanswered = None;
    }

    /// The lease is over: the guest stops (`paused_reason: lease`); from now on nothing is
    /// released, no checkpoint is taken and a resume is refused, until a release.
    fn lease_over(&mut self) {
        let was_running = !self.is_stopped();
        warn!("The lease of the checkpoints is over: the guest stops");
        if was_running {
            self.checkpoint.lease_stopped = true;
        } else if self.checkpoint.reason_before_lease.is_none() {
            self.checkpoint.reason_before_lease = self.instance_info.paused_reason.clone();
        }
        if let Err(err) = self.stop_vm(PausedReason::Lease) {
            error!("Failed to stop the guest at the end of its lease: {}", err);
        }
        self.refuse_resume(Some(
            "The lease of the checkpoints is over: only a release continues the guest".into(),
        ));
        Checkpointer::disarm(&mut self.checkpoint.lease_timer);
    }

    /// Ends the lease when its time is over (also at a resume, which the timer may not have
    /// seen: a stop or a long call keeps it from firing), else arms its timer.
    pub(crate) fn lease_check(&mut self) {
        match self.checkpoint.lease.end_if_passed() {
            (true, _) => self.lease_over(),
            (false, Some(left_ms)) => {
                let left_us = if self.checkpoint.lease.held_fault() {
                    // (The clock is read often.)
                    left_ms.min(100) * 1000
                } else {
                    left_ms * 1000
                };
                Checkpointer::arm(&mut self.checkpoint.lease_timer, left_us);
            }
            (false, None) => {}
        }
    }

    /// The guest was resumed: an armed lease begins.
    pub(crate) fn checkpoint_resumed(&mut self) {
        self.checkpoint.lease.resumed();
        self.lease_check();
    }

    /// The events of the loop: called by the event loop when one of its descriptors is ready,
    /// and at each turn of the loop that serves a stopped guest.
    pub fn checkpoint_service(&mut self) {
        if self.checkpoint.open_stop.is_some() {
            // A stop waits for the hook: the loop stands until it ends (no stamp, so the signal
            // pauses as in every long stop), and nothing else is handled before.
            self.checkpoint.clear_fds();
            if !self.continue_stop(Some(std::time::Instant::now())) {
                return;
            }
        }
        self.checkpoint.lease.stamp();
        self.checkpoint.clear_fds();
        while let Some((generation, event)) =
            self.checkpoint.sender.as_ref().and_then(Sender::try_event)
        {
            self.handle_event(generation, event);
        }
        self.lease_check();
        self.schedule();
    }

    fn handle_event(&mut self, generation: u64, event: Event) {
        let current = self
            .checkpoint
            .run
            .as_ref()
            .is_some_and(|r| r.generation == generation);
        if !current {
            return;
        }
        match event {
            Event::Connected { local, peer } => {
                self.checkpoint.run.as_mut().unwrap().addrs = Some((local, peer));
                if self.checkpoint.config.cont {
                    // The signal goes beside the stream from its begin.
                    self.start_signal();
                }
            }
            Event::FullCopyDone { pages, bytes } => {
                info!("The full copy is out ({} pages, {} bytes)", pages, bytes);
                self.checkpoint.run.as_mut().unwrap().phase = Phase::Active;
                // Checkpoint 0 closes the full copy.
                self.take_checkpoint("interval", -1);
            }
            Event::Continued { at_us } => {
                let run = self.checkpoint.run.as_mut().unwrap();
                run.phase = Phase::Active;
                self.checkpoint.st.have_ack = true;
                self.checkpoint.st.last_ack_ms = at_us / 1000;
            }
            Event::Sent { epoch, t_sent_us } => {
                if let Some(w) = self
                    .checkpoint
                    .run
                    .as_mut()
                    .unwrap()
                    .on_its_way
                    .as_mut()
                    .filter(|w| w.epoch == epoch)
                {
                    w.t_sent = Some(t_sent_us);
                }
                if let Some(s) = self.checkpoint.sender.as_ref().and_then(Sender::take_spare) {
                    self.checkpoint.spare = Some(s);
                }
            }
            Event::Answer { epoch, at_us } => self.answer(epoch, at_us),
            Event::Late { epoch } => {
                let run = self.checkpoint.run.as_mut().unwrap();
                if run.on_its_way.as_ref().is_some_and(|w| w.epoch == epoch) {
                    run.on_its_way = None;
                }
                self.lease_check();
            }
            Event::Lost { why, broken, .. } => {
                self.checkpoint.lost(&why);
                if broken {
                    let run = self.checkpoint.run.as_mut().unwrap();
                    run.broken = true;
                    if run.phase == Phase::Starting && !self.checkpoint.config.cont {
                        // A new stream that never began (its connect or its full copy failed)
                        // ends, as a migration of QEMU that fails: the query keeps the reason,
                        // and the mode can be started again.
                        self.checkpoint.run = None;
                        self.end_stream(None);
                        self.checkpoint.config.on = false;
                        self.end_tracking_if_idle();
                    }
                }
            }
            Event::Ended => {}
        }
    }

    fn start_signal(&mut self) {
        let signal_ms = self.checkpoint.config.signal_ms;
        let id = self.checkpoint.config.id;
        let Some((local, peer)) = self.checkpoint.run.as_ref().and_then(|r| r.addrs) else {
            return;
        };
        if signal_ms == 0 {
            return;
        }
        if let Some(signal) = self.checkpoint.signal.as_mut() {
            self.checkpoint.lease.stamp();
            signal.start(local, peer, signal_ms, id);
            self.checkpoint.beat_timer.arm(
                Duration::from_millis(BEAT_MS),
                Some(Duration::from_millis(BEAT_MS)),
            );
        }
    }

    /// The answer to `epoch` was read at `at_us` and the hook was told `commit N`: when the
    /// lease runs at this moment, the frames up to its mark go out. An answer never moves the
    /// end of the lease.
    fn answer(&mut self, epoch: u64, at_us: i64) {
        let leased = self.checkpoint.run.as_ref().unwrap().leased;
        let Some(w) = self
            .checkpoint
            .run
            .as_mut()
            .unwrap()
            .on_its_way
            .take_if(|w| w.epoch == epoch)
        else {
            return;
        };
        let lease = &self.checkpoint.lease;
        if leased && lease.passed(lease.now()) {
            lease.count_late();
            self.lease_check();
            return;
        }
        self.device_manager.release_held(epoch);
        let t_sent = w.t_sent.unwrap_or(at_us);
        let st = &mut self.checkpoint.st;
        st.acked = epoch;
        st.have_ack = true;
        st.unanswered = None;
        st.last_ack_ms = at_us / 1000;
        st.ack_us = at_us - t_sent;
        // An answer that came late: the copy is in step again.
        st.lost = false;
        let run = self.checkpoint.run.as_mut().unwrap();
        if let Some(stats) = run.stats.as_mut() {
            // The words after the run state: why the checkpoint began, how long its oldest frame
            // had waited at its begin, its frames, whether the guest was busy (-1: not looked
            // at), when this answer was read, the account at its begin and after it, and how
            // many of its pages the guest wrote: the pages that the account counts.
            let line = format!(
                "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {}\n",
                epoch,
                w.t_begin,
                w.stop_us,
                w.pages,
                w.bytes,
                at_us - t_sent,
                w.run_state,
                w.reason,
                w.waited_us,
                w.covered,
                w.busy,
                at_us,
                w.account_before,
                w.account_after,
                w.written
            );
            let _ = stats.write_all(line.as_bytes());
        }
    }

    /// Takes the next checkpoint when a rule asks for it, else arms the timer of the loop.
    fn schedule(&mut self) {
        let c = &self.checkpoint;
        let Some(run) = c.run.as_ref() else {
            return;
        };
        if run.phase != Phase::Active || run.broken || run.on_its_way.is_some() || run.finishing {
            return;
        }
        if run.leased && c.lease.passed(c.lease.now()) {
            // No checkpoint: the lease is over, or ends at once.
            self.lease_check();
            return;
        }
        let now = host_us();
        let first_pending = run.first_pending;
        let t_begin = run.t_begin;
        match c.config.need {
            None => {
                let left = t_begin + i64::from(c.config.interval_ms) * 1000 - now;
                if left > 0 {
                    Checkpointer::arm(&mut self.checkpoint.loop_timer, left);
                } else {
                    self.take_checkpoint("interval", -1);
                }
            }
            Some(nc) => {
                if first_pending {
                    let busy = i32::from(!self.guest_idle());
                    self.take_checkpoint("first", busy);
                    return;
                }
                let (waiting, first_us) = HOLD.waiting();
                let stopped = self.is_stopped();
                let looks = self.vcpu_blocking_looks();
                let mut need = self.checkpoint.run.as_mut().unwrap().need.take().unwrap();
                let decision =
                    need.decide(&nc, now, waiting, first_us, t_begin, || stopped || looks());
                self.checkpoint.run.as_mut().unwrap().need = Some(need);
                match decision {
                    Decision::Take { reason, busy } => {
                        self.take_checkpoint(reason.as_str(), i32::from(busy))
                    }
                    Decision::Wait(us) => {
                        Checkpointer::arm(&mut self.checkpoint.loop_timer, us);
                    }
                }
            }
        }
    }

    /// One look at the vCPUs: each sleeps in the kernel after a halt. A look that cannot tell
    /// says "not idle", so `idle` never comes by mistake.
    fn vcpu_blocking_looks(&self) -> impl Fn() -> bool + use<> {
        let stats: Vec<_> = self
            .vm
            .as_kvm()
            .map(|kvm_vm| {
                kvm_vm
                    .vcpus_handles()
                    .iter()
                    .map(|h| h.blocking_stat())
                    .collect()
            })
            .unwrap_or_default();
        move || {
            !stats.is_empty()
                && stats
                    .iter()
                    .all(|s| s.as_ref().is_some_and(|s| s.read() == Some(true)))
        }
    }

    fn guest_idle(&self) -> bool {
        self.is_stopped() || (self.vcpu_blocking_looks())()
    }

    /// The stop of checkpoint N (see the head of this module).
    fn take_checkpoint(&mut self, reason: &'static str, busy: i32) {
        self.take_checkpoint_until(reason, busy, None);
    }

    /// The stop of checkpoint N, whose wait for the hook's answer to `epoch N` ends at
    /// `deadline` (a finish) or has no limit. A stop whose hook has not answered at `deadline`
    /// stays open: the guest stays stopped, and the stop goes on when the answer comes.
    fn take_checkpoint_until(
        &mut self,
        reason: &'static str,
        busy: i32,
        deadline: Option<std::time::Instant>,
    ) {
        let Some(kvm_vm) = self.kvm_vm_arc() else {
            return;
        };
        let (epoch, leased, first_of_new) = {
            let run = self.checkpoint.run.as_ref().unwrap();
            if run.broken {
                // Nothing more goes out.
                return;
            }
            let epoch = if run.zero_next { 0 } else { run.epoch + 1 };
            (epoch, run.leased, run.zero_next)
        };
        if leased && self.checkpoint.lease.passed(self.checkpoint.lease.now()) {
            // The lease time is over: no checkpoint.
            self.lease_check();
            return;
        }
        let t_begin = host_us();
        self.checkpoint.st.unanswered = Some(monotonic_ms());
        let account_before = {
            let run = self.checkpoint.run.as_mut().unwrap();
            run.first_pending = false;
            match (run.need.as_mut(), self.checkpoint.config.need.as_ref()) {
                (Some(n), Some(nc)) => n.begin(nc, t_begin),
                _ => 0,
            }
        };
        if self.checkpoint.fault_on(Fault::InternalError) && !self.is_stopped() {
            // For tests: the guest stops with an internal error.
            if kvm_vm.pause_vcpus().is_ok() {
                self.checkpoint.internal_error = true;
            }
        }
        if self.checkpoint.internal_error || self.shutdown_exit_code.is_some() {
            // KVM could not run the guest: what it says of the CPUs now need not be their state,
            // and this VMM cannot run the guest again.
            let run = self.checkpoint.run.as_mut().unwrap();
            run.broken = true;
            self.checkpoint.st.unanswered = None;
            self.checkpoint
                .lost("the guest is in an internal error: its state is not copied");
            return;
        }
        let was_running = !self.is_stopped();
        let run_state = if was_running {
            "running"
        } else {
            match self.instance_info.paused_reason {
                Some(PausedReason::DiskError(_)) => "io-error",
                _ => "paused",
            }
        };
        if was_running && let Err(err) = kvm_vm.pause_vcpus() {
            error!("The stop of a checkpoint: {}", err);
            self.checkpoint.run.as_mut().unwrap().broken = true;
            self.checkpoint.st.unanswered = None;
            self.checkpoint
                .lost("the state could not be copied: the vCPUs did not stop");
            return;
        }
        if self.checkpoint.fault_on(Fault::StopHeld) && !self.checkpoint.stop_held_done {
            // For tests: this stop lasts two times the lease and 2 s, as a stop in which a disk
            // request never ends. The main loop stands: the lease cannot be ended in this time,
            // and the signal stops by itself. Once.
            self.checkpoint.stop_held_done = true;
            self.checkpoint.fault = None;
            let ms = 2 * u64::from(self.checkpoint.config.lease_ms) + 2000;
            eprintln!(
                "checkpoint: fault stop-held: the stop of checkpoint {epoch} is held from {} for {ms} ms",
                host_us()
            );
            wait_on_vmm_thread(Duration::from_millis(ms));
            eprintln!(
                "checkpoint: fault stop-held: the stop of checkpoint {epoch} ended at {}",
                host_us()
            );
        }
        // No disk request is in work, and the hook is told the number of this checkpoint.
        self.device_manager.quiesce_virtio_devices();
        let hook_gone = !hook_say(&self.checkpoint.hook, "epoch", epoch);
        self.checkpoint.open_stop = Some(OpenStop {
            epoch,
            reason,
            busy,
            t_begin,
            account_before,
            was_running,
            run_state,
            leased,
            first_of_new,
            hook_gone,
        });
        self.continue_stop(deadline);
    }

    /// The rest of the stop of checkpoint N, after the hook's answer to `epoch N` (`hook_gone`:
    /// it gave none): the state, the pages, the mark of the hold, the resume, and the frame.
    fn end_stop(&mut self, stop: OpenStop, hook_gone: bool) {
        let OpenStop {
            epoch,
            reason,
            busy,
            t_begin,
            account_before,
            was_running,
            run_state,
            leased,
            first_of_new,
            ..
        } = stop;
        let Some(kvm_vm) = self.kvm_vm_arc() else {
            return;
        };
        let mut broken: Option<String> = hook_gone.then(|| "the hook gives no answer".into());
        let mut state_bytes = Vec::new();
        let mut gpu = None;
        if broken.is_none() {
            match self.save_verified(was_running) {
                Ok((bytes, side)) => {
                    state_bytes = bytes;
                    gpu = side;
                }
                Err(why) => broken = Some(why),
            }
        }
        let mut frame = None;
        let mut covered = 0;
        let mut waited_us = 0;
        if broken.is_none() {
            // The pages, then the reset of the bitmaps, then the rings marked again.
            match self.copy_pages(&kvm_vm) {
                Ok((pages, count, written)) => frame = Some((pages, count, written)),
                Err(why) => broken = Some(why),
            }
            let mem = kvm_vm.guest_memory();
            mem.reset_dirty();
            self.device_manager.mark_virtio_queue_memory_dirty(mem);
            if first_of_new && self.checkpoint.config.hold {
                // The hold begins with the stop of checkpoint 0.
                HOLD.set(true, 1);
            }
            let (n, first_us) = HOLD.waiting();
            covered = n;
            waited_us = if n > 0 {
                (t_begin - first_us).max(0)
            } else {
                0
            };
            HOLD.mark(epoch);
        }
        if first_of_new && broken.is_none() {
            // The stop of the full copy's checkpoint 0 is the begin of the mode: its lease, its
            // signal, and the hook's first line was told above.
            if leased && !self.checkpoint.lease.any() {
                let now = self.checkpoint.lease.now();
                self.checkpoint
                    .lease
                    .begin(now, self.checkpoint.config.lease_ms);
            }
            self.checkpoint.st.active = true;
            self.start_signal();
        }
        if was_running {
            let lease = &self.checkpoint.lease;
            if leased && lease.passed(lease.now()) {
                // The stop took longer than the lease had left: the guest does not run again.
                self.lease_check();
            } else {
                self.device_manager.resume_virtio_devices_after_checkpoint();
                if let Err(err) = kvm_vm.resume_vcpus() {
                    error!("The end of the stop of a checkpoint: {}", err);
                } else {
                    self.device_manager.kick_net_receive();
                }
            }
        }
        let stop_us = host_us() - t_begin;
        let Some((pages, count, written)) = frame.filter(|_| broken.is_none()) else {
            // It does not go out: none is on its way, and none after it.
            let why = broken.unwrap_or_else(|| "the state could not be copied".into());
            self.checkpoint.run.as_mut().unwrap().broken = true;
            self.checkpoint.st.unanswered = None;
            self.checkpoint.lost(&why);
            return;
        };
        let (account_before, account_after) = {
            let run = self.checkpoint.run.as_mut().unwrap();
            match (run.need.as_mut(), self.checkpoint.config.need.as_ref()) {
                // Checkpoint 0 closes the full copy and costs the account nothing: the account
                // starts at its end.
                (Some(n), Some(nc)) if first_of_new => {
                    *n = NeedState::start(nc, host_us());
                    (0, 0)
                }
                (Some(n), Some(nc)) => (
                    account_before,
                    n.paid(nc, account_before, written, stop_us, busy == 1),
                ),
                _ => (0, 0),
            }
        };
        let bytes = (pages.len() + state_bytes.len()) as u64;
        let run = self.checkpoint.run.as_mut().unwrap();
        run.epoch = epoch;
        run.t_begin = t_begin;
        run.zero_next = false;
        run.on_its_way = Some(OnItsWay {
            epoch,
            t_begin,
            stop_us,
            pages: count,
            bytes,
            written,
            run_state,
            reason,
            waited_us,
            covered,
            busy,
            account_before,
            account_after,
            t_sent: None,
        });
        let st = &mut self.checkpoint.st;
        st.sent = epoch;
        st.stop_us = stop_us;
        st.pages = count;
        st.bytes = bytes;
        st.count += 1;
        st.total_pages += count;
        st.total_bytes += bytes;
        st.total_stop_us += u64::try_from(stop_us).unwrap_or(0);
        st.account_us = account_after;
        if let Some(s) = &self.checkpoint.sender {
            s.send(Job::Frame {
                epoch,
                held: leased,
                pages,
                state: state_bytes,
                gpu,
            });
        }
    }

    /// The state of this stop as the bytes of a state file, with its checks: tried again with a
    /// new save when a check fails, three times. With it, the GPU device's large state (its side
    /// file, which the frame carries apart), if the guest has the device.
    #[allow(clippy::type_complexity)]
    fn save_verified(
        &mut self,
        running: bool,
    ) -> Result<(Vec<u8>, Option<Arc<GpuSideState>>), String> {
        let vm_info = VmInfo::from(&*self);
        let mut tries = 0;
        loop {
            tries += 1;
            #[allow(unused_mut)]
            let mut state = self
                .save_checkpoint_state(&vm_info)
                .map_err(|e| format!("the state could not be copied: {e}"))?;
            #[cfg(target_arch = "x86_64")]
            {
                let run = self.checkpoint.run.as_mut().unwrap();
                if self.checkpoint.fault == Some(Fault::StaleClock)
                    && let Some(old) = run.last_clock
                {
                    // For tests: kvmclock keeps the value that it saved last.
                    state.vm_state.replace_clock(old);
                } else {
                    run.last_clock = Some(*state.vm_state.clock());
                }
                if self.checkpoint.fault == Some(Fault::ZeroCpu) {
                    // For tests: what KVM gives for the registers of the control structure when
                    // the host has turned virtualization off.
                    for cpu in &mut state.vcpu_states {
                        cpu.regs.rip = 0;
                        cpu.regs.rflags = 0;
                        cpu.regs.rsp = 0;
                        cpu.sregs.cr3 = 0;
                        for seg in [
                            &mut cpu.sregs.cs,
                            &mut cpu.sregs.ds,
                            &mut cpu.sregs.es,
                            &mut cpu.sregs.fs,
                            &mut cpu.sregs.gs,
                            &mut cpu.sregs.ss,
                        ] {
                            *seg = Default::default();
                        }
                    }
                }
            }
            #[cfg(target_arch = "x86_64")]
            let now = self
                .vm
                .as_kvm()
                .and_then(|k| k.get_clock().ok())
                .map(|c| c.clock);
            #[cfg(target_arch = "aarch64")]
            let now = None;
            match verify(&state, running, now) {
                Ok(()) => {
                    let mut bytes = Vec::with_capacity(64 * 1024);
                    Snapshot::new(&state)
                        .save(&mut bytes)
                        .map_err(|e| format!("the state could not be copied: {e}"))?;
                    let gpu = state
                        .device_states
                        .virtio_state
                        .gpu_mut()
                        .and_then(|g| g.side.take());
                    return Ok((bytes, gpu));
                }
                Err(why) if tries >= SAVE_TRIES => {
                    return Err(format!(
                        "the saved state is not the state of this stop: {why}"
                    ));
                }
                Err(why) => warn!("A checkpoint is saved again: {}", why),
            }
        }
    }

    /// The pages of this checkpoint as page records with their end record: each page that the
    /// guest or a device changed (KVM's dirty log, read and cleared here, and Firecracker's
    /// bitmap) with its bytes, and each page that was given back since as zeros. Returns the
    /// records, the pages, and the pages that were written.
    fn copy_pages(
        &mut self,
        kvm_vm: &crate::vstate::vm::KvmVm,
    ) -> Result<(Vec<u8>, u64, u64), String> {
        let kvm_bits = kvm_vm
            .get_dirty_bitmap()
            .map_err(|e| format!("the state could not be copied: {e}"))?;
        let discarded = discarded_take();
        let mut runs: Vec<PageRun> = Vec::new();
        let mut written = 0u64;
        let mut zero_pages = 0u64;
        let mut region_offset = 0u64;
        for region in kvm_vm.guest_memory().iter() {
            let region_start = region.start_addr().0;
            for slot in region.plugged_slots() {
                let pages = slot.slice.len() / PAGE;
                let slot_start = slot.guest_addr.0;
                let slot_offset = region_offset + (slot_start - region_start);
                let host = slot.slice.ptr_guard().as_ptr() as usize;
                let kvm = kvm_bits.get(&slot.slot);
                let mut gone = vec![false; pages];
                for &(addr, len) in &discarded {
                    let from = addr.max(slot_start);
                    let to = (addr + len).min(slot_start + (pages * PAGE) as u64);
                    let mut a = from;
                    while a < to {
                        gone[usize::try_from((a - slot_start) / PAGE as u64).unwrap()] = true;
                        a += PAGE as u64;
                    }
                }
                let bitmap = slot.slice.bitmap();
                for i in 0..pages {
                    let by_kvm = kvm.is_some_and(|k| k[i / 64] & (1 << (i % 64)) != 0);
                    let dirty = by_kvm || bitmap.dirty_at(i * PAGE);
                    let kind = if dirty {
                        Some(true)
                    } else if gone[i] {
                        Some(false)
                    } else {
                        None
                    };
                    let Some(data) = kind else {
                        continue;
                    };
                    if data {
                        written += 1;
                    } else {
                        zero_pages += 1;
                    }
                    let offset = slot_offset + (i * PAGE) as u64;
                    match runs.last_mut() {
                        Some(r)
                            if r.data == data
                                && r.offset + r.pages * PAGE as u64 == offset
                                && r.host + usize::try_from(r.pages).unwrap() * PAGE
                                    == host + i * PAGE
                                && r.pages < stream::MAX_RECORD_PAGES =>
                        {
                            r.pages += 1
                        }
                        _ => runs.push(PageRun {
                            offset,
                            host: host + i * PAGE,
                            pages: 1,
                            data,
                        }),
                    }
                }
            }
            region_offset += region.len();
        }
        let len = 16 * (runs.len() + 1) + usize::try_from(written).unwrap() * PAGE;
        let mut out = match self.checkpoint.spare.take() {
            Some(mut v)
                if v.capacity() >= len && (v.capacity() <= 4 * len || v.capacity() <= 64 << 20) =>
            {
                v.clear();
                v
            }
            _ => Vec::with_capacity(len),
        };
        for r in &runs {
            stream::record_head(
                &mut out,
                r.offset,
                u32::try_from(r.pages).unwrap(),
                if r.data {
                    stream::KIND_DATA
                } else {
                    stream::KIND_ZERO
                },
            );
            if r.data {
                // SAFETY: the run is plugged guest memory of this VMM; the vCPUs are stopped
                // and no device runs, so nothing writes it while it is copied.
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        r.host as *const u8,
                        usize::try_from(r.pages).unwrap() * PAGE,
                    )
                };
                out.extend_from_slice(bytes);
            }
        }
        stream::end_record(&mut out);
        Ok((out, written + zero_pages, written))
    }
}

#[cfg(test)]
mod tests;
