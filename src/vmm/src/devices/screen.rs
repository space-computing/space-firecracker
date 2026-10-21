// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The screen's thread (`fc_screen`): the event loop of the devices of a guest with a display.
//!
//! The screen's devices are the GPU device, its keyboard and tablet, its sound device and the
//! vsock device (which carries the guest agent's channel and the link of the renderer inside the
//! guest). Their events run here, on a thread of their own, and not on the VMM thread, so that
//! the host can count the screen's CPU to the guest (the thread goes into the guest's CPU group)
//! while the VMM thread, which stops the guest and copies the memory of a checkpoint, stays out
//! of it (the user's decision of 2026-10-15: the host carries the work of checkpoints).
//!
//! The VMM thread pauses the loop at every stop of the guest and waits for its answer before it
//! saves any device or KVM state ([`ScreenLoop::pause`]). Paused, the thread handles no event:
//! it writes no guest memory and moves no queue, until the VMM thread resumes it
//! ([`ScreenLoop::resume`]), after the copy of the memory and the reset of the dirty tracking.
//! A device that is locked only while its state is saved is not enough: once its lock is free,
//! its thread could take buffered traffic while the memory is copied, and the checkpoint would
//! hold the device's state and the memory of two moments. The block workers are paused at a
//! stop for the same reason.
//!
//! The thread is made at the build and at the restore of the VM, paused (the first resume of the
//! VM starts it), and applies the `vmm` seccomp filter: it runs the same device code as the VMM
//! thread did, and makes no thread.
//!
//! Two checks watch the pause. The witness, always on and cheap: the devices' places in their
//! queues at the acknowledged pause must be the same at the resume. The observation, for the
//! test of a checkpoint's consistency (on with [`OBSERVE_ENV`]`=1` when the thread is made; off it
//! costs nothing): at the acknowledged pause it hashes each guest page that the screen's devices
//! may write (their rings and descriptor tables, and the write-only buffers of every chain that
//! their available rings name), and again just before the resume; a page whose content changed
//! is logged. It also logs, at each pause, what moved since the last resume (the queues, the
//! pictures of the in-guest renderer passed on, the message ids of each renderer), so that the
//! test sees the traffic go on after each resume. The content of the pages, not the dirty log,
//! is observed: KVM's dirty log does not see the VMM's own writes, and the checkpoint resets and
//! marks again Firecracker's bitmap inside the interval.

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hasher};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::EventManager;
use crate::devices::virtio::gpu::GpuTraffic;
use crate::logger::{error, info, warn};
use crate::seccomp::BpfProgram;
use crate::vstate::memory::{Bytes, GuestAddress, GuestMemoryMmap};

/// The name of the thread (the host places it by name).
pub const SCREEN_THREAD_NAME: &str = "fc_screen";

/// A pause that has not been answered after this long is logged (and still waited for).
const PAUSE_WARN: Duration = Duration::from_secs(1);

/// The environment variable that turns the observation on (`1`): read when the thread is made.
pub const OBSERVE_ENV: &str = "SPACE_TEST_SCREEN_OBSERVE";

/// The size of the pages that the observation hashes.
const PAGE_BYTES: usize = 4096;
const PAGE: u64 = PAGE_BYTES as u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Want {
    Run,
    Pause,
    Exit,
}

#[derive(Debug)]
struct CtlState {
    want: Want,
    /// The thread is between two events and waits: no device of the loop runs.
    paused: bool,
}

#[derive(Debug)]
struct Ctl {
    st: Mutex<CtlState>,
    cond: Condvar,
    /// Wakes the thread out of its wait for events.
    wake: EventFd,
}

/// The loop's own event: it only wakes the thread, which then looks at what is wanted.
#[derive(Debug)]
struct Wake(EventFd);

impl MutEventSubscriber for Wake {
    fn init(&mut self, ops: &mut EventOps) {
        if let Err(err) = ops.add(Events::new(&self.0, EventSet::IN)) {
            error!("fc_screen: failed to register its wake event: {err}");
        }
    }

    fn process(&mut self, _events: Events, _ops: &mut EventOps) {
        let _ = self.0.read();
    }
}

/// The event loop moved to its thread.
struct Moved(EventManager);

// SAFETY: every subscriber of the loop is a device of the screen (a `VirtioDevice`, which is
// `Send`) or the loop's `Wake`; the same `Arc<Mutex<_>>` of each device that the device manager
// keeps is shared between threads already (the vCPU threads lock it). The epoll context is a file
// descriptor. Only the type `dyn MutEventSubscriber` lacks the bound.
unsafe impl Send for Moved {}

/// The screen's devices' places in their queues (by device) when a checkpoint's state was saved.
type Positions = Vec<Vec<(u16, u16)>>;

/// The check that no device of the screen moved a queue from the save of a checkpoint's state to the
/// resume: the device state of a checkpoint and the memory copied after it are of one moment.
#[derive(Debug, Default)]
struct Witness {
    mark: Option<(Instant, Positions)>,
    checked: u64,
    moved: u64,
}

/// A summary of the checks is logged after this many.
const WITNESS_SUMMARY: u64 = 60;

/// What the device manager reads of the screen's devices for the observation, at a pause and
/// at a resume.
#[derive(Debug, Default, Clone)]
pub struct Seen {
    /// The devices (type and id), in the order of the positions.
    pub devices: Vec<String>,
    /// The guest memory that each device may write: (device, queue, address, length, part).
    pub watched: Vec<(usize, usize, GuestAddress, usize, &'static str)>,
    /// The GPU device's pictures and message ids.
    pub traffic: GpuTraffic,
    /// Each device's chains made available by the guest and not taken yet, by queue.
    pub pending: Vec<Vec<u16>>,
    /// The vsock device's muxer holds data for the guest.
    pub vsock_rx_pending: bool,
}

/// The observation of one stop, from its acknowledged pause.
#[derive(Debug)]
struct Observed {
    stop: u64,
    at: Instant,
    devices: Vec<String>,
    /// Each page watched (its guest address), what it holds first (device, queue, part), and
    /// the hash of its content at the pause.
    pages: Vec<(u64, String, u64)>,
    bytes: u64,
}

/// The observation's state between stops.
#[derive(Debug, Default)]
struct Observer {
    stops: u64,
    open: Option<Observed>,
    /// The last resume: when, the places, the GPU's traffic.
    resumed: Option<(Instant, Positions, GpuTraffic)>,
}

/// The hash of a page's content (`None`: the page is not guest memory).
fn page_hash(mem: &GuestMemoryMmap, page: u64) -> Option<u64> {
    let mut buf = [0u8; PAGE_BYTES];
    mem.read_slice(&mut buf, GuestAddress(page)).ok()?;
    let mut h = DefaultHasher::new();
    h.write(&buf);
    Some(h.finish())
}

/// `a` less `b` for each queue's (next available, next used) of each device.
fn moved(a: &Positions, b: &Positions) -> Vec<Vec<(u16, u16)>> {
    a.iter()
        .zip(b)
        .map(|(x, y)| {
            x.iter()
                .zip(y)
                .map(|(p, q)| (p.0.wrapping_sub(q.0), p.1.wrapping_sub(q.1)))
                .collect()
        })
        .collect()
}

/// The handle of the screen's thread, kept by the device manager.
#[derive(Debug)]
pub struct ScreenLoop {
    ctl: Arc<Ctl>,
    witness: Mutex<Witness>,
    /// The observation, when it is on.
    observer: Option<Mutex<Observer>>,
}

impl ScreenLoop {
    /// Starts the thread with the event loop `em`, which holds the screen's devices, paused. It
    /// applies `filter` before anything else. The observation is on when [`OBSERVE_ENV`] is `1`.
    pub fn spawn(em: EventManager, filter: Arc<BpfProgram>) -> std::io::Result<ScreenLoop> {
        let observe = std::env::var(OBSERVE_ENV).is_ok_and(|v| v == "1");
        Self::spawn_with(em, filter, observe)
    }

    fn spawn_with(
        mut em: EventManager,
        filter: Arc<BpfProgram>,
        observe: bool,
    ) -> std::io::Result<ScreenLoop> {
        let wake = EventFd::new(libc::EFD_NONBLOCK)?;
        em.add_subscriber(Arc::new(Mutex::new(Wake(wake.try_clone()?))));
        let ctl = Arc::new(Ctl {
            st: Mutex::new(CtlState {
                want: Want::Pause,
                paused: false,
            }),
            cond: Condvar::new(),
            wake,
        });
        let moved = Moved(em);
        let thread_ctl = ctl.clone();
        let (ok_tx, ok_rx) = std::sync::mpsc::channel();
        thread::Builder::new()
            .name(SCREEN_THREAD_NAME.to_owned())
            .spawn(move || {
                let moved = moved;
                if let Err(err) = crate::seccomp::apply_filter(&filter) {
                    let _ = ok_tx.send(Err(err.to_string()));
                    return;
                }
                let _ = ok_tx.send(Ok(()));
                run(moved.0, &thread_ctl);
            })?;
        match ok_rx.recv() {
            Ok(Ok(())) => {
                if observe {
                    info!(
                        "{SCREEN_THREAD_NAME}: the observation of the stops is on ({OBSERVE_ENV})"
                    );
                }
                Ok(ScreenLoop {
                    ctl,
                    witness: Mutex::new(Witness::default()),
                    observer: observe.then(|| Mutex::new(Observer::default())),
                })
            }
            Ok(Err(e)) => Err(std::io::Error::other(format!(
                "{SCREEN_THREAD_NAME}: seccomp filter: {e}"
            ))),
            Err(_) => Err(std::io::Error::other(format!(
                "{SCREEN_THREAD_NAME}: thread ended"
            ))),
        }
    }

    /// Pauses the loop and returns once the thread has answered: from then on no device of the
    /// screen runs until [`Self::resume`]. A loop that is paused already returns at once. The
    /// caller holds no lock of a device (the thread may wait for one to end its event).
    pub fn pause(&self) {
        let t0 = Instant::now();
        let mut warned = false;
        let mut st = self.ctl.st.lock().expect("Poisoned lock");
        if st.want == Want::Exit {
            return;
        }
        st.want = Want::Pause;
        if !st.paused {
            let _ = self.ctl.wake.write(1);
        }
        while !st.paused {
            let (next, _) = self
                .ctl
                .cond
                .wait_timeout(st, PAUSE_WARN)
                .expect("Poisoned lock");
            st = next;
            if !st.paused && !warned && t0.elapsed() >= PAUSE_WARN {
                warned = true;
                warn!(
                    "{SCREEN_THREAD_NAME}: no answer to the pause after {} ms: still waiting",
                    t0.elapsed().as_millis()
                );
            }
        }
    }

    /// Lets the loop run again.
    pub fn resume(&self) {
        let mut st = self.ctl.st.lock().expect("Poisoned lock");
        if st.want == Want::Pause {
            st.want = Want::Run;
            self.ctl.cond.notify_all();
        }
    }

    /// Whether the thread is paused now (for tests and checks).
    pub fn is_paused(&self) -> bool {
        self.ctl.st.lock().expect("Poisoned lock").paused
    }

    /// Whether the observation is on: the device manager then gives [`Self::mark`] and
    /// [`Self::check`] what it reads of the devices.
    pub fn observing(&self) -> bool {
        self.observer.is_some()
    }

    /// The screen's devices' places in their queues at the acknowledged pause of a stop (the
    /// thread is paused), and with the observation on what it watches (`seen`, read from `mem`).
    /// The first mark of a stop counts.
    pub fn mark(&self, positions: Positions, seen: Option<(Seen, &GuestMemoryMmap)>) {
        let mut w = self.witness.lock().expect("Poisoned lock");
        if w.mark.is_some() {
            return;
        }
        w.mark = Some((Instant::now(), positions.clone()));
        drop(w);
        let (Some(observer), Some((seen, mem))) = (&self.observer, seen) else {
            return;
        };
        let mut o = observer.lock().expect("Poisoned lock");
        o.stops += 1;
        let mut pages: BTreeMap<u64, String> = BTreeMap::new();
        let mut bytes = 0u64;
        for (d, q, addr, len, part) in &seen.watched {
            bytes += *len as u64;
            if *len == 0 {
                continue;
            }
            let first = addr.0 & !(PAGE - 1);
            let last = (addr.0 + *len as u64 - 1) & !(PAGE - 1);
            let mut page = first;
            while page <= last {
                pages
                    .entry(page)
                    .or_insert_with(|| format!("{} q{q} {part}", seen.devices[*d]));
                page += PAGE;
            }
        }
        let pages: Vec<(u64, String, u64)> = pages
            .into_iter()
            .filter_map(|(page, what)| page_hash(mem, page).map(|h| (page, what, h)))
            .collect();
        // what moved since the last resume: the traffic of the interval before this stop
        let since = o.resumed.as_ref().map(|(t, before, traffic)| {
            serde_json::json!({
                "ms": u64::try_from(t.elapsed().as_millis()).unwrap_or(u64::MAX),
                "queues": moved(&positions, before),
                "pictures": seen.traffic.pictures.wrapping_sub(traffic.pictures),
                "user_sent": seen.traffic.user.0.wrapping_sub(traffic.user.0),
                "user_received": seen.traffic.user.1.wrapping_sub(traffic.user.1),
                "guest_sent": seen.traffic.guest.0.wrapping_sub(traffic.guest.0),
                "guest_received": seen.traffic.guest.1.wrapping_sub(traffic.guest.1),
            })
        });
        info!(
            "{SCREEN_THREAD_NAME}: observe pause {}",
            serde_json::json!({
                "stop": o.stops,
                "devices": seen.devices,
                "positions": positions,
                "pending": seen.pending,
                "vsock_rx_pending": seen.vsock_rx_pending,
                "pages": pages.len(),
                "watched_bytes": bytes,
                "since_resume": since,
            })
        );
        let open = Observed {
            stop: o.stops,
            at: Instant::now(),
            devices: seen.devices,
            pages,
            bytes,
        };
        o.open = Some(open);
    }

    /// At the resume, before any device runs again: the places must be those of the mark. A move is
    /// logged as an error; a summary every [`WITNESS_SUMMARY`] checks. With the observation on, the
    /// pages watched at the pause are hashed again (`seen`, from `mem`), and the stop is logged.
    /// Returns whether the places were the same and no page watched changed (true with no mark).
    pub fn check(&self, positions: Positions, seen: Option<(Seen, &GuestMemoryMmap)>) -> bool {
        let mut w = self.witness.lock().expect("Poisoned lock");
        let Some((t0, before)) = w.mark.take() else {
            return true;
        };
        w.checked += 1;
        let same = before == positions;
        if !same {
            w.moved += 1;
            error!(
                "{SCREEN_THREAD_NAME}: a queue of the screen's devices moved between the pause of a stop and its resume: {before:?} -> {positions:?}"
            );
        }
        if w.checked.is_multiple_of(WITNESS_SUMMARY) {
            info!(
                "{SCREEN_THREAD_NAME}: {} checkpoint stops checked, a queue of the screen moved in {}; the last from its pause to its resume {} us",
                w.checked,
                w.moved,
                t0.elapsed().as_micros()
            );
        }
        drop(w);
        let (Some(observer), Some((seen, mem))) = (&self.observer, seen) else {
            return same;
        };
        let mut o = observer.lock().expect("Poisoned lock");
        let Some(open) = o.open.take() else {
            return same;
        };
        let changed: Vec<serde_json::Value> = open
            .pages
            .iter()
            .filter(|(page, _, h)| page_hash(mem, *page) != Some(*h))
            .map(|(page, what, _)| serde_json::json!({"page": format!("{page:#x}"), "what": what}))
            .collect();
        let unchanged = changed.is_empty();
        let line = serde_json::json!({
            "stop": open.stop,
            "devices": open.devices,
            "paused_us": u64::try_from(open.at.elapsed().as_micros()).unwrap_or(u64::MAX),
            "pages": open.pages.len(),
            "watched_bytes": open.bytes,
            "changed": changed,
            "positions_at_pause": before,
            "positions_at_resume": positions,
            "positions_same": same,
        });
        if unchanged && same {
            info!("{SCREEN_THREAD_NAME}: observe resume {line}");
        } else {
            error!("{SCREEN_THREAD_NAME}: observe resume {line}");
        }
        o.resumed = Some((Instant::now(), positions, seen.traffic));
        same && unchanged
    }

    /// A save of a snapshot or of a move's state: the devices may work their queues in it (vsock
    /// sends its reset event, the GPU device drains its renderer), so the mark of the stop is
    /// dropped, and the stop is not observed.
    pub fn unmark(&self) {
        self.witness.lock().expect("Poisoned lock").mark = None;
        if let Some(observer) = &self.observer
            && let Some(open) = observer.lock().expect("Poisoned lock").open.take()
        {
            info!(
                "{SCREEN_THREAD_NAME}: observe stop {} not checked: the state of a snapshot or a move was saved",
                open.stop
            );
        }
    }

    /// (checked, moved) so far.
    pub fn witnessed(&self) -> (u64, u64) {
        let w = self.witness.lock().expect("Poisoned lock");
        (w.checked, w.moved)
    }
}

impl Drop for ScreenLoop {
    fn drop(&mut self) {
        let mut st = self.ctl.st.lock().expect("Poisoned lock");
        st.want = Want::Exit;
        self.ctl.cond.notify_all();
        let _ = self.ctl.wake.write(1);
    }
}

fn run(mut em: EventManager, ctl: &Ctl) {
    loop {
        {
            let mut st = ctl.st.lock().expect("Poisoned lock");
            if st.want == Want::Pause {
                st.paused = true;
                ctl.cond.notify_all();
                while st.want == Want::Pause {
                    st = ctl.cond.wait(st).expect("Poisoned lock");
                }
                st.paused = false;
            }
            if st.want == Want::Exit {
                return;
            }
        }
        // Every event that is ready is handled, then the loop looks at what is wanted again: a
        // pause waits at most for the events of one wait.
        if let Err(err) = em.run() {
            error!("{SCREEN_THREAD_NAME}: event loop: {err:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::*;

    /// A device of the test: counts its events; each event takes `busy`, and marks while it
    /// runs.
    struct Counter {
        evt: EventFd,
        n: Arc<AtomicU64>,
        inside: Arc<AtomicBool>,
        busy: Duration,
    }

    impl MutEventSubscriber for Counter {
        fn init(&mut self, ops: &mut EventOps) {
            ops.add(Events::new(&self.evt, EventSet::IN)).unwrap();
        }

        fn process(&mut self, _events: Events, _ops: &mut EventOps) {
            self.inside.store(true, Ordering::SeqCst);
            let _ = self.evt.read();
            thread::sleep(self.busy);
            self.n.fetch_add(1, Ordering::SeqCst);
            self.inside.store(false, Ordering::SeqCst);
        }
    }

    fn setup(busy: Duration) -> (ScreenLoop, EventFd, Arc<AtomicU64>, Arc<AtomicBool>) {
        let mut em = EventManager::new().unwrap();
        let evt = EventFd::new(libc::EFD_NONBLOCK).unwrap();
        let n = Arc::new(AtomicU64::new(0));
        let inside = Arc::new(AtomicBool::new(false));
        em.add_subscriber(Arc::new(Mutex::new(Counter {
            evt: evt.try_clone().unwrap(),
            n: n.clone(),
            inside: inside.clone(),
            busy,
        })));
        let l = ScreenLoop::spawn(em, Arc::new(vec![])).unwrap();
        (l, evt, n, inside)
    }

    fn wait_for(f: impl Fn() -> bool) -> bool {
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(5) {
            if f() {
                return true;
            }
            thread::sleep(Duration::from_millis(1));
        }
        false
    }

    #[test]
    fn the_loop_starts_paused_and_runs_after_the_first_resume() {
        let (l, evt, n, _) = setup(Duration::ZERO);
        assert!(wait_for(|| l.is_paused()));
        evt.write(1).unwrap();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            n.load(Ordering::SeqCst),
            0,
            "an event ran before the resume"
        );
        l.resume();
        assert!(wait_for(|| n.load(Ordering::SeqCst) == 1));
        assert!(!l.is_paused());
    }

    #[test]
    fn a_paused_loop_handles_no_event_until_it_resumes() {
        let (l, evt, n, _) = setup(Duration::ZERO);
        l.resume();
        evt.write(1).unwrap();
        assert!(wait_for(|| n.load(Ordering::SeqCst) == 1));
        for round in 0..20u64 {
            l.pause();
            assert!(l.is_paused());
            // traffic that arrives while it is paused waits
            evt.write(1).unwrap();
            thread::sleep(Duration::from_millis(5));
            assert_eq!(n.load(Ordering::SeqCst), 1 + round);
            l.resume();
            assert!(wait_for(|| n.load(Ordering::SeqCst) == 2 + round));
        }
    }

    #[test]
    fn a_pause_waits_for_the_event_in_work() {
        let (l, evt, n, inside) = setup(Duration::from_millis(100));
        l.resume();
        evt.write(1).unwrap();
        assert!(wait_for(|| inside.load(Ordering::SeqCst)));
        l.pause();
        // the answer comes only after the event in work has ended
        assert!(!inside.load(Ordering::SeqCst));
        assert_eq!(n.load(Ordering::SeqCst), 1);
        l.resume();
    }

    #[test]
    fn pauses_and_resumes_are_idempotent() {
        let (l, evt, n, _) = setup(Duration::ZERO);
        l.pause();
        l.pause();
        l.resume();
        l.resume();
        evt.write(1).unwrap();
        assert!(wait_for(|| n.load(Ordering::SeqCst) == 1));
        // a pause then a resume then a pause before the thread woke: it stays paused
        l.pause();
        l.resume();
        l.pause();
        evt.write(1).unwrap();
        thread::sleep(Duration::from_millis(20));
        assert_eq!(n.load(Ordering::SeqCst), 1);
        assert!(l.is_paused());
        l.resume();
        assert!(wait_for(|| n.load(Ordering::SeqCst) == 2));
    }

    #[test]
    fn the_witness_counts_a_queue_that_moved_from_the_pause_to_the_resume() {
        let l = ScreenLoop::spawn(EventManager::new().unwrap(), Arc::new(vec![])).unwrap();
        // no mark (a stop that saved no checkpoint): nothing checked
        assert!(l.check(vec![vec![(1, 1)]], None));
        assert_eq!(l.witnessed(), (0, 0));
        l.mark(vec![vec![(3, 2)], vec![(7, 7), (0, 0)]], None);
        // a second mark in the same stop keeps the first
        l.mark(vec![vec![(9, 9)]], None);
        assert!(l.check(vec![vec![(3, 2)], vec![(7, 7), (0, 0)]], None));
        l.mark(vec![vec![(3, 2)]], None);
        assert!(!l.check(vec![vec![(3, 3)]], None));
        assert_eq!(l.witnessed(), (2, 1));
    }

    #[test]
    fn the_observation_sees_a_write_to_a_watched_page_between_the_pause_and_the_resume() {
        let mem = crate::test_utils::single_region_mem(0x10000);
        let l =
            ScreenLoop::spawn_with(EventManager::new().unwrap(), Arc::new(vec![]), true).unwrap();
        assert!(l.observing());
        let seen = Seen {
            devices: vec!["Vsock:vsock".into()],
            // a ring within one page and a buffer over two
            watched: vec![
                (0, 0, GuestAddress(0x1010), 0x20, "used"),
                (0, 0, GuestAddress(0x2f00), 0x200, "buffer"),
            ],
            traffic: GpuTraffic::default(),
            pending: vec![vec![0]],
            vsock_rx_pending: false,
        };
        let at = || vec![vec![(5, 4)]];
        let open_pages = |l: &ScreenLoop| {
            let o = l.observer.as_ref().unwrap().lock().unwrap();
            o.open
                .as_ref()
                .map(|x| x.pages.iter().map(|p| p.0).collect::<Vec<_>>())
        };
        // nothing written: the same
        l.mark(at(), Some((seen.clone(), &mem)));
        assert_eq!(open_pages(&l), Some(vec![0x1000, 0x2000, 0x3000]));
        assert!(l.check(at(), Some((seen.clone(), &mem))));
        // a write into the second page of the buffer while the stop lasts
        l.mark(at(), Some((seen.clone(), &mem)));
        mem.write_obj(0xabu8, GuestAddress(0x3004)).unwrap();
        assert!(!l.check(at(), Some((seen.clone(), &mem))));
        // a write outside the watched pages, or after the resume, is not the stop's
        mem.write_obj(0xcdu8, GuestAddress(0x5000)).unwrap();
        l.mark(at(), Some((seen.clone(), &mem)));
        assert!(l.check(at(), Some((seen.clone(), &mem))));
        // the witness counted them all, with no queue moved
        assert_eq!(l.witnessed(), (3, 0));
        // a snapshot's save drops the stop's observation: its devices may write
        l.mark(at(), Some((seen.clone(), &mem)));
        l.unmark();
        mem.write_obj(0xefu8, GuestAddress(0x1010)).unwrap();
        assert!(l.check(at(), Some((seen, &mem))));
        assert_eq!(l.witnessed(), (3, 0));
    }

    #[test]
    fn the_observation_is_off_by_default() {
        let l = ScreenLoop::spawn(EventManager::new().unwrap(), Arc::new(vec![])).unwrap();
        assert_eq!(
            l.observing(),
            std::env::var(OBSERVE_ENV).is_ok_and(|v| v == "1")
        );
        let l =
            ScreenLoop::spawn_with(EventManager::new().unwrap(), Arc::new(vec![]), false).unwrap();
        assert!(!l.observing());
        // with no observation a mark and a check are the witness's only
        l.mark(vec![vec![(1, 1)]], None);
        assert!(l.check(vec![vec![(1, 1)]], None));
    }

    #[test]
    fn the_thread_is_named_for_the_host() {
        let em = EventManager::new().unwrap();
        let l = ScreenLoop::spawn(em, Arc::new(vec![])).unwrap();
        assert!(wait_for(|| l.is_paused()));
        let found = std::fs::read_dir("/proc/self/task").unwrap().any(|t| {
            let p = t.unwrap().path().join("comm");
            std::fs::read_to_string(p).is_ok_and(|c| c.trim() == SCREEN_THREAD_NAME)
        });
        assert!(found);
    }
}
