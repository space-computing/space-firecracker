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

use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use event_manager::{EventOps, Events, MutEventSubscriber, SubscriberOps};
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use crate::EventManager;
use crate::logger::{error, warn};
use crate::seccomp::BpfProgram;

/// The name of the thread (the host places it by name).
pub const SCREEN_THREAD_NAME: &str = "fc_screen";

/// A pause that has not been answered after this long is logged (and still waited for).
const PAUSE_WARN: Duration = Duration::from_secs(1);

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

/// The handle of the screen's thread, kept by the device manager.
#[derive(Debug)]
pub struct ScreenLoop {
    ctl: Arc<Ctl>,
}

impl ScreenLoop {
    /// Starts the thread with the event loop `em`, which holds the screen's devices, paused. It
    /// applies `filter` before anything else.
    pub fn spawn(mut em: EventManager, filter: Arc<BpfProgram>) -> std::io::Result<ScreenLoop> {
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
            Ok(Ok(())) => Ok(ScreenLoop { ctl }),
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
        assert_eq!(n.load(Ordering::SeqCst), 0, "an event ran before the resume");
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
