// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The lease of the held output, and its clock.
//!
//! The lease is kept by the signal and by nothing else: it runs until the lease time after the
//! send of the newest signal whose echo was read while the lease ran. Its first end is the lease
//! time after the stop of checkpoint 0 (for a guest that arrived: after its resume). An echo that
//! is read after the lease time is over renews nothing, so a VMM that stood still cannot make its
//! lease longer with echoes that waited in its socket. When the lease is over, a timer of the VMM
//! thread stops the guest, no further signal is sent, and from then on no answer releases
//! anything. So a receiving place that waits longer than the lease after the last echo that it
//! gave, by its own clock, knows that nothing leaves this VMM any more.
//!
//! The lease clock is the monotonic clock of this host, in milliseconds; it is compared with no
//! other clock. With the fault `lease-clock-held` (for tests) it does not count a time of 1 s or
//! more in which nothing read it: it stands still while this process is held, as the clock of a
//! server that is held does.
//!
//! This state is shared by the VMM thread (the timer, the answers), the sender thread (the
//! answers) and the signal thread (the echoes), under one lock.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use utils::time::{ClockType, get_time_ns};

/// The monotonic clock of the host, in milliseconds.
pub fn monotonic_ms() -> i64 {
    i64::try_from(get_time_ns(ClockType::Monotonic) / 1_000_000).unwrap_or(i64::MAX)
}

/// The host clock (`CLOCK_REALTIME`), in microseconds: the clock of the lines of the checkpoints
/// and of the packets.
pub fn host_us() -> i64 {
    i64::try_from(get_time_ns(ClockType::Real) / 1000).unwrap_or(i64::MAX)
}

#[derive(Debug, Default)]
struct LeaseState {
    /// A lease runs: the output is held under it.
    on: bool,
    /// The tracking armed it: it begins when the guest is resumed.
    armed: bool,
    /// It ended; only a release ends this state.
    over: bool,
    /// Its end, on the lease clock (ms).
    until: i64,
    /// The lease time.
    lease_ms: u32,
    /// The send time of the newest signal whose echo counted; None before the first.
    echo_sent: Option<i64>,
    /// Answers that were read after the lease ended.
    late: u64,
}

#[derive(Debug, Default)]
struct LeaseClock {
    raw: i64,
    skew: i64,
}

/// The lease, shared by the threads of the checkpoint loop.
#[derive(Debug, Default)]
pub struct Lease {
    state: Mutex<LeaseState>,
    clock: Mutex<LeaseClock>,
    held_fault: AtomicBool,
    // The lease clock of the last turn of the main loop of the VMM thread; the signal thread
    // sends only while it is young.
    beat: AtomicI64,
}

/// What `GET /space/checkpoint` says of the lease.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LeaseInfo {
    /// The lease time, or 0 with none.
    pub lease_ms: u32,
    /// The lease ended.
    pub over: bool,
    /// How long it still runs, while it runs.
    pub left_ms: Option<i64>,
    /// The time since the send of the newest signal whose echo counted.
    pub since_echo_ms: Option<i64>,
    /// Answers read after the end.
    pub late: u64,
}

impl Lease {
    /// A new lease that does not run.
    pub fn new() -> Arc<Lease> {
        Arc::new(Lease::default())
    }

    /// The lease clock (ms).
    pub fn now(&self) -> i64 {
        let raw = monotonic_ms();
        let mut clock = self.clock.lock().expect("Poisoned lock");
        if clock.raw != 0 && raw - clock.raw >= 1000 && self.held_fault.load(Ordering::Relaxed) {
            clock.skew += raw - clock.raw;
        }
        clock.raw = raw;
        raw - clock.skew
    }

    /// Turns the fault `lease-clock-held` on or off; it counts from here.
    pub fn set_held_fault(&self, on: bool) {
        self.now();
        self.held_fault.store(on, Ordering::Relaxed);
    }

    /// Whether the fault `lease-clock-held` is on.
    pub fn held_fault(&self) -> bool {
        self.held_fault.load(Ordering::Relaxed)
    }

    /// The main loop of the VMM thread turns now.
    pub fn stamp(&self) {
        self.beat.store(monotonic_ms(), Ordering::Release);
    }

    /// The monotonic clock (ms) of the last turn of the main loop.
    pub fn last_beat(&self) -> i64 {
        self.beat.load(Ordering::Acquire)
    }

    /// Begins the lease at `from` (lease clock) for `lease_ms`.
    pub fn begin(&self, from: i64, lease_ms: u32) {
        let mut s = self.state.lock().expect("Poisoned lock");
        s.on = true;
        s.armed = false;
        s.lease_ms = lease_ms;
        s.until = from + i64::from(lease_ms);
    }

    /// Arms the first lease of a guest that arrived: it begins at the resume.
    pub fn arm(&self, lease_ms: u32) {
        let mut s = self.state.lock().expect("Poisoned lock");
        s.armed = true;
        s.lease_ms = lease_ms;
    }

    /// The guest is resumed: an armed lease begins now.
    pub fn resumed(&self) {
        let now = self.now();
        let mut s = self.state.lock().expect("Poisoned lock");
        if s.armed && !s.over {
            s.on = true;
            s.armed = false;
            s.until = now + i64::from(s.lease_ms);
        }
    }

    /// Whether a lease runs, is armed, or is over.
    pub fn any(&self) -> bool {
        let s = self.state.lock().expect("Poisoned lock");
        s.on || s.armed || s.over
    }

    /// Whether a lease runs or is armed (the lease of a mode that starts goes on).
    pub fn on_or_armed(&self) -> bool {
        let s = self.state.lock().expect("Poisoned lock");
        s.on || s.armed
    }

    /// The lease time of a lease that runs or is armed, else 0: the lease that a mode that
    /// starts goes on with.
    pub fn current_lease_ms(&self) -> u32 {
        let s = self.state.lock().expect("Poisoned lock");
        if s.on || s.armed { s.lease_ms } else { 0 }
    }

    /// The lease time of a lease that runs, is armed or is over.
    pub fn lease_ms(&self) -> u32 {
        self.state.lock().expect("Poisoned lock").lease_ms
    }

    /// A lease is on and its time is over at `now` (the VMM thread has ended it, or will):
    /// no answer counts, no signal is sent, no echo renews.
    pub fn passed(&self, now: i64) -> bool {
        let s = self.state.lock().expect("Poisoned lock");
        s.over || (s.on && now > s.until)
    }

    /// Whether the lease ended.
    pub fn over(&self) -> bool {
        self.state.lock().expect("Poisoned lock").over
    }

    /// Ends the lease when its time is over; returns true when it ended now. Otherwise returns
    /// false and the time (ms) until its end, when it runs.
    pub fn end_if_passed(&self) -> (bool, Option<i64>) {
        let now = self.now();
        let mut s = self.state.lock().expect("Poisoned lock");
        if !s.on || s.over {
            return (false, None);
        }
        if now <= s.until {
            return (false, Some(s.until - now + 1));
        }
        s.over = true;
        (true, None)
    }

    /// The echo of the signal that was sent at `sent` (lease clock) was read. If the lease still
    /// runs now, its end becomes that send time plus the lease, when that is later. An echo does
    /// nothing else: it releases no frame.
    pub fn echo(&self, sent: i64) {
        let now = self.now();
        let mut s = self.state.lock().expect("Poisoned lock");
        if !s.over && !(s.on && now > s.until) {
            if s.on && sent + i64::from(s.lease_ms) > s.until {
                s.until = sent + i64::from(s.lease_ms);
            }
            if s.echo_sent.is_none_or(|old| sent > old) {
                s.echo_sent = Some(sent);
            }
        }
    }

    /// An answer was read after the lease time was over.
    pub fn count_late(&self) {
        self.state.lock().expect("Poisoned lock").late += 1;
    }

    /// The signal starts again: no echo has counted yet.
    pub fn forget_echoes(&self) {
        self.state.lock().expect("Poisoned lock").echo_sent = None;
    }

    /// Ends the lease and its armed state (a release).
    pub fn end(&self) {
        let mut s = self.state.lock().expect("Poisoned lock");
        s.on = false;
        s.armed = false;
        s.over = false;
    }

    /// What the query says.
    pub fn info(&self) -> LeaseInfo {
        let now = self.now();
        let s = self.state.lock().expect("Poisoned lock");
        LeaseInfo {
            lease_ms: if s.on || s.armed || s.over {
                s.lease_ms
            } else {
                0
            },
            over: s.over,
            left_ms: (s.on && !s.over).then(|| s.until - now),
            since_echo_ms: s.echo_sent.map(|sent| now - sent),
            late: s.late,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lease_from_an_echo() {
        let lease = Lease::new();
        let now = lease.now();
        lease.begin(now, 5000);
        assert!(!lease.passed(now + 5000));
        assert!(lease.passed(now + 5001));
        // An echo of a signal sent 1 s after the begin moves the end to its send plus the lease.
        lease.echo(now + 1000);
        assert!(!lease.passed(now + 5900));
        // An echo of an older signal does not move it back.
        lease.echo(now - 100);
        assert!(!lease.passed(now + 5900));
        assert!(lease.passed(now + 6001));
        let info = lease.info();
        assert_eq!(info.lease_ms, 5000);
        assert!(!info.over);
        assert!(info.left_ms.unwrap() > 5000);
        assert!(info.since_echo_ms.unwrap() <= 0);
    }

    #[test]
    fn test_an_echo_after_the_lease_changes_nothing() {
        let lease = Lease::new();
        let now = lease.now();
        // A lease of 50 ms that began 100 ms ago is over, also when the VMM thread has not
        // ended it yet.
        lease.begin(now - 100, 50);
        lease.echo(now - 10);
        assert!(lease.passed(lease.now()));
        assert_eq!(lease.info().since_echo_ms, None);
        assert_eq!(lease.end_if_passed(), (true, None));
        assert!(lease.over());
        // Over: an echo changes nothing; only an end (a release) ends this state.
        lease.echo(lease.now());
        assert!(lease.passed(lease.now()));
        lease.end();
        assert!(!lease.any());
    }

    #[test]
    fn test_armed_lease_begins_at_the_resume() {
        let lease = Lease::new();
        lease.arm(200);
        assert!(lease.any());
        assert!(!lease.passed(lease.now() + 10_000));
        assert_eq!(lease.end_if_passed(), (false, None));
        std::thread::sleep(std::time::Duration::from_millis(50));
        let at = lease.now();
        lease.resumed();
        assert!(!lease.passed(at + 200));
        assert!(lease.passed(at + 260));
    }

    #[test]
    fn test_held_clock() {
        let lease = Lease::new();
        lease.set_held_fault(true);
        let a = lease.now();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        // The time in which nothing read the clock is not counted.
        let b = lease.now();
        assert!(b - a < 50, "{a} {b}");
        lease.set_held_fault(false);
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(lease.now() - b >= 1100);
    }
}
