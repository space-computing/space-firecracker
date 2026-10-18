// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checkpoints by need: when the next checkpoint of the loop begins.
//!
//! The loop takes its checkpoints by the clock, one at each interval, unless the mode by need is
//! set (`need` of `PUT /space/checkpoint`). Then it asks this file. A checkpoint is needed before
//! output leaves; a guest that sends nothing needs one only to bound the work that is done again
//! after a loss. The answer to the last checkpoint is in hand when the loop asks: at most one
//! checkpoint is on its way. A checkpoint begins at the first of these moments:
//!
//! - `idle`: a packet waits that no checkpoint covers, and the guest is idle: each vCPU waits,
//!   at two looks in a row. At once: such a guest loses nothing by the stop and has changed few
//!   pages.
//! - `budget`: a packet waits, the guest is busy, and the account is at zero or above. The
//!   account alone decides here; the clock does not count.
//! - `clock`: nothing waits, and the interval is over since the begin of the last checkpoint.
//!
//! No checkpoint is taken to keep a lease: the lease is kept by the signal.
//!
//! The account is a number of microseconds; under zero it is a debt.
//! 1. It starts at the cap.
//! 2. It gains the budget share (10%) of the time that passes. A gain does not lift it over the
//!    cap: the cap limits what is saved up, not a debt.
//! 3. The cost of a checkpoint is its pages times the page cost (what the guest pays for the
//!    first write of each page after the checkpoint), plus its stop when the guest was busy at
//!    its begin. The pages are those that the guest wrote: a page that the guest freed and that
//!    the balloon gave back is sent too, and the guest paid nothing for it.
//! 4. A checkpoint that begins with the account at zero or above takes its cost from it. The
//!    account can go under zero by any quantity.
//! 5. A checkpoint that begins with the account under zero sets it to the lower of the account
//!    and minus its cost.
//! 6. `budget` is permitted when the account is at zero or above.
//!
//! So a guest that is busy with output that waits gets one checkpoint each 10 times its cost,
//! and a debt is never more than the cost of the most expensive checkpoint since the account was
//! last at zero.
//!
//! `clock` asks for a checkpoint at a fixed time, and the account can be under zero then (a
//! guest whose one checkpoint costs more than the cap). Which of the two wins is the setting
//! `first`: `time` (the clock: at the interval, whatever the account holds) or `budget` (the
//! account: at the interval when it is at zero or above, and else when it is at zero again).

/// Why a checkpoint begins in the mode by need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedReason {
    /// Output waits and the guest is idle.
    Idle,
    /// Output waits, the guest is busy, and the account permits it.
    Budget,
    /// Nothing waits and the interval is over.
    Clock,
}

impl NeedReason {
    /// The word of the reason in the line of a checkpoint.
    pub fn as_str(self) -> &'static str {
        match self {
            NeedReason::Idle => "idle",
            NeedReason::Budget => "budget",
            NeedReason::Clock => "clock",
        }
    }
}

/// The settings of the mode by need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedConfig {
    /// The time of `clock`, in microseconds.
    pub interval_us: i64,
    /// The share of its time that a busy guest may lose.
    pub budget_pct: u32,
    /// The account saves up no more than this.
    pub cap_us: i64,
    /// What the first write of a page costs the guest, in nanoseconds.
    pub page_ns: u64,
    /// `clock` waits until the account is at zero.
    pub first_budget: bool,
    /// The time between two looks at the vCPUs.
    pub look_us: i64,
    /// A guest that is not idle this long after the first packet is busy.
    pub busy_us: i64,
}

/// The account and the looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeedState {
    /// Under zero: a debt.
    pub account_us: i64,
    /// The account has its gain up to here.
    t_account: i64,
    /// Looks in a row that found each vCPU waiting.
    idle_looks: u32,
    t_look: i64,
}

/// What the decision says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A checkpoint begins now; `busy` says whether the guest was busy.
    Take {
        /// Why.
        reason: NeedReason,
        /// The guest was busy.
        busy: bool,
    },
    /// Not yet: the loop may sleep this long (when nothing waits, a packet wakes it).
    Wait(i64),
}

impl NeedState {
    /// The account at the start of the mode: the cap.
    pub fn start(c: &NeedConfig, now: i64) -> NeedState {
        NeedState {
            account_us: c.cap_us,
            t_account: now,
            idle_looks: 0,
            t_look: 0,
        }
    }

    /// Line 2 of the account.
    fn gain(&mut self, c: &NeedConfig, now: i64) {
        if now <= self.t_account {
            return;
        }
        let pct = i64::from(c.budget_pct);
        let gain = (now - self.t_account) * pct / 100;
        // Only the time that this gain stands for is used up: the rest counts at the next look.
        // (While a packet waits the loop looks each 200 us or so; a gain that is rounded down at
        // each look is some percent short.)
        self.t_account += gain * 100 / pct;
        if self.account_us < c.cap_us {
            self.account_us = (self.account_us + gain).min(c.cap_us);
        }
    }

    /// How long until the account is at zero.
    fn debt_time(&self, c: &NeedConfig) -> i64 {
        if self.account_us >= 0 {
            0
        } else {
            let pct = i64::from(c.budget_pct);
            (-self.account_us * 100 + pct - 1) / pct
        }
    }

    /// Whether a checkpoint begins now. Asked only when the answer to the last checkpoint is in
    /// hand. `now` and `t_begin` (the begin of the last checkpoint) are microseconds of one
    /// clock; `waiting` is the number of packets that no checkpoint covers and `first_us` the
    /// time of the first of them; `idle` looks at the vCPUs (each waits, or a command stopped
    /// the guest).
    pub fn decide(
        &mut self,
        c: &NeedConfig,
        now: i64,
        waiting: u64,
        first_us: i64,
        t_begin: i64,
        mut idle: impl FnMut() -> bool,
    ) -> Decision {
        self.gain(c, now);
        let ok = self.account_us >= 0;

        if waiting > 0 {
            if now - self.t_look < c.look_us * 3 / 4 {
                // Two looks are one look time apart.
                return Decision::Wait(c.look_us - (now - self.t_look));
            }
            self.t_look = now;
            let is_idle = idle();
            self.idle_looks = if is_idle { self.idle_looks + 1 } else { 0 };
            if self.idle_looks >= 2 {
                self.idle_looks = 0;
                return Decision::Take {
                    reason: NeedReason::Idle,
                    busy: false,
                };
            }
            if !is_idle && ok && now - first_us >= c.busy_us {
                return Decision::Take {
                    reason: NeedReason::Budget,
                    busy: true,
                };
            }
            return Decision::Wait(c.look_us);
        }

        self.idle_looks = 0;
        let mut t_clock = t_begin + c.interval_us;
        if now >= t_clock && (ok || !c.first_budget) {
            return Decision::Take {
                reason: NeedReason::Clock,
                busy: !idle(),
            };
        }
        if c.first_budget {
            t_clock = t_clock.max(now + self.debt_time(c));
        }
        Decision::Wait((t_clock - now).max(50))
    }

    /// A checkpoint begins at `t_begin`: returns the account at that moment.
    pub fn begin(&mut self, c: &NeedConfig, t_begin: i64) -> i64 {
        self.gain(c, t_begin);
        self.idle_looks = 0;
        self.account_us
    }

    /// Lines 3 to 5 of the account: the checkpoint that began with `before` cost `pages` written
    /// pages and a stop of `stop_us` (counted when the guest was busy). Returns the account
    /// after it. The time of the stop gains as each other.
    pub fn paid(
        &mut self,
        c: &NeedConfig,
        before: i64,
        pages: u64,
        stop_us: i64,
        busy: bool,
    ) -> i64 {
        let cost = i64::try_from(pages.saturating_mul(c.page_ns) / 1000).unwrap_or(i64::MAX)
            + if busy { stop_us } else { 0 };
        self.account_us = if before >= 0 {
            before - cost
        } else {
            before.min(-cost)
        };
        self.account_us
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> NeedConfig {
        NeedConfig {
            interval_us: 2_000_000,
            budget_pct: 10,
            cap_us: 200_000,
            page_ns: 2000,
            first_budget: false,
            look_us: 200,
            busy_us: 1000,
        }
    }

    #[test]
    fn test_idle_at_two_looks_in_a_row() {
        let c = config();
        let mut n = NeedState::start(&c, 0);
        // A packet waits; the first look finds the guest idle: not yet.
        assert_eq!(n.decide(&c, 1000, 1, 1000, 0, || true), Decision::Wait(200));
        // Too early for the second look.
        assert_eq!(n.decide(&c, 1100, 1, 1000, 0, || true), Decision::Wait(100));
        // The second look: idle at two looks in a row.
        assert_eq!(
            n.decide(&c, 1200, 1, 1000, 0, || true),
            Decision::Take {
                reason: NeedReason::Idle,
                busy: false
            }
        );
        // A look in between that is not idle starts the count again.
        let mut n = NeedState::start(&c, 0);
        n.decide(&c, 1000, 1, 1000, 0, || true);
        n.decide(&c, 1200, 1, 1000, 0, || false);
        assert_eq!(n.decide(&c, 1400, 1, 1000, 0, || true), Decision::Wait(200));
    }

    #[test]
    fn test_budget_when_busy_and_the_account_permits() {
        let c = config();
        let mut n = NeedState::start(&c, 0);
        // Busy, but not yet busy-us after the first packet.
        assert_eq!(n.decide(&c, 1000, 3, 500, 0, || false), Decision::Wait(200));
        assert_eq!(
            n.decide(&c, 1600, 3, 500, 0, || false),
            Decision::Take {
                reason: NeedReason::Budget,
                busy: true
            }
        );
        // With a debt the account alone decides: no budget until it is at zero again.
        let before = n.begin(&c, 1600);
        assert_eq!(before, 200_000);
        // 150,000 pages at 2 us each and a stop of 5 ms: 305 ms; from 200 ms: a debt of 105 ms.
        assert_eq!(n.paid(&c, before, 150_000, 5000, true), -105_000);
        // 10% of the time: the debt is paid after 1.05 s.
        assert_eq!(
            n.decide(&c, 1_000_000, 3, 900_000, 1600, || false),
            Decision::Wait(200)
        );
        assert!(matches!(
            n.decide(&c, 1_060_000, 3, 900_000, 1600, || false),
            Decision::Take {
                reason: NeedReason::Budget,
                ..
            }
        ));
    }

    #[test]
    fn test_clock_and_first() {
        let mut c = config();
        let mut n = NeedState::start(&c, 0);
        // Nothing waits: the clock at the interval after the begin of the last checkpoint.
        assert_eq!(
            n.decide(&c, 500_000, 0, 0, 0, || true),
            Decision::Wait(1_500_000)
        );
        assert_eq!(
            n.decide(&c, 2_000_000, 0, 0, 0, || true),
            Decision::Take {
                reason: NeedReason::Clock,
                busy: false
            }
        );
        // An account under zero: with `time` the clock wins, with `budget` the account.
        let before = n.begin(&c, 0);
        n.paid(&c, before, 500_000, 0, false);
        assert_eq!(n.account_us, -800_000);
        assert!(matches!(
            n.decide(&c, 2_000_000, 0, 0, 0, || true),
            Decision::Take {
                reason: NeedReason::Clock,
                ..
            }
        ));
        c.first_budget = true;
        let mut n = NeedState::start(&c, 0);
        let before = n.begin(&c, 0);
        n.paid(&c, before, 500_000, 0, false);
        // The debt of 800 ms is paid 8 s after its begin.
        match n.decide(&c, 2_000_000, 0, 0, 0, || true) {
            Decision::Wait(us) => assert!((5_900_000..=6_000_100).contains(&us), "{us}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            n.decide(&c, 8_000_100, 0, 0, 0, || true),
            Decision::Take {
                reason: NeedReason::Clock,
                ..
            }
        ));
    }

    #[test]
    fn test_account_gain_and_cap() {
        let c = config();
        let mut n = NeedState::start(&c, 0);
        let before = n.begin(&c, 0);
        assert_eq!(n.paid(&c, before, 50_000, 0, false), 100_000);
        // 10% of 3 s is 300 ms; the cap keeps 200 ms.
        n.gain(&c, 3_000_000);
        assert_eq!(n.account_us, 200_000);
        // A debt is not limited by the cap, and a checkpoint that begins under zero sets the
        // account to the lower of the account and minus its cost.
        assert_eq!(n.paid(&c, -50_000, 10_000, 0, false), -50_000);
        assert_eq!(n.paid(&c, -50_000, 100_000, 0, false), -200_000);
        // The stop counts only when the guest was busy.
        assert_eq!(n.paid(&c, 200_000, 0, 7000, true), 193_000);
        assert_eq!(n.paid(&c, 200_000, 0, 7000, false), 200_000);
    }

    #[test]
    fn test_gain_is_not_rounded_away() {
        let c = config();
        let mut n = NeedState::start(&c, 0);
        n.account_us = -100_000;
        // Looks each 7 us: each gain is rounded down, but the time it stands for is kept.
        let mut now = 0;
        while n.account_us < 0 {
            now += 7;
            n.gain(&c, now);
        }
        // 100 ms of debt at 10% is paid in 1 s, not later.
        assert!((1_000_000..1_000_020).contains(&now), "{now}");
    }
}
