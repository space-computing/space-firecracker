// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The bodies of the `/space/checkpoint` endpoints. The members and fields are those of the QMP
//! commands `x-checkpoint-set`, `x-checkpoint-track`, `x-checkpoint-finish` and
//! `x-query-checkpoint` of the QEMU fork, spelled as there (kebab case), and `uri` for the
//! receiving place (in QMP, the URI of `migrate`).

use serde::{Deserialize, Serialize};

/// In the mode by need: which wins when nothing waits, the interval is over and the account is
/// under zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointFirst {
    /// The checkpoint begins at the interval, whatever the account holds.
    Time,
    /// The checkpoint begins when the account is at zero again.
    Budget,
}

/// `PUT /space/checkpoint`: the members of `x-checkpoint-set`, and `uri`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CheckpointSetParams {
    /// The time from one checkpoint to the next (with `need`: when no frame waits); 0: off.
    pub interval_ms: u32,
    /// An answer that does not come for this long sets `lost` (default 1000).
    pub lost_ms: Option<u32>,
    /// The unix socket of the hook of a disk program.
    pub hook: Option<String>,
    /// A file that gets one line for each answered checkpoint.
    pub stats: Option<String>,
    /// The frames that the guest sends are held (default true).
    pub hold: Option<bool>,
    /// Taken for the members of QMP; the stop of a checkpoint always stops the vCPUs only.
    pub cpus_only: Option<bool>,
    /// For tests only: `stale-clock`, `zero-cpu`, `internal-error`, `lease-clock-held`,
    /// `stop-held`; "" turns it off.
    pub fault: Option<String>,
    /// The stream continues the stream of another VMM.
    #[serde(rename = "continue")]
    pub cont: Option<bool>,
    /// With `continue`: the last checkpoint of the other VMM.
    pub epoch: Option<u64>,
    /// With `hold`: the lease.
    pub lease_ms: Option<u32>,
    /// The mode by need.
    pub need: Option<bool>,
    /// The share of its time that a busy guest may lose (default 10).
    pub budget_pct: Option<u32>,
    /// The account saves up no more than this (default 200).
    pub cap_ms: Option<u32>,
    /// What the first write of a page costs the guest (default 2000).
    pub page_ns: Option<u32>,
    /// Which wins when nothing waits and the account is under zero (default `time`).
    pub first: Option<CheckpointFirst>,
    /// The time between two looks at the vCPUs (default 200).
    pub look_us: Option<u32>,
    /// A guest that is not idle this long after the first frame is busy (default 1000).
    pub busy_us: Option<u32>,
    /// For checks only: a file that gets one line for each held frame.
    pub packets: Option<String>,
    /// The identity of the receiving place, 32 hex characters.
    pub stream_id: Option<String>,
    /// The time between two signals (default 500); 0: no signal, only with no lease.
    pub signal_ms: Option<u32>,
    /// The receiving place, `tcp:ADDRESS:PORT`: it starts the mode.
    pub uri: Option<String>,
}

/// `PUT /space/checkpoint/track`: the members of `x-checkpoint-track`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CheckpointTrackParams {
    /// Turns the tracking of changed pages on (on a stopped guest) or off.
    pub enable: bool,
    /// The frames that the guest sends are held from now on (default false).
    pub hold: Option<bool>,
    /// With `hold`: the first lease begins at the resume and runs this long.
    pub lease_ms: Option<u32>,
}

/// The answer of `PUT /space/checkpoint/finish`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct CheckpointFinish {
    /// The number of the last checkpoint.
    pub epoch: u64,
    /// It was answered (always true).
    pub acked: bool,
}

/// `GET /space/checkpoint`: the fields of `x-query-checkpoint`, but `incoming` and
/// `incoming-pages`, which are the UFFD handler's on Firecracker.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct CheckpointInfo {
    /// The mode was set with an interval.
    pub enabled: bool,
    /// The loop runs.
    pub active: bool,
    /// The interval.
    pub interval_ms: u32,
    /// The frames of the guest are held.
    pub hold: bool,
    /// The newest checkpoint that went out.
    pub sent: u64,
    /// The newest checkpoint that was answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acked: Option<u64>,
    /// An answer is overdue, or the stream or the hook ended.
    pub lost: bool,
    /// Why `lost` was set last.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The time since the last answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_ack_ms: Option<i64>,
    /// How long the guest stood for the newest checkpoint.
    pub stop_us: i64,
    /// The time from the send of a checkpoint to its answer, for the newest answer.
    pub ack_us: i64,
    /// The pages of the newest checkpoint.
    pub pages: u64,
    /// Its bytes.
    pub bytes: u64,
    /// Frames that wait now.
    pub packets_held: u64,
    /// Frames that were lost because too many waited.
    pub packets_dropped: u64,
    /// The tracking runs with no stream, or a continued stream runs.
    pub tracking: bool,
    /// The checkpoints that went out since the mode or the tracking began.
    pub checkpoints: u64,
    /// Their pages.
    pub total_pages: u64,
    /// Their bytes.
    pub total_bytes: u64,
    /// The time for which they stopped the guest.
    pub total_stop_us: u64,
    /// A finish ended the mode with this checkpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_epoch: Option<u64>,
    /// Frames that were thrown away at an end with no release.
    pub packets_discarded: u64,
    /// The frames that the guest sends wait now.
    pub holding: bool,
    /// The lease, or 0 with none.
    pub lease_ms: u32,
    /// The lease ended.
    pub lease_over: bool,
    /// How long the lease still runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_left_ms: Option<i64>,
    /// Answers that were read after the lease ended.
    pub late: u64,
    /// The mode by need.
    pub need: bool,
    /// With `need`: the setting of `first`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<CheckpointFirst>,
    /// With `need`, while the loop runs: the account after the newest checkpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_us: Option<i64>,
    /// The identity of the receiving place.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    /// The time between two signals (0: the mode is off, or it has no signal).
    pub signal_ms: u32,
    /// The time since the send of the newest signal whose echo counted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since_echo_ms: Option<i64>,
    /// The time since the begin of a checkpoint whose answer has not counted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unanswered_ms: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_bodies() {
        let p: CheckpointSetParams = serde_json::from_str(
            r#"{"interval-ms": 2000, "lost-ms": 15000, "hold": true, "cpus-only": true,
                "continue": true, "epoch": 7, "lease-ms": 5000, "need": true, "budget-pct": 10,
                "first": "budget", "stream-id": "0123456789abcdef0123456789abcdef",
                "signal-ms": 500, "uri": "tcp:10.0.0.1:7000"}"#,
        )
        .unwrap();
        assert_eq!(p.interval_ms, 2000);
        assert_eq!(p.cont, Some(true));
        assert_eq!(p.first, Some(CheckpointFirst::Budget));
        assert_eq!(p.uri.as_deref(), Some("tcp:10.0.0.1:7000"));
        serde_json::from_str::<CheckpointSetParams>(r#"{"interval-ms": 1, "other": 1}"#)
            .unwrap_err();
        serde_json::from_str::<CheckpointSetParams>(r#"{"lost-ms": 1}"#).unwrap_err();
        let t: CheckpointTrackParams =
            serde_json::from_str(r#"{"enable": true, "hold": true, "lease-ms": 5000}"#).unwrap();
        assert_eq!(t.lease_ms, Some(5000));

        let info = CheckpointInfo {
            acked: Some(4),
            lease_left_ms: Some(4100),
            first: Some(CheckpointFirst::Time),
            ..Default::default()
        };
        let v = serde_json::to_value(info).unwrap();
        assert_eq!(v["acked"], 4);
        assert_eq!(v["lease-left-ms"], 4100);
        assert_eq!(v["first"], "time");
        assert_eq!(v["packets-held"], 0);
        assert!(v.get("reason").is_none());
        assert_eq!(
            serde_json::to_value(CheckpointFinish {
                epoch: 9,
                acked: true
            })
            .unwrap(),
            serde_json::json!({"epoch": 9, "acked": true})
        );
    }
}
