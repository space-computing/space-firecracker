// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

/// The defaults of the QEMU fork's remote GPU source (`SPACEBOX_GPU_REMOTE_*`).
const DEFAULT_FENCE_WINDOW: u32 = 8;
const DEFAULT_FENCE_AGE_MS: u32 = 20;
const DEFAULT_TX_LIMIT_MIB: u32 = 8;
const DEFAULT_ZSTD_LEVEL: i32 = 1;
const MAX_ZSTD_LEVEL: i32 = 19;

/// The GPU device: a virtio-gpu device (virgl) whose commands are rendered by a renderer
/// outside Firecracker (the sink of the Spacebox QEMU fork), reached through a unix socket.
/// The strongly typed equivalent of the body of `PUT /gpu` and of the config file's `gpu`.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GpuConfig {
    /// The unix socket of the renderer. The device connects to it, and again every 250 ms
    /// while it is not there or after the connection was lost.
    pub socket_path: String,
    /// The GPU spec: what the guest is shown of the GPU (its capsets), in the format of the
    /// capset profile of the spacebox repository (`screen/spec/`). The device answers the
    /// guest's capset queries from it from the start, with no renderer, and every renderer
    /// checks at its pairing that it can do all of it. Read when the device is made; a snapshot
    /// keeps it.
    pub spec_path: String,
    /// A file to which the device appends its statistics every 5 seconds and its messages
    /// about the connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats_path: Option<String>,
    /// Fenced commands answered before the renderer has run them (default 8, 0 = every
    /// command waits for the renderer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fence_window: Option<u32>,
    /// Beyond the window, fenced commands are answered early while the oldest unanswered one
    /// was sent less than two round trips and this many milliseconds ago (default 20, 0 =
    /// not beyond the window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fence_age_ms: Option<u32>,
    /// The device stops taking the guest's commands while more than this many MiB wait to be
    /// written to the renderer (default 8, at least 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_limit_mib: Option<u32>,
    /// The zstd level of the connection, used when the renderer offers compression too
    /// (default 1, 0 = not offered, at most 19).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zstd_level: Option<i32>,
    /// Log the commands that wait for the renderer and the query objects into the statistics
    /// file (for debugging).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug_wait: Option<bool>,
    /// A file that gets a copy of every message written to the renderer, before compression
    /// (for debugging).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dump_path: Option<String>,
    /// Two virtio-input devices, a keyboard and a tablet (absolute axes, buttons, wheels), fed
    /// by the renderer's input (default false).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<bool>,
    /// A virtio-snd device with one playback stream (48 kHz, 2 channels, 16 bit), played at
    /// playback speed and sent to the renderer (default false).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sound: Option<bool>,
    /// A unix socket on which the device takes the connection of the guest agent and carries
    /// the renderer's scroll channel to it. With the vsock device, the agent connects to the
    /// host's port P and Firecracker connects that to `<vsock uds_path>_P`, so this is that
    /// path (the agent uses port 5000). The device creates the socket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_socket_path: Option<String>,
    /// The unix socket of a renderer on this server's CPU (the same sink, run with software
    /// GL). With it, the device switches to that renderer when the user's renderer detaches or
    /// has been silent for 10 s, and back when the user's renderer connects again; the guest
    /// keeps running, and the device builds the renderer's state again from its journal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_socket_path: Option<String>,
}

impl GpuConfig {
    pub(crate) fn fence_window(&self) -> u32 {
        self.fence_window.unwrap_or(DEFAULT_FENCE_WINDOW)
    }

    pub(crate) fn fence_age_us(&self) -> i64 {
        i64::from(self.fence_age_ms.unwrap_or(DEFAULT_FENCE_AGE_MS)) * 1000
    }

    pub(crate) fn tx_limit_bytes(&self) -> usize {
        (self.tx_limit_mib.unwrap_or(DEFAULT_TX_LIMIT_MIB) as usize) << 20
    }

    pub(crate) fn zstd_level(&self) -> i32 {
        self.zstd_level.unwrap_or(DEFAULT_ZSTD_LEVEL)
    }

    pub(crate) fn input(&self) -> bool {
        self.input.unwrap_or(false)
    }

    pub(crate) fn sound(&self) -> bool {
        self.sound.unwrap_or(false)
    }

    /// Check the values.
    pub fn validate(&self) -> Result<(), GpuConfigError> {
        if self.socket_path.is_empty() {
            return Err(GpuConfigError::SocketPath);
        }
        if self.spec_path.is_empty() {
            return Err(GpuConfigError::SpecPath);
        }
        if self.tx_limit_mib == Some(0) {
            return Err(GpuConfigError::TxLimit);
        }
        if let Some(l) = self.zstd_level
            && !(0..=MAX_ZSTD_LEVEL).contains(&l)
        {
            return Err(GpuConfigError::ZstdLevel(l));
        }
        if self.agent_socket_path.as_deref() == Some("") {
            return Err(GpuConfigError::AgentSocketPath);
        }
        if self.cpu_socket_path.as_deref() == Some("") {
            return Err(GpuConfigError::CpuSocketPath);
        }
        Ok(())
    }
}

/// Errors of the GPU device's configuration.
#[derive(Debug, thiserror::Error, displaydoc::Display, PartialEq, Eq)]
pub enum GpuConfigError {
    /// The socket path of the renderer is empty.
    SocketPath,
    /// The path of the GPU spec is empty.
    SpecPath,
    /// The transmit limit must be at least 1 MiB.
    TxLimit,
    /// The zstd level {0} is not between 0 and 19.
    ZstdLevel(i32),
    /// The socket path of the guest agent's channel is empty.
    AgentSocketPath,
    /// The socket path of the CPU renderer is empty.
    CpuSocketPath,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults_and_validation() {
        let c: GpuConfig =
            serde_json::from_str(r#"{"socket_path": "/run/gpu.sock", "spec_path": "/g.spec"}"#)
                .unwrap();
        c.validate().unwrap();
        assert_eq!(c.fence_window(), 8);
        assert_eq!(c.fence_age_us(), 20_000);
        assert_eq!(c.tx_limit_bytes(), 8 << 20);
        assert_eq!(c.zstd_level(), 1);
        // Only the given fields are listed back.
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"socket_path":"/run/gpu.sock","spec_path":"/g.spec"}"#
        );

        assert!(!c.input() && !c.sound() && c.agent_socket_path.is_none());

        let c: GpuConfig = serde_json::from_str(
            r#"{"socket_path": "/s", "spec_path": "/g.spec", "stats_path": "/t", "fence_window": 0, "fence_age_ms": 5,
                "tx_limit_mib": 2, "zstd_level": 0, "debug_wait": true, "dump_path": "/d",
                "input": true, "sound": true, "agent_socket_path": "/v.sock_5000",
                "cpu_socket_path": "/c.sock"}"#,
        )
        .unwrap();
        c.validate().unwrap();
        assert_eq!(c.fence_window(), 0);
        assert_eq!(c.tx_limit_bytes(), 2 << 20);
        assert!(c.input() && c.sound());
        assert_eq!(c.agent_socket_path.as_deref(), Some("/v.sock_5000"));
        assert_eq!(c.cpu_socket_path.as_deref(), Some("/c.sock"));

        serde_json::from_str::<GpuConfig>(
            r#"{"socket_path": "/s", "spec_path": "/g", "other": 1}"#,
        )
        .unwrap_err();
        serde_json::from_str::<GpuConfig>(r#"{}"#).unwrap_err();
        // the spec is required
        serde_json::from_str::<GpuConfig>(r#"{"socket_path": "/s"}"#).unwrap_err();
        let bad = |j: &str| serde_json::from_str::<GpuConfig>(j).unwrap().validate();
        assert_eq!(
            bad(r#"{"socket_path": "", "spec_path": "/g"}"#),
            Err(GpuConfigError::SocketPath)
        );
        assert_eq!(
            bad(r#"{"socket_path": "/s", "spec_path": ""}"#),
            Err(GpuConfigError::SpecPath)
        );
        assert_eq!(
            bad(r#"{"socket_path": "/s", "spec_path": "/g", "tx_limit_mib": 0}"#),
            Err(GpuConfigError::TxLimit)
        );
        assert_eq!(
            bad(r#"{"socket_path": "/s", "spec_path": "/g", "zstd_level": 20}"#),
            Err(GpuConfigError::ZstdLevel(20))
        );
        assert_eq!(
            bad(r#"{"socket_path": "/s", "spec_path": "/g", "agent_socket_path": ""}"#),
            Err(GpuConfigError::AgentSocketPath)
        );
        assert_eq!(
            bad(r#"{"socket_path": "/s", "spec_path": "/g", "cpu_socket_path": ""}"#),
            Err(GpuConfigError::CpuSocketPath)
        );
        serde_json::from_str::<GpuConfig>(
            r#"{"socket_path": "/s", "spec_path": "/g", "input": 1}"#,
        )
        .unwrap_err();
    }
}
