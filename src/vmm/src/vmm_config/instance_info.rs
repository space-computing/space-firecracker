// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use std::fmt::{self, Display, Formatter};

use serde::{Serialize, ser};

/// Enumerates microVM runtime states.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum VmState {
    /// Vm not started (yet)
    #[default]
    NotStarted,
    /// Vm is Paused
    Paused,
    /// Vm is running
    Running,
}

impl Display for VmState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            VmState::NotStarted => write!(f, "Not started"),
            VmState::Paused => write!(f, "Paused"),
            VmState::Running => write!(f, "Running"),
        }
    }
}

impl ser::Serialize for VmState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

/// Why a microVM is paused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PausedReason {
    /// A pause request of the API.
    Api,
    /// The microVM was loaded from a snapshot and was not resumed yet.
    Load,
    /// The lease of the checkpoints ended.
    Lease,
    /// A disk request of the drive with this id failed.
    DiskError(String),
}

impl PausedReason {
    /// The name of the reason in the API.
    pub fn name(&self) -> &'static str {
        match self {
            PausedReason::Api => "api",
            PausedReason::Load => "load",
            PausedReason::Lease => "lease",
            PausedReason::DiskError(_) => "disk-error",
        }
    }

    /// The drive whose error stopped the microVM, if that is the reason.
    pub fn drive_id(&self) -> Option<&str> {
        match self {
            PausedReason::DiskError(drive_id) => Some(drive_id),
            _ => None,
        }
    }
}

impl ser::Serialize for PausedReason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.name().serialize(serializer)
    }
}

/// Serializable struct that contains general information about the microVM.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InstanceInfo {
    /// The ID of the microVM.
    pub id: String,
    /// Whether the microVM is not started/running/paused.
    pub state: VmState,
    /// The version of the VMM that runs the microVM.
    pub vmm_version: String,
    /// The name of the application that runs the microVM.
    pub app_name: String,
    /// Whether a resume succeeded since the microVM was booted or loaded.
    pub ran_since_load: bool,
    /// Why the microVM is paused; absent while it runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_reason: Option<PausedReason>,
    /// The drive whose error paused the microVM; present only with `paused_reason: disk-error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_drive_id: Option<String>,
}

impl InstanceInfo {
    /// Records that the microVM is paused for `reason`.
    pub fn set_paused(&mut self, reason: PausedReason) {
        self.state = VmState::Paused;
        self.paused_drive_id = reason.drive_id().map(str::to_owned);
        self.paused_reason = Some(reason);
    }

    /// Records that a resume of the microVM succeeded.
    pub fn set_running(&mut self) {
        self.state = VmState::Running;
        self.ran_since_load = true;
        self.paused_reason = None;
        self.paused_drive_id = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_info_paused_reason() {
        let mut info = InstanceInfo {
            id: "a".to_string(),
            ..Default::default()
        };
        info.set_paused(PausedReason::DiskError("rootfs".to_string()));
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["state"], "Paused");
        assert_eq!(json["ran_since_load"], false);
        assert_eq!(json["paused_reason"], "disk-error");
        assert_eq!(json["paused_drive_id"], "rootfs");

        info.set_running();
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["state"], "Running");
        assert_eq!(json["ran_since_load"], true);
        assert!(json.get("paused_reason").is_none());
        assert!(json.get("paused_drive_id").is_none());

        for (reason, name) in [
            (PausedReason::Api, "api"),
            (PausedReason::Load, "load"),
            (PausedReason::Lease, "lease"),
        ] {
            info.set_paused(reason);
            let json = serde_json::to_value(&info).unwrap();
            assert_eq!(json["paused_reason"], name);
            assert!(json.get("paused_drive_id").is_none());
        }
    }
}
