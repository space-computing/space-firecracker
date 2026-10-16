// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The bodies of the `/space/` endpoints.

use serde::Serialize;

/// One region of guest memory, as `GET /space/memory` gives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemoryRegion {
    /// The address of the region in the address space of the Firecracker process.
    pub host_addr: u64,
    /// The size of the region, in bytes.
    pub size: u64,
    /// The guest physical address where the region starts.
    pub guest_addr: u64,
    /// The offset of the region in the memory file of a snapshot (the same offset that a UFFD
    /// handler gets at a load).
    pub offset: u64,
}

/// The body of `GET /space/memory`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MemoryRegions {
    /// The regions, in the order of the memory file.
    pub regions: Vec<MemoryRegion>,
}

/// What the fill of guest memory (`PUT /space/fill`) is doing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FillState {
    /// No fill was asked for yet.
    #[default]
    Idle,
    /// A fill runs.
    Running,
    /// The last fill populated every page.
    Done,
    /// The last fill stopped with an error.
    Failed,
}

/// The body of `GET /space/fill`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FillStatus {
    /// What the fill is doing.
    pub state: FillState,
    /// Why the last fill failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_space_bodies() {
        let regions = MemoryRegions {
            regions: vec![MemoryRegion {
                host_addr: 0x7f00_0000_0000,
                size: 0x1000_0000,
                guest_addr: 0,
                offset: 0,
            }],
        };
        assert_eq!(
            serde_json::to_string(&regions).unwrap(),
            r#"{"regions":[{"host_addr":139637976727552,"size":268435456,"guest_addr":0,"offset":0}]}"#
        );
        assert_eq!(
            serde_json::to_string(&FillStatus::default()).unwrap(),
            r#"{"state":"idle"}"#
        );
        let failed = FillStatus {
            state: FillState::Failed,
            error: Some("x".to_string()),
        };
        assert_eq!(
            serde_json::to_string(&failed).unwrap(),
            r#"{"state":"failed","error":"x"}"#
        );
    }
}
