// Copyright 2026 The Spacebox Authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::gpu::GpuConfig;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::Body;

pub(crate) fn parse_put_gpu(body: &Body) -> Result<ParsedRequest, RequestError> {
    let cfg = serde_json::from_slice::<GpuConfig>(body.raw())?;
    Ok(ParsedRequest::new_sync(VmmAction::SetGpuDevice(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_put_gpu_request() {
        parse_put_gpu(&Body::new("invalid_payload")).unwrap_err();
        // No socket.
        parse_put_gpu(&Body::new("{}")).unwrap_err();
        // An unknown field.
        parse_put_gpu(&Body::new(r#"{"socket_path": "/gpu.sock", "some_id": 4}"#)).unwrap_err();

        let body = r#"{"socket_path": "/gpu.sock", "stats_path": "/gpu.stats", "fence_window": 8}"#;
        let expected = GpuConfig {
            socket_path: "/gpu.sock".into(),
            stats_path: Some("/gpu.stats".into()),
            fence_window: Some(8),
            ..Default::default()
        };
        assert_eq!(
            vmm_action_from_request(parse_put_gpu(&Body::new(body)).unwrap()),
            VmmAction::SetGpuDevice(expected)
        );
    }
}
