// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The endpoints under `/space/`.

use serde::Deserialize;
use vmm::rpc_interface::VmmAction;
use vmm::vmm_config::checkpoint::{CheckpointSetParams, CheckpointTrackParams};

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::{Body, Method, StatusCode};

/// The body of `PUT /space/fill`, `PUT /space/checkpoint/finish` and
/// `PUT /space/checkpoint/release`: no member.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FillParams {}

fn no_member(body: Option<&Body>) -> Result<(), RequestError> {
    if let Some(body) = body {
        serde_json::from_slice::<FillParams>(body.raw())?;
    }
    Ok(())
}

fn needs_body<'b>(body: Option<&'b Body>, path: &str) -> Result<&'b Body, RequestError> {
    body.ok_or_else(|| {
        RequestError::Generic(StatusCode::BadRequest, format!("{path} needs a body"))
    })
}

pub(crate) fn parse_get_space<'a, T>(mut path_tokens: T) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match (path_tokens.next(), path_tokens.next()) {
        (Some("memory"), None) => Ok(ParsedRequest::new_sync(VmmAction::GetSpaceMemory)),
        (Some("fill"), None) => Ok(ParsedRequest::new_sync(VmmAction::GetSpaceFill)),
        (Some("checkpoint"), None) => Ok(ParsedRequest::new_sync(VmmAction::GetCheckpoint)),
        (Some(resource), _) => Err(RequestError::InvalidPathMethod(
            format!("/space/{resource}"),
            Method::Get,
        )),
        (None, _) => Err(RequestError::InvalidPathMethod(
            "/space".to_string(),
            Method::Get,
        )),
    }
}

pub(crate) fn parse_put_space<'a, T>(
    body: Option<&Body>,
    mut path_tokens: T,
) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match (path_tokens.next(), path_tokens.next()) {
        (Some("fill"), None) => {
            no_member(body)?;
            Ok(ParsedRequest::new_sync(VmmAction::StartSpaceFill))
        }
        (Some("checkpoint"), None) => {
            let params = serde_json::from_slice::<CheckpointSetParams>(
                needs_body(body, "/space/checkpoint")?.raw(),
            )?;
            Ok(ParsedRequest::new_sync(VmmAction::SetCheckpoint(params)))
        }
        (Some("checkpoint"), Some("track")) if path_tokens.next().is_none() => {
            let params = serde_json::from_slice::<CheckpointTrackParams>(
                needs_body(body, "/space/checkpoint/track")?.raw(),
            )?;
            Ok(ParsedRequest::new_sync(VmmAction::TrackCheckpoint(params)))
        }
        (Some("checkpoint"), Some("finish")) if path_tokens.next().is_none() => {
            no_member(body)?;
            Ok(ParsedRequest::new_sync(VmmAction::FinishCheckpoint))
        }
        (Some("checkpoint"), Some("release")) if path_tokens.next().is_none() => {
            no_member(body)?;
            Ok(ParsedRequest::new_sync(VmmAction::ReleaseCheckpoint))
        }
        (Some(resource), _) => Err(RequestError::InvalidPathMethod(
            format!("/space/{resource}"),
            Method::Put,
        )),
        (None, _) => Err(RequestError::InvalidPathMethod(
            "/space".to_string(),
            Method::Put,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::parsed_request::tests::vmm_action_from_request;

    #[test]
    fn test_parse_get_space() {
        assert_eq!(
            vmm_action_from_request(parse_get_space(["memory"].into_iter()).unwrap()),
            VmmAction::GetSpaceMemory
        );
        assert_eq!(
            vmm_action_from_request(parse_get_space(["fill"].into_iter()).unwrap()),
            VmmAction::GetSpaceFill
        );
        parse_get_space(["other"].into_iter()).unwrap_err();
        parse_get_space(["memory", "x"].into_iter()).unwrap_err();
        parse_get_space([].into_iter()).unwrap_err();
    }

    #[test]
    fn test_parse_put_space() {
        assert_eq!(
            vmm_action_from_request(parse_put_space(None, ["fill"].into_iter()).unwrap()),
            VmmAction::StartSpaceFill
        );
        assert_eq!(
            vmm_action_from_request(
                parse_put_space(Some(&Body::new("{}")), ["fill"].into_iter()).unwrap()
            ),
            VmmAction::StartSpaceFill
        );
        parse_put_space(Some(&Body::new(r#"{"x": 1}"#)), ["fill"].into_iter()).unwrap_err();
        parse_put_space(None, ["memory"].into_iter()).unwrap_err();
        parse_put_space(None, [].into_iter()).unwrap_err();
    }

    #[test]
    fn test_parse_checkpoint() {
        assert_eq!(
            vmm_action_from_request(parse_get_space(["checkpoint"].into_iter()).unwrap()),
            VmmAction::GetCheckpoint
        );
        let body = Body::new(
            r#"{"interval-ms": 2000, "need": true, "first": "budget", "lease-ms": 5000,
                "uri": "tcp:10.0.0.2:7000", "stream-id": "0123456789abcdef0123456789abcdef"}"#,
        );
        match vmm_action_from_request(
            parse_put_space(Some(&body), ["checkpoint"].into_iter()).unwrap(),
        ) {
            VmmAction::SetCheckpoint(p) => {
                assert_eq!(p.interval_ms, 2000);
                assert_eq!(p.need, Some(true));
                assert_eq!(p.lease_ms, Some(5000));
                assert_eq!(p.uri.as_deref(), Some("tcp:10.0.0.2:7000"));
            }
            other => panic!("{other:?}"),
        }
        parse_put_space(None, ["checkpoint"].into_iter()).unwrap_err();
        parse_put_space(
            Some(&Body::new(r#"{"interval-ms": 1, "x": 1}"#)),
            ["checkpoint"].into_iter(),
        )
        .unwrap_err();
        let body = Body::new(r#"{"enable": true, "hold": true, "lease-ms": 5000}"#);
        match vmm_action_from_request(
            parse_put_space(Some(&body), ["checkpoint", "track"].into_iter()).unwrap(),
        ) {
            VmmAction::TrackCheckpoint(p) => {
                assert!(p.enable);
                assert_eq!(p.hold, Some(true));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            vmm_action_from_request(
                parse_put_space(Some(&Body::new("{}")), ["checkpoint", "finish"].into_iter())
                    .unwrap()
            ),
            VmmAction::FinishCheckpoint
        );
        assert_eq!(
            vmm_action_from_request(
                parse_put_space(None, ["checkpoint", "release"].into_iter()).unwrap()
            ),
            VmmAction::ReleaseCheckpoint
        );
        parse_put_space(None, ["checkpoint", "other"].into_iter()).unwrap_err();
        parse_put_space(None, ["checkpoint", "release", "x"].into_iter()).unwrap_err();
    }
}
