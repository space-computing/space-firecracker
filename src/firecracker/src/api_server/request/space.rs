// Copyright 2026 Spacebox authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The endpoints under `/space/`.

use serde::Deserialize;
use vmm::rpc_interface::VmmAction;

use super::super::parsed_request::{ParsedRequest, RequestError};
use super::{Body, Method};

/// The body of `PUT /space/fill`: no member.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FillParams {}

pub(crate) fn parse_get_space<'a, T>(mut path_tokens: T) -> Result<ParsedRequest, RequestError>
where
    T: Iterator<Item = &'a str>,
{
    match (path_tokens.next(), path_tokens.next()) {
        (Some("memory"), None) => Ok(ParsedRequest::new_sync(VmmAction::GetSpaceMemory)),
        (Some("fill"), None) => Ok(ParsedRequest::new_sync(VmmAction::GetSpaceFill)),
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
            if let Some(body) = body {
                serde_json::from_slice::<FillParams>(body.raw())?;
            }
            Ok(ParsedRequest::new_sync(VmmAction::StartSpaceFill))
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
}
