// SPDX-License-Identifier: GPL-3.0-or-later

//! JSON-RPC 2.0 envelopes and NDJSON framing.

use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::RpcError;
use crate::events::Event;
use crate::methods::Call;

/// The literal `"jsonrpc": "2.0"` member; any other value fails to parse.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JsonRpcVersion;

impl Serialize for JsonRpcVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("2.0")
    }
}

impl<'de> Deserialize<'de> for JsonRpcVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let version = String::deserialize(deserializer)?;
        if version == "2.0" {
            Ok(Self)
        } else {
            Err(de::Error::custom(format!(
                "unsupported jsonrpc version '{version}'"
            )))
        }
    }
}

/// Request id. Clients should use increasing integers; strings are accepted
/// because JSON-RPC allows them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    Number(i64),
    String(String),
}

/// A typed request: an id and the call it carries.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub id: Id,
    pub call: Call,
}

#[derive(Serialize)]
struct WireRequest<'a> {
    jsonrpc: JsonRpcVersion,
    id: &'a Id,
    method: &'static str,
    params: Value,
}

impl Serialize for Request {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WireRequest {
            jsonrpc: JsonRpcVersion,
            id: &self.id,
            method: self.call.method(),
            params: self.call.params(),
        }
        .serialize(serializer)
    }
}

#[derive(Deserialize)]
struct RawRequest {
    #[allow(dead_code)]
    jsonrpc: JsonRpcVersion,
    #[serde(default)]
    id: Option<Id>,
    method: String,
    #[serde(default)]
    params: Value,
}

/// Parses one frame into a request. On failure returns the error response
/// to send back, already addressed to the request's id when it was readable.
pub fn parse_request(frame: &[u8]) -> Result<Request, Response> {
    let value: Value = serde_json::from_slice(frame)
        .map_err(|e| Response::error(None, RpcError::parse_error(e)))?;

    if value.is_array() {
        return Err(Response::error(
            None,
            RpcError::invalid_request("batch requests are not supported"),
        ));
    }
    // Salvage the id before strict parsing so the error still reaches the
    // caller that is waiting on it.
    let salvaged_id = value
        .get("id")
        .and_then(|id| serde_json::from_value::<Id>(id.clone()).ok());

    let raw: RawRequest = serde_json::from_value(value)
        .map_err(|e| Response::error(salvaged_id.clone(), RpcError::invalid_request(e)))?;
    let Some(id) = raw.id else {
        return Err(Response::error(
            None,
            RpcError::invalid_request("missing id; client notifications are not supported"),
        ));
    };
    let call = Call::from_parts(&raw.method, raw.params)
        .map_err(|e| Response::error(Some(id.clone()), e))?;
    Ok(Request { id, call })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Result(Value),
    Error(RpcError),
}

/// A response to one request. `id` is `null` only when the request was too
/// malformed to read its id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub jsonrpc: JsonRpcVersion,
    pub id: Option<Id>,
    #[serde(flatten)]
    pub outcome: Outcome,
}

impl Response {
    pub fn result<T: Serialize>(id: Id, result: &T) -> Self {
        let outcome = match serde_json::to_value(result) {
            Ok(value) => Outcome::Result(value),
            Err(e) => Outcome::Error(RpcError::new(
                crate::ErrorCode::InternalError,
                format!("result serialization failed: {e}"),
            )),
        };
        Self {
            jsonrpc: JsonRpcVersion,
            id: Some(id),
            outcome,
        }
    }

    pub fn error(id: Option<Id>, error: RpcError) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            id,
            outcome: Outcome::Error(error),
        }
    }
}

/// A daemon → client event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    pub jsonrpc: JsonRpcVersion,
    #[serde(flatten)]
    pub event: Event,
}

impl From<Event> for Notification {
    fn from(event: Event) -> Self {
        Self {
            jsonrpc: JsonRpcVersion,
            event,
        }
    }
}

/// Serializes a message as one NDJSON frame, trailing newline included.
/// Compact JSON escapes every newline inside strings, so the only raw `\n`
/// in the output is the terminator.
pub fn encode_frame<T: Serialize>(message: &T) -> serde_json::Result<String> {
    let mut line = serde_json::to_string(message)?;
    line.push('\n');
    Ok(line)
}
