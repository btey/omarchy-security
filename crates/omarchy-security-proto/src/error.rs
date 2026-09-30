// SPDX-License-Identifier: GPL-3.0-or-later

//! JSON-RPC error objects and the daemon's application error codes.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Every error code the daemon emits. The JSON-RPC 2.0 reserved codes come
/// first; application codes live in the implementation-defined
/// `-32000..=-32099` server range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ParseError,
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    /// A method other than `HELLO` arrived before the handshake.
    HandshakeRequired,
    /// `HELLO` asked for a protocol version this daemon does not speak.
    UnsupportedProtocolVersion,
    /// The backing module is disabled, failed to start, or its system
    /// dependency (usbguard, nftables, ...) is missing.
    ModuleUnavailable,
    /// The referenced alert, device, token, vault, or rule does not exist.
    NotFound,
    /// The caller may not perform this action (peer check, policy).
    PermissionDenied,
    /// The target changed since it was reported, e.g. the PID now belongs
    /// to a different process than the one the alert describes.
    StaleTarget,
    /// The backend (kernel, USBGuard, cryptsetup, ...) rejected the action.
    BackendError,
    /// The method is part of the protocol but not implemented yet.
    NotImplemented,
    /// The user dismissed a prompt the method needed (the vault passphrase).
    Cancelled,
    /// The call cannot work in the current firewall mode, such as an
    /// inbound allow while `ufw` is active. The message says what to do.
    ModeConflict,
}

impl ErrorCode {
    pub const fn code(self) -> i64 {
        match self {
            Self::ParseError => -32700,
            Self::InvalidRequest => -32600,
            Self::MethodNotFound => -32601,
            Self::InvalidParams => -32602,
            Self::InternalError => -32603,
            Self::HandshakeRequired => -32000,
            Self::UnsupportedProtocolVersion => -32001,
            Self::ModuleUnavailable => -32002,
            Self::NotFound => -32003,
            Self::PermissionDenied => -32004,
            Self::StaleTarget => -32005,
            Self::BackendError => -32006,
            Self::NotImplemented => -32007,
            Self::Cancelled => -32008,
            Self::ModeConflict => -32009,
        }
    }

    pub const ALL: [Self; 15] = [
        Self::ParseError,
        Self::InvalidRequest,
        Self::MethodNotFound,
        Self::InvalidParams,
        Self::InternalError,
        Self::HandshakeRequired,
        Self::UnsupportedProtocolVersion,
        Self::ModuleUnavailable,
        Self::NotFound,
        Self::PermissionDenied,
        Self::StaleTarget,
        Self::BackendError,
        Self::NotImplemented,
        Self::Cancelled,
        Self::ModeConflict,
    ];

    pub fn from_code(code: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.code() == code)
    }
}

/// A JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("{message} ({code})")]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.code(),
            message: message.into(),
            data: None,
        }
    }

    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    pub fn kind(&self) -> Option<ErrorCode> {
        ErrorCode::from_code(self.code)
    }

    pub fn parse_error(err: impl std::fmt::Display) -> Self {
        Self::new(ErrorCode::ParseError, format!("parse error: {err}"))
    }

    pub fn invalid_request(reason: impl std::fmt::Display) -> Self {
        Self::new(
            ErrorCode::InvalidRequest,
            format!("invalid request: {reason}"),
        )
    }

    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            ErrorCode::MethodNotFound,
            format!("unknown method '{method}'"),
        )
    }

    pub fn invalid_params(err: impl std::fmt::Display) -> Self {
        Self::new(ErrorCode::InvalidParams, format!("invalid params: {err}"))
    }
}
