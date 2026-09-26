// SPDX-License-Identifier: GPL-3.0-or-later

//! Netlink framing (`netlink(7)`) for the two netlink protocols connection
//! interception speaks: `nfnetlink_queue` and `sock_diag`.
//!
//! These are written out here rather than taken from a crate. The `nfq`
//! crate has had no release since 2022, and the few fixed structures used
//! are simpler to encode, test and fuzz directly than to adopt the
//! `netlink-packet-*` family for. Everything goes through nix's safe socket
//! calls, so this needs no `unsafe`.

use std::io;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::time::Duration;

use nix::sys::socket::{
    AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, bind, recv, sendto,
    setsockopt, sockopt,
};
use nix::sys::time::TimeVal;

pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x1;
pub const NLM_F_ACK: u16 = 0x4;
pub const NLM_F_DUMP: u16 = 0x300;

const HEADER_LEN: usize = 16;
/// The flag bits of an attribute type (`NLA_F_NESTED`, `NLA_F_NET_BYTEORDER`).
const NLA_TYPE_MASK: u16 = 0x3fff;

const fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// One message of a received buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message<'a> {
    pub kind: u16,
    pub flags: u16,
    pub seq: u32,
    pub payload: &'a [u8],
}

/// Splits a buffer into its messages, stopping at the first malformed one.
pub fn messages(mut buf: &[u8]) -> impl Iterator<Item = Message<'_>> {
    std::iter::from_fn(move || {
        let header = buf.get(..HEADER_LEN)?;
        let len = u32::from_ne_bytes(header[0..4].try_into().ok()?) as usize;
        if len < HEADER_LEN || len > buf.len() {
            buf = &[];
            return None;
        }
        let message = Message {
            kind: u16::from_ne_bytes(header[4..6].try_into().ok()?),
            flags: u16::from_ne_bytes(header[6..8].try_into().ok()?),
            seq: u32::from_ne_bytes(header[8..12].try_into().ok()?),
            payload: &buf[HEADER_LEN..len],
        };
        buf = buf.get(align4(len)..).unwrap_or(&[]);
        Some(message)
    })
}

/// A complete message: header, then `payload`.
pub fn message(kind: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = HEADER_LEN + payload.len();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    // Port 0: the kernel fills in ours.
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(payload);
    out
}

/// Appends one attribute, padded to four bytes.
pub fn push_attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = 4 + data.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(data);
    out.resize(out.len() + align4(len) - len, 0);
}

/// The attributes of a payload, as `(type, data)`, with the type's flag
/// bits cleared. Stops at the first malformed attribute.
pub fn attrs(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let header = buf.get(..4)?;
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let kind = u16::from_ne_bytes([header[2], header[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > buf.len() {
            buf = &[];
            return None;
        }
        let data = &buf[4..len];
        buf = buf.get(align4(len)..).unwrap_or(&[]);
        Some((kind, data))
    })
}

/// The errno of an `NLMSG_ERROR` payload; 0 is an acknowledgement.
pub fn error_code(payload: &[u8]) -> Option<i32> {
    Some(-i32::from_ne_bytes(payload.get(..4)?.try_into().ok()?))
}

pub struct Socket(OwnedFd);

impl Socket {
    pub fn open(protocol: SockProtocol) -> io::Result<Self> {
        let fd = socket_fd(protocol)?;
        bind(fd.as_raw_fd(), &NetlinkAddr::new(0, 0))?;
        Ok(Self(fd))
    }

    /// Makes `recv` fail with `WouldBlock` after `timeout`.
    pub fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        let tv = TimeVal::new(timeout.as_secs() as _, timeout.subsec_micros() as _);
        setsockopt(&self.0, sockopt::ReceiveTimeout, &tv)?;
        Ok(())
    }

    pub fn set_receive_buffer(&self, bytes: usize) -> io::Result<()> {
        setsockopt(&self.0, sockopt::RcvBuf, &bytes)?;
        Ok(())
    }

    pub fn send(&self, message: &[u8]) -> io::Result<()> {
        sendto(
            self.0.as_fd().as_raw_fd(),
            message,
            &NetlinkAddr::new(0, 0),
            MsgFlags::empty(),
        )?;
        Ok(())
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(recv(self.0.as_raw_fd(), buf, MsgFlags::empty())?)
    }

    /// Sends a request with `NLM_F_ACK` and waits for its acknowledgement.
    /// Other messages that arrive meanwhile are dropped, so this is only
    /// for setup, before anything else is expected.
    pub fn request(&self, kind: u16, seq: u32, payload: &[u8]) -> io::Result<()> {
        self.send(&message(kind, NLM_F_REQUEST | NLM_F_ACK, seq, payload))?;
        let mut buf = vec![0u8; 8192];
        loop {
            let n = self.recv(&mut buf)?;
            for reply in messages(&buf[..n]) {
                if reply.kind == NLMSG_ERROR && reply.seq == seq {
                    return match error_code(reply.payload) {
                        Some(0) => Ok(()),
                        Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                        None => Err(io::Error::other("short netlink error message")),
                    };
                }
            }
        }
    }
}

fn socket_fd(protocol: SockProtocol) -> io::Result<OwnedFd> {
    Ok(nix::sys::socket::socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        protocol,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_messages_and_attributes() {
        let mut payload = vec![9, 9, 9, 9];
        push_attr(&mut payload, 1, &[1, 2, 3]);
        push_attr(&mut payload, 0x8002, &[4, 5, 6, 7]);
        assert_eq!(payload.len(), 4 + 8 + 8);
        let mut buf = message(0x300, NLM_F_REQUEST, 7, &payload);
        buf.extend(message(NLMSG_DONE, 0, 8, &[]));

        let all: Vec<Message> = messages(&buf).collect();
        assert_eq!(all.len(), 2);
        assert_eq!((all[0].kind, all[0].flags, all[0].seq), (0x300, 1, 7));
        let found: Vec<(u16, &[u8])> = attrs(&all[0].payload[4..]).collect();
        assert_eq!(found, [(1, &[1, 2, 3][..]), (2, &[4, 5, 6, 7][..])]);
        assert_eq!(all[1].kind, NLMSG_DONE);
    }

    #[test]
    fn stops_at_malformed_input() {
        let good = message(1, 0, 1, &[0; 4]);
        let mut bad = good.clone();
        bad[0] = 200; // longer than the buffer
        assert_eq!(messages(&bad).count(), 0);
        let mut short = good.clone();
        short[0] = 3; // shorter than a header
        assert_eq!(messages(&short).count(), 0);
        assert_eq!(messages(&good[..10]).count(), 0);
        assert_eq!(attrs(&[8, 0, 1, 0, 0]).count(), 0);
        assert_eq!(attrs(&[2, 0, 1, 0]).count(), 0);
        assert_eq!(error_code(&(-13i32).to_ne_bytes()), Some(13));
        assert_eq!(error_code(&[0; 2]), None);
    }
}
