// SPDX-License-Identifier: GPL-3.0-or-later

//! Finds the socket behind a queued packet with `NETLINK_SOCK_DIAG`
//! (`sock_diag(7)`), for its inode and owner.
//!
//! The lookup dumps the sockets of the packet's protocol and local port
//! (the kernel filters on the port) and picks the best match here, rather
//! than using the exact lookup: an unconnected UDP socket has no remote
//! address, and an IPv6 socket may send IPv4 packets through a mapped
//! address, and neither is found by an exact lookup.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use nix::sys::socket::SockProtocol;
use omarchy_security_proto::types::Protocol;

use crate::netlink::{self, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, Socket};
use crate::packet::Flow;

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
/// A connecting TCP socket is in `SYN_SENT`; `ESTABLISHED` covers a race
/// with a fast handshake.
const TCP_STATES: u32 = 1 << 1 | 1 << 2;
/// UDP sockets report `ESTABLISHED` when connected and `CLOSE` when not.
const UDP_STATES: u32 = u32::MAX;
/// `sizeof(struct inet_diag_msg)`.
const DIAG_MSG_LEN: usize = 72;

/// A socket as `sock_diag` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagSocket {
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
    pub uid: u32,
    pub inode: u32,
}

pub struct SockDiag {
    socket: Socket,
    seq: u32,
}

/// `struct inet_diag_req_v2`, with only the local port set in the id.
fn dump_request(family: u8, protocol: u8, states: u32, sport: u16) -> Vec<u8> {
    let mut out = vec![family, protocol, 0, 0];
    out.extend_from_slice(&states.to_ne_bytes());
    // struct inet_diag_sockid: sport, dport, src, dst, if, cookie.
    out.extend_from_slice(&sport.to_be_bytes());
    out.resize(out.len() + 2 + 16 + 16 + 4, 0);
    // INET_DIAG_NOCOOKIE.
    out.extend_from_slice(&[0xff; 8]);
    out
}

/// Decodes a `struct inet_diag_msg`.
pub fn parse_socket(payload: &[u8]) -> Option<DiagSocket> {
    let msg = payload.get(..DIAG_MSG_LEN)?;
    let addr = |bytes: &[u8]| -> Option<IpAddr> {
        Some(match msg[0] {
            AF_INET => Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[..4]).ok()?).into(),
            AF_INET6 => Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).into(),
            _ => return None,
        })
    };
    let word = |at: usize| u32::from_ne_bytes(msg[at..at + 4].try_into().expect("4 bytes"));
    Some(DiagSocket {
        sport: u16::from_be_bytes([msg[4], msg[5]]),
        dport: u16::from_be_bytes([msg[6], msg[7]]),
        src: addr(&msg[8..24])?,
        dst: addr(&msg[24..40])?,
        uid: word(64),
        inode: word(68),
    })
}

/// Unmaps `::ffff:a.b.c.d` so that a dual-stack socket compares equal to
/// the IPv4 packet it sent.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// How well `socket` explains `flow`: 2 for a connected socket with the
/// same remote end, 1 for an unconnected one on the same local port.
fn score(socket: &DiagSocket, flow: &Flow) -> u8 {
    let local = canonical(socket.src) == flow.src || socket.src.is_unspecified();
    if socket.sport != flow.sport || !local {
        return 0;
    }
    if socket.dport == flow.dport && canonical(socket.dst) == flow.dst {
        2
    } else if socket.dport == 0 && socket.dst.is_unspecified() {
        1
    } else {
        0
    }
}

/// The socket that sent `flow`, among `sockets`.
pub fn best_match(flow: &Flow, sockets: &[DiagSocket]) -> Option<DiagSocket> {
    sockets
        .iter()
        .filter(|s| s.inode != 0)
        .map(|s| (score(s, flow), s))
        .filter(|(score, _)| *score > 0)
        .max_by_key(|(score, _)| *score)
        .map(|(_, s)| *s)
}

impl SockDiag {
    pub fn open() -> io::Result<Self> {
        let socket = Socket::open(SockProtocol::NetlinkSockDiag)?;
        socket.set_timeout(Duration::from_secs(1))?;
        Ok(Self { socket, seq: 0 })
    }

    /// The socket that sent `flow`, if it still exists.
    pub fn find(&mut self, flow: &Flow) -> io::Result<Option<DiagSocket>> {
        let (protocol, states) = match flow.protocol {
            Protocol::Tcp => (IPPROTO_TCP, TCP_STATES),
            Protocol::Udp => (IPPROTO_UDP, UDP_STATES),
        };
        // An IPv4 packet may come from an IPv6 socket.
        let families: &[u8] = if flow.src.is_ipv4() {
            &[AF_INET, AF_INET6]
        } else {
            &[AF_INET6]
        };
        let mut sockets = Vec::new();
        for &family in families {
            sockets.extend(self.dump(family, protocol, states, flow.sport)?);
            if let Some(found) = best_match(flow, &sockets) {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    fn dump(
        &mut self,
        family: u8,
        protocol: u8,
        states: u32,
        sport: u16,
    ) -> io::Result<Vec<DiagSocket>> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        self.socket.send(&netlink::message(
            SOCK_DIAG_BY_FAMILY,
            NLM_F_REQUEST | NLM_F_DUMP,
            seq,
            &dump_request(family, protocol, states, sport),
        ))?;
        let mut sockets = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = self.socket.recv(&mut buf)?;
            for message in netlink::messages(&buf[..n]) {
                if message.seq != seq {
                    continue;
                }
                match message.kind {
                    NLMSG_DONE => return Ok(sockets),
                    NLMSG_ERROR => {
                        return match netlink::error_code(message.payload) {
                            Some(0) => Ok(sockets),
                            // No diag module for this family and protocol.
                            Some(errno) if errno == nix::errno::Errno::ENOENT as i32 => Ok(sockets),
                            Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                            None => Err(io::Error::other("short netlink error message")),
                        };
                    }
                    SOCK_DIAG_BY_FAMILY => sockets.extend(parse_socket(message.payload)),
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(src: &str, sport: u16, dst: &str, dport: u16, inode: u32) -> DiagSocket {
        DiagSocket {
            src: src.parse().unwrap(),
            sport,
            dst: dst.parse().unwrap(),
            dport,
            uid: 1000,
            inode,
        }
    }

    fn flow(protocol: Protocol) -> Flow {
        Flow {
            protocol,
            src: "10.0.0.5".parse().unwrap(),
            sport: 40000,
            dst: "192.0.2.1".parse().unwrap(),
            dport: 443,
        }
    }

    #[test]
    fn prefers_the_connected_socket() {
        let f = flow(Protocol::Udp);
        let sockets = [
            socket("0.0.0.0", 40000, "0.0.0.0", 0, 1),
            socket("10.0.0.5", 40000, "192.0.2.1", 443, 2),
            socket("10.0.0.5", 40000, "192.0.2.9", 443, 3),
        ];
        assert_eq!(best_match(&f, &sockets).unwrap().inode, 2);
        assert_eq!(best_match(&f, &sockets[..1]).unwrap().inode, 1);
        assert_eq!(best_match(&f, &sockets[2..]), None);
        // A socket with inode 0 (time-wait, request) names no process.
        assert_eq!(
            best_match(&f, &[socket("10.0.0.5", 40000, "192.0.2.1", 443, 0)]),
            None
        );
    }

    #[test]
    fn matches_dual_stack_sockets() {
        let f = flow(Protocol::Tcp);
        let mapped = socket("::ffff:10.0.0.5", 40000, "::ffff:192.0.2.1", 443, 7);
        assert_eq!(best_match(&f, &[mapped]).unwrap().inode, 7);
        let other_port = socket("::", 40001, "::", 0, 8);
        assert_eq!(best_match(&f, &[other_port]), None);
    }

    #[test]
    fn encodes_requests_and_decodes_replies() {
        let request = dump_request(AF_INET, IPPROTO_UDP, UDP_STATES, 0x1f90);
        assert_eq!(request.len(), 56);
        assert_eq!(request[..4], [AF_INET, IPPROTO_UDP, 0, 0]);
        assert_eq!(request[8..10], [0x1f, 0x90]);
        assert_eq!(request[48..], [0xff; 8]);

        let mut reply = vec![AF_INET6, 1, 0, 0, 0x9c, 0x40, 0x01, 0xbb];
        reply.extend_from_slice(&"2001:db8::5".parse::<Ipv6Addr>().unwrap().octets());
        reply.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        reply.resize(64, 0);
        reply.extend_from_slice(&1000u32.to_ne_bytes());
        reply.extend_from_slice(&4242u32.to_ne_bytes());
        assert_eq!(
            parse_socket(&reply),
            Some(socket("2001:db8::5", 40000, "2001:db8::1", 443, 4242))
        );
        assert_eq!(parse_socket(&reply[..71]), None);
        reply[0] = 99;
        assert_eq!(parse_socket(&reply), None);
    }

    /// Finds a socket of this process for real.
    #[test]
    fn finds_a_live_socket() {
        let Ok(mut diag) = SockDiag::open() else {
            eprintln!("sock_diag unavailable; skipping");
            return;
        };
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let f = Flow {
            protocol: Protocol::Udp,
            src: "127.0.0.1".parse().unwrap(),
            sport: client.local_addr().unwrap().port(),
            dst: "127.0.0.1".parse().unwrap(),
            dport: server.local_addr().unwrap().port(),
        };
        let found = diag.find(&f).unwrap().expect("the client socket");
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        assert_eq!(found.uid, uid);
        let fd = std::os::fd::AsRawFd::as_raw_fd(&client);
        let link = std::fs::read_link(format!("/proc/self/fd/{fd}")).unwrap();
        assert_eq!(link.to_str().unwrap(), format!("socket:[{}]", found.inode));
    }
}
