// SPDX-License-Identifier: GPL-3.0-or-later

//! A client for one `nfnetlink_queue` queue: the packets that the `queue`
//! rule in `table inet omarchy_sec` sends to userspace, and the verdicts
//! that release them. The constants are from
//! `<linux/netfilter/nfnetlink_queue.h>`.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use nix::sys::socket::SockProtocol;

use crate::netlink::{self, NLMSG_ERROR, Socket};

const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = NFNL_SUBSYS_QUEUE << 8;
const NFQNL_MSG_VERDICT: u16 = NFNL_SUBSYS_QUEUE << 8 | 1;
const NFQNL_MSG_CONFIG: u16 = NFNL_SUBSYS_QUEUE << 8 | 2;

const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_UID: u16 = 16;

const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;
/// Accept packets instead of dropping them when the queue is full.
const NFQA_CFG_F_FAIL_OPEN: u32 = 1;
/// Report the socket owner's uid and gid.
const NFQA_CFG_F_UID_GID: u32 = 8;

const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;

/// Enough of each packet for the IP header, IPv6 extension headers and
/// the ports.
const COPY_RANGE: u32 = 256;
/// Packets the kernel holds before the queue counts as full.
const MAX_QUEUED: u32 = 1024;

/// A queued packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub id: u32,
    /// The sending socket's owner, when the kernel knows it.
    pub uid: Option<u32>,
    pub payload: Vec<u8>,
}

pub struct Queue {
    socket: Socket,
    num: u16,
    seq: AtomicU32,
}

/// `struct nfgenmsg`: family `AF_UNSPEC`, `NFNETLINK_V0`, and the queue
/// number, big-endian.
fn nfgen(num: u16) -> Vec<u8> {
    let mut out = vec![0, 0];
    out.extend_from_slice(&num.to_be_bytes());
    out
}

fn bind_payload(num: u16) -> Vec<u8> {
    let mut out = nfgen(num);
    // struct nfqnl_msg_config_cmd: command, padding, protocol family (0).
    netlink::push_attr(&mut out, NFQA_CFG_CMD, &[NFQNL_CFG_CMD_BIND, 0, 0, 0]);
    out
}

fn params_payload(num: u16) -> Vec<u8> {
    let mut out = nfgen(num);
    // struct nfqnl_msg_config_params (packed): copy range, copy mode.
    let mut params = COPY_RANGE.to_be_bytes().to_vec();
    params.push(NFQNL_COPY_PACKET);
    netlink::push_attr(&mut out, NFQA_CFG_PARAMS, &params);
    netlink::push_attr(&mut out, NFQA_CFG_QUEUE_MAXLEN, &MAX_QUEUED.to_be_bytes());
    let flags = NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_UID_GID;
    netlink::push_attr(&mut out, NFQA_CFG_MASK, &flags.to_be_bytes());
    netlink::push_attr(&mut out, NFQA_CFG_FLAGS, &flags.to_be_bytes());
    out
}

fn verdict_payload(num: u16, id: u32, accept: bool) -> Vec<u8> {
    let mut out = nfgen(num);
    // struct nfqnl_msg_verdict_hdr: verdict, packet id.
    let mut header = if accept { NF_ACCEPT } else { NF_DROP }
        .to_be_bytes()
        .to_vec();
    header.extend_from_slice(&id.to_be_bytes());
    netlink::push_attr(&mut out, NFQA_VERDICT_HDR, &header);
    out
}

/// Decodes an `NFQNL_MSG_PACKET` payload.
pub fn parse_packet(payload: &[u8]) -> Option<Packet> {
    let mut id = None;
    let mut uid = None;
    let mut data = None;
    for (kind, value) in netlink::attrs(payload.get(4..)?) {
        match kind {
            // struct nfqnl_msg_packet_hdr: packet id, hw protocol, hook.
            NFQA_PACKET_HDR => id = Some(u32::from_be_bytes(value.get(..4)?.try_into().ok()?)),
            NFQA_UID => uid = Some(u32::from_be_bytes(value.get(..4)?.try_into().ok()?)),
            NFQA_PAYLOAD => data = Some(value.to_vec()),
            _ => {}
        }
    }
    Some(Packet {
        id: id?,
        uid,
        payload: data?,
    })
}

impl Queue {
    /// Binds queue `num`. Fails with `EPERM` without `CAP_NET_ADMIN`, and
    /// with `EBUSY` when another program has the queue.
    pub fn bind(num: u16) -> io::Result<Self> {
        let socket = Socket::open(SockProtocol::NetlinkNetFilter)?;
        socket.set_timeout(Duration::from_secs(2))?;
        socket.request(NFQNL_MSG_CONFIG, 1, &bind_payload(num))?;
        socket.request(NFQNL_MSG_CONFIG, 2, &params_payload(num))?;
        // Room for a burst of queued packets; the kernel caps it at
        // net.core.rmem_max.
        socket.set_receive_buffer(1 << 20)?;
        Ok(Self {
            socket,
            num,
            seq: AtomicU32::new(3),
        })
    }

    pub fn num(&self) -> u16 {
        self.num
    }

    pub fn set_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.socket.set_timeout(timeout)
    }

    /// Waits for packets. `buf` must hold a whole netlink message.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Vec<Packet>> {
        let n = self.socket.recv(buf)?;
        let mut packets = Vec::new();
        for message in netlink::messages(&buf[..n]) {
            match message.kind {
                NFQNL_MSG_PACKET => match parse_packet(message.payload) {
                    Some(packet) => packets.push(packet),
                    None => tracing::warn!("ignoring a malformed queued packet"),
                },
                NLMSG_ERROR => {
                    if let Some(errno) = netlink::error_code(message.payload).filter(|&e| e != 0) {
                        tracing::warn!("nfqueue: {}", io::Error::from_raw_os_error(errno));
                    }
                }
                _ => {}
            }
        }
        Ok(packets)
    }

    pub fn verdict(&self, id: u32, accept: bool) -> io::Result<()> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        self.socket.send(&netlink::message(
            NFQNL_MSG_VERDICT,
            netlink::NLM_F_REQUEST,
            seq,
            &verdict_payload(self.num, id, accept),
        ))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An `NFQNL_MSG_PACKET` payload as the kernel sends it.
    pub fn packet_payload(id: u32, uid: Option<u32>, payload: &[u8]) -> Vec<u8> {
        let mut out = nfgen(7);
        let mut header = id.to_be_bytes().to_vec();
        header.extend_from_slice(&[0x08, 0x00, 3]);
        netlink::push_attr(&mut out, NFQA_PACKET_HDR, &header);
        netlink::push_attr(&mut out, 5, &2u32.to_be_bytes());
        if let Some(uid) = uid {
            netlink::push_attr(&mut out, NFQA_UID | 0x4000, &uid.to_be_bytes());
        }
        netlink::push_attr(&mut out, NFQA_PAYLOAD, payload);
        out
    }

    #[test]
    fn parses_queued_packets() {
        let payload = packet_payload(42, Some(1000), &[0x45, 1, 2]);
        assert_eq!(
            parse_packet(&payload),
            Some(Packet {
                id: 42,
                uid: Some(1000),
                payload: vec![0x45, 1, 2]
            })
        );
        let no_uid = parse_packet(&packet_payload(1, None, &[0x60])).unwrap();
        assert_eq!(no_uid.uid, None);
        // No packet header, or truncated before the attributes.
        assert_eq!(parse_packet(&payload[..3]), None);
        let mut headless = nfgen(7);
        netlink::push_attr(&mut headless, NFQA_PAYLOAD, &[0x45]);
        assert_eq!(parse_packet(&headless), None);
    }

    #[test]
    fn encodes_config_and_verdicts() {
        assert_eq!(
            bind_payload(0x1234),
            [0, 0, 0x12, 0x34, 8, 0, 1, 0, 1, 0, 0, 0]
        );
        let params = params_payload(1);
        let found: Vec<(u16, &[u8])> = netlink::attrs(&params[4..]).collect();
        assert_eq!(found[0], (NFQA_CFG_PARAMS, &[0, 0, 1, 0, 2][..]));
        assert_eq!(found[3], (NFQA_CFG_FLAGS, &[0, 0, 0, 9][..]));
        assert_eq!(
            verdict_payload(1, 0x01020304, true),
            [0, 0, 0, 1, 12, 0, 2, 0, 0, 0, 0, 1, 1, 2, 3, 4]
        );
        assert_eq!(verdict_payload(1, 5, false)[8..12], [0, 0, 0, 0]);
    }
}
