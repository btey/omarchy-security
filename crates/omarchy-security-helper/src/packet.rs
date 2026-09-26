// SPDX-License-Identifier: GPL-3.0-or-later

//! Parses the IP and TCP/UDP headers of a packet from the NFQUEUE, as far
//! as needed to name its connection (plan §5.7).
//!
//! The input comes from the kernel, but the parser treats it as untrusted:
//! every length is checked, and anything it does not understand yields
//! `None` rather than a guess.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use omarchy_security_proto::types::Protocol;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// IPv6 extension headers that may sit between the fixed header and the
/// transport header: hop-by-hop, routing, destination options, and AH.
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_AH: u8 = 51;
const IPPROTO_DSTOPTS: u8 = 60;

/// One direction of a connection: the packet's source is the local side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flow {
    pub protocol: Protocol,
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
}

pub fn parse(packet: &[u8]) -> Option<Flow> {
    match packet.first()? >> 4 {
        4 => parse_v4(packet),
        6 => parse_v6(packet),
        _ => None,
    }
}

fn parse_v4(packet: &[u8]) -> Option<Flow> {
    let header_len = usize::from(packet.first()? & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    // A fragment other than the first has no transport header.
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x1fff != 0 {
        return None;
    }
    let src = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?);
    let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?);
    transport(packet[9], &packet[header_len..], src.into(), dst.into())
}

fn parse_v6(packet: &[u8]) -> Option<Flow> {
    if packet.len() < 40 {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    let mut next = packet[6];
    let mut rest = &packet[40..];
    loop {
        match next {
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS => {
                let len = (usize::from(*rest.get(1)?) + 1) * 8;
                next = *rest.first()?;
                rest = rest.get(len..)?;
            }
            IPPROTO_AH => {
                let len = (usize::from(*rest.get(1)?) + 2) * 4;
                next = *rest.first()?;
                rest = rest.get(len..)?;
            }
            IPPROTO_FRAGMENT => {
                let offset = u16::from_be_bytes([*rest.get(2)?, *rest.get(3)?]) >> 3;
                if offset != 0 {
                    return None;
                }
                next = *rest.first()?;
                rest = rest.get(8..)?;
            }
            _ => return transport(next, rest, src.into(), dst.into()),
        }
    }
}

fn transport(protocol: u8, header: &[u8], src: IpAddr, dst: IpAddr) -> Option<Flow> {
    let protocol = match protocol {
        IPPROTO_TCP => Protocol::Tcp,
        IPPROTO_UDP => Protocol::Udp,
        _ => return None,
    };
    let ports = header.get(..4)?;
    Some(Flow {
        protocol,
        src,
        sport: u16::from_be_bytes([ports[0], ports[1]]),
        dst,
        dport: u16::from_be_bytes([ports[2], ports[3]]),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn v4(protocol: u8, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[9] = protocol;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 16]);
        p
    }

    fn v6(next: u8, extensions: &[u8], sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = next;
        p[23] = 1; // ::1 → ::2
        p[39] = 2;
        p.extend_from_slice(extensions);
        p.extend_from_slice(&sport.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 4]);
        p
    }

    #[test]
    fn parses_ipv4_tcp_and_udp() {
        let flow = parse(&v4(6, [10, 0, 0, 1], 40000, [192, 0, 2, 7], 443)).unwrap();
        assert_eq!(
            flow,
            Flow {
                protocol: Protocol::Tcp,
                src: "10.0.0.1".parse().unwrap(),
                sport: 40000,
                dst: "192.0.2.7".parse().unwrap(),
                dport: 443,
            }
        );
        let flow = parse(&v4(17, [10, 0, 0, 1], 5353, [192, 0, 2, 7], 53)).unwrap();
        assert_eq!((flow.protocol, flow.dport), (Protocol::Udp, 53));
    }

    #[test]
    fn honours_ipv4_options_and_fragments() {
        let mut p = v4(6, [10, 0, 0, 1], 1, [10, 0, 0, 2], 2);
        // IHL 6: four bytes of options before the ports.
        p[0] = 0x46;
        p.splice(20..20, [1, 1, 1, 0]);
        assert_eq!(parse(&p).unwrap().dport, 2);
        let mut fragment = v4(6, [10, 0, 0, 1], 1, [10, 0, 0, 2], 2);
        fragment[7] = 1;
        assert_eq!(parse(&fragment), None);
    }

    #[test]
    fn walks_ipv6_extension_headers() {
        let flow = parse(&v6(17, &[], 1000, 53)).unwrap();
        assert_eq!(flow.dst, "::2".parse::<IpAddr>().unwrap());
        assert_eq!(
            (flow.protocol, flow.sport, flow.dport),
            (Protocol::Udp, 1000, 53)
        );
        // Hop-by-hop (8 bytes), then a first fragment (8 bytes), then TCP.
        let mut ext = vec![IPPROTO_FRAGMENT, 0, 0, 0, 0, 0, 0, 0];
        ext.extend_from_slice(&[IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 1]);
        let flow = parse(&v6(IPPROTO_HOPOPTS, &ext, 1, 443)).unwrap();
        assert_eq!((flow.protocol, flow.dport), (Protocol::Tcp, 443));
        // A later fragment: no ports.
        let later = [IPPROTO_TCP, 0, 0, 8, 0, 0, 0, 1];
        assert_eq!(parse(&v6(IPPROTO_FRAGMENT, &later, 1, 443)), None);
    }

    #[test]
    fn rejects_short_and_foreign_packets() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[0x45; 10]), None);
        let full = v4(6, [10, 0, 0, 1], 1, [10, 0, 0, 2], 2);
        for len in 0..24 {
            assert_eq!(parse(&full[..len]), None, "length {len}");
        }
        // ICMP.
        assert_eq!(parse(&v4(1, [10, 0, 0, 1], 1, [10, 0, 0, 2], 2)), None);
        // An extension header that claims more bytes than there are.
        assert_eq!(parse(&v6(IPPROTO_ROUTING, &[IPPROTO_TCP, 200], 1, 2)), None);
        assert_eq!(parse(&[0x20; 60]), None);
    }
}
