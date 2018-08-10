extern crate chrono;
#[macro_use]
extern crate log;
extern crate either;
extern crate glob;
extern crate hexplay;
extern crate httparse;
extern crate itertools;
extern crate pnet;
extern crate pretty_env_logger;

extern crate pcap2;

use std::cell::RefCell;
use std::cmp;
use std::fmt;
use std::fmt::Write;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::rc::Rc;

use chrono::{DateTime, Local};
use either::Either;
use glob::glob;
use httparse::{Request as HttpRequest, Response as HttpResponse, EMPTY_HEADER};
use pcap2::{pcap, pcapng};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::{TcpFlags::*, TcpPacket},
    udp::UdpPacket,
    Packet,
};
use std::collections::HashMap;

const TCP_FLAGS: &[(u16, char)] = &[
    (FIN, 'F'),
    (SYN, 'S'),
    (RST, 'R'),
    (PSH, 'P'),
    (ACK, '.'),
    (URG, 'U'),
    (ECE, 'E'),
    (CWR, 'W'),
];

const HTTP_PORT: u16 = 80;
const HTTP_PORT_ALT: u16 = 8080;

type IpAddr = Either<Ipv4Addr, Ipv6Addr>;

trait IpPacket {
    fn get_source(&self) -> IpAddr;

    fn get_destination(&self) -> IpAddr;
}

impl<'a> IpPacket for Either<&'a Ipv4Packet<'a>, &'a Ipv6Packet<'a>> {
    fn get_source(&self) -> IpAddr {
        self.map_left(|pkt| pkt.get_source())
            .map_right(|pkt| pkt.get_source())
    }

    fn get_destination(&self) -> IpAddr {
        self.map_left(|pkt| pkt.get_destination())
            .map_right(|pkt| pkt.get_destination())
    }
}

#[derive(Clone, Debug)]
struct SessionKey {
    pub proto: IpNextHeaderProtocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl SessionKey {
    pub fn tcp_v4(ip_pkt: &Ipv4Packet, tcp_pkt: &TcpPacket) -> Self {
        SessionKey {
            proto: IpNextHeaderProtocols::Tcp,
            src_ip: Either::Left(ip_pkt.get_source()),
            src_port: tcp_pkt.get_source(),
            dst_ip: Either::Left(ip_pkt.get_destination()),
            dst_port: tcp_pkt.get_destination(),
        }
    }

    pub fn tcp_v6(ip_pkt: &Ipv6Packet, tcp_pkt: &TcpPacket) -> Self {
        SessionKey {
            proto: IpNextHeaderProtocols::Tcp,
            src_ip: Either::Right(ip_pkt.get_source()),
            src_port: tcp_pkt.get_source(),
            dst_ip: Either::Right(ip_pkt.get_destination()),
            dst_port: tcp_pkt.get_destination(),
        }
    }

    pub fn udp_v4(ip_pkt: &Ipv4Packet, udp_pkt: &UdpPacket) -> Self {
        SessionKey {
            proto: IpNextHeaderProtocols::Udp,
            src_ip: Either::Left(ip_pkt.get_source()),
            src_port: udp_pkt.get_source(),
            dst_ip: Either::Left(ip_pkt.get_destination()),
            dst_port: udp_pkt.get_destination(),
        }
    }

    pub fn udp_v6(ip_pkt: &Ipv6Packet, udp_pkt: &UdpPacket) -> Self {
        SessionKey {
            proto: IpNextHeaderProtocols::Udp,
            src_ip: Either::Right(ip_pkt.get_source()),
            src_port: udp_pkt.get_source(),
            dst_ip: Either::Right(ip_pkt.get_destination()),
            dst_port: udp_pkt.get_destination(),
        }
    }

    fn as_tuple(&self) -> (IpNextHeaderProtocol, (IpAddr, u16), (IpAddr, u16)) {
        (
            self.proto,
            cmp::min((self.src_ip, self.src_port), (self.dst_ip, self.dst_port)),
            cmp::max((self.src_ip, self.src_port), (self.dst_ip, self.dst_port)),
        )
    }
}

impl PartialEq for SessionKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_tuple() == other.as_tuple()
    }
}

impl Eq for SessionKey {}

impl Hash for SessionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_tuple().hash(state)
    }
}

#[derive(Clone, Debug)]
struct Session {
    pub key: SessionKey,
    pub seq: u32,
    pub ack: u32,
}

impl Deref for Session {
    type Target = SessionKey;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

impl Session {
    pub fn new(key: SessionKey) -> Self {
        Session {
            key,
            seq: 0,
            ack: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.seq == 0 && self.ack == 0
    }
}

struct Dumper<W> {
    w: W,
    sessions: Rc<RefCell<HashMap<SessionKey, Rc<RefCell<Session>>>>>,
}

impl<W: Write> Dumper<W> {
    pub fn new(w: W, sessions: Rc<RefCell<HashMap<SessionKey, Rc<RefCell<Session>>>>>) -> Self {
        Dumper { w, sessions }
    }

    pub fn into_inner(self) -> W {
        self.w
    }

    fn get_session(&mut self, sesson_key: SessionKey) -> Rc<RefCell<Session>> {
        self.sessions
            .borrow_mut()
            .entry(sesson_key.clone())
            .or_insert_with(|| {
                debug!(
                    "create new session: {:?}, {:?}",
                    sesson_key,
                    sesson_key.as_tuple()
                );

                Rc::new(RefCell::new(Session::new(sesson_key)))
            })
            .clone()
    }

    fn dump_pcap_packet<'a>(&mut self, pkt: pcap::Packet<'a>) -> fmt::Result {
        let ts = DateTime::<Local>::from(pkt.timestamp).time();
        let pkt = EthernetPacket::new(&pkt.payload).unwrap();

        write!(&mut self.w, "{:?} ", ts)?;

        self.dump_ethernet_packet(&pkt)
    }

    fn dump_ethernet_packet(&mut self, ether_pkt: &EthernetPacket) -> fmt::Result {
        write!(&mut self.w, "IP ")?;

        match ether_pkt.get_ethertype() {
            EtherTypes::Ipv4 => {
                self.dump_ipv4_packet(Ipv4Packet::new(ether_pkt.payload()).unwrap())
            }
            EtherTypes::Ipv6 => {
                self.dump_ipv6_packet(Ipv6Packet::new(ether_pkt.payload()).unwrap())
            }
            _ => unimplemented!(),
        }
    }

    fn dump_ipv4_packet(&mut self, ipv4_pkt: Ipv4Packet) -> fmt::Result {
        match ipv4_pkt.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_pkt = TcpPacket::new(ipv4_pkt.payload()).unwrap();
                let session_key = SessionKey::tcp_v4(&ipv4_pkt, &tcp_pkt);
                let session = self.get_session(session_key);

                self.dump_tcp_packet(tcp_pkt, Either::Left(&ipv4_pkt), session)
            }
            IpNextHeaderProtocols::Udp => {
                let udp_pkt = UdpPacket::new(ipv4_pkt.payload()).unwrap();
                let session_key = SessionKey::udp_v4(&ipv4_pkt, &udp_pkt);
                let session = self.get_session(session_key);

                self.dump_udp_packet(udp_pkt, Either::Left(&ipv4_pkt), session)
            }
            _ => unimplemented!(),
        }
    }

    fn dump_ipv6_packet(&mut self, ipv6_pkt: Ipv6Packet) -> fmt::Result {
        match ipv6_pkt.get_next_header() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_pkt = TcpPacket::new(ipv6_pkt.payload()).unwrap();
                let session_key = SessionKey::tcp_v6(&ipv6_pkt, &tcp_pkt);
                let session = self.get_session(session_key);

                self.dump_tcp_packet(tcp_pkt, Either::Right(&ipv6_pkt), session)
            }
            IpNextHeaderProtocols::Udp => {
                let udp_pkt = UdpPacket::new(ipv6_pkt.payload()).unwrap();
                let session_key = SessionKey::udp_v6(&ipv6_pkt, &udp_pkt);
                let session = self.get_session(session_key);

                self.dump_udp_packet(udp_pkt, Either::Right(&ipv6_pkt), session)
            }
            _ => unimplemented!(),
        }
    }

    fn dump_tcp_packet(
        &mut self,
        tcp_pkt: TcpPacket,
        ip_pkt: Either<&Ipv4Packet, &Ipv6Packet>,
        session_ref: Rc<RefCell<Session>>,
    ) -> fmt::Result {
        write!(
            &mut self.w,
            "{}.{} > {}.{}: Flags [{}]",
            ip_pkt.get_source(),
            tcp_pkt.get_source(),
            ip_pkt.get_destination(),
            tcp_pkt.get_destination(),
            TCP_FLAGS
                .iter()
                .filter(|(flag, _)| (tcp_pkt.get_flags() & *flag) == *flag)
                .map(|(_, name)| name)
                .collect::<String>()
        )?;

        let mut seq = tcp_pkt.get_sequence();
        let mut ack = tcp_pkt.get_acknowledgement();

        let is_sending = ip_pkt.get_source() == session_ref.borrow().src_ip;

        if session_ref.borrow().is_empty() || (tcp_pkt.get_flags() & SYN) == SYN {
            trace!("update session with TCP packet: {:?}", tcp_pkt);

            let mut session = session_ref.borrow_mut();

            if is_sending {
                session.seq = tcp_pkt.get_sequence();
                session.ack = tcp_pkt
                    .get_acknowledgement()
                    .checked_sub(1)
                    .unwrap_or_default();
            } else {
                session.ack = tcp_pkt.get_sequence();
                session.seq = tcp_pkt
                    .get_acknowledgement()
                    .checked_sub(1)
                    .unwrap_or_default();
            }
        } else {
            let session = session_ref.borrow();

            if is_sending {
                seq -= session.seq;
                ack -= session.ack;
            } else {
                seq -= session.ack;
                ack -= session.seq;
            }
        }

        if !tcp_pkt.payload().is_empty() || (tcp_pkt.get_flags() & (SYN | FIN | RST)) != 0 {
            write!(&mut self.w, ", seq {}", seq)?;

            if !tcp_pkt.payload().is_empty() {
                write!(&mut self.w, ":{}", seq as usize + tcp_pkt.payload().len())?;
            }
        }

        if (tcp_pkt.get_flags() & ACK) != 0 {
            write!(&mut self.w, ", ack {}", ack)?;
        }

        write!(&mut self.w, ", win {}", tcp_pkt.get_window())?;

        if (tcp_pkt.get_flags() & URG) != 0 {
            write!(&mut self.w, ", urg {}", tcp_pkt.get_urgent_ptr())?;
        }

        write!(&mut self.w, ", length {}", tcp_pkt.payload().len())?;

        if tcp_pkt.payload().is_empty() {
            Ok(())
        } else {
            match (tcp_pkt.get_source(), tcp_pkt.get_destination()) {
                (_, HTTP_PORT) | (_, HTTP_PORT_ALT) => self.dump_http_request(tcp_pkt.payload()),
                (HTTP_PORT, _) | (HTTP_PORT_ALT, _) => self.dump_http_response(tcp_pkt.payload()),
                _ => Ok(()),
            }
        }
    }

    fn dump_udp_packet(
        &mut self,
        udp_pkt: UdpPacket,
        ip_pkt: Either<&Ipv4Packet, &Ipv6Packet>,
        session_ref: Rc<RefCell<Session>>,
    ) -> fmt::Result {
        write!(
            &mut self.w,
            "{}.{} > {}.{}",
            ip_pkt.get_source(),
            udp_pkt.get_source(),
            ip_pkt.get_destination(),
            udp_pkt.get_destination(),
        )
    }

    fn dump_http_request(&mut self, payload: &[u8]) -> fmt::Result {
        let mut headers = [EMPTY_HEADER; 16];
        let mut req = HttpRequest::new(&mut headers);

        req.parse(payload).unwrap();

        write!(
            &mut self.w,
            ": HTTP: {} {} HTTP/1.{}",
            req.method.unwrap_or_default(),
            req.path.unwrap_or_default(),
            req.version.unwrap_or_default()
        )
    }

    fn dump_http_response(&mut self, payload: &[u8]) -> fmt::Result {
        let mut headers = [EMPTY_HEADER; 16];
        let mut res = HttpResponse::new(&mut headers);

        res.parse(payload).unwrap();

        write!(
            &mut self.w,
            ": HTTP: HTTP/1.{} {} {}",
            res.version.unwrap_or_default(),
            res.code.unwrap_or_default(),
            res.reason.unwrap_or_default()
        )
    }
}

#[test]
fn test_pcap_data() {
    let _ = pretty_env_logger::try_init();

    for entry in glob("tests/data/*.pcap").unwrap() {
        let path = entry.unwrap();
        let sessions = Rc::new(RefCell::new(HashMap::new()));

        let packets = pcap::open(&path).unwrap().into_iter().map(|packet| {
            let mut dumper = Dumper::new(String::new(), sessions.clone());
            dumper.dump_pcap_packet(packet).unwrap();
            dumper.into_inner()
        });

        let dumps = BufReader::new(File::open(path.with_extension("tcpdump")).unwrap())
            .lines()
            .flat_map(|line| line);

        if let Some(diff) = itertools::diff_with(packets, dumps, |lhs, rhs| lhs == rhs) {
            match diff {
                itertools::Diff::Shorter(n, _) => {
                    panic!("{:?} decoded too many packets, {} more then dumps", path, n)
                }
                itertools::Diff::Longer(n, _) => {
                    panic!("{:?} decoded too few packets, {} less then dumps", path, n)
                }
                itertools::Diff::FirstMismatch(n, mut packets, mut dumps) => panic!(
                    "{:?} decoded #{} packet mismatch:\npacket:\n\t{}\ndumps:\n\t{}",
                    path,
                    n,
                    packets.next().unwrap(),
                    dumps.next().unwrap()
                ),
            }
        }
    }
}

#[test]
fn test_pcapng_data() {}

#[test]
fn test_generated_data() {}
