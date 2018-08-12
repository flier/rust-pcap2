extern crate chrono;
#[macro_use]
extern crate log;
extern crate either;
extern crate glob;
extern crate hexplay;
extern crate itertools;
extern crate pnet;
extern crate pretty_env_logger;

extern crate pcap2;

use std::fmt;
use std::fmt::Write;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Local};
use either::Either;
use glob::glob;
use pcap2::{pcap, pcapng};
use pnet::packet::{
    arp::{ArpOperations, ArpPacket},
    ethernet::{EtherTypes, EthernetPacket},
    icmp::{IcmpPacket, IcmpTypes::*},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    tcp::TcpPacket,
    udp::UdpPacket,
    Packet,
};

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

struct Dumper<W> {
    w: W,
}

impl<W: Write> Dumper<W> {
    pub fn new(w: W) -> Self {
        Dumper { w }
    }

    pub fn into_inner(self) -> W {
        self.w
    }

    fn dump_pcap_packet<'a>(&mut self, pkt: pcap::Packet<'a>) -> fmt::Result {
        let ts = DateTime::<Local>::from(pkt.timestamp).time();
        let pkt = EthernetPacket::new(&pkt.payload).unwrap();

        write!(&mut self.w, "{} ", ts.format("%H:%M:%S%.6f"))?;

        self.dump_ethernet_packet(&pkt)
    }

    fn dump_ethernet_packet(&mut self, ether_pkt: &EthernetPacket) -> fmt::Result {
        match ether_pkt.get_ethertype() {
            EtherTypes::Ipv4 => {
                self.dump_ipv4_packet(Ipv4Packet::new(ether_pkt.payload()).unwrap())
            }
            EtherTypes::Ipv6 => {
                self.dump_ipv6_packet(Ipv6Packet::new(ether_pkt.payload()).unwrap())
            }
            EtherTypes::Arp => self.dump_arp_packet(ArpPacket::new(ether_pkt.payload()).unwrap()),
            _ => unimplemented!(),
        }
    }

    fn dump_arp_packet(&mut self, arp_pkt: ArpPacket) -> fmt::Result {
        write!(&mut self.w, "ARP")?;

        match arp_pkt.get_operation() {
            ArpOperations::Request => {
                write!(
                    &mut self.w,
                    ", Request who-has {}",
                    arp_pkt.get_target_proto_addr(),
                )?;

                if arp_pkt.get_target_hw_addr() != unsafe { mem::zeroed() } {
                    write!(&mut self.w, " ({})", arp_pkt.get_target_hw_addr())?;
                }

                write!(&mut self.w, " tell {}", arp_pkt.get_sender_proto_addr())?;
            }
            ArpOperations::Reply => {
                write!(
                    &mut self.w,
                    ", Reply {} is-at {}",
                    arp_pkt.get_sender_proto_addr(),
                    arp_pkt.get_sender_hw_addr(),
                )?;
            }
            _ => unimplemented!(),
        }

        write!(&mut self.w, ", length {}", arp_pkt.packet().len())
    }

    fn dump_ipv4_packet(&mut self, ipv4_pkt: Ipv4Packet) -> fmt::Result {
        write!(&mut self.w, "IP ")?;

        match ipv4_pkt.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => self.dump_tcp_packet(
                TcpPacket::new(ipv4_pkt.payload()).unwrap(),
                Either::Left(&ipv4_pkt),
            ),
            IpNextHeaderProtocols::Udp => self.dump_udp_packet(
                UdpPacket::new(ipv4_pkt.payload()).unwrap(),
                Either::Left(&ipv4_pkt),
            ),
            IpNextHeaderProtocols::Icmp => {
                self.dump_icmp_packet(IcmpPacket::new(ipv4_pkt.payload()).unwrap(), &ipv4_pkt)
            }
            _ => {
                warn!(
                    "unsupport protocol: {}\n{:#?}",
                    ipv4_pkt.get_next_level_protocol(),
                    ipv4_pkt
                );

                unimplemented!()
            }
        }
    }

    fn dump_ipv6_packet(&mut self, ipv6_pkt: Ipv6Packet) -> fmt::Result {
        write!(&mut self.w, "IP ")?;

        match ipv6_pkt.get_next_header() {
            IpNextHeaderProtocols::Tcp => self.dump_tcp_packet(
                TcpPacket::new(ipv6_pkt.payload()).unwrap(),
                Either::Right(&ipv6_pkt),
            ),
            IpNextHeaderProtocols::Udp => self.dump_udp_packet(
                UdpPacket::new(ipv6_pkt.payload()).unwrap(),
                Either::Right(&ipv6_pkt),
            ),
            _ => {
                warn!(
                    "unsupport protocol: {}\n{:#?}",
                    ipv6_pkt.get_next_header(),
                    ipv6_pkt
                );

                unimplemented!()
            }
        }
    }

    fn dump_tcp_packet(
        &mut self,
        tcp_pkt: TcpPacket,
        ip_pkt: Either<&Ipv4Packet, &Ipv6Packet>,
    ) -> fmt::Result {
        write!(
            &mut self.w,
            "{}.{} > {}.{}",
            ip_pkt.get_source(),
            tcp_pkt.get_source(),
            ip_pkt.get_destination(),
            tcp_pkt.get_destination(),
        )
    }

    fn dump_udp_packet(
        &mut self,
        udp_pkt: UdpPacket,
        ip_pkt: Either<&Ipv4Packet, &Ipv6Packet>,
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

    fn dump_icmp_packet(&mut self, icmp_pkt: IcmpPacket, ip_pkt: &Ipv4Packet) -> fmt::Result {
        write!(
            &mut self.w,
            "{} > {}: ICMP ",
            ip_pkt.get_source(),
            ip_pkt.get_destination()
        )?;

        match icmp_pkt.get_icmp_type() {
            TimeExceeded => {
                write!(&mut self.w, "time exceeded in-transit")?;
            }
            _ => {
                warn!(
                    "ignore unsupport ICMP type: {:?}\n{:#?}",
                    icmp_pkt.get_icmp_type(),
                    icmp_pkt
                );

                return Ok(());
            }
        }

        write!(&mut self.w, ", length {}", icmp_pkt.packet().len())
    }
}

#[test]
fn test_pcap_data() {
    let _ = pretty_env_logger::try_init();

    for entry in glob("tests/data/*.pcap").unwrap() {
        let path = entry.unwrap();

        let packets = pcap::open(&path).unwrap().into_iter().map(|packet| {
            let mut dumper = Dumper::new(String::new());
            dumper.dump_pcap_packet(packet).unwrap();
            dumper.into_inner()
        });

        let dumps = BufReader::new(File::open(path.with_extension("tcpdump")).unwrap())
            .lines()
            .flat_map(|line| line)
            .filter(|line| !line.is_empty());

        if let Some(diff) = itertools::diff_with(packets, dumps, |lhs, rhs| rhs.starts_with(lhs)) {
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
