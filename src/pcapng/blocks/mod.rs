pub mod custom;
pub mod enhanced_packet;
pub mod interface_description;
pub mod interface_statistics;
pub mod name_resolution;
pub mod obsoleted_packet;
pub mod section_header;
pub mod simple_packet;
pub mod timestamp;

pub use self::custom::CustomBlock;
pub use self::enhanced_packet::{
    epb_dropcount, epb_flags, epb_hash, EnhancedPacket, HASH_ALGO_2S_COMPLEMENT, HASH_ALGO_CRC32,
    HASH_ALGO_MD5, HASH_ALGO_SHA1, HASH_ALGO_XOR,
};
pub use self::interface_description::{
    if_description, if_euiaddr, if_fcslen, if_filter, if_ipv4addr, if_ipv6addr, if_macaddr,
    if_name, if_os, if_speed, if_tsoffset, if_tsresol, if_tzone, InterfaceDescription,
};
pub use self::interface_statistics::{
    isb_endtime, isb_filteraccept, isb_ifdrop, isb_ifrecv, isb_osdrop, isb_starttime, isb_usrdeliv,
    InterfaceStatistics,
};
pub use self::name_resolution::{
    nrb_record_end, nrb_record_ipv4, nrb_record_ipv6, ns_dnsip4addr, ns_dnsip6addr, ns_dnsname,
    NameResolution,
};
pub use self::obsoleted_packet::{pack_flags, pack_hash, ObsoletedPacket};
pub use self::section_header::{
    shb_hardware, shb_os, shb_userappl, SectionHeader, BYTE_ORDER_MAGIC,
};
pub use self::simple_packet::SimplePacket;
pub use self::timestamp::Timestamp;

#[repr(u32)]
#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
pub enum BlockType {
    CustomBlock = self::custom::BLOCK_TYPE,
    PrivateCustomBlock = self::custom::PRIVATE_BLOCK_TYPE,
    EnhancedPacket = self::enhanced_packet::BLOCK_TYPE,
    InterfaceDescription = self::interface_description::BLOCK_TYPE,
    InterfaceStatistics = self::interface_statistics::BLOCK_TYPE,
    NameResolution = self::name_resolution::BLOCK_TYPE,
    ObsoletedPacket = self::obsoleted_packet::BLOCK_TYPE,
    SectionHeader = self::section_header::BLOCK_TYPE,
    SimplePacket = self::simple_packet::BLOCK_TYPE,
}
