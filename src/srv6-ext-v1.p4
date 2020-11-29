#include <core.p4>
#include <sume_switch.p4>


/*******************************************************************/
/**************************** Constants ****************************/
/*******************************************************************/
typedef bit<48> EthAddr_t;
typedef bit<32> IPv4Addr_t;
typedef bit<128> IPv6Addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86DD;

// some common protocols code
const bit<8> PROTO_ICMP = 1;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_SRV6 = 43;
const bit<8> PROTO_ICMPV6 = 58;

// According to your own needs, customize the maximum depth of segment list
#define MAX_HOPS 15

/*******************************************************************/
/**************************** Header *******************************/
/*******************************************************************/

header Ethernet_h {
    EthAddr_t dstAddr;
    EthAddr_t srcAddr;
    bit<16> etherType;
}

header IPv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    IPv4Addr_t srcAddr;
    IPv4Addr_t dstAddr;
}

header IPv6_h {
    bit<4> version;
    bit<8> trafficClass;
    bit<20> flowLabel;
    bit<16> payloadLen;
    bit<8> nextHdr;
    bit<8> hopLimit;
    IPv6Addr_t srcAddr;
    IPv6Addr_t dstAddr;
}

header TCP_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header UDP_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}

header ICMP_h {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header ICMPv6_h {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header SRv6_h {
    bit<8> nextHdr;
    bit<8> hdrExtLen;
    bit<8> routingType;
    bit<8> segmentLeft;
    bit<8> lastEntry;
    bit<8> flags;
    bit<16> tag;
}

header SRv6_list_h {
    IPv6Addr_t segmentId;
}

// 需要解析的headers
struct Parsed_packet {
    Ethernet_h ethernet;
    IPv4_h ipv4;
    IPv6_h ipv6;
    SRv6_h srv6;
    SRv6_list_h[MAX_HOPS] srv6_list;
    TCP_h tcp;
    UDP_h udp;
    ICMP_h icmp;
    ICMPv6_h icmpv6;
}

// 发送给cpu，总共256位
struct digest_data_t {
    bit<256>  unused;
}

// 保存用户定义的一些变量
struct user_metadata_t {
    bit<8> segment_list_cur; // 主要用于parse_srv6_list阶段
}


/*******************************************************************/
/**************************** Parser *******************************/
/*******************************************************************/

@Xilinx_MaxPacketRegion(16384)
parser TopParser(packet_in packet,
                 out Parsed_packet hdr,
                 out user_metadata_t user_metadata,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata){
    state start {
        // user_metadata 和 digest_data 初始化, 否则会有警告信息
        digest_data.unused = 0;
        user_metadata.segment_list_cur = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            PROTO_TCP:  parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMP: parse_icmp;
            _: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr){
            PROTO_TCP:  parse_tcp;
            PROTO_UDP: parse_udp;
            PROTO_ICMPV6: parse_icmpv6;
            PROTO_SRV6: parse_srv6;
            _: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition: accept
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition: accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition: accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition: accept;
    }

    state parse_srv6 {
        packet.extract(hdr.srv6);
        transition parse_srv6_list;
    }

    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        // bool next_segment = (bit<32>)hdr.srv6_list.lastIndex == (bit<32>)hdr.srv6.segmentLeft - 1; // lastIndex无法在p4c-sdnet编译环境下通过
        bool is_last_segment = user_metadata.segment_list_cur == hdr.srv6.lastEntry; // 作用和lastIndex一样，指向栈顶（最后一个元素）
        // TODO, 这里并没有判断segment list的长度是否超过我们设置的阈值MAX_HOPS，现在考虑的场景比较简单，后面有待完善
        user_metadata.segment_list_cur = user_metadata.segment_list_cur + 1;
        // 循环读取srv6 segment list区域
        transition select(is_last_segment) {
            true: parse_srv6_next_hdr;
            _: parse_srv6_list;
        }
    }

    state parse_srv6_next_hdr {
        transition accept;
    }
}

/*******************************************************************/
/******************** Match Action Pipeline ************************/
/*******************************************************************/

control TopPipe(inout Parsed_packet hdr,
                inout user_metadata_t user_metadata,
                inout digest_data_t digest_data,
                inout sume_metadata_t sume_metadata){
    action drop() {
        sume_metadata.dst_port = 0;
    }



    apply{

    }
}

/*******************************************************************/
/*************************** Deparser ******************************/
/*******************************************************************/

@Xilinx_MaxPacketRegion(16384)
control TopDeparser(packet_out packet,
                    in Parsed_packet hdr,
                    in user_metadata_t user_metadata,
                    inout digest_data_t digest_data,
                    inout sume_metadata_t sume_metadata){
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.srv6);
        packet.emit(hdr.srv6_list);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
    }
}

SimpleSumeSwitch(
    TopParser(),
    TopPipe(),
    TopDeparser()
) main;