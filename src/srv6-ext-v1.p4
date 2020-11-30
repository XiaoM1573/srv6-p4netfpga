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
#define MAX_HOPS 6

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

// 发送给cpu，总共256位，推荐用于控制信号，用户可自定义
struct digest_data_t {
    bit<254>  unused;
    bit unknown_eth_dst;
    bit unknown_ip_dst;
}

// 保存用户定义的一些变量
struct user_metadata_t {
    bit<8> segment_list_cur; // 主要用于parse_srv6_list阶段
    IPv6Addr_t next_srv6_sid; // 用于记录下一跳sid
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
        digest_data.unknown_eth_dst = 0;
        digest_data.unknown_ip_dst = 0;

        user_metadata.segment_list_cur = 0;
        user_metadata.next_srv6_sid = 0;
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
        user_metadata.segment_list_cur = user_metadata.segment_list_cur + 1; // 相当于nextIndex，主要用来解决lastIndex在p4c-sdnet编译环境下无法通过问题
        bool is_current_segment = user_metadata.segment_list_cur == hdr.srv6.segmentLeft; // 判断是否是当前sid
        transition select(is_current_segment) {
            true: mark_next_sid;
            _: check_last_srv6;
        }
    }

    // 标记下一个sid
    state mark_next_sid {
        user_metadata.next_srv6_sid = hdr.srv6_list.last.segmentId;
        transition check_last_srv6;
    }

    // 判断是否遍历到segment list最后一个segment
    state check_last_srv6 {
        bool is_last_segment = user_metadata.segment_list_cur - 1 == hdr.srv6.lastEntry; // 作用和lastIndex一样，指向栈顶（最后一个元素）
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

    // TODO, 该部分后面会整合成一个action
    // 发送给控制端, 发现未知的目的mac
    action report_unknown_eth_dst() {
        sume_metadata.send_dig_to_cpu = 1;
        digest_data.unknown_eth_dst = 1;
    }

    // 发送给控制端, 发现未知的目的ip
    action report_unknown_ip_dst() {
        sume_metadata.send_dig_to_cpu = 1;
        digest_data.unknown_ip_dst = 1;
    }

    // 丢弃该包
    action drop() {
        sume_metadata.dst_port = 0;
    }

    // 设置数据包的物理出口
    action set_out_port(port_t port) {
        sume_metadata.dst_port = port;
    }

    // mac地址-端口映射表
    table l2_forward_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        action = {
            set_out_port;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    // 设置下一跳，替换源mac地址和目的mac地址，作用相当于ARP表和路由转发表
    action set_next_hop(EthAddr_t dmac) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dmac;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1; // decrement TTL
    }

    // ipv6路由表
    table ipv6_routing_table {
        key = {
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            set_next_hop;
            report_unknown_ip_dst;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    // 插入SRH，segment routing header
    action insert_srv6_header(bit<8> num_segments) {
        hdr.srv6.setValid();
        hdr.srv6.nextHdr = hdr.ipv6.nextHdr;
        hdr.srv6.hdrExtLen = num_segments;
        hdr.srv6.routingType = 4;
        hdr.srv6.segmentLeft = num_segments - 1;
        hdr.srv6.lastEntry = num_segments - 1;
        hdr.srv6.flags = 0;
        hdr.srv6.tag = 0;
        hdr.ipv6.nextHdr = PROTO_SRV6;
    }

    // 插入srv6 segment list
    #include "actions_insert_srv6_list.p4"

    // 用于入口节点处，used to inject SRv6 policy
    table srv6_source_node_table {
        key = {
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            insert_srv6_list_2;
            insert_srv6_list_3;
            insert_srv6_list_4;
            insert_srv6_list_5;
            insert_srv6_list_6;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    // 用于出口节点，需要移除掉srv6头，也就是倒数第二跳，最后一跳就是目的地址
    action pop_srv6() {
        hdr.ipv6.nextHdr = hdr.srv6.nextHdr;
        // srv6 header (SRH) outer is 8 bytes.
        // srv6 segment list is 16 bytes each
        bit<16> srv6_size = (((bit<16>)hdr.srv6.lastEntry + 1) << 4) + 8;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen - srv6_size;

        hdr.srv6.setInvalid();
        // Need to set MAX_HOPS headers invalid
        hdr.srv6_list[0].setInvalid();
        hdr.srv6_list[1].setInvalid();
        hdr.srv6_list[2].setInvalid();
        hdr.srv6_list[3].setInvalid();
        hdr.srv6_list[4].setInvalid();
        hdr.srv6_list[5].setInvalid();
    }

    // srv6 endpoint behavior(a participating waypoint in an SRv6 policy), need to modify the SRv6 header and perform a specified function
    action end_action(){
        // decrement segment left
        hdr.srv6.segmentLeft = hdr.srv6.segmentLeft - 1;
        // 修改目的地址
        hdr.ipv6.dstAddr = user_metadata.next_srv6_sid;
    }

    // 用于判断当前节点是不是end node，如果是执行end_action
    table srv6_end_node_table {
        key = {
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            end_action;
        }
        size = 64;
        default_action = end_action;
    }

    // 用于判断目的router/switch/host是否是支持srv6
    table srv6_stations_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = { NoAction; }
        size = 64;
        default_action = NoAction;
    }

    apply{
        // 如果是ipv6数据包，查看当前设备是否支持srv6
        if(hdr.ipv6.isValid() && srv6_stations_table.apply().hit){
            // TODO，这里只对source node, end node 讨论， tansit node 暂时先不考虑
            if(srv6_end_node_table.apply().hit){
                if(hdr.srv6.isValid() && hdr.srv6.segmentLeft == 0){
                    pop_srv6();
                }
            }else{
                srv6_source_node_table.apply();
            }
            ipv6_routing_table.apply();
            if(hdr.ipv6.hopLimit == 0){drop();}
        }
        l2_forward_table.apply();
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