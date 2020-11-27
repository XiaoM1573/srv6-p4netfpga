// 头文件
#include <core.p4>
#include <sume_switch.p4>
#include <xilinx.p4>
#include <xilinx_core.p4>

/********************** Constants ************************/
// 首先定义一些需要的地址格式以及常量
typedef bit<48> EthAddr_t;
typedef bit<32> IPv4Addr_t;
typedef bit<128> IPv6Addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86DD;

const bit<8> PROTO_SRV6 = 43;

// segment list的最大深度
#define MAX_HOPS 4
/********************** Headers ************************/
// 以太网头
header Ethernet_h {
    EthAddr_t dstAddr;
    EthAddr_t srcAddr;
    bit<16> etherType;
}

// IPv4头
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

// IPv6头
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

// SRv6头
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

/********************** Struct ************************/
// 需要解析的包头
struct Parsed_packet {
    Ethernet_h ethernet;
    IPv4_h ipv4;
    IPv6_h ipv6;
    SRv6_h srv6;
    SRv6_list_h[MAX_HOPS] srv6_list;
}

// 发送给cpu的摘要信息
struct digest_data_t {
    bit<248>  unused;
    port_t src_port;
}

// 自定义的一些元数据
struct user_metadata_t {
    bit<8>  unused;
    IPv6Addr_t next_srv6_sid; //记录下一跳sid
    bit<8> segment_list_cur; // 主要用于parse_srv6_list阶段
}



/********************** Parser ************************/
// 解析headers
@Xilinx_MaxPacketRegion(16384)
parser TopParser(packet_in packet,
                 out Parsed_packet hdr,
                 out user_metadata_t user_metadata,
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata){


    state start{
        packet.extract(hdr.ethernet);
        // user_metadata 和 digest_data 初始化, 否则会有警告信息
        user_metadata.unused = 0;
        user_metadata.next_srv6_sid = 0;
        user_metadata.segment_list_cur = 0;
        digest_data.unused = 0;
        digest_data.src_port = 0;

        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        transition accept;
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr){
            PROTO_SRV6: parse_srv6;
            default: accept;
        }
    }

    state parse_srv6 {
        packet.extract(hdr.srv6);
        transition parse_srv6_list;
    }

    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        // bool next_segment = (bit<32>)hdr.srv6_list.lastIndex == (bit<32>)hdr.srv6.segmentLeft - 1; // lastIndex无法在p4c-sdnet编译环境下通过
        bool is_last_segment = user_metadata.segment_list_cur == hdr.srv6.lastEntry; // 作用和lastIndex一样，指向栈顶（最后一个元素）
        user_metadata.segment_list_cur = user_metadata.segment_list_cur + 1;
        // 循环读取srv6 segment list区域
        transition select(is_last_segment) {
            true: parse_srv6_next_hdr;
            _: parse_srv6_list;
        }
    }
    /*
    state mark_current_srv6 {
        user_metadata.next_srv6_sid = hdr.srv6_list.last.segmentId;
        transition check_last_srv6;
    }

    // 检查当前是否是倒数第二跳
    state check_last_srv6 {
        bool last_segment = (bit<32>)hdr.srv6.lastEntry == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(last_segment) {
            true: parse_srv6_next_hdr;
            false: parse_srv6_list;
        }
    }*/

    state parse_srv6_next_hdr {
        transition accept;
    }
}

/********************** Control ************************/
// match-action pipe
control TopPipe(inout Parsed_packet hdr,
                inout user_metadata_t user_metadata,
                inout digest_data_t digest_data,
                inout sume_metadata_t sume_metadata){
/*
    action send_to_control() {
        digest_data.src_port = sume_metadata.src_port;
        digest_data.eth_src_addr = 16w0 ++ hdr.ethernet.srcAddr;
        sume_metadata.send_dig_to_cpu = 1;
    }
    */

    action set_out_port(port_t port) {
        sume_metadata.dst_port = port;
    }

    // Mac地址-port 映射表
    table l2_exact_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_out_port;
            NoAction;
        }

        default_action = NoAction;
    }

    // 设置下一跳的mac地址
    action set_next_hop(EthAddr_t dmac) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dmac;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1; // decrement TTL
    }

    table ipv6_routing_table {
        key = {
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            set_next_hop;
        }
    }

    // 插入SRH
    action insert_srv6_header(bit<8> num_segments) {
        hdr.srv6.setValid();
        hdr.srv6.nextHdr = hdr.ipv6.nextHdr;
        hdr.srv6.hdrExtLen = num_segments * 2;
        hdr.srv6.routingType = 4;
        hdr.srv6.segmentLeft = num_segments - 1;
        hdr.srv6.lastEntry = num_segments - 1;
        hdr.srv6.flags = 0;
        hdr.srv6.tag = 0;
        hdr.ipv6.nextHdr = PROTO_SRV6;
    }


    // 插入单个segment，没有任何意义，也就是插入了一个目的地址
    action insert_srv6_list_2(IPv6Addr_t s1, IPv6Addr_t s2){
        hdr.ipv6.dstAddr = s1; // 修改目的地址
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 40; // 修正负载长度
        insert_srv6_header(2);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segmentId = s2;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segmentId = s1;
    }

    action insert_srv6_list_3(IPv6Addr_t s1, IPv6Addr_t s2, IPv6Addr_t s3){
        hdr.ipv6.dstAddr = s1; // 修改目的地址
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 56; // 修正负载长度
        insert_srv6_header(3);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segmentId = s3;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segmentId = s2;
        hdr.srv6_list[2].setValid();
        hdr.srv6_list[2].segmentId = s1;
    }

    // 针对的是入口节点，
    table srv6_transit_table {
        key = {
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            insert_srv6_list_2;
            insert_srv6_list_3;
            NoAction;
        }
        default_action = NoAction;
    }

    // 出口节点，需要弹出srv6头
    action pop_srv6() {
        hdr.ipv6.nextHdr = hdr.srv6.nextHdr;
        // srv6 header (SRH) is 8 bytes.
        // srv6 segment list is 16 bytes each
        bit<16> srv6_size = (((bit<16>)hdr.srv6.lastEntry + 1) << 4) + 8;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen - srv6_size;

        hdr.srv6.setInvalid();
        // Need to set MAX_HOPS headers invalid
        hdr.srv6_list[0].setInvalid();
        hdr.srv6_list[1].setInvalid();
        hdr.srv6_list[2].setInvalid();
    }


    // srv6 endpoint behavior
    action end_action(){
        // decrement segment left
        hdr.srv6.segmentLeft = hdr.srv6.segmentLeft - 1;
        // 修改目的地址
        hdr.ipv6.dstAddr = user_metadata.next_srv6_sid;
    }

    // 中间节点
    table srv6_sid_table {
        key = {
            hdr.ipv6.dstAddr: exact;
        }

        actions = {
            end_action;
            NoAction;
        }
        default_action = NoAction;
    }

    action drop(){
        sume_metadata.dst_port = 0;
    }


    apply {
        if(hdr.ipv6.isValid()){
            if(srv6_sid_table.apply().hit){
                if(hdr.srv6.isValid() && hdr.srv6.segmentLeft == 0){ // 中间节点
                    pop_srv6();
                }
            }else{ // 入口节点
                srv6_transit_table.apply();
            }

            ipv6_routing_table.apply();
            if(hdr.ipv6.hopLimit == 0){
                drop();
            }
        }

        l2_exact_table.apply();
    }


}


/********************** Deparser ************************/
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
    }
}

SimpleSumeSwitch(
    TopParser(),
    TopPipe(),
    TopDeparser()
) main;