#ifndef ACTIONS_INSERT_SRV6_LIST_P4
#define ACTIONS_INSERT_SRV6_LIST_P4

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

action insert_srv6_list_4(IPv6Addr_t s1, IPv6Addr_t s2, IPv6Addr_t s3, IPv6Addr_t s4){
    hdr.ipv6.dstAddr = s1; // 修改目的地址
    hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 72; // 修正负载长度
    insert_srv6_header(4);
    hdr.srv6_list[0].setValid();
    hdr.srv6_list[0].segmentId = s4;
    hdr.srv6_list[1].setValid();
    hdr.srv6_list[1].segmentId = s3;
    hdr.srv6_list[2].setValid();
    hdr.srv6_list[2].segmentId = s2;
    hdr.srv6_list[3].setValid();
    hdr.srv6_list[3].segmentId = s1;
}

action insert_srv6_list_5(IPv6Addr_t s1, IPv6Addr_t s2, IPv6Addr_t s3, IPv6Addr_t s4, IPv6Addr_t s5){
    hdr.ipv6.dstAddr = s1; // 修改目的地址
    hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 88; // 修正负载长度
    insert_srv6_header(5);
    hdr.srv6_list[0].setValid();
    hdr.srv6_list[0].segmentId = s5;
    hdr.srv6_list[1].setValid();
    hdr.srv6_list[1].segmentId = s4;
    hdr.srv6_list[2].setValid();
    hdr.srv6_list[2].segmentId = s3;
    hdr.srv6_list[3].setValid();
    hdr.srv6_list[3].segmentId = s2;
    hdr.srv6_list[4].setValid();
    hdr.srv6_list[4].segmentId = s1;
}

action insert_srv6_list_6(IPv6Addr_t s1, IPv6Addr_t s2, IPv6Addr_t s3, IPv6Addr_t s4, IPv6Addr_t s5, IPv6Addr_t s6){
    hdr.ipv6.dstAddr = s1; // 修改目的地址
    hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 104; // 修正负载长度
    insert_srv6_header(6);
    hdr.srv6_list[0].setValid();
    hdr.srv6_list[0].segmentId = s6;
    hdr.srv6_list[1].setValid();
    hdr.srv6_list[1].segmentId = s5;
    hdr.srv6_list[2].setValid();
    hdr.srv6_list[2].segmentId = s4;
    hdr.srv6_list[3].setValid();
    hdr.srv6_list[3].segmentId = s3;
    hdr.srv6_list[4].setValid();
    hdr.srv6_list[4].segmentId = s2;
    hdr.srv6_list[5].setValid();
    hdr.srv6_list[5].segmentId = s1;
}
#endif