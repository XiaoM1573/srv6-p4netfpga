#!/usr/bin/env python
# coding=utf-8

#
# Copyright (c) 2017 Stephen Ibanez
# All rights reserved.
#
# This software was developed by Stanford University and the University of Cambridge Computer Laboratory
# under National Science Foundation under Grant No. CNS-0855268,
# the University of Cambridge Computer Laboratory under EPSRC INTERNET Project EP/H040536/1 and
# by the University of Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249 ("MRC2"),
# as part of the DARPA MRC research programme.
#
# @NETFPGA_LICENSE_HEADER_START@
#
# Licensed to NetFPGA C.I.C. (NetFPGA) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  NetFPGA licenses this
# file to you under the NetFPGA Hardware-Software License, Version 1.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at:
#
#   http://www.netfpga-cic.org
#
# Unless required by applicable law or agreed to in writing, Work distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations under the License.
#
# @NETFPGA_LICENSE_HEADER_END@
#


from nf_sim_tools import *
import random
from collections import OrderedDict
import sss_sdnet_tuples

###########
# pkt generation tools
###########

pktsApplied = []
pktsExpected = []

# Pkt lists for SUME simulations
nf_applied = OrderedDict()
nf_applied[0] = []
nf_applied[1] = []
nf_applied[2] = []
nf_applied[3] = []
nf_expected = OrderedDict()
nf_expected[0] = []
nf_expected[1] = []
nf_expected[2] = []
nf_expected[3] = []

nf_port_map = {"nf0": 0b00000001, "nf1": 0b00000100, "nf2": 0b00010000, "nf3": 0b01000000, "dma0": 0b00000010}
nf_id_map = {"nf0": 0, "nf1": 1, "nf2": 2, "nf3": 3}

sss_sdnet_tuples.clear_tuple_files()


def applyPkt(pkt, ingress, time):
    pktsApplied.append(pkt)
    sss_sdnet_tuples.sume_tuple_in['pkt_len'] = len(pkt)
    sss_sdnet_tuples.sume_tuple_in['src_port'] = nf_port_map[ingress]
    sss_sdnet_tuples.sume_tuple_expect['pkt_len'] = len(pkt)
    sss_sdnet_tuples.sume_tuple_expect['src_port'] = nf_port_map[ingress]
    pkt.time = time
    nf_applied[nf_id_map[ingress]].append(pkt)


def expPkt(pkt, egress):
    pktsExpected.append(pkt)
    sss_sdnet_tuples.sume_tuple_expect['dst_port'] = nf_port_map[egress]
    sss_sdnet_tuples.write_tuples()
    if egress in ["nf0", "nf1", "nf2", "nf3"]:
        nf_expected[nf_id_map[egress]].append(pkt)
    elif egress == 'bcast':
        nf_expected[0].append(pkt)
        nf_expected[1].append(pkt)
        nf_expected[2].append(pkt)
        nf_expected[3].append(pkt)


def write_pcap_files():
    wrpcap("src.pcap", pktsApplied)
    wrpcap("dst.pcap", pktsExpected)

    for i in nf_applied.keys():
        if (len(nf_applied[i]) > 0):
            wrpcap('nf{0}_applied.pcap'.format(i), nf_applied[i])

    for i in nf_expected.keys():
        if (len(nf_expected[i]) > 0):
            wrpcap('nf{0}_expected.pcap'.format(i), nf_expected[i])

    for i in nf_applied.keys():
        print "nf{0}_applied times: ".format(i), [p.time for p in nf_applied[i]]


#####################
# generate testdata #
#####################
MAC_s1 = "11:11:11:11:11:11"
MAC_s2 = "22:22:22:22:22:22"
MAC_s3 = "33:33:33:33:33:33"
MAC_s4 = "44:44:44:44:44:44"
MAC_s5 = "55:55:55:55:55:55"
MAC_s6 = "66:66:66:66:66:66"
MAC_h1 = "00:00:00:00:00:10"
MAC_h2 = "00:00:00:00:00:20"

SID_s1 = "A1::1"
SID_s2 = "A1::2"
SID_s3 = "A1::3"
SID_s4 = "A1::4"
SID_s5 = "A1::5"
SID_s6 = "A1::6"

IPv6_h1 = "2001:1::1"
IPv6_h2 = "2001:1::2"

ingress = 'nf0'
egress = 'nf1'

# 这是一个简单的ipv6包
pkt1_in = simple_ipv6ip_packet(eth_src=MAC_h1, eth_dst=MAC_s1, ipv6_src=IPv6_h1, ipv6_dst=IPv6_h2)

cnt = 0
applyPkt(pkt1_in, ingress, cnt)

# 测试在入口节点s1处插入SRH
pkt1_out = simple_ipv6_sr_packet(eth_src=MAC_s1, eth_dst=MAC_s2, ipv6_dst=SID_s2, ipv6_src=IPv6_h1,
                                 srh_seg_list=[IPv6_h2, SID_s6, SID_s2], srh_seg_left=2,
                                 srh_first_seg=2)
expPkt(pkt1_out, egress)

write_pcap_files()