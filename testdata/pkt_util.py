from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, IPv6ExtHdrRouting
from scapy.layers.inet import IP, UDP


# generate a very simple ipv6 packet
def simple_ipv6ip_packet(eth_dst='00:01:02:03:04:05',
                         eth_src='00:06:07:08:09:0a',
                         ipv6_src='1::2',
                         ipv6_dst='3::4',
                         ipv6_hlim=64,
                         ipv6_nh=59,
                         ):
    pkt = Ether(dst=eth_dst, src=eth_src) / \
          IPv6(src=ipv6_src, dst=ipv6_dst, hlim=ipv6_hlim, nh=ipv6_nh)
    return pkt


# generate a very simple srv6 packet
def simple_ipv6_sr_packet(eth_dst='00:01:02:03:04:05',
                          eth_src='00:06:07:08:09:0a',
                          ipv6_src='2000::1',
                          ipv6_dst='2000::2',
                          ipv6_hlim=63,
                          srh_seg_left=0,
                          srh_first_seg=0,
                          srh_flags=0,
                          srh_seg_list=[],
                          srh_nh=59
                          ):
    pkt = Ether(dst=eth_dst, src=eth_src)
    pkt /= IPv6(src=ipv6_src, dst=ipv6_dst, nh=43, hlim=ipv6_hlim)
    reserved = (srh_first_seg << 24) + (srh_flags << 8)
    pkt /= IPv6ExtHdrRouting(nh=srh_nh, type=4, segleft=srh_seg_left,
                             reserved=reserved, addresses=srh_seg_list)
    return pkt
