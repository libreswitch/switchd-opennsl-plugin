/*
 * Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
 * All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 *
 * File: ops-copp-defaults.h
 */

/*
 * +----------+-----------+---------------------------------+
 * |          |           |                                 |
 * |Priority  | CPU Queue |  Description                    |
 * +--------------------------------------------------------+
 * |          |           |                                 |
 * |Critical  |   Q10     |  xSTP                           |
 * |          |           |                                 |
 * +--------------------------------------------------------+
 * |          |           |                                 |
 * |Important |   Q9      |  OSPF,BGP                       |
 * |          |           |                                 |
 * +--------------------------------------------------------+
 * |          |           |                                 |
 * |BPDU/LLDP |   Q8      |  LLDP, LACP                     |
 * |/LACP     |           |                                 |
 * |          |           |                                 |
 * +--------------------------------------------------------+
 * |          |           |For now no inband management     |
 * |MANAGEMENT|   Q7      |traffic supported.               |
 * |          |           |                                 |
 * +--------------------------------------------------------+
 * |          |           |                                 |
 * |UNKNOWN_IP|   Q6      |Unknown destination IP address   |
 * |          |           |                                 |
 * +--------------------------------------------------------+
 * |          |           |Unicast ARP, Unicast ICMP,       |
 * |SW-PATH   |   Q5      |ICMPv6, IP options               |
 * |          |           |                                 |
 * +--------------------------------------------------------+
 * |          |           |                                 |
 * |NORMAL    |   Q4      |Broadcast ARP,Broadcast/Multicast|
 * |          |           |ICMP, DHCP                       |
 * +--------------------------------------------------------+
 * |          |           |                                 |
 * |sFlow     |   Q3      |  Sampled sFlow traffic          |
 * +--------------------------------------------------------+
 * |Snooping  |   Q2      |                                 |
 * |          |           |                                 |
 * +--------------------------------------------------------+
 * |Default   |   Q1      | Unclasssified Packets           |
 * |          |           |                                 |
 * +--------------------------------------------------------+
 * |Exceptions|           |                                 |
 * |/ ACL     |   Q0      | ACL Logging                     |
 * |  Logging |           |                                 |
 * +----------+-----------+---------------------------------+
 *
 * Table containing the QoS categories for different control
 *        packet types for AS5712, AS6712 and AS7712.
 */

/*
 * +---------------+--------------------------------+-------------+------------+------------+
 * |               |                                |             |            |            |
 * |Packet Class   |  Description                   | Queue       | Rate Limit | Burst Size |
 * |               |                                |             |   (PPS)    |  (Packets) |
 * +---------------------------------------------------------------------------+------------+
 * | ACL_LOGGING   |  ACL Logging                   |  Q0         |  5         |  5         |
 * +---------------------------------------------------------------------------+------------+
 * | ARP_BC        |  Broadcast ARP Packets         |  Q4         |  1000      |  1000      |
 * +---------------------------------------------------------------------------+------------+
 * | ARP_UC        |  Unicast ARPs                  |  Q5         |  1000      |  1000      |
 * +---------------------------------------------------------------------------+------------+
 * | BGP           |  BGP packets                   |  Q9         |  5000      |  5000      |
 * +---------------------------------------------------------------------------+------------+
 * | DHCP          |  DHCP packets                  |  Q4         |  500       |  500       |
 * +---------------------------------------------------------------------------+------------+
 * | DHCPV6        |  IPv6 DHCP packets             |  Q4         |  500       |  500       |
 * +---------------------------------------------------------------------------+------------+
 * | ICMP_BC       |  IPv4 broadcast/multicast ICMP |  Q4         |  1000      |  1000      |
 * |               |  packets                       |             |            |            |
 * +---------------------------------------------------------------------------+------------+
 * | ICMP_UC       |  IPv4 unicast ICMP packets     |  Q5         |  1000      |  1000      |
 * +---------------------------------------------------------------------------+------------+
 * | ICMPV6_MC     |  IPv6 multicast ICMP packets   |  Q4         |  1000      |  1000      |
 * +---------------------------------------------------------------------------+------------+
 * | ICMPV6_UC     |  IPv6 unicast ICMP             |  Q5         |  1000      |  1000      |
 * +---------------------------------------------------------------------------+------------+
 * | LACP          |  LACP packets                  |  Q8         |  1000      |  1000      |
 * +---------------------------------------------------------------------------+------------+
 * | LLDP          |  LLDP packets                  |  Q8         |  500       |  500       |
 * +---------------------------------------------------------------------------+------------+
 * | OSPF_MC       |  Multicast OSPF packets        |  Q9         |  5000      |  5000      |
 * +---------------------------------------------------------------------------+------------+
 * | OSPF_UC       |  Unicast OSPF packets          |  Q9         |  5000      |  5000      |
 * +---------------------------------------------------------------------------+------------+
 * | sFlow         |  Sampled sFlow packets         |  Q3         |  20000     |  20000     |
 * +---------------------------------------------------------------------------+------------+
 * | STP           |  STP packets                   |  Q9         |  1000      |  1000      |
 * +---------------------------------------------------------------------------+------------+
 * | IPOPTION      |  Packets with IPv4 options     |  Q5         |  250       |  250       |
 * +---------------------------------------------------------------------------+------------+
 * | IPOPTIONV6    |  Packets with IPv6 options     |  Q5         |  250       |  250       |
 * +---------------------------------------------------------------------------+------------+
 * | UNKOWN_IP_DEST|  Packets with unknown IPv4/IPv6|  Q6         |  2500      |  2500      |
 * |               |  destination IPs               |             |            |            |
 * +---------------------------------------------------------------------------+------------+
 * | UNCLASSIFIED  |  Any Unclassified packets      |  Q1         |  5000      |  5000      |
 * +---------------+--------------------------------+-------------+------------+------------+
 *
 * Table containing QoS queue categories, packet rates and packet burst for different control
 *                         packets for AS5712, AS6712 and AS7712.
 */

/*
 * The order of the control plane packets in this file is important. The earlier
 * entry's action gets preference over later entry's action. The following have
 * been kept in mind before adding rules in this file.
 * 1. The broadcast ARP FP rule should be programmed before unicast ARP becuase
 *    we do not a FP qualifier in egress to tell if some ARP is unicast.
 * 2. The rule for the unclassified packets should occur last in the rule
 *    sequence.
 *
 * TOne entry in this file has the following description:-
 *
 * Control Plane packet id (for setting enum names)
 * Control Plane packet name
 * Control Plane packet CPU queue number
 * Control Plane packet rate
 * Control Plane packet burst
 * Control plane packet class function name
 * Control Plane packet egress FP qualifier function name
 * Control Plane packet ingress FP qualifier function names
 */
OPS_DEF_COPP_CLASS(ACL_LOGGING_PACKET, "ACL Logging packets", OPS_COPP_QOS_QUEUE_ACL_LOGGING, 5, 5, NULL, ops_copp_egress_fp_acl_logging, OPS_COPP_INGRESS_FUNC_POINTERS())
OPS_DEF_COPP_CLASS(BROADCAST_ARP_PACKET, "Broadcast ARPs packets", OPS_COPP_QOS_QUEUE_NORMAL, 1000, 1000, NULL, ops_copp_egress_fp_broadcast_arp, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_broadcast_arp))
OPS_DEF_COPP_CLASS(UNICAST_ARP_PACKET, "Unicast ARPs packets", OPS_COPP_QOS_QUEUE_SWPATH, 1000, 1000, NULL, ops_copp_egress_fp_unicast_arp, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_unicast_arp))
OPS_DEF_COPP_CLASS(LACP_PACKET, "LACP packets", OPS_COPP_QOS_QUEUE_BPDU, 1000, 1000, NULL, ops_copp_egress_fp_lacp, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_lacp))
OPS_DEF_COPP_CLASS(LLDP_PACKET, "LLDP packets", OPS_COPP_QOS_QUEUE_BPDU, 500, 500, NULL, ops_copp_egress_fp_lldp, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_lldp, ops_copp_ingress_fp_lldp, ops_copp_ingress_fp_lldp))
OPS_DEF_COPP_CLASS(STP_PACKET, "STP packets", OPS_COPP_QOS_QUEUE_CRITICAL, 1000, 1000, NULL, ops_copp_egress_fp_stp, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_stp))
OPS_DEF_COPP_CLASS(IPV4_OPTIONS_PACKET, "IPv4 options packets", OPS_COPP_QOS_QUEUE_SWPATH, 250, 250, NULL, ops_copp_egress_fp_ipv4_options, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_ipv4_options))
OPS_DEF_COPP_CLASS(IPV6_OPTIONS_PACKET, "IPv6 options packets", OPS_COPP_QOS_QUEUE_SWPATH, 250, 250, NULL, ops_copp_egress_fp_ipv6_options, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_ipv6_options))
OPS_DEF_COPP_CLASS(BGP_PACKET, "BGP packets", OPS_COPP_QOS_QUEUE_IMPORTANT, 5000, 5000, NULL, ops_copp_egress_fp_bgp, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_bgp))
OPS_DEF_COPP_CLASS(DHCPV4_PACKET, "DHCPv4 packets", OPS_COPP_QOS_QUEUE_NORMAL, 500, 500, NULL, ops_copp_egress_fp_dhcpv4, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_dhcpv4))
OPS_DEF_COPP_CLASS(DHCPV6_PACKET, "DHCPv6 packets", OPS_COPP_QOS_QUEUE_NORMAL, 500, 500, NULL, ops_copp_egress_fp_dhcpv6, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_dhcpv6))
OPS_DEF_COPP_CLASS(ICMPV4_UCAST_PACKET, "ICMPV4 unicast packets", OPS_COPP_QOS_QUEUE_SWPATH, 1000, 1000, NULL, ops_copp_egress_fp_icmpv4_ucast, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_icmpv4_ucast))
OPS_DEF_COPP_CLASS(ICMPV4_BMCAST_PACKET, "ICMPV4 broadcast/multicast packets", OPS_COPP_QOS_QUEUE_NORMAL, 1000, 1000, NULL, ops_copp_egress_fp_icmpv4_bcast_mcast, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_icmpv4_bcast, ops_copp_ingress_fp_icmpv4_mcast))
OPS_DEF_COPP_CLASS(ICMPV6_UCAST_PACKET, "ICMPV6 unicast packets", OPS_COPP_QOS_QUEUE_SWPATH, 1000, 1000, NULL, ops_copp_egress_fp_icmpv6_ucast, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_icmpv6_ucast))
OPS_DEF_COPP_CLASS(ICMPV6_MCAST_PACKET, "ICMPV6 multicast packets", OPS_COPP_QOS_QUEUE_NORMAL, 1000, 1000, NULL, ops_copp_egress_fp_icmpv6_mcast, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_icmpv6_mcast))
OPS_DEF_COPP_CLASS(OSPFV2_MCAST_PACKET, "OSPFV2 multicast packets", OPS_COPP_QOS_QUEUE_IMPORTANT, 5000, 5000, NULL, ops_copp_egress_fp_ospfv2_mcast, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_ospfv2_dr_mcast, ops_copp_ingress_fp_ospfv2_all_mcast))
OPS_DEF_COPP_CLASS(OSPFV2_UCAST_PACKET, "OSPFV2 unicast packets", OPS_COPP_QOS_QUEUE_IMPORTANT, 5000, 5000, NULL, ops_copp_egress_fp_ospfv2_ucast, OPS_COPP_INGRESS_FUNC_POINTERS(ops_copp_ingress_fp_ospfv2_ucast))
OPS_DEF_COPP_CLASS(SFLOW_PACKET, "Sflow packets", OPS_COPP_QOS_QUEUE_SFLOW, 5000, 5000, ops_copp_sflow, ops_copp_egress_fp_sflow, OPS_COPP_INGRESS_FUNC_POINTERS())
OPS_DEF_COPP_CLASS(UNKNOWN_IP_UNICAST_PACKET, "Unknown IP unicast packets", OPS_COPP_QOS_QUEUE_UNKNOWN_IP, 2500, 2500, ops_copp_unknown_ip_unicast, ops_copp_egress_fp_unknown_ip_unicast, OPS_COPP_INGRESS_FUNC_POINTERS())
OPS_DEF_COPP_CLASS(UNCLASSIFIED_PACKET, "Unclassified packets", OPS_COPP_QOS_QUEUE_DEFAULT, 5000, 5000, ops_copp_unclassified, ops_copp_egress_fp_unclassified, OPS_COPP_INGRESS_FUNC_POINTERS())
