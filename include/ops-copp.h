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
 * File: ops-copp.h
 */

#ifndef __OPS_COPP_H__
#define __OPS_COPP_H__ 1

#include <stdint.h>
#include <opennsl/field.h>
#include "platform-defines.h"
#include "copp-asic-provider.h"
#include "ops-qos.h"

/*
 * Function pointer structure for qualifying control plane packets in ingress.
 */
typedef int (*ops_copp_ingress_fp_function_pointer)(uint32 unit,
                                    opennsl_field_entry_t* ingress_fp_entry);

/*
 * Function pointer structure for qualifying control plane packets in egress.
 */
typedef int (*ops_copp_egress_fp_function_pointer)(uint32 unit,
                                    opennsl_field_entry_t* engress_fp_entry,
                                    uint8 ingress_cpu_queue_number);

/*
 * Function pointer structure for global control packet class rules.
 */
typedef int (*ops_copp_packet_class_function_pointer)(uint32 unit);

/*
 * CoPP related constants
 */
/*
 * TODO: Move the CoPP ingress and Egress group priorities
 *       to a global file containing other group priorities
 *       of other components like ACL and OSPFv2.
 */
#define OPS_COPP_INGRESS_GROUP_PRIORITY         1 /* Priority of the ingress
                                                     CoPP FP group*/
#define OPS_COPP_EGRESS_GROUP_PRIORITY          1 /* Priority of the egress
                                                     CoPP FP group*/
#define OPS_COPP_SUCCESS_CODE                   0 /* CoPP success code */
#define OPS_COPP_FAILURE_CODE                   1 /* CoPP failure code */

/*
 * Maximum number of hardware units
 */
#define OPS_COPP_MAX_UNITS                      MAX_SWITCH_UNITS

/*
 * Minimum and Maximum values of internal priorities for control
 * plane packets.
 */
#define OPS_COPP_INT_PRIORITY_MIN               0
#define OPS_COPP_INT_PRIORITY_MAX               7

/*
 * Maximum number of FP rules for a packet class in ingress pipeline
 */
#define OPS_COPP_MAX_RULES_INGRESS              5

/*
 * Queue numbers as per the control packet classes.
 */
#define OPS_COPP_QOS_QUEUE_CRITICAL             10 /* Q10 */
#define OPS_COPP_QOS_QUEUE_IMPORTANT            9  /* Q9 */
#define OPS_COPP_QOS_QUEUE_BPDU                 8  /* Q8 */
#define OPS_COPP_QOS_QUEUE_MANAGEMENT           7  /* Q7 */
#define OPS_COPP_QOS_QUEUE_UNKNOWN_IP           6  /* Q6 */
#define OPS_COPP_QOS_QUEUE_SWPATH               5  /* Q5 */
#define OPS_COPP_QOS_QUEUE_NORMAL               4  /* Q4 */
#define OPS_COPP_QOS_QUEUE_SFLOW                3  /* Q3 */
#define OPS_COPP_QOS_QUEUE_SNOOPING             2  /* Q2 */
#define OPS_COPP_QOS_QUEUE_DEFAULT              1  /* Q1 */
#define OPS_COPP_QOS_QUEUE_ACL_LOGGING          0  /* Q0 */
#define OPS_COPP_QOS_QUEUE_MAX                  OPS_COPP_QOS_QUEUE_CRITICAL
#define OPS_COPP_QOS_QUEUE_MIN                  OPS_COPP_QOS_QUEUE_ACL_LOGGING

/*
 * Protocol common constants
 */
#define OPS_COPP_OUT_PORT                       0x00000000
#define OPS_COPP_OUT_PORT_MASK                  0xFFFFFFFF
#define OPS_COPP_L4_PORT_MASK                   0xFFFFFFFF
#define OPS_COPP_IP_PROTOCOL_IP_NUMBER_TCP      0x06
#define OPS_COPP_IP_PROTOCOL_IP_NUMBER_UDP      0x11
#define OPS_COPP_IP_PROTOCOL_IPV4_NUMBER_ICMP   0x01
#define OPS_COPP_IP_PROTOCOL_IPV6_NUMBER_ICMP   0x3A
#define OPS_COPP_IP_PROTOCOL_IP_NUMBER_OSPFV2   0x59
#define OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK     0xFF
#define OPS_COPP_DST_IP_LOCAL_DATA              0x01
#define OPS_COPP_DST_IP_LOCAL_MASK              0x0F
#define OPS_COPP_L2_BROADCAST_DEST              {0xFF, 0xFF, 0xFF, \
                                                 0xFF, 0xFF, 0xFF}
#define OPS_COPP_L2_ADDR_MASK                   {0xFF, 0xFF, 0xFF, \
                                                 0xFF, 0xFF, 0xFF}
#define OPS_COPP_L2_ETHER_TYPE_MASK             0xFFFF
#define OPS_COPP_L3_IPV4_BROADCAST_ADDR         "255.255.255.255"
#define OPS_COPP_L3_IPV4_MCAST_ADDR             "224.0.0.0"
#define OPS_COPP_L3_IPV4_ADDR_MASK              OPS_COPP_L3_IPV4_BROADCAST_ADDR
#define OPS_COPP_L3_IPV4_MCAST_ADDR_MASK        "240.0.0.0"
#define OPS_COPP_L3_IPV6_MCAST_ADDR             {0xFF, 0x00, 0x00, 0x00,\
                                                 0x00, 0x00, 0x00, 0x00,\
                                                 0x00, 0x00, 0x00, 0x00,\
                                                 0x00, 0x00, 0x00, 0x00}
#define OPS_COPP_L3_IPV6_MCAST_ADDR_MASK        OPS_COPP_L3_IPV6_MCAST_ADDR

/*
 * ARP related constants
 */
#define OPS_COPP_ARP_ETHER_TYPE                 0x0806

/*
 * LACP packet constants
 */
#define OPS_COPP_LACP_MAC_DEST                  {0x01, 0x80, 0xc2, \
                                                 0x00, 0x00, 0x02}

/*
 * LLDP packet constants
 */
#define OPS_COPP_LLDP_ETHER_TYPE                0x88CC
#define OPS_COPP_LLDP_MAC_DEST_1                {0x01, 0x80, 0xc2, \
                                                 0x00, 0x00, 0x0E}
#define OPS_COPP_LLDP_MAC_DEST_2                {0x01, 0x80, 0xc2, \
                                                 0x00, 0x00, 0x03}
#define OPS_COPP_LLDP_MAC_DEST_3                {0x01, 0x80, 0xc2, \
                                                 0x00, 0x00, 0x00}

/*
 * STP packet constants.
 *
 * We choose the two MAC addresses 01:80:c2:00:00:00 and
 * 01:80:c2:00:00:08 as the destination MAC addresses for STP
 * packets. Instead of creating two FP entries in the ingress,
 * one for 01:80:c2:00:00:00 and one for 01:80:c2:00:00:08, we
 * create one P entry with destination MAC address as 01:80:c2:00:00:00
 * but use the mask as FF:FF:FF:FF:FF:F7. This mask will cover both
 * the destination MAC addresses.
 */
#define OPS_COPP_STP_MAC_DEST                   {0x01, 0x80, 0xc2, \
                                                 0x00, 0x00, 0x00}
#define OPS_COPP_STP_MAC_DEST_MASK              {0xFF, 0xFF, 0xFF, \
                                                 0xFF, 0xFF, 0xF7}

/*
 * BGP related constants
 */
#define OPS_COPP_L4_PORT_BGP                    179

/*
 * DHCPv4 related constants
 */
#define OPS_COPP_L4_PORT_DHCPV4                 67

/*
 * DHCPv6 related constants
 */
#define OPS_COPP_L4_PORT_DHCPV6                 547

/*
 * OSPFv2 related constants
 */
#define OPS_COPP_OSPF_MAC_ALL_ROUTERS           {0x01,0x00,0x5E,\
                                                 0x00,0x00,0x05}
#define OPS_COPP_OSPF_MAC_DR_ROUTERS            {0x01,0x00,0x5E,\
                                                 0x00,0x00,0x06}
#define OPS_COPP_OSPF_IPV4_ALL_POUTERS          "224.0.0.5"
#define OPS_COPP_OSPF_IPV4_DR_POUTERS           "224.0.0.6"

/*
 * Macro for array for function pointers for a control packet class
 * in ingress pipeline.
 */
#define OPS_COPP_INGRESS_FUNC_POINTERS(...)

/*
 * Macro for generating the enum names for different control plane
 * packets.
 */
#define OPS_DEF_COPP_CLASS(name,packet_name,queue,rate,burst,\
                           pkt_class_func,egress_func,\
                           ingress_func) PLUGIN_COPP_##name,

/*
 * Enum for storing the indexing id for different control place packets. The
 * following points need to be considered while adding entries to this
 * enum:-
 * 1. The sequence of rules is important. If a packet matches two sets of
 *    rules within the CoPP group, then the rule appearing earlier in the
 *    enum will get precedence with respect to the action chosen for that
 *    packet. The sequence of the control plane packets must be correctly
 *    specified in the file ops-copp-defaults.h.
 */
enum ops_copp_packet_class_code_t
{
#include "ops-copp-defaults.h"
};

/*
 * If OPS_COPP_INGRESS_FUNC_POINTERS is already defined, then undefine it.
 */
#undef OPS_COPP_INGRESS_FUNC_POINTERS

/*
 * If OPS_DEF_COPP_CLASS is already defined, then undefine it.
 */
#undef OPS_DEF_COPP_CLASS

/*
 * CoPP constants for dumping configuration and stats for control plane
 * packet classes.
 */
#define COPP_MAX_PACKET_STAT_BUFFER_SIZE          300 /* Total number of bytes
                                                         per control plane
                                                         packet class buffer */
#define OPS_COPP_MAX_PACKET_NAME_SIZE              50 /* Number of bytes for
                                                         the buffer used for
                                                         storing the packet
                                                         class name */


/*
 * Declarations of the qualifier functions for different control plane
 * packets.
 */
extern int ops_copp_egress_fp_acl_logging (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_broadcast_arp (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_broadcast_arp (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_unicast_arp (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_unicast_arp (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_lacp (uint32 unit,
                                     opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_lacp (uint32 unit,
                                    opennsl_field_entry_t* egress_fp_entry,
                                    uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_lldp (uint32 unit,
                                     opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_lldp (uint32 unit,
                                    opennsl_field_entry_t* egress_fp_entry,
                                    uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_stp (uint32 unit,
                                    opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_stp (uint32 unit,
                                   opennsl_field_entry_t* egress_fp_entry,
                                   uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_bgp (uint32 unit,
                                    opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_bgp (uint32 unit,
                                   opennsl_field_entry_t* egress_fp_entry,
                                   uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_dhcpv4 (uint32 unit,
                                       opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_dhcpv4 (uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_dhcpv6 (uint32 unit,
                                       opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_dhcpv6 (uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_icmpv4_ucast (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_icmpv4_ucast (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_icmpv4_bcast (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_ingress_fp_icmpv4_mcast (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_icmpv4_bcast_mcast (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_icmpv6_ucast (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_icmpv6_ucast (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_icmpv6_mcast (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_icmpv6_mcast (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_ospfv2_dr_mcast (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_ingress_fp_ospfv2_all_mcast (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_ospfv2_mcast (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_ospfv2_ucast (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_ospfv2_ucast (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_ipv4_options (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_ipv4_options (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_ingress_fp_ipv6_options (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry);
extern int ops_copp_egress_fp_ipv6_options (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_sflow (uint32 unit);
extern int ops_copp_egress_fp_sflow (uint32 unit,
                                     opennsl_field_entry_t* egress_fp_entry,
                                     uint8 ingress_cpu_queue_number);
extern int ops_copp_unknown_ip_unicast (uint32 unit);
extern int ops_copp_egress_fp_unknown_ip_unicast (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);
extern int ops_copp_unclassified (uint32 unit);
extern int ops_copp_egress_fp_unclassified (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number);


/*
 * Structure for storing the ingress and egress FP entry ids, stat object
 * id, policer id (per hardware unit) and the function pointers for the
 * qualifying FP rules
 */
struct ops_copp_fp_rule_t {

    /*
     * Array of pointers to the ingress entry id, one per hardware unit.
     */
    opennsl_field_entry_t*
                            ops_copp_ingress_fp_entry[OPS_COPP_MAX_UNITS][
                                               OPS_COPP_MAX_RULES_INGRESS];

    /*
     * Array of pointers to the egress entry id, one per hardware unit.
     */
    opennsl_field_entry_t*
                            ops_copp_egress_fp_entry[OPS_COPP_MAX_UNITS];

    /*
     * Array of pointers to the egress stat object id for keeping track of
     * allowed and dropped control packets. This is one per hardware unit.
     */
    int*                    ops_copp_egress_fp_stat_id[OPS_COPP_MAX_UNITS];

    /*
     * Array of pointers to the egress ploicer for keeping track of
     * the policer with the egress FP entry. This is one per hardware unit.
     */
    opennsl_policer_t*
                           ops_copp_egress_fp_policer_id[OPS_COPP_MAX_UNITS];

    /*
     * Name of the control plane packet.
     */
    char*                  ops_copp_packet_name;

    /*
     * Value of the current CPU QoS queue for this control plane packet.
     */
    uint32                 ops_copp_ingress_fp_queue_number;

    /*
     * Value of the current rate for this control plane packet.
     */
    uint32                 ops_copp_egress_fp_rate;

    /*
     * Value of the current burst for this control plane packet.
     */
    uint32                 ops_copp_egress_fp_burst;

    /*
     * Function pointer to the control packet class global pipeline
     * rules.
     */
    ops_copp_packet_class_function_pointer
                           ops_copp_packet_class_function_pointer;

    /*
     * Function pointer to the FP qualifying rules in egress pipeline.
     */
    ops_copp_egress_fp_function_pointer
                           ops_copp_egress_fp_funtion_pointer;

    /*
     * Function pointer to the FP qualifying rules in ingress pipeline.
     */
    ops_copp_ingress_fp_function_pointer
                           ops_copp_ingress_fp_funtion_pointer[
                                          OPS_COPP_MAX_RULES_INGRESS];
    /*
     * Status of the fp rule per hw_unit.
     * Valid : true; Invalid : false
     */
    bool                   status[OPS_COPP_MAX_UNITS];
};

/*
 * Structure for exposing the configuration of CPU queue number, rate
 * and burst for a control plane packet class.
 */
struct ops_copp_config_t {

    /*
     * Control packet class.This must be specified in the
     * strcuture when attempting to set the configuration.
     */
    enum ops_copp_packet_class_code_t
                ops_copp_packet_class;

    /*
     * Control packet CPU queue number. This must be specified
     * in the strcuture when attempting to set the configuration.
     */
    uint32      ops_copp_queue_number;

    /*
     * Control packet rate. This must be specified in the
     * strcuture when attempting to set the configuration.
     */
    uint32      ops_copp_rate;

    /*
     * Control packet burst. This must be specified in the
     * strcuture when attempting to set the configuration.
     */
    uint32      ops_copp_burst;
};

/*
 * Structure for exposing stats for a control plane packet class.
 */
struct ops_copp_stats_t {

    /*
     * Hardware nnit number. This must be specified in the
     * strcuture when attempting to get the stats.
     */
    uint32      ops_copp_hardware_unit_number;

    /*
     * Control packet class.This must be specified in the
     * strcuture when attempting to get the stats.
     */
    enum ops_copp_packet_class_code_t
                ops_copp_packet_class;

    /*
     * Number of control plane packets sent to CPU
     */
    uint64      ops_copp_packets_allowed;

    /*
     * Number of control plane packet bytes sent to CPU
     */
    uint64      ops_copp_bytes_allowed;

    /*
     * Number of control plane packets not sent to CPU
     */
    uint64      ops_copp_packets_dropped;

    /*
     * Number of control plane packet bytes not sent to CPU
     */
    uint64      ops_copp_bytes_dropped;
};

extern int copp_opennsl_stats_get(const unsigned int hw_asic_id,
                          const enum copp_protocol_class class,
                          struct copp_protocol_stats *const stats);
extern int copp_opennsl_hw_status_get(const unsigned int hw_asic_id,
                              const enum copp_protocol_class class,
                              struct copp_hw_status *const hw_status);

extern int ops_copp_init();
extern int ops_get_all_packet_stats();
extern int get_copp_counts (uint32 num_packets_classes,
                            struct ops_copp_stats_t* copp_stats_array);
extern int set_copp_policy (uint32 num_packets_classes,
                            struct ops_copp_config_t* copp_config_array);
extern uint32 ops_copp_get_cpu_queue_number_from_name (const char* queue_name);
extern enum ops_copp_packet_class_code_t
ops_copp_get_packet_class_from_packet_name (char* packet_name);
extern char*
ops_copp_get_packet_name_from_packet_class (
                enum ops_copp_packet_class_code_t packet_Class);
extern opennsl_field_group_t ops_copp_get_ingress_group_id_for_hw_unit (
                                                         int hardware_unit);
extern opennsl_field_group_t ops_copp_get_egress_group_id_for_hw_unit (
                                                         int hardware_unit);

#endif /* __OPS_COPP_H__ */
