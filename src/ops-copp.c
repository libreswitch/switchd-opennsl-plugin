/* Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 * All Rights Reserved.

 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/* Purpose: This file contains code to enable CoPP functionality
 * in the Broadcom ASIC.
 */

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <util.h>
#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/field.h>
#include <opennsl/policer.h>
#include <opennsl/pkt.h>
#include <opennsl/rx.h>
#include "ops-copp.h"
#include "eventlog.h"
#include "ops-fp.h"

/*
 * Logging module for CoPP.
 */
VLOG_DEFINE_THIS_MODULE(ops_copp);

/*
 * Ingress group ids per hardware unit
 */
static opennsl_field_group_t
                    ops_copp_ingress_fp_group_array[OPS_COPP_MAX_UNITS];

/*
 * Egress group ids per hardware unit
 */
static opennsl_field_group_t
                    ops_copp_egress_fp_group_array[OPS_COPP_MAX_UNITS];

/*
 * Index counter for global rx rules for control packet class.
 */
static int ops_copp_packet_class_rx_index[OPS_COPP_MAX_UNITS];

/*
 * Macro for array of function pointers for qualifying different control
 * packet types in a control packet class in the ingress pipeline.
 */
#define OPS_COPP_INGRESS_FUNC_POINTERS(...) {__VA_ARGS__}

/*
 * Macro for populating the structure ops_copp_fp_rule_t with the default
 * values specified in the file ops-copp-defaults.h.
 *
 * The following values need to be entered into the strcuture entry:-
 * 1. The packet name is set to the name of the control packet.
 * 2. Ingress CPU queue number is set to platform packet class queue default
 *    value.
 * 3. Egress rate is set to platform packet default value.
 * 4. Egress burst is set to platform packet default value.
 * 5. Global control packet rule programming function pointer is pointed to
 *    the control packet class programming function.
 * 6. Egress FP entry programming function pointer is pointed to the
 *    egress implementation function.
 * 7. Ingress FP entry  programming function pointer array is pointed to the
 *    ingress implementation function pointers.
 */
#define OPS_DEF_COPP_CLASS(id,packet_name,queue,rate,\
                           burst,packet_class_func,\
                           egress_func,ingress_func) {\
                           .ops_copp_packet_name=packet_name,\
                           .ops_copp_ingress_fp_queue_number=queue, \
                           .ops_copp_egress_fp_rate=rate, \
                           .ops_copp_egress_fp_burst=burst, \
                           .ops_copp_packet_class_function_pointer=packet_class_func,\
                           .ops_copp_egress_fp_funtion_pointer=egress_func,\
                           .ops_copp_ingress_fp_funtion_pointer=ingress_func},
/*
 * Static array for ingress and egress FP rules. The number of entries in
 * this array is equal to the number of control plane packet rules given
 * in file ops-copp-defaults.h.
 */
static struct ops_copp_fp_rule_t ops_copp_packet_class_t[] =
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
 * Maximum number of CoPP rules
 */
#define PLUGIN_COPP_MAX_CLASSES  sizeof(ops_copp_packet_class_t)/\
                              sizeof(struct ops_copp_fp_rule_t)

/*
 * Buffer for storing all the control plane packet configuration and
 * statistics.
 */
char ops_copp_all_packet_stat_buffer[COPP_MAX_PACKET_STAT_BUFFER_SIZE
                                     * PLUGIN_COPP_MAX_CLASSES];

/*
 * Array of strings for names for CPU queue numbers
 */
char* ops_cpu_queue_name[OPS_COPP_QOS_QUEUE_MAX + 1] = {
                                                          "Acl-logging",
                                                          "Default",
                                                          "Snooping",
                                                          "Sflow",
                                                          "Normal",
                                                          "Swpath",
                                                          "Unknown-IP",
                                                          "Management",
                                                          "Bpdu",
                                                          "Important",
                                                          "Critical"
                                                             };

/*
 * ops_copp_get_ingress_group_id_for_hw_unit
 *
'* This function returns the group-id for the CoPP ingress FP rules for
 * the given hardware unit.
 */
opennsl_field_group_t ops_copp_get_ingress_group_id_for_hw_unit (
                                                    int hardware_unit)
{
    if ((hardware_unit >= OPS_COPP_MAX_UNITS) ||
        (hardware_unit < 0))  {
        return(-1);
    }

    return(ops_copp_ingress_fp_group_array[hardware_unit]);
}

/*
 * ops_copp_get_egress_group_id_for_hw_unit
 *
'* This function returns the group-id for the CoPP egress FP rules for
 * the given hardware unit.
 */
opennsl_field_group_t ops_copp_get_egress_group_id_for_hw_unit (
                                                    int hardware_unit)
{
    if ((hardware_unit >= OPS_COPP_MAX_UNITS) ||
        (hardware_unit < 0))  {
        return(-1);
    }

    return(ops_copp_egress_fp_group_array[hardware_unit]);
}

/*
 * ops_copp_get_cpu_queue_name
 *
 * This function gets the CPU queue name from CPU queue number
 */
static char* ops_copp_get_name_from_cpu_queue_number (uint32 cpu_queue)
{
    if (cpu_queue > OPS_COPP_QOS_QUEUE_MAX) {
        return(NULL);
    }

    return(ops_cpu_queue_name[cpu_queue]);
}

/*
 * ops_copp_get_cpu_queue_number_from_name
 *
 * This function gets the CPU queue number from CPU queue name. This
 * function returns UINT_MAX if the queue_name is not found in the array
 * of available queue names.
 */
uint32 ops_copp_get_cpu_queue_number_from_name (const char* queue_name)
{
    uint32 index;

    if (!queue_name) {
        return(~0);
    }

    /*
     * Iterate over all the available set of queue names to find a
     * match.
     */
    for (index = 0; index <= OPS_COPP_QOS_QUEUE_MAX; ++index) {
        if (!strcasecmp(queue_name, ops_cpu_queue_name[index])) {
            return(index);
        }
    }

    return(~0);
}

/*
 * ops_copp_get_packet_name_from_packet_class
 *
 * This function returns the name of control packet class based on
 * control packet code passed to it.
 */
char*
ops_copp_get_packet_name_from_packet_class (
                enum ops_copp_packet_class_code_t packet_class)
{
    /*
     * If the packet class is not valid, then do not do anything and
     * return from this function.
     */
    if ((packet_class < 0) ||
        (packet_class >= PLUGIN_COPP_MAX_CLASSES)) {
        VLOG_DBG("Not a valid packet class");
        return(NULL);
    }

    return(ops_copp_packet_class_t[packet_class].ops_copp_packet_name);
}

/*
 * ops_copp_to_lowercase
 *
 * This function converts a string into a lowercase string.
 */
static char* ops_copp_to_lowercase (char* str)
{
    int len = strlen(str);
    int index;
    char* lowercase_string;

    if (!str || !len) {
        return(NULL);
    }

    /*
     * Allocate memory for the lowercase string.
     */
    lowercase_string = xzalloc(len);

    /*
     * Copy the characters from the source string to the
     * lowercase character string.
     */
    for (index = 0; index < len; ++index) {
        if (isalpha(str[index])) {
            lowercase_string[index] = tolower(str[index]);
        } else {
            lowercase_string[index] = str[index];
        }
    }

    return(lowercase_string);
}

/*
 * ops_copp_get_packet_class_from_packet_name
 *
 * This function reurns the control packet class for the control
 * packet name supplied from the appctl. The packet_name should be
 * of the format aaaa-bbbb-cccc. This function returns UINT_MAX if
 * no control packet class is found for the packet_name.
 */
enum ops_copp_packet_class_code_t
ops_copp_get_packet_class_from_packet_name (char* packet_name)
{
    char*           packet_class_name_lowercase = NULL;
    int             num_packet_name_sub_parts;
    char*           packet_name_token = NULL;
    char*           packet_name_token_lowercase = NULL;
    char*           packet_name_token_lowercase_array[5];
    enum            ops_copp_packet_class_code_t found_packet_class;
    int             fp_rule_iterator;
    int             index;

    /*
     * If the packet_name is NULL, then return UINT_MAX
     */
    if (!packet_name) {
        return(~0);
    }

    packet_name_token = strtok(packet_name, "-");

    /*
     * If there no valid tokens in the packet_name string, then return
     * UINT_MAX
     */
    if (!packet_name_token) {
        return(~0);
    }

    /*
     * Put the lowercase token pointers in the array of strings.
     */
    num_packet_name_sub_parts = 0;
    while (packet_name_token) {

        packet_name_token_lowercase =
                ops_copp_to_lowercase(packet_name_token);

        if (!packet_name_token_lowercase) {
            packet_name_token = strtok(NULL, "-");
            continue;
        }

        packet_name_token_lowercase_array[num_packet_name_sub_parts] =
                            packet_name_token_lowercase;
        ++num_packet_name_sub_parts;

        packet_name_token = strtok(NULL, "-");
    }

    /*
     * Iterate over all control plane packet classes and check if all the
     * token from the packet_name are present in the name of a control
     * packet class.
     */
    found_packet_class = ~0;
    if (num_packet_name_sub_parts) {
        for (fp_rule_iterator = 0; fp_rule_iterator < PLUGIN_COPP_MAX_CLASSES;
             ++fp_rule_iterator) {

            packet_class_name_lowercase =
                ops_copp_to_lowercase(
                        ops_copp_packet_class_t[
                            fp_rule_iterator].ops_copp_packet_name);

            if (!packet_class_name_lowercase) {
                continue;
            }

            for (index = 0; index < num_packet_name_sub_parts; ++index) {
                if (!strstr(packet_class_name_lowercase,
                            packet_name_token_lowercase_array[index])) {
                    break;
                }
            }

            free(packet_class_name_lowercase);

            if (index == num_packet_name_sub_parts) {
                found_packet_class = fp_rule_iterator;
                break;
            }
        }
    }

    /*
     * Free the lowercase string tokens
     */
    for (index = 0; index < num_packet_name_sub_parts; ++index) {
        free(packet_name_token_lowercase_array[index]);
    }

    /*
     * Return the control plane packet class
     */
    return(found_packet_class);
}

/*
 * ops_copp_create_egress_policer_id
 *
 * This function creates a policy-id with a given rate and burst an egress
 * FP entry. This function is called per hardware unit.
 */
static int ops_copp_create_egress_policer_id (
                                       uint32 unit,
                                       opennsl_policer_t* policer_id,
                                       uint32 rate, uint32 burst)
{
    opennsl_policer_config_t   pol_cfg;
    int32                      retval = -1;

    if (!policer_id) {
        VLOG_ERR("     Egress: The policer id is NULL");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Intialize the policier configuration.
     */
    opennsl_policer_config_t_init(&pol_cfg);

    /*
     * Populate the policier parameters with the rate and the
     * burst values.
     */
    pol_cfg.mode = opennslPolicerModeSrTcm;
    pol_cfg.ckbits_sec = rate; /*Eg: Limit = 100 pkts per sec */
    pol_cfg.ckbits_burst = burst; /*Eg. burst = 100 pkts */
    pol_cfg.flags = OPENNSL_POLICER_MODE_PACKETS;
    pol_cfg.flags |= OPENNSL_POLICER_COLOR_BLIND;

    memset(policer_id, 0, sizeof(opennsl_policer_t));

    /*
     * Create the policier-id with the policier configuration.
     */
    retval = opennsl_policer_create(unit, &pol_cfg, policer_id);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to create policer = %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_create_egress_stat_id
 *
 * This function creates a stats-id for storing stats for dropped and
 * accepted control packets in an egress FP entry. This function is called
 * per hardware unit.
 */
static int ops_copp_create_egress_stat_id (uint32 unit, int* stat_id)
{
    int retval = -1;
    int num_stat = 4;

    /*
     * Array of the packet types that need to be captured.
     *
     * TODO:- Need to add opennslFieldStatYellowBytes and
     *        opennslFieldStatYellowPackets to the statistics.
     */
    opennsl_field_stat_t stat_ifp[4]={ opennslFieldStatGreenPackets,
                                       opennslFieldStatGreenBytes,
                                       opennslFieldStatRedPackets,
                                       opennslFieldStatRedBytes
                                      };

    if (!stat_id) {
        VLOG_ERR("     Egress: Invalid stat-id pointer");
        return(OPS_COPP_FAILURE_CODE);
    }

    *stat_id = 0;

    /*
     * Create the statistics id
     */
    retval = opennsl_field_stat_create(unit,
                                 ops_copp_egress_fp_group_array[unit],
                                 num_stat, stat_ifp, stat_id);

    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to create stat object = %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_fp_entry_cleanup
 *
 * This function destroys the FP entry from hardware and releases the
 * hardware resources. Finally this function frees the program memory
 * by calling free().
 */
static inline void ops_copp_fp_entry_cleanup (
                                       uint32 unit,
                                       opennsl_field_entry_t* fp_entry)
{
    if (!fp_entry) {
        return;
    }

    opennsl_field_entry_destroy(unit, *fp_entry);
    free(fp_entry);
}

/*
 * ops_copp_fp-policer_cleanup
 *
 * This function destroys the FP policer from hardware and releases the
 * hardware resources. Finally this function frees the program memory
 * by calling free().
 */
static inline void ops_copp_fp_policer_cleanup (
                                         uint32 unit,
                                         opennsl_policer_t* policer)
{
    if (!policer) {
        return;
    }

    opennsl_policer_destroy(unit, *policer);
    free(policer);
}

/*
 * ops_copp_fp_statid_cleanup
 *
 * This function destroys the FP policer from hardware and releases the
 * hardware resources. Finally this function frees the program memory
 * by calling free().
 */
static inline void ops_copp_fp_statid_cleanup (uint32 unit, int* stat_id)
{
    if (!stat_id) {
        return;
    }

    opennsl_field_stat_destroy(unit, *stat_id);
    free(stat_id);
}

/*
 * ops_copp_egress_fp_acl_logging
 *
 * This function programs the qualifiers for identifying an ACL Logging
 * packet in egress pipeline.
 */
int ops_copp_egress_fp_acl_logging (uint32 unit,
                                    opennsl_field_entry_t* egress_fp_entry,
                                    uint8 ingress_cpu_queue_number)
{
    int32                      retval = -1;
    opennsl_port_t             port = OPS_COPP_OUT_PORT;
    opennsl_port_t             port_mask = OPS_COPP_OUT_PORT_MASK;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ACL Logging. Qualify the ACL Logging
     * on the following rules:-
     * 1. The out port should be zero as the packet is destined to CPU.
     * 2  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_broadcast_arp
 *
 * This function programs the qualifiers for identifying an broadcast ARP
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_broadcast_arp (
                                      uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry)
{
    int32                  retval = -1;
    uint16                 ether_type = OPS_COPP_ARP_ETHER_TYPE;
    uint16                 ether_mask = OPS_COPP_L2_ETHER_TYPE_MASK;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for broadcast ARP. Qualify the broadcast ARP
     * on the following rules:-
     * 1. Ethertype in L2 frame should be 0x0806
     * 2. The destination MAC should be broadcast.
     */
    retval = opennsl_field_qualify_EtherType(unit, *ingress_fp_entry,
                                             ether_type, ether_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ether type for "
                 "broadcast ARP %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_PacketRes(unit, *ingress_fp_entry,
                                             OPENNSL_FIELD_PKT_RES_L2BC,
                                             0xFFFFFFFF);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on broadcast "
                 "destination MAC address %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_broadcast_arp
 *
 * This function programs the qualifiers for identifying an broadcast ARP
 * packet in egress pipeline.
 */
int ops_copp_egress_fp_broadcast_arp (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number)
{
    int32                      retval = -1;
    uint16                     ether_type = OPS_COPP_ARP_ETHER_TYPE;
    uint16                     ether_mask = OPS_COPP_L2_ETHER_TYPE_MASK;
    opennsl_mac_t              ether_dst_mac = OPS_COPP_L2_BROADCAST_DEST;
    opennsl_mac_t              ether_dst_mask = OPS_COPP_L2_ADDR_MASK;
    opennsl_port_t             port = OPS_COPP_OUT_PORT;
    opennsl_port_t             port_mask = OPS_COPP_OUT_PORT_MASK;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for broadcast ARP. Qualify the broadcast ARP
     * on the following rules:-
     * 1. Ethertype in L2 frame should be 0x0806
     * 2. Check if the destination MAC in the L2 frame is broadcast.
     * 3. The out port should be zero as the packet is destined to CPU.
     * 4  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_EtherType(unit, *egress_fp_entry,
                                             ether_type, ether_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ether type for "
                 "broadcast ARP %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstMac(unit, *egress_fp_entry,
                                          ether_dst_mac, ether_dst_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on broadcast "
                 "destination MAC address %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_unicast_arp
 *
 * This function programs the qualifiers for identifying an unicast ARP
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_unicast_arp (uint32 unit,
                                     opennsl_field_entry_t* ingress_fp_entry)
{
    int32                  retval = -1;
    uint16                 ether_type = OPS_COPP_ARP_ETHER_TYPE;
    uint16                 ether_mask = OPS_COPP_L2_ETHER_TYPE_MASK;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for unicast ARP. Qualify the unicast ARP
     * on the following rules:-
     * 1. Ethertype in L2 frame should be 0x0806
     * 2. The destination MAC should be unicast.
     */
    retval = opennsl_field_qualify_EtherType(
                                unit,
                                *ingress_fp_entry,
                                ether_type, ether_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ether type for "
                 "unicast ARP %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

#if 0
    /*
     * TODO: This needs to be uncommented once the support for
     *       opennsl_field_qualify_PacketRes for unicast ARP
     *       is available again.
     */
    retval = opennsl_field_qualify_PacketRes(
                                unit,
                                *ingress_fp_entry,
                                OPENNSL_FIELD_PKT_RES_L2UC, 0xFFFFFFFF);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on unicast "
                 "destination MAC address %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }
#endif

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_unicast_arp
 *
 * This function programs the qualifiers for identifying an unicast ARP
 * packet in egress pipeline.
 */
int ops_copp_egress_fp_unicast_arp (uint32 unit,
                                    opennsl_field_entry_t* egress_fp_entry,
                                    uint8 ingress_cpu_queue_number)
{
    int32                      retval = -1;
    uint16                     ether_type = OPS_COPP_ARP_ETHER_TYPE;
    uint16                     ether_mask = OPS_COPP_L2_ETHER_TYPE_MASK;
    opennsl_port_t             port = OPS_COPP_OUT_PORT;
    opennsl_port_t             port_mask = OPS_COPP_OUT_PORT_MASK;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for unicast ARP. Qualify the unicast ARP
     * on the following rules:-
     * 1. Ethertype in L2 frame should be 0x0806
     * 2. The out port should be zero as the packet is destined to CPU.
     * 3  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_EtherType(
                                unit,
                                *egress_fp_entry,
                                ether_type, ether_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ether type for "
                 "unicast ARP %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_lacp
 *
 * This function programs the qualifiers for identifying a LACP
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_lacp (uint32 unit,
                              opennsl_field_entry_t* ingress_fp_entry)
{
    int32                  retval = -1;
    opennsl_mac_t          ether_dst_mac = OPS_COPP_LACP_MAC_DEST;
    opennsl_mac_t          ether_dst_mask = OPS_COPP_L2_ADDR_MASK;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for LACP packets. Qualify the LACP packets
     * on the following rules:-
     * 1. The destination MAC should be 01:80:c2:00:00:02.
     */
    retval = opennsl_field_qualify_DstMac(unit, *ingress_fp_entry,
                                          ether_dst_mac, ether_dst_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on LACP "
                 "destination MAC address %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_lacp
 *
 * This function programs the qualifiers for identifying a LACP
 * packet in egress pipeline.
 */
int ops_copp_egress_fp_lacp (uint32 unit,
                             opennsl_field_entry_t* egress_fp_entry,
                             uint8 ingress_cpu_queue_number)
{
    int32                  retval = -1;
    opennsl_mac_t          ether_dst_mac = OPS_COPP_LACP_MAC_DEST;
    opennsl_mac_t          ether_dst_mask = OPS_COPP_L2_ADDR_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for LACP packets. Qualify the LACP packets
     * on the following rules:-
     * 1. The destination MAC should be 01:80:c2:00:00:02.
     * 2. The out port should be zero as the packet is destined to CPU.
     * 3  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_DstMac(unit, *egress_fp_entry,
                                          ether_dst_mac, ether_dst_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on LACP "
                 "destination MAC address %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_lldp
 *
 * This function programs the qualifiers for identifying a LLDP
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_lldp (uint32 unit,
                              opennsl_field_entry_t* ingress_fp_entry)
{
    int32                  retval = -1;
    uint16                 ether_type = OPS_COPP_LLDP_ETHER_TYPE;
    uint16                 ether_mask = OPS_COPP_L2_ETHER_TYPE_MASK;
    opennsl_mac_t          ether_dst_mac_array[] = {OPS_COPP_LLDP_MAC_DEST_1,
                                                    OPS_COPP_LLDP_MAC_DEST_2,
                                                    OPS_COPP_LLDP_MAC_DEST_3};
    opennsl_mac_t          ether_dst_mask = OPS_COPP_L2_ADDR_MASK;
    static int             index;


    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for LLDP packets. Qualify the LLDP packets
     * on the following rules:-
     * 1. Ethertype in L2 frame should be 0x88CC
     * 2. Program the L@ destination MAC as one of OPS_COPP_LLDP_MAC_DEST_1,
     *     OPS_COPP_LLDP_MAC_DEST_2 and OPS_COPP_LLDP_MAC_DEST_3.
     */
    retval = opennsl_field_qualify_EtherType(unit, *ingress_fp_entry,
                                             ether_type, ether_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ether type for "
                 "LLDP packet %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    if (index < sizeof(ether_dst_mac_array)/sizeof(opennsl_mac_t)) {

        retval = opennsl_field_qualify_DstMac(unit, *ingress_fp_entry,
                                              ether_dst_mac_array[index],
                                              ether_dst_mask);
        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("     Ingress: Failed to qualify on  "
                     "destination MAC address %s \n", opennsl_errmsg(retval));
            return(OPS_COPP_FAILURE_CODE);
        }

        ++index;

        if ((index % (sizeof(ether_dst_mac_array)/sizeof(opennsl_mac_t))) == 0) {
            index = 0;
        }
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_lldp
 *
 * This function programs the qualifiers for identifying a LLDP
 * packet in egress pipeline.
 */
int ops_copp_egress_fp_lldp (uint32 unit,
                             opennsl_field_entry_t* egress_fp_entry,
                             uint8 ingress_cpu_queue_number)
{
    int32                      retval = -1;
    uint16                     ether_type = OPS_COPP_LLDP_ETHER_TYPE;
    uint16                     ether_mask = OPS_COPP_L2_ETHER_TYPE_MASK;
    opennsl_port_t             port = OPS_COPP_OUT_PORT;
    opennsl_port_t             port_mask = OPS_COPP_OUT_PORT_MASK;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for LLDP packets. Qualify the LLDP packets
     * on the following rules:-
     * 1. Ethertype in L2 frame should be 0x0806
     * 2. The out port should be zero as the packet is destined to CPU.
     * 3  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_EtherType(unit, *egress_fp_entry,
                                             ether_type, ether_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ether type for "
                 "broadcast ARP %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_stp
 *
 * This function programs the qualifiers for identifying a STP
 * packet (for bridges and provider bridges) in ingress pipeline.
 */
int ops_copp_ingress_fp_stp (uint32 unit,
                             opennsl_field_entry_t* ingress_fp_entry)
{
    int32                  retval = -1;
    opennsl_mac_t          ether_dst_mac = OPS_COPP_STP_MAC_DEST;
    opennsl_mac_t          ether_dst_mask = OPS_COPP_STP_MAC_DEST_MASK;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for STP packets. Qualify the STP packets
     * on the following rules:-
     * 1. The destination MAC should be 01:80:c2:00:00:00.
     */
    retval = opennsl_field_qualify_DstMac(unit, *ingress_fp_entry,
                                          ether_dst_mac, ether_dst_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on STP "
                 "destination MAC address %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_stp
 *
 * This function programs the qualifiers for identifying a STP
 * packet (for bridges and provider bridges) in egress pipeline.
 */
int ops_copp_egress_fp_stp (uint32 unit,
                            opennsl_field_entry_t* egress_fp_entry,
                            uint8 ingress_cpu_queue_number)
{
    int32                  retval = -1;
    opennsl_mac_t          ether_dst_mac = OPS_COPP_STP_MAC_DEST;
    opennsl_mac_t          ether_dst_mask = OPS_COPP_STP_MAC_DEST_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for STP packets. Qualify the STP packets
     * on the following rules:-
     * 1. The destination MAC should be 01:80:c2:00:00:00.
     * 2. The out port should be zero as the packet is destined to CPU.
     * 3  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_DstMac(unit, *egress_fp_entry,
                                          ether_dst_mac, ether_dst_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on STP "
                 "destination MAC address %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_bgp_L4_dst_port
 *
 * This function programs the qualifiers for identifying a BGP packet
 * in ingress pipeline for destination port.
 */
int ops_copp_ingress_fp_bgp_L4_dst_port (uint32 unit,
                             opennsl_field_entry_t* ingress_fp_entry)
{
    opennsl_l4_port_t      L4_dst_port = OPS_COPP_L4_PORT_BGP;
    opennsl_l4_port_t      L4_dst_port_mask = OPS_COPP_L4_PORT_MASK;
    uint8                  address_data = OPS_COPP_DST_IP_LOCAL_DATA;
    uint8                  address_mask = OPS_COPP_DST_IP_LOCAL_MASK;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_TCP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for BGP. Qualify the BGP packets
     * on the following rules:-
     * 1. L4 destination port is 179
     * 2. The destination IP address is local to the box
     * 3. The protocol in IP packet is TCP.
     */
    retval = opennsl_field_qualify_L4DstPort(unit, *ingress_fp_entry,
                                             L4_dst_port, L4_dst_port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on L4 destination "
                 "port %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpProtocol(unit, *ingress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIpLocal(unit, *ingress_fp_entry,
                                              address_data, address_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on destination "
                 "IP being Local %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_bgp_L4_src_port
 *
 * This function programs the qualifiers for identifying a BGP packet
 * in ingress pipeline for source port.
 */
int ops_copp_ingress_fp_bgp_L4_src_port (uint32 unit,
                                      opennsl_field_entry_t* ingress_fp_entry)
{
    opennsl_l4_port_t      L4_src_port = OPS_COPP_L4_PORT_BGP;
    opennsl_l4_port_t      L4_src_port_mask = OPS_COPP_L4_PORT_MASK;
    uint8                  address_data = OPS_COPP_DST_IP_LOCAL_DATA;
    uint8                  address_mask = OPS_COPP_DST_IP_LOCAL_MASK;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_TCP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for BGP. Qualify the BGP packets
     * on the following rules:-
     * 1. L4 source port is 179
     * 2. The destination IP address is local to the box
     * 3. The protocol in IP packet is TCP.
     */
    retval = opennsl_field_qualify_L4SrcPort(unit, *ingress_fp_entry,
                                             L4_src_port, L4_src_port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on L4 destination "
                 "port %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpProtocol(unit, *ingress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIpLocal(unit, *ingress_fp_entry,
                                              address_data, address_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on destination "
                 "IP being Local %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_bgp
 *
 * This function programs the qualifiers for identifying a BGP packet
 * in egress pipeline.
 */
int ops_copp_egress_fp_bgp (uint32 unit,
                            opennsl_field_entry_t* egress_fp_entry,
                            uint8 ingress_cpu_queue_number)
{
    int32                  retval = -1;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_TCP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for BGP. Qualify the BGP packets
     * on the following rules:-
     * 1. The destination IP address is local to the box
     * 2. The out port should be zero as the packet is destined to CPU.
     * 3  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */

    retval = opennsl_field_qualify_IpProtocol(unit, *egress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_dhcpv4
 *
 * This function programs the qualifiers for identifying a DHCPv4 packet
 * in ingress pipeline. The DHCPv4 packet in destined for the DHCP server.
 */
int ops_copp_ingress_fp_dhcpv4 (uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    opennsl_l4_port_t      L4_dst_port = OPS_COPP_L4_PORT_DHCPV4;
    opennsl_l4_port_t      L4_dst_port_mask = OPS_COPP_L4_PORT_MASK;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_UDP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for DHCPv4. Qualify the DHCPv4 packets
     * on the following rules:-
     * 1. L4 destination port is 67
     * 2. The protocol in IP packet is UDP
     * 3. The packet should be an IPv4 packet
     */
    retval = opennsl_field_qualify_L4DstPort(unit, *ingress_fp_entry,
                                             L4_dst_port, L4_dst_port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on L4 destination "
                 "port %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpProtocol(unit, *ingress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_dhcpv4
 *
 * This function programs the qualifiers for identifying a DHCPv4 packet
 * in egress pipeline. The DHCPv4 packet in destined for the DHCP server.
 */
int ops_copp_egress_fp_dhcpv4 (uint32 unit,
                               opennsl_field_entry_t* egress_fp_entry,
                               uint8 ingress_cpu_queue_number)
{
    opennsl_l4_port_t      L4_dst_port = OPS_COPP_L4_PORT_DHCPV4;
    opennsl_l4_port_t      L4_dst_port_mask = OPS_COPP_L4_PORT_MASK;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_UDP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for DHCPv4. Qualify the DHCPv4 packets
     * on the following rules:-
     * 1. L4 destination port is 67
     * 2. The protocol in IP packet is UDP.
     * 3. The packet should be an IPv4 packet
     * 4. The out port should be zero as the packet is destined to CPU.
     * 5  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_L4DstPort(unit, *egress_fp_entry,
                                             L4_dst_port, L4_dst_port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on L4 destination "
                 "port %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpProtocol(unit, *egress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_dhcpv6
 *
 * This function programs the qualifiers for identifying a DHCPv6 packet
 * in ingress pipeline. The DHCPv6 packet in destined for the DHCP server.
 */
int ops_copp_ingress_fp_dhcpv6 (uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    opennsl_l4_port_t      L4_dst_port = OPS_COPP_L4_PORT_DHCPV6;
    opennsl_l4_port_t      L4_dst_port_mask = OPS_COPP_L4_PORT_MASK;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_UDP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for DHCPv6. Qualify the DHCPv6 packets
     * on the following rules:-
     * 1. L4 destination port is 547
     * 2. The protocol in IP packet is UDP
     * 3. The packet should be an IPv6 packet
     */
    retval = opennsl_field_qualify_L4DstPort(unit, *ingress_fp_entry,
                                             L4_dst_port, L4_dst_port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on L4 destination "
                 "port %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_Ip6NextHeader(unit, *ingress_fp_entry,
                                                 prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IPv6 protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv6);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv6 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_dhcpv6
 *
 * This function programs the qualifiers for identifying a DHCPv6 packet
 * in egress pipeline. The DHCPv6 packet in destined for the DHCP server.
 */
int ops_copp_egress_fp_dhcpv6 (uint32 unit,
                               opennsl_field_entry_t* egress_fp_entry,
                               uint8 ingress_cpu_queue_number)
{
    opennsl_l4_port_t      L4_dst_port = OPS_COPP_L4_PORT_DHCPV6;
    opennsl_l4_port_t      L4_dst_port_mask = OPS_COPP_L4_PORT_MASK;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_UDP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for DHCPv6. Qualify the DHCPv6 packets
     * on the following rules:-
     * 1. L4 destination port is 547
     * 2. The protocol in IP packet is UDP
     * 3. The packet should be an IPv6 packet
     * 4. The out port should be zero as the packet is destined to CPU.
     * 5  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_L4DstPort(unit, *egress_fp_entry,
                                             L4_dst_port, L4_dst_port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on L4 destination "
                 "port %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_Ip6NextHeader(unit, *egress_fp_entry,
                                                 prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on IPv6 protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv6);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv6 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_icmpv4_ucast
 *
 * This function programs the qualifiers for identifying a ICMPv4 unicast
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_icmpv4_ucast (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    uint8                  address_data = OPS_COPP_DST_IP_LOCAL_DATA;
    uint8                  address_mask = OPS_COPP_DST_IP_LOCAL_MASK;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IPV4_NUMBER_ICMP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ICMPv4 unicast packets. Qualify the
     * ICMPv4 unicast packets on the following rules:-
     * 1. The protocol in IP packet is ICMP.
     * 2. The packet should be an IPv4 packet
     * 3. The destination IP address is local to the box
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *ingress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIpLocal(unit, *ingress_fp_entry,
                                              address_data, address_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on destination "
                 "IP being Local %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_icmpv4_ucast
 *
 * This function programs the qualifiers for identifying a ICMPv4 unicast
 * packet in egress pipeline.
 */
int ops_copp_egress_fp_icmpv4_ucast (uint32 unit,
                                     opennsl_field_entry_t* egress_fp_entry,
                                     uint8 ingress_cpu_queue_number)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IPV4_NUMBER_ICMP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ICMPv4 unicast packets. Qualify the
     * ICMPv4 unicast packets on the following rules:-
     * 1. The protocol in IP packet is ICMP.
     * 2. The packet should be an IPv4 packet
     * 3. The out port should be zero as the packet is destined to CPU.
     * 4  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *egress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_icmpv4_bcast
 *
 * This function programs the qualifiers for identifying a ICMPv4 broadcast
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_icmpv4_bcast (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IPV4_NUMBER_ICMP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ICMPv4 broadcast packets. Qualify the
     * ICMPv4 broadcast packets on the following rules:-
     * 1. The protocol in IP packet is ICMP.
     * 2. The packet should be an IPv4 packet
     * 3. The destination IP address is 255.255.255.255
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *ingress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIp(
                                unit, *ingress_fp_entry,
                                inet_network(OPS_COPP_L3_IPV4_BROADCAST_ADDR),
                                inet_network(OPS_COPP_L3_IPV4_ADDR_MASK));
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on broadcast "
                 "IP address  %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_icmpv4_mcast
 *
 * This function programs the qualifiers for identifying a ICMPv4 multicast
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_icmpv4_mcast (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IPV4_NUMBER_ICMP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ICMPv4 multicast packets. Qualify the
     * ICMPv4 multicast packets on the following rules:-
     * 1. The protocol in IP packet is ICMP.
     * 2. The packet should be an IPv4 packet
     * 3. The destination IP address is within the range 224.0.0.0 to
     *    239.255.255.255.
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *ingress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIp(
                                unit, *ingress_fp_entry,
                                inet_network(OPS_COPP_L3_IPV4_MCAST_ADDR),
                                inet_network(OPS_COPP_L3_IPV4_MCAST_ADDR_MASK));
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on multicast "
                 "IP address  %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_icmpv4_bcast_mcast
 *
 * This function programs the qualifiers for identifying a ICMPv4 broadcast
 * or multicast packet in egress pipeline.
 */
int ops_copp_egress_fp_icmpv4_bcast_mcast (
                                      uint32 unit,
                                      opennsl_field_entry_t* egress_fp_entry,
                                      uint8 ingress_cpu_queue_number)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IPV4_NUMBER_ICMP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ICMPv4 broadcast/multicast packets.
     * Qualify the ICMPv4 broadcast/multicast packets on the following rules:-
     * 1. The protocol in IP packet is ICMP.
     * 2. The packet should be an IPv4 packet
     * 3. The out port should be zero as the packet is destined to CPU.
     * 4  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *egress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_icmpv6_ucast
 *
 * This function programs the qualifiers for identifying a ICMPv6 unicast
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_icmpv6_ucast (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    uint8                  address_data = OPS_COPP_DST_IP_LOCAL_DATA;
    uint8                  address_mask = OPS_COPP_DST_IP_LOCAL_MASK;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IPV6_NUMBER_ICMP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ICMPv4 unicast packets. Qualify the
     * ICMPv6 unicast packets on the following rules:-
     * 1. The destination IPv6 address is local to the box
     * 2. The packet should be an IPv6 packet
     * 3. The protocol in IPv6 packet is ICMPv6.
     */
    retval = opennsl_field_qualify_Ip6NextHeader(unit, *ingress_fp_entry,
                                                 prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IPv6 protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv6);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIpLocal(unit, *ingress_fp_entry,
                                              address_data, address_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on destination "
                 "IP being Local %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_icmpv6_ucast
 *
 * This function programs the qualifiers for identifying a ICMPv6 unicast
 * packet in ingress pipeline.
 */
int ops_copp_egress_fp_icmpv6_ucast (uint32 unit,
                                     opennsl_field_entry_t* egress_fp_entry,
                                     uint8 ingress_cpu_queue_number)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IPV6_NUMBER_ICMP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ICMPv4 unicast packets. Qualify the
     * ICMPv4 unicast packets on the following rules:-
     * 1. The protocol in IPv6 packet is ICMPv6.
     * 2. The packet should be an IPv6 packet
     * 3. The out port should be zero as the packet is destined to CPU.
     * 4  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_Ip6NextHeader(unit, *egress_fp_entry,
                                                 prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on IPv6 protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv6);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_icmpv6_mcast
 *
 * This function programs the qualifiers for identifying a ICMPv6 multicast
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_icmpv6_mcast (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IPV6_NUMBER_ICMP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_ip6_t          ipv6_mcast_addr = OPS_COPP_L3_IPV6_MCAST_ADDR;
    opennsl_ip6_t          ipv6_mcast_addr_mask = OPS_COPP_L3_IPV6_MCAST_ADDR_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ICMPv6 multicast packets. Qualify the
     * ICMPv6 multicast packets on the following rules:-
     * 1. The destination IPv6 address should be IPv6 multicast
     * 2. The packet should be an IPv6 packet
     * 3. The protocol in IPv6 packet is ICMPv6.
     */
    retval = opennsl_field_qualify_Ip6NextHeader(unit, *ingress_fp_entry,
                                                 prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IPv6 protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv6);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIp6(unit, *ingress_fp_entry,
                                          ipv6_mcast_addr, ipv6_mcast_addr_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on destination "
                 "IPv6 being multicast %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_icmpv6_mcast
 *
 * This function programs the qualifiers for identifying a ICMPv6 multicast
 * packet in ingress pipeline.
 */
int ops_copp_egress_fp_icmpv6_mcast (uint32 unit,
                                     opennsl_field_entry_t* egress_fp_entry,
                                     uint8 ingress_cpu_queue_number)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IPV6_NUMBER_ICMP;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for ICMPv6 multicast packets. Qualify the
     * ICMPv6 multicast packets on the following rules:-
     * 1. The protocol in IPv6 packet is ICMPv6.
     * 2. The packet should be an IPv6 packet
     * 3. The out port should be zero as the packet is destined to CPU.
     * 4  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_Ip6NextHeader(unit, *egress_fp_entry,
                                                 prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on IPv6 protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv6);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_ospfv2_dr_mcast
 *
 * This function programs the qualifiers for identifying a OSPFv2 dr
 * multicast packet in ingress pipeline.
 */
int ops_copp_ingress_fp_ospfv2_dr_mcast (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_OSPFV2;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;
    opennsl_mac_t          dr_mac = OPS_COPP_OSPF_MAC_DR_ROUTERS;
    opennsl_mac_t          mac_mask = OPS_COPP_L2_ADDR_MASK;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for OSPFv2 dr multicast packets. Qualify the
     * OSPFv2 dr multicast packets on the following rules:-
     * 1. The protocol in IP packet is OSPFv2.
     * 2. The packet should be an IPv4 packet
     * 3. The destination MAC address should be OSPFv2 dr router MAC
     * 4. The destination IP address should be OSPFv2 dr router IP.
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *ingress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstMac(unit, *ingress_fp_entry,
                                          dr_mac, mac_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on dr multicast "
                 "OSPFv2 MAC  %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIp(
                                unit, *ingress_fp_entry,
                                inet_network(OPS_COPP_OSPF_IPV4_DR_POUTERS),
                                inet_network(OPS_COPP_L3_IPV4_ADDR_MASK));
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on dr multicast "
                 "OSPFv2 IP address  %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_ospfv2_all_mcast
 *
 * This function programs the qualifiers for identifying a OSPFv2 all
 * multicast packet in ingress pipeline.
 */
int ops_copp_ingress_fp_ospfv2_all_mcast (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_OSPFV2;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;
    opennsl_mac_t          all_mac = OPS_COPP_OSPF_MAC_ALL_ROUTERS;
    opennsl_mac_t          mac_mask = OPS_COPP_L2_ADDR_MASK;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for OSPFv2 all multicast packets. Qualify the
     * OSPFv2 all multicast packets on the following rules:-
     * 1. The protocol in IP packet is OSPFv2.
     * 2. The packet should be an IPv4 packet
     * 3. The destination MAC address should be OSPFv2 all router MAC
     * 4. The destination IP address should be OSPFv2 all router IP.
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *ingress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstMac(unit, *ingress_fp_entry,
                                          all_mac, mac_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on all multicast "
                 "OSPFv2 MAC  %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIp(
                                unit, *ingress_fp_entry,
                                inet_network(OPS_COPP_OSPF_IPV4_ALL_POUTERS),
                                inet_network(OPS_COPP_L3_IPV4_ADDR_MASK));
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on all multicast "
                 "OSPFv2 IP address  %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_ospfv2_mcast
 *
 * This function programs the qualifiers for identifying an OSPFv2
 * multicast packet in egress pipeline.
 */
int ops_copp_egress_fp_ospfv2_mcast (uint32 unit,
                                     opennsl_field_entry_t* egress_fp_entry,
                                     uint8 ingress_cpu_queue_number)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_OSPFV2;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    opennsl_mac_t          all_mac = OPS_COPP_OSPF_MAC_ALL_ROUTERS;
    opennsl_mac_t          mac_mask = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00};
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for OSPFv2 multicast packets.
     * Qualify the OSPFv2 multicast packets on the following rules:-
     * 1. The protocol in IP packet is OSPFv2.
     * 2. The packet should be an IPv4 packet
     * 3. The destination IP address is within the range 224.0.0.0 to
     *    239.255.255.255.
     * 4. The destination MAC should match 01:00:5E:00:00:XX.
     * 5. The out port should be zero as the packet is destined to CPU.
     * 6  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *egress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIp(
                                unit, *egress_fp_entry,
                                inet_network(OPS_COPP_L3_IPV4_MCAST_ADDR),
                                inet_network(OPS_COPP_L3_IPV4_MCAST_ADDR_MASK));
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on multicast "
                 "IP address  %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstMac(unit, *egress_fp_entry,
                                          all_mac, mac_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on all multicast "
                 "OSPFv2 MAC  %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_ospfv2_ucast
 *
 * This function programs the qualifiers for identifying a OSPFv2 unicast
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_ospfv2_ucast (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    uint8                  address_data = OPS_COPP_DST_IP_LOCAL_DATA;
    uint8                  address_mask = OPS_COPP_DST_IP_LOCAL_MASK;
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_OSPFV2;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for OSPFv2 unicast packets. Qualify the
     * OSPFv2 unicast packets on the following rules:-
     * 1. The protocol in IP packet is OSPFv2.
     * 2. The packet should be an IPv4 packet
     * 3. The destination IP address is local to the box
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *ingress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_DstIpLocal(unit, *ingress_fp_entry,
                                              address_data, address_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on destination "
                 "IP being Local %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_ospfv2_ucast
 *
 * This function programs the qualifiers for identifying a OSPFv2 unicast
 * packet in ingress pipeline.
 */
int ops_copp_egress_fp_ospfv2_ucast (uint32 unit,
                                     opennsl_field_entry_t* egress_fp_entry,
                                     uint8 ingress_cpu_queue_number)
{
    uint8                  prot_type = OPS_COPP_IP_PROTOCOL_IP_NUMBER_OSPFV2;
    uint8                  prot_mask = OPS_COPP_IP_PROTOCOL_IP_NUMBER_MASK;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for OSPFv2 unicast packets. Qualify the
     * OSPFv2 unicast packets on the following rules:-
     * 1. The protocol in IP packet is OSPFv2.
     * 2. The packet should be an IPv4 packet
     * 3. The out port should be zero as the packet is destined to CPU.
     * 4  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_IpProtocol(unit, *egress_fp_entry,
                                              prot_type, prot_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on IP protocol "
                 "number %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_ipv4_options
 *
 * This function programs the qualifiers for identifying an IPv4 options
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_ipv4_options (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for IPv4 oprions packets. Qualify the
     * IPv4 options packets on the following rules:-
     * 1. The packet should be an IPv4 packet
     * 2. The IP packet should have options feild should be set.
     */
    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv4WithOpts);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv4 options"
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_ipv4_options
 *
 * This function programs the qualifiers for identifying an IPv4 options
 * packet in egress pipeline.
 */
int ops_copp_egress_fp_ipv4_options (uint32 unit,
                                     opennsl_field_entry_t* egress_fp_entry,
                                     uint8 ingress_cpu_queue_number)
{
    int32                  retval = -1;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for IPv4 oprions packets. Qualify the
     * IPv4 options packets on the following rules:-
     * 1. The packet should be an IPv4 packet
     * 2. The IP packet should have options feild should be set.
     * 3. The out port should be zero as the packet is destined to CPU.
     * 4  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv4Any);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv4 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv4WithOpts);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv4 options"
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_ipv6_options
 *
 * This function programs the qualifiers for identifying an IPv6 options
 * packet in ingress pipeline.
 */
int ops_copp_ingress_fp_ipv6_options (
                                uint32 unit,
                                opennsl_field_entry_t* ingress_fp_entry)
{
    int32                  retval = -1;

    if (!ingress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for IPv6 oprions packets. Qualify the
     * IPv4 options packets on the following rules:-
     * 1. The packet should be an IPv6 packet
     * 2. The IPv6 packet should have options feild should be set.
     */
    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv6);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv6 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *ingress_fp_entry,
                                          opennslFieldIpTypeIpv6OneExtHdr);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Ingress: Failed to qualify on ipv6 options"
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_ipv6_options
 *
 * This function programs the qualifiers for identifying an IPv6 options
 * packet in egress pipeline.
 */
int ops_copp_egress_fp_ipv6_options (uint32 unit,
                                     opennsl_field_entry_t* egress_fp_entry,
                                     uint8 ingress_cpu_queue_number)
{
    int32                  retval = -1;
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for IPv6 oprions packets. Qualify the
     * IPv6 options packets on the following rules:-
     * 1. The packet should be an IPv6 packet
     * 2. The IPv6 packet should have options feild should be set.
     * 3. The out port should be zero as the packet is destined to CPU.
     * 4  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv6);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv6 packet type "
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_IpType(unit, *egress_fp_entry,
                                          opennslFieldIpTypeIpv6OneExtHdr);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on ipv6 options"
                 " %s \n", opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_sflow
 *
 * This function programs the global rx rule for sflow packets.
 */
int ops_copp_sflow (uint32 unit)
{
    uint8                   int_prio=0;
    uint8                   int_prio_mask=0;
    uint32                  packet_type = 0;
    uint32                  packet_type_mask = 0;
    opennsl_rx_reasons_t    rx_reasons;
    opennsl_rx_reasons_t    rx_reasons_mask;
    opennsl_cos_queue_t     cpu_cosq = OPS_COPP_QOS_QUEUE_SFLOW;
    int32                   retval = -1;

    /*
     * Set rx reason code for Sampled destination
     */
    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons);
    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons_mask);
    OPENNSL_RX_REASON_SET(rx_reasons, opennslRxReasonSampleDest);
    OPENNSL_RX_REASON_SET(rx_reasons_mask, opennslRxReasonSampleDest);

    retval = opennsl_rx_cosq_mapping_set(unit, ops_copp_packet_class_rx_index[unit],
                                         rx_reasons, rx_reasons_mask,
                                         int_prio, int_prio_mask, packet_type,
                                         packet_type_mask, cpu_cosq);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Packet class: Failed to program the "
                 "packet class rule for sampled destination sflow %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Increment the rx index counter
     */
    ops_copp_packet_class_rx_index[unit]++;

    /*
     * Set rx reason code for Sampled source
     */
    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons);
    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons_mask);
    OPENNSL_RX_REASON_SET(rx_reasons, opennslRxReasonSampleSource);
    OPENNSL_RX_REASON_SET(rx_reasons_mask, opennslRxReasonSampleSource);

    retval = opennsl_rx_cosq_mapping_set(unit, ops_copp_packet_class_rx_index[unit],
                                         rx_reasons, rx_reasons_mask,
                                         int_prio, int_prio_mask, packet_type,
                                         packet_type_mask, cpu_cosq);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Packet class: Failed to program the "
                 "packet class rule for sampled source sflow %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Increment the rx index counter
     */
    ops_copp_packet_class_rx_index[unit]++;

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_sflow
 *
 * This function programs the qualifiers for matching all sflow
 * packets in egress pipeline.
 */
int ops_copp_egress_fp_sflow (uint32 unit,
                              opennsl_field_entry_t* egress_fp_entry,
                              uint8 ingress_cpu_queue_number)
{
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for sflow packets. Qualify the
     * sflow packets on the following rules:-
     * 1. The out port should be zero as the packet is destined to CPU.
     * 2  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_unknown_ip_unicast
 *
 * This function programs the rx rule for unknown IP packets.
 */
int ops_copp_unknown_ip_unicast (uint32 unit)
{
    uint8                   int_prio=0;
    uint8                   int_prio_mask=0;
    uint32                  packet_type = 0;
    uint32                  packet_type_mask = 0;
    opennsl_rx_reasons_t    rx_reasons;
    opennsl_rx_reasons_t    rx_reasons_mask;
    opennsl_cos_queue_t     cpu_cosq = OPS_COPP_QOS_QUEUE_UNKNOWN_IP;
    int32                   retval = -1;

    /*
     * Program rx rule for directing unknown destination IP packets to
     * appropriate CPU queue.
     */
    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons);
    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons_mask);
    OPENNSL_RX_REASON_SET(rx_reasons, opennslRxReasonL3DestMiss);
    OPENNSL_RX_REASON_SET(rx_reasons_mask, opennslRxReasonL3DestMiss);

    retval = opennsl_rx_cosq_mapping_set(unit, ops_copp_packet_class_rx_index[unit],
                                         rx_reasons, rx_reasons_mask,
                                         int_prio, int_prio_mask, packet_type,
                                         packet_type_mask, cpu_cosq);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Packet class: Failed to program the "
                 "packet class rule for dest unknown IP %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Increment the rx index counter
     */
    ops_copp_packet_class_rx_index[unit]++;

    /*
     * Program the rx rule to send packets with priroty
     * OPS_COPP_UNKNOWN_IP_COS_RESERVED to unknown IP cpuq
     */
    int_prio = OPS_COPP_UNKNOWN_IP_COS_RESERVED;
    int_prio_mask = 0xff;

    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons);
    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons_mask);
    retval  = opennsl_rx_cosq_mapping_set(unit,
                                             ops_copp_packet_class_rx_index[unit],
                                             rx_reasons, rx_reasons_mask,
                                             int_prio, int_prio_mask, packet_type,
                                             packet_type_mask, cpu_cosq);

    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Packet class: Failed to program the packet"
                 "class rule for glean packets  %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Increment the rx index counter
     */
    ops_copp_packet_class_rx_index[unit]++;

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_unknown_ip_unicast
 *
 * This function programs the qualifiers for matching all unknown unicast IP
 * packets in egress pipeline.
 */
int ops_copp_egress_fp_unknown_ip_unicast (
                                   uint32 unit,
                                   opennsl_field_entry_t* egress_fp_entry,
                                   uint8 ingress_cpu_queue_number)
{
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for unknown unicast IP packets. Qualify the
     * unknown unicast IP packets on the following rules:-
     * 1. The out port should be zero as the packet is destined to CPU.
     * 2  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_unclassified
 *
 * This function programs the rx rule for unclassified packets.
 * We determine if a control plane packet is unclassified based on
 * the priority set in the packet.
 */
int ops_copp_unclassified (uint32 unit)
{
    uint8                   int_prio_min = OPS_COPP_INT_PRIORITY_MIN;
    uint8                   int_prio_max = OPS_COPP_INT_PRIORITY_MAX;
    uint8                   int_prio = 0;
    uint8                   int_prio_mask = 0xff;
    uint32                  packet_type = 0;
    uint32                  packet_type_mask = 0;
    opennsl_rx_reasons_t    rx_reasons;
    opennsl_rx_reasons_t    rx_reasons_mask;
    opennsl_cos_queue_t     cpu_cosq = OPS_COPP_QOS_QUEUE_DEFAULT;
    int32                   retval = -1;

    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons);
    OPENNSL_RX_REASON_CLEAR_ALL(rx_reasons_mask);

    for (int_prio = int_prio_min; int_prio <= int_prio_max; ++int_prio) {

        /*
         * TODO: We could program just one mapping using the appropriate
         *       mask on the internal priority range from 0-7. But we are keeping
         *       this logic unless we know that the range of priority values are
         *       from 0-7 only.
         */
        retval = opennsl_rx_cosq_mapping_set(unit,
                                             ops_copp_packet_class_rx_index[unit],
                                             rx_reasons, rx_reasons_mask,
                                             int_prio, int_prio_mask, packet_type,
                                             packet_type_mask, cpu_cosq);
        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("     Packet class: Failed to program the "
                     "packet class rule for unclassified packets %s\n",
                     opennsl_errmsg(retval));
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Increment the rx index counter
         */
        ops_copp_packet_class_rx_index[unit]++;
    }

    return(OPS_COPP_SUCCESS_CODE);
}


/*
 * ops_copp_egress_fp_unclassified
 *
 * This function programs the qualifiers for matching all control packets
 * pn egress pipeline which do not match any preceeding FP rules.
 */
int ops_copp_egress_fp_unclassified (
                                   uint32 unit,
                                   opennsl_field_entry_t* egress_fp_entry,
                                   uint8 ingress_cpu_queue_number)
{
    opennsl_port_t         port = OPS_COPP_OUT_PORT;
    opennsl_port_t         port_mask = OPS_COPP_OUT_PORT_MASK;
    int32                  retval = -1;

    if (!egress_fp_entry) {
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Add the FP qualifier rules for unclassified packets. Qualify the
     * unclassified packets on the following rules:-
     * 1. The out port should be zero as the packet is destined to CPU.
     * 2  The packet's meta data should contain the CPU queue set in ingress
     *    pipeline.
     */
    retval = opennsl_field_qualify_OutPort(unit, *egress_fp_entry,
                                           port, port_mask);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on out port %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    retval = opennsl_field_qualify_CpuQueue(unit,
                             *egress_fp_entry, ingress_cpu_queue_number, 0xff);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_packet_class_set_status
 *
 * This function sets the status value in the global structure for copp
 * to the value specified in the input parameters.
 */
static int ops_copp_packet_class_set_status(
                              uint32 unit,
                              enum ops_copp_packet_class_code_t packet_class,
                              bool status_value)
{
    struct ops_copp_fp_rule_t* copp_packet_class = NULL;

    /*
     * If the packet class is not valid, then do not do anything and
     * return from this function.
     */
    if ((packet_class < 0) ||
        (packet_class >= PLUGIN_COPP_MAX_CLASSES)) {
        VLOG_ERR("Not a valid packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * If the unit is not valid, then do not do anything and
     * return from this function raising a failure.
     */
    if ((unit < 0) || (unit >= OPS_COPP_MAX_UNITS)) {
        VLOG_ERR("Not a valid unit");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Get the pointer reference to the control packet rule.
     */
    copp_packet_class = &ops_copp_packet_class_t[packet_class];
    if (copp_packet_class == NULL) {
        VLOG_ERR("Global Copp structure not present for pkt class %d",
                  packet_class);
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Set the status value passed into the function for the hw_unit.
     */
    copp_packet_class->status[unit] = status_value;

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_packet_class_programmer
 *
 * This function programs the global packet rules for some packet types for a
 * given hardware unit if only the function pointer for the control plane
 * packet is defined.
 */
static int ops_copp_packet_class_programmer(
                              uint32 unit,
                              enum ops_copp_packet_class_code_t packet_class)
{
    int32                      retval = -1;
    struct ops_copp_fp_rule_t* copp_packet_class = NULL;

    /*
     * If the packet class is not valid, then do not do anything and
     * return from this function.
     */
    if ((packet_class < 0) ||
        (packet_class >= PLUGIN_COPP_MAX_CLASSES)) {
        VLOG_ERR("Not a valid packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Get the pointer reference to the control packet rule.
     */
    copp_packet_class = &ops_copp_packet_class_t[packet_class];

    if (!copp_packet_class) {
        VLOG_ERR("Invalid pointer to packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * If the function pointer for the control packet is defined,
     * then call the function for programming the rx rule.
     */
    if (copp_packet_class->ops_copp_packet_class_function_pointer) {
        retval = (*copp_packet_class->ops_copp_packet_class_function_pointer)
                                                                      (unit);
        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("     Packet class: Failed to program the "
                     "packet class rule %s\n",
                     opennsl_errmsg(retval));
            return(OPS_COPP_FAILURE_CODE);
        }

        VLOG_DBG("     Packet class: Successfully programmed the "
                 "packet class rule for %s",
                 copp_packet_class->ops_copp_packet_name);
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_programmer
 *
 * This function does the following two operations for the control packets:-
 * 1. If the ingress FP entry for the control packet is NULL, then this
 *    function creates a new ingress FP entry and attaches the default CPU
 *    queue number for the control packets. This is the case at the
 *    initialization time when the plugin gets loaded in vswitchd for the
 *    first time.
 * 2. If the ingress FP entry for the control packet is not NULL, then this
 *    function updates the CPU queue for the control packet with the
 *    CPU queue value passed to this function.
 */
static int ops_copp_ingress_fp_programmer (
                              uint32 unit,
                              enum ops_copp_packet_class_code_t packet_class,
                              uint32* ingress_fp_queue)
{
    int32                        retval = -1;
    bool                         if_init_ingress_fp_program = false;
    bool                         if_config_ingress_fp_program = false;
    int                          ingress_fp_rule_number;
    struct ops_copp_fp_rule_t*   copp_packet_class = NULL;

    /*
     * If the packet class is not valid, then do not do anything and
     * return from this function.
     */
    if ((packet_class < 0) ||
        (packet_class >= PLUGIN_COPP_MAX_CLASSES)) {
        VLOG_ERR("Not a valid packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Get the pointer reference to the control packet rule.
     */
    copp_packet_class = &ops_copp_packet_class_t[packet_class];

    if (!copp_packet_class) {
        VLOG_ERR("Invalid pointer to packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * There are no ingress FP function pointers for ACL logging, sflow,
     * unknown IP and unclassified packets. So return from this function.
     */
    if ((packet_class == PLUGIN_COPP_ACL_LOGGING_PACKET) ||
        (packet_class == PLUGIN_COPP_SFLOW_PACKET) ||
        (packet_class == PLUGIN_COPP_UNCLASSIFIED_PACKET) ||
        (packet_class == PLUGIN_COPP_UNKNOWN_IP_UNICAST_PACKET)) {
        return(OPS_COPP_SUCCESS_CODE);
    }

    /*
     * If the ingress FP entry pointer for the control packet is NULL,
     * then we need to allocate a new FP entry and program the hardware.
     */
    if (!(copp_packet_class->ops_copp_ingress_fp_entry[unit][0]) &&
        copp_packet_class->ops_copp_ingress_fp_funtion_pointer[0]) {
        if_init_ingress_fp_program = true;
    }

    /*
     * If the ingress FP entry pointer for the control packet is not NULL,
     * then we need to update the FP entry with the new CPU queue value.
     */
    if (copp_packet_class->ops_copp_ingress_fp_entry[unit][0] &&
        ingress_fp_queue) {
        if_config_ingress_fp_program = true;
    }

    /*
     * If we find that this function is neither called at init time or
     * at CPU queue modification time, then return from this function.
     */
    if (!if_init_ingress_fp_program && !if_config_ingress_fp_program) {
        VLOG_ERR("Invalid use of the ingress function for %s",
                 copp_packet_class->ops_copp_packet_name);
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * If the function is called at the initialization time, then allocate
     * a new FP entry and program the ingress pipeline with the FP rule.
     */
    if (if_init_ingress_fp_program) {

        VLOG_DBG("Create a new ingress FP %s entry with default queue number "
                 "for unit %u", copp_packet_class->ops_copp_packet_name, unit);

        ingress_fp_rule_number = 0;
        while (copp_packet_class->ops_copp_ingress_fp_funtion_pointer[
                                                    ingress_fp_rule_number]) {

            /*
             * Allocate a new FP ingress entry.
             */
            copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                ingress_fp_rule_number] =
                                        xzalloc(sizeof(opennsl_field_entry_t));

            /*
             * Create a new ingress FP entry in the ingress group for the
             * given unit.
             */
            retval = opennsl_field_entry_create(
                        unit, ops_copp_ingress_fp_group_array[unit],
                        copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                     ingress_fp_rule_number]);

            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Ingress: Failed to create entry: %s\n",
                         opennsl_errmsg(retval));
                free(copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                    ingress_fp_rule_number]);
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Call the function pointer for programming the FP qualifier for this
             * packet class.
             */
            retval = (*copp_packet_class->ops_copp_ingress_fp_funtion_pointer[
                                                      ingress_fp_rule_number])(
                            unit,
                            copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                         ingress_fp_rule_number]);
            if (retval != OPS_COPP_SUCCESS_CODE) {
                VLOG_ERR("     Ingress: Failed to add FP qualifiers\n");
                ops_copp_fp_entry_cleanup(unit,
                        copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                          ingress_fp_rule_number]);
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Add the action for the ingress FP entry to be the default CPU
             * queue for the control packet.
             */
            retval = opennsl_field_action_add(
                        unit,
                        *(copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                         ingress_fp_rule_number]),
                        opennslFieldActionCosQCpuNew,
                        copp_packet_class->ops_copp_ingress_fp_queue_number, 0);
            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Ingress: Failed to add action for "
                         "the FP entry %s\n", opennsl_errmsg(retval));
                ops_copp_fp_entry_cleanup(unit,
                        copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                         ingress_fp_rule_number]);
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Install the FP entry into the hardware.
             */
            retval = opennsl_field_entry_install(
                        unit,
                        *(copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                       ingress_fp_rule_number]));
            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Ingress entry program failure: %s\n",
                         opennsl_errmsg(retval));
                ops_copp_fp_entry_cleanup(unit,
                        copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                         ingress_fp_rule_number]);
                return(OPS_COPP_FAILURE_CODE);
            }

            ingress_fp_rule_number++;
        }

        VLOG_DBG("     Ingress: Successfully programmed the FP rule "
                 "for %s", copp_packet_class->ops_copp_packet_name);
    }

    /*
     * If the function is called at the configuration time, then delete
     * CPU queue current action, attach the new CPU queue action and
     * install the FP entry into the hardware.
     */
    if (if_config_ingress_fp_program) {

        /*
         * If the new CPU queue value is same as the already configured
         * value, then do nothing and return from this function.
         */
        if (copp_packet_class->ops_copp_ingress_fp_queue_number ==
            *ingress_fp_queue) {

            VLOG_DBG("     Ingress: The previous CPU queue "
                     "value %u is same as the new intended value %u for %s",
                     copp_packet_class->ops_copp_ingress_fp_queue_number,
                     *ingress_fp_queue,
                     copp_packet_class->ops_copp_packet_name);
        } else {

            ingress_fp_rule_number = 0;
            while (copp_packet_class->ops_copp_ingress_fp_funtion_pointer[
                                                    ingress_fp_rule_number]) {
                /*
                 * Delete the current CPU queue from the FP entry.
                 */
                retval = opennsl_field_action_delete(
                            unit,
                            *(copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                          ingress_fp_rule_number]),
                            opennslFieldActionCosQCpuNew,
                            copp_packet_class->ops_copp_ingress_fp_queue_number,
                            0);
                if (OPENNSL_FAILURE(retval)) {
                    VLOG_ERR("     Ingress action update failure: %s\n",
                             opennsl_errmsg(retval));
                    return(OPS_COPP_FAILURE_CODE);
                }

                /*
                 * Add the new CPU queue to the FP entry.
                 */
                retval = opennsl_field_action_add(
                            unit,
                            *(copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                           ingress_fp_rule_number]),
                            opennslFieldActionCosQCpuNew,
                            *ingress_fp_queue, 0);
                if (OPENNSL_FAILURE(retval)) {
                    VLOG_ERR("     Ingress:  Failed to add new action = %s\n",
                             opennsl_errmsg(retval));
                    return(OPS_COPP_FAILURE_CODE);
                }

                /*
                 * Install the FP entry into the hardware.
                 */
                retval = opennsl_field_entry_install(
                          unit,
                          *(copp_packet_class->ops_copp_ingress_fp_entry[unit][
                                                        ingress_fp_rule_number]));
                if (OPENNSL_FAILURE(retval)) {
                    VLOG_ERR("     Ingress entry program failure: %s\n",
                             opennsl_errmsg(retval));
                    return(OPS_COPP_FAILURE_CODE);
                }

                ingress_fp_rule_number++;
            }

            /*
             * Need to update the FP entry in the egress as the
             * qualifier in egress uses CPU QoS Queue.
             */
            retval = opennsl_field_qualify_CpuQueue(unit,
                             *(copp_packet_class->ops_copp_egress_fp_entry[unit]),
                             *ingress_fp_queue, 0xff);
            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Egress: Failed to qualify on CPU queue %s\n",
                         opennsl_errmsg(retval));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Install the egress FP entry into the hardware.
             */
            retval = opennsl_field_entry_install(
                        unit,
                        *(copp_packet_class->ops_copp_egress_fp_entry[unit]));
            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Ingress entry program failure: %s\n",
                         opennsl_errmsg(retval));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Copy the new CPU queue value into the configured FP rules.
             */
            copp_packet_class->ops_copp_ingress_fp_queue_number =
                                                    *ingress_fp_queue;

            VLOG_DBG("     Ingress: Successfully reprogrammed the FP rule "
                     "for %s with new CPU queue %u",
                     copp_packet_class->ops_copp_packet_name,
                     *ingress_fp_queue);
        }
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_programmer
 *
 * This function does the following two operations for a given control packet:-
 * 1. If the egress FP entry for the control packet is NULL, then this
 *    function creates a new ingress FP entry and attaches a policier with
 *    the default rate and burst value and a stats object to the egress FP
 *    entry. This is the case at the initialization time when the plugin
 *    gets loaded in vswitchd for the first time.
 * 2. If the egress FP entry for the control packet is not NULL, then this
 *    function updates the rate and the burst in the policier for the control
 *    packet with the rate and burst values passed to this function.
 */
static int ops_copp_egress_fp_programmer (
                               uint32 unit,
                               enum ops_copp_packet_class_code_t packet_class,
                               uint32* egress_fp_rate,
                               uint32* egress_fp_burst)
{
    int32                      retval = -1;
    bool                       if_init_egress_fp_program = false;
    bool                       if_config_egress_fp_program = false;
    struct ops_copp_fp_rule_t* copp_packet_class = NULL;

    /*
     * If the packet class is not valid, then do not do anything and
     * return from this function.
     */
    if ((packet_class < 0) ||
        (packet_class >= PLUGIN_COPP_MAX_CLASSES)) {
        VLOG_ERR("Not a valid packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Get the pointer reference to the control packet rule.
     */
    copp_packet_class = &ops_copp_packet_class_t[packet_class];

    if (!copp_packet_class) {
        VLOG_ERR("Invalid pointer to packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * If the egress FP entry pointer for the control packet is NULL, then
     * we need to allocate a new FP entry and program the hardware.
     */
    if (!(copp_packet_class->ops_copp_egress_fp_entry[unit]) &&
        copp_packet_class->ops_copp_egress_fp_funtion_pointer) {
        if_init_egress_fp_program = true;
    }

    /*
     * If the egress FP entry pointer for the control packet is not NULL,
     * then we need to update the FP entry with the new rate and burst values.
     */
    if (copp_packet_class->ops_copp_egress_fp_entry[unit] && egress_fp_rate
        && egress_fp_burst) {
        if_config_egress_fp_program = true;
    }

    /*
     * If we find that this function is neither called at init time or
     * at rate/burst modification time, then return from this function.
     */
    if (!if_init_egress_fp_program && !if_config_egress_fp_program) {
        VLOG_ERR("Invalid use of the egress function for %s",
                 copp_packet_class->ops_copp_packet_name);
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * If the function is called at the initialization time, then allocate
     * a new FP entry and program the egress pipeline with the FP rule.
     */
    if (if_init_egress_fp_program) {

        VLOG_DBG("Create a new egress FP %s entry with default rate/burst",
                 copp_packet_class->ops_copp_packet_name);

        /*
         * Allocate a new FP egress entry.
         */
        copp_packet_class->ops_copp_egress_fp_entry[unit] =
                                xzalloc(sizeof(opennsl_field_entry_t));

        /*
         * Create a new egress FP entry in the egress group for the
         * given unit.
         */
        retval= opennsl_field_entry_create(
                            unit, ops_copp_egress_fp_group_array[unit],
                            copp_packet_class->ops_copp_egress_fp_entry[unit]);

        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("     Egress: Failed to create entry: %s\n",
                     opennsl_errmsg(retval));
            free(copp_packet_class->ops_copp_egress_fp_entry[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Call the function pointer for programming the FP qualifier for this
         * packet class.
         */
        retval = (*copp_packet_class->ops_copp_egress_fp_funtion_pointer)(unit,
                          copp_packet_class->ops_copp_egress_fp_entry[unit],
                          copp_packet_class->ops_copp_ingress_fp_queue_number);
        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("     Egress: Failed to add FP qualifiers\n");
            ops_copp_fp_entry_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_entry[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Add the action for the egress FP entry to drop the packet if the
         * rate/burst is exceeded for the control packet.
         */
        retval = opennsl_field_action_add(
                     unit,
                     *(copp_packet_class->ops_copp_egress_fp_entry[unit]),
                     opennslFieldActionRpDrop, 0, 0);
        if (retval != OPS_COPP_SUCCESS_CODE) {
            VLOG_ERR("     Egress:  Failed to add action  = %s\n",
                     opennsl_errmsg(retval));
            ops_copp_fp_entry_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_entry[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Allocate a new policer.
         */
        copp_packet_class->ops_copp_egress_fp_policer_id[unit] =
                                            xzalloc(sizeof(opennsl_policer_t));

        if(!(copp_packet_class->ops_copp_egress_fp_policer_id[unit])) {
            VLOG_ERR("      Egress: Unable to allocate memory for policer");
            ops_copp_fp_entry_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_entry[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Create the policier having the default rate/burst.
         */
        retval = ops_copp_create_egress_policer_id(
                       unit,
                       copp_packet_class->ops_copp_egress_fp_policer_id[unit],
                       copp_packet_class->ops_copp_egress_fp_rate,
                       copp_packet_class->ops_copp_egress_fp_burst);
        if (retval != OPS_COPP_SUCCESS_CODE) {
            VLOG_ERR("     Egress policer program failure");
            ops_copp_fp_entry_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_entry[unit]);
            free(copp_packet_class->ops_copp_egress_fp_policer_id[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Attach the policier to the egress FP entry for unicast ARP.
         */
        retval = opennsl_field_entry_policer_attach(
                   unit,
                   *(copp_packet_class->ops_copp_egress_fp_entry[unit]),
                   0,
                   *(copp_packet_class->ops_copp_egress_fp_policer_id[unit]));
        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("     Egress: Failed to attach the action to FP "
                     "entry = %s\n", opennsl_errmsg(retval));
            ops_copp_fp_policer_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_policer_id[unit]);
            ops_copp_fp_entry_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_entry[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        copp_packet_class->ops_copp_egress_fp_stat_id[unit] =
                                                        xzalloc(sizeof(int));

        if (!(copp_packet_class->ops_copp_egress_fp_stat_id[unit])) {
            VLOG_ERR("     Egress: Unable to allocate for stat id");
            ops_copp_fp_policer_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_policer_id[unit]);
            ops_copp_fp_entry_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_entry[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Create the stats object to count the number of control packets
         * dropped from being pushed to CPU or sent to CPU from the egress
         * pipeline.
         */
        retval = ops_copp_create_egress_stat_id(
                    unit, copp_packet_class->ops_copp_egress_fp_stat_id[unit]);
        if (retval != OPS_COPP_SUCCESS_CODE) {
            VLOG_ERR("     Egress stat object program failure");
            ops_copp_fp_policer_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_policer_id[unit]);
            ops_copp_fp_entry_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_entry[unit]);
            free(copp_packet_class->ops_copp_egress_fp_stat_id[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Attach the stats object to the egress FP entry
         */
        retval = opennsl_field_entry_stat_attach(
                      unit,
                      *(copp_packet_class->ops_copp_egress_fp_entry[unit]),
                      *(copp_packet_class->ops_copp_egress_fp_stat_id[unit]));
        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("     Egress: Failed to attach the stats object "
                     "to FP entry = %s\n", opennsl_errmsg(retval));
            ops_copp_fp_policer_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_policer_id[unit]);
            ops_copp_fp_statid_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_stat_id[unit]);
            ops_copp_fp_entry_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_entry[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Install the FP entry into the hardware.
         */
        retval = opennsl_field_entry_install(
                   unit, *(copp_packet_class->ops_copp_egress_fp_entry[unit]));
        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("     Egress entry program failure: %s\n",
                     opennsl_errmsg(retval));
            ops_copp_fp_policer_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_policer_id[unit]);
            ops_copp_fp_statid_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_stat_id[unit]);
            ops_copp_fp_entry_cleanup(unit,
                    copp_packet_class->ops_copp_egress_fp_entry[unit]);
            return(OPS_COPP_FAILURE_CODE);
        }

        VLOG_DBG("     Egress: Successfully programmed the FP rule "
                 "for %s", copp_packet_class->ops_copp_packet_name);
    }

    /*
     * If the function is called at the configuration time, then detach
     * the egress policier and attach a new policier having the new rate
     * and burst values.
     */
    if (if_config_egress_fp_program) {
        if ((copp_packet_class->ops_copp_egress_fp_rate == *egress_fp_rate)
            && (copp_packet_class->ops_copp_egress_fp_burst
                                                    == *egress_fp_burst)) {

            /*
             * If the new rate and burst values are same as the already
             * configured values, then do nothing and return from this
             * function.
             */
            VLOG_DBG("     Egress: The current rate/burst %u/%u is same new "
                     " intended rate/burst %u/%u for %s",
                     copp_packet_class->ops_copp_egress_fp_rate,
                     copp_packet_class->ops_copp_egress_fp_burst,
                     *egress_fp_rate, *egress_fp_burst,
                     copp_packet_class->ops_copp_packet_name);
        } else {

            /*
             * Detach the current policier from the egress FP entry.
             */
            retval = opennsl_field_entry_policer_detach(
                         unit,
                         *(copp_packet_class->ops_copp_egress_fp_entry[unit]),
                         0);
            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Egress: policy detach failed: %s\n",
                         opennsl_errmsg(retval));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Install the FP entry into the hardware to detach the policer
             * completely from the egress FP entry.
             */
            retval = opennsl_field_entry_install(
                       unit,
                       *(copp_packet_class->ops_copp_egress_fp_entry[unit]));
            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Egress entry reprogram failure: %s\n",
                        opennsl_errmsg(retval));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Destroy the policer and free hardware resources.
             */
            retval = opennsl_policer_destroy(unit,
                        *(copp_packet_class->ops_copp_egress_fp_policer_id[unit]));
            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Egress policer destroy failure: %s\n",
                        opennsl_errmsg(retval));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Create a new policier with the new rate/burst values.
             */
            retval = ops_copp_create_egress_policer_id(
                         unit,
                         copp_packet_class->ops_copp_egress_fp_policer_id[unit],
                         *egress_fp_rate,
                         *egress_fp_burst);
            if (retval != OPS_COPP_SUCCESS_CODE) {
                VLOG_ERR("     Egress policer update failure: %s\n",
                        opennsl_errmsg(retval));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Attach the new policier from the FP entry.
             * Install the FP entry into the hardware.
             */
            retval = opennsl_field_entry_policer_attach(
                     unit,
                     *(copp_packet_class->ops_copp_egress_fp_entry[unit]),
                     0,
                     *(copp_packet_class->ops_copp_egress_fp_policer_id[unit]));
            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Egress: Failure to attach a new policer to "
                         "the FP entry = %s\n", opennsl_errmsg(retval));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Install the FP entry into the hardware.
             */
            retval = opennsl_field_entry_install(
                       unit,
                       *(copp_packet_class->ops_copp_egress_fp_entry[unit]));
            if (OPENNSL_FAILURE(retval)) {
                VLOG_ERR("     Egress entry reprogram failure: %s\n",
                        opennsl_errmsg(retval));
                return(OPS_COPP_FAILURE_CODE);
            }

            VLOG_DBG("     Egress: Successfully updated rate/burst %u/%u "
                     "to new rate/burst %u/%u for %s",
                     copp_packet_class->ops_copp_egress_fp_rate,
                     copp_packet_class->ops_copp_egress_fp_burst,
                     *egress_fp_rate, *egress_fp_burst,
                     copp_packet_class->ops_copp_packet_name);

            /*
             * Copy the new rates/burst into the configured FP rules.
             */
            copp_packet_class->ops_copp_egress_fp_rate = *egress_fp_rate;
            copp_packet_class->ops_copp_egress_fp_burst = *egress_fp_burst;
        }
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_ingress_fp_group_create
 *
 * This function forms group for CoPP FP rules in ingress pipeline on all the
 * available hardware units. This function sets the qualifiers needed in the
 * CoPP group and then iterates over all the hardware units to create the CoPP
 * group ids.
 */
static int ops_copp_ingress_fp_group_create ()
{
    opennsl_field_qset_t       OpennslFPQualSetIngress;
    int32                      retval = -1;
    int                        unit_iterator;

    OPENNSL_FIELD_QSET_INIT(OpennslFPQualSetIngress);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyStageIngress);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyEtherType);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyPacketRes);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyL4DstPort);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyL4SrcPort);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyIpProtocol);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyDstIpLocal);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyDstIp);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyIp6NextHeader);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyIpType);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyDstMac);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetIngress,
                                    opennslFieldQualifyDstIp6);

    /*
     * Iterate over all the units and create the ingress FP groups
     */
    for (unit_iterator = 0; unit_iterator < OPS_COPP_MAX_UNITS;
                                                ++unit_iterator) {
        retval = opennsl_field_group_create(
                                unit_iterator, OpennslFPQualSetIngress,
                                FP_GROUP_PRIORITY_2,
                                &ops_copp_ingress_fp_group_array[
                                                        unit_iterator]);

        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("\nIngress group create failed : %s\n",
                     opennsl_errmsg(retval));
            return(OPS_COPP_FAILURE_CODE);
        }
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_egress_fp_group_create
 *
 * This function forms group for CoPP FP rules in egress pipeline on all the
 * available hardware units. This function sets the qualifiers needed in the
 * CoPP group and then iterates over all the hardware units to create the CoPP
 * group ids.
 */
static int ops_copp_egress_fp_group_create ()
{
    opennsl_field_qset_t       OpennslFPQualSetEgress;
    int32                      retval = -1;
    int                        unit_iterator;

    OPENNSL_FIELD_QSET_INIT(OpennslFPQualSetEgress);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyStageEgress);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyEtherType);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyOutPort);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyL4DstPort);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyIpProtocol);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyCpuQueue);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyDstMac);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyIp6NextHeader);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyIpType);
    OPENNSL_FIELD_QSET_ADD(OpennslFPQualSetEgress,
                                        opennslFieldQualifyDstIp);

    /*
     * Iterate over all the units and create the egress FP groups
     */
    for (unit_iterator = 0; unit_iterator < OPS_COPP_MAX_UNITS;
                                                    ++unit_iterator) {
        retval = opennsl_field_group_create(
                                    unit_iterator, OpennslFPQualSetEgress,
                                    FP_GROUP_PRIORITY_2,
                                    &ops_copp_egress_fp_group_array[
                                                            unit_iterator]);

        if (OPENNSL_FAILURE(retval)) {
            VLOG_ERR("\nEgress group create failed : %s\n",
                     opennsl_errmsg(retval));
            return(OPS_COPP_FAILURE_CODE);
        }
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_program_fp_defaults
 *
 * This function iterates over all the hardware units and all the FP
 * rules for CoPP feature and programs the FP rule entries in the ingress
 * and egress pipelines with the default values.
 */
static int ops_copp_program_fp_defaults ()
{
    int32                  retval = -1;
    int                    unit_iterator;
    int                    fp_rule_iterator;

    /*
     * Iterate over all the hardware units
     */
    for (unit_iterator = 0; unit_iterator < OPS_COPP_MAX_UNITS;
                                                        ++unit_iterator) {

        /*
         * Iterate over all the FP rules for control packets and program
         * ingress and egress FP entries.
         */
        for (fp_rule_iterator = 0; fp_rule_iterator < PLUGIN_COPP_MAX_CLASSES;
             ++fp_rule_iterator) {

            /*
             * Program the control packet class rules for some
             * control plane packets.
             */
            retval = ops_copp_packet_class_programmer(
                       unit_iterator, fp_rule_iterator);

            if (retval != OPS_COPP_SUCCESS_CODE) {
                VLOG_ERR("Packet class rule create failed");
                log_event("COPP_CLASS_PACKET_RULE_FAILURE",
                           EV_KV("class", "%s",
                           (ops_copp_packet_class_t[fp_rule_iterator])
                           .ops_copp_packet_name));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Program the ingress FP entry with default values.
             */
            retval = ops_copp_ingress_fp_programmer(
                       unit_iterator, fp_rule_iterator, NULL);

            if (retval != OPS_COPP_SUCCESS_CODE) {
                VLOG_ERR("Ingress FP rule create failed");
                log_event("COPP_CLASS_INGRESS_FP_CREATE_FAILURE",
                           EV_KV("class", "%s",
                           (ops_copp_packet_class_t[fp_rule_iterator])
                           .ops_copp_packet_name));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Program the egress FP entry with default values.
             */
            retval = ops_copp_egress_fp_programmer(
                       unit_iterator, fp_rule_iterator, NULL, NULL);

            if (retval != OPS_COPP_SUCCESS_CODE) {
                VLOG_ERR("Egress FP rule create failed");
                log_event("COPP_CLASS_EGRESS_FP_CREATE_FAILURE",
                           EV_KV("class", "%s",
                           (ops_copp_packet_class_t[fp_rule_iterator])
                           .ops_copp_packet_name));
                return(OPS_COPP_FAILURE_CODE);
            }

            /*
             * Set the hardware status in the fp rule structure as valid (true)
             */
            retval = ops_copp_packet_class_set_status(
                       unit_iterator, fp_rule_iterator, true);
            if (retval != OPS_COPP_SUCCESS_CODE) {
                VLOG_ERR("Valid status set for  FP rule create failed");
                return(OPS_COPP_FAILURE_CODE);
            }
        }
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * ops_copp_set_packet_class_config
 *
 * This function sets the CPU queue, rate and burst configuration for a
 * packet class in ingress and egress pipelines.
 */
static int ops_copp_set_packet_class_config
                                (struct ops_copp_config_t* copp_config)
{
    int                        retval;
    int                        unit_iterator;

    /*
     * If the config object is not valid, then return error
     */
    if (!copp_config) {
        VLOG_ERR("Invalid structure passed for setting CoPP configuration");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * If the packet class is not valid, then do not do anything and
     * return from this function.
     */
    if ((copp_config->ops_copp_packet_class < 0) ||
        (copp_config->ops_copp_packet_class >= PLUGIN_COPP_MAX_CLASSES)) {
        VLOG_ERR("Not a valid packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    for (unit_iterator = 0; unit_iterator < OPS_COPP_MAX_UNITS;
                                                        ++unit_iterator) {
        /*
         * Reprogram the ingress FP entry with new CPU queue values.
         */
        retval = ops_copp_ingress_fp_programmer(
                        unit_iterator,
                        copp_config->ops_copp_packet_class,
                        &(copp_config->ops_copp_queue_number));

        if (retval != OPS_COPP_SUCCESS_CODE) {
            VLOG_ERR("Ingress FP rule reprogram failed");
            return(OPS_COPP_FAILURE_CODE);
        }

        /*
         * Reprogram the ingress FP entry with new rate and burst values.
         */
        retval = ops_copp_egress_fp_programmer(
                        unit_iterator,
                        copp_config->ops_copp_packet_class,
                        &(copp_config->ops_copp_rate),
                        &(copp_config->ops_copp_burst));

        if (retval != OPS_COPP_SUCCESS_CODE) {
            VLOG_ERR("Egress FP rule reprogram failed");
            return(OPS_COPP_FAILURE_CODE);
        }
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * set_copp_policy
 *
 * This function configures the various control plane packets
 * with the user defined values of CPU queue, rate and burst.
 */
int set_copp_policy (uint32 num_packets_classes,
                     struct ops_copp_config_t* copp_config_array)
{
    int                        index;
    int                        retval = 0;

    if (!copp_config_array) {
        VLOG_ERR("Invalid CoPP packet config array");
        return(OPS_COPP_FAILURE_CODE);
    }

    for (index = 0; index < num_packets_classes; ++index) {

        retval |= ops_copp_set_packet_class_config(&(copp_config_array[index]));
        if (retval != OPS_COPP_SUCCESS_CODE) {
            VLOG_ERR("     Egress: Failed to set copp config = %s\n",
                     opennsl_errmsg(retval));
        }
    }

    return(retval);
}

/*
 * ops_copp_get_packet_class_stats
 *
 * The function fills the CoPP stats for that control plane packet.
 */
static int ops_copp_get_packet_class_stats
                              (struct ops_copp_stats_t* copp_stats)
{
    struct ops_copp_fp_rule_t*          copp_packet_class;
    uint64                              number_green_packets;
    uint64                              number_green_bytes;
    uint64                              number_red_packets;
    uint64                              number_red_bytes;
    int                                 retval;
    uint32                              unit;
    enum ops_copp_packet_class_code_t   packet_class;

    /*
     * If the stats objects is not valid, then return error
     */
    if (!copp_stats) {
        VLOG_ERR("Invalid structure passed for fetching CoPP stats");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * If the hardware unit is greater to equal to the maximum
     * number hardware units, then return failure.
     */
    if (copp_stats->ops_copp_hardware_unit_number >=
                                        OPS_COPP_MAX_UNITS) {
        VLOG_ERR("Not a valid hardware unit number");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * If the packet class is not valid, then do not do anything and
     * return from this function.
     */
    if ((copp_stats->ops_copp_packet_class < 0) ||
        (copp_stats->ops_copp_packet_class >= PLUGIN_COPP_MAX_CLASSES)) {
        VLOG_ERR("Not a valid packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    unit = copp_stats->ops_copp_hardware_unit_number;
    packet_class = copp_stats->ops_copp_packet_class;

    /*
     * Get the pointer reference to the control packet rule.
     */
    copp_packet_class = &ops_copp_packet_class_t[packet_class];

    if (!copp_packet_class ||
        !(copp_packet_class->ops_copp_egress_fp_stat_id[unit])) {
        VLOG_ERR("Invalid pointer to packet class");
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Get the number of green packets for this control packet class
     */
    retval = opennsl_field_stat_get(
                 unit,
                 *(copp_packet_class->ops_copp_egress_fp_stat_id[unit]),
                 opennslFieldStatGreenPackets,
                 &number_green_packets);

    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to get green packets stats = %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Get the number of green bytes for this control packet class
     */
    retval = opennsl_field_stat_get(
                 unit,
                 *(copp_packet_class->ops_copp_egress_fp_stat_id[unit]),
                 opennslFieldStatGreenBytes,
                 &number_green_bytes);

    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to get green bytes stats = %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Get the number of red packets for this control packet class
     */
    retval = opennsl_field_stat_get(
                 unit,
                 *(copp_packet_class->ops_copp_egress_fp_stat_id[unit]),
                 opennslFieldStatRedPackets,
                 &number_red_packets);

    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to get red packets stats = %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Get the number of red bytes for this control packet class
     */
    retval = opennsl_field_stat_get(
                 unit,
                 *(copp_packet_class->ops_copp_egress_fp_stat_id[unit]),
                 opennslFieldStatRedBytes,
                 &number_red_bytes);

    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("     Egress: Failed to get red bytes stats = %s\n",
                 opennsl_errmsg(retval));
        return(OPS_COPP_FAILURE_CODE);
    }

    /*
     * Populate the stats object with the stat values
     */
    copp_stats->ops_copp_packets_allowed = number_green_packets;
    copp_stats->ops_copp_bytes_allowed = number_green_bytes;
    copp_stats->ops_copp_packets_dropped = number_red_packets;
    copp_stats->ops_copp_bytes_dropped = number_red_bytes;

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * get_copp_counts
 *
 * This function gets the CoPP stats for the various control
 * plane packet classes and updates the stats in the copp_stats
 * array.
 */
int get_copp_counts (uint32 num_packets_classes,
                     struct ops_copp_stats_t* copp_stats_array)
{
    int                        index;
    int                        retval;

    if (!copp_stats_array) {
        VLOG_ERR("Invalid CoPP packet stats array");
        return(OPS_COPP_FAILURE_CODE);
    }

    for (index = 0; index < num_packets_classes; ++index) {

        retval = ops_copp_get_packet_class_stats(&(copp_stats_array[index]));
        if (retval != OPS_COPP_SUCCESS_CODE) {
            VLOG_ERR("     Egress: Failed to get copp stats = %s\n",
                     opennsl_errmsg(retval));
            continue;
        }
    }

    return(OPS_COPP_SUCCESS_CODE);
}

/*
 * copp_packet_class_mapper
 *
 * This function takes in the ops packet class as the input and converts it to
 * the copp packet class enum
 */
static
enum ops_copp_packet_class_code_t
copp_packet_class_mapper(enum copp_protocol_class ops_class)
{
    switch(ops_class) {
        case COPP_ACL_LOGGING:
            return PLUGIN_COPP_ACL_LOGGING_PACKET;
        case COPP_ARP_BROADCAST:
            return PLUGIN_COPP_BROADCAST_ARP_PACKET;
        case COPP_ARP_MY_UNICAST:
            return PLUGIN_COPP_UNICAST_ARP_PACKET;
        case COPP_BGP:
            return PLUGIN_COPP_BGP_PACKET;
        case COPP_DEFAULT_UNKNOWN:
            return PLUGIN_COPP_UNCLASSIFIED_PACKET;
        case COPP_DHCPv4:
            return PLUGIN_COPP_DHCPV4_PACKET;
        case COPP_DHCPv6:
            return PLUGIN_COPP_DHCPV6_PACKET;
        case COPP_ICMPv4_MULTIDEST:
            return PLUGIN_COPP_ICMPV4_BMCAST_PACKET;
        case COPP_ICMPv4_UNICAST:
            return PLUGIN_COPP_ICMPV4_UCAST_PACKET;
        case COPP_ICMPv6_MULTICAST:
            return PLUGIN_COPP_ICMPV6_MCAST_PACKET;
        case COPP_ICMPv6_UNICAST:
            return PLUGIN_COPP_ICMPV6_UCAST_PACKET;
        case COPP_LACP:
            return PLUGIN_COPP_LACP_PACKET;
        case COPP_LLDP:
            return PLUGIN_COPP_LLDP_PACKET;
        case COPP_OSPFv2_MULTICAST:
            return PLUGIN_COPP_OSPFV2_MCAST_PACKET;
        case COPP_OSPFv2_UNICAST:
            return PLUGIN_COPP_OSPFV2_UCAST_PACKET;
        case COPP_sFLOW_SAMPLES:
            return PLUGIN_COPP_SFLOW_PACKET;
        case COPP_STP_BPDU:
            return PLUGIN_COPP_STP_PACKET;
        case COPP_UNKNOWN_IP_UNICAST:
            return PLUGIN_COPP_UNKNOWN_IP_UNICAST_PACKET;
        case COPP_IPv4_OPTIONS:
            return PLUGIN_COPP_IPV4_OPTIONS_PACKET;
        case COPP_IPv6_OPTIONS:
            return PLUGIN_COPP_IPV6_OPTIONS_PACKET;
        default:
            return PLUGIN_COPP_MAX_CLASSES;
    }
}

/*
 * copp_opennsl_stats_get
 *
 * This is the implementaion of the function interfacing with switchd,
 * which is polled every 5000 ms by switchd. This function returns the
 * statistics corresponding to a particular protocol.
 */
int copp_opennsl_stats_get(const unsigned int hw_asic_id,
                   const enum copp_protocol_class class,
                   struct copp_protocol_stats *const stats)
{
    int    retval;
    enum   ops_copp_packet_class_code_t mapped_packet_class;
    struct ops_copp_stats_t copp_stats_array;

    /* Check for stats pointer passed not being NULL */
    if (stats == NULL) {
        VLOG_ERR("Stats pointer passed to function is NULL");
        return EINVAL;
    }

    /* Map the incoming enum to our copp class enum */
    mapped_packet_class = copp_packet_class_mapper(class);
    if (mapped_packet_class == PLUGIN_COPP_MAX_CLASSES) {
        VLOG_DBG("CoPP packet class %d not supported.\n", mapped_packet_class);
        return EOPNOTSUPP;
    }

    copp_stats_array.ops_copp_packet_class = mapped_packet_class;
    copp_stats_array.ops_copp_hardware_unit_number = hw_asic_id;

    /*
     * After the above 2 fields are filled, pass it to the get_copp_counts.
     * The number of copp classes passed is just one.
     */
    retval = get_copp_counts(1, &copp_stats_array);
    if (retval != OPS_COPP_SUCCESS_CODE) {
        VLOG_ERR("Error getting stats for hardware unit %u", hw_asic_id);
        return EIO;
    }

    /* Fill in the 4 stats field in the stats pointer */
    stats->packets_passed = copp_stats_array.ops_copp_packets_allowed;
    stats->bytes_passed = copp_stats_array.ops_copp_bytes_allowed;
    stats->packets_dropped = copp_stats_array.ops_copp_packets_dropped;
    stats->bytes_dropped = copp_stats_array.ops_copp_bytes_dropped;

    return 0;
}

/*
 * copp_opennsl_hw_status_get
 *
 * This is the implementaion of the function interfacing with switchd,
 * which is polled every 5000 ms by switchd. This function returns the
 * hw_status info like rate,burst, local_priority corresponding to a particular
 * protocol.
 */
int copp_opennsl_hw_status_get(const unsigned int hw_asic_id,
                       const enum copp_protocol_class class,
                       struct copp_hw_status *const hw_status)
{
    enum   ops_copp_packet_class_code_t mapped_packet_class;

    /* Check for stats pointer passed not being NULL */
    if (hw_status == NULL) {
        VLOG_ERR("Hardware status pointer passed to function is NULL");
        return EINVAL;
    }

    /* Map the incoming enum to our copp class enum */
    mapped_packet_class = copp_packet_class_mapper(class);
    if (mapped_packet_class == PLUGIN_COPP_MAX_CLASSES) {
        VLOG_ERR("CoPP packet class %d not supported.\n", mapped_packet_class);
        return EOPNOTSUPP;
    }

    /*
     * Check for error condition.
     * if the packet_class struct has egress or ingress fp as NULL ptr,
     * it means that, the configuration has not gone througgh fine.
     */
    if (ops_copp_packet_class_t[mapped_packet_class].status[hw_asic_id]
        == false) {
        VLOG_ERR("Error getting hw status for hardware unit %u", hw_asic_id);
        return EIO;
    }

    hw_status->rate =
          ops_copp_packet_class_t[mapped_packet_class].ops_copp_egress_fp_rate;
    hw_status->burst =
          ops_copp_packet_class_t[mapped_packet_class].ops_copp_egress_fp_burst;
    hw_status->local_priority =
          ops_copp_packet_class_t[mapped_packet_class].ops_copp_ingress_fp_queue_number;

    return 0;
}

/*
 * ops_copp_packet_stats_to_string
 *
 * This function prepares a buffer with the packet statistics
 * for a given control plane packet class. The CoPP stat values are
 * read from the structure ops_copp_stats_t which is passed to this
 * function. The control plane packet stats are populated in the buffer
 * passed to this function.
 */
static int ops_copp_packet_stats_to_string (
                                     struct ops_copp_stats_t copp_stats,
                                     char* ops_copp_packet_stat_buffer,
                                     uint32 bytes_already_written,
                                     uint32 max_length)
{
    int                        bytes_written;

    /*
     * Test for error conditions
     */
    if (!ops_copp_packet_stat_buffer || !max_length ||
        (bytes_already_written >= max_length)) {
        return(0);
    }

    /*
     * Zero out the buffer for the per control plane packet class.
     */
    memset(ops_copp_packet_stat_buffer + bytes_already_written, 0,
           max_length - bytes_already_written);

    /*
     * The following details are entered into the per control plane packet
     * buffer.
     * 1. Stats
     *   a. Packets allowed and bytes allowed
     *   b. Packets dropped and bytes dropped
     */
    bytes_written = snprintf(
                        ops_copp_packet_stat_buffer + bytes_already_written,
                        max_length - bytes_already_written,
                        "\tPacket Statistics:\n"
                        "\t\tPackets Allowed: %10llu\tBytes Allowed: %10llu\n"
                        "\t\tPackets Dropped: %10llu\tBytes Dropped: %10llu\n\n",
                        copp_stats.ops_copp_packets_allowed,
                        copp_stats.ops_copp_bytes_allowed,
                        copp_stats.ops_copp_packets_dropped,
                        copp_stats.ops_copp_bytes_dropped);

    /*
     * Return the number of bytes written into the per control plane packet
     * buffer.
     */
    return(bytes_written);
}

/*
 * ops_copp_packet_config_to_string
 *
 * This function prepares a buffer with the control packet configuration
 * values for a given control plane packet class. The CoPP configuration
 * values are read from the structure ops_copp_fp_rule_t which is passed to
 * this function. The control plane configuration values are populated in the
 * buffer passed to this function.
 */
static int ops_copp_packet_config_to_string (
                                      struct ops_copp_fp_rule_t copp_fp_rule,
                                      char* ops_copp_packet_stat_buffer,
                                      uint32 bytes_already_written,
                                      uint32 max_length)
{
    int                        bytes_written;
    char*                      cpu_queue_name;

    /*
     * Test for error conditions
     */
    if (!ops_copp_packet_stat_buffer || !max_length ||
        (bytes_already_written >= max_length)) {
        return(0);
    }

    /*
     * Zero out the buffer for the per control plane packet class.
     */
    memset(ops_copp_packet_stat_buffer + bytes_already_written, 0,
           max_length - bytes_already_written);

    /*
     * The following details are entered into the per control plane packet
     * buffer.
     * 1. Configuration
     *   a. CPU QoS queue number
     *   b. Packet rate in pps units
     *   c. Packet Burst in packet units
     */
    cpu_queue_name = ops_copp_get_name_from_cpu_queue_number(
                            copp_fp_rule.ops_copp_ingress_fp_queue_number);
    bytes_written = snprintf(
                        ops_copp_packet_stat_buffer + bytes_already_written,
                        max_length - bytes_already_written,
                        "Control Plane Packet: %s\n"
                        "\tConfiguration:\n"
                        "\t\tCPU QoS queue: %s (%u)\n"
                        "\t\tRate: %u pps\n"
                        "\t\tBurst: %u packets\n",
                        copp_fp_rule.ops_copp_packet_name,
                        cpu_queue_name ? cpu_queue_name : "NULL",
                        copp_fp_rule.ops_copp_ingress_fp_queue_number,
                        copp_fp_rule.ops_copp_egress_fp_rate,
                        copp_fp_rule.ops_copp_egress_fp_burst);

    /*
     * Return the number of bytes written into the per control plane packet
     * buffer.
     */
    return(bytes_written);

}

/*
 * ops_get_all_packet_stats
 *
 * This function iterates over all the hardware units and prepares a buffer with
 * the configuration parameters and packet statistics for each control
 * plane packet class.
 */
int ops_get_all_packet_stats ()
{
    int                         unit_iterator;
    int                         fp_rule_iterator;
    int                         total_bytes_written;
    int                         packet_class_config_bytes_written;
    int                         packet_class_stats_bytes_written;
    int                         maximum_bytes_available;
    int                         retval;
    struct ops_copp_stats_t     copp_stats[PLUGIN_COPP_MAX_CLASSES];

    maximum_bytes_available = COPP_MAX_PACKET_STAT_BUFFER_SIZE
                                            * PLUGIN_COPP_MAX_CLASSES;

    /*
     * Zero out the global buffer that will contain all the output for
     * copp stats.
     */
    memset(ops_copp_all_packet_stat_buffer, 0, maximum_bytes_available);

    /*
     * Iterate over all the hardware units
     */
    total_bytes_written = 0;
    for (unit_iterator = 0; unit_iterator < OPS_COPP_MAX_UNITS;
                                                        ++unit_iterator) {

        /*
         * Zero out copp_stats array
         */
        memset(copp_stats, 0, PLUGIN_COPP_MAX_CLASSES *
                                      sizeof(struct ops_copp_stats_t));

        /*
         * Add the hardware unit number into the buffer.
         */
        total_bytes_written += snprintf(
                                 ops_copp_all_packet_stat_buffer,
                                 maximum_bytes_available,
                                 "\nHardware Unit: %u\n\n",
                                 unit_iterator);

        /*
         * Populate the copp_stats array with the hardware unit and the
         * CoPP packet class rule to fetch the CoPP stats.
         */
        for (fp_rule_iterator = 0; fp_rule_iterator < PLUGIN_COPP_MAX_CLASSES;
             ++fp_rule_iterator) {
            copp_stats[fp_rule_iterator].ops_copp_hardware_unit_number =
                                                                unit_iterator;
            copp_stats[fp_rule_iterator].ops_copp_packet_class =
                                                             fp_rule_iterator;
        }

        /*
         * Get CoPP stats for all CoPP control packet classes
         */
        retval = get_copp_counts(PLUGIN_COPP_MAX_CLASSES,
                                 copp_stats);
        if (retval != OPS_COPP_SUCCESS_CODE) {
            VLOG_ERR("Error getting stats for hardware unit %u", unit_iterator);
            continue;
        }

        /*
         * Iterate over all the FP rules for control packets and printall
         * the configuration and statistics into the global buffer
         */
        for (fp_rule_iterator = 0; fp_rule_iterator < PLUGIN_COPP_MAX_CLASSES;
             ++fp_rule_iterator) {

            /*
             * Get the per control plane packet class configuration details
             */
            packet_class_config_bytes_written =
                        ops_copp_packet_config_to_string(
                                 ops_copp_packet_class_t[fp_rule_iterator],
                                 ops_copp_all_packet_stat_buffer,
                                 total_bytes_written,
                                 maximum_bytes_available);

            /*
             * If some data was written for the  control packet class, then
             * update the total_bytes_written with the number of bytes written
             * into the global buffer.
             */
            if (packet_class_config_bytes_written > 0) {
                total_bytes_written += packet_class_config_bytes_written;
            }

            /*
             * Get the per control plane packet class packet stats.
             */
            packet_class_stats_bytes_written =
                        ops_copp_packet_stats_to_string(
                                      copp_stats[fp_rule_iterator],
                                      ops_copp_all_packet_stat_buffer,
                                      total_bytes_written,
                                      maximum_bytes_available);

            /*
             * If some data was written for the  control packet class, then
             * update the total_bytes_written with the number of bytes written
             * into the global buffer.
             */
            if (packet_class_stats_bytes_written > 0) {
                total_bytes_written += packet_class_stats_bytes_written;
            }
        }
    }

    /*
     * Return the total number of bytes written into the global buffer.
     */
    return(total_bytes_written);
}

/*
 * ops_copp_init
 *
 * This function does the CoPP intitalization in the opennsl plugin. This
 * function should be called at the init time.
 */
int ops_copp_init ()
{
    int retval = 0;

    if(event_log_init("COPP") < 0) {
        VLOG_ERR("Event log initialization failed for COPP");
    }

    if (ops_copp_ingress_fp_group_create() != OPS_COPP_SUCCESS_CODE) {
        VLOG_ERR("Ingress: Group create failed");
        log_event("COPP_INGRESS_FP_GROUP_CREATE_FAILURE", NULL);
        return(OPS_COPP_FAILURE_CODE);
    }

    if (ops_copp_egress_fp_group_create() != OPS_COPP_SUCCESS_CODE) {
        VLOG_ERR("Egress: Group create failed");
        log_event("COPP_EGRESS_FP_GROUP_CREATE_FAILURE", NULL);
        return(OPS_COPP_FAILURE_CODE);
    }

    if (ops_copp_program_fp_defaults() != OPS_COPP_SUCCESS_CODE) {
        VLOG_ERR("Programming of FP rules failed");
        log_event("COPP_INIT_DEFAULTS_FAILURE", NULL);
        return(OPS_COPP_FAILURE_CODE);
    }

    VLOG_INFO("OPS CoPP init successful");
    log_event("COPP_INITIALIZATION_SUCCESS", NULL);

    return(retval);
}
