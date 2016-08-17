/* Copyright (C) 2015. 2016 Hewlett Packard Enterprise Development LP
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

/* Purpose: This file contains code to enable routing related functionality
 * in the Broadcom ASIC.
 */

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <util.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/switch.h>
#include <opennsl/vlan.h>
#include <opennsl/l3.h>
#include <opennsl/l2.h>
#include <ofproto/ofproto.h>
#include "ops-routing.h"
#include "ops-stats.h"
#include "ops-debug.h"
#include "ops-vlan.h"
#include "ops-knet.h"
#include "platform-defines.h"
#include "openswitch-dflt.h"
#include "netdev-bcmsdk.h"
#include <opennsl/stat.h>
#include "netdev.h"
#include "eventlog.h"
#include "ops-fp.h"
#include "ops-pbmp.h"

VLOG_DEFINE_THIS_MODULE(ops_routing);
/* ecmp resiliency flag */
bool ecmp_resilient_flag = false;

#define VLAN_ID_MAX_LENGTH   5
#define ECMP_ID_MAX_LENGTH 128
static opennsl_error_t
ops_subinterface_fp_entry_create(opennsl_port_t hw_port, int hw_unit);

struct ops_l3_subintf_fp_info subintf_fp_grp_info[MAX_SWITCH_UNITS];
static int
ops_update_l3ecmp_egress_resilient(int unit, opennsl_l3_egress_ecmp_t *ecmp,
                 int intf_count, opennsl_if_t *egress_obj, void *user_data);

static opennsl_error_t
ops_update_subint_fp_entry(int hw_unit, opennsl_port_t hw_port, bool add);

static opennsl_error_t
ops_destroy_l3_subintf_fp_entry(int hw_unit, opennsl_field_entry_t entryid);

opennsl_if_t local_nhid;
/* fake MAC to create a local_nhid */
opennsl_mac_t LOCAL_MAC =  {0x0,0x0,0x01,0x02,0x03,0x04};

/* KEY in ops_mac_move_egress_id_map */
char    egress_id_key[24];
struct hmap ops_mac_move_egress_id_map;
struct hmap ops_hmap_switch_macs;

/* all routes in asic*/
struct ops_route_table {
   struct hmap routes;
};
struct ops_route_table ops_rtable;

/* ecmp egress hashmap*/
struct hmap ecmp_egress_nexthops_map;

/* Profile id for ip-options */
int default_ip4_options_profile_id = 1;

/* Global Structure that stores OSPF related data */
static ops_ospf_data_t *ospf_data = NULL;

/* Internal default route needed for ALPM mode */
static opennsl_l3_route_t ipv4_default_route;
static opennsl_l3_route_t ipv6_default_route;

/* List of internal VLANs */
struct shash internal_vlans;
static int
ops_delete_ecmp_object(int hw_unit, opennsl_if_t ecmp_intf);


struct ecmp_egress_info {
    struct hmap_node node;   /* ecmp egress value */
    int ref_count;           /* reference count */
    int hw_unit;             /* hw_unit */
    opennsl_if_t ecmp_grpid; /* ecmp egress ID */
};

/* ops_routing_is_internal_vlan
 *
 * This function checks if the vlan is an internal VLAN.
 */
bool
ops_routing_is_internal_vlan (opennsl_vlan_t vlan)
{
    char vlan_str[VLAN_ID_MAX_LENGTH];
    snprintf(vlan_str, VLAN_ID_MAX_LENGTH, "%d", vlan);

    if (shash_find(&internal_vlans, vlan_str)) {
        return true;
    }
    return false;
}

/*
 * ops_routing_get_ospf_group_id_by_hw_unit
 *
 * This function returns the group-id for the OSPF ingress FP rules for
 * the given hardware unit.
 */
opennsl_field_group_t
ops_routing_get_ospf_group_id_by_hw_unit (int unit)
{
    if (!ospf_data) {
        return(-1);
    }

    return(ospf_data->ospf_group_id);
}


/* This function is used to add an OSPF field entry.
 * There are two entries in OSPF distinguished using the
 * 'designatedRouter' parameter:
 *   1. All OSPF Routers   (224.0.0.5)
 *   2. Designated Routers (224.0.0.6)
 *   This function also attaches stat entries to the FPs.
 *
 * TODO: See TODO for ops_routing_ospf_init()
 */
static int
ops_routing_create_ospf_field_entry(int unit, bool designatedRouter)
{
    opennsl_field_entry_t      fieldEntry;
    int                        stat_id;
    int                        retval = -1;
    opennsl_field_stat_t       stat_arr[] = {opennslFieldStatPackets};
    char                       *ospf_packet_rule = designatedRouter ?
                                                   "OSPF:DesignatedRouters" :
                                                   "OSPF:AllRouters";

    /* OSPF constants used for programming FPs */
    opennsl_mac_t  OSPF_MAC_ALL_ROUTERS = {0x01,0x00,0x5E,0x00,0x00,0x05};
    opennsl_mac_t  OSPF_MAC_DESIGNATED_ROUTERS = {0x01,0x00,0x5E,0x00,0x00,0x06};
    opennsl_mac_t  OSPF_MAC_MASK = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8          OSPF_PROTOCOL_TYPE = 0x59;
    uint8          OSPF_PROTOCOL_MASK = 0xFF;

    retval = opennsl_field_entry_create(unit, ospf_data->ospf_group_id, &fieldEntry);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at %s opennsl_field_entry_create :: "
                 "unit=%d retval=%s ",
                 ospf_packet_rule, unit, opennsl_errmsg(retval));
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "opennsl_field_entry_create"),
                  EV_KV("rule", "%s", ospf_packet_rule),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        return retval;
    }

    retval = opennsl_field_qualify_DstMac(unit, fieldEntry,
                                          designatedRouter ?
                                          OSPF_MAC_DESIGNATED_ROUTERS :
                                          OSPF_MAC_ALL_ROUTERS,
                                          OSPF_MAC_MASK);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at %s opennsl_field_qualify_DstMac :: "
                 "unit=%d retval=%s ",
                 ospf_packet_rule, unit, opennsl_errmsg(retval));
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "opennsl_field_qualify_DstMac"),
                  EV_KV("rule", "%s", ospf_packet_rule),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        opennsl_field_entry_destroy(unit, fieldEntry);
        return retval;
    }

    retval = opennsl_field_qualify_IpProtocol(unit, fieldEntry,
                                              OSPF_PROTOCOL_TYPE,
                                              OSPF_PROTOCOL_MASK);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at %s opennsl_field_qualify_IpProtocol :: "
                 "unit=%d retval=%s ",
                 ospf_packet_rule, unit, opennsl_errmsg(retval));
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "opennsl_field_qualify_IpProtocol"),
                  EV_KV("rule", "%s", ospf_packet_rule),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        opennsl_field_entry_destroy(unit, fieldEntry);
        return retval;
    }

    if (designatedRouter) {
        retval = opennsl_field_qualify_DstIp(
                    unit, fieldEntry,
                    inet_network(OPS_ROUTING_DESIGNATED_ROUTER_OSPF_MULTICAST_IP_ADDR),
                    inet_network("255.255.255.255"));
    } else {
        retval = opennsl_field_qualify_DstIp(
                    unit, fieldEntry,
                    inet_network(OPS_ROUTING_ALL_OSPF_MULTICAST_IP_ADDR),
                    inet_network("255.255.255.255"));
    }
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at %s opennsl_field_qualify_DstIp :: "
                 "unit=%d retval=%s ",
                 ospf_packet_rule, unit, opennsl_errmsg(retval));
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "opennsl_field_qualify_DstIp"),
                  EV_KV("rule", "%s", ospf_packet_rule),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        opennsl_field_entry_destroy(unit, fieldEntry);
        return retval;
    }

    retval = opennsl_field_action_add(unit, fieldEntry,
                                      opennslFieldActionCopyToCpu,0,0);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at %s opennslFieldActionCopyToCpu :: "
                 "unit=%d retval=%s ",
                 ospf_packet_rule, unit, opennsl_errmsg(retval));
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "opennslFieldActionCopyToCpu"),
                  EV_KV("rule", "%s", ospf_packet_rule),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        opennsl_field_entry_destroy(unit, fieldEntry);
        return retval;
    }

    retval =  opennsl_field_stat_create(unit, ospf_data->ospf_group_id, 1,
                                        stat_arr, &stat_id);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at %s opennsl_field_stat_create :: unit=%d retval=%s ",
                 ospf_packet_rule, unit, opennsl_errmsg(retval));
        opennsl_field_entry_destroy(unit, fieldEntry);
        return retval;
    }

    retval = opennsl_field_entry_stat_attach(unit, fieldEntry, stat_id);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at %s opennsl_field_entry_stat_attach :: "
                "unit=%d retval=%s ",
                 ospf_packet_rule, unit, opennsl_errmsg(retval));
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "opennsl_field_entry_stat_attach"),
                  EV_KV("rule", "%s", ospf_packet_rule),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        opennsl_field_stat_destroy(unit, stat_id);
        opennsl_field_entry_destroy(unit, fieldEntry);
        return retval;
    }

    retval = opennsl_field_entry_install(unit, fieldEntry);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed to %s opennsl_field_entry_install : unit=%d retval=%s",
                 ospf_packet_rule, unit, opennsl_errmsg(retval));
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "opennsl_field_entry_install"),
                  EV_KV("rule", "%s", ospf_packet_rule),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        opennsl_field_stat_destroy(unit, stat_id);
        opennsl_field_entry_destroy(unit, fieldEntry);
        return retval;
    }
    if (designatedRouter) {
        ospf_data->ospf_desginated_routers_fp_id = fieldEntry;
        ospf_data->ospf_desginated_routers_stat_id = stat_id;
    } else {
        ospf_data->ospf_all_routers_fp_id = fieldEntry;
        ospf_data->ospf_all_routers_stat_id = stat_id;
    }
    return retval;
}

/* This function is used to create a group for OSPF
 * and add field processor entries for forwarding
 * OSPF packets to ASIC. This includes packets with the
 * following destinations:
 *   1. All OSPF Routers mcast address (224.0.0.5)
 *   2. OSPF Designated Routers[DR] mcast address (224.0.0.6)
 *
 * TODO : Currently this function enables OSPF on a global level.
 *        This is temporary and later there will be a new table
 *        which will store all mcast addresses of interest and
 *        program the ASIC to selectively forward multicast traffic
 *        on an interface level. Once this is implemented, this function
 *        will become obsolete and should be removed.
 */
static int
ops_routing_ospf_init(int unit)
{

    opennsl_field_qset_t       qualifierSet;
    int                        retval = -1;

    ospf_data = xzalloc(sizeof(ops_ospf_data_t));

    /* Build the qualifier set */
    OPENNSL_FIELD_QSET_INIT (qualifierSet);
    OPENNSL_FIELD_QSET_ADD (qualifierSet, opennslFieldQualifyStageIngress);
    OPENNSL_FIELD_QSET_ADD (qualifierSet, opennslFieldQualifyDstMac);
    OPENNSL_FIELD_QSET_ADD (qualifierSet, opennslFieldQualifyIpProtocol);
    OPENNSL_FIELD_QSET_ADD (qualifierSet, opennslFieldQualifyDstIp);

    retval = opennsl_field_group_create(unit, qualifierSet,
                                        FP_GROUP_PRIORITY_2,
                                        &ospf_data->ospf_group_id);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at OSPF opennsl_field_group_create :: "
                "unit=%d retval=%s ", unit, opennsl_errmsg(retval));
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "opennsl_field_group_create"),
                  EV_KV("rule", "%s", ""),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        free(ospf_data);
        return retval;
    }

    VLOG_DBG("OSPF group added :: group_id=%d ", ospf_data->ospf_group_id);

    retval = ops_routing_create_ospf_field_entry(unit, false);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at create field entry for OSPF:AllRouters :: "
                "unit=%d retval=%s ", unit, opennsl_errmsg(retval));
        opennsl_field_group_destroy(unit, ospf_data->ospf_group_id);
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "create field entry for OSPF:AllRouters"),
                  EV_KV("rule", "%s", ""),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        free(ospf_data);
        return retval;
    }

    VLOG_DBG("OSPF all routers field entry added: "
            "group_id=%d fp_id=%d stat_id=%d",
            ospf_data->ospf_group_id,
            ospf_data->ospf_all_routers_fp_id,
            ospf_data->ospf_all_routers_stat_id);
    log_event("OSPFv2_FP_SUCCESS",
            EV_KV("group_id", "%d", ospf_data->ospf_group_id),
            EV_KV("fp_id", "%d", ospf_data->ospf_all_routers_fp_id),
            EV_KV("stats_id", "%d", ospf_data->ospf_all_routers_stat_id));

    retval = ops_routing_create_ospf_field_entry(unit, true);
    if (OPENNSL_FAILURE(retval)) {
        VLOG_ERR("Failed at create field entry for OSPF:DesignatedRouters :: "
                "unit=%d retval=%s ", unit, opennsl_errmsg(retval));
        log_event("OSPFv2_FP_ERR",
                  EV_KV("action", "%s", "create field entry for OSPF:DesignatedRouters"),
                  EV_KV("rule", "%s", ""),
                  EV_KV("err", "%s", opennsl_errmsg(retval)));
        opennsl_field_group_destroy(unit, ospf_data->ospf_group_id);
        free(ospf_data);
        return retval;
    }

    VLOG_DBG("OSPF designated routers field entry added: "
             "group_id=%d fp_id=%d stat_id=%d",
             ospf_data->ospf_group_id,
             ospf_data->ospf_desginated_routers_fp_id,
             ospf_data->ospf_desginated_routers_stat_id);
    log_event("OSPFv2_DR_FP_SUCCESS",
            EV_KV("group_id", "%d", ospf_data->ospf_group_id),
            EV_KV("fp_id", "%d", ospf_data->ospf_desginated_routers_fp_id),
            EV_KV("stats_id", "%d", ospf_data->ospf_desginated_routers_stat_id));

    return retval;
}

/* Function to add ipv4/ipv6 default routes to support ALPM mode.
** This was suggestated by broadcom */
int
ops_add_default_routes(int unit)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_egress_t egress_object;
    opennsl_if_t default_egress_id;

    /* Create a egress object for default route's */
    opennsl_l3_egress_t_init(&egress_object);
    egress_object.intf = -1;
    egress_object.port = 0;
    egress_object.flags = OPENNSL_L3_DST_DISCARD;
    memcpy(egress_object.mac_addr, LOCAL_MAC, ETH_ALEN);
    rc = opennsl_l3_egress_create(unit, 0,
                                  &egress_object, &default_egress_id);

    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Default egress create failed, rc=%s", opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }

    /* Configure ipv4 default route, with vrf, addr and mask = 0 */
    /* Setting subnet/mask to zero even after doing init, just to
    ** make it visible that we are programming 0 */
    opennsl_l3_route_t_init(&ipv4_default_route);
    ipv4_default_route.l3a_flags = OPENNSL_L3_REPLACE;
    ipv4_default_route.l3a_vrf = 0;
    ipv4_default_route.l3a_subnet = 0;
    ipv4_default_route.l3a_ip_mask = 0;
    /* ipv4_default_route.l3a_intf = 0; Doesn't work  */
    ipv4_default_route.l3a_intf = default_egress_id;
    rc = opennsl_l3_route_add (unit, &ipv4_default_route);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Default route for IPv4 failed rc = %s",
                 opennsl_errmsg(rc));
        return rc; /* Return error */
    }

    /* Configure ipv6 default route, with vrf, addr and mask = 0 */
    opennsl_l3_route_t_init(&ipv6_default_route);
    ipv6_default_route.l3a_flags = OPENNSL_L3_IP6 | OPENNSL_L3_REPLACE;
    ipv6_default_route.l3a_vrf = 0;
    memset(&ipv6_default_route.l3a_ip6_net, 0,
                               sizeof(ipv6_default_route.l3a_ip6_net));
    memset(&ipv6_default_route.l3a_ip6_mask, 0,
                               sizeof(ipv6_default_route.l3a_ip6_mask));
    ipv6_default_route.l3a_intf = default_egress_id;
    rc = opennsl_l3_route_add (unit, &ipv6_default_route);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Default route for IPv6 failed rc = %s",
                 opennsl_errmsg(rc));
        return rc; /* Return error */
    }

    return 0;
}

/* Function to compare internal ipv4/ipv6 default 0 route */
int
is_default_route(int unit,
                 struct ofproto_route *of_routep,
                 opennsl_l3_route_t *route)
{
    if (of_routep->family == OFPROTO_ROUTE_IPV4) {
        if ( (route->l3a_vrf == ipv4_default_route.l3a_vrf) &&
             (route->l3a_subnet == ipv4_default_route.l3a_subnet) &&
             (route->l3a_ip_mask == ipv4_default_route.l3a_ip_mask) )
            return 1; /* Matched v4 default route */
    } else {
        if ( (route->l3a_vrf == ipv6_default_route.l3a_vrf) &&
             (memcmp(route->l3a_ip6_net, ipv6_default_route.l3a_ip6_net,
                     sizeof(ipv6_default_route.l3a_ip6_net)) == 0) &&
             (memcmp(route->l3a_ip6_mask, ipv6_default_route.l3a_ip6_mask,
                     sizeof(ipv6_default_route.l3a_ip6_mask))) )
            return 1; /* Matched v6 default route */
    }

    return 0;
}

int
ops_l3_init(int unit)
{
    int hash_cfg = 0;
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_egress_t egress_object;
    shash_init(&internal_vlans);

    rc = opennsl_switch_control_set(unit, opennslSwitchL3IngressMode, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchL3IngressMode: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    rc = opennsl_switch_control_set(unit, opennslSwitchL3EgressMode, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchL3EgressMode: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    /* Create a system wide egress object for unresolved NH */
    opennsl_l3_egress_t_init(&egress_object);

    egress_object.intf = -1;
    egress_object.port = 0; /* CPU port */
    egress_object.flags = OPENNSL_L3_COPY_TO_CPU;
    memcpy(egress_object.mac_addr, LOCAL_MAC, ETH_ALEN);
    rc = opennsl_l3_egress_create(unit, OPENNSL_L3_COPY_TO_CPU,
                                  &egress_object, &local_nhid);

    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error, create a local egress object, rc=%s", opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }

    /* Add ipv4/ipv6 default route to support ALPM mode */
    rc = ops_add_default_routes(unit);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Default route configuration failed unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    /* Send ARP to CPU */
    rc = opennsl_switch_control_set(unit, opennslSwitchArpRequestToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchArpRequestToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    rc = opennsl_switch_control_set(unit, opennslSwitchArpReplyToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchArpReplyToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }


    rc = opennsl_switch_control_set(unit, opennslSwitchDhcpPktToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchDhcpPktToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    /* IPv6 ND packets */
    rc = opennsl_switch_control_set(unit, opennslSwitchNdPktToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchNdPktToCpu: unit=%d  rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    /* Send IPv4 and IPv6 to CPU */
    rc = opennsl_switch_control_set(unit,opennslSwitchUnknownL3DestToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchUnknownL3DestToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    rc = opennsl_switch_control_set(unit, opennslSwitchV6L3DstMissToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchV6L3DstMissToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    /* Copying packets to CPU whose TTL=1 */
    rc = opennsl_switch_control_set(unit,opennslSwitchL3UcastTtl1ToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchL3UcastTtl1ToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    /* Enable ECMP enhanced hash method */
    rc = opennsl_switch_control_set(unit, opennslSwitchHashControl,
                                    OPENNSL_HASH_CONTROL_ECMP_ENHANCE);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set OPENNSL_HASH_CONTROL_ECMP_ENHANCE: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    rc = opennsl_l3_route_max_ecmp_set(unit, MAX_NEXTHOPS_PER_ROUTE);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set Max ECMP  paths unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    /* Enable IPv4 src ip, src port, dst ip, dst port hashing by default */
    hash_cfg = OPENNSL_HASH_FIELD_IP4SRC_LO | OPENNSL_HASH_FIELD_IP4SRC_HI |
               OPENNSL_HASH_FIELD_SRCL4 | OPENNSL_HASH_FIELD_IP4DST_LO |
               OPENNSL_HASH_FIELD_IP4DST_HI | OPENNSL_HASH_FIELD_DSTL4;

    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP4TcpUdpPortsEqualField0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4TcpUdpPortsEqualField0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP4TcpUdpField0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4TcpUdpPortsEqualField0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP4Field0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4Field0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    /* Enable IPv6 src ip, src port, dst ip, dst port hashing by default */
    hash_cfg = OPENNSL_HASH_FIELD_IP6SRC_LO | OPENNSL_HASH_FIELD_IP6SRC_HI |
               OPENNSL_HASH_FIELD_SRCL4 | OPENNSL_HASH_FIELD_IP6DST_LO |
               OPENNSL_HASH_FIELD_IP6DST_HI | OPENNSL_HASH_FIELD_DSTL4;

    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP6TcpUdpPortsEqualField0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6TcpUdpPortsEqualField0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP6TcpUdpField0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6TcpUdpPortsEqualField0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP6Field0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6Field0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    /* Enabling the ecmp resiliency initially*/
    ecmp_resilient_flag = true;

    /* FIXME : Generate the seed from the system MAC? */
    rc = opennsl_switch_control_set(unit, opennslSwitchHashSeed0, 0x12345678);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashSeed0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchHashField0PreProcessEnable,
                                    1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashField0PreProcessEnable: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchHashField0Config,
                                    OPENNSL_HASH_FIELD_CONFIG_CRC16CCITT);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashField0Config: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchHashField0Config1,
                                    OPENNSL_HASH_FIELD_CONFIG_CRC16CCITT);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashField0Config1: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchECMPHashSet0Offset, 0);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchECMPHashSet0Offset: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchHashSelectControl, 0);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashSelectControl: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }

    /* Creating profile for ip-options */
    rc = opennsl_l3_ip4_options_profile_create(unit,
                                               OPENNSL_L3_IP4_OPTIONS_WITH_ID,
                                               opennslIntfIPOptionActionCopyCPUAndDrop,
                                               &default_ip4_options_profile_id);
    if (OPENNSL_FAILURE(rc)) {
      VLOG_ERR("Failed to set opennslIntfIPOptionActionCopyCPUAndDrop: unit=%d rc=%s",
                unit, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
      return 1;
    }

    /* initialize route table hash map */
    hmap_init(&ops_rtable.routes);
    hmap_init(&ecmp_egress_nexthops_map);

    /* Initialize egress-id hash map. Used only during mac-move. */
    hmap_init(&ops_mac_move_egress_id_map);

    /* Install FPs for forwarding OSPF traffic */
    rc = ops_routing_ospf_init(unit);
    if (rc) {
        VLOG_ERR("OSPF FP init failed");
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", "OSPF FP init failed"));
        return 1; /* Return error */
    }

    /* Initialize hash map of switch mac's */
    hmap_init(&ops_hmap_switch_macs);

    return 0;
}

/* Function to find switch mac in local hash */
static struct ops_switch_mac_info*
ops_switch_mac_hash_lookup(const char *mac)
{
    struct ops_switch_mac_info *switch_mac_info;

    HMAP_FOR_EACH_WITH_HASH (switch_mac_info, node, hash_string(mac, 0),
                             &ops_hmap_switch_macs) {
        if (strcmp(switch_mac_info->mac, mac) == 0) {
            VLOG_DBG("In lookup found mac %s and station-id=%d",
             ether_ntoa((struct ether_addr*)switch_mac_info->mac),
             switch_mac_info->station_id);

            return switch_mac_info;
        }
    }
    return NULL;
}

/* Function to add new mac to hash */
static void
ops_switch_mac_hash_add(const char *mac, int station_id)
{
    struct ops_switch_mac_info *switch_mac_info;

    VLOG_DBG("In mac_hash_add for mac %s, station_id=%d",
             ether_ntoa((struct ether_addr*)mac), station_id);
    switch_mac_info = xzalloc(sizeof *switch_mac_info);
    switch_mac_info->mac = xstrdup(mac);
    switch_mac_info->station_id = station_id;

    hmap_insert(&ops_hmap_switch_macs, &switch_mac_info->node,
                hash_string(switch_mac_info->mac, 0));

}

/* Function to add mac in asic l2 station tcam */
static int
ops_switch_mac_add(int hw_unit, const char *mac)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l2_station_t l2_station;
    struct ops_switch_mac_info *switch_mac_info;
    int station_id = 0;

    VLOG_DBG("In ops_switch_mac_add for mac %s",
             ether_ntoa((struct ether_addr*)mac));
    /* Check in local hash first */
    switch_mac_info = ops_switch_mac_hash_lookup(mac);

    /* Check if already programmed */
    if (switch_mac_info) {
        VLOG_DBG("Mac exists in hash, check in asic");
        rc = opennsl_l2_station_get(hw_unit, switch_mac_info->station_id,
                                    &l2_station);

        VLOG_DBG("station_get rc=%s", opennsl_errmsg(rc));
        if (rc == OPENNSL_E_NONE) {
            VLOG_DBG("mac exists in asic");
            return rc;
        }
    }
    VLOG_DBG("Mac not in asic, adding to asic");

    /* Else add to TCAM */
    opennsl_l2_station_t_init(&l2_station);
    memcpy(&l2_station.dst_mac, mac, ETH_ALEN);
    memset(&l2_station.dst_mac_mask, 0xFF, ETH_ALEN);
    l2_station.flags |= (OPENNSL_L2_STATION_IPV4 | OPENNSL_L2_STATION_IPV6 |
                       OPENNSL_L2_STATION_ARP_RARP);
    rc = opennsl_l2_station_add(hw_unit, &station_id, &l2_station);
    if (rc == OPENNSL_E_NONE) {
        /* Add to hash */
        ops_switch_mac_hash_add(mac, station_id);
    }

    return rc;
}

/* Function to create l3 interface */
static int
ops_routing_create_l3_intf(int hw_unit, opennsl_vrf_t vrf_id,
                           opennsl_vlan_t vlan_id, unsigned char *mac,
                           opennsl_l3_intf_t *l3_intf)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    /* Create L3 interface */
    opennsl_l3_intf_t_init(l3_intf);
    l3_intf->l3a_vrf = vrf_id;
    l3_intf->l3a_intf_id = vlan_id;
    l3_intf->l3a_flags = OPENNSL_L3_WITH_ID;
    memcpy(l3_intf->l3a_mac_addr, mac, ETH_ALEN);
    l3_intf->l3a_vid = vlan_id;
    l3_intf->l3a_ip4_options_profile_id = default_ip4_options_profile_id;

    rc = opennsl_l3_intf_create(hw_unit, l3_intf);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("opennsl_l3_intf_create failed: unit=%d vlan=%d vrf=%d rc=%s",
                 hw_unit, vlan_id, vrf_id, opennsl_errmsg(rc));
        return rc;
    }

    /* Add the mac in l2 station table, instead of ARL */
    rc = ops_switch_mac_add(hw_unit, (const char *)mac);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("ops_switch_mac_add failed: unit=%d vlan=%d vrf=%d rc=%s",
                 hw_unit, vlan_id, vrf_id, opennsl_errmsg(rc));

        rc = opennsl_l3_intf_delete(hw_unit, l3_intf);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("l3_intf_delete failed: unit=%d vlan=%d vrf=%d rc=%s",
                 hw_unit, vlan_id, vrf_id, opennsl_errmsg(rc));
        }

        return rc;
    }

    VLOG_DBG("L3 intf created: unit=%d vlan=%d vrf=%d rc=%s",
              hw_unit, vlan_id, vrf_id, opennsl_errmsg(rc));

    return rc;
}

opennsl_l3_intf_t *
ops_routing_enable_l3_interface(int hw_unit, opennsl_port_t hw_port,
                                opennsl_vrf_t vrf_id, opennsl_vlan_t vlan_id,
                                unsigned char *mac, struct netdev *netdev)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_pbmp_t pbmp;
    opennsl_l3_intf_t *l3_intf;
    char vlan_str[VLAN_ID_MAX_LENGTH];

    VLOG_DBG("%s unit=%d port=%d vlan=%d vrf=%d",
             __FUNCTION__, hw_unit, hw_port, vlan_id, vrf_id);
    /* VLAN config */
    rc = bcmsdk_create_vlan(vlan_id, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_create_vlan: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
        log_event("L3INTERFACE_VLAN_CREATE_ERR",
                  EV_KV("interface", "%s", netdev_get_name(netdev)),
                  EV_KV("vlanid", "%d", vlan_id));
        goto failed_vlan_creation;
    }


    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_PORT_ADD(pbmp, hw_port);
    /* Add as native untagged as we would not want to restrict all
       tagged packets if a port is configured to the specific vlan */
    bcmsdk_add_native_untagged_ports(vlan_id, &pbmp, true);

    /* Create L3 interface */
    l3_intf = (opennsl_l3_intf_t *)xmalloc(sizeof(opennsl_l3_intf_t));
    if (!l3_intf) {
        VLOG_ERR("Failed allocating opennsl_l3_intf_t: unit=%d port=%d"
                 " vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
        goto failed_allocating_l3_intf;
    }

    /* Create l3 interface and add the mac to station tcam */
    rc = ops_routing_create_l3_intf(hw_unit, vrf_id, vlan_id, mac, l3_intf);
    if (OPENNSL_FAILURE(rc)) {
        log_event("L3INTERFACE_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        goto failed_l3_intf_create;
    }

    SW_L3_DBG("Enabled L3 on unit=%d port=%d vlan=%d vrf=%d",
            hw_unit, hw_port, vlan_id, vrf_id);
    snprintf(vlan_str, VLAN_ID_MAX_LENGTH, "%d", vlan_id);
    shash_add_once(&internal_vlans, vlan_str, &vlan_id);
    handle_bcmsdk_knet_l3_port_filters(netdev, vlan_id, true);
    return l3_intf;

failed_l3_intf_create:
    free(l3_intf);

failed_allocating_l3_intf:
    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_PORT_ADD(pbmp, hw_port);
    bcmsdk_del_native_untagged_ports(vlan_id, &pbmp, true);

    rc = bcmsdk_destroy_vlan(vlan_id, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_destroy_vlan: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
        log_event("L3INTERFACE_VLAN_DESTROY_ERR",
                EV_KV("interface", "%s", netdev_get_name(netdev)),
                EV_KV("vlanid", "%d", vlan_id),
                EV_KV("err", "%s", opennsl_errmsg(rc)));
    }

failed_vlan_creation:
    return NULL;
}

opennsl_l3_intf_t *
ops_routing_enable_l3_subinterface(int hw_unit, opennsl_port_t hw_port,
                                opennsl_vrf_t vrf_id, opennsl_vlan_t vlan_id,
                                unsigned char *mac, struct netdev *netdev)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_pbmp_t pbmp;
    opennsl_l3_intf_t *l3_intf;

    /* VLAN config */
    rc = bcmsdk_create_vlan(vlan_id, false);
    if (rc < 0) {
        log_event("SUBINTERFACE_VLAN_CREATE_ERR",
                  EV_KV("interface", "%s", netdev_get_name(netdev)),
                  EV_KV("vlanid", "%d", vlan_id));
        VLOG_ERR("Failed at bcmsdk_create_vlan: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
        goto failed_vlan_creation;
    }


    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_PORT_ADD(pbmp, hw_port);
    VLOG_DBG("Adding hw_port = %d to trunk\n", hw_port);
    bcmsdk_add_trunk_ports(vlan_id, &pbmp);

    VLOG_DBG("Adding hw_port = %d to subinterface\n", hw_port);
    bcmsdk_add_subinterface_ports(vlan_id, &pbmp);

    /* Create L3 interface */
    l3_intf = (opennsl_l3_intf_t *)xmalloc(sizeof(opennsl_l3_intf_t));
    if (!l3_intf) {
        VLOG_ERR("Failed allocating opennsl_l3_intf_t: unit=%d port=%d"
                 " vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
        goto failed_allocating_l3_intf;
    }

    /* Create l3 interface and add the mac to station tcam */
    rc = ops_routing_create_l3_intf(hw_unit, vrf_id, vlan_id, mac, l3_intf);
    if (rc != OPENNSL_E_EXISTS && OPENNSL_FAILURE(rc)) {
        log_event("SUBINTERFACE_L3INTF_CREATE_ERR",
                  EV_KV("interface", "%s", netdev_get_name(netdev)));
        goto failed_l3_intf_create;
    }

    SW_L3_DBG("Enabled L3 on unit=%d port=%d vlan=%d vrf=%d",
            hw_unit, hw_port, vlan_id, vrf_id);

    VLOG_DBG("Create knet filter\n");
    if (netdev_bcmsdk_get_subint_count(netdev) == 0) {
        handle_bcmsdk_knet_subinterface_filters(netdev, true);
        VLOG_DBG("Create FP to stop switching");
        rc = ops_subinterface_fp_entry_create(hw_port, hw_unit);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("FP creation failed");
            goto failed_l3_intf_create;
        }
    }
    netdev_bcmsdk_update_subint_count(netdev, true);

    return l3_intf;

failed_l3_intf_create:
    free(l3_intf);

failed_allocating_l3_intf:
    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_PORT_ADD(pbmp, hw_port);
    bcmsdk_del_trunk_ports(vlan_id, &pbmp);
    bcmsdk_del_subinterface_ports(vlan_id, &pbmp);

    rc = bcmsdk_destroy_vlan(vlan_id, false);
    if (rc < 0) {
        log_event("SUBINTERFACE_VLAN_DESTROY_ERR",
                EV_KV("interface", "%s", netdev_get_name(netdev)),
                EV_KV("vlanid", "%d", vlan_id),
                EV_KV("err", "%s", opennsl_errmsg(rc)));
        VLOG_ERR("Failed at bcmsdk_destroy_vlan: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
    }

failed_vlan_creation:
    /* Delete subinterface entry from group*/
    rc = ops_update_subint_fp_entry(hw_unit, hw_port, false);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to delete port to entry = %d for group = %d,\
                Unit=%d port=%d rc=%s",
                subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
                subintf_fp_grp_info[hw_unit].l3_fp_grpid,
                hw_unit, hw_port, opennsl_errmsg(rc));
    }
    return NULL;
}

void
ops_routing_disable_l3_interface(int hw_unit, opennsl_port_t hw_port,
                                 opennsl_l3_intf_t *l3_intf, struct netdev *netdev)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_vlan_t vlan_id = l3_intf->l3a_vid;
    char vlan_str[VLAN_ID_MAX_LENGTH];

    VLOG_DBG("%s unit=%d vlan=%d",__FUNCTION__, hw_unit, vlan_id);
    rc = opennsl_l3_intf_delete(hw_unit, l3_intf);
    if (OPENNSL_FAILURE(rc)) {
        log_event("L3INTERFACE_DELETE_ERR",
                  EV_KV("interface", "%s", netdev_get_name(netdev)),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        VLOG_ERR("Failed at opennsl_l3_intf_delete: unit=%d vlan=%d"
                 " rc=%s",
                 hw_unit, vlan_id, opennsl_errmsg(rc));
    }
    free(l3_intf);

    rc = bcmsdk_destroy_vlan(vlan_id, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_destroy_vlan: unit=%d vlan=%d rc=%d",
                hw_unit, vlan_id, rc);
        log_event("L3INTERFACE_VLAN_DESTROY_ERR",
                EV_KV("interface", "%s", netdev_get_name(netdev)),
                EV_KV("vlanid", "%d", vlan_id),
                EV_KV("err", "%s", opennsl_errmsg(rc)));
    }

    SW_L3_DBG("Disabled L3 on unit=%d", hw_unit);

    snprintf(vlan_str, VLAN_ID_MAX_LENGTH, "%d", vlan_id);
    shash_find_and_delete(&internal_vlans, vlan_str);

    handle_bcmsdk_knet_l3_port_filters(netdev, vlan_id, false);
}

void
ops_routing_disable_l3_subinterface(int hw_unit, opennsl_port_t hw_port,
                       opennsl_l3_intf_t *l3_intf, struct netdev *netdev)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_vlan_t vlan_id = l3_intf->l3a_vid;
    opennsl_vrf_t vrf_id = l3_intf->l3a_vrf;
    opennsl_pbmp_t pbmp;

    rc = opennsl_l3_intf_delete(hw_unit, l3_intf);
    if (OPENNSL_FAILURE(rc)) {
        log_event("SUBINTERFACE_L3INTF_DELETE_ERR",
                  EV_KV("interface", "%s", netdev_get_name(netdev)),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        VLOG_ERR("Failed at opennsl_l3_intf_delete: unit=%d port=%d vlan=%d"
                 " vrf=%d rc=%s",
                 hw_unit, hw_port, vlan_id, vrf_id, opennsl_errmsg(rc));
    }
    free(l3_intf);

    /* Reset VLAN on port back to default and destroy the VLAN */
    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_PORT_ADD(pbmp, hw_port);
    bcmsdk_del_trunk_ports(vlan_id, &pbmp);

    bcmsdk_del_subinterface_ports(vlan_id, &pbmp);

    if (is_vlan_membership_empty(vlan_id) && !is_user_created_vlan(vlan_id)) {
        VLOG_DBG("Vlan %d is empty\n", vlan_id);
        rc = bcmsdk_destroy_vlan(vlan_id, false);
        if (rc < 0) {
            log_event("SUBINTERFACE_VLAN_DESTROY_ERR",
                      EV_KV("interface", "%s", netdev_get_name(netdev)),
                      EV_KV("vlanid", "%d", vlan_id),
                      EV_KV("err", "%s", opennsl_errmsg(rc)));
            VLOG_ERR("Failed at bcmsdk_destroy_vlan: unit=%d port=%d vlan=%d"
                     " rc=%d",
                     hw_unit, hw_port, vlan_id, rc);
        }
    }

    SW_L3_DBG("Disabled L3 on unit=%d port=%d vrf=%d", hw_unit, hw_port, vrf_id);

    netdev_bcmsdk_update_subint_count(netdev, false);

    VLOG_DBG("Delete subinterface knet filter\n");
    if (netdev_bcmsdk_get_subint_count(netdev) == 0) {
        handle_bcmsdk_knet_subinterface_filters(netdev, false);
        /* Delete subinterface entry from group*/
        rc = ops_update_subint_fp_entry(hw_unit, hw_port, false);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to delete port to entry = %d for group = %d,\
                    Unit=%d port=%d rc=%s",
                    subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
                    subintf_fp_grp_info[hw_unit].l3_fp_grpid,
                    hw_unit, hw_port, opennsl_errmsg(rc));
        }
    }
}

opennsl_l3_intf_t *
ops_routing_enable_l3_vlan_interface(int hw_unit, opennsl_vrf_t vrf_id,
                                     opennsl_vlan_t vlan_id,
                                     unsigned char *mac)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_intf_t *l3_intf;

    /* Create L3 interface */
    l3_intf = (opennsl_l3_intf_t *)xmalloc(sizeof(opennsl_l3_intf_t));
    if (!l3_intf) {
        VLOG_ERR("Failed allocating opennsl_l3_intf_t: unit=%d vlan=%d rc=%d",
                 hw_unit, vlan_id, rc);
        return NULL;
    }

    /* Create l3 interface and add the mac to station tcam */
    rc = ops_routing_create_l3_intf(hw_unit, vrf_id, vlan_id, mac, l3_intf);
    if (OPENNSL_FAILURE(rc)) {
        log_event("VLANINTERFACE_L3INTF_CREATE_ERR",
                  EV_KV("vlan", "%d", vlan_id),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        free(l3_intf);
        return NULL;
    }

    SW_L3_DBG("Enabled L3 on unit=%d vlan=%d vrf=%d",
            hw_unit, vlan_id, vrf_id);

    return l3_intf;
} /* ops_routing_enable_l3_vlan_interface */

/* Add nexthop into the route entry */
static void
ops_nexthop_add(struct ops_route *route,  struct ofproto_route_nexthop *of_nh)
{
    char *hashstr;
    struct ops_nexthop *nh;

    if (!route || !of_nh) {
        return;
    }

    nh = xzalloc(sizeof(*nh));
    nh->type = of_nh->type;
    /* NOTE: Either IP or Port, not both */
    if (of_nh->id) {
        nh->id = xstrdup(of_nh->id);
    }

    nh->l3_egress_id = (of_nh->state == OFPROTO_NH_RESOLVED) ?
                        of_nh->l3_egress_id : local_nhid ;

    hashstr = of_nh->id;
    hmap_insert(&route->nexthops, &nh->node, hash_string(hashstr, 0));
    route->n_nexthops++;

    VLOG_DBG("Add NH %s, egress_id %d, for route %s",
            nh->id, nh->l3_egress_id, route->prefix);
} /* ops_nexthop_add */

/* Delete nexthop into route entry */
static void
ops_nexthop_delete(struct ops_route *route, struct ops_nexthop *nh)
{
    if (!route || !nh) {
        return;
    }

    VLOG_DBG("Delete NH %s in route %s", nh->id, route->prefix);
    hmap_remove(&route->nexthops, &nh->node);
    if (nh->id) {
        free(nh->id);
    }
    free(nh);
    route->n_nexthops--;
} /* ops_nexthop_delete */

/* Find nexthop entry in the route's nexthops hash */
static struct ops_nexthop*
ops_nexthop_lookup(struct ops_route *route, struct ofproto_route_nexthop *of_nh)
{
    char *hashstr;
    struct ops_nexthop *nh;

    hashstr = of_nh->id;
    HMAP_FOR_EACH_WITH_HASH(nh, node, hash_string(hashstr, 0),
                            &route->nexthops) {
        if ((strcmp(nh->id, of_nh->id) == 0)){
            return nh;
        }
    }
    return NULL;
} /* ops_nexthop_lookup */

/* Create route hash */
static void
ops_route_hash(int vrf, char *prefix, char *hashstr, int hashlen)
{
    snprintf(hashstr, hashlen, "%d:%s", vrf, prefix);
} /* ops_route_hash */

/* Find a route entry matching the prefix */
static struct ops_route *
ops_route_lookup(int vrf, struct ofproto_route *of_routep)
{
    struct ops_route *route;
    char hashstr[OPS_ROUTE_HASH_MAXSIZE];

    ops_route_hash(vrf, of_routep->prefix, hashstr, sizeof(hashstr));
    HMAP_FOR_EACH_WITH_HASH(route, node, hash_string(hashstr, 0),
                            &ops_rtable.routes) {
        if ((strcmp(route->prefix, of_routep->prefix) == 0) &&
            (route->vrf == vrf)) {
            return route;
        }
    }
    return NULL;
} /* ops_route_lookup */

/* Add new route and NHs */
static struct ops_route*
ops_route_add(int vrf, struct ofproto_route *of_routep)
{
    int i;
    struct ops_route *routep;
    struct ofproto_route_nexthop *of_nh;
    char hashstr[OPS_ROUTE_HASH_MAXSIZE];

    if (!of_routep) {
        return NULL;
    }

    routep = xzalloc(sizeof(*routep));
    routep->vrf = vrf;
    routep->prefix = xstrdup(of_routep->prefix);
    routep->is_ipv6 = (of_routep->family == OFPROTO_ROUTE_IPV6) ? true : false;
    routep->n_nexthops = 0;

    hmap_init(&routep->nexthops);

    for (i = 0; i < of_routep->n_nexthops; i++) {
        of_nh = &of_routep->nexthops[i];
        ops_nexthop_add(routep, of_nh);
    }

    ops_route_hash(vrf, of_routep->prefix, hashstr, sizeof(hashstr));
    hmap_insert(&ops_rtable.routes, &routep->node, hash_string(hashstr, 0));
    VLOG_DBG("Add route %s", of_routep->prefix);
    return routep;
} /* ops_route_add */

/* Update route nexthop: add, delete, resolve and unresolve nh */
static void
ops_route_update(int vrf, struct ops_route *routep,
                 struct ofproto_route *of_routep,
                 bool is_delete_nh)
{
    struct ops_nexthop* nh;
    struct ofproto_route_nexthop *of_nh;
    int i;

    for (i = 0; i < of_routep->n_nexthops; i++) {
        of_nh = &of_routep->nexthops[i];
        nh = ops_nexthop_lookup(routep, of_nh);
        if (is_delete_nh) {
            ops_nexthop_delete(routep, nh);
        } else {
            /* add or update */
            if (!nh) {
                ops_nexthop_add(routep, of_nh);
            } else {
                /* update is currently resolved on unreoslved */
                nh->l3_egress_id = (of_nh->state == OFPROTO_NH_RESOLVED) ?
                    of_nh->l3_egress_id : local_nhid ;
                VLOG_DBG("Update for route %s", of_routep->prefix);
            }
        }
    }
} /* ops_route_update */

/* Delete route in system*/
static void
ops_route_delete(struct ops_route *routep)
{
    struct ops_nexthop *nh, *next;

    if (!routep) {
        return;
    }

    VLOG_DBG("delete route %s", routep->prefix);

    hmap_remove(&ops_rtable.routes, &routep->node);

    HMAP_FOR_EACH_SAFE(nh, next, node, &routep->nexthops) {
        ops_nexthop_delete(routep, nh);
    }

    if (routep->prefix) {
        free(routep->prefix);
    }
    free(routep);
} /* ops_route_delete */

/* Function to add l3 host entry via ofproto */
int
ops_routing_add_host_entry(int hw_unit, opennsl_port_t hw_port,
                           opennsl_vrf_t vrf_id, bool is_ipv6_addr,
                           char *ip_addr, char *next_hop_mac_addr,
                           opennsl_if_t l3_intf_id,
                           opennsl_if_t *l3_egress_id,
                           opennsl_vlan_t vlan_id,
                           int trunk_id)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_egress_t egress_object;
    opennsl_l3_host_t l3host;
    in_addr_t ipv4_dest_addr;
    char ipv6_dest_addr[sizeof(struct in6_addr)];
    int flags = 0;
    struct ether_addr *ether_mac = ether_aton(next_hop_mac_addr);
    opennsl_port_t port = hw_port;
    opennsl_l2_addr_t addr;

    /* If we dont have a hw_port, this is likely a vlan interface
     * Look it up.
     */
    if(hw_port == -1) {
        opennsl_mac_t host_mac;
        if (ether_mac != NULL)
           memcpy(host_mac, ether_mac, ETH_ALEN);
        opennsl_l2_addr_get(hw_unit, host_mac, vlan_id, &addr);
        port = addr.port;
    }

    /* Create the l3_egress object which gives the index to l3 interface
     * during lookup */
    VLOG_DBG("In ops_routing_add_host_entry for ip %s", ip_addr);
    opennsl_l3_egress_t_init(&egress_object);

    /* Copy the nexthop destmac, set dest port and index of L3_INTF table
     * which is created above */
    egress_object.intf = l3_intf_id;
    /* LAG l3 */
    if (trunk_id != -1) {
        egress_object.trunk = trunk_id;
        egress_object.flags = OPENNSL_L3_TGID;
    } else {
        egress_object.port = port;
    }

    if (ether_mac != NULL) {
        memcpy(egress_object.mac_addr, ether_mac, ETH_ALEN);
    } else {
        VLOG_ERR("Invalid mac-%s", next_hop_mac_addr);
        return 1; /* Return error */
    }

    rc = opennsl_l3_egress_find(hw_unit, &egress_object, l3_egress_id);
    if (rc == OPENNSL_E_NONE) {
        /* An entry exists. Use OPENNSL_L3_REPLACE flag to replace it. */
        flags = (OPENNSL_L3_REPLACE | OPENNSL_L3_WITH_ID);
    } else if (rc != OPENNSL_E_NOT_FOUND) {
        VLOG_ERR("Error, finding an egress entry: rc=%s", opennsl_errmsg(rc));
    } else {
        /* no entry found in egress table. */
    }

    rc = opennsl_l3_egress_create(hw_unit, flags, &egress_object, l3_egress_id);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error, create egress object, out_port=%d, rc=%s", hw_port,
                 opennsl_errmsg(rc));
        log_event("L3INTERFACE_CREATE_EGRESS_OBJ_ERR",
                  EV_KV("port", "%d", hw_port),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }
    log_event("L3INTERFACE_CREATE_EGRESS_OBJ",
            EV_KV("egress_id", "%d", *l3_egress_id),
            EV_KV("port", "%d", hw_port),
            EV_KV("intf", "%d", l3_intf_id));

    VLOG_DBG("Created L3 egress ID %d for out_port: %d intf_id: %d ",
          *l3_egress_id, port, l3_intf_id);

    /* Create Host Entry */
    opennsl_l3_host_t_init(&l3host);
    if( is_ipv6_addr ) {
        flags |= OPENNSL_L3_IP6;

        /* convert string ip into host format */
        rc = inet_pton(AF_INET6, ip_addr, ipv6_dest_addr);
        if ( rc != 1 ) {
            VLOG_ERR("Failed to create L3 host entry. Invalid ipv6 address %s", ip_addr);
            return 1; /* Return error */
        }

        memcpy(l3host.l3a_ip6_addr, ipv6_dest_addr, sizeof(struct in6_addr));
    } else {
        /* convert string ip into host format */
        ipv4_dest_addr = inet_network(ip_addr);
        if ( ipv4_dest_addr == -1 ) {
            VLOG_ERR("Failed to create L3 host entry. Invalid ipv4 address %s", ip_addr);
            return 1; /* Return error */
        }

        VLOG_DBG("ipv4 addr converted = 0x%x", ipv4_dest_addr);
        l3host.l3a_ip_addr = ipv4_dest_addr;
    }

    l3host.l3a_intf = *l3_egress_id;
    l3host.l3a_vrf = vrf_id;
    l3host.l3a_flags = flags;
    rc = opennsl_l3_host_add(hw_unit, &l3host);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR ("opennsl_l3_host_add failed: rc=%s", opennsl_errmsg(rc));
        log_event("L3INTERFACE_ADD_HOST_ERR",
                  EV_KV("ipaddr", "%s", ip_addr),
                  EV_KV("egressid", "%d", *l3_egress_id),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }
    log_event("L3INTERFACE_ADD_HOST",
              EV_KV("ipaddr", "%s", ip_addr),
              EV_KV("egressid", "%d", *l3_egress_id));

    return rc;
} /* ops_routing_add_host_entry */

/* Function to delete l3 host entry via ofproto */
int
ops_routing_delete_host_entry(int hw_unit, opennsl_port_t hw_port,
                              opennsl_vrf_t vrf_id, bool is_ipv6_addr,
                              char *ip_addr, opennsl_if_t *l3_egress_id)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_host_t l3host;
    in_addr_t ipv4_dest_addr;
    char ipv6_dest_addr[sizeof(struct in6_addr)];
    int flags = 0;


    /* Delete an IP route / Host Entry */
    VLOG_DBG("In ops_routing_delete_host_entry for ip %s", ip_addr);
    opennsl_l3_host_t_init(&l3host);
    if( is_ipv6_addr ) {
        VLOG_DBG("ipv6 addr type");
        flags |= OPENNSL_L3_IP6;

        /* convert string ip into host format */
        rc = inet_pton(AF_INET6, ip_addr, ipv6_dest_addr);
        if ( rc != 1 ) {
            VLOG_ERR("invalid ipv6-%s", ip_addr);
            return 1; /* Return error */
        }

        memcpy(l3host.l3a_ip6_addr, ipv6_dest_addr, sizeof(struct in6_addr));
    } else {
        /* convert string ip into host format */
        ipv4_dest_addr = inet_network(ip_addr);
        if ( ipv4_dest_addr == -1 ) {
            VLOG_ERR("Invalid ip-%s", ip_addr);
            return 1; /* Return error */
        }

        VLOG_DBG("ipv4 addr converted =0x%x", ipv4_dest_addr);
        l3host.l3a_ip_addr = ipv4_dest_addr;
    }

    l3host.l3a_intf = *l3_egress_id;
    l3host.l3a_vrf = vrf_id;
    l3host.l3a_flags = flags;
    rc = opennsl_l3_host_delete(hw_unit, &l3host);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR ("opennsl_l3_host_delete failed: %s", opennsl_errmsg(rc));
        log_event("L3INTERFACE_DEL_HOST_ERR",
                  EV_KV("ipaddr", "%s", ip_addr),
                  EV_KV("egressid", "%d", *l3_egress_id),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }
    log_event("L3INTERFACE_DEL_HOST",
            EV_KV("ipaddr", "%s", ip_addr),
            EV_KV("egressid", "%d", *l3_egress_id));

    /* Delete the egress object */
    VLOG_DBG("Deleting egress object for egress-id %d", *l3_egress_id);
    rc = opennsl_l3_egress_destroy(hw_unit, *l3_egress_id);
    if (OPENNSL_FAILURE(rc)) {
       VLOG_ERR ("opennsl_egress_destroy failed: %s", opennsl_errmsg(rc));
        log_event("L3INTERFACE_DESTROY_EGRESS_OBJ_ERR",
                  EV_KV("port", "%d", hw_port),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }
    log_event("L3INTERFACE_DESTROY_EGRESS_OBJ",
            EV_KV("egress_id", "%d", *l3_egress_id),
            EV_KV("port", "%d", hw_port));

    *l3_egress_id = -1;
    return rc;
} /* ops_routing_delete_host_entry */

/* Ft to read and reset the host hit-bit */
int
ops_routing_get_host_hit(int hw_unit, opennsl_vrf_t vrf_id,
                         bool is_ipv6_addr, char *ip_addr, bool *hit_bit)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_host_t l3host;
    in_addr_t ipv4_dest_addr;
    char ipv6_dest_addr[sizeof(struct in6_addr)];
    int flags = 0;

    VLOG_DBG("In ops_routing_get_host_hit for ip %s", ip_addr);
    opennsl_l3_host_t_init(&l3host);
    if( is_ipv6_addr ) {
        VLOG_DBG("ipv6 addr type");
        flags |= OPENNSL_L3_IP6;

        /* convert string ip into host format */
        rc = inet_pton(AF_INET6, ip_addr, ipv6_dest_addr);
        if ( rc != 1 ) {
            VLOG_ERR("invalid ipv6-%s", ip_addr);
            return 1;
        }

        memcpy(l3host.l3a_ip6_addr, ipv6_dest_addr, sizeof(struct in6_addr));
    } else {
        /* convert string ip into host format */
        ipv4_dest_addr = inet_network(ip_addr);
        if ( ipv4_dest_addr == -1 ) {
            VLOG_ERR("Invalid ip-%s", ip_addr);
            return 1;
        }

        VLOG_DBG("ipv4 addr converted =0x%x", ipv4_dest_addr);
        l3host.l3a_ip_addr = ipv4_dest_addr;
    }

    /* Get Host Entry */
    l3host.l3a_vrf = vrf_id;
    l3host.l3a_flags = flags;
    rc = opennsl_l3_host_find(hw_unit, &l3host);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR ("opennsl_l3_host_find failed: %s", opennsl_errmsg(rc));
        return rc;
    } else {
        *hit_bit = (l3host.l3a_flags & OPENNSL_L3_HIT);
        VLOG_DBG("Got the hit-bit =0x%x", *hit_bit);
        if(*hit_bit) {
            l3host.l3a_flags = flags | OPENNSL_L3_HIT_CLEAR;
            /* Reset the hit-bit */
            rc = opennsl_l3_host_find(hw_unit, &l3host);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR ("Reset hit-bit failed: %s", opennsl_errmsg(rc));
                return rc;
            }
        }
    }

    return rc;
} /* ops_routing_get_host_hit */

/* Convert from string to ipv4/ipv6 prefix */
static int
ops_string_to_prefix(int family, char *ip_address, void *prefix,
                     unsigned char *prefixlen)
{
    char *p;
    char *tmp_ip_addr;
    int maxlen = (family == AF_INET) ? IPV4_PREFIX_LEN :
                                       IPV6_PREFIX_LEN;
    *prefixlen = maxlen;
    tmp_ip_addr = xstrdup(ip_address);

    if ((p = strchr(tmp_ip_addr, '/'))) {
        *p++ = '\0';
        *prefixlen = atoi(p);
    }

    if (*prefixlen > maxlen) {
        VLOG_DBG("Bad prefixlen %d > %d", *prefixlen, maxlen);
        free(tmp_ip_addr);
        return EINVAL;
    }

    if (family == AF_INET) {
        /* ipv4 address in host order */
        in_addr_t *addr = (in_addr_t*)prefix;
        *addr = inet_network(tmp_ip_addr);
        if (*addr == -1) {
            VLOG_ERR("Invalid ip address %s", ip_address);
            free(tmp_ip_addr);
            return EINVAL;
        }
    } else {
        /* ipv6 address */
        if (inet_pton(family, tmp_ip_addr, prefix) == 0) {
            VLOG_DBG("%d inet_pton failed with %s", family, strerror(errno));
            free(tmp_ip_addr);
            return EINVAL;
        }
    }

    free(tmp_ip_addr);
    return 0;
} /* ops_string_to_prefix */

static void
ops_update_ecmp_resilient(opennsl_l3_egress_ecmp_t *ecmp){

    if (ecmp == NULL){
        VLOG_ERR("ECMP group is NULL");
        return;
    }

    if (ecmp_resilient_flag) {
        ecmp->dynamic_mode |= OPENNSL_L3_ECMP_DYNAMIC_MODE_RESILIENT;
    } else {
        ecmp->dynamic_mode &=  ~OPENNSL_L3_ECMP_DYNAMIC_MODE_RESILIENT;
    }

    ecmp->dynamic_size = ecmp_resilient_flag ? ECMP_DYN_SIZE_64 :
                                               ECMP_DYN_SIZE_ZERO;
}

/* This function is to set the flags in the ecmp group for update */
static void ecmp_group_flags_set(opennsl_l3_egress_ecmp_t *ecmp_grp) {

    if (ecmp_resilient_flag) {
        ecmp_grp->flags = (OPENNSL_L3_ECMP_RH_REPLACE | OPENNSL_L3_WITH_ID);
    } else {
        ecmp_grp->flags = (OPENNSL_L3_REPLACE | OPENNSL_L3_WITH_ID);
    }
} /* ecmp_group_flags_set */

/* This function is to lookup the ecmp egress node from the hashmap */
static struct ecmp_egress_info *
ecmp_egress_node_lookup( char* ecmp_nexthop_str, opennsl_if_t *ecmp_intfp,
                         int hw_unit)
{
   struct ecmp_egress_info    *ecmp_egress_node;

   HMAP_FOR_EACH_WITH_HASH(ecmp_egress_node, node,
                  hash_string(ecmp_nexthop_str, 0), &ecmp_egress_nexthops_map) {
       if (ecmp_egress_node->hw_unit == hw_unit &&
           ecmp_egress_node->ecmp_grpid == *ecmp_intfp) {
           return ecmp_egress_node;
       }
   }

   return NULL;
} /* ecmp_egress_node_lookup */


/* Find or create and ecmp egress object */
static int
ops_create_or_update_ecmp_object(int hw_unit, struct ops_route *ops_routep,
                                 opennsl_if_t *old_ecmp_grpid, bool update,
                                 opennsl_l3_route_t *routep)
{
    int nh_count = 0;
    struct ops_nexthop *nh;
    opennsl_if_t egress_obj[MAX_NEXTHOPS_PER_ROUTE];
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_egress_ecmp_t ecmp_grp;
    char ecmp_grpid_str[ECMP_ID_MAX_LENGTH];
    struct ecmp_egress_info *old_ecmp_egress_node = NULL;

    if(!ops_routep) {
        return EINVAL;
    }

    HMAP_FOR_EACH(nh, node, &ops_routep->nexthops) {
        egress_obj[nh_count++] = nh->l3_egress_id;
        /* break once max ecmp is reached */
        if (nh_count == MAX_NEXTHOPS_PER_ROUTE) {
            break;
        }
    }

    if (update) {
        snprintf(ecmp_grpid_str, ECMP_ID_MAX_LENGTH, "%d", *old_ecmp_grpid);
        old_ecmp_egress_node = ecmp_egress_node_lookup(ecmp_grpid_str, old_ecmp_grpid, hw_unit);
    }

    opennsl_l3_egress_ecmp_t_init(&ecmp_grp);

    /* Checking the availability of an ecmp group */
    rc = opennsl_l3_egress_ecmp_find(hw_unit, nh_count, egress_obj, &ecmp_grp);
    if (rc == OPENNSL_E_NONE) {

        struct ecmp_egress_info *new_ecmp_egress_node = NULL;
        /* There is an ecmp egress object with same next hop interfaces */
        VLOG_DBG("ECMP group available %d for route %s", ecmp_grp.ecmp_intf,
                                                         ops_routep->prefix);
        snprintf(ecmp_grpid_str, ECMP_ID_MAX_LENGTH, "%d", ecmp_grp.ecmp_intf);
        new_ecmp_egress_node = ecmp_egress_node_lookup(ecmp_grpid_str,
                                               &ecmp_grp.ecmp_intf, hw_unit);
        assert(new_ecmp_egress_node);
        /* Increment referance count for existing ecmp egress object */
        new_ecmp_egress_node->ref_count++;
        if (old_ecmp_egress_node) {
            /* Decrement referance count for old ecmp egress object */
            old_ecmp_egress_node->ref_count--;
            VLOG_DBG("referance count decremented for %d", *old_ecmp_grpid);
        }
    } else {
        VLOG_DBG("ECMP group NOT available for route %s", ops_routep->prefix);
        if (old_ecmp_egress_node) {
            if (old_ecmp_egress_node->ref_count == 1) {
                /*
                 * In this case we update the existing ecmp object as the
                 * reference count is 1 and set the flags for update case
                 */
                ecmp_grp.ecmp_intf = *old_ecmp_grpid;
                ecmp_group_flags_set(&ecmp_grp);
            }
        }

        ops_update_ecmp_resilient(&ecmp_grp);

        /* creating ecmp egress object for new combination of egress nexthops */
        rc = opennsl_l3_egress_ecmp_create(hw_unit, &ecmp_grp, nh_count,
                                           egress_obj);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to update ecmp object for route %s: rc=%s",
                     ops_routep->prefix, opennsl_errmsg(rc));
            log_event("ECMP_CREATE_ERR",
                      EV_KV("route", "%s", ops_routep->prefix),
                      EV_KV("err", "%s", opennsl_errmsg(rc)));
            return rc;
        } else {
            VLOG_DBG("Succes in create/update ecmp object for route %s: rc=%s",
                     ops_routep->prefix, opennsl_errmsg(rc));
            log_event("ECMP_CREATE",
                      EV_KV("route", "%s", ops_routep->prefix));
        }

        /*
         * Insert into the ecmp egress hashmap when new create for route
         * and not an update on the existing ecmp egress object
         */
        if (!update || (old_ecmp_egress_node &&
                       (old_ecmp_egress_node->ref_count > 1))) {
            struct ecmp_egress_info *new_ecmp_egress_node = NULL;
            snprintf(ecmp_grpid_str, ECMP_ID_MAX_LENGTH, "%d",ecmp_grp.ecmp_intf);
            new_ecmp_egress_node = (struct ecmp_egress_info *)
                               xmalloc (sizeof(struct ecmp_egress_info));
            new_ecmp_egress_node->ref_count = 1;
            new_ecmp_egress_node->ecmp_grpid = ecmp_grp.ecmp_intf;
            new_ecmp_egress_node->hw_unit   = hw_unit;
            hmap_insert(&ecmp_egress_nexthops_map, &new_ecmp_egress_node->node,
                        hash_string(ecmp_grpid_str, 0));
            VLOG_DBG("New ecmp egress object %d hw_unit %d",
                     new_ecmp_egress_node->ecmp_grpid, hw_unit);
            if (old_ecmp_egress_node) {
                old_ecmp_egress_node->ref_count--;
                VLOG_DBG("referance count decremented for %d", *old_ecmp_grpid);
            }
        }
    }

    ops_routep->rstate = (ops_routep->n_nexthops > 1) ?
                         OPS_ROUTE_STATE_ECMP : OPS_ROUTE_STATE_NON_ECMP;
    /* Route pointing to exisiting or newly created object */
    routep->l3a_intf = ecmp_grp.ecmp_intf;
    rc = opennsl_l3_route_add(hw_unit, routep);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to add/update ECMP route %s: %s",
                ops_routep->prefix,
                opennsl_errmsg(rc));
        log_event("L3INTERFACE_ROUTE_ADD_ERR",
                  EV_KV("prefix", "%s", ops_routep->prefix),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    } else {
        VLOG_DBG("Success to add/update ECMP route %s",
                 ops_routep->prefix);
    }

    /* deleting old ecmp egress object if referance count is 0 */
    if (old_ecmp_egress_node && old_ecmp_egress_node->ref_count == 0) {

        ecmp_grp.ecmp_intf = *old_ecmp_grpid;
        rc = opennsl_l3_egress_ecmp_destroy(hw_unit, &ecmp_grp);
        if( OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to delete ecmp egress object %d: %s",
                     ecmp_grp.ecmp_intf, opennsl_errmsg(rc));
            log_event("ECMP_DELETE_ERR",
                      EV_KV("egressid", "%d", ecmp_grp.ecmp_intf),
                      EV_KV("err", "%s", opennsl_errmsg(rc)));
            return rc;
        }
        log_event("ECMP_DELETE",
                  EV_KV("egressid", "%d", ecmp_grp.ecmp_intf));
        hmap_remove(&ecmp_egress_nexthops_map,
                    &old_ecmp_egress_node->node);
        free(old_ecmp_egress_node);
    }

    return rc;
} /* ops_create_or_update_ecmp_object */

/* Delete ecmp object */
static int
ops_delete_ecmp_object(int hw_unit, opennsl_if_t ecmp_intf)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_egress_ecmp_t ecmp_grp;
    char ecmp_grpid_str[ECMP_ID_MAX_LENGTH];
    struct ecmp_egress_info  *ecmp_egress_node;

    opennsl_l3_egress_ecmp_t_init(&ecmp_grp);
    ecmp_grp.ecmp_intf = ecmp_intf;

    snprintf(ecmp_grpid_str, ECMP_ID_MAX_LENGTH, "%d", ecmp_grp.ecmp_intf);
    ecmp_egress_node = ecmp_egress_node_lookup(ecmp_grpid_str, &ecmp_grp.ecmp_intf, hw_unit);
    assert(ecmp_egress_node);
    ecmp_egress_node->ref_count--;
    if (ecmp_egress_node->ref_count == 0) {
        rc = opennsl_l3_egress_ecmp_destroy(hw_unit, &ecmp_grp);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to delete ecmp egress object %d: %s",
                     ecmp_intf, opennsl_errmsg(rc));
            log_event("ECMP_DELETE_ERR",
                      EV_KV("egressid", "%d", ecmp_intf),
                      EV_KV("err", "%s", opennsl_errmsg(rc)));
            return rc;
        }
        VLOG_DBG("ECMP egress object deleted  %d", ecmp_grp.ecmp_intf);
        log_event("ECMP_DELETE",
                  EV_KV("egressid", "%d", ecmp_intf));
        hmap_remove(&ecmp_egress_nexthops_map, &ecmp_egress_node->node);
        free(ecmp_egress_node);
    }

    return rc;
} /* ops_delete_ecmp_object */

/* add or update ECMP or non-ECMP route */
static int
ops_add_route_entry(int hw_unit, opennsl_vrf_t vrf_id,
                    struct ofproto_route *of_routep,
                    opennsl_l3_route_t *routep)
{
    struct ops_route *ops_routep;
    struct ops_nexthop *ops_nh;
    opennsl_if_t l3_intf;
    int rc;
    bool add_route = false;
    struct ofproto_route_nexthop *of_nh;

    /* assert for zero nexthop */
    assert(of_routep && (of_routep->n_nexthops > 0));

    /* look for prefix in LPM table*/
    rc = opennsl_l3_route_get(hw_unit, routep);

    /* Return error other than found / not found */
    if ((rc != OPENNSL_E_NOT_FOUND) &&
        (OPENNSL_FAILURE(rc))) {
        VLOG_ERR("Route lookup error: %s", opennsl_errmsg(rc));
        return rc;
    }

    /* new route */
    if (rc == OPENNSL_E_NOT_FOUND){
        /* add the route in local data structure */
        ops_routep = ops_route_add(vrf_id, of_routep);
        /* create or get ecmp object */
        if (ops_routep->n_nexthops > 1){
            routep->l3a_flags |= OPENNSL_L3_MULTIPATH;
            rc = ops_create_or_update_ecmp_object(hw_unit, ops_routep,
                                               &l3_intf, false,
                                               routep);
            if (OPS_FAILURE(rc)) {
                return rc;
            }
            return rc;
        } else {
            HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
                routep->l3a_intf = ops_nh->l3_egress_id;
            }
        }
        add_route = true;

        /* If there is only 1 nexthop and if the arp is unresolved,
         * set the OPENNSL_L3_RPE flag and set the priority in the l3a_pri
         * field to 15. (This is used by copp to identify if the packet is
         * destined to unknown IP cpu queue or not)
         * We set this only for non-ecmp next hops and directly connected
         * routes
         * FIXME: Need to take care of ECMP next hops case
         */
        if (of_routep->n_nexthops == 1) {
            of_nh = &of_routep->nexthops[0];
            VLOG_DBG("of_nh->state = %d", of_nh->state);
            if (of_nh->state != OFPROTO_NH_RESOLVED) {
                routep->l3a_flags |= OPENNSL_L3_RPE;
                routep->l3a_pri = OPS_COPP_UNKNOWN_IP_COS_RESERVED;
            }
        }

    } else {
        /* update route in local data structure */
        ops_routep = ops_route_lookup(vrf_id, of_routep);
        if (!ops_routep) {
            VLOG_ERR("Failed to find route %s", of_routep->prefix);
            return EINVAL;
        }

        ops_route_update(vrf_id, ops_routep, of_routep, false);

        switch (ops_routep->rstate) {
        case OPS_ROUTE_STATE_NON_ECMP:
            /* if nexthops becomes more than 1 */
            if (ops_routep->n_nexthops > 1) {
                routep->l3a_flags |= (OPENNSL_L3_MULTIPATH |
                                      OPENNSL_L3_REPLACE);
                rc = ops_create_or_update_ecmp_object(hw_unit, ops_routep,
                                                     &l3_intf, false,
                                                     routep);
                if (OPS_FAILURE(rc)) {
                    VLOG_ERR("Failed to create ecmp object for route %s: %s",
                              ops_routep->prefix, opennsl_errmsg(rc));
                    return rc;
                }
                return rc;
            } else {
                HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
                    routep->l3a_intf = ops_nh->l3_egress_id;
                    routep->l3a_flags &= ~OPENNSL_L3_MULTIPATH;
                    routep->l3a_flags |= OPENNSL_L3_REPLACE;
                }
            }
            break;
        case OPS_ROUTE_STATE_ECMP:
            /* update the ecmp table */
            l3_intf = routep->l3a_intf;
            routep->l3a_flags |= (OPENNSL_L3_MULTIPATH |
                                  OPENNSL_L3_REPLACE);
            rc = ops_create_or_update_ecmp_object(hw_unit, ops_routep,
                                                 &l3_intf, true,
                                                 routep);
            if (OPS_FAILURE(rc)) {
                VLOG_ERR("Failed to update ecmp object for route %s: %s",
                         ops_routep->prefix, opennsl_errmsg(rc));
            }
            return rc;
            break;
        default:
            break;
        }

    }
    ops_routep->rstate = (ops_routep->n_nexthops > 1) ?
                         OPS_ROUTE_STATE_ECMP : OPS_ROUTE_STATE_NON_ECMP;

    rc = opennsl_l3_route_add(hw_unit, routep);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to %s route %s: %s",
                add_route ? "add" : "update", of_routep->prefix,
                opennsl_errmsg(rc));
        log_event("L3INTERFACE_ROUTE_ADD_ERR",
                  EV_KV("prefix", "%s", of_routep->prefix),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
    } else {
        VLOG_DBG("Success to %s route %s: %s",
                add_route ? "add" : "update", of_routep->prefix,
                opennsl_errmsg(rc));
    }

    return rc;
} /* ops_add_route_entry */

/* Delete a route entry */
static int
ops_delete_route_entry(int hw_unit, opennsl_vrf_t vrf_id,
                       struct ofproto_route *of_routep,
                       opennsl_l3_route_t *routep)
{
    struct ops_route *ops_routep;
    opennsl_if_t l3_intf ;
    bool is_delete_ecmp = false;
    int rc;
    int reprogram_def_route;

    assert(of_routep);

    /* look for prefix in LPM table*/
    rc = opennsl_l3_route_get(hw_unit, routep);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Route lookup error: %s", opennsl_errmsg(rc));
        return rc;
    }

    /* route lookup in local data structure */
    ops_routep = ops_route_lookup(vrf_id, of_routep);
    if (!ops_routep) {
        VLOG_ERR("Failed to get route %s", of_routep->prefix);
        return EINVAL;
    }

    /* Check if this is same as default route */
    reprogram_def_route = is_default_route(hw_unit, of_routep,
                                           routep);

    /* Remove from local hash */
    ops_route_delete(ops_routep);

    if (routep->l3a_flags & OPENNSL_L3_MULTIPATH) {
        l3_intf = routep->l3a_intf;
        is_delete_ecmp = true;
    }

    rc = opennsl_l3_route_delete(hw_unit, routep);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to delete route %s: %s", of_routep->prefix,
                  opennsl_errmsg(rc));
        log_event("L3INTERFACE_ROUTE_DELETE_ERR",
                  EV_KV("prefix", "%s", of_routep->prefix),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
    } else {
        VLOG_DBG("Success to delete route %s: %s", of_routep->prefix,
                opennsl_errmsg(rc));
    }

    if (is_delete_ecmp) {
        rc = ops_delete_ecmp_object(hw_unit, l3_intf);
        log_event("ECMP_DELETE",
                EV_KV("route", "%s", of_routep->prefix));
    }

    /* Reprogram default route for ALPM mode */
    if (reprogram_def_route) {
        ops_add_default_routes(hw_unit);
    }

    return rc;
} /* ops_delete_route_entry */

/* Delete nexthop entry in route table */
static int
ops_delete_nh_entry(int hw_unit, opennsl_vrf_t vrf_id,
                    struct ofproto_route *of_routep,
                    opennsl_l3_route_t *routep)
{
    struct ops_route *ops_routep;
    struct ops_nexthop *ops_nh;
    opennsl_if_t l3_intf;
    bool is_delete_ecmp = false;
    int rc;

    /* assert for zero nexthop */
    assert(of_routep && (of_routep->n_nexthops > 0));

    /* look for prefix in LPM table*/
    rc = opennsl_l3_route_get(hw_unit, routep);

    /* Return error other than found / not found */
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Route lookup error: %s", opennsl_errmsg(rc));
        return rc;
    }

    /* route lookup in local data structure */
    ops_routep = ops_route_lookup(vrf_id, of_routep);
    if (!ops_routep) {
        VLOG_ERR("Failed to get route %s", of_routep->prefix);
        return EINVAL;
    }
    ops_route_update(vrf_id, ops_routep, of_routep, true);

    switch (ops_routep->rstate) {
    case OPS_ROUTE_STATE_NON_ECMP:
        HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
            routep->l3a_intf = ops_nh->l3_egress_id;
            routep->l3a_flags &= ~OPENNSL_L3_MULTIPATH;
            routep->l3a_flags |= OPENNSL_L3_REPLACE;
        }
        break;
    case OPS_ROUTE_STATE_ECMP:
        /* ecmp route to non-ecmp route*/
        if (ops_routep->n_nexthops < 2) {
            /* delete ecmp table if route has single nexthop */
            if (routep->l3a_flags & OPENNSL_L3_MULTIPATH) {
                /* store intf to delete ecmp object */
                l3_intf = routep->l3a_intf;
                is_delete_ecmp = true;
            }
            /* update with single nexthop */
            HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
                routep->l3a_intf = ops_nh->l3_egress_id;
            }
            routep->l3a_flags &= ~OPENNSL_L3_MULTIPATH;
            routep->l3a_flags |= OPENNSL_L3_REPLACE;
        } else {
            /* update the ecmp table */
            l3_intf = routep->l3a_intf;
            routep->l3a_flags |= (OPENNSL_L3_MULTIPATH |
                                  OPENNSL_L3_REPLACE);
            rc = ops_create_or_update_ecmp_object(hw_unit, ops_routep,
                                                 &l3_intf, true,
                                                 routep);
            if (OPS_FAILURE(rc)) {
                VLOG_ERR("Failed to update ecmp object for route %s: %s",
                              ops_routep->prefix, opennsl_errmsg(rc));
            }
            return rc;
            }
            break;
        default:
            break;
    }
    ops_routep->rstate = (ops_routep->n_nexthops > 1) ?
                          OPS_ROUTE_STATE_ECMP : OPS_ROUTE_STATE_NON_ECMP;

    rc = opennsl_l3_route_add(hw_unit, routep);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to (delete NH) update route %s: %s",
                  of_routep->prefix, opennsl_errmsg(rc));
        log_event("L3INTERFACE_ROUTE_DELETE_ERR",
                  EV_KV("prefix", "%s", of_routep->prefix),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    } else {
        VLOG_DBG("Success to (delete NH) update route %s: %s",
                  of_routep->prefix, opennsl_errmsg(rc));
    }

    if (is_delete_ecmp) {
        rc = ops_delete_ecmp_object(hw_unit, l3_intf);
    }

    return rc;
} /* ops_delete_nh_entry */

/* update the error */
static void
ops_update_nexthop_error(int ret_code, struct ofproto_route *of_routep)
{
    char *error_str = NULL;
    struct ofproto_route_nexthop *of_nh;

    if (OPENNSL_FAILURE(ret_code)) {
        error_str = opennsl_errmsg(ret_code);
    } else {
        error_str = strerror(ret_code);
    }

    for (int i = 0;  i < of_routep->n_nexthops; i++) {
        of_nh = &of_routep->nexthops[i];
        of_nh->err_str = error_str;
        of_nh->rc = ret_code;
    }
}/* ops_update_nexthop_error */

/* Add, delete route and nexthop */
int
ops_routing_route_entry_action(int hw_unit,
                               opennsl_vrf_t vrf_id,
                               enum ofproto_route_action action,
                               struct ofproto_route *routep)
{
    int rc = 0;
    opennsl_l3_route_t route;
    in_addr_t ipv4_addr;
    struct in6_addr ipv6_addr;
    uint8_t prefix_len;

    VLOG_DBG("%s: vrfid: %d, action: %d", __FUNCTION__, vrf_id, action);

    if (!routep && !routep->n_nexthops) {
        VLOG_ERR("route/nexthop entry null");
        return EINVAL; /* Return error */
    }

    opennsl_l3_route_t_init(&route);

    switch (routep->family) {
    case OFPROTO_ROUTE_IPV4:
        rc = ops_string_to_prefix(AF_INET, routep->prefix, &ipv4_addr,
                                  &prefix_len);
        if (rc) {
            VLOG_DBG("Invalid IPv4/Prefix");
            return rc; /* Return error */
        }
        route.l3a_subnet = ipv4_addr;
        route.l3a_ip_mask = opennsl_ip_mask_create(prefix_len);
        break;
    case OFPROTO_ROUTE_IPV6:
        rc = ops_string_to_prefix(AF_INET6, routep->prefix, &ipv6_addr,
                                  &prefix_len);
        if (rc) {
            VLOG_DBG("Invalid IPv6/Prefix");
            return rc; /* Return error */
        }
        route.l3a_flags |= OPENNSL_L3_IP6;
        memcpy(route.l3a_ip6_net, &ipv6_addr, sizeof(struct in6_addr));
        opennsl_ip6_mask_create(route.l3a_ip6_mask, prefix_len);
        break;
     default:
        VLOG_ERR ("Unknown protocol %d", routep->family);
        return EINVAL;

    }
    route.l3a_vrf = vrf_id;

    VLOG_DBG("action: %d, vrf: %d, prefix: %s, nexthops: %d",
              action, vrf_id, routep->prefix, routep->n_nexthops);

    switch (action) {
    case OFPROTO_ROUTE_ADD:
        rc = ops_add_route_entry(hw_unit, vrf_id, routep, &route);
        break;
    case OFPROTO_ROUTE_DELETE:
        rc = ops_delete_route_entry(hw_unit, vrf_id, routep, &route);
        break;
    case OFPROTO_ROUTE_DELETE_NH:
        rc = ops_delete_nh_entry(hw_unit, vrf_id, routep, &route);
        break;
    default:
        VLOG_ERR("Unknown route action %d", action);
        rc = EINVAL;
        break;
    }

    if ((action == OFPROTO_ROUTE_ADD) && OPS_FAILURE(rc)) {
        /* upadate the next hops error */
        ops_update_nexthop_error(rc, routep);
    }

    return rc;
} /* ops_routing_route_entry_action */

/* FIXME : Remove once these macros are exposed by opennsl */
#define opennslSwitchHashMultipath (135)
#define OPENNSL_HASH_ZERO          0x00000001
int
ops_routing_ecmp_set(int hw_unit, bool enable)
{
    int cur_cfg = 0;
    static int last_cfg;
    opennsl_error_t rc = OPENNSL_E_NONE;

    rc = opennsl_switch_control_get(hw_unit, opennslSwitchHashMultipath,
                                    &cur_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get opennslSwitchHashMultipath : unit=%d, rc=%s",
                 hw_unit, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }

    /* check if already in the desired state */
    if (((cur_cfg != OPENNSL_HASH_ZERO) && enable) ||
        ((cur_cfg == OPENNSL_HASH_ZERO) && !enable)) {
        return OPENNSL_E_NONE;
    }

    if (enable) { /* Enable ECMP */
        /* write back the config that existed before disabling */
        rc = opennsl_switch_control_set(hw_unit, opennslSwitchHashMultipath,
                                        last_cfg);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set opennslSwitchHashMultipath : unit=%d, rc=%s",
                     hw_unit, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
            return rc;
        }
    } else { /* Disable ECMP */
        /* save the current config before disabling */
        last_cfg = cur_cfg;
        rc = opennsl_switch_control_set(hw_unit, opennslSwitchHashMultipath,
                                        OPENNSL_HASH_ZERO);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to clear opennslSwitchHashMultipath : unit=%d, rc=%s",
                    hw_unit, opennsl_errmsg(rc));
            log_event("ECMP_ERR",
                    EV_KV("err", "%s", opennsl_errmsg(rc)));
            return rc;
        }
    }
    return OPENNSL_E_NONE;
}

int
ops_routing_ecmp_hash_set(int hw_unit, unsigned int hash, bool status)
{
    int hash_v4 = 0, hash_v6 = 0;
    int cur_hash_ip4 = 0, cur_hash_ip6 = 0;
    opennsl_error_t rc = OPENNSL_E_NONE;

    rc = opennsl_switch_control_get(hw_unit, opennslSwitchHashIP4Field0,
                                    &cur_hash_ip4);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get opennslSwitchHashIP4Field0 : unit=%d, rc=%s",
                hw_unit, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }
    rc = opennsl_switch_control_get(hw_unit, opennslSwitchHashIP6Field0,
                                    &cur_hash_ip6);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get opennslSwitchHashIP6Field0 : unit=%d, rc=%s",
                 hw_unit, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }

    if (hash & OFPROTO_ECMP_HASH_SRCPORT) {
        hash_v4 |= OPENNSL_HASH_FIELD_SRCL4;
        hash_v6 |= OPENNSL_HASH_FIELD_SRCL4;
    }
    if (hash & OFPROTO_ECMP_HASH_DSTPORT) {
        hash_v4 |= OPENNSL_HASH_FIELD_DSTL4;
        hash_v6 |= OPENNSL_HASH_FIELD_DSTL4;
    }
    if (hash & OFPROTO_ECMP_HASH_SRCIP) {
        hash_v4 |= OPENNSL_HASH_FIELD_IP4SRC_LO | OPENNSL_HASH_FIELD_IP4SRC_HI;
        hash_v6 |= OPENNSL_HASH_FIELD_IP6SRC_LO | OPENNSL_HASH_FIELD_IP6SRC_HI;
    }
    if (hash & OFPROTO_ECMP_HASH_DSTIP) {
        hash_v4 |= OPENNSL_HASH_FIELD_IP4DST_LO | OPENNSL_HASH_FIELD_IP4DST_HI;
        hash_v6 |= OPENNSL_HASH_FIELD_IP6DST_LO | OPENNSL_HASH_FIELD_IP6DST_HI;
    }

    if ((hash & OFPROTO_ECMP_HASH_RESILIENT)) {
        if (ecmp_resilient_flag != status) {
            ecmp_resilient_flag = status;
            rc = opennsl_l3_egress_ecmp_traverse(hw_unit,
                                      ops_update_l3ecmp_egress_resilient, NULL);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to traverse ECMP groups rc=%s",
                        opennsl_errmsg(rc));
                log_event("ECMP_ERR",
                        EV_KV("err", "%s", opennsl_errmsg(rc)));
            }
        }
    }


    if (status) {
        cur_hash_ip4 |= hash_v4;
        cur_hash_ip6 |= hash_v6;
    } else {
        cur_hash_ip4 &= ~hash_v4;
        cur_hash_ip6 &= ~hash_v6;
    }

    rc = opennsl_switch_control_set(hw_unit,
                                    opennslSwitchHashIP4TcpUdpPortsEqualField0,
                                    cur_hash_ip4);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4TcpUdpPortsEqualField0:"
                 "unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip4, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(hw_unit,
                                    opennslSwitchHashIP4TcpUdpField0,
                                    cur_hash_ip4);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4TcpUdpPortsEqualField0:"
                 "unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip4, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(hw_unit, opennslSwitchHashIP4Field0,
                                    cur_hash_ip4);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4Field0 : unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip4, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }

    rc = opennsl_switch_control_set(hw_unit,
                                    opennslSwitchHashIP6TcpUdpPortsEqualField0,
                                    cur_hash_ip6);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6TcpUdpPortsEqualField0:"
                 "unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip6, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(hw_unit,
                                    opennslSwitchHashIP6TcpUdpField0,
                                    cur_hash_ip6);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6TcpUdpPortsEqualField0:"
                 "unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip6, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                EV_KV("err", "%s", opennsl_errmsg(rc)));
        return 1;
    }
    rc = opennsl_switch_control_set(hw_unit, opennslSwitchHashIP6Field0,
                                    cur_hash_ip6);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6Field0 : unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip6, opennsl_errmsg(rc));
        log_event("ECMP_ERR",
                EV_KV("err", "%s", opennsl_errmsg(rc)));
        return rc;
    }

    return OPENNSL_E_NONE;
}

/*
** FIXME: Combine above neighbor l3_host_add/delete to use common
** host action routine.
*/
/*
** Add/Delete local host entries.
*/
int
ops_routing_host_entry_action(int hw_unit, opennsl_vrf_t vrf_id,
                              enum ofproto_host_action action,
                              struct ofproto_l3_host *host_info)
{
    int rc = OPENNSL_E_NONE;
    opennsl_l3_host_t l3host;
    in_addr_t ipv4_addr;
    struct in6_addr ipv6_addr;
    uint8_t prefix_len;
    int flags = OPENNSL_L3_HOST_LOCAL;

    VLOG_DBG("%s: vrfid: %d, action: %d", __FUNCTION__, vrf_id, action);

    if (!host_info) {
        VLOG_ERR("Null host entry");
        return EINVAL; /* Return error */
    }

    opennsl_l3_host_t_init(&l3host);
    if (host_info->family == OFPROTO_ROUTE_IPV6) {
        flags |= OPENNSL_L3_IP6;
        rc = ops_string_to_prefix(AF_INET6, host_info->ip_address, &ipv6_addr,
                                  &prefix_len);
        if (rc) {
            VLOG_DBG("Invalid IPv6/Prefix");
            return rc; /* Return error */
        }
        memcpy(l3host.l3a_ip6_addr, &ipv6_addr, sizeof(struct in6_addr));
    } else {
        rc = ops_string_to_prefix(AF_INET, host_info->ip_address, &ipv4_addr,
                                  &prefix_len);
        if (rc) {
            VLOG_DBG("Invalid IPv4/Prefix");
            return rc; /* Return error */
        }
        l3host.l3a_ip_addr = ipv4_addr;
    }

    /* Fill the host info, and try to find first */
    l3host.l3a_vrf = vrf_id;
    l3host.l3a_flags = flags;
    rc = opennsl_l3_host_find(hw_unit, &l3host);

    switch (action) {
    case OFPROTO_HOST_ADD:
        if (rc == OPENNSL_E_NOT_FOUND) {
            /* Use system wide dummy egress object id */
            l3host.l3a_intf = local_nhid;
            rc = opennsl_l3_host_add(hw_unit, &l3host);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR ("opennsl_l3_host_add failed: %s", opennsl_errmsg(rc));
                log_event("L3INTERFACE_ERR",
                        EV_KV("err", "%s", opennsl_errmsg(rc)));
            }
        } else {
            VLOG_DBG ("Host entry exists: 0x%x", rc);
        }
        break;
    case OFPROTO_HOST_DELETE:
        if (rc != OPENNSL_E_NOT_FOUND) {
            /* Use system wide dummy egress object id */
            l3host.l3a_intf = local_nhid;
            rc = opennsl_l3_host_delete(hw_unit, &l3host);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR ("opennsl_l3_host_delete failed: %s", opennsl_errmsg(rc));
                log_event("L3INTERFACE_ERR",
                        EV_KV("err", "%s", opennsl_errmsg(rc)));
            }
        } else {
            VLOG_DBG ("Host entry doesn't exists: 0x%x", rc);
        }
        break;
    default:
        VLOG_ERR("Unknown l3 host action %d", action);
        rc = EINVAL;
        break;
    }

    return rc;
} /* ops_routing_route_entry_action */

static void
l3_intf_print(struct ds *ds, int unit, int print_hdr,
              opennsl_l3_intf_t *intf)
{
    char if_mac_str[SAL_MACADDR_STR_LEN];

    if (NULL == intf) {
        return;
    }

    if (print_hdr) {
         ds_put_format(ds ,"Unit  Intf  VRF VLAN    Source Mac     MTU TTL\n");
         ds_put_format(ds ,"----------------------------------------------\n");
    }

    snprintf(if_mac_str, SAL_MACADDR_STR_LEN, "%s",
             ether_ntoa((struct ether_addr*)intf->l3a_mac_addr));

    ds_put_format(ds ,"%-5d %-5d %-5d %-4d %-18s %-4d %-4d\n",
                  unit, intf->l3a_intf_id, intf->l3a_vrf, intf->l3a_vid,
                  if_mac_str, intf->l3a_mtu, intf->l3a_ttl);
    return;
} /* l3_intf_print */

static struct ops_mac_move_egress_id *
ops_egress_id_lookup(char*egress_id_key_l)
{
   struct ops_mac_move_egress_id    *egress_id_node;

   HMAP_FOR_EACH_WITH_HASH(egress_id_node, node, hash_string(egress_id_key_l, 0),
                                               &ops_mac_move_egress_id_map) {
           return egress_id_node;
   }

   return NULL;
}

void
ops_l3_mac_move_add(int   unit,
                    opennsl_l2_addr_t  *l2addr,
                    void   *userdata)
{
   opennsl_l3_egress_t     egress_object;
   opennsl_error_t         rc = OPENNSL_E_NONE;
   struct ops_mac_move_egress_id    *egress_id_node;

   if (!(l2addr->flags & OPENNSL_L2_MOVE_PORT)) {
       /* Only handle ADD due to mac-move */
       return;
   }

   /* ADD call, due to mac-move. */

   memset(egress_id_key, 0, sizeof(egress_id_key));
   snprintf(egress_id_key, 24, "%d:" ETH_ADDR_FMT, l2addr->vid,
                               ETH_ADDR_BYTES_ARGS(l2addr->mac));

   egress_id_node = ops_egress_id_lookup(egress_id_key);
   if (egress_id_node == NULL) {
       VLOG_DBG("Egress object id NOT found in process cache, possibly "
                 "deleted: unit=%d, key=%s, vlan=%d, mac=" ETH_ADDR_FMT,
                 unit, egress_id_key, l2addr->vid, ETH_ADDR_BYTES_ARGS(l2addr->mac));

       /* Unexpected condition. This shouldn't happen. */
       return;
   }

   opennsl_l3_egress_t_init(&egress_object);

   /* Using egress id, get egress object from ASIC */
   rc = opennsl_l3_egress_get(unit, egress_id_node->egress_object_id, &egress_object);

   if (OPENNSL_FAILURE(rc)) {
       VLOG_ERR("Egress object not found in ASIC for given vlan/mac. rc=%s "
               "unit=%d, key=%s, vlan=%d, mac=" ETH_ADDR_FMT ", egr-id: %d",
               opennsl_errmsg(rc), unit, egress_id_key, l2addr->vid,
               ETH_ADDR_BYTES_ARGS(l2addr->mac), egress_id_node->egress_object_id);
       log_event("L3INTERFACE_ERR",
               EV_KV("err", "%s", opennsl_errmsg(rc)));

       goto done;
   }

   egress_object.flags    |= (OPENNSL_L3_REPLACE|OPENNSL_L3_WITH_ID);
   egress_object.port     = l2addr->port;  /* new port */
   /* L3 intf will remain unchanged */

   VLOG_DBG("Input: unit=%d, flags=0x%x, port=%d, vlan=%d, mac=" ETH_ADDR_FMT
             " egr-id=%d, intf=%d", unit, egress_object.flags, egress_object.port,
             egress_object.vlan, ETH_ADDR_BYTES_ARGS(egress_object.mac_addr),
             egress_id_node->egress_object_id, egress_object.intf);

   rc = opennsl_l3_egress_create(unit, egress_object.flags, &egress_object,
                                   &(egress_id_node->egress_object_id));
   if (OPENNSL_FAILURE(rc)) {
       VLOG_ERR("Failed creation of egress object: rc=%s, unit=%d", opennsl_errmsg(rc), unit);
        log_event("L3INTERFACE_CREATE_EGRESS_OBJ_ERR",
                  EV_KV("port", "%d", egress_object.port),
                  EV_KV("err", "%s", opennsl_errmsg(rc)));
       goto done;
   }
   log_event("L3INTERFACE_CREATE_EGRESS_OBJ",
           EV_KV("egress_id", "%d", egress_id_node->egress_object_id),
           EV_KV("port", "%d", egress_object.port),
           EV_KV("intf", "%d", egress_object.intf));

done:
   /* remove hmap entry for given mac/vlan */
   hmap_remove(&ops_mac_move_egress_id_map, &egress_id_node->node);
}

void
ops_l3_mac_move_delete(int   unit,
                       opennsl_l2_addr_t  *l2addr,
                       void   *userdata)
{
   opennsl_l3_egress_t     egress_object;
   opennsl_if_t            egress_object_id;
   struct ops_mac_move_egress_id   *egress_node;
   opennsl_error_t         rc = OPENNSL_E_NONE;

   if (!(l2addr->flags & OPENNSL_L2_MOVE_PORT)) {
       /* Only handle DELTE due to mac-move */
       return;
   }

   /* DELETE call due to mac-move */

   memset(egress_id_key, 0, sizeof(egress_id_key));
   snprintf(egress_id_key, 24, "%d:" ETH_ADDR_FMT, l2addr->vid,
                               ETH_ADDR_BYTES_ARGS(l2addr->mac));

   /* Create an egress object with old/deleted port and save in hashmap */

   opennsl_l3_egress_t_init(&egress_object);
   memcpy(egress_object.mac_addr, l2addr->mac, ETH_ALEN);
   egress_object.vlan     = l2addr->vid;
   egress_object.port     = l2addr->port; /* old/deleted port */
   egress_object.intf     = l2addr->vid;  /* l3 intf is same as vlanid */

   /* egress_id is the id of row containing egress_object in ASIC */
   opennsl_l3_egress_find(unit, &egress_object, &egress_object_id);
   if (OPENNSL_FAILURE(rc)) {
       VLOG_ERR("Failed retrieving egress object id: rc=%s, unit=%d, vlan=%d, "
                "mac=" ETH_ADDR_FMT, opennsl_errmsg(rc), unit, l2addr->vid,
                ETH_ADDR_BYTES_ARGS(l2addr->mac));

       return;
   }

   /* add the egress id to hashmap */
   egress_node = (struct ops_mac_move_egress_id *) xmalloc(sizeof(struct
                                                   ops_mac_move_egress_id));
   if (egress_node == NULL) {
       VLOG_ERR("Failed allocating memory to ops_mac_move_egress_id: "
                "unit=%d", unit);
       return;
   }
   egress_node->egress_object_id = egress_object_id;
   hmap_insert(&ops_mac_move_egress_id_map, &egress_node->node, hash_string(egress_id_key, 0));
}

void
ops_l3intf_dump(struct ds *ds, int intfid)
{
    int               unit;
    int               rv;
    int               free_l3intf;
    opennsl_l3_info_t l3_hw_status;
    opennsl_l3_intf_t intf;
    int               print_hdr = TRUE;

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        rv = opennsl_l3_info(unit, &l3_hw_status);
        if (OPENNSL_FAILURE(rv)){
            VLOG_ERR("Error in L3 info access: %s\n",
                     opennsl_errmsg(rv));
            return;
        }

        free_l3intf = l3_hw_status.l3info_max_intf -
                      l3_hw_status.l3info_used_intf;

        if (intfid != -1) {
            if ((intfid < 0) || (intfid > l3_hw_status.l3info_max_intf)) {
                VLOG_ERR("Invalid interface index: %d\n", intfid);
                return;
            }
        }
        ds_put_format(ds, "Free L3INTF entries: %d\n", free_l3intf);

        if (intfid != -1) {
            opennsl_l3_intf_t_init(&intf);
            intf.l3a_intf_id = intfid;
            rv = opennsl_l3_intf_get(unit, &intf);
            if (OPENNSL_SUCCESS(rv)) {
                l3_intf_print(ds, unit, TRUE, &intf);
                return ;
            } else {
                VLOG_ERR("Error L3 interface %d: %s\n", intfid,
                         opennsl_errmsg(rv));
                return;
            }
       } else {
            /* Note: last interface id is reserved for Copy To CPU purposes. */
            for (intfid = 0; intfid < l3_hw_status.l3info_max_intf - 1;
                 intfid++) {
                opennsl_l3_intf_t_init(&intf);
                intf.l3a_intf_id = intfid;
                rv = opennsl_l3_intf_get(unit, &intf);
                if (OPENNSL_SUCCESS(rv)) {
                    l3_intf_print(ds, unit, print_hdr, &intf);
                    print_hdr = FALSE;
                } else if (rv == OPENNSL_E_NOT_FOUND) {
                    continue;
                } else if (OPENNSL_FAILURE(rv)) {
                    VLOG_ERR("Error traverse l3 interfaces: %s\n",
                             opennsl_errmsg(rv));
                }
            }
        }
    }
} /* ops_l3intf_dump */

int ops_host_print(int unit, int index, opennsl_l3_host_t *info,
                   void *user_data)
{
    char *hit;
    char *trunk = " ";
    int     port = 0;
    struct ds *pds = (struct ds *)user_data;

    hit = (info->l3a_flags & OPENNSL_L3_HIT) ? "y" : "n";

    if (info->l3a_flags & OPENNSL_L3_TGID) {
        trunk = "t" ;
    }
    port = info->l3a_port_tgid;

    if (info->l3a_flags & OPENNSL_L3_IP6) {
        char ip_str[IPV6_BUFFER_LEN];
        sprintf(ip_str, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
            (((uint16)info->l3a_ip6_addr[0] << 8) | info->l3a_ip6_addr[1]),
            (((uint16)info->l3a_ip6_addr[2] << 8) | info->l3a_ip6_addr[3]),
            (((uint16)info->l3a_ip6_addr[4] << 8) | info->l3a_ip6_addr[5]),
            (((uint16)info->l3a_ip6_addr[6] << 8) | info->l3a_ip6_addr[7]),
            (((uint16)info->l3a_ip6_addr[8] << 8) | info->l3a_ip6_addr[9]),
            (((uint16)info->l3a_ip6_addr[10] << 8) | info->l3a_ip6_addr[11]),
            (((uint16)info->l3a_ip6_addr[12] << 8) | info->l3a_ip6_addr[13]),
            (((uint16)info->l3a_ip6_addr[14] << 8) | info->l3a_ip6_addr[15]));

        ds_put_format(pds, "%-6d %-4d %-42s %d %4d%s %5s\n", index,
                info->l3a_vrf, ip_str, info->l3a_intf,
                port, trunk, hit);
    } else {
        char ip_str[IPV4_BUFFER_LEN];
        sprintf(ip_str, "%d.%d.%d.%d",
            (info->l3a_ip_addr >> 24) & 0xff, (info->l3a_ip_addr >> 16) & 0xff,
            (info->l3a_ip_addr >> 8) & 0xff, info->l3a_ip_addr & 0xff);

        ds_put_format(pds,"%-6d %-4d %-16s %2d %4d%s %6s\n",
                index, info->l3a_vrf, ip_str, info->l3a_intf,
                port, trunk, hit);
    }

    return OPENNSL_E_NONE;
} /*ops_host_print*/

void
ops_l3host_dump(struct ds *ds, int ipv6_enabled)
{
    int               unit = 0;
    int               rv;
    int               last_entry;
    int               first_entry;
    opennsl_l3_info_t l3_hw_status;

    rv = opennsl_l3_info(unit, &l3_hw_status);
    if (OPENNSL_FAILURE(rv)){
        VLOG_ERR("Error in L3 info access: %s\n",opennsl_errmsg(rv));
        return;
    }

    last_entry = l3_hw_status.l3info_max_host;
    first_entry = 0;

    if (ipv6_enabled == TRUE) {
        ds_put_format(ds ,"Entry VRF                 IP address                 "
                          "INTF PORT    HIT \n");
        ds_put_format(ds ,"------------------------------------------------"
                           "---------------------\n");
        opennsl_l3_host_traverse(unit, OPENNSL_L3_IP6, first_entry, last_entry,
                                 &ops_host_print, ds);
    } else {
        ds_put_format(ds ,"Entry VRF     IP address     INTF PORT    HIT \n");
        ds_put_format(ds ,"-----------------------------------------------\n");
        opennsl_l3_host_traverse(unit, 0, first_entry, last_entry,
                                 &ops_host_print, ds);
    }

} /* ops_l3host_dump */

int ops_route_print(int unit, int index, opennsl_l3_route_t *info,
                    void *user_data)
{
    char *hit;
    char *ecmp_str;
    struct ds *pds = (struct ds *)user_data;

    hit = (info->l3a_flags & OPENNSL_L3_HIT) ? "Y" : "N";
    ecmp_str = (info->l3a_flags & OPENNSL_L3_MULTIPATH) ? "(ECMP)" : "";

    if (info->l3a_flags & OPENNSL_L3_IP6) {
        char subnet_str[IPV6_BUFFER_LEN];
        char subnet_mask[IPV6_BUFFER_LEN];
        sprintf(subnet_str, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
            (((uint16)info->l3a_ip6_net[0] << 8) | info->l3a_ip6_net[1]),
            (((uint16)info->l3a_ip6_net[2] << 8) | info->l3a_ip6_net[3]),
            (((uint16)info->l3a_ip6_net[4] << 8) | info->l3a_ip6_net[5]),
            (((uint16)info->l3a_ip6_net[6] << 8) | info->l3a_ip6_net[7]),
            (((uint16)info->l3a_ip6_net[8] << 8) | info->l3a_ip6_net[9]),
            (((uint16)info->l3a_ip6_net[10] << 8) | info->l3a_ip6_net[11]),
            (((uint16)info->l3a_ip6_net[12] << 8) | info->l3a_ip6_net[13]),
            (((uint16)info->l3a_ip6_net[14] << 8) | info->l3a_ip6_net[15]));
        sprintf(subnet_mask, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
            (((uint16)info->l3a_ip6_mask[0] << 8) | info->l3a_ip6_mask[1]),
            (((uint16)info->l3a_ip6_mask[2] << 8) | info->l3a_ip6_mask[3]),
            (((uint16)info->l3a_ip6_mask[4] << 8) | info->l3a_ip6_mask[5]),
            (((uint16)info->l3a_ip6_mask[6] << 8) | info->l3a_ip6_mask[7]),
            (((uint16)info->l3a_ip6_mask[8] << 8) | info->l3a_ip6_mask[9]),
            (((uint16)info->l3a_ip6_mask[10] << 8) | info->l3a_ip6_mask[11]),
            (((uint16)info->l3a_ip6_mask[12] << 8) | info->l3a_ip6_mask[13]),
            (((uint16)info->l3a_ip6_mask[14] << 8) | info->l3a_ip6_mask[15]));

        ds_put_format(pds, "%-6d %-4d %-42s %-42s %2d %4s %s\n", index,
                      info->l3a_vrf, subnet_str, subnet_mask, info->l3a_intf,
                      hit, ecmp_str);
    } else {
        char subnet_str[IPV4_BUFFER_LEN];
        char subnet_mask[IPV4_BUFFER_LEN];
        sprintf(subnet_str, "%d.%d.%d.%d",
            (info->l3a_subnet >> 24) & 0xff, (info->l3a_subnet >> 16) & 0xff,
            (info->l3a_subnet >> 8) & 0xff, info->l3a_subnet & 0xff);
        sprintf(subnet_mask, "%d.%d.%d.%d",
            (info->l3a_ip_mask >> 24) & 0xff, (info->l3a_ip_mask >> 16) & 0xff,
            (info->l3a_ip_mask >> 8) & 0xff, info->l3a_ip_mask & 0xff);

        ds_put_format(pds,"%-6d %-4d %-16s %-16s %2d %5s %s\n", index,
                      info->l3a_vrf, subnet_str, subnet_mask, info->l3a_intf,
                      hit, ecmp_str);
    }
    return OPENNSL_E_NONE;
} /*ops_route_print*/

void
ops_l3route_dump(struct ds *ds, int ipv6_enabled)
{
    int               unit = 0;
    int               rv;
    int               last_entry;
    int               first_entry;
    opennsl_l3_info_t l3_hw_status;

    rv = opennsl_l3_info(unit, &l3_hw_status);
    if (OPENNSL_FAILURE(rv)){
        VLOG_ERR("Error in L3 info access: %s\n",opennsl_errmsg(rv));
        return;
    }

    last_entry = l3_hw_status.l3info_max_route;
    first_entry = 0;
    /*
     * FIXME: We need the l3info_used_route to display the number of
     * entries used
     */

    if (ipv6_enabled == TRUE) {
        int ipv6_hash = 0;
        rv = opennsl_switch_control_get(unit, opennslSwitchHashIP6Field0,
                                        &ipv6_hash);
        if (OPENNSL_FAILURE(rv)){
            VLOG_ERR("Error in get opennslSwitchHashIP6Field0: %s\n",
                      opennsl_errmsg(rv));
            return;
        }
        ds_put_format(ds ,"ECMP IPv6 hash\n");
        ds_put_format(ds ,"Src Addr    Dst Addr    Src Port    Dst Port\n");
        ds_put_format(ds ,"--------------------------------------------\n");
        ds_put_format(ds ,"%4s %11s %11s %11s\n\n",
                          ((ipv6_hash & OPENNSL_HASH_FIELD_IP6SRC_LO) ||
                           (ipv6_hash & OPENNSL_HASH_FIELD_IP6SRC_HI)) ? "Y" : "N",
                          ((ipv6_hash & OPENNSL_HASH_FIELD_IP6DST_LO) ||
                           (ipv6_hash & OPENNSL_HASH_FIELD_IP6DST_HI)) ? "Y" : "N",
                          (ipv6_hash & OPENNSL_HASH_FIELD_SRCL4) ? "Y" : "N",
                          (ipv6_hash & OPENNSL_HASH_FIELD_DSTL4) ? "Y" : "N");
        ds_put_format(ds ,"Entry VRF                Subnet                      "
                      "                 Mask                         I/F     HIT \n");
        ds_put_format(ds ,"-----------------------------------------------------"
                      "----------------------------------------------------------\n");
        opennsl_l3_route_traverse(unit, OPENNSL_L3_IP6, first_entry, last_entry,
                                 &ops_route_print, ds);
    } else {
        int ipv4_hash = 0;
        rv = opennsl_switch_control_get(unit, opennslSwitchHashIP4Field0,
                                        &ipv4_hash);
        if (OPENNSL_FAILURE(rv)){
            VLOG_ERR("Error in get opennslSwitchHashIP4Field0: %s\n",
                      opennsl_errmsg(rv));
            return;
        }
        ds_put_format(ds ,"ECMP IPv4 hash\n");
        ds_put_format(ds ,"Src Addr    Dst Addr    Src Port    Dst Port\n");
        ds_put_format(ds ,"--------------------------------------------\n");
        ds_put_format(ds ,"%4s %11s %11s %11s\n\n",
                          ((ipv4_hash & OPENNSL_HASH_FIELD_IP4SRC_LO) ||
                           (ipv4_hash & OPENNSL_HASH_FIELD_IP4SRC_HI)) ? "Y" : "N",
                          ((ipv4_hash & OPENNSL_HASH_FIELD_IP4DST_LO) ||
                           (ipv4_hash & OPENNSL_HASH_FIELD_IP4DST_HI)) ? "Y" : "N",
                          (ipv4_hash & OPENNSL_HASH_FIELD_SRCL4) ? "Y" : "N",
                          (ipv4_hash & OPENNSL_HASH_FIELD_DSTL4) ? "Y" : "N");
        ds_put_format(ds, "Entry VRF    Subnet             Mask            I/F     HIT \n");
        ds_put_format(ds ,"------------------------------------------------------------\n");

        opennsl_l3_route_traverse(unit, 0, first_entry, last_entry,
                                 &ops_route_print, ds);
    }

} /* ops_l3route_dump */

static int
l3_egress_print(int unit, int index, opennsl_l3_egress_t *info, void *user_data)
{
    char mac_str[SAL_MACADDR_STR_LEN];
    struct ds *pds = (struct ds *)user_data;

    snprintf(mac_str, SAL_MACADDR_STR_LEN, "%s",
             ether_ntoa((struct ether_addr*)info->mac_addr));

    ds_put_format(pds ,"%d %-18s %4d %4d %4d %4s %4s\n",
                  index, mac_str, info->vlan, info->intf, info->port,
                  (info->flags & OPENNSL_L3_COPY_TO_CPU) ? "yes" : "no",
                  (info->flags & OPENNSL_L3_DST_DISCARD) ? "yes" : "no");

    return 0;
} /* l3_egress_print */

void
ops_l3egress_dump(struct ds *ds, int egressid)
{
    int unit = 0;
    opennsl_error_t rc;
    opennsl_l3_egress_t egress_object;

    ds_put_format(ds ,"Entry      Mac             Vlan INTF PORT ToCpu Drop\n");
    ds_put_format(ds ,"-----------------------------------------------------\n");

    /* single egress object */
    if (egressid != -1) {
        opennsl_l3_egress_t_init(&egress_object);
        rc = opennsl_l3_egress_get(unit, egressid, &egress_object);
        if (OPENNSL_FAILURE(rc)){
            VLOG_ERR("Error reading egress entry %d: %s\n", egressid,
                     opennsl_errmsg(rc));
            return;
        } else {
           l3_egress_print(unit, egressid, &egress_object, ds);
        }
    } else {
        rc = opennsl_l3_egress_traverse(unit, l3_egress_print, ds);
        if (OPENNSL_FAILURE(rc)){
            VLOG_ERR("Error reading egress table: %s\n", opennsl_errmsg(rc));
            return;
        }
    }
} /* ops_l3egress_dump */

static int
l3ecmp_egress_print(int unit, opennsl_l3_egress_ecmp_t *ecmp,
                    int intf_count, opennsl_if_t *info, void *user_data)
{
    int idx;
    struct ds *pds = (struct ds *)user_data;
    ds_put_format(pds, "Multipath Egress Object %d\n", ecmp->ecmp_intf);
    ds_put_format(pds, "ECMP Resilient %s\n", ecmp->dynamic_mode ? "TRUE": "FALSE");
    ds_put_format(pds, "dynamic size %d\n", ecmp->dynamic_size);
    ds_put_format(pds, "Interfaces:");

    for (idx = 0; idx < intf_count; idx++) {
        ds_put_format(pds, " %d", info[idx]);
        if (idx && (!(idx % 10))) {
            ds_put_format(pds, "\n           ");
        }
    }
    ds_put_format(pds, "\n");

    return 0;
} /*l3ecmp_egress_print */

static int
ops_update_l3ecmp_egress_resilient(int unit, opennsl_l3_egress_ecmp_t *ecmp,
                    int intf_count, opennsl_if_t *egress_obj, void *user_data)
{
    opennsl_error_t rc;

    ops_update_ecmp_resilient(ecmp);
    ecmp->flags = (OPENNSL_L3_REPLACE | OPENNSL_L3_WITH_ID);

    /*updating the egress object based on whether
     * the ecmp resilient flag is set or reset */
    VLOG_DBG(" ECMP dynamic mode %d , interface count %d,dynamic size :%u"
            "ecmp_resilient_flag:%d \n", ecmp->dynamic_mode, intf_count,
             ecmp->dynamic_size, ecmp_resilient_flag);
    rc = opennsl_l3_egress_ecmp_create(unit , ecmp, intf_count, egress_obj);

    if (OPENNSL_FAILURE(rc)){
        VLOG_ERR("Error creating/udpating the ecmp egress object" \
                  "%s\n", opennsl_errmsg(rc));
    }

    return 0;
} /*ops_update_l3ecmp_egress_resilient */

void
ops_l3ecmp_egress_dump(struct ds *ds, int ecmpid)
{
    int unit = 0;
    opennsl_error_t rc;
    opennsl_l3_egress_ecmp_t ecmp_grp;
    opennsl_l3_ecmp_member_t ecmp_member[MAX_NEXTHOPS_PER_ROUTE];
    opennsl_if_t ecmp_intf[MAX_NEXTHOPS_PER_ROUTE];
    int member_count = 0;

    /* single multipath object */
    if (ecmpid != -1) {
        opennsl_l3_egress_ecmp_t_init(&ecmp_grp);
        ecmp_grp.ecmp_intf = ecmpid;
        rc = opennsl_l3_ecmp_get(unit, &ecmp_grp, MAX_NEXTHOPS_PER_ROUTE,
                                 ecmp_member, &member_count);
        if (OPENNSL_FAILURE(rc)){
            VLOG_ERR("Error reading ecmp egress entry %d: %s\n", ecmpid,
                     opennsl_errmsg(rc));
            return;
        } else {
            for (int i= 0; i < member_count ; i++) {
                ecmp_intf[i] = ecmp_member[i].egress_if;
            }
            l3ecmp_egress_print(unit, &ecmp_grp, member_count, ecmp_intf, ds);
        }
    } else {
        rc = opennsl_l3_egress_ecmp_traverse(unit, l3ecmp_egress_print, ds);
        if (OPENNSL_FAILURE(rc)){
            VLOG_ERR("Error reading ecmp table: %s\n", opennsl_errmsg(rc));
            return;
        }
    }
} /* ops_l3ecmp_egress_dump */

/* Create group for l3 subinterface feature.
 * This group is used to create feature specific rules.
 */
static opennsl_error_t
ops_create_l3_subintf_fp_group(int hw_unit)
{
    /* FP groups for subinterface and L3 stats*/
    opennsl_error_t rc = OPENNSL_E_NONE;
    /* Qset for l3 feature */
    opennsl_field_qset_t l3_qset;

    VLOG_DBG("Create group, Check group = %d", subintf_fp_grp_info[hw_unit].l3_fp_grpid);
    /* If group is already created then don't create again */
    if (subintf_fp_grp_info[hw_unit].l3_fp_grpid == -1) {

        OPENNSL_FIELD_QSET_INIT(l3_qset);
        /* for subinterface */
        OPENNSL_FIELD_QSET_ADD (l3_qset,
                                opennslFieldQualifyMyStationHit);
        OPENNSL_FIELD_QSET_ADD (l3_qset, opennslFieldQualifyInPorts);

        VLOG_DBG("%s, Create FP for unit = %d", __FUNCTION__, hw_unit);
        rc = opennsl_field_group_create(hw_unit, l3_qset,
                                        FP_GROUP_PRIORITY_0,
                                        &subintf_fp_grp_info[hw_unit].l3_fp_grpid);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to create FP group Unit=%d, rc=%s",
                    hw_unit, opennsl_errmsg(rc));
            return rc;
        }
        VLOG_DBG("%s, Created FP Group = %d for unit = %d",
                 __FUNCTION__, subintf_fp_grp_info[hw_unit].l3_fp_grpid, hw_unit);
    }

    return rc;
}

/*
 * FP creation to stop subinterface switching traffic.
 */
static opennsl_error_t
ops_subinterface_fp_entry_create(opennsl_port_t hw_port, int hw_unit)
{
    /* FP groups for subinterface */
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_pbmp_t pbm;
    opennsl_pbmp_t pbm_mask;

    rc = ops_create_l3_subintf_fp_group(hw_unit);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to create FP group for L3 features \
                Unit=%d port=%d rc=%s",
                hw_unit, hw_port, opennsl_errmsg(rc));
        return rc;
    }

    /* If the entry was not created then create the entry,
       else update the port bit map and reinstall the entry */
    if (subintf_fp_grp_info[hw_unit].subint_fp_entry_id == -1) {

        /* add hw_port to the rule */
        OPENNSL_PBMP_CLEAR(pbm);
        OPENNSL_PBMP_CLEAR(pbm_mask);
        OPENNSL_PBMP_PORT_ADD(pbm, hw_port);
        OPENNSL_PBMP_PORT_ADD(pbm_mask, hw_port);

        VLOG_DBG("%s, Create entry unit = %d, port %d",
                __FUNCTION__, hw_unit, hw_port);
        rc =  opennsl_field_entry_create(hw_unit,
                subintf_fp_grp_info[hw_unit].l3_fp_grpid,
                &subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to create FP entry for subinterface \
                    Unit=%d port=%d rc=%s",
                    hw_unit, hw_port, opennsl_errmsg(rc));
            return rc;
        }

        VLOG_DBG("%s, Create qualify my station hit unit = %d, port %d",
                __FUNCTION__, hw_unit, hw_port);
        rc = opennsl_field_qualify_MyStationHit(hw_unit,
                subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
                0x0, 0x1); /* NOT hit */
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set qualify for my station hit \
                    Unit=%d port=%d rc=%s",
                    hw_unit, hw_port, opennsl_errmsg(rc));
            ops_destroy_l3_subintf_fp_entry(hw_unit,
            subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
            return rc;
        }

        VLOG_DBG("%s, Create qualify Inport unit = %d, port %d",
                __FUNCTION__, hw_unit, hw_port);
        rc = opennsl_field_qualify_InPorts(hw_unit,
                subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
                pbm, pbm_mask);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set qualify for InPort \
                    Unit=%d port=%d rc=%s",
                    hw_unit, hw_port, opennsl_errmsg(rc));
            ops_destroy_l3_subintf_fp_entry(hw_unit,
                                             subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
            return rc;
        }

        VLOG_DBG("%s, Set action unit = %d, port %d",
                __FUNCTION__, hw_unit, hw_port);
        rc = opennsl_field_action_add(hw_unit,
                subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
                opennslFieldActionDrop, 0, 0);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set action to drop all packets \
                    Unit=%d port=%d rc=%s",
                    hw_unit, hw_port, opennsl_errmsg(rc));
            ops_destroy_l3_subintf_fp_entry(hw_unit,
                                             subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
            return rc;
        }

        rc = opennsl_field_entry_install(hw_unit, subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to install group = %d entry = %d\
                    Unit=%d port=%d rc=%s",
                    subintf_fp_grp_info[hw_unit].l3_fp_grpid,
                    subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
                    hw_unit, hw_port, opennsl_errmsg(rc));
            ops_destroy_l3_subintf_fp_entry(hw_unit,
                                    subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
            return rc;
        }
        VLOG_DBG("%s ADD hw_port = %d, added",
                 __FUNCTION__, hw_port);
    } else {

        VLOG_DBG("Entry already created now update the entry = %d, with port = %d",
                  subintf_fp_grp_info[hw_unit].subint_fp_entry_id, hw_port);
        /* Add multiple subinterfaces to the entry*/
        rc = ops_update_subint_fp_entry(hw_unit, hw_port, true);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to add port to entry = %d for group = %d,\
                    Unit=%d port=%d rc=%s",
                    subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
                    subintf_fp_grp_info[hw_unit].l3_fp_grpid,
                    hw_unit, hw_port, opennsl_errmsg(rc));
            return rc;
        }
    }

    VLOG_DBG("%s, Group entry  = %d install success unit = %d, port %d",
               __FUNCTION__,
               subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
               hw_unit, hw_port);

    return rc;
}

static opennsl_error_t
ops_update_subint_fp_entry(int hw_unit, opennsl_port_t hw_port, bool add)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_pbmp_t pbm;
    opennsl_pbmp_t pbm_mask;
    char pfmt[_SHR_PBMP_FMT_LEN];

    VLOG_DBG("%s, Get Inport bitmask unit = %d",
            __FUNCTION__, hw_unit);
    rc = opennsl_field_qualify_InPorts_get(hw_unit,
            subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
            &pbm, &pbm_mask);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set qualify for InPort \
                Unit=%d port=%d rc=%s",
                hw_unit, hw_port, opennsl_errmsg(rc));
    }
    VLOG_DBG("%s, Get Inport bitmask unit = %d pbm = %s",
            __FUNCTION__, hw_unit, _SHR_PBMP_FMT(pbm, pfmt));

    if (add) {
        /* add hw_port to the rule */
        OPENNSL_PBMP_PORT_ADD(pbm, hw_port);
        OPENNSL_PBMP_PORT_ADD(pbm_mask, hw_port);
        VLOG_DBG("%s After adding hw_port = %d, added to pbm = %s",
                 __FUNCTION__, hw_port, _SHR_PBMP_FMT(pbm, pfmt));
    } else {
        /* del hw_port to the rule */
        OPENNSL_PBMP_PORT_REMOVE(pbm, hw_port);
        OPENNSL_PBMP_PORT_REMOVE(pbm_mask, hw_port);
        VLOG_DBG("%s After deleting hw_port = %d, pbm = %s",
                __FUNCTION__, hw_port, _SHR_PBMP_FMT(pbm, pfmt));
        if (OPENNSL_PBMP_IS_NULL(pbm)) {
            VLOG_DBG("pbm is empty so delete the entry = %d",
                    subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
            rc = ops_destroy_l3_subintf_fp_entry(hw_unit,
                    subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to delete FP entry for subinterface \
                        Unit=%d rc=%s",
                        hw_unit, opennsl_errmsg(rc));
            }
            subintf_fp_grp_info[hw_unit].subint_fp_entry_id = -1;
            return rc;
        }
    }
    VLOG_DBG("%s, Create qualify Inport unit = %d, port %d",
            __FUNCTION__, hw_unit, hw_port);
    rc = opennsl_field_qualify_InPorts(hw_unit,
            subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
            pbm, pbm_mask);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set qualify for InPort \
                Unit=%d port=%d rc=%s",
                hw_unit, hw_port, opennsl_errmsg(rc));
        ops_destroy_l3_subintf_fp_entry(hw_unit, subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
        return rc;
    }
    VLOG_DBG("reinstall entry = %d", subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
    rc = opennsl_field_entry_reinstall(hw_unit, subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to install group = %d entry = %d\
                Unit=%d port=%d rc=%s",
                subintf_fp_grp_info[hw_unit].l3_fp_grpid,
                subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
                hw_unit, hw_port, opennsl_errmsg(rc));
        ops_destroy_l3_subintf_fp_entry(hw_unit, subintf_fp_grp_info[hw_unit].subint_fp_entry_id);
        return rc;
    }
    return rc;
}
/*
 * Function deletes the l3 group entries.
 * If no entry exists then the group is deleted.
 */
static opennsl_error_t
ops_destroy_l3_subintf_fp_entry(int hw_unit, opennsl_field_entry_t entryid)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int entry_count = 0;

    VLOG_DBG("%s, Delete entry %d, unit = %d",
              __FUNCTION__,
              subintf_fp_grp_info[hw_unit].subint_fp_entry_id,
              hw_unit);
    rc = opennsl_field_entry_destroy(hw_unit, entryid);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to delete FP entry for subinterface \
                Unit=%d rc=%s",
                hw_unit, opennsl_errmsg(rc));
        return rc;
    }

    /* check if the group has more entries,
       if not, then destroy the group */
    rc = opennsl_field_entry_multi_get(hw_unit,
                                       subintf_fp_grp_info[hw_unit].l3_fp_grpid,
                                       0, /* get all entries in the grp */
                                       NULL, /* Array for entries */
                                       &entry_count);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get FP entries for l3 feature group = %d \
                Unit=%d entry_count = %d rc=%s",
                subintf_fp_grp_info[hw_unit].l3_fp_grpid,
                hw_unit, entry_count, opennsl_errmsg(rc));
        return rc;
    }
    VLOG_DBG("%s group = %d entry_count = %d\n",
              __FUNCTION__, subintf_fp_grp_info[hw_unit].l3_fp_grpid, entry_count);

    if (entry_count == 0) {

        VLOG_DBG("%s, Delete group = %d, unit = %d",
                __FUNCTION__, subintf_fp_grp_info[hw_unit].l3_fp_grpid, hw_unit);
        rc = opennsl_field_group_destroy(hw_unit,
                                         subintf_fp_grp_info[hw_unit].l3_fp_grpid);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to delete FP group for subinterface \
                    Unit=%d rc=%s",
                    hw_unit, opennsl_errmsg(rc));
            return rc;
        }
        subintf_fp_grp_info[hw_unit].l3_fp_grpid = -1;
    }
    return rc;
}

/*
 * Function initializes l3 group and subinterface info.
 */
int
ops_l3_fp_init(int hw_unit)
{
    VLOG_DBG("%s Hw_unit = %d", __FUNCTION__, hw_unit);
    /* Group ID for l3 feature */
    subintf_fp_grp_info[hw_unit].l3_fp_grpid = -1;
    /* Entry id for all subinterface */
    subintf_fp_grp_info[hw_unit].subint_fp_entry_id = -1;

    /* Group IDs for l3 stats feature */
    l3_rx_stats_fp_grps[hw_unit] = -1;
    l3_tx_stats_fp_grps[hw_unit] = -1;
    return 0;
}
