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
#include "ops-debug.h"
#include "ops-vlan.h"
#include "ops-knet.h"
#include "platform-defines.h"
#include "openswitch-dflt.h"
#include "netdev-bcmsdk.h"

VLOG_DEFINE_THIS_MODULE(ops_routing);
/* ecmp resiliency flag */
bool ecmp_resilient_flag = false;

static int
ops_update_l3ecmp_egress_resilient(int unit, opennsl_l3_egress_ecmp_t *ecmp,
                 int intf_count, opennsl_if_t *egress_obj, void *user_data);
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

    ecmp->dynamic_size = ecmp_resilient_flag ? ECMP_DYN_SIZE_512 :
                                               ECMP_DYN_SIZE_ZERO;
}

int
ops_l3_init(int unit)
{
    int hash_cfg = 0;
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_egress_t egress_object;

    rc = opennsl_switch_control_set(unit, opennslSwitchL3IngressMode, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchL3IngressMode: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    rc = opennsl_switch_control_set(unit, opennslSwitchL3EgressMode, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchL3EgressMode: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
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
        return rc;
    }

    /* Send ARP to CPU */
    rc = opennsl_switch_control_set(unit, opennslSwitchArpRequestToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchArpRequestToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    rc = opennsl_switch_control_set(unit, opennslSwitchArpReplyToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchArpReplyToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }


    rc = opennsl_switch_control_set(unit, opennslSwitchDhcpPktToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchDhcpPktToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    /* IPv6 ND packets */
    rc = opennsl_switch_control_set(unit, opennslSwitchNdPktToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchNdPktToCpu: unit=%d  rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    /* Send IPv4 and IPv6 to CPU */
    rc = opennsl_switch_control_set(unit,opennslSwitchUnknownL3DestToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchUnknownL3DestToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    rc = opennsl_switch_control_set(unit, opennslSwitchV6L3DstMissToCpu, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchV6L3DstMissToCpu: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    /* Enable ECMP enhanced hash method */
    rc = opennsl_switch_control_set(unit, opennslSwitchHashControl,
                                    OPENNSL_HASH_CONTROL_ECMP_ENHANCE);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set OPENNSL_HASH_CONTROL_ECMP_ENHANCE: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
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
        return 1;
    }
    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP4TcpUdpField0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4TcpUdpPortsEqualField0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP4Field0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4Field0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
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
        return 1;
    }
    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP6TcpUdpField0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6TcpUdpPortsEqualField0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(unit,
                                    opennslSwitchHashIP6Field0,
                                    hash_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6Field0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }
    /* Enabling the ecmp resiliency initially*/
    ecmp_resilient_flag = true;

    /* FIXME : Generate the seed from the system MAC? */
    rc = opennsl_switch_control_set(unit, opennslSwitchHashSeed0, 0x12345678);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashSeed0: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchHashField0PreProcessEnable,
                                    1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashField0PreProcessEnable: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchHashField0Config,
                                    OPENNSL_HASH_FIELD_CONFIG_CRC16CCITT);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashField0Config: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchHashField0Config1,
                                    OPENNSL_HASH_FIELD_CONFIG_CRC16CCITT);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashField0Config1: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchECMPHashSet0Offset, 0);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchECMPHashSet0Offset: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(unit, opennslSwitchHashSelectControl, 0);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashSelectControl: unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    /* initialize route table hash map */
    hmap_init(&ops_rtable.routes);

    /* Initialize egress-id hash map. Used only during mac-move. */
    hmap_init(&ops_mac_move_egress_id_map);

    /* register for mac-move. When move happens, ASIC sends a MAC delete
     * message followed by MAC add message. There will be MOVE flag set in
     * both the messages, differentiating it from regular add and delete
     * messages. */
    rc = opennsl_l2_addr_register(unit, ops_l3_mac_move_cb, NULL);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("L2 address registration failed");
        return 1;
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

    /* VLAN config */
    rc = bcmsdk_create_vlan(vlan_id, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_create_vlan: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
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
        goto failed_l3_intf_create;
    }

    SW_L3_DBG("Enabled L3 on unit=%d port=%d vlan=%d vrf=%d",
            hw_unit, hw_port, vlan_id, vrf_id);

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
    if (OPENNSL_FAILURE(rc)) {
        goto failed_l3_intf_create;
    }

    SW_L3_DBG("Enabled L3 on unit=%d port=%d vlan=%d vrf=%d",
            hw_unit, hw_port, vlan_id, vrf_id);

    VLOG_DBG("Create knet filter\n");
    handle_bcmsdk_knet_subinterface_filters(netdev, true);

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
        VLOG_ERR("Failed at bcmsdk_destroy_vlan: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
    }

failed_vlan_creation:
    return NULL;
}

void
ops_routing_disable_l3_interface(int hw_unit, opennsl_port_t hw_port,
                                 opennsl_l3_intf_t *l3_intf, struct netdev *netdev)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_vlan_t vlan_id = l3_intf->l3a_vid;
    opennsl_vrf_t vrf_id = l3_intf->l3a_vrf;
    opennsl_pbmp_t pbmp;

    rc = opennsl_l3_intf_delete(hw_unit, l3_intf);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed at opennsl_l3_intf_delete: unit=%d port=%d vlan=%d"
                 " vrf=%d rc=%s",
                 hw_unit, hw_port, vlan_id, vrf_id, opennsl_errmsg(rc));
    }

    /* Reset VLAN on port back to default and destroy the VLAN */
    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_PORT_ADD(pbmp, hw_port);
    bcmsdk_del_native_untagged_ports(vlan_id, &pbmp, true);

    rc = bcmsdk_destroy_vlan(vlan_id, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_destroy_vlan: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
    }

    SW_L3_DBG("Disabled L3 on unit=%d port=%d vrf=%d", hw_unit, hw_port, vrf_id);

    VLOG_DBG("Delete l3 port knet filter\n");
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
        VLOG_ERR("Failed at opennsl_l3_intf_delete: unit=%d port=%d vlan=%d"
                 " vrf=%d rc=%s",
                 hw_unit, hw_port, vlan_id, vrf_id, opennsl_errmsg(rc));
    }

    /* Reset VLAN on port back to default and destroy the VLAN */
    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_PORT_ADD(pbmp, hw_port);
    bcmsdk_del_trunk_ports(vlan_id, &pbmp);

    bcmsdk_del_subinterface_ports(vlan_id, &pbmp);

    if (is_vlan_membership_empty(vlan_id) && !is_user_created_vlan(vlan_id)) {
        VLOG_DBG("Vlan %d is empty\n", vlan_id);
        rc = bcmsdk_destroy_vlan(vlan_id, false);
        if (rc < 0) {
            VLOG_ERR("Failed at bcmsdk_destroy_vlan: unit=%d port=%d vlan=%d"
                     " rc=%d",
                     hw_unit, hw_port, vlan_id, rc);
        }
    }

    SW_L3_DBG("Disabled L3 on unit=%d port=%d vrf=%d", hw_unit, hw_port, vrf_id);

    VLOG_DBG("Delete subinterface knet filter\n");
    handle_bcmsdk_knet_subinterface_filters(netdev, false);
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
                           opennsl_vlan_t vlan_id)
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
    egress_object.port = port;

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
        return rc;
    }

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
        return rc;
    }

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
        return rc;
    }

    /* Delete the egress object */
    VLOG_DBG("Deleting egress object for egress-id %d", *l3_egress_id);
    rc = opennsl_l3_egress_destroy(hw_unit, *l3_egress_id);
    if (OPENNSL_FAILURE(rc)) {
       VLOG_ERR ("opennsl_egress_destroy failed: %s", opennsl_errmsg(rc));
        return rc;
    }

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
    tmp_ip_addr = strdup(ip_address);

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

/* Find or create and ecmp egress object */
static int
ops_create_or_update_ecmp_object(int hw_unit, struct ops_route *routep,
                                 opennsl_if_t *ecmp_intfp, bool update)
{
    int nh_count = 0;
    struct ops_nexthop *nh;
    opennsl_if_t egress_obj[MAX_NEXTHOPS_PER_ROUTE];
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_egress_ecmp_t ecmp_grp;

    if(!routep) {
        return EINVAL;
    }

    HMAP_FOR_EACH(nh, node, &routep->nexthops) {
        egress_obj[nh_count++] = nh->l3_egress_id;
        /* break once max ecmp is reached */
        if (nh_count == MAX_NEXTHOPS_PER_ROUTE) {
            break;
        }
    }

    if (update){
        opennsl_l3_egress_ecmp_t_init(&ecmp_grp);
        if (ecmp_resilient_flag) {
            ecmp_grp.flags = (OPENNSL_L3_ECMP_RH_REPLACE | OPENNSL_L3_WITH_ID);
        } else {
            ecmp_grp.flags = (OPENNSL_L3_REPLACE | OPENNSL_L3_WITH_ID);
        }
        ecmp_grp.ecmp_intf = *ecmp_intfp;
        ops_update_ecmp_resilient(&ecmp_grp);
        rc = opennsl_l3_egress_ecmp_create(hw_unit, &ecmp_grp, nh_count,
                                           egress_obj);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to update ecmp object for route %s: rc=%s",
                     routep->prefix, opennsl_errmsg(rc));
            return rc;
        }
    } else {
        opennsl_l3_egress_ecmp_t_init(&ecmp_grp);
        ops_update_ecmp_resilient(&ecmp_grp);
        rc = opennsl_l3_egress_ecmp_create(hw_unit, &ecmp_grp, nh_count,
                                           egress_obj);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to create ecmp object for route %s: rc=%s",
                     routep->prefix, opennsl_errmsg(rc));
            return rc;
        }
        *ecmp_intfp = ecmp_grp.ecmp_intf;
    }
    return rc;
} /* ops_create_or_update_ecmp_object */

/* Delete ecmp object */
static int
ops_delete_ecmp_object(int hw_unit, opennsl_if_t ecmp_intf)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_egress_ecmp_t ecmp_grp;

    opennsl_l3_egress_ecmp_t_init(&ecmp_grp);
    ecmp_grp.ecmp_intf = ecmp_intf;

    rc = opennsl_l3_egress_ecmp_destroy(hw_unit, &ecmp_grp);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to delete ecmp egress object %d: %s",
                  ecmp_intf, opennsl_errmsg(rc));
        return rc;
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
            rc = ops_create_or_update_ecmp_object(hw_unit, ops_routep,
                                                 &l3_intf, false);
            if (OPS_FAILURE(rc)) {
                return rc;
            }
            routep->l3a_intf = l3_intf;
            routep->l3a_flags |= OPENNSL_L3_MULTIPATH;
        } else {
            HMAP_FOR_EACH(ops_nh, node, &ops_routep->nexthops) {
                routep->l3a_intf = ops_nh->l3_egress_id;
            }
        }
        add_route = true;
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
                rc = ops_create_or_update_ecmp_object(hw_unit, ops_routep,
                                                     &l3_intf, false);
                if (OPS_FAILURE(rc)) {
                    VLOG_ERR("Failed to create ecmp object for route %s: %s",
                              ops_routep->prefix, opennsl_errmsg(rc));
                    return rc;
                }
                routep->l3a_intf = l3_intf;
                routep->l3a_flags |= (OPENNSL_L3_MULTIPATH |
                                      OPENNSL_L3_REPLACE);
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
            rc = ops_create_or_update_ecmp_object(hw_unit, ops_routep,
                                                 &l3_intf, true);
            if (OPS_FAILURE(rc)) {
                VLOG_ERR("Failed to update ecmp object for route %s: %s",
                         ops_routep->prefix, opennsl_errmsg(rc));
                return rc;
            }
            routep->l3a_flags |= (OPENNSL_L3_MULTIPATH |
                                  OPENNSL_L3_REPLACE);
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

    ops_route_delete(ops_routep);

    if (routep->l3a_flags & OPENNSL_L3_MULTIPATH) {
        l3_intf = routep->l3a_intf;
        is_delete_ecmp = true;
    }

    rc = opennsl_l3_route_delete(hw_unit, routep);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to delete route %s: %s", of_routep->prefix,
                  opennsl_errmsg(rc));
    } else {
        VLOG_DBG("Success to delete route %s: %s", of_routep->prefix,
                 opennsl_errmsg(rc));
    }

    if (is_delete_ecmp) {
        rc = ops_delete_ecmp_object(hw_unit, l3_intf);
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
            rc = ops_create_or_update_ecmp_object(hw_unit, ops_routep,
                                                 &l3_intf, true);
            if (OPS_FAILURE(rc)) {
                VLOG_ERR("Failed to update ecmp object for route %s: %s",
                              ops_routep->prefix, opennsl_errmsg(rc));
                    return rc;
                }
                routep->l3a_flags |= (OPENNSL_L3_MULTIPATH |
                                      OPENNSL_L3_REPLACE);
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
        return rc;
    }
    rc = opennsl_switch_control_get(hw_unit, opennslSwitchHashIP6Field0,
                                    &cur_hash_ip6);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get opennslSwitchHashIP6Field0 : unit=%d, rc=%s",
                 hw_unit, opennsl_errmsg(rc));
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
        return 1;
    }
    rc = opennsl_switch_control_set(hw_unit,
                                    opennslSwitchHashIP4TcpUdpField0,
                                    cur_hash_ip4);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4TcpUdpPortsEqualField0:"
                 "unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip4, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(hw_unit, opennslSwitchHashIP4Field0,
                                    cur_hash_ip4);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP4Field0 : unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip4, opennsl_errmsg(rc));
        return rc;
    }

    rc = opennsl_switch_control_set(hw_unit,
                                    opennslSwitchHashIP6TcpUdpPortsEqualField0,
                                    cur_hash_ip6);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6TcpUdpPortsEqualField0:"
                 "unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip6, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(hw_unit,
                                    opennslSwitchHashIP6TcpUdpField0,
                                    cur_hash_ip6);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6TcpUdpPortsEqualField0:"
                 "unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip6, opennsl_errmsg(rc));
        return 1;
    }
    rc = opennsl_switch_control_set(hw_unit, opennslSwitchHashIP6Field0,
                                    cur_hash_ip6);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set opennslSwitchHashIP6Field0 : unit=%d, hash=%x, rc=%s",
                 hw_unit, cur_hash_ip6, opennsl_errmsg(rc));
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
       VLOG_INFO("Egress object id NOT found in process cache, possibly "
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
       goto done;
   }

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

/*This function can get called by ASIC for following events:
*  Add, Delete, Mac-Learn, Mac-Age, & Mac-Move
*
*  Currently, it handles Add & Delete events, triggered due to mac-move. */
void
ops_l3_mac_move_cb(int   unit,
                   opennsl_l2_addr_t  *l2addr,
                   int    operation,
                   void   *userdata)
{
   if (l2addr == NULL) {
       VLOG_ERR("Invalid arguments. l2-addr is NULL");
       return;
   }

   switch(operation) {
       case OPENNSL_L2_CALLBACK_ADD:
           ops_l3_mac_move_add(unit, l2addr, userdata);
           break;
       case OPENNSL_L2_CALLBACK_DELETE:
           ops_l3_mac_move_delete(unit, l2addr, userdata);
           break;
       default:
           break;
   }
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
