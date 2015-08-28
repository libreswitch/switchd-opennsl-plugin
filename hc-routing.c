/* Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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
#include <netinet/ether.h>
#include <linux/if_ether.h>
#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/switch.h>
#include <opennsl/vlan.h>
#include <opennsl/l3.h>
#include <opennsl/l2.h>
#include "hc-routing.h"
#include "hc-debug.h"
#include "hc-vlan.h"
#include "hc-knet.h"
#include "platform-defines.h"
#include <util.h>

VLOG_DEFINE_THIS_MODULE(hc_routing);

int
hc_l3_init(int unit)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

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

    return 0;
}

opennsl_l3_intf_t *
hc_routing_enable_l3_interface(int hw_unit, opennsl_port_t hw_port,
                               opennsl_vrf_t vrf_id, opennsl_vlan_t vlan_id,
                               unsigned char *mac)
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
    rc = bcmsdk_add_access_ports(vlan_id, &pbmp, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_add_access_ports: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
        goto failed_adding_vlan;
    }

    /* Create L3 interface */
    l3_intf = (opennsl_l3_intf_t *)xmalloc(sizeof(opennsl_l3_intf_t));
    if (!l3_intf) {
        VLOG_ERR("Failed allocating opennsl_l3_intf_t: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
        goto failed_allocating_l3_intf;
    }

    opennsl_l3_intf_t_init(l3_intf);
    l3_intf->l3a_vrf = vrf_id;
    l3_intf->l3a_intf_id = vlan_id;
    l3_intf->l3a_flags = OPENNSL_L3_ADD_TO_ARL | OPENNSL_L3_WITH_ID;
    memcpy(l3_intf->l3a_mac_addr, mac, ETH_ALEN);
    l3_intf->l3a_vid = vlan_id;

    rc = opennsl_l3_intf_create(hw_unit, l3_intf);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed at opennsl_l3_intf_create: unit=%d port=%d vlan=%d vrf=%d rc=%s",
                 hw_unit, hw_port, vlan_id, vrf_id, opennsl_errmsg(rc));
        goto failed_l3_intf_create;
    }

    SW_L3_DBG("Enabled L3 on unit=%d port=%d vlan=%d vrf=%d",
            hw_unit, hw_port, vlan_id, vrf_id);

    return l3_intf;

failed_l3_intf_create:
    free(l3_intf);

failed_allocating_l3_intf:
    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_PORT_ADD(pbmp, hw_port);
    rc = bcmsdk_del_access_ports(vlan_id, &pbmp, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_del_access_ports: unit=%d port=%d rc=%d",
                 hw_unit, hw_port, rc);
    }

failed_adding_vlan:
    rc = bcmsdk_destroy_vlan(vlan_id, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_destroy_vlan: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
    }

failed_vlan_creation:
    return NULL;
}

void
hc_routing_disable_l3_interface(int hw_unit, opennsl_port_t hw_port,
                                opennsl_l3_intf_t *l3_intf)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_vlan_t vlan_id = l3_intf->l3a_vid;
    opennsl_vrf_t vrf_id = l3_intf->l3a_vrf;
    opennsl_pbmp_t pbmp;


    rc = opennsl_l3_intf_delete(hw_unit, l3_intf);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed at opennsl_l3_intf_delete: unit=%d port=%d vlan=%d vrf=%d rc=%s",
                 hw_unit, hw_port, vlan_id, vrf_id, opennsl_errmsg(rc));
    }

    /* Reset VLAN on port back to default and destroy the VLAN */
    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_PORT_ADD(pbmp, hw_port);
    rc = bcmsdk_del_access_ports(vlan_id, &pbmp, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_del_access_ports: unit=%d port=%d rc=%d",
                 hw_unit, hw_port, rc);
    }

    rc = bcmsdk_destroy_vlan(vlan_id, true);
    if (rc < 0) {
        VLOG_ERR("Failed at bcmsdk_destroy_vlan: unit=%d port=%d vlan=%d rc=%d",
                 hw_unit, hw_port, vlan_id, rc);
    }

    SW_L3_DBG("Disabled L3 on unit=%d port=%d vrf=%d", hw_unit, hw_port, vrf_id);
}

opennsl_l3_intf_t *
hc_routing_enable_l3_vlan_interface(int hw_unit, opennsl_vrf_t vrf_id,
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

    opennsl_l3_intf_t_init(l3_intf);
    l3_intf->l3a_vrf = vrf_id;
    l3_intf->l3a_intf_id = vlan_id;
    l3_intf->l3a_flags = OPENNSL_L3_ADD_TO_ARL | OPENNSL_L3_WITH_ID;
    memcpy(l3_intf->l3a_mac_addr, mac, ETH_ALEN);
    l3_intf->l3a_vid = vlan_id;

    rc = opennsl_l3_intf_create(hw_unit, l3_intf);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed at opennsl_l3_intf_create: unit=%d vlan=%d vrf=%d rc=%s",
                 hw_unit, vlan_id, vrf_id, opennsl_errmsg(rc));
        free(l3_intf);
        return NULL;
    }

    SW_L3_DBG("Enabled L3 on unit=%d vlan=%d vrf=%d",
            hw_unit, vlan_id, vrf_id);

    return l3_intf;
} /* hc_routing_enable_l3_vlan_interface */

/* Function to add l3 host entry via ofproto */
int
hc_routing_add_host_entry(int hw_unit, opennsl_port_t hw_port,
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
    VLOG_DBG("In hc_routing_add_host_entry for ip %s", ip_addr);
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

    rc = opennsl_l3_egress_create(hw_unit, flags, &egress_object, l3_egress_id);
    if (rc != OPENNSL_E_NONE) {
        VLOG_ERR("Error, create egress object, out_port=%d", hw_port);
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
    if (rc != OPENNSL_E_NONE) {
        VLOG_ERR ("opennsl_l3_host_add failed: %x", rc);
        return rc;
    }

    return rc;
} /* hc_routing_add_host_entry */

/* Function to delete l3 host entry via ofproto */
int
hc_routing_delete_host_entry(int hw_unit, opennsl_port_t hw_port,
                             opennsl_vrf_t vrf_id, bool is_ipv6_addr,
                             char *ip_addr, opennsl_if_t *l3_egress_id)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_host_t l3host;
    in_addr_t ipv4_dest_addr;
    char ipv6_dest_addr[sizeof(struct in6_addr)];
    int flags = OPENNSL_L3_HOST_LOCAL;


    /* Delete an IP route / Host Entry */
    VLOG_DBG("In hc_routing_delete_host_entry for ip %s", ip_addr);
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
    if (rc != OPENNSL_E_NONE) {
        VLOG_ERR ("opennsl_l3_host_delete failed: %x", rc);
        return rc;
    }

    /* Delete the egress object */
    VLOG_DBG("Deleting egress object for egress-id %d", *l3_egress_id);
    rc = opennsl_l3_egress_destroy(hw_unit, *l3_egress_id);
    if (rc != OPENNSL_E_NONE) {
       VLOG_ERR ("opennsl_egress_destroy failed: %x", rc);
        return rc;
    }

    *l3_egress_id = -1;
    return rc;
} /* hc_routing_delete_host_entry */

/* Ft to read and reset the host hit-bit */
int
hc_routing_get_host_hit(int hw_unit, opennsl_vrf_t vrf_id,
                        bool is_ipv6_addr, char *ip_addr, bool *hit_bit)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_l3_host_t l3host;
    in_addr_t ipv4_dest_addr;
    char ipv6_dest_addr[sizeof(struct in6_addr)];
    int flags = OPENNSL_L3_HOST_LOCAL;

    VLOG_DBG("In hc_routing_get_host_hit for ip %s", ip_addr);
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
    if (rc != OPENNSL_E_NONE) {
        VLOG_ERR ("opennsl_l3_host_find failed: %x", rc);
        return rc;
    } else {
        *hit_bit = (l3host.l3a_flags & OPENNSL_L3_HIT);
        VLOG_DBG("Got the hit-bit =0x%x", *hit_bit);
        if(*hit_bit) {
            l3host.l3a_flags = flags | OPENNSL_L3_HIT_CLEAR;
            /* Reset the hit-bit */
            rc = opennsl_l3_host_find(hw_unit, &l3host);
            if (rc != OPENNSL_E_NONE) {
                VLOG_ERR ("Reset hit-bit failed: %x", rc);
                return rc;
            }
        }
    }

    return rc;
} /* hc_routing_get_host_hit */

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

void
hc_l3intf_dump(struct ds *ds, int intfid)
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
} /* hc_l3intf_dump */

int hc_host_print(
    int unit,
    int index,
    opennsl_l3_host_t *info,
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
        char ip_str[64];
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
        char ip_str[32];
        sprintf(ip_str, "%d.%d.%d.%d",
            (info->l3a_ip_addr >> 24) & 0xff, (info->l3a_ip_addr >> 16) & 0xff,
            (info->l3a_ip_addr >> 8) & 0xff, info->l3a_ip_addr & 0xff);

        ds_put_format(pds,"%-6d %-4d %-16s %2d %4d%s %6s\n",
                index, info->l3a_vrf, ip_str, info->l3a_intf,
                port, trunk, hit);
    }

    return OPENNSL_E_NONE;
} /*hc_host_print*/

void
hc_l3host_dump(struct ds *ds, int ipv6_enabled)
{
    int               unit = 0;
    int               rv;
    int               free_l3host;
    int               last_entry;
    int               first_entry;
    opennsl_l3_info_t l3_hw_status;

    rv = opennsl_l3_info(unit, &l3_hw_status);
    if (OPENNSL_FAILURE(rv)){
        VLOG_ERR("Error in L3 info access: %s\n",opennsl_errmsg(rv));
        return;
    }

    free_l3host = l3_hw_status.l3info_max_host;
    last_entry = l3_hw_status.l3info_max_host;
    first_entry = 0;
    ds_put_format(ds,"Unit %d, free L3 table entries: %d\n", unit, free_l3host);

    if (ipv6_enabled == TRUE) {
        ds_put_format(ds ,"Entry VRF                 IP address                 "
                          "INTF PORT    HIT \n");
        ds_put_format(ds ,"------------------------------------------------"
                           "---------------------\n");
        opennsl_l3_host_traverse(unit, OPENNSL_L3_IP6, first_entry, last_entry,
                                 &hc_host_print, ds);
    } else {
        ds_put_format(ds ,"Entry VRF     IP address     INTF PORT    HIT \n");
        ds_put_format(ds ,"-----------------------------------------------\n");
        opennsl_l3_host_traverse(unit, 0, first_entry, last_entry,
                                 &hc_host_print, ds);
    }

} /* hc_l3host_dump */
