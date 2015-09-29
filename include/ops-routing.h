/*
 * Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
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
 * File: ops-routing.h
 */

#ifndef __OPS_ROUTING_H__
#define __OPS_ROUTING_H__ 1

#include <ovs/dynamic-string.h>
#include <opennsl/types.h>
#include <opennsl/l2.h>
#include <opennsl/l3.h>
#include <netinet/in.h>
#include <ofproto/ofproto.h>

#define IPV4_PREFIX_LEN     32
#define IPV6_PREFIX_LEN     128

#define IPV4_BUFFER_LEN     32
#define IPV6_BUFFER_LEN     64

#define OPS_ROUTE_HASH_MAXSIZE 64

#define OPS_FAILURE(rc) (((rc) < 0 ) || ((rc) == EINVAL))

enum ops_route_state {
    OPS_ROUTE_STATE_NON_ECMP = 0,
    OPS_ROUTE_STATE_ECMP
};

struct ops_route {
    struct hmap_node node;          /* all_routes */
    int vrf;
    char *prefix;                   /* route prefix */
    char *from;                     /* routing protocol (BGP, OSPF) using this route */
    bool is_ipv6;                   /* IP V4/V6 */
    int n_nexthops;
    struct hmap nexthops;           /* list of selected next hops */
    enum ops_route_state rstate;     /* state of route */
    int  nh_index;                  /* next hop index ecmp*/
};

struct ops_nexthop {
    struct hmap_node node;            /* route->nexthops */
    enum ofproto_nexthop_type type;   /* v4/v6 */
    char *id;                         /* IP address or Port name */
    int  l3_egress_id;
};

struct net_address {
    struct hmap_node addr_node;
    char *address;
};

/* Node keeping track of egress_object id's. Used only for mac-move scenarios */
struct ops_mac_move_egress_id {
    struct  hmap_node node;
    int     egress_object_id;
};

/* Hashmap of egress object ID's. Only used for mac-moves.
 * key = vlan_id + mac_addr
 * val = ID of the row in Egress table (in ASIC) for given vlan_id and mac_addr.
 */
extern struct hmap ops_mac_move_egress_id_map;

extern int ops_l3_init(int);

extern opennsl_l3_intf_t *ops_routing_enable_l3_interface(int hw_unit,
                                                         opennsl_port_t hw_port,
                                                         opennsl_vrf_t vrf_id,
                                                         opennsl_vlan_t vlan_id,
                                                         unsigned char *mac);

extern void ops_routing_disable_l3_interface(int hw_unit,
                                            opennsl_port_t hw_port,
                                            opennsl_l3_intf_t *l3_intf);

extern opennsl_l3_intf_t * ops_routing_enable_l3_vlan_interface(int hw_unit,
                                                               opennsl_vrf_t vrf_id,
                                                               opennsl_vlan_t vlan_id,
                                                               unsigned char *mac);

extern void ops_routing_disable_l3_vlan_interface(int hw_unit,
                                                 opennsl_l3_intf_t *l3_intf);

extern int ops_routing_add_host_entry(int hw_unit, opennsl_port_t hw_port,
                                     opennsl_vrf_t vrf_id, bool is_ipv6_addr,
                                     char *ip_addr, char *next_hop_mac_addr,
                                     opennsl_if_t l3_intf_id,
                                     opennsl_if_t *l3_egress_id,
                                     opennsl_vlan_t vlan_id);
extern int ops_routing_delete_host_entry(int hw_unit, opennsl_port_t hw_port,
                                        opennsl_vrf_t vrf_id,
                                        bool is_ipv6_addr, char *ip_addr,
                                        opennsl_if_t *l3_egress_id);

extern int ops_routing_get_host_hit(int hw_unit, opennsl_vrf_t vrf_id,
                                   bool is_ipv6_addr, char *ip_addr, bool *hit_bit);

extern int ops_routing_route_entry_action(int hw_unit,
                                         opennsl_vrf_t vrf_id,
                                         enum ofproto_route_action action,
                                         struct ofproto_route *routep);

extern int ops_routing_host_entry_action(int hw_unit, opennsl_vrf_t vrf_id,
                                         enum ofproto_host_action action,
                                         struct ofproto_l3_host *host_info);

extern int ops_routing_ecmp_set(int hw_unit, bool enable);
extern int ops_routing_ecmp_hash_set(int hw_unit, unsigned int hash,
                                    bool enable);
extern void ops_l3intf_dump(struct ds *ds, int intfid);

extern void ops_l3host_dump(struct ds *ds, int ipv6_enabled);
extern void ops_l3route_dump(struct ds *ds, int ipv6_enabled);

extern void ops_l3egress_dump(struct ds *ds, int egressid);
extern void ops_l3ecmp_egress_dump(struct ds *ds, int ecmpid);

extern void ops_l3_mac_move_cb(int unit, opennsl_l2_addr_t *l2addr,
                                int operation, void *userdata);

#endif /* __OPS_ROUTING_H__ */
