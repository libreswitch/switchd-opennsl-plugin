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

#ifndef __HC_ROUTING_H__
#define __HC_ROUTING_H__ 1

#include <ovs/dynamic-string.h>
#include <opennsl/types.h>
#include <opennsl/l3.h>

extern int hc_l3_init(int);

extern opennsl_l3_intf_t *hc_routing_enable_l3_interface(int hw_unit,
                                                         opennsl_port_t hw_port,
                                                         opennsl_vrf_t vrf_id,
                                                         opennsl_vlan_t vlan_id,
                                                         unsigned char *mac);

extern void hc_routing_disable_l3_interface(int hw_unit,
                                            opennsl_port_t hw_port,
                                            opennsl_l3_intf_t *l3_intf);
extern int hc_routing_add_host_entry(int hw_unit, opennsl_port_t hw_port,
                                     opennsl_vrf_t vrf_id, bool is_ipv6_addr,
                                     char *ip_addr, char *next_hop_mac_addr,
                                     opennsl_if_t l3_intf_id,
                                     opennsl_if_t *l3_egress_id);
extern int hc_routing_delete_host_entry(int hw_unit, opennsl_port_t hw_port,
                                        opennsl_vrf_t vrf_id,
                                        bool is_ipv6_addr, char *ip_addr,
                                        opennsl_if_t *l3_egress_id);
extern int hc_routing_get_host_hit(int hw_unit, opennsl_vrf_t vrf_id,
                        bool is_ipv6_addr, char *ip_addr, bool *hit_bit);

extern void hc_l3intf_dump(struct ds *ds, int intfid);
extern void hc_l3host_dump(struct ds *ds, int ipv6_enabled);

#endif /* __HC_ROUTING_H__ */
