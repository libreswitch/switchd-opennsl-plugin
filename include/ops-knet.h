/*
 * (C) Copyright 2015-2016 Hewlett Packard Enterprise Development Company, L.P.
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
 * File: ops-knet.h
 */

#ifndef __OPS_KNET_H__
#define __OPS_KNET_H__ 1

#include <ovs/dynamic-string.h>
#include <netinet/ether.h>
#include <opennsl/types.h>

/* BCM PRIORITY
 * The order in which knet filters are arranged.
 * BPDU filter - to send all bpdu packets to kernel port
 * L3 port filter - to send all packets with matching internal vlan
 *                  to kernel port matching the incoming port. The
 *                  filter will strip the internal vlan.
 * Subinterface filter - to send all packet from in port to
 *                       corresponding out port. Created when subinterface
 *                       is created.
 * Default filter is bridge normal - this filter is installed at start
 *                                   and is never deleted. All packets
 *                                   are sent to bridge normal port.
 */
/* BCM KNET filter priorities.
 * Filters with priority 0 are applied only on RX channel 0.
 * Filters with priority 1 are applied only on RX channel 1.
 * Filters with priority 2 and above are applied to both RX channels.
 */
enum knet_filter_prio_e
{
    KNET_FILTER_PRIO_HIGHEST = 2,
    KNET_FILTER_PRIO_SFLOW = 5,
    KNET_FILTER_PRIO_BPDU,
    KNET_FILTER_PRIO_PORT,
    KNET_FILTER_PRIO_VLAN,
    KNET_FILTER_PRIO_SUBINTF,
    KNET_FILTER_PRIO_BRIDGE_NORMAL,
    KNET_FILTER_PRIO_LOWEST = 255
};

typedef enum knet_debug_type_ {
    KNET_DEBUG_NETIF,
    KNET_DEBUG_FILTER,
    KNET_DEBUG_MAX
} knet_debug_type_t;

struct knet_user_data {
    struct ds *ds;
    int count;
};

extern int ops_knet_init(int unit);
extern int bcmsdk_knet_if_create(char *name, int unit, opennsl_port_t port,
                                 struct ether_addr *mac, int *knet_if_id);
extern int bcmsdk_knet_if_delete(char *name, int unit, int knet_if_id);

extern void bcmsdk_knet_filter_delete(char *name, int unit, int knet_filter_id);

extern int bcmsdk_knet_if_delete_by_name(char* name, int hw_unit);
extern void bcmsdk_knet_l3_port_filter_create(int hw_unit, int vid, opennsl_port_t hw_port,
                               int knet_if_id, int *knet_filter_id);
extern void bcmsdk_knet_subinterface_filter_create(int hw_unit, opennsl_port_t hw_port,
                               int knet_if_id, int *knet_filter_id);
extern void bcmsdk_knet_port_bpdu_filter_create(char *name, int hw_unit, opennsl_port_t hw_port,
                                           int knet_if_id, int *knet_filter_id);
extern void bcmsdk_knet_bridge_normal_filter_create(char *knet_dst_if_name,
        int *knet_filter_id);
extern void ops_knet_dump(struct ds *ds, knet_debug_type_t debug_type);

extern void bcmsdk_knet_sflow_filter_create(int *knet_filter_id, int reason, char *desc);

#endif /* __OPS_KNET_H__ */
