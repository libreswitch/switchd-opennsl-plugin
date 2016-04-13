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
 * File: ops-stats.h
 *
 * Purpose: This file provides public definitions for Interface statistics API.
 */

#ifndef __OPS_STAT_H__
#define __OPS_STAT_H__ 1

#include "ops-sflow.h"
#include <ofproto/ofproto.h>
#include <opennsl/l3.h>
#include <opennsl/stat.h>
#include <opennsl/field.h>

struct ops_stats_egress_id {
    struct   hmap_node egress_node;
    int      egress_object_id;
    uint32_t egress_num_id;
    uint32_t egress_stat_id;
};

struct ops_l3_stats_ingress {
    int      ingress_vlan_id;
    uint32_t ingress_num_id;
    uint32_t ingress_stat_id;
};

struct ops_deleted_stats {
    uint32_t del_uc_packets;
    uint32_t del_uc_bytes;
    uint32_t del_mc_packets;
    uint32_t del_mc_bytes;
};

#define NUM_L3_FP_STATS 16
#define L3_UCAST_STAT_GROUP_COUNTER_OFFSET 0
#define L3_MCAST_STAT_GROUP_COUNTER_OFFSET 1

#define ipv4_uc_known_rx     0
#define ipv4_uc_unknown_rx   1
#define ipv4_mc_known_rx     2
#define ipv4_mc_unknown_rx   3
#define ipv4_uc_known_tx     4
#define ipv4_uc_unknown_tx   5
#define ipv4_mc_known_tx     6
#define ipv4_mc_unknown_tx   7
#define ipv6_uc_known_rx     8
#define ipv6_uc_unknown_rx   9
#define ipv6_mc_known_rx     10
#define ipv6_mc_unknown_rx   11
#define ipv6_uc_known_tx     12
#define ipv6_uc_unknown_tx   13
#define ipv6_mc_known_tx     14
#define ipv6_mc_unknown_tx   15


extern int bcmsdk_get_port_stats(int hw_unit, int hw_port, struct netdev_stats *stats);
extern int bcmsdk_get_sflow_port_stats(int hw_unit, int hw_port,
                                       struct ops_sflow_port_stats *stats);

extern int bcmsdk_get_l3_egress_stats(int hw_unit,
                               struct netdev_stats *stats, int egress_object_id,
                               uint32_t egress_num_id);

extern int bcmsdk_get_l3_ingress_stats(int hw_unit,
                               struct netdev_stats *stats, int ingress_vlan_id,
                               uint32_t ingress_num_id);
#endif /* __OPS_STAT_H__ */
