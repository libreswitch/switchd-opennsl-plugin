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
 * File: ops-stats.c
 *
 * Purpose: This file has code to retreive Interface statistics.
 */

#include <openvswitch/vlog.h>

#include <opennsl/error.h>
#include <opennsl/stat.h>

#include <openvswitch/vlog.h>
#include <netdev.h>
#include "ops-stats.h"
#include <inttypes.h>

#include "ops-stats.h"
#include "eventlog.h"

VLOG_DEFINE_THIS_MODULE(ops_stats);

/* The number of elements in start_arr[] should be same as MAX_STATS. */
#define MAX_STATS       18

extern int netdev_bcmsdk_populate_l3_stats(int hw_unit, int hw_port,
        struct netdev_stats *stats);

opennsl_stat_val_t stat_arr[MAX_STATS] =
{
    /* rx_packets */
    opennsl_spl_snmpIfInUcastPkts, /* 0 */
    opennsl_spl_snmpIfInNUcastPkts, /* 1 */

    /* tx_packets */
    opennsl_spl_snmpIfOutUcastPkts, /* 2 */
    opennsl_spl_snmpIfOutNUcastPkts, /* 3 */

    /* rx_bytes */
    opennsl_spl_snmpIfInOctets, /* 4 */

    /* tx_bytes */
    opennsl_spl_snmpIfOutOctets, /* 5 */

    /* rx_errors */
    opennsl_spl_snmpIfInErrors, /* 6 */

    /* tx_errors */
    opennsl_spl_snmpIfOutErrors, /* 7 */

    /* rx_dropped */
    opennsl_spl_snmpIfInDiscards, /* 8 */

    /* tx_dropped */
    opennsl_spl_snmpIfOutDiscards, /* 9 */

    /* multicast */
    opennsl_spl_snmpEtherStatsMulticastPkts, /* 10 */

    /* collisions */
    opennsl_spl_snmpEtherStatsCollisions, /* 11 */

    /* rx_crc_errors */
    opennsl_spl_snmpEtherStatsCRCAlignErrors, /* 12 */

    /* rx multicast */
    opennsl_spl_snmpIfInMulticastPkts, /* 13 */

    /* rx broadcast */
    opennsl_spl_snmpIfInBroadcastPkts, /* 14 */

    /* rx unknown protos */
    opennsl_spl_snmpIfInUnknownProtos, /* 15 */

    /* tx multicast */
    opennsl_spl_snmpIfOutMulticastPkts, /* 16 */

    /* tx broadcast */
    opennsl_spl_snmpIfOutBroadcastPkts, /* 17 */
};

int bcmsdk_get_l3_ingress_stats(int hw_unit, struct netdev_stats *stats,
                                int ingress_vlan_id, uint32_t ingress_num_id)
{
    int rc = 0;
    uint32_t counter_index[10];
    opennsl_stat_value_t count_arr[10];

    /* Get packet stats */
    /* Initialize the stat structures for fetching packet details*/
    memset(counter_index, 0 , 10);
    counter_index[0] = L3_UCAST_STAT_GROUP_COUNTER_OFFSET;
    counter_index[1] = L3_MCAST_STAT_GROUP_COUNTER_OFFSET;
    opennsl_stat_value_t_init(&(count_arr[0]));
    opennsl_stat_value_t_init(&(count_arr[1]));
    VLOG_DBG("opennsl_stat_init packets SUCCESS for l3 ingress vlan id: %d",
              ingress_vlan_id);

    rc = opennsl_l3_ingress_stat_counter_get(hw_unit, ingress_vlan_id,
                                         opennslL3StatInPackets, ingress_num_id,
                                         &(counter_index[0]),
                                         &(count_arr[0]));
    if (rc) {
        VLOG_ERR("Failed to get stat input packets for l3 ingress vlan id: %d",
                  ingress_vlan_id);
        return 1; /* Return error */
    }

    stats->l3_uc_rx_packets = count_arr[0].packets;
    stats->l3_mc_rx_packets = count_arr[1].packets;

    /* Get bytes stats */
    /* Initialize the stat structures for fetching packet details*/
    memset(counter_index, 0 , 10);
    counter_index[0] = L3_UCAST_STAT_GROUP_COUNTER_OFFSET;
    counter_index[1] = L3_MCAST_STAT_GROUP_COUNTER_OFFSET;
    opennsl_stat_value_t_init(&(count_arr[0]));
    opennsl_stat_value_t_init(&(count_arr[1]));

    rc = opennsl_l3_ingress_stat_counter_get(hw_unit, ingress_vlan_id,
                                         opennslL3StatInBytes, ingress_num_id,
                                         &(counter_index[0]),
                                         &(count_arr[0]));
    if (rc) {
        VLOG_ERR("Failed to get stat input bytes for l3 ingress vlan id: %d",
                  ingress_vlan_id);
        return 1; /* Return error */
    }
    stats->l3_uc_rx_bytes = count_arr[0].bytes;
    stats->l3_mc_rx_bytes = count_arr[1].bytes;

    return rc;
}

int bcmsdk_get_l3_egress_stats(int hw_unit, struct netdev_stats *stats,
                               int egress_object_id, uint32_t egress_num_id)
{
    int rc = 0;
    uint32_t counter_index[10];
    opennsl_stat_value_t count_arr[10];

    /* Initialize the stat structures for fetching packet details*/
    memset(counter_index, 0 , 10);
    counter_index[0] = L3_UCAST_STAT_GROUP_COUNTER_OFFSET;
    counter_index[1] = L3_MCAST_STAT_GROUP_COUNTER_OFFSET;
    opennsl_stat_value_t_init(&(count_arr[0]));
    opennsl_stat_value_t_init(&(count_arr[1]));

    rc = opennsl_l3_egress_stat_counter_get(hw_unit, egress_object_id,
                                      opennslL3StatOutPackets,
                                      egress_num_id, &(counter_index[0]),
                                      &(count_arr[0]));
    if (rc) {
        VLOG_ERR("Failed to get stat output packets for l3 egress id: %d",
                 egress_object_id);
        return 1; /* Return error */
    }
    stats->l3_uc_tx_packets += count_arr[0].packets;
    stats->l3_mc_tx_packets += count_arr[1].packets;

    /* Initialize the stat structures for fetching bytes details*/
    memset(counter_index, 0 , 10);
    counter_index[0] = L3_UCAST_STAT_GROUP_COUNTER_OFFSET;
    counter_index[1] = L3_MCAST_STAT_GROUP_COUNTER_OFFSET;
    opennsl_stat_value_t_init(&(count_arr[0]));
    opennsl_stat_value_t_init(&(count_arr[1]));
    VLOG_DBG("opennsl_stat_init bytes SUCCESS for l3 egress id: %d",
              egress_object_id);

    rc = opennsl_l3_egress_stat_counter_get(hw_unit, egress_object_id,
                                      opennslL3StatOutBytes,
                                      egress_num_id, &(counter_index[0]),
                                      &(count_arr[0]));
    if (rc) {
        VLOG_ERR("Failed to get stat output bytes for l3 egress id: %d",
                 egress_object_id);
        return 1; /* Return error */
    }
    stats->l3_uc_tx_bytes += count_arr[0].bytes;
    stats->l3_mc_tx_bytes += count_arr[1].bytes;

    return rc;
}

int
bcmsdk_get_port_stats(int hw_unit, int hw_port, struct netdev_stats *stats)
{
    uint64 value_arr[MAX_STATS];
    opennsl_error_t rc = OPENNSL_E_NONE;

    /* global stats */
    rc = opennsl_stat_multi_get(hw_unit, hw_port, MAX_STATS, stat_arr, value_arr);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get interface statistics. Unit=%d port=%d. rc=%s",
                 hw_unit, hw_port, opennsl_errmsg(rc));
        return -1;
    }

    stats->rx_packets = value_arr[0] + value_arr[1];
    stats->tx_packets = value_arr[2] + value_arr[3];
    stats->rx_bytes = value_arr[4];
    stats->tx_bytes = value_arr[5];
    stats->rx_errors = value_arr[6];
    stats->tx_errors = value_arr[7];
    stats->rx_dropped = value_arr[8];
    stats->tx_dropped = value_arr[9];
    stats->multicast = value_arr[10];
    stats->collisions = value_arr[11];
    stats->rx_crc_errors = value_arr[12];

    /* l3 stats */
    rc = netdev_bcmsdk_populate_l3_stats(hw_unit, hw_port, stats);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get L3 interface statistics. Unit=%d port=%d. rc=%s",
                 hw_unit, hw_port, opennsl_errmsg(rc));
        return -1;
    }
    return 0;
} // bcmsdk_get_port_stats

int
bcmsdk_get_sflow_port_stats(int hw_unit, int hw_port,
                            struct ops_sflow_port_stats *stats)
{
    uint64 value_arr[MAX_STATS];
    opennsl_error_t rc = OPENNSL_E_NONE;

    rc = opennsl_stat_multi_get(hw_unit, hw_port, MAX_STATS, stat_arr, value_arr);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get interface statistics. Unit=%d port=%d. rc=%s",
                 hw_unit, hw_port, opennsl_errmsg(rc));
        log_event("SFLOW_INTF_STATISTICS_FAILURE",
                  EV_KV("unit", "%d", hw_unit),
                  EV_KV("port", "%d", hw_port),
                  EV_KV("error", "%s", opennsl_errmsg(rc)));
        return -1;
    }

    stats->in_octets = value_arr[4];
    stats->in_ucastpkts = value_arr[0];
    stats->in_multicastpkts = value_arr[13];
    stats->in_broadcastpkts = value_arr[14];
    stats->in_discards = value_arr[8];
    stats->in_errors = value_arr[6];
    stats->in_unknownprotos = value_arr[15];
    stats->out_octets = value_arr[5];
    stats->out_ucastpkts = value_arr[2];
    stats->out_multicastpkts = value_arr[16];
    stats->out_broadcastpkts = value_arr[17];
    stats->out_discards = value_arr[9];
    stats->out_errors = value_arr[7];

    return 0;

} // bcmsdk_get_sflow_port_stats
