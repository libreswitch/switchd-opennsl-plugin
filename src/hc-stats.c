/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    hc-stats.c
 *
 * Purpose: This file has code to retreive Interface statistics.
 *
 */

#include <openvswitch/vlog.h>

#include <opennsl/error.h>
#include <opennsl/stat.h>

#include <openvswitch/vlog.h>
#include <netdev.h>

VLOG_DEFINE_THIS_MODULE(hc_stats);

/* The number of elements in start_arr[] should be same as MAX_STATS. */
#define MAX_STATS       13

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
    opennsl_spl_snmpEtherStatsCRCAlignErrors /* 12 */
};

int
bcmsdk_get_port_stats(int hw_unit, int hw_port, struct netdev_stats *stats)
{
    uint64 value_arr[MAX_STATS];
    opennsl_error_t rc = OPENNSL_E_NONE;

    opennsl_stat_multi_get(hw_unit, hw_port, MAX_STATS, stat_arr, value_arr);
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

    return 0;

} // bcmsdk_get_port_stats
