/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    hc-knet.c
 *
 * Purpose: This file contains implementation of KNET virtual linux Ethernet interface.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/knet.h>

#include "platform-defines.h"
#include "hc-debug.h"
#include "hc-knet.h"

VLOG_DEFINE_THIS_MODULE(hc_knet);


//////////////////////////////// Public API //////////////////////////////

int
bcmsdk_knet_if_create(char *name, int hw_unit, opennsl_port_t hw_port,
                      struct ether_addr *mac, int *knet_if_id)
{
    char cmd[256];
    opennsl_knet_netif_t knet_if;
    opennsl_error_t rc = OPENNSL_E_NONE;

    /* Create BCM KNET network interface.
     * BCM diag command:
     *   BCM.0> knet netif create IFName="eth_NAME" Port=xeN
     */
    opennsl_knet_netif_t_init(&knet_if);

    strncpy(knet_if.name, name, OPENNSL_KNET_NETIF_NAME_MAX);
    knet_if.type = OPENNSL_KNET_NETIF_T_TX_LOCAL_PORT;
    memcpy(knet_if.mac_addr, mac, ETH_ALEN);
    knet_if.port = hw_port;

    rc = opennsl_knet_netif_create(hw_unit, &knet_if);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error creating KNET interface: unit=%d intf_name=%s hw_port=%d rc=%s",
                 hw_unit, name, hw_port, opennsl_errmsg(rc));
        return 1;
    }

    /* Store the interface ID. */
    *knet_if_id = knet_if.id;

    /* Bring the virtual Ethernet interface UP. */
    /* HALON_TODO: Change the 'system' function to something better. */
    snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s up", knet_if.name);
    rc = system(cmd);
    if (rc != 0) {
        VLOG_ERR("Failed to bring up KNET interface. Name=%s (rc=%d)",
                 knet_if.name, rc);
        return 1;
    }

    return 0;

} /* bcmsdk_knet_if_create */

int
bcmsdk_knet_if_delete(char *name, int hw_unit, int knet_if_id)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    /* KNET intferface ID starts from 1. */
    if (knet_if_id) {
        rc = opennsl_knet_netif_destroy(hw_unit, knet_if_id);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to delete KNET interface: unit=%d intf_name=%s rc=%s",
                     hw_unit, name, opennsl_errmsg(rc));
            return 1;
        }
    }
    return 0;

} /* bcmsdk_knet_if_delete */

void
bcmsdk_knet_filter_create(char *name, int hw_unit, opennsl_port_t hw_port,
                          int knet_if_id, int *knet_filter_id)
{
    opennsl_knet_filter_t knet_filter;
    opennsl_error_t rc = OPENNSL_E_NONE;

    /* Create BCM KNET network filter.
     * BCM diag commands:
     *  BCM.0> knet filter create DestType=NetIF DestID=XX StripTag=yes Desc=knet_filter_xeN
     */
    opennsl_knet_filter_t_init(&knet_filter);

    knet_filter.type = OPENNSL_KNET_FILTER_T_RX_PKT;

    snprintf(knet_filter.desc, OPENNSL_KNET_FILTER_DESC_MAX,
             "knet_filter_%s", name);

    knet_filter.priority = KNET_FILTER_PRIO;
    knet_filter.dest_type = OPENNSL_KNET_DEST_T_NETIF;
    knet_filter.dest_id = knet_if_id;
    knet_filter.flags |= OPENNSL_KNET_FILTER_F_STRIP_TAG;
    knet_filter.match_flags |= OPENNSL_KNET_FILTER_M_INGPORT;
    knet_filter.m_ingport = hw_port;

    rc = opennsl_knet_filter_create(hw_unit, &knet_filter);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error creating KNET filter rule. unit=%d intf_name=%s hw_port=%d rc=%s",
                 hw_unit, name, hw_port, opennsl_errmsg(rc));
        *knet_filter_id = 0;
    }

    /* Store the filter ID. */
    *knet_filter_id = knet_filter.id;

} /* bcmsdk_knet_filter_create */

void
bcmsdk_knet_filter_delete(char *name, int hw_unit, int knet_filter_id)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    /* KNET filter ID starts from 2. ID 1 is used by default rule. */
    if (knet_filter_id > 1) {
        rc = opennsl_knet_filter_destroy(hw_unit, knet_filter_id);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to delete KNET filter rule. unit=%d intf_name=%s rc=%s",
                     hw_unit, name, opennsl_errmsg(rc));
        }
    }
} /* bcmsdk_knet_filter_delete */


///////////////////////////////// INIT /////////////////////////////////

int
hc_knet_init(int hw_unit)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    rc = opennsl_knet_init(hw_unit);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to initialize BCM KNET subsystem. unit=%d rc=%s",
                 hw_unit, opennsl_errmsg(rc));
        return 1;
    }

    /* HALON_TODO: Delete all the existing KNET interfaces and filters.
     * When SDK restarts, existing interfaces and filters are not deleted
     * from the kernel.
     */

    return 0;

} /* hc_knet_init */
