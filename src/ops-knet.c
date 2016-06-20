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
 * File: ops-knet.c
 *
 * Purpose: This file contains implementation of KNET virtual linux Ethernet interface.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/knet.h>
#include <opennsl/rx.h>

#include "platform-defines.h"
#include "ops-debug.h"
#include "ops-knet.h"
#include "ops-classifier.h"
#include "eventlog.h"

VLOG_DEFINE_THIS_MODULE(ops_knet);

/* Byte positions of ETHERTYPE in ethernet frames */
#define FRAME_ETHERTYPE_BYTE1_POSITION      16
#define FRAME_ETHERTYPE_BYTE2_POSITION      17

/* KNET Filter raw data size for comparison */
#define FILTER_RAW_DATA_SIZE                24

struct knet_if_info {
    char *name;
    int if_id;
};

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
    memcpy(knet_if.mac_addr, mac, ETH_ALEN);

    if(hw_port == -1) {
        knet_if.type = OPENNSL_KNET_NETIF_T_TX_CPU_INGRESS;
        knet_if.port = 0;
    } else {
        knet_if.type = OPENNSL_KNET_NETIF_T_TX_LOCAL_PORT;
        knet_if.port = hw_port;
    }

    rc = opennsl_knet_netif_create(hw_unit, &knet_if);

    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error creating KNET interface: unit=%d intf_name=%s hw_port=%d rc=%s",
                 hw_unit, name, hw_port, opennsl_errmsg(rc));
        return 1;
    }

    /* Store the interface ID. */
    *knet_if_id = knet_if.id;

    /* Bring the virtual Ethernet interface UP. */
    /* OPS_TODO: Change the 'system' function to something better. */
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

    /* KNET interface ID starts from 1. */
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


static int
get_netif_by_name(int unit, opennsl_knet_netif_t *netif, void *knetif)
{
    int rc = OPENNSL_E_NONE;
    char * ifname = ((struct knet_if_info *)knetif)->name;

    if(strcmp(netif->name, ifname) == 0) {
       ((struct knet_if_info *)knetif)->if_id = netif->id;
    }
    return rc;
}

int bcmsdk_knet_ifid_get_by_name(char *if_name, int hw_unit)
{
    struct knet_if_info knetif;

    knetif.name = if_name;
    knetif.if_id = 0;

    if (opennsl_knet_netif_traverse(hw_unit, get_netif_by_name, &knetif) < 0) {
        VLOG_ERR("Traverse to find knet interface %s failed", if_name);
    }

    return knetif.if_id;
}

/* Create filter for sFlow sampling. 'filter' contains info on type of
 * incoming traffic that hits that 'filter' (L2, L3 etc). Use it to create
 * sFlow filter for that traffic type.
 */
void
bcmsdk_knet_sflow_filter_create(opennsl_knet_filter_t *filter, int priority,
        char *desc, int *filter_id)
{
    opennsl_knet_filter_t   knet_filter;
    opennsl_error_t rc = OPENNSL_E_NONE;

    if (filter == NULL || desc == NULL) {
        VLOG_ERR("Invalid params passed in creating sFlow KNET filter");
        return;
    }

    opennsl_knet_filter_t_init(&knet_filter);

    memcpy(&knet_filter, filter, sizeof(opennsl_knet_filter_t));
    snprintf(knet_filter.desc, OPENNSL_KNET_FILTER_DESC_MAX, desc);
    knet_filter.priority = priority;
    knet_filter.match_flags |= OPENNSL_KNET_FILTER_M_REASON;
    knet_filter.mirror_type = OPENNSL_KNET_DEST_T_OPENNSL_RX_API;

    OPENNSL_RX_REASON_SET(knet_filter.m_reason, opennslRxReasonSampleSource);

    rc = opennsl_knet_filter_create(0, &knet_filter);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error creating sFlow KNET filter rule. rc=%s", opennsl_errmsg(rc));
        *filter_id = 0;
    }

    *filter_id = knet_filter.id;
}

void
bcmsdk_knet_port_bpdu_filter_create(char *name, int hw_unit, opennsl_port_t hw_port,
                               int knet_if_id, int *knet_filter_id,
                               int *knet_sflow_filter_id)
{
    opennsl_knet_filter_t knet_filter;
    opennsl_error_t rc = OPENNSL_E_NONE;
    char    desc[OPENNSL_KNET_FILTER_DESC_MAX];

    /* Create filter for BPDU */

    opennsl_knet_filter_t_init(&knet_filter);

    knet_filter.type = OPENNSL_KNET_FILTER_T_RX_PKT;

    snprintf(knet_filter.desc, OPENNSL_KNET_FILTER_DESC_MAX,
             "knet_filter_bpdu_%s", name);

    knet_filter.priority = KNET_FILTER_PRIO_BPDU;
    knet_filter.dest_type = OPENNSL_KNET_DEST_T_NETIF;
    knet_filter.dest_id = knet_if_id;
    knet_filter.flags |= OPENNSL_KNET_FILTER_F_STRIP_TAG;
    knet_filter.match_flags |= (OPENNSL_KNET_FILTER_M_INGPORT | OPENNSL_KNET_FILTER_M_RAW);
    knet_filter.m_ingport = hw_port;

     knet_filter.raw_size = 24;
     memset(knet_filter.m_raw_data, 0, FILTER_RAW_DATA_SIZE);
     memset(knet_filter.m_raw_mask, 0, FILTER_RAW_DATA_SIZE);

     /* BPDU - based on dst mac */
     knet_filter.m_raw_data[0] = 0x01;
     knet_filter.m_raw_data[1] = 0x80;
     knet_filter.m_raw_data[2] = 0xC2;
     knet_filter.m_raw_data[3] = 0x00;
     knet_filter.m_raw_data[4] = 0x00;

     /* Populate filter mask */
     knet_filter.m_raw_mask[0] = 0xFF;
     knet_filter.m_raw_mask[1] = 0xFF;
     knet_filter.m_raw_mask[2] = 0xFF;
     knet_filter.m_raw_mask[3] = 0xFF;
     knet_filter.m_raw_mask[4] = 0xFF;

    rc = opennsl_knet_filter_create(hw_unit, &knet_filter);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error creating KNET filter rule. unit=%d intf_name=%s hw_port=%d rc=%s",
                 hw_unit, name, hw_port, opennsl_errmsg(rc));
        *knet_filter_id = 0;
    }

    /* Store the filter ID. */
    *knet_filter_id = knet_filter.id;

    /* sFlow filter */
    snprintf(desc, OPENNSL_KNET_FILTER_DESC_MAX, "sflow_knet_filter_bpdu_%s", name);
    bcmsdk_knet_sflow_filter_create(&knet_filter, KNET_FILTER_PRIO_SFLOW_BPDU, desc,
            knet_sflow_filter_id);

} /* bcmsdk_knet_port_bpdu_filter_create */

void
bcmsdk_knet_l3_port_filter_create(int hw_unit, int vid, opennsl_port_t hw_port,
                               int knet_if_id, int *knet_filter_id,
                               int *knet_sflow_filter_id)
{
    opennsl_knet_filter_t knet_filter;
    opennsl_error_t rc = OPENNSL_E_NONE;
    char    desc[OPENNSL_KNET_FILTER_DESC_MAX];

    /* Create BCM KNET network filter.
     * BCM diag commands:
     *  BCM.0> knet filter create DestType=NetIF DestID=XX StripTag=yes Desc=knet_filter_xeN
     */
    opennsl_knet_filter_t_init(&knet_filter);

    knet_filter.type = OPENNSL_KNET_FILTER_T_RX_PKT;

    snprintf(knet_filter.desc, OPENNSL_KNET_FILTER_DESC_MAX,
             "knet_filter_l3_%d", vid);

    knet_filter.priority = KNET_FILTER_PRIO_PORT;
    knet_filter.dest_type = OPENNSL_KNET_DEST_T_NETIF;
    knet_filter.dest_id = knet_if_id;
    knet_filter.flags |= OPENNSL_KNET_FILTER_F_STRIP_TAG;
    knet_filter.match_flags |= OPENNSL_KNET_FILTER_M_INGPORT | OPENNSL_KNET_FILTER_M_VLAN;
    knet_filter.m_ingport = hw_port;
    knet_filter.m_vlan = vid;

    rc = opennsl_knet_filter_create(hw_unit, &knet_filter);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error creating KNET filter rule. unit=%dhw_port=%d rc=%s",
                 hw_unit, hw_port, opennsl_errmsg(rc));
        *knet_filter_id = 0;
    }

    /* Store the filter ID. */
    *knet_filter_id = knet_filter.id;

    /* Create sFlow KNET filter for l3 interface. */
    snprintf(desc, OPENNSL_KNET_FILTER_DESC_MAX, "sflow_knet_filter_l3_%d", vid);
    bcmsdk_knet_sflow_filter_create(&knet_filter, KNET_FILTER_PRIO_SFLOW_PORT,
            desc, knet_sflow_filter_id);

} /* bcmsdk_knet_l3_port_filter_create */

void
bcmsdk_knet_subinterface_filter_create(int hw_unit, opennsl_port_t hw_port,
                               int knet_if_id, int *knet_filter_id,
                               int *knet_sflow_filter_id)
{
    opennsl_knet_filter_t knet_filter;
    opennsl_error_t rc = OPENNSL_E_NONE;
    char    desc[OPENNSL_KNET_FILTER_DESC_MAX];

    /* Create BCM KNET network filter.
     * BCM diag commands:
     *  BCM.0> knet filter create DestType=NetIF DestID=XX StripTag=yes Desc=knet_filter_xeN
     */
    opennsl_knet_filter_t_init(&knet_filter);

    knet_filter.type = OPENNSL_KNET_FILTER_T_RX_PKT;
    snprintf(knet_filter.desc, OPENNSL_KNET_FILTER_DESC_MAX,
                  "knet_filter_subinterface");

    knet_filter.priority = KNET_FILTER_PRIO_SUBINTF;
    knet_filter.dest_type = OPENNSL_KNET_DEST_T_NETIF;
    knet_filter.dest_id = knet_if_id;
    knet_filter.match_flags |= OPENNSL_KNET_FILTER_M_INGPORT;
    knet_filter.m_ingport = hw_port;

    rc = opennsl_knet_filter_create(hw_unit, &knet_filter);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error creating KNET filter rule. unit=%dhw_port=%d rc=%s",
                 hw_unit, hw_port, opennsl_errmsg(rc));
        *knet_filter_id = 0;
    }

    /* Store the filter ID. */
    *knet_filter_id = knet_filter.id;

    /* Create sFlow KNET filter for sub-interface. */
    snprintf(desc, OPENNSL_KNET_FILTER_DESC_MAX, "sflow_knet_filter_subinterface");
    bcmsdk_knet_sflow_filter_create(&knet_filter, KNET_FILTER_PRIO_SFLOW_SUBINTF,
            desc, knet_sflow_filter_id);

} /* bcmsdk_knet_subinterface_filter_create */

void bcmsdk_knet_bridge_normal_filter_create(char *knet_dst_if_name,
        int *knet_filter_id, int *knet_sflow_filter_id)
{
    opennsl_knet_filter_t knet_filter;
    char    desc[OPENNSL_KNET_FILTER_DESC_MAX+1];

    opennsl_knet_filter_t_init(&knet_filter);

    int knet_dst_id = bcmsdk_knet_ifid_get_by_name(knet_dst_if_name, 0);

    knet_filter.type = OPENNSL_KNET_FILTER_T_RX_PKT;
    snprintf(knet_filter.desc, OPENNSL_KNET_FILTER_DESC_MAX,
             "knet_filter_bridge_normal");

    knet_filter.priority = KNET_FILTER_PRIO_BRIDGE_NORMAL;
    knet_filter.dest_type = OPENNSL_KNET_DEST_T_NETIF;
    knet_filter.dest_id = knet_dst_id;

    opennsl_knet_filter_create(0, &knet_filter);

    /* sFlow */
    snprintf(desc, OPENNSL_KNET_FILTER_DESC_MAX, "sflow_knet_filter_bridge_normal");
    bcmsdk_knet_sflow_filter_create(&knet_filter, KNET_FILTER_PRIO_SFLOW_BRIDGE_NORMAL,
            desc, knet_sflow_filter_id);

} /* bcmsdk_knet_bridge_normal_filter_create */

void bcmsdk_knet_acl_logging_filter_create(char *knet_dst_if_name,
        int *knet_filter_id)
{
    opennsl_error_t rc;
    const char *desc = "knet_filter_acl_logging";
    opennsl_knet_filter_t knet_filter;
    opennsl_knet_filter_t_init(&knet_filter);

    knet_filter.type = OPENNSL_KNET_FILTER_T_RX_PKT;
    snprintf(knet_filter.desc, OPENNSL_KNET_FILTER_DESC_MAX,
             desc);

    /* Note that this priority can be very high because the only packets copied
     * for ACL logging are packets that should be denied/dropped, so no other
     * parts of the system should need to see them. */
    knet_filter.priority = KNET_FILTER_PRIO_ACL_LOGGING;
    knet_filter.dest_type = OPENNSL_KNET_DEST_T_OPENNSL_RX_API;
    knet_filter.m_fp_rule = ACL_LOG_RULE_ID;
    knet_filter.flags |= OPENNSL_KNET_FILTER_F_STRIP_TAG;
    knet_filter.match_flags |= OPENNSL_KNET_FILTER_M_REASON
                               | OPENNSL_KNET_FILTER_M_FP_RULE;
    OPENNSL_RX_REASON_SET(knet_filter.m_reason, opennslRxReasonFilterMatch);

    rc = opennsl_knet_filter_create(0, &knet_filter);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to create KNET filter for: %s", desc);
        *knet_filter_id = 0;
    } else {
        VLOG_DBG("Successfully created KNET filter for: %s, id=%d", desc, knet_filter.id);
        *knet_filter_id = knet_filter.id;
    }

    return;
} /* bcmsdk_knet_acl_logging_filter_create */

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


///////////////////////////////// DEBUG/DUMP /////////////////////////////////

/* Note:  See knet.h, OPENNSL_KNET_NETIF_T_xxx */
static char *netif_type[] = {
    "unknown", "Vlan", "Port", "Meta", NULL
};

/* Note:  See knet.h, OPENNSL_KNET_DEST_T_xxx */
static char *filter_dest_type[] = {
    "Null", "NetIF", "RxAPI", "CallBack", NULL
};

static void
knet_show_netif (int unit, opennsl_knet_netif_t *netif, struct ds *ds)
{
    char *type_str = "?";
    char *port_str = "n/a";

    switch (netif->type) {
    case OPENNSL_KNET_NETIF_T_TX_CPU_INGRESS:
        type_str = netif_type[netif->type];
        break;
    case OPENNSL_KNET_NETIF_T_TX_LOCAL_PORT:
        type_str = netif_type[netif->type];
#if 0
        /* OPS_TODO: OpenNSL unavailable */
        port_str = OPENNSL_PORT_NAME(unit, netif->port);
#endif
        break;
    default:
        break;
    }

    ds_put_format(ds, "Interface ID %d: name=%s type=%s vlan=%d port=%s",
                  netif->id, netif->name, type_str, netif->vlan, port_str);

    if (netif->flags & OPENNSL_KNET_NETIF_F_ADD_TAG) {
        ds_put_format(ds, " addtag");
    }
    ds_put_format(ds, "\n");
}

static int
knet_netif_traverse_cb (int unit, opennsl_knet_netif_t *netif, void *user_data)
{
    struct knet_user_data *params = (struct knet_user_data *)user_data;
    struct ds *ds = params->ds;

    knet_show_netif(unit, netif, ds);

    params->count++;

    return OPENNSL_E_NONE;
}

static void
ops_knet_netif_show (struct ds *ds)
{
    struct knet_user_data user_data;
    int unit = 0;
    int ret;

    user_data.ds = ds;
    user_data.count = 0;

    ret = opennsl_knet_netif_traverse(unit, knet_netif_traverse_cb,
                                      &user_data);
    if (ret != OPENNSL_E_NONE) {
        VLOG_ERR("KNET netif traversal failure");
    }
    if (user_data.count == 0) {
        ds_put_format(ds, "No network interfaces\n");
    }
}

static void
knet_show_filter(int unit, opennsl_knet_filter_t *filter, struct ds *ds)
{
    char *dest_str = "?";
    char proto_str[16];
    int idx, edx;

    switch (filter->dest_type) {
    case OPENNSL_KNET_DEST_T_NETIF:
        dest_str = filter_dest_type[filter->dest_type];
        break;
    default:
        break;
    }

    proto_str[0] = 0;
    if (filter->dest_proto) {
        sprintf(proto_str, "[0x%04x]", filter->dest_proto);
    }
    ds_put_format(ds, "Filter ID %d: prio=%d dest=%s(%d)%s desc='%s'",
                filter->id, filter->priority, dest_str,
                filter->dest_id, proto_str, filter->desc);
    if (filter->mirror_type ==  OPENNSL_KNET_DEST_T_NETIF) {
        proto_str[0] = 0;
        if (filter->mirror_proto) {
            sprintf(proto_str, "[0x%04x]", filter->mirror_proto);
        }
        ds_put_format(ds, " mirror=netif(%d)%s", filter->mirror_id, proto_str);
    }
    if (filter->flags & OPENNSL_KNET_FILTER_F_STRIP_TAG) {
        ds_put_format(ds, " striptag");
    }
    if (filter->match_flags & OPENNSL_KNET_FILTER_M_VLAN) {
        ds_put_format(ds, " vlan=%d", filter->m_vlan);
    }

    /* OPS_TODO: Call OPENNSL_PORT_NAME after it becomes available */
    if (filter->match_flags & OPENNSL_KNET_FILTER_M_INGPORT) {
        ds_put_format(ds, " ingport=%d", filter->m_ingport);
    }

    if (filter->match_flags & OPENNSL_KNET_FILTER_M_RAW) {
        ds_put_format(ds, " rawdata");
        for (idx = 0; idx < filter->raw_size; idx++) {
            if (filter->m_raw_mask[idx]) {
                break;
            }
        }
        for (edx = filter->raw_size - 1; edx > idx; edx--) {
            if (filter->m_raw_mask[edx]) {
                break;
            }
        }
        if (edx < idx) {
            /* Entire mask is empty - should not happen */
            ds_put_format(ds, "?");
        } else {
            /* Show offset of first valid byte */
            ds_put_format(ds, "[%d]", idx);
            /* Dump data */
            for (; idx <= edx; idx++) {
                if (filter->m_raw_mask[idx]) {
                    ds_put_format(ds, ":0x%02x", filter->m_raw_data[idx]);
                    if (filter->m_raw_mask[idx] != 0xff) {
                        ds_put_format(ds, "/0x%02x", filter->m_raw_mask[idx]);
                    }
                } else {
                    ds_put_format(ds, ":-");
                }
            }
        }
    }
    ds_put_format(ds, "\n");
}

static int
knet_filter_traverse_cb (int unit, opennsl_knet_filter_t *filter,
                         void *user_data)
{
    struct knet_user_data *params = (struct knet_user_data *)user_data;
    struct ds *ds = params->ds;

    knet_show_filter(unit, filter, ds);

    params->count++;

    return OPENNSL_E_NONE;
}

static void
ops_knet_filter_show (struct ds *ds)
{
    struct knet_user_data user_data;
    int unit = 0;
    int ret;

    user_data.ds = ds;
    user_data.count = 0;

    ret = opennsl_knet_filter_traverse(unit, knet_filter_traverse_cb,
                                       &user_data);
    if (ret != OPENNSL_E_NONE) {
        VLOG_ERR("KNET filter traversal failure");
    }
    if (user_data.count == 0) {
        ds_put_format(ds, "No knet filters\n");
    }
}

void
ops_knet_dump (struct ds *ds, knet_debug_type_t debug_type)
{
    switch (debug_type) {
    case KNET_DEBUG_NETIF:
        ops_knet_netif_show(ds);
        break;
    case KNET_DEBUG_FILTER:
        ops_knet_filter_show(ds);
        break;
    default:
        VLOG_ERR("show knet unknown option ");
        break;
    }
}

///////////////////////////////// INIT /////////////////////////////////

int
ops_knet_init(int hw_unit)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    rc = opennsl_knet_init(hw_unit);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to initialize BCM KNET subsystem. unit=%d rc=%s",
                 hw_unit, opennsl_errmsg(rc));
        return 1;
    }

    /* OPS_TODO: Delete all the existing KNET interfaces and filters.
     * When SDK restarts, existing interfaces and filters are not deleted
     * from the kernel.
     */

    return 0;

} /* ops_knet_init */
