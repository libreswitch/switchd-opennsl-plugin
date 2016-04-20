/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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
 */

/*
 * File: ops-qos.h
 */

#ifndef __OPS_QOS_H__
#define __OPS_QOS_H__ 1

#include <stdint.h>
#include <ofproto/ofproto-provider.h>
#include <opennsl/types.h>
#include <opennsl/qos.h>
#include <opennsl/cosq.h>
#include "ofproto-bcm-provider.h"
#include "platform-defines.h"
#include "qos-asic-provider.h"

#define OPS_QOS_SUCCESS_CODE               0
#define OPS_QOS_FAILURE_CODE              -1

#define OPS_EGR_QOS_MAP_ID_NO_CHANGE      -1
#define OPS_ING_QOS_MAP_ID_NO_CHANGE      -1

#define OPS_EGR_QOS_MAP_ID_NONE            0
#define OPS_ING_QOS_MAP_ID_NONE            0

#define OPS_QOS_COS_MAP_ID_DEFAULT        -1
#define OPS_QOS_DSCP_MAP_ID_DEFAULT       -1
#define OPS_QOS_DSCP_MAP_ALL              -1
#define OPS_QOS_PORT_TRUST_DEFAULT        -1

#define OPS_QOS_COS_COUNT                  8
#define OPS_QOS_DSCP_COUNT                 64

/* QoS scheduling related macros */
#define OPS_OPENNSL_HSP_SCHED_L0_COUNT     5
#define OPS_OPENNSL_HSP_SCHED_L1_COUNT     10
#define OPS_OPENNSL_CPU_SCHED_L2_COUNT     44


/* Maximum number of hardware units (asics) on the system */
#define OPS_QOS_MAX_UNITS                  MAX_SWITCH_UNITS
#define OPS_QOS_MAX_SWITCH_UNIT_ID         MAX_SWITCH_UNIT_ID

/* COS map structure */
typedef struct ops_cos_map_entry_s {

    /* Color to be assigned */
    int color;

    /* Internal priority to be assigned */
    int int_priority;

} ops_cos_map_entry_t;

/* DSCP map structure */
typedef struct ops_dscp_map_entry_s {

    /* Color to be assigned */
    int color;

    /* Internal priority to be assigned */
    int int_priority;

    /* COS remark value */
    int cos_remark;

} ops_dscp_map_entry_t;

/* Scheduling nodes structure */
typedef struct ops_qos_sched_nodes_s {

    /* Hardware unit number */
    int hw_unit;

    /* Hardware port number */
    int hw_port;

    opennsl_gport_t gport;

    /* Port root scheduler */
    opennsl_gport_t port_sched;

    /* Level 0 (L0) node */
    opennsl_gport_t level0_sched;

    /* Level 1 (L1) nodes - one for each cos */
    opennsl_gport_t level1_sched[OPENNSL_COS_COUNT];

    /* Level 2 (L2) nodes - unicast queue for eash cosq */
    opennsl_gport_t uc_queue[OPENNSL_COS_COUNT];

    /* Level 2 (L2) nodes - multicast queue for eash cosq */
    opennsl_gport_t mc_queue[OPENNSL_COS_COUNT];

} ops_qos_sched_nodes_t;

/* Port config structure */
typedef struct ops_qos_port_config_s {

    /* Trust config */
    int trust;

    /* Flag to identify if COS override is in use */
    bool cos_override_enable;

    /* Flag to identify if DSCP override is in use */
    bool dscp_override_enable;

    /*
     * COS override value.
     * Valid only if COS override flag is TRUE.
     */
    uint8_t cos_override_value;

    /*
     * DSCP override value.
     * Valid only if DSCP override flag is TRUE.
     */
    uint8_t dscp_override_value;

} ops_qos_port_config_t;

/* Structure for global QoS configs */
typedef struct ops_qos_config_s {

    /*
     * QoS port config
     * OPS_TODO:
     *     Use per unit max ports instead of MAX_HW_PORTS
     *     as MAX_HW_PORTS is for entire system. For now, it's ok.
     */
    ops_qos_port_config_t port_cfg[OPS_QOS_MAX_UNITS][MAX_HW_PORTS];

    /* COS map config */
    ops_cos_map_entry_t cos_map[OPS_QOS_COS_COUNT];

    /* DSCP map config */
    ops_dscp_map_entry_t dscp_map[OPS_QOS_DSCP_COUNT];

    /* Default COS map id for each hardware unit */
    int cos_map_id_default[OPS_QOS_MAX_UNITS];

    /* COS map id for each hardware unit */
    int cos_map_id[OPS_QOS_MAX_UNITS];

    /* DSCP map id for each hardware unit */
    int dscp_map_id[OPS_QOS_MAX_UNITS];

    /*
     * Date structure for scheduling hierarchy
     * OPS_TODO:
     *     Use per unit max ports instead of MAX_HW_PORTS
     *     as MAX_HW_PORTS is for entire system. For now, it's ok.
     */
    ops_qos_sched_nodes_t *sched_nodes[OPS_QOS_MAX_UNITS][MAX_HW_PORTS];

} ops_qos_config_t;

extern int
ops_qos_global_init();

extern int
ops_qos_hw_unit_init(int hw_unit);

extern int
ops_qos_set_cos_map(const struct cos_map_settings *settings);

extern int
ops_qos_set_dscp_map(const struct dscp_map_settings *settings);

extern int
ops_qos_set_port_cfg(struct ofbundle *bundle,
                           int hw_unit, int hw_port,
                           const struct  qos_port_settings *cfg);

extern int
ops_qos_get_cosq_stats(int hw_unit, int hw_port,
                       netdev_dump_queue_stats_cb* cb,
                       void *aux);

extern int
ops_qos_apply_queue_profile(struct bcmsdk_provider_node *ofproto,
                       const struct schedule_profile_settings *s_settings,
                       const struct queue_profile_settings *q_settings);

extern int
ops_qos_apply_schedule_profile(struct ofbundle *bundle,
                       int hw_unit, int hw_port,
                       const struct schedule_profile_settings *s_settings,
                       const struct queue_profile_settings *q_settings);

extern void
ops_qos_dump_trust(struct ds *ds);

extern void
ops_qos_dump_cos_map(struct ds *ds);

extern void
ops_qos_dump_dscp_map(struct ds *ds);

extern void
ops_qos_dump_dscp_override(struct ds *ds);

extern void
ops_qos_dump_queuing(struct ds *ds);

extern void
ops_qos_dump_scheduling(struct ds *ds);

extern void
ops_qos_dump_statistics(struct ds *ds);

extern void
ops_qos_dump_all(struct ds *ds);

#endif /* __OPS_QOS_H__ */
