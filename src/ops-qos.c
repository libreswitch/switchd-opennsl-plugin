/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
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
 *
 */

/*
 * File: ops-qos.c
 *
 * Purpose:
 *     This file contains code to enable QoS functionality
 *     in Broadcom ASIC.
 */

#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <util.h>

#include <netdev.h>
#include <ofproto/ofproto-provider.h>
#include <openvswitch/vlog.h>

#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/qos.h>
#include <opennsl/cosq.h>
#include <opennsl/stat.h>

#include "ops-qos.h"
#include "qos-asic-provider.h"

/*
 * QoS global config structure
 * OPS_TODO:
 *      Do we need this per VRF???
 *      Per VRF QoS config is not supported now
 *      and not planned for near future.
 */
ops_qos_config_t ops_qos_config;

/*
 * QoS global index used for scheduling node retrieval callback
 */
int ops_qos_global_scheduling_index = 0;

/*
 * Logging module for QoS.
 */
VLOG_DEFINE_THIS_MODULE(ops_qos);

/*
 * ops_qos_global_init
 *
 * This function initializes the global data structures
 * used for QoS feature.
 */
int
ops_qos_global_init()
{
    int rc = OPS_QOS_SUCCESS_CODE;

    /* Initialize the global structure to 0 */
    memset(&ops_qos_config, 0, sizeof(ops_qos_config_t));

    VLOG_DBG("QoS global initialization done");

    return rc;
}

/*
 * ops_qos_schedule_callback
 *
 * This function is the callback handler for retrieving SDK created cosq
 * gports and updating the OPS scheduling data structures for each port.
 */
int
ops_qos_schedule_callback(int unit, opennsl_gport_t port, int numq,
                          uint32 flags, opennsl_gport_t gport,
                          void *user_data)
{
    int hw_port;
    int index = ops_qos_global_scheduling_index;
    ops_qos_sched_nodes_t *port_sched_node;

    hw_port = OPENNSL_GPORT_MODPORT_PORT_GET(port);

    VLOG_DBG("ops_qos_schedule_callback: port %d, hw_port %d, flags 0x%x, "
              "gport 0x%x numq %d",
               port, hw_port, flags, gport, numq);

    if (hw_port == 0) {
        /*
         * If local port is 0, it's a CPU port and nothing needs to
         * be done.
         */
        return OPS_QOS_SUCCESS_CODE;
    }

    if (!VALID_HW_UNIT(unit) || !VALID_HW_UNIT_PORT(unit,
        hw_port)) {
        VLOG_ERR("ops_qos_schedule_callback: invalid hw unit %d "
                 "or port %d",
                  unit, hw_port);

        return OPS_QOS_FAILURE_CODE;
    }

    /* Allocate memory for sched node structure if not allocated */
    if (ops_qos_config.sched_nodes[unit][hw_port] == NULL) {
        port_sched_node =
           (ops_qos_sched_nodes_t *)xzalloc(sizeof(ops_qos_sched_nodes_t));
        if (port_sched_node == NULL) {
            VLOG_ERR("ops_qos_schedule_callback memory allocation failed for "
                     "hw_unit %d, hw_port %d",
                      unit, hw_port);

            return OPS_QOS_FAILURE_CODE;
        }

        port_sched_node->hw_unit = unit;
        port_sched_node->hw_port = hw_port;
        port_sched_node->level0_sched = port;

        ops_qos_config.sched_nodes[unit][hw_port] = port_sched_node;
    }

    /* Following code is ported from Broadcom script */
    if (index < OPENNSL_COS_COUNT) {

        port_sched_node = ops_qos_config.sched_nodes[unit][hw_port];

        if (flags & OPENNSL_COSQ_GPORT_SCHEDULER) {
            port_sched_node->level1_sched[index] = gport;
        } else if (flags & OPENNSL_COSQ_GPORT_UCAST_QUEUE_GROUP) {
            port_sched_node->uc_queue[index] = gport;
        } else if (flags & OPENNSL_COSQ_GPORT_MCAST_QUEUE_GROUP) {
            port_sched_node->mc_queue[index] = gport;
        } else {
            VLOG_ERR("ops_qos_schedule_callback: Invalid flags for "
                     "unit %d hw_port %d, flags 0x%x",
                      unit, hw_port, flags);
        }
    }

    ops_qos_global_scheduling_index = (index + 1) % (OPENNSL_COS_COUNT+2);

    return OPS_QOS_SUCCESS_CODE;

}

/*
 * ops_qos_retrieve_scheduling_nodes
 *
 * This function just passes the callback handler to retrieve the SDK
 * created cosq gports for the given hardware unit.
 */
static int
ops_qos_retrieve_scheduling_nodes(int hw_unit)
{
    opennsl_error_t rc;

    rc = opennsl_cosq_gport_traverse(hw_unit,
                                     ops_qos_schedule_callback, NULL);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("QoS: opennsl_cosq_gport_traverse failed for unit %d, "
                 "rc %d - %s",
                  hw_unit, rc, opennsl_errmsg(rc));

        return OPS_QOS_FAILURE_CODE;
    }

    return OPS_QOS_SUCCESS_CODE;

}

/*
 * ops_qos_hsp_port_sched_init
 *
 * This function initializes the scheduling hierarchy for
 * HSP ports (High Speed Port).
 *
 * Scheduling hierarchy for each port
 * ==================================
 *
 *   Port scheduler
 *   |
 *   ----> 5 Level 0 schedulers
 *         |
 *         ----> 10 L1 schedulers (8 for L0.1 and 2 for L0.4)
 *               |
 *               ----> 2 L2 nodes per L1 (1 unicast queue + 1 multicast queue)
 *
 */
static int
ops_qos_hsp_port_sched_init(int unit, int hw_port)
{
    int         l0_idx;
    int         l1_idx;
    int         cos;
    const int   l0_node_count = OPS_OPENNSL_HSP_SCHED_L0_COUNT;
    const int   queue_count = OPS_OPENNSL_HSP_SCHED_L1_COUNT;
    const int   l1_per_l0[5] = { 0, OPENNSL_COS_COUNT, 0, 0, 2 };
    ops_qos_sched_nodes_t *port_sched_node;

    opennsl_gport_t gport;
    opennsl_gport_t port_sched;
    opennsl_error_t rc;
    opennsl_gport_t uc_queues[queue_count];
    opennsl_gport_t mc_queues[queue_count];
    opennsl_gport_t l0_gport[l0_node_count];
    opennsl_gport_t l1_gport[queue_count];

    if (!VALID_HW_UNIT(unit) || !VALID_HW_UNIT_PORT(unit,
        hw_port)) {
        VLOG_ERR("ops_qos_hsp_port_sched_init: invalid hw unit %d "
                 "or port %d",
                  unit, hw_port);
    }

    VLOG_DBG("QoS: Creating HSP schedule hierarchy for hw unit %d port %d",
              unit, hw_port);

    /* Start with egress gport */
    rc = opennsl_port_gport_get(unit, hw_port, &gport);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("HSP opennsl_port_gport_get failed for hw_unit %d "
                 "hw_port %d, rc %d - %s",
                  unit, hw_port, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    /* Delete the existing scheduler */
    rc = opennsl_cosq_gport_delete(unit, gport);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("HSP opennsl_cosq_gport_delete failed for hw_unit %d "
                 "hw_port %d, rc %d - %s",
                  unit, hw_port, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    /* Add port schedule node (l0_node_count input cos, flags=0) */
    rc = opennsl_cosq_gport_add(unit, gport, l0_node_count, 0, &port_sched);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("HSP opennsl_cosq_gport_add failed for "
                 "port schedule node, hw_unit %d "
                 "hw_port %d, rc %d - %s",
                  unit, hw_port, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    /* Allocate memory for sched node structure */
    port_sched_node =
       (ops_qos_sched_nodes_t *)xzalloc(sizeof(ops_qos_sched_nodes_t));
    if (port_sched_node == NULL) {
        VLOG_ERR("HSP memory allocation failed, port sched node structure "
                 "hw_unit %d, hw_port %d",
                  unit, hw_port);

        return OPS_QOS_FAILURE_CODE;
    }

    port_sched_node->hw_unit = unit;
    port_sched_node->hw_port = hw_port;
    port_sched_node->gport = gport;
    port_sched_node->port_sched = port_sched;

    ops_qos_config.sched_nodes[unit][hw_port] = port_sched_node;

    cos = 0;
    for (l0_idx = 1; l0_idx < l0_node_count; l0_idx++) {
        int input_count = l1_per_l0[l0_idx];
        int padded_input_count =
                    input_count < (OPENNSL_COS_COUNT - 1) ? input_count + 1 :
                                                            input_count;

        /* Add the next L0 schedule node */
        rc = opennsl_cosq_gport_add(unit,
                                    gport, padded_input_count,
                                    OPENNSL_COSQ_GPORT_SCHEDULER,
                                    &l0_gport[l0_idx]);

        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("HSP opennsl_cosq_gport_add failed for "
                     "L0 schedule node %d, hw_unit %d "
                     "hw_port %d, rc %d - %s",
                      l0_idx, unit, hw_port, rc, opennsl_errmsg(rc));
            return OPS_QOS_FAILURE_CODE;
        }

        /*
         * Save the L0.1 cosq GPORT ids to use it for user defined scheduling
         * config during run time.
         */
        if (l0_idx == 1 ) {
            port_sched_node->level0_sched = l0_gport[l0_idx];
        }

        /* Attach L0 to the port scheduler */
        rc = opennsl_cosq_gport_attach(unit, l0_gport[l0_idx],
                                       port_sched, l0_idx);
        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("HSP opennsl_cosq_gport_attach failed for "
                     "L0 schedule node %d, hw_unit %d "
                     "hw_port %d, rc %d - %s",
                      l0_idx, unit, hw_port, rc, opennsl_errmsg(rc));
            return OPS_QOS_FAILURE_CODE;
        }


        rc = opennsl_cosq_gport_sched_set(unit, gport,
                                          l0_idx, OPENNSL_COSQ_STRICT, 0);
        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("HSP opennsl_cosq_gport_sched_set failed for "
                     "L0 schedule node %d, hw_unit %d "
                     "hw_port %d, rc %d - %s",
                      l0_idx, unit, hw_port, rc, opennsl_errmsg(rc));
            return OPS_QOS_FAILURE_CODE;
        }


        for (l1_idx = 0; l1_idx < input_count; l1_idx++) {

            /* Add an L1 schedule node for each cos */
            rc = opennsl_cosq_gport_add(unit, gport, 2,
                                        OPENNSL_COSQ_GPORT_SCHEDULER,
                                        &l1_gport[cos]);
           if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("HSP opennsl_cosq_gport_add failed for "
                         "L1 schedule node %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          l1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /* Attach L1 to the L0 scheduler */
            rc = opennsl_cosq_gport_attach(unit, l1_gport[cos],
                                           l0_gport[l0_idx], l1_idx);
            if (OPENNSL_FAILURE(rc)) {
                /* Log a DBG message and try HSP scheduler config */
                VLOG_DBG("HSP opennsl_cosq_gport_attach failed for "
                         "L1 schedule node %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          l1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            rc = opennsl_cosq_gport_sched_set(unit, l0_gport[l0_idx],
                                              l1_idx, OPENNSL_COSQ_STRICT, 0);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("HSP opennsl_cosq_gport_sched_set failed for "
                         "L1 schedule node %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          l1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /* Add a unicast (L2) queue */
            rc = opennsl_cosq_gport_add(unit, gport, 1,
                                        OPENNSL_COSQ_GPORT_UCAST_QUEUE_GROUP,
                                        &uc_queues[cos]);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("HSP opennsl_cosq_gport_add failed for "
                         "UC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          l1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /* Attach unicast queue to L1 node */
            rc = opennsl_cosq_gport_attach(unit, uc_queues[cos],
                                           l1_gport[cos], 0);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("HSP opennsl_cosq_gport_attach failed for "
                         "UC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          l1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /* Add a multicast (L2) queue */
            rc = opennsl_cosq_gport_add(unit, gport, 1,
                                        OPENNSL_COSQ_GPORT_MCAST_QUEUE_GROUP,
                                        &mc_queues[cos]);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("HSP opennsl_cosq_gport_add failed for "
                         "MC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          l1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /* Attach multicast queue to L1 node */
            rc = opennsl_cosq_gport_attach(unit, mc_queues[cos],
                                           l1_gport[cos], 1);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("HSP opennsl_cosq_gport_attach failed for "
                         "MC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          l1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /*
             * Save the L0.1 cosq GPORT ids to use it for user defined
             * scheduling config during run time.
             */
            if (l0_idx == 1 && l1_idx < OPENNSL_COS_COUNT &&
                cos == l1_idx) {
                port_sched_node->level1_sched[l1_idx] = l1_gport[cos];
                port_sched_node->uc_queue[l1_idx] = uc_queues[cos];
                port_sched_node->mc_queue[l1_idx] = mc_queues[cos];
            }

            cos++;

        } /* for (l1_idx =0; ... */

    } /* for (l0_idx = 1; ... */

    return OPS_QOS_SUCCESS_CODE;
}

/*
 * ops_qos_lls_port_sched_init
 *
 * This function initializes the scheduling hierarchy for
 * LLS ports (Linked List Scheduler).
 *
 * Scheduling hierarchy for each port
 * ==================================
 *
 *   Port scheduler
 *   |
 *   ----> Level 0 scheduler
 *         |
 *         ----> 8 L1 schedulers
 *               |
 *               ----> 2 L2 nodes per L1 (1 unicast queue + 1 multicast queue)
 */
static int
ops_qos_lls_port_sched_init(int unit, opennsl_port_t hw_port, int queue_count,
          opennsl_gport_t *uc_queues,
          opennsl_gport_t *mc_queues, int L0_node_count,
          int *L0_config, int *weights)
{
    opennsl_gport_t gp;
    opennsl_gport_t l0_gport;
    opennsl_gport_t l1_gport;
    opennsl_gport_t port_sched;
    opennsl_error_t rc;
    ops_qos_sched_nodes_t *port_sched_node;
    int         cos;
    int         L0_idx;
    int         L1_idx;

    if (queue_count > OPENNSL_COS_COUNT) {
        VLOG_ERR("ops_qos_lls_port_sched_init: invalid queue count "
                 "for hw unit %d port %d",
                  unit, hw_port);
        return OPENNSL_E_PARAM;
    }

    if (!VALID_HW_UNIT(unit) || !VALID_HW_UNIT_PORT(unit,
        hw_port)) {
        VLOG_ERR("ops_qos_lls_port_sched_init: invalid hw unit %d "
                 "or port %d",
                  unit, hw_port);
    }

    VLOG_DBG("QoS: Creating LLS schedule hierarchy for hw unit %d port %d",
              unit, hw_port);

    /* Start with egress gport */
    rc = opennsl_port_gport_get(unit, hw_port, &gp);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("opennsl_port_gport_get failed for hw_unit %d "
                 "hw_port %d, rc %d - %s",
                  unit, hw_port, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    /* Delete the existing scheduler */
    rc = opennsl_cosq_gport_delete(unit, gp);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("opennsl_cosq_gport_delete failed for hw_unit %d "
                 "hw_port %d, rc %d - %s",
                  unit, hw_port, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    /* Add port schedule node (single input cos, flags=0) */
    rc = opennsl_cosq_gport_add(unit, gp, L0_node_count, 0, &port_sched);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("opennsl_cosq_gport_add failed for "
                 "port schedule node, hw_unit %d "
                 "hw_port %d, rc %d - %s",
                  unit, hw_port, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    /* Allocate memory for sched node structure */
    port_sched_node =
       (ops_qos_sched_nodes_t *)xzalloc(sizeof(ops_qos_sched_nodes_t));
    if (port_sched_node == NULL) {
        VLOG_ERR("memory allocation failed, port sched node structure "
                 "hw_unit %d, hw_port %d",
                  unit, hw_port);

        return OPS_QOS_FAILURE_CODE;
    }

    port_sched_node->hw_unit = unit;
    port_sched_node->hw_port = hw_port;
    port_sched_node->gport = gp;
    port_sched_node->port_sched = port_sched;

    ops_qos_config.sched_nodes[unit][hw_port] = port_sched_node;

    cos = 0;
    for (L0_idx = 0; L0_idx < L0_node_count; L0_idx++) {
        /* Add the next L0 schedule node */
        rc = opennsl_cosq_gport_add(unit, gp, queue_count,
                                    OPENNSL_COSQ_GPORT_SCHEDULER,
                                    &l0_gport);
        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("opennsl_cosq_gport_add failed for "
                     "L0 schedule node %d, hw_unit %d "
                     "hw_port %d, rc %d - %s",
                      L0_idx, unit, hw_port, rc, opennsl_errmsg(rc));
            return OPS_QOS_FAILURE_CODE;
        }

        /*
         * Save the cosq GPORT id to use it for user defined scheduling
         * config during run time.
         */
        port_sched_node->level0_sched = l0_gport;

        /* Attach L0 to the port scheduler */
        rc = opennsl_cosq_gport_attach(unit, l0_gport, port_sched, L0_idx);
        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("opennsl_cosq_gport_attach failed for "
                     "L0 schedule node %d, hw_unit %d "
                     "hw_port %d, rc %d - %s",
                      L0_idx, unit, hw_port, rc, opennsl_errmsg(rc));
            return OPS_QOS_FAILURE_CODE;
        }

        rc = opennsl_cosq_gport_sched_set(unit, port_sched, L0_idx,
                          weights[L0_idx] ? OPENNSL_COSQ_WEIGHTED_ROUND_ROBIN :
                          OPENNSL_COSQ_STRICT, weights[L0_idx]);
        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("opennsl_cosq_gport_sched_set failed for "
                     "L0 schedule node %d, hw_unit %d "
                     "hw_port %d, rc %d - %s",
                      L0_idx, unit, hw_port, rc, opennsl_errmsg(rc));
            return OPS_QOS_FAILURE_CODE;
        }

        for (L1_idx = 0; L1_idx < L0_config[L0_idx]; L1_idx++) {

            /* Add an L1 schedule node for each cos */
            rc = opennsl_cosq_gport_add(unit, gp, 2,
                                       OPENNSL_COSQ_GPORT_SCHEDULER,
                                       &l1_gport);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_add failed for "
                         "L1 schedule node %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          L1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /* Attach L1 to the L0 scheduler */
            rc = opennsl_cosq_gport_attach(unit, l1_gport, l0_gport, L1_idx);
            if (OPENNSL_FAILURE(rc)) {
                /* Log a DBG message and try HSP scheduler config */
                VLOG_DBG("opennsl_cosq_gport_attach failed for "
                         "L1 schedule node %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          L1_idx, unit, hw_port, rc, opennsl_errmsg(rc));

                /*
                 * Note:
                 *   Broadcom update - depending on the platform, 40G ports
                 *   would use LLS scheduler or HSP scheduler. For e.g. 40G
                 *   ports on AS5712 use LLS scheduler and 40G ports on AS6712
                 *   use HSP scheduler. Currently there is no BCM SDK API or
                 *   OpenNSL API to identify the scheduling mode for any port.
                 *   So, for now, if the ports' scheduling mode is HSP, it
                 *   would fail right here as L1 node can't be attached to the
                 *   first L0 node in HSP scheduler. For this special case,
                 *   undo the LLS config and try HSP scheduler config for
                 *   this port.
                 *
                 * OPS_TODO:
                 *   Follow up with Broadcom if this can be done in a better
                 *   way.
                 */
                free(port_sched_node);
                ops_qos_config.sched_nodes[unit][hw_port] = NULL;
                return (ops_qos_hsp_port_sched_init(unit, hw_port));
            }

            rc = opennsl_cosq_gport_sched_set(unit, l0_gport, L1_idx,
                          weights[L0_idx] ? OPENNSL_COSQ_WEIGHTED_ROUND_ROBIN :
                          OPENNSL_COSQ_STRICT, weights[L0_idx]);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_sched_set failed for "
                         "L1 schedule node %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          L1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /* Add a unicast (L2) queue */
            rc = opennsl_cosq_gport_add(unit, gp, 1,
                                        OPENNSL_COSQ_GPORT_UCAST_QUEUE_GROUP,
                                        &uc_queues[cos + L1_idx]);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_add failed for "
                         "UC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          L1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }


            /* Attach unicast queue to L1 node */
            rc = opennsl_cosq_gport_attach(unit, uc_queues[cos + L1_idx],
                                           l1_gport, 0);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_attach failed for "
                         "UC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          L1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            rc = opennsl_cosq_gport_sched_set(unit, l1_gport, 0,
                          weights[L0_idx] ? OPENNSL_COSQ_WEIGHTED_ROUND_ROBIN :
                          OPENNSL_COSQ_STRICT, weights[L0_idx]);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_sched_set failed for "
                         "UC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          L1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /* Add a multicast (L2) queue */
            rc = opennsl_cosq_gport_add(unit, gp, 1,
                                       OPENNSL_COSQ_GPORT_MCAST_QUEUE_GROUP,
                                       &mc_queues[cos + L1_idx]);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_add failed for "
                         "MC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          L1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            /* Attach multicast queue to L1 node */
            rc = opennsl_cosq_gport_attach(unit, mc_queues[cos + L1_idx],
                                           l1_gport, 1);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_attach failed for "
                         "MC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          L1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            rc = opennsl_cosq_gport_sched_set(unit, l1_gport, 1,
                          weights[L0_idx] ? OPENNSL_COSQ_WEIGHTED_ROUND_ROBIN :
                          OPENNSL_COSQ_STRICT, weights[L0_idx]);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_sched_set failed for "
                         "MC queue %d, hw_unit %d "
                         "hw_port %d, rc %d - %s",
                          L1_idx, unit, hw_port, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            } /* if (OPENNSL_FAILURE(rc)) */

            /*
             * Save the L0.1 cosq GPORT ids to use it for user defined
             * scheduling config during run time.
             */
            if (L1_idx < OPENNSL_COS_COUNT) {
                port_sched_node->level1_sched[L1_idx] = l1_gport;
                port_sched_node->uc_queue[L1_idx] = uc_queues[cos + L1_idx];
                port_sched_node->mc_queue[L1_idx] = mc_queues[cos + L1_idx];
            }

        } /* for (L1_idx = 0; */

        cos += L0_config[L0_idx];

    } /* for (L0_idx = 0; */

    return OPS_QOS_SUCCESS_CODE;

}

/*
 * ops_qos_cpu_port_sched_init
 *
 * This function initializes the scheduling hierarchy for
 * CPU port.
 *
 */
static int
ops_qos_cpu_port_sched_init(int unit)
{
    int   L2_mc_count = OPS_OPENNSL_CPU_SCHED_L2_COUNT;
    int   L1_node_count =
          (L2_mc_count + (OPENNSL_COS_COUNT - 1)) / OPENNSL_COS_COUNT;
    int   max_queues_per_node = OPENNSL_COS_COUNT;

    opennsl_gport_t cpu_port = OPENNSL_GPORT_LOCAL_CPU;
    opennsl_gport_t root;
    opennsl_gport_t L0;
    opennsl_gport_t L1[L1_node_count];
    opennsl_gport_t L2_mc[L2_mc_count];
    opennsl_error_t rc;
    int         mc_index;

    VLOG_DBG("QoS: Initializing CPU port scheduler");

    rc = opennsl_cosq_gport_add(unit, cpu_port, 1, 0, &root);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("opennsl_cosq_gport_add failed for "
                 "CPU port root schedule node, hw_unit %d, "
                 "rc %d - %s",
                  unit, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    rc = opennsl_cosq_gport_add(unit, cpu_port, L1_node_count,
                                OPENNSL_COSQ_GPORT_SCHEDULER, &L0);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("opennsl_cosq_gport_add failed for "
                 "CPU port L0 schedule node, hw_unit %d, "
                 "rc %d - %s",
                  unit, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    rc = opennsl_cosq_gport_attach(unit, L0, root, 0);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("opennsl_cosq_gport_attach failed for "
                 "CPU port L0 schedule node, hw_unit %d, "
                 "rc %d - %s",
                  unit, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }


    mc_index = 0;
    while (mc_index < L2_mc_count) {
        const int remaining_queues = L2_mc_count - mc_index;
        const int   queues_this_pass =
                    (remaining_queues > max_queues_per_node) ?
                      max_queues_per_node : remaining_queues;
        const int         L1_idx = mc_index / max_queues_per_node;
        opennsl_gport_t *L1_ptr = &L1[L1_idx];
        int         L2_idx;

        rc = opennsl_cosq_gport_add(unit, cpu_port, queues_this_pass,
                                    OPENNSL_COSQ_GPORT_SCHEDULER, L1_ptr);
        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("opennsl_cosq_gport_add failed for "
                     "CPU port L1 schedule node, hw_unit %d, "
                     "rc %d - %s",
                      unit, rc, opennsl_errmsg(rc));
            return OPS_QOS_FAILURE_CODE;
        }

        rc = opennsl_cosq_gport_attach(unit, *L1_ptr, L0, L1_idx);
        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("opennsl_cosq_gport_attach failed for "
                     "CPU port L1 schedule node, hw_unit %d, "
                     "rc %d - %s",
                      unit, rc, opennsl_errmsg(rc));
            return OPS_QOS_FAILURE_CODE;
        }

        for (L2_idx = 0; L2_idx < queues_this_pass; L2_idx++) {
            rc = opennsl_cosq_gport_add(unit, cpu_port, 1,
                                        OPENNSL_COSQ_GPORT_MCAST_QUEUE_GROUP,
                                        &L2_mc[mc_index + L2_idx]);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_add failed for "
                         "CPU port L2 schedule node, hw_unit %d, "
                         "rc %d - %s",
                          unit, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

            rc = opennsl_cosq_gport_attach(unit, L2_mc[mc_index + L2_idx],
                                          *L1_ptr, L2_idx);
            if (OPENNSL_FAILURE(rc)) {
                /* Log an ERR message and return */
                VLOG_ERR("opennsl_cosq_gport_attach failed for "
                         "CPU port L2 schedule node, hw_unit %d, "
                         "rc %d - %s",
                          unit, rc, opennsl_errmsg(rc));
                return OPS_QOS_FAILURE_CODE;
            }

        } /* for (L2_idx = 0; ... */

        mc_index += queues_this_pass;

    } /* while (mc_index ... */

    return OPS_QOS_SUCCESS_CODE;
}

/*
 * ops_qos_scheduler_init
 *
 * This function initializes the QoS MMU scheduler for
 * Broadcom ASIC.
 *
 */
static int
ops_qos_scheduler_init(int hw_unit)
{
    int cosq;
    int queue_count = OPENNSL_COS_COUNT;
    int L0_node_count = 1;
    int L0_config[L0_node_count];
    int weights[L0_node_count];

    opennsl_gport_t hg_mc_queues[queue_count];
    opennsl_gport_t hg_uc_queues[queue_count];
    opennsl_gport_t xe_mc_queues[queue_count];
    opennsl_gport_t xe_uc_queues[queue_count];
    opennsl_port_config_t port_config;
    opennsl_port_t  hg_ports[MAX_HW_PORTS];
    opennsl_port_t  port;
    opennsl_port_t  xe_ports[MAX_HW_PORTS];
    opennsl_error_t rc;

    int hg_port_count = 0;
    int hg_port_idx;
    int xe_port_count = 0;
    int xe_port_idx;
    int priority;

    L0_config[0] =  OPENNSL_COS_COUNT;
    weights[0] = 1;

    rc = opennsl_port_config_get(hw_unit, &port_config);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("opennsl_port_config_get failed for hw_unit %d, "
                 "rc %d - %s",
                  hw_unit, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    /* Create a list of all XE ports */
    OPENNSL_PBMP_ITER(port_config.xe, port) {
        xe_ports[xe_port_count] = port;
        xe_port_count++;
    }

    /*
     * Create a list of all HiGig ports.
     * Currently OPS doesn't support any platform that involves
     * HiGig ports but let's keep the code in place to handle all
     * cases.
     */
    OPENNSL_PBMP_ITER(port_config.hg, port) {
        hg_ports[hg_port_count] = port;
        hg_port_count++;
    }

    /*
     * Check for CE ports.
     */
    OPENNSL_PBMP_ITER(port_config.ce, port) {
        /*
         * Currently if the platform has CE ports, then it uses
         * a different scheduler from LLS or HSP. In this case,
         * retrieve the SDK created scheduling nodes instead of creating
         * new nodes.
         * OPS_TODO:
         *   Instead of checking for CE ports for this, this has to come from
         *   platform_init.c for each platform.
         */
        VLOG_INFO("QoS: retieving SDK created scheduling nodes for "
                  "this platform");
        rc = ops_qos_retrieve_scheduling_nodes(hw_unit);

        return rc;
    }

    rc = opennsl_cosq_config_set(hw_unit, OPENNSL_COS_COUNT);
    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("opennsl_cosq_config_set failed for hw_unit %d, "
                 "rc %d - %s", hw_unit, rc, opennsl_errmsg(rc));
        return OPS_QOS_FAILURE_CODE;
    }

    for (priority = 0; priority < (OPENNSL_COS_COUNT * 2); priority++) {
        cosq = (priority < OPENNSL_COS_COUNT) ?
                priority : (OPENNSL_COS_COUNT - 1);

        rc = opennsl_cosq_mapping_set(hw_unit, priority, cosq);
        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("opennsl_cosq_mapping_set failed for hw_unit %d, "
                     "cosq %d, rc %d - %s",
                      rc, hw_unit, cosq, opennsl_errmsg(rc));
            return OPS_QOS_FAILURE_CODE;
        }
    }

    /* Configure schedule for HG ports */
    for (hg_port_idx = 0; hg_port_idx < hg_port_count; hg_port_idx++) {
        opennsl_port_t  hg_port = hg_ports[hg_port_idx];

        rc = ops_qos_lls_port_sched_init(hw_unit, hg_port, queue_count,
                                   hg_uc_queues, hg_mc_queues,
                                   L0_node_count, L0_config, weights);
        if (rc != OPS_QOS_SUCCESS_CODE) {
            return rc;
        }
    }

    /* Configure schedule for XE ports */
    for (xe_port_idx = 0; xe_port_idx < xe_port_count; xe_port_idx++) {
        opennsl_port_t  xe_port = xe_ports[xe_port_idx];

        rc = ops_qos_lls_port_sched_init(hw_unit, xe_port, queue_count,
                                  xe_uc_queues, xe_mc_queues,
                                  L0_node_count, L0_config, weights);
        if (rc != OPS_QOS_SUCCESS_CODE) {
            return rc;
        }
    }

    /* Do configuration for CPU ports as well */
    rc = ops_qos_cpu_port_sched_init(hw_unit);
    if (rc != OPS_QOS_SUCCESS_CODE) {
        return rc;
    }

    VLOG_INFO("QoS: Scheduling heirarchy initialization done");

    /* We reach here if it's all SUCCESS. Return success code */
    return (OPS_QOS_SUCCESS_CODE);
}

/*
 * ops_qos_hw_unit_init
 *
 * This function initializes the hardware unit specific data
 * structures used for QoS feature.
 */
int
ops_qos_hw_unit_init(int hw_unit)
{
    int rc = OPS_QOS_SUCCESS_CODE;
    int hw_port;

    /* Validate the hw_unit */
    if (!VALID_HW_UNIT(hw_unit)) {
        VLOG_ERR("Invalid hw_unit %d passed in for QoS init",
                  hw_unit);
        return OPS_QOS_FAILURE_CODE;
    }

    /* Initialize the COS and DSCP map ids for the hardware unit */
    ops_qos_config.cos_map_id_default[hw_unit] = OPS_QOS_COS_MAP_ID_DEFAULT;
    ops_qos_config.cos_map_id[hw_unit] = OPS_QOS_COS_MAP_ID_DEFAULT;
    ops_qos_config.dscp_map_id[hw_unit] = OPS_QOS_DSCP_MAP_ID_DEFAULT;

    /* Initialize the trust config for all ports */
    for (hw_port = 0; hw_port < MAX_HW_PORTS; hw_port++) {
        ops_qos_config.port_cfg[hw_unit][hw_port].trust =
                               OPS_QOS_PORT_TRUST_DEFAULT;
    }

    /* Initialize the scheduling hierarchy for all ports in the ASIC */
    rc = ops_qos_scheduler_init(hw_unit);

    /* Log a INFO message in case of SUCCESS */
    if (rc == OPS_QOS_SUCCESS_CODE) {
        VLOG_INFO("QoS hw unit initialization done for hw_unit %d",
                  hw_unit);
    }

    return rc;
}

/*
 * ops_qos_get_opennsl_color
 *
 * This function returns the corresponding OpenNSL
 * color enum for the given color.
 */
static opennsl_color_t
ops_qos_get_opennsl_color(int color)
{
    opennsl_color_t ret_color;

    switch (color) {
        case COS_COLOR_GREEN:
            ret_color = opennslColorGreen;
            break;

        case COS_COLOR_YELLOW:
            ret_color = opennslColorYellow;
            break;

        case COS_COLOR_RED:
            ret_color = opennslColorRed;
            break;

        default:
            ret_color = opennslColorGreen;
            break;
    }

    return ret_color;
}

/*
 * ops_qos_set_cos_map
 *
 * This function programs the given COS map config in
 * COS map table of the Broadcom ASIC.
 */
int
ops_qos_set_cos_map(const struct cos_map_settings *settings)
{
    int   index, hw_unit;
    struct cos_map_entry *entry;
    int cos;

    int qos_flags;
    opennsl_qos_map_t cos_map;
    int cos_map_id;
    opennsl_error_t rc = OPENNSL_E_NONE;

    if (settings->n_entries == 0) {
        VLOG_ERR("Number of entries in COS map settings is 0");
        return OPS_QOS_FAILURE_CODE;
    }

    /* Set the qos flags - L2 & Ingress flags */
    qos_flags = (OPENNSL_QOS_MAP_L2 | OPENNSL_QOS_MAP_INGRESS);

    /*
     * Create the QoS COS maps in each hardware unit if it's
     * not already created.
     */
    for (hw_unit = 0; hw_unit <= MAX_SWITCH_UNIT_ID; hw_unit++) {
        if (ops_qos_config.cos_map_id_default[hw_unit] ==
                                OPS_QOS_COS_MAP_ID_DEFAULT) {
            rc = opennsl_qos_map_create(hw_unit, qos_flags, &cos_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("cos map default: opennsl_qos_map_create failed "
                         "for hw unit %d, rc = %d, %s",
                          rc, hw_unit, opennsl_errmsg(rc));
                return rc;
            }

            ops_qos_config.cos_map_id_default[hw_unit] = cos_map_id;

            /* Log the debug message with INFO level as it is one time event */
            VLOG_INFO("qos default cos map id %d created successfully "
                      "for hw unit %d",
                       cos_map_id, hw_unit);
        }

        if (ops_qos_config.cos_map_id[hw_unit] ==
                               OPS_QOS_COS_MAP_ID_DEFAULT) {
            rc = opennsl_qos_map_create(hw_unit, qos_flags, &cos_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("cos map: opennsl_qos_map_create failed "
                         "for hw unit %d, rc = %d, %s",
                          rc, hw_unit, opennsl_errmsg(rc));
                return rc;
            }

            ops_qos_config.cos_map_id[hw_unit] = cos_map_id;

            /* Log the debug message with INFO level as it is one time event */
            VLOG_INFO("qos cos map id %d created successfully for "
                      "hw unit %d",
                       cos_map_id, hw_unit);
        }

    }

    /* Initialize the qos cos map entry */
    memset(&cos_map, 0, sizeof(opennsl_qos_map_t));

    /* Program the Broadcom ASIC with cos map config */
    for (index = 0; index < settings->n_entries; index++) {
        entry = &settings->entries[index];

        VLOG_DBG("set cos map: index=%d color=%d cp=%d lp=%d",
                  index, entry->color,
                  entry->codepoint, entry->local_priority);

        cos_map.pkt_pri = entry->codepoint;
        cos_map.int_pri = entry->local_priority;
        cos_map.color = ops_qos_get_opennsl_color(entry->color);

        /* Add the cos map to all asics */
        for (hw_unit = 0; hw_unit <= MAX_SWITCH_UNIT_ID; hw_unit++) {
            cos_map_id = ops_qos_config.cos_map_id[hw_unit];

            rc = opennsl_qos_map_add(hw_unit, qos_flags, &cos_map, cos_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("cos map: opennsl_qos_map_add failed "
                         "for hw unit %d, rc = %d, %s",
                          rc, hw_unit, opennsl_errmsg(rc));
                return rc;
            }
        } /* for (hw_unit = 0; ...) */

        /* Update the software copy now */
        ops_qos_config.cos_map[entry->codepoint].int_priority =
                                           entry->local_priority;
        ops_qos_config.cos_map[entry->codepoint].color = entry->color;

        /* Log the debug message */
        VLOG_DBG("qos cos map %d: cos cp %d, local pri %d color %d "
                 "set successfully on hw unit %d",
                  cos_map_id, entry->codepoint, entry->local_priority,
                  entry->color, hw_unit);

        VLOG_INFO("qos cos map %d: cos cp %d, local pri %d color %d "
                  "set successfully on hw unit %d",
                   cos_map_id, entry->codepoint, entry->local_priority,
                   entry->color, hw_unit);

        /*
         * If the COS map entry for COS 0 is changed, update the
         * default COS map table accordingly for all COS values.
         */
        if (entry->codepoint == 0) {
            for (cos = 0; cos < OPS_QOS_COS_COUNT; cos++) {
                cos_map.pkt_pri = cos;

                for (hw_unit = 0; hw_unit <= MAX_SWITCH_UNIT_ID;
                    hw_unit++) {
                    cos_map_id = ops_qos_config.cos_map_id_default[hw_unit];

                    rc = opennsl_qos_map_add(hw_unit, qos_flags, &cos_map,
                                             cos_map_id);

                    if (OPENNSL_FAILURE(rc)) {
                        VLOG_ERR("cos map default: opennsl_qos_map_add failed "
                                 "for hw unit %d, rc = %d, %s",
                                  rc, hw_unit, opennsl_errmsg(rc));
                        return rc;
                    }

                } /* for (hw_unit = 0; ... ) */

            } /* for (cos = 0; ... ) */

            /* Log the debug message */
            VLOG_DBG("qos default cos map %d: cos cp %d, local pri %d "
                     "color %d set successfully on hw unit %d",
                      cos_map_id, entry->codepoint, entry->local_priority,
                      entry->color, hw_unit);

        } /* if (cos_map.pkt_pri = 0) */

    } /* for (index = 0; ... ) */

    return rc;

}

/*
 * ops_qos_set_dscp_map
 *
 * This function programs the given DSCP map config in
 * DSCP table of the Broadcom ASIC.
 */
int
ops_qos_set_dscp_map(const struct dscp_map_settings *settings)
{
    int   index, hw_unit;
    struct dscp_map_entry *entry;

    int qos_flags;
    opennsl_qos_map_t dscp_map;
    int dscp_map_id;
    opennsl_error_t rc = OPENNSL_E_NONE;

    if (settings->n_entries == 0) {
        VLOG_ERR("Number of entries in DSCP map settings is 0");
        return OPS_QOS_FAILURE_CODE;
    }

    /* Set the qos flags - L3 & Ingress flags */
    qos_flags = (OPENNSL_QOS_MAP_L3 | OPENNSL_QOS_MAP_INGRESS);

    /*
     * Create the QoS DSCP maps in each hardware unit if it's
     * not already created.
     */
    for (hw_unit = 0; hw_unit <= MAX_SWITCH_UNIT_ID; hw_unit++) {
        if (ops_qos_config.dscp_map_id[hw_unit] ==
                                OPS_QOS_DSCP_MAP_ID_DEFAULT) {
            rc = opennsl_qos_map_create(hw_unit, qos_flags, &dscp_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("dscp map: opennsl_qos_map_create failed "
                         "for hw unit %d, rc = %d, %s",
                          rc, hw_unit, opennsl_errmsg(rc));
                return rc;
            }

            ops_qos_config.dscp_map_id[hw_unit] = dscp_map_id;

            /* Log the debug message with INFO level as it is one time event */
            VLOG_INFO("qos dscp map id %d created successfully for "
                      "hw unit %d",
                       dscp_map_id, hw_unit);

        }
    }

    /* Initialize the qos dscp map entry */
    memset(&dscp_map, 0, sizeof(opennsl_qos_map_t));

    /* Program the Broadcom ASIC with dscp map config */
    for (index = 0; index < settings->n_entries; index++) {
        entry = &settings->entries[index];

        VLOG_DBG("set dscp map: index=%d color=%d cp=%d lp=%d cos=%d",
                  index, entry->color,
                  entry->codepoint, entry->local_priority,
                  entry->cos);

        dscp_map.dscp = entry->codepoint;
        dscp_map.int_pri = entry->local_priority;
        dscp_map.color = ops_qos_get_opennsl_color(entry->color);

        /* Add the cos map to all asics */
        for (hw_unit = 0; hw_unit <= MAX_SWITCH_UNIT_ID; hw_unit++) {
            dscp_map_id = ops_qos_config.dscp_map_id[hw_unit];

            rc = opennsl_qos_map_add(hw_unit, qos_flags, &dscp_map,
                                     dscp_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("dscp map: opennsl_qos_map_add failed "
                         "for hw unit %d, rc = %d, %s",
                          rc, hw_unit, opennsl_errmsg(rc));
                return rc;
            }
        } /* for (hw_unit = 0; ...) */

        /* Update the software copy now */
        ops_qos_config.dscp_map[entry->codepoint].int_priority =
                                           entry->local_priority;
        ops_qos_config.dscp_map[entry->codepoint].color = entry->color;
        ops_qos_config.dscp_map[entry->codepoint].cos_remark = entry->cos;

        /* Log the debug message */
        VLOG_DBG("qos dscp map %d: dscp cp %d, local pri %d color %d "
                 "set successfully on hw unit %d",
                  dscp_map_id, entry->codepoint, entry->local_priority,
                  entry->color, hw_unit);

    }

    return rc;

}

/*
 * ops_qos_get_opennsl_int_pri_and_color
 *
 * This function returns the internal priority and color in DSCP
 * map table for the given DSCP codepoint.
 */
static int
ops_qos_get_opennsl_int_pri_and_color(int dscp)
{
    int int_priority, ops_qos_color, color = 0;
    int ret_val = 0;

    int_priority = ops_qos_config.dscp_map[dscp].int_priority;
    ops_qos_color = ops_qos_config.dscp_map[dscp].color;

    switch (ops_qos_color) {
        case COS_COLOR_GREEN:
            /* Green is default and color should be 0 */
            color = 0;
            break;

        case COS_COLOR_YELLOW:
            color = OPENNSL_PRIO_YELLOW;
            break;

        case COS_COLOR_RED:
            color = OPENNSL_PRIO_RED;
            break;

        default:
            /* Default is same as Green and color should be 0 */
            color = 0;
            break;
    }

    /* Return value is OR of internal priority & color */
    ret_val = int_priority | color;

    return ret_val;
}

/*
 * ops_qos_set_dscp_override
 *
 * This function programs the qos DSCP override in
 * Broadcom ASIC for the given port.
 */
static int
ops_qos_set_dscp_override(int hw_unit, int hw_port,
                          const struct  qos_port_settings *cfg)
{
    int dscp_map_mode;
    int int_pri_and_color;
    int dscp_override_value;
    opennsl_error_t rc = OPENNSL_E_NONE;

    VLOG_DBG("set dscp override: hw_unit %d port %d "
             "override enable %d override value %d",
              hw_unit, hw_port, cfg->dscp_override_enable,
              cfg->dscp_override_value);

    dscp_override_value = cfg->dscp_override_value;

    /* First set the DSCP map mode to None */
    dscp_map_mode = OPENNSL_PORT_DSCP_MAP_NONE;

    if (cfg->dscp_override_enable == true) {

        /*
         * Validate the DSCP pverride value as it should have
         * a valid value.
         */
        if (dscp_override_value < 0 ||
            dscp_override_value >= OPS_QOS_DSCP_COUNT) {
            VLOG_ERR("Invalid DSCP override value %d for "
                     "hw_unit %d hw_port %d",
                      dscp_override_value, hw_unit, hw_port);

            return OPS_QOS_FAILURE_CODE;
        }

        /* Set the map mode to map all */
        dscp_map_mode = OPENNSL_PORT_DSCP_MAP_ALL;

        int_pri_and_color = ops_qos_get_opennsl_int_pri_and_color(
                                  dscp_override_value);

        /* Program the DSCP override value in hardware */
        rc = opennsl_port_dscp_map_set(hw_unit, hw_port,
                                       OPS_QOS_DSCP_MAP_ALL,
                                       dscp_override_value,
                                       int_pri_and_color);

        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and return */
            VLOG_ERR("opennsl_port_dscp_map_set failed for hw_unit %d, "
                     "hw_port %d dscp %d int_pri_and_color 0x%x, "
                     "rc = %d - %s",
                      hw_unit, hw_port, dscp_override_value,
                      int_pri_and_color, rc, opennsl_errmsg(rc));

            return rc;
        }

        /* Update the software copy */
        ops_qos_config.port_cfg[hw_unit][hw_port].dscp_override_value =
                       dscp_override_value;
    }

    /* Program the map mode now */
    rc = opennsl_port_dscp_map_mode_set(hw_unit, hw_port,
                                        dscp_map_mode);

    if (OPENNSL_FAILURE(rc)) {
        /* Log an ERR message and return */
        VLOG_ERR("opennsl_port_dscp_map_mode_set failed for hw_unit %d, "
                 "hw_port %d dscp mode %d, rc = %d - %s",
                  hw_unit, hw_port, dscp_map_mode,
                  rc, opennsl_errmsg(rc));

        return rc;
    }

    /* Update the software copy */
    ops_qos_config.port_cfg[hw_unit][hw_port].dscp_override_enable =
                                     cfg->dscp_override_enable;

    return OPS_QOS_SUCCESS_CODE;
}

/*
 * ops_qos_set_port_trust_cfg
 *
 * This function programs the qos port trust config in
 * Broadcom ASIC.
 */
static int
ops_qos_set_port_trust_cfg(int hw_unit, int hw_port,
                           const struct  qos_port_settings *cfg)
{
    int qos_ing_map_id, qos_egr_map_id;
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_gport_t gport;

    VLOG_DBG("set port trust: hw_unit %d port %d "
             "qos_trust %d",
              hw_unit, hw_port, cfg->qos_trust);

    /* Get the gport for the physical port */
    rc = opennsl_port_gport_get(hw_unit, hw_port, &gport);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("ops_qos_set_port_trust_cfg: failed to get gport for "
                 "hw unit %d, port %d, rc = %d, %s",
                  hw_unit, hw_port, rc, opennsl_errmsg(rc));
        return rc;
    }

    /* For all cases, egress qos map id is set to NO CHANGE */
    qos_egr_map_id = OPS_EGR_QOS_MAP_ID_NO_CHANGE;

    switch (cfg->qos_trust) {
        case QOS_TRUST_NONE:
            /*
             * The procedure to set the qos trust to None is
             *    - Set the ingress qos map to none
             *    - Then set the ingress qos map to default COS map id
             */
            qos_ing_map_id = OPS_ING_QOS_MAP_ID_NONE;
            rc = opennsl_qos_port_map_set(hw_unit, gport,
                                          qos_ing_map_id, qos_egr_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("qos set port trust to none failed step 1 for "
                         "hw unit %d, port %d, rc = %d, %s",
                          hw_unit, hw_port, rc, opennsl_errmsg(rc));
                return rc;
            }

            qos_ing_map_id = ops_qos_config.cos_map_id_default[hw_unit];
            rc = opennsl_qos_port_map_set(hw_unit, gport,
                                          qos_ing_map_id, qos_egr_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("qos set port trust to none failed in step 2 for "
                         "hw unit %d, port %d, rc = %d, %s",
                          hw_unit, hw_port, rc, opennsl_errmsg(rc));
                return rc;
            }

            VLOG_DBG("qos port trust none %d set successfully for "
                     "hw unit %d port %d",
                      qos_ing_map_id, hw_unit, hw_port);

            break;

        case QOS_TRUST_COS:
            /*
             * The procedure to set the qos trust to COS is
             *    - Set the ingress qos map to none
             *    - Then set the ingress qos map to COS map id
             */
            qos_ing_map_id = OPS_ING_QOS_MAP_ID_NONE;
            rc = opennsl_qos_port_map_set(hw_unit, gport,
                                          qos_ing_map_id, qos_egr_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("qos set port trust to COS failed in step 1 for "
                         "hw unit %d, port %d, rc = %d, %s",
                          hw_unit, hw_port, rc, opennsl_errmsg(rc));
                return rc;
            }

            qos_ing_map_id = ops_qos_config.cos_map_id[hw_unit];
            rc = opennsl_qos_port_map_set(hw_unit, gport,
                                          qos_ing_map_id, qos_egr_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("qos set port trust to COS failed in step 2 for "
                         "hw unit %d, port %d, rc = %d, %s",
                          hw_unit, hw_port, rc, opennsl_errmsg(rc));
                return rc;
            }

            VLOG_DBG("qos port trust COS %d set successfully for "
                     "hw unit %d port %d",
                      qos_ing_map_id, hw_unit, hw_port);

            break;

        case QOS_TRUST_DSCP:
            /*
             * The procedure to set the qos trust to DSCP is
             *    - Set the ingress qos map to none
             *    - Then set the ingress qos map to DSCP map id
             *    - Then set the ingress qos map to default COS map id
             *      (This is needed to handle non-IP packets)
             */
            qos_ing_map_id = OPS_ING_QOS_MAP_ID_NONE;
            rc = opennsl_qos_port_map_set(hw_unit, gport,
                                          qos_ing_map_id, qos_egr_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("qos set port trust to DSCP failed in step 1 for "
                         "hw unit %d, port %d, rc = %d, %s",
                          hw_unit, hw_port, rc, opennsl_errmsg(rc));
                return rc;
            }

            qos_ing_map_id = ops_qos_config.dscp_map_id[hw_unit];
            rc = opennsl_qos_port_map_set(hw_unit, gport,
                                          qos_ing_map_id, qos_egr_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("qos set port trust to DSCP failed in step 2 for "
                         "hw unit %d, port %d, rc = %d, %s",
                          hw_unit, hw_port, rc, opennsl_errmsg(rc));
                return rc;
            }

            qos_ing_map_id = ops_qos_config.cos_map_id_default[hw_unit];
            rc = opennsl_qos_port_map_set(hw_unit, gport,
                                          qos_ing_map_id, qos_egr_map_id);

            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("qos set port trust to DSCP failed in step 3 for "
                         "hw unit %d, port %d, rc = %d, %s",
                          hw_unit, hw_port, rc, opennsl_errmsg(rc));
                return rc;
            }

            VLOG_DBG("qos port trust DSCP %d set successfully for "
                     "hw unit %d port %d",
                      qos_ing_map_id, hw_unit, hw_port);

            break;

        default:
            VLOG_ERR("Invalid qos trust config %d for hw unit %d, port %d",
                      cfg->qos_trust, hw_unit, hw_port);
            return OPS_QOS_FAILURE_CODE;
    }

    /*
     * The control reaches here on successful hardware update. So,
     * update the software copy now.
     */
    ops_qos_config.port_cfg[hw_unit][hw_port].trust = cfg->qos_trust;

    return OPS_QOS_SUCCESS_CODE;

}

/*
 * ops_qos_is_port_trust_changed
 *
 * This function checks if the qos port trust config is
 * changed or not.
 */
static bool
ops_qos_is_port_trust_changed(int hw_unit, int hw_port,
                              const struct  qos_port_settings *cfg)
{

    if (cfg->qos_trust == ops_qos_config.port_cfg[hw_unit][hw_port].trust) {
        return false;
    }

    return true;
}

/*
 * ops_qos_is_dscp_override_changed
 *
 * This function checks if the qos dscp override config is
 * changed or not for the given port.
 */
static bool
ops_qos_is_dscp_override_changed(int hw_unit, int hw_port,
                                 const struct  qos_port_settings *cfg)
{

    /*
     * First check if the enable flag is changed. DSCP override
     * value is valid only if the enable flag is set to true.
     */
    if (cfg->dscp_override_enable ==
        ops_qos_config.port_cfg[hw_unit][hw_port].dscp_override_enable) {
        if (cfg->dscp_override_enable == true) {
            if (cfg->dscp_override_value ==
                ops_qos_config.port_cfg[hw_unit][hw_port].
                dscp_override_value) {
                return false;
            } else {
                return true;
            }
        } else {
            return false;
        }
    }

    return true;
}

/*
 * ops_qos_set_port_trust_cfg
 *
 * This function programs the qos port config in
 * Broadcom ASIC.
 */
int
ops_qos_set_port_cfg(struct ofbundle *bundle,
                           int hw_unit, int hw_port,
                           const struct  qos_port_settings *cfg)
{
    int rc = OPS_QOS_SUCCESS_CODE;

    VLOG_DBG("set port trust: port %s, settings->qos_trust %d, cfg@ %p",
              bundle->name, cfg->qos_trust, cfg->other_config);

    /*
     * If this is the first time set port cfg is called for
     * this port, disable cos remark for this port as COS
     * override or remark is not supported currently.
     */
    if (ops_qos_config.port_cfg[hw_unit][hw_port].trust ==
        OPS_QOS_PORT_TRUST_DEFAULT) {
        /* Log an INFO msg as it is one time event */
        VLOG_INFO("set qos port trust: disable cos remark at egress for "
                 "hw unit %d hw port %d",
                  hw_unit, hw_port);

        rc = opennsl_port_control_set(hw_unit, hw_port,
                          opennslPortControlEgressVlanPriUsesPktPri, true);

        if (OPENNSL_FAILURE(rc)) {
            /* Log an ERR message and continue */
            VLOG_ERR("set qos port cos: disable cos remark failed for "
                     "hw unit %d hw port %d",
                      hw_unit, hw_port);
        }

    }

    if (ops_qos_is_port_trust_changed(hw_unit, hw_port, cfg) == true) {
        rc = ops_qos_set_port_trust_cfg(hw_unit, hw_port, cfg);

        if (rc != OPS_QOS_SUCCESS_CODE) {
            VLOG_ERR("set port trust config returned error for "
                     "hw_unit %d hw_port %d, rc = %d",
                      hw_unit, hw_port, rc);

            return rc;
        }
    }

    if (ops_qos_is_dscp_override_changed(hw_unit, hw_port, cfg) == true) {
        rc = ops_qos_set_dscp_override(hw_unit, hw_port, cfg);

        if (rc != OPS_QOS_SUCCESS_CODE) {
            VLOG_ERR("set dscp override returned error for "
                     "hw_unit %d hw_port %d, rc = %d",
                      hw_unit, hw_port, rc);

            return rc;
        }
    }

    return rc;

}

/*
 * ops_qos_get_cosq_stats
 *
 * This function retrieves the queue statistics of the given
 * port from Broadcom ASIC.
 */
int
ops_qos_get_cosq_stats(int hw_unit, int hw_port,
                       netdev_dump_queue_stats_cb* cb,
                       void *aux)
{
    struct netdev_queue_stats qstats[OPENNSL_COS_COUNT];
    opennsl_gport_t gport;
    opennsl_cos_queue_t cosq;
    opennsl_cosq_stat_t stat;
    opennsl_error_t rc = OPENNSL_E_NONE;
    uint64 value;

    if (!VALID_HW_UNIT(hw_unit) ||
        !VALID_HW_UNIT_PORT(hw_unit, hw_port)) {
        /*
         * Stats error messages should be logged as DBG
         * to avoid flooding of ERR logs.
         */
        VLOG_DBG("qos cosq stats: invalid input - "
                 "hw unit %d, port %d",
                  hw_unit, hw_port);
        return OPS_QOS_FAILURE_CODE;
    }

    /* Get the gport for the physical port */
    rc = opennsl_port_gport_get(hw_unit, hw_port, &gport);
    if (OPENNSL_FAILURE(rc)) {
        /*
         * Stats error messages should be logged as DBG
         * to avoid flooding of ERR logs.
         */
        VLOG_DBG("qos cosq stats: failed to get gport for "
                 "hw unit %d, port %d, rc = %d, %s",
                  hw_unit, hw_port, rc, opennsl_errmsg(rc));
        return rc;
    }

    /*
     * For each cosq, retrieve the MMU statistics for Txpackets,
     * TxBytes & TxDrops and call the PI callback function.
     */
    for (cosq = 0; cosq < OPENNSL_COS_COUNT; cosq++) {
        /*
         * OPS_TODO:
         *     If more stats need to be retrieved in future, use an
         *     array with needed stats enums and traverse the array
         *     enums and retrieve each stats.
         *     Also, check with Broadcom if *_multi_get API is
         *     available for cosq stats or will be supported in
         *     future.
         */
        stat = opennslCosqStatOutPackets;
        rc = opennsl_cosq_stat_get(hw_unit, hw_port,
                                   cosq, stat, &value);

        if (OPENNSL_FAILURE(rc)) {
            /*
             * Stats error messages should be logged as DBG
             * to avoid flooding of ERR logs.
             */
            VLOG_DBG("qos cosq stats: failed to get TxPackets for "
                     "hw unit %d, port %d gport %x, rc = %d, %s",
                      hw_unit, hw_port, gport,
                      rc, opennsl_errmsg(rc));
            return rc;
        }

        qstats[cosq].tx_packets = value;

        stat = opennslCosqStatOutBytes;
        rc = opennsl_cosq_stat_get(hw_unit, hw_port,
                                   cosq, stat, &value);

        if (OPENNSL_FAILURE(rc)) {
            /*
             * Stats error messages should be logged as DBG
             * to avoid flooding of ERR logs.
             */
            VLOG_DBG("qos cosq stats: failed to get TxBytes for "
                     "hw unit %d, port %d gport %x, rc = %d, %s",
                      hw_unit, hw_port, gport,
                      rc, opennsl_errmsg(rc));
            return rc;
        }

        qstats[cosq].tx_bytes = value;

        stat = opennslCosqStatDroppedPackets;
        rc = opennsl_cosq_stat_get(hw_unit, hw_port,
                                   cosq, stat, &value);

        if (OPENNSL_FAILURE(rc)) {
            /*
             * Stats error messages should be logged as DBG
             * to avoid flooding of ERR logs.
             */
            VLOG_DBG("qos cosq stats: failed to get DroppedPackets for "
                     "hw unit %d, port %d gport %x, rc = %d, %s",
                      hw_unit, hw_port, gport,
                      rc, opennsl_errmsg(rc));
            return rc;
        }

        qstats[cosq].tx_errors = value;

        /*
         * Invoke the PI layer callback function.
         * No need for error checking here.
         */
        if (cb) {
            (*cb)(cosq, &qstats[cosq], aux);
        } else {
            /*
             * Stats error messages should be logged as DBG
             * to avoid flooding of ERR logs.
             */
            VLOG_DBG("qos cosq stats: NULL PI callback function for "
                     "hw unit %d, port %d",
                      hw_unit, hw_port);

            return OPS_QOS_FAILURE_CODE;
        }

    }

    return rc;
}

/*
 * ops_qos_apply_queue_profile
 *
 * This function programs the given queue map config in
 * COS map table of the Broadcom ASIC.
 */
int
ops_qos_apply_queue_profile(
                       const struct schedule_profile_settings *s_settings,
                       const struct queue_profile_settings *q_settings)
{
    int hw_unit;
    int cosq_index, priority_index;
    struct queue_profile_entry *qp_entry;
    struct local_priority_entry *lp_entry;
    opennsl_cos_queue_t cosq;
    int int_priority;
    opennsl_error_t rc = OPENNSL_E_NONE;

    for (cosq_index = 0; cosq_index < q_settings->n_entries; cosq_index++) {
        qp_entry = q_settings->entries[cosq_index];

        cosq = qp_entry->queue;

        for (priority_index = 0;
            priority_index < qp_entry->n_local_priorities; priority_index++) {

            lp_entry = qp_entry->local_priorities[priority_index];
            int_priority = lp_entry->local_priority;

            /* Log a DBG message */
            VLOG_DBG("ops_qos_apply_queue_profile - cosq %d, int pri %d",
                      cosq, int_priority);

            for (hw_unit = 0; hw_unit <= MAX_SWITCH_UNIT_ID;
                hw_unit++) {

                rc = opennsl_cosq_mapping_set(hw_unit, int_priority, cosq);
                if (OPENNSL_FAILURE(rc)) {
                    VLOG_ERR("ops_qos_apply_queue_profile failed - cosq %d, "
                             "int pri %d, hw_unit %d, rc = %d - %s",
                              cosq, int_priority,
                              hw_unit, rc, opennsl_errmsg(rc));
                    return rc;
                }

            } /* for (hw_unit = 0 ... */

        } /* for (priority_index = 0; ... */

    } /* for (cosq_index = 0; ... */

    return rc;

}

/*
 * ops_qos_get_opennsl_sched_mode
 *
 * This function returns the corresponding OpenNSL
 * scheduling mode for the given scheduling algorithm.
 */
static int
ops_qos_get_opennsl_sched_mode(int algorithm)
{
    int sched_mode;

    switch (algorithm) {
        case ALGORITHM_STRICT:
            sched_mode = OPENNSL_COSQ_STRICT;
            break;

        case ALGORITHM_DWRR:
            sched_mode = OPENNSL_COSQ_DEFICIT_ROUND_ROBIN;
            break;

        default:
            sched_mode = OPENNSL_COSQ_DEFICIT_ROUND_ROBIN;
            break;
    }

    return sched_mode;
}

/*
 * ops_qos_apply_schedule_profile
 *
 * This function programs the given schedule profile config in
 * the Broadcom ASIC.
 */
int
ops_qos_apply_schedule_profile(struct ofbundle *bundle,
                       int hw_unit, int hw_port,
                       const struct schedule_profile_settings *s_settings,
                       const struct queue_profile_settings *q_settings)
{
    int cosq_index;
    struct schedule_profile_entry *sp_entry;
    ops_qos_sched_nodes_t *port_sched_node;
    opennsl_cos_queue_t cosq;
    int weight;
    int sched_mode;
    opennsl_error_t rc = OPENNSL_E_NONE;

    port_sched_node = ops_qos_config.sched_nodes[hw_unit][hw_port];
    if (port_sched_node == NULL) {
        VLOG_ERR("ops_qos_apply_schedule_profile: scheduling node hierarchy "
                 "not initialized for hw unit %d, hw port %d",
                  hw_unit, hw_port);

        return OPS_QOS_FAILURE_CODE;
    }

    for (cosq_index = 0; cosq_index < s_settings->n_entries; cosq_index++) {
        sp_entry = s_settings->entries[cosq_index];

        cosq = cosq_index;
        weight = sp_entry->weight;
        sched_mode = ops_qos_get_opennsl_sched_mode(sp_entry->algorithm);

        VLOG_DBG("ops_qos_apply_schedule_profile: mode %d weight %d cosq %d "
                 "for hw unit %d, hw port %d",
                  sched_mode, weight, cosq,
                  hw_unit, hw_port);

        /* Use the cosq gport at L0 to set scheduling algorithm */
        rc = opennsl_cosq_gport_sched_set(hw_unit,
                                          port_sched_node->level0_sched,
                                          cosq,
                                          sched_mode, weight);

        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("ops_qos_apply_schedule_profile failed - "
                     "mode %d weight %d cosq %d "
                     "for hw unit %d, hw port %d, rc = %d - %s",
                      sched_mode, weight, cosq,
                      hw_unit, hw_port, rc, opennsl_errmsg(rc));

            return rc;

        }

    } /* for (cosq_index = 0; ... */

    return rc;

}

/*
 * ops_qos_dump_trust
 *
 * This function retrieves the QoS trust config programmed in
 * the Broadcom ASIC.
 */
void
ops_qos_dump_trust(struct ds *ds)
{
    int map_id, flags;
    int unit = 0;
    int port = 1;
    opennsl_gport_t gport;
    opennsl_error_t rc;

    /* Get the gport for the physical port */
    rc = opennsl_port_gport_get(unit, port, &gport);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("ops_qos_dump_trust: failed to get gport for "
                 "hw unit %d, port %d, rc = %d, %s",
                  unit, port, rc, opennsl_errmsg(rc));

        ds_put_format(ds, "Error in getting gport for QoS trust config\n\n");
        return;
    }

    /* Set the qos flags - L2 & Ingress flags */
    flags = (OPENNSL_QOS_MAP_L2 | OPENNSL_QOS_MAP_INGRESS);

    /* Retrieve the QoS trust config from Broadcom ASIC */
    rc = opennsl_qos_port_map_type_get(unit, gport,
                                       flags, &map_id);
    if (OPENNSL_FAILURE(rc)) {
        if (rc == OPENNSL_E_NOT_FOUND) {
            /*
             * Exception: If there is no qos trust configured, then SDK will
             * return error as OPENNSL_E_NOT_FOUND. Treat this as SUCCESS
             * and set the map_id to 0.
             */
            VLOG_INFO("opennsl_qos_port_map get returned OPENNSL_E_NOT_FOUND "
                      "for hw unit %d port %d",
                       unit, port);
            map_id = 0;
        } else {
            VLOG_ERR("opennsl_qos_port_map_get failed for "
                     "hw unit %d, port %d, rc = %d, %s",
                      unit, port, rc, opennsl_errmsg(rc));

            ds_put_format(ds, "Error in retrieving QoS trust config\n\n");
            return;
        }
    }

    /* Print the QoS trust config in required format */
    ds_put_format(ds, "QoS trust config\n");
    ds_put_format(ds, "----------------\n");
    ds_put_format(ds, "Ingress qos map ID: %d\n", map_id);

    ds_put_format(ds, "SUCCESS in retrieving QoS trust config\n\n");

    return;
}

/*
 * ops_qos_dump_cos_map
 *
 * This function retrieves the QoS COS map config programmed in
 * the Broadcom ASIC.
 */
void
ops_qos_dump_cos_map(struct ds *ds)
{
    int cos_map_id_default;
    int cos_map_id;
    int unit = 0;

    /*
     * As there is no BRCM SDK or OpenNSL API to retrieve the COS
     * map id programmed in hardware, get the cached software copy.
     * If this has non-default value, then COS map should be programmed
     * correctly in hardware as this gets updated to valid value only
     * after successful hardware programming.
     */
    cos_map_id_default = ops_qos_config.cos_map_id_default[unit];
    cos_map_id = ops_qos_config.cos_map_id[unit];

    ds_put_format(ds, "QoS COS map config\n");
    ds_put_format(ds, "------------------\n");
    ds_put_format(ds, "Default COS map ID: %d\n", cos_map_id_default);
    ds_put_format(ds, "System config COS map ID: %d\n\n", cos_map_id);

    /*
     * If any of the COS map IDs has default value, then it is considered as a
     * failure case.
     */
    if (cos_map_id_default == OPS_QOS_COS_MAP_ID_DEFAULT ||
        cos_map_id == OPS_QOS_COS_MAP_ID_DEFAULT) {
        ds_put_format(ds, "Error in programming of default or system config "
                          "COS map\n\n");

        return;
    }

    ds_put_format(ds, "SUCCESS in retrieving QoS COS map config\n\n");

    return;
}

/*
 * ops_qos_dump_dscp_map
 *
 * This function retrieves the QoS DSCP map config programmed in
 * the Broadcom ASIC.
 */
void
ops_qos_dump_dscp_map(struct ds *ds)
{
    int dscp_map_id;
    int unit = 0;

    /*
     * As there is no BRCM SDK or OpenNSL API to retrieve the DSCP
     * map id programmed in hardware, get the cached software copy.
     * If this has non-default value, then DSCP map should be programmed
     * correctly in hardware as this gets updated to valid value only
     * after successful hardware programming.
     */
    dscp_map_id = ops_qos_config.dscp_map_id[unit];

    ds_put_format(ds, "QoS DSCP map config\n");
    ds_put_format(ds, "------------------\n");
    ds_put_format(ds, "DSCP map ID: %d\n\n", dscp_map_id);

    /*
     * If DSCP map id has default value, then it is considered as a
     * failure case.
     */
    if (dscp_map_id == OPS_QOS_DSCP_MAP_ID_DEFAULT) {
        ds_put_format(ds, "Error in programming of DSCP map table\n\n");

        return;
    }

    ds_put_format(ds, "SUCCESS in retrieving QoS DSCP map config\n\n");

    return;

}

/*
 * ops_qos_dump_dscp_override
 *
 * This function retrieves the QoS DSCP override config programmed in
 * the Broadcom ASIC.
 */
void
ops_qos_dump_dscp_override(struct ds *ds)
{
    int dscp_override_value;
    int dscp_map_mode;
    int int_pri_and_color;
    int unit = 0, port = 1;
    opennsl_error_t rc;

    /* Retrieve the DSCP map mode first */
    rc = opennsl_port_dscp_map_mode_get(unit, port,
                                        &dscp_map_mode);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("opennsl_port_dscp_map_mode_get failed for "
                 "hw unit %d, port %d, rc = %d, %s",
                  unit, port, rc, opennsl_errmsg(rc));

        ds_put_format(ds, "Error in retrieving QoS DSCP map mode\n\n");
        return;
    }

    ds_put_format(ds, "QoS DSCP override config\n");
    ds_put_format(ds, "------------------------\n");
    ds_put_format(ds, "DSCP map mode: %d\n\n", dscp_map_mode);

    /* Retrieve the DSCP override value if map mode is enabled */
    if (dscp_map_mode == OPENNSL_PORT_DSCP_MAP_ALL) {
        rc = opennsl_port_dscp_map_get(unit, port,
                                       OPS_QOS_DSCP_MAP_ALL,
                                       &dscp_override_value,
                                       &int_pri_and_color);

        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("opennsl_port_dscp_map_get failed for "
                     "hw unit %d, port %d, rc = %d, %s",
                      unit, port, rc, opennsl_errmsg(rc));

            ds_put_format(ds, "Error in retrieving QoS DSCP override "
                              "value\n\n");

            return;
        }

        ds_put_format(ds, "DSCP override value: %d\n", dscp_override_value);
        ds_put_format(ds, "DSCP override priority: 0x%x\n\n",
                           int_pri_and_color);
    }

    ds_put_format(ds, "SUCCESS in retrieving QoS DSCP override config\n\n");

    return;

}

/*
 * ops_qos_dump_queuing
 *
 * This function retrieves the QoS queuing config programmed in
 * the Broadcom ASIC.
 */
void
ops_qos_dump_queuing(struct ds *ds)
{
    int priority;
    int cosq;
    int unit = 0;
    opennsl_error_t rc;

    ds_put_format(ds, "QoS COSq mapping\n");
    ds_put_format(ds, "================\n");
    ds_put_format(ds, "Internal Priority      Egress queue\n");
    ds_put_format(ds, "-----------------------------------\n");

    for (priority = 0; priority < OPENNSL_COS_COUNT; priority++) {
        /* Retrieve the cosq mapping for the priority */
        rc = opennsl_cosq_mapping_get(unit, priority, &cosq);

        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("opennsl_cosq_mapping_get failed for "
                     "hw unit %d, priority %d, rc = %d, %s",
                      unit, priority, rc, opennsl_errmsg(rc));

            ds_put_format(ds, "Error in retrieving QoS COSq mapping "
                              "for priority %d\n\n",
                               priority);

            return;
        }

        ds_put_format(ds, "       %d                   %d\n",
                           priority, cosq);
    }

    ds_put_format(ds, "\n");

    ds_put_format(ds, "SUCCESS in retrieving QoS COSq mapping\n\n");

    return;

}

/*
 * ops_qos_dump_scheduling
 *
 * This function retrieves the QoS scheduling config programmed in
 * the Broadcom ASIC.
 */
void
ops_qos_dump_scheduling(struct ds *ds)
{
    int cosq;
    int sched_mode;
    int weight;
    int unit = 0;
    int port = 1;
    ops_qos_sched_nodes_t *port_sched_node;
    opennsl_error_t rc;

    ds_put_format(ds, "QoS COSq scheduling config\n");
    ds_put_format(ds, "==========================\n");

    port_sched_node = ops_qos_config.sched_nodes[unit][port];
    if (port_sched_node == NULL) {
        VLOG_ERR("ops_qos_dump_scheduling: scheduling node hierarchy "
                 "not initialized for hw unit %d, hw port %d",
                  unit, port);

        ds_put_format(ds, "Error in retrieving scheduling config as "
                          "scheduling herarchy is not initialized\n\n");
        return;
    }

    ds_put_format(ds, "COSq      Scheduling mode     Weight\n");
    ds_put_format(ds, "------------------------------------\n");

    /* Retrieve the scheduling mode for each COSq */
    for (cosq = 0; cosq < OPENNSL_COS_COUNT; cosq++) {
        rc = opennsl_cosq_gport_sched_get(unit,
                                          port_sched_node->level0_sched,
                                          cosq,
                                          &sched_mode, &weight);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("opennsl_cosq_gport_sched_get failed for "
                     "hw unit %d, cosq %d, rc = %d, %s",
                      unit, cosq, rc, opennsl_errmsg(rc));

            ds_put_format(ds, "Error in retrieving QoS COSq mapping "
                              "for cosq %d\n\n",
                               cosq);

            return;
        }

        ds_put_format(ds, "  %d       0x%x                    %d\n",
                          cosq, sched_mode, weight);
    }

    ds_put_format(ds, "\n");

    ds_put_format(ds, "SUCCESS in retrieving QoS COSq mapping\n\n");

    return;
}

/*
 * ops_qos_dump_statistics
 *
 * This function retrieves the QoS statistics from the
 * the Broadcom ASIC.
 */
void
ops_qos_dump_statistics(struct ds *ds)
{
    /*
     * OPS_TODO:
     *    Currently there is no component test (CT) infra to send packets for
     *    QoS classification. This is a TODO item for future. For now, return
     *    success.
     */
    ds_put_format(ds, "QoS COSq statistics\n");
    ds_put_format(ds, "-------------------\n");
    ds_put_format(ds, "SUCCESS (not implemented currently)\n\n");

    return;

}

/*
 * ops_qos_port_config
 *
 * This function sets per port QoS config (DSCP override and scheduling)
 * in Broadcom ASIC and is intended to be used only by QoS CT script.
 */
void
ops_qos_port_config(struct ds *ds)
{
    int hw_unit = 0;
    int hw_port = 1;
    struct qos_port_settings cfg;
    int ret_val;
    ops_qos_sched_nodes_t *port_sched_node;
    opennsl_cos_queue_t cosq;
    int weight;
    int sched_mode;
    opennsl_error_t rc = OPENNSL_E_NONE;

    /*
     * Configure DSCP override value of 7 as the CT script
     * verifies for the same.
     */
    cfg.dscp_override_enable = true;
    cfg.dscp_override_value = 7;

    ret_val = ops_qos_set_dscp_override(hw_unit, hw_port, &cfg);

    if (ret_val != OPS_QOS_SUCCESS_CODE) {
        ds_put_format(ds, "Set DSCP override failed\n");

        VLOG_ERR("ops_qos_port_config: set DSCP override failed, "
                 " ret_val = %d", ret_val);
        return;
    }

    /*
     * Configure scheduling mode to Strict Priority as the CT script
     * verifies for the same.
     */
    sched_mode = OPENNSL_COSQ_STRICT;
    weight = 0;

    port_sched_node = ops_qos_config.sched_nodes[hw_unit][hw_port];
    if (port_sched_node == NULL) {
        ds_put_format(ds, "Set scheduling mode failed as scheduling node "
                          "hierarchy is not initialized\n");

        VLOG_ERR("ops_qos_port_config: scheduling node hierarchy "
                 "not initialized for hw unit %d, hw port %d",
                  hw_unit, hw_port);

        return;
    }

    for (cosq = 0; cosq < OPENNSL_COS_COUNT; cosq++) {

        /* Use the cosq gport at L0 to set scheduling algorithm */
        rc = opennsl_cosq_gport_sched_set(hw_unit,
                                          port_sched_node->level0_sched,
                                          cosq,
                                          sched_mode, weight);

        if (OPENNSL_FAILURE(rc)) {
            ds_put_format(ds, "Set scheduling mode failed\n");

            VLOG_ERR("ops_qos_port_config scheduling config failed - "
                     "mode %d weight %d cosq %d "
                     "for hw unit %d, hw port %d, rc = %d - %s",
                      sched_mode, weight, cosq,
                      hw_unit, hw_port, rc, opennsl_errmsg(rc));

            return;

        }

    } /* for (cosq = 0; ... */

    ds_put_format(ds, "Successfully configured per port DSCP override and "
                      "scheduling mode\n");

    return;

}

/*
 * ops_qos_dump_all
 *
 * This function retrieves all of the QoS config programmed in
 * the Broadcom ASIC.
 */
void
ops_qos_dump_all(struct ds *ds)
{

    /* Dump all QoS config from hardware */
    ops_qos_dump_trust(ds);
    ops_qos_dump_cos_map(ds);
    ops_qos_dump_dscp_map(ds);
    ops_qos_dump_dscp_override(ds);
    ops_qos_dump_queuing(ds);
    ops_qos_dump_scheduling(ds);
    ops_qos_dump_statistics(ds);

    return;

}
