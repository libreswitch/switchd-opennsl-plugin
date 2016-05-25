/*
 * Copyright (C) 2015-2016 Hewlett-Packard Enterprise Development Company, L.P.
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
 * File: ops-bcm-init.c
 *
 * Purpose: Main file for the implementation of OpenSwitch BCM SDK application initialization.
 */

#include <openvswitch/vlog.h>
#include <ovs/uuid.h>

#include <sal/driver.h>
#include <opennsl/error.h>
#include <opennsl/rx.h>

#include "bcm.h"
#include "platform-defines.h"
#include "ops-bcm-init.h"
#include "ops-knet.h"
#include "ops-port.h"
#include "ops-routing.h"
#include "ops-vlan.h"
#include "ops-classifier.h"
#include "ops-debug.h"
#include "ops-copp.h"
#include "ops-stg.h"
#include "ops-sflow.h"
#include "ops-qos.h"
#include "ops-mac-learning.h"
#include "netdev-bcmsdk.h"
#include "eventlog.h"
#include "ops-mirrors.h"

VLOG_DEFINE_THIS_MODULE(ops_bcm_init);


extern int
opennsl_rx_register(int, const char *, opennsl_rx_cb_f, uint8, void *, uint32);

/* TODO: This callback is also sending sFlow pkts to collectors. It must
 * do minimal computation in order to receive subsequent sFlow pkts.
 * Callback should queue up pkts received from ASIC and return.
 * Temporarily, configure a low sampling rate (say 1 in 10 pkts, when
 * incoming rate is 1 pkt/s as in case of 'ping'). Eventually, a different
 * thread will process incoming pkts.
 */
opennsl_rx_t opennsl_rx_callback(int unit, opennsl_pkt_t *pkt, void *cookie)
{
    if (!pkt) {
        VLOG_ERR("Invalid pkt sent by ASIC");
        log_event("SFLOW_CALLBACK_INVALID_PKT", NULL);
        return OPENNSL_RX_HANDLED;
    }

    /* sFlow's sampled pkt */
    if (OPENNSL_RX_REASON_GET(pkt->rx_reasons, opennslRxReasonSampleDest) ||
        OPENNSL_RX_REASON_GET(pkt->rx_reasons, opennslRxReasonSampleSource)) {

        /* Uncomment to print the sampled pkt info */
        /* print_pkt(pkt); */

        char port[IFNAMSIZ];

        if (OPENNSL_RX_REASON_GET(pkt->rx_reasons,
                                  opennslRxReasonSampleSource)) {
            snprintf(port, IFNAMSIZ, "%d", pkt->src_port);
            netdev_bcmsdk_populate_sflow_stats(true, port, pkt->pkt_len);
        }

        if (OPENNSL_RX_REASON_GET(pkt->rx_reasons,
                                  opennslRxReasonSampleDest)) {
            snprintf(port, IFNAMSIZ, "%d", pkt->dest_port);
            netdev_bcmsdk_populate_sflow_stats(false, port, pkt->pkt_len);
        }

        /* Write incoming data to Receivers buffer. When buffer is full,
         * data is sent to Collectors. */
        ops_sflow_write_sampled_pkt(pkt);
    }

    /* ACL logging packet */
    if (OPENNSL_RX_REASON_GET(pkt->rx_reasons, opennslRxReasonFilterMatch)
          && (pkt->rx_matched == ACL_LOG_RULE_ID)) {
        /* Copy relevant parts of the metadata and header to an ACL logging
        * buffer */
        acl_log_handle_rx_event(pkt);
    }

    return OPENNSL_RX_HANDLED;
}

int
ops_rx_init(int unit)
{
    opennsl_error_t  rc = OPENNSL_E_NONE;
    opennsl_rx_cfg_t rx_cfg;

    rc = opennsl_rx_register(unit,
                            "opennsl rx callback function",
                            opennsl_rx_callback,
                            OPS_RX_PRIORITY_MAX, /* Relative priority of callback.
                                                    0 is lowest */
                            NULL,   /* No data is passed to callback. */
                            -1);

    /* Get the current RX config settings. */
    (void)opennsl_rx_cfg_get(unit, &rx_cfg);

    /* Set a global rate limit on number of RX pkts per second. */
    rx_cfg.global_pps = OPS_RX_GLOBAL_PPS;

    rc = opennsl_rx_start(unit, &rx_cfg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to start BCM RX subsystem. unit=%d rc=%s",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    /* Always strip CRC from the incoming packet. */
    rc = opennsl_rx_control_set(unit, opennslRxControlCRCStrip, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set BCM RX control option. unit=%d rc=%s ",
                 unit, opennsl_errmsg(rc));
        return 1;
    }

    return 0;

} // ops_rx_init

int
ops_bcm_appl_init(void)
{
    int unit = 0;
    int rc = 0;

    ops_debug_init();
    rc = ops_mac_learning_init();
    if (rc) {
        VLOG_ERR("Mac learning init failed");
        return (1);
    }
    rc = event_log_init("SUBINTERFACE");
    if(rc < 0) {
        VLOG_ERR("Event log initialization failed for SUBINTERFACE");
    }
    rc = event_log_init("LAG");
    if(rc < 0) {
        VLOG_ERR("Event log initialization failed for LAG");
    }
    rc = event_log_init("VLANINTERFACE");
    if(rc < 0) {
        VLOG_ERR("Event log initialization failed for VLANINTERFACE");
    }
    rc = event_log_init("L3INTERFACE");
    if(rc < 0) {
        VLOG_ERR("Event log initialization failed for L3INTERFACE");
    }
    rc = event_log_init("ECMP");
    if(rc < 0) {
        VLOG_ERR("Event log initialization failed for ECMP");
    }

    /* Initialize QoS global data structures */
    rc = ops_qos_global_init();
    if (rc) {
        VLOG_ERR("QoS global subsytem init failed, rc %d", rc);
        return 1;
    }

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {

        rc = ops_port_init(unit);
        if (rc) {
            VLOG_ERR("Port subsystem init failed");
            return 1;
        }

        rc = ops_vlan_init(unit);
        if (rc) {
            VLOG_ERR("VLAN subsystem init failed");
            return 1;
        }

        rc = ops_rx_init(unit);
        if (rc) {
            VLOG_ERR("RX subsystem init failed");
            return 1;
        }

        rc = ops_knet_init(unit);
        if (rc) {
            VLOG_ERR("KNET subsystem init failed");
            return 1;
        }

        rc = ops_l3_init(unit);
        if (rc) {
            VLOG_ERR("L3 subsystem init failed");
            return 1;
        }

        rc = ops_stg_init(unit);
        if (rc) {
            VLOG_ERR("STG subsystem init failed");
            return 1;
        }

        rc = ops_sflow_init(unit);
        if (rc) {
            VLOG_ERR("sflow init failed");
            log_event("SFLOW_INIT_FAILURE", NULL);
            return 1;
        }

        rc = ops_copp_init();
        if (rc) {
            VLOG_ERR("COPP subsystem init failed");
            log_event("COPP_INITIALIZATION_FAILURE", NULL);
            return 1;
        }

        /* Initialize QoS per hw unit data structures */
        rc = ops_qos_hw_unit_init(unit);
        if (rc) {
            VLOG_ERR("QoS hw unit %d init failed, rc %d",
                      unit, rc);
            return 1;
        }

        rc = bcmsdk_mirrors_init(unit);
        if (rc) {
            VLOG_ERR("MIRRORING/SPAN subsystem init failed");
            return 1;
        }

        rc = ops_classifier_init(unit);
        if (rc) {
            VLOG_ERR("Classifier subsystem init failed");
            return 1;
        }
    }

    return 0;

} // ops_bcm_appl_init

int
ops_switch_main(int argc, char *argv[])
{
    opennsl_error_t rv;

    VLOG_INFO("Initializing OpenNSL driver.");

    /* Initialize the system. */
    rv = opennsl_driver_init(NULL);

    if (rv != OPENNSL_E_NONE) {
        VLOG_ERR("Failed to initialize the system.  rc=%s",
                 opennsl_errmsg(rv));
        return rv;
    }

    VLOG_INFO("OpenNSL driver init complete");

    if (ops_bcm_appl_init() != 0) {
        VLOG_ERR("OpenSwitch BCM application init failed!");
        return 1;
    }

    /* Let OVS know that BCM initialization is complete. */
    ovs_bcm_init_done();

#ifndef CDP_EXCLUDE
    opennsl_driver_shell();
    VLOG_INFO("OpenNSL BCM shell initialized");
#endif

    return 0;
}
