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
 * File: bcm-plugins.c
 */

#include <openvswitch/vlog.h>
#include <netdev-provider.h>
#include "bcm.h"
#include "bufmon-bcm-provider.h"
#include "netdev-bcmsdk.h"
#include "ofproto-bcm-provider.h"
#include "plugin-extensions.h"
#include "asic-plugin.h"
#include "ops-stg.h"
#include "eventlog.h"
#include "ops-copp.h"
#include "copp-asic-provider.h"
#include "ops-mac-learning.h"

#define init libovs_bcm_plugin_LTX_init
#define run libovs_bcm_plugin_LTX_run
#define wait libovs_bcm_plugin_LTX_wait
#define destroy libovs_bcm_plugin_LTX_destroy
#define netdev_register libovs_bcm_plugin_LTX_netdev_register
#define ofproto_register libovs_bcm_plugin_LTX_ofproto_register
#define bufmon_register libovs_bcm_plugin_LTX_bufmon_register

VLOG_DEFINE_THIS_MODULE(bcm_plugin);

struct asic_plugin_interface opennsl_interface ={
    /* The new functions that need to be exported, can be declared here*/
    .create_stg = &create_stg,
    .delete_stg = &delete_stg,
    .add_stg_vlan = &add_stg_vlan,
    .remove_stg_vlan = &remove_stg_vlan,
    .set_stg_port_state = &set_stg_port_state,
    .get_stg_port_state = &get_stg_port_state,
    .get_stg_default = &get_stg_default,
    .get_mac_learning_hmap = &ops_mac_learning_get_hmap,
};

struct copp_asic_plugin_interface copp_opennsl_interface ={
    /*
     * The function pointers are set to the interfacing functions
     * implemented by copp in the opennsl-plugin
     */
    .copp_stats_get = &copp_opennsl_stats_get,
    .copp_hw_status_get = &copp_opennsl_hw_status_get,
};

/* To avoid compiler warning... */
static void netdev_change_seq_changed(const struct netdev *) __attribute__((__unused__));

void
init(void) {

    int retval;
    struct plugin_extension_interface opennsl_extension;
    struct plugin_extension_interface copp_opennsl_extension;

    /* Event log initialization for sFlow */
    retval = event_log_init("SFLOW");
    if (retval < 0) {
        VLOG_ERR("Event log initialization failed for SFLOW");
    }

    /* Event log initialization for LAG */
    retval = event_log_init("LAG");
    if (retval < 0) {
        VLOG_ERR("Event log initialization failed for LAG");
    }

    opennsl_extension.plugin_name = ASIC_PLUGIN_INTERFACE_NAME;
    opennsl_extension.major = ASIC_PLUGIN_INTERFACE_MAJOR;
    opennsl_extension.minor = ASIC_PLUGIN_INTERFACE_MINOR;
    opennsl_extension.plugin_interface = (void *)&opennsl_interface;

    register_plugin_extension(&opennsl_extension);
    VLOG_INFO("The %s asic plugin interface was registered", ASIC_PLUGIN_INTERFACE_NAME);

    copp_opennsl_extension.plugin_name = COPP_ASIC_PLUGIN_INTERFACE_NAME;
    copp_opennsl_extension.major = COPP_ASIC_PLUGIN_INTERFACE_MAJOR;
    copp_opennsl_extension.minor = COPP_ASIC_PLUGIN_INTERFACE_MINOR;
    copp_opennsl_extension.plugin_interface = (void *)&copp_opennsl_interface;

    register_plugin_extension(&copp_opennsl_extension);
    VLOG_INFO("The %s asic plugin interface was registered",
                                              COPP_ASIC_PLUGIN_INTERFACE_NAME);

    register_qos_extension();
    ovs_bcm_init();
}

void
run(void) {
}

void
wait(void) {
}

void
destroy(void) {
    // OPS_TODO: add graceful shutdown of BCM threads.
}

void
netdev_register(void) {
    netdev_bcmsdk_register();
}

void
ofproto_register(void) {
    ofproto_class_register(&ofproto_bcm_provider_class);
}

void
bufmon_register(void) {
    bufmon_class_register(&bufmon_bcm_provider_class);
}
