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
 * File: bufmon-bcm-provider.c
 *
 * Purpose: This file contains OpenSwitch bufmon provider implementation code
 */

#include <stdlib.h>
#include <errno.h>
#include <seq.h>
#include <coverage.h>
#include <openvswitch/vlog.h>
#include "platform-defines.h"
#include "bufmon-bcm-provider.h"

VLOG_DEFINE_THIS_MODULE(bufmon_bcm_provider);

/* Factory functions. */

int
init(void)
{
    return 0;
} /* init */

void
bufmon_system_config(const bufmon_system_config_t *args)
{
    /* Tracking Enabled */
    bst_switch_control_set(opennslSwitchBstEnable, args->enabled);

    /* Tracking Mode */
    bst_switch_control_set(opennslSwitchBstTrackingMode,
                           args->counters_mode);

    /* Register the trigger callback function */
    bst_switch_event_register(args->threshold_trigger_collection_enabled);

    return;
} /* bufmon_system_config */

void
bufmon_counter_config(bufmon_counter_info_t *args)
{
    handle_bufmon_counter_mgmt(args, SET_COUNTER_THRESHOLD);
} /* bufmon_counter_config */

void
bufmon_counter_stats_get(bufmon_counter_info_t *list,
                         int num_counters)
{
    int i = 0;

    if (!num_counters) {
        return;
    }

    /* stats sync from ASIC */
    realm_sync_all();

    for (i = 0; i < num_counters; i++) {
        bufmon_counter_info_t *counter = &list[i];
        handle_bufmon_counter_mgmt(counter, GET_COUNTER_VALUE);
    }

    return;
} /* bufmon_counter_stats_get */

void
bufmon_trigger_register(bool enable)
{
    bst_switch_event_register(enable);
} /* bufmon_trigger_register */

const struct bufmon_class bufmon_bcm_provider_class = {
    init,
    bufmon_system_config,
    bufmon_counter_config,
    bufmon_counter_stats_get,
    bufmon_trigger_register,
};
