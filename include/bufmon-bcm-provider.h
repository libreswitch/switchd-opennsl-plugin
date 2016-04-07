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
 * File: bufmon-bcm-provider.h
 */

#ifndef BUFMON_BCM_PROVIDER_H
#define BUFMON_BCM_PROVIDER_H 1

#include <opennsl/types.h>
#include <opennsl/error.h>
#include <opennsl/cosq.h>
#include <opennsl/switch.h>
#include <bufmon-provider.h>

/* Counter Operations Type */
typedef enum counter_operations
{
    GET_COUNTER_VALUE = (0x1 << 0),
    SET_COUNTER_THRESHOLD = (0x1 << 1),
} counter_operations_t;

extern const struct bufmon_class bufmon_bcm_provider_class;

void realm_sync_all(void);

void handle_bufmon_counter_mgmt(bufmon_counter_info_t *counter,
                                counter_operations_t type);
void bst_init_thresholds(void);

void bst_switch_event_register(bool enable);

void bst_switch_control_set(opennsl_switch_control_t  type, int arg);

void bst_switch_control_get(int unit, opennsl_switch_control_t type, int *value);

void bst_switch_event_callback (int asic, opennsl_switch_event_t event,
                                int bid, int port, int cosq, void *cookie);

#endif /* bufmon-bcm-provider.h */
