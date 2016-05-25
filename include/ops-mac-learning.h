/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Development Company, L.P.
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
 * File: ops-mac-learning.h
 *
 * Purpose: This file provides public definitions for Interface statistics API.
 */

#ifndef __OPS_MAC_LEARNING_H__
#define __OPS_MAC_LEARNING_H__ 1

#include <opennsl/l2.h>
#include "openvswitch/vlog.h"
#include "mac-learning-plugin.h"
#include "plugin-extensions.h"
#include "ops-routing.h"

extern int ops_mac_learning_init();
extern void ops_mac_learn_cb(int unit, opennsl_l2_addr_t *l2addr,
                             int operation, void *userdata);
extern int ops_mac_learning_get_hmap(struct mlearn_hmap **mhmap);
int ops_l2_addr_flush_handler(mac_flush_params_t *settings);
#endif /* __OPS_MAC_LEARNING_H__ */
