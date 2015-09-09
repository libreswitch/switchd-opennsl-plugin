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
 * File: ops-lag.h
 *
 * Purpose: This file provides public definitions for OpenSwitch LAG applications.
 */

#ifndef __OPS_LAG_H__
#define __OPS_LAG_H__ 1

#include <ovs/dynamic-string.h>

#include <opennsl/types.h>
#include <opennsl/trunk.h>

extern void ops_lag_dump(struct ds *ds, opennsl_trunk_t lagid);

extern void bcmsdk_create_lag(opennsl_trunk_t *lag_id);
extern void bcmsdk_destroy_lag(opennsl_trunk_t lag_id);
extern void bcmsdk_attach_ports_to_lag(opennsl_trunk_t lag_id, opennsl_pbmp_t *pbm);
extern void bcmsdk_egress_enable_lag_ports(opennsl_trunk_t lag_id, opennsl_pbmp_t *pbm);
extern void bcmsdk_set_lag_balance_mode(opennsl_trunk_t lag_id, int lag_mode);

#endif /* __OPS_LAG_H__ */
