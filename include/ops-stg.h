/*
 * Copyright (C) 2016 Hewlett-Packard Development Company, L.P.
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
 * File: ops-stg.h
 *
 * Purpose: This file provides public definitions for Opennsl Spanning Tree Group API's.
 */

#ifndef __OPS_STG_H__
#define __OPS_STG_H__ 1

#include <ovs/dynamic-string.h>
#include <opennsl/types.h>
#include "platform-defines.h"
#include "ops-pbmp.h"

#define OPS_STG_RESERVED      0
#define OPS_STG_DEFAULT       1
#define OPS_STG_MIN           1
#define OPS_STG_MAX           64
#define OPS_STG_VALID(v)  ((v)>=OPS_STG_MIN && (v)<=OPS_STG_MAX)
#define OPS_STG_COUNT         64

typedef struct ops_stg_vlan {
    struct hmap_node node;            /* ops_stg[stg_id]->vlans */
    uint16  vlan_id;
}ops_stg_vlan_t;

typedef struct ops_stg_data {
    int stg_id;
    int n_vlans;
    struct hmap vlans;
    opennsl_pbmp_t disabled_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t blocked_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t learning_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t forwarding_ports[MAX_SWITCH_UNITS];
} ops_stg_data_t;

typedef enum ops_stg_port_state {
    OPS_STG_PORT_STATE_DISABLED = 0,
    OPS_STG_PORT_STATE_BLOCKED,
    OPS_STG_PORT_STATE_LEARNING,
    OPS_STG_PORT_STATE_FORWARDING,
    OPS_STG_PORT_STATE_NOT_SET
}ops_stg_port_state_t;

int ops_stg_init(int hw_unit);
void ops_stg_dump(struct ds *ds, int stgid);
void ops_stg_hw_dump(struct ds *ds, int stgid);

int ops_stg_default_get(opennsl_stg_t *stg_ptr);
int ops_stg_vlan_add(opennsl_stg_t stg, opennsl_vlan_t vid);
int ops_stg_vlan_remove(opennsl_stg_t stg, opennsl_vlan_t vid);
int ops_stg_create(opennsl_stg_t *stg_ptr);
int ops_stg_delete(opennsl_stg_t stg);
int ops_stg_stp_set(opennsl_stg_t stg, opennsl_port_t port,
                          int stp_state, bool port_stp_set);
int ops_stg_stp_get(opennsl_stg_t stg, opennsl_port_t port,
                           int *stp_state_ptr);

int create_stg(int *p_stg);
int delete_stg(int stg);
int add_stg_vlan(int stg, int vid);
int remove_stg_vlan(int stg, int vid);
int set_stg_port_state(char *port_name, int stg,
                          int stp_state, bool port_stp_set);
int get_stg_port_state(char *port_name, int stg, int *p_stp_state);
int get_stg_default(int *p_stg);
#endif /* __OPS_STG_H__ */
