
/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __QOS_H__
#define __QOS_H__ 1

#include <stdio.h>
#include <stdlib.h>
#include "ofproto/ofproto-provider.h"

/* QOS */

/* Defines & structures that platform-independent (PI) layer API use when
   communicating with platform-dependent (PD) code, so that PD does not
   have to know anything about the IDL interface. */

/* In System or Port table, possible values in qos_enum_config column. */
enum qos_trust {
    QOS_TRUST_NONE = 0,
    QOS_TRUST_COS,
    QOS_TRUST_DSCP,
    QOS_TRUST_MAX /* Used for validation only! */
};

/* collection of parameters to set_port_qos_cfg API */
struct qos_port_settings {
    enum qos_trust qos_trust;
    const struct smap *other_config;
};

/* in QoS_DSCP_Map or QoS_COS_Map, possibible values for color column */
enum cos_color {
    COS_COLOR_GREEN = 0,
    COS_COLOR_YELLOW,
    COS_COLOR_RED,
    COS_COLOR_MAX
};

/* single row from QoS_DSCP_Map table */
struct dscp_map_entry {
    enum cos_color  color;
    int codepoint;
    int local_priority;
    int cos;
    struct smap *other_config;
};

/* 1 or more rows in QoS_DSCP_Map passed to set_dscp_map API */
struct dscp_map_settings {
    int n_entries;
    struct dscp_map_entry *entries;   /* array of 'struct dscp_map_entry' */
};

/* single row from QoS_COS_Map table */
struct cos_map_entry {
    enum cos_color color;
    int codepoint;
    int local_priority;
    struct smap *other_config;
};

/* 1 or more rows in QoS_COS_Map passed to set_cos_map API */
struct cos_map_settings {
    int n_entries;
    struct cos_map_entry *entries;   /* array of 'struct cos_map_entry' */
};

int set_port_qos_cfg(struct ofproto *ofproto,
                        void *aux,
                        const struct qos_port_settings *settings);

int set_cos_map(struct ofproto *ofproto,
                    const void *aux,
                    const struct cos_map_settings *settings);

int set_dscp_map(struct ofproto *ofproto,
                    void *aux,
                    const struct dscp_map_settings *settings);

#endif /*__QOS_H__*/
