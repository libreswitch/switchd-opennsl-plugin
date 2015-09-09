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
 * File: ops-port.h
 *
 * Purpose: This file provides public definitions for BCMSDK Port applications.
 */

#ifndef __OPS_PORT_H__
#define __OPS_PORT_H__ 1

#include <stdint.h>
#include <netinet/ether.h>

#include <opennsl/types.h>
#include <opennsl/port.h>

#include "platform-defines.h"

// Max frame size.  We want to support jumbo frame for all ports
// (0x2400, or 9216) on all ports running at speeds up to 1G.
// For 10G or faster ports, we use Broadcom's default 16356 (0x3fe4).
#define JUMBO_SZ                          0x2400
#define JUMBO_10G_SZ                      0x3fe4

#define BCMSDK_MTU_TO_MAXFRAMESIZE_PAD    24

#define PORT_INFO(unit, port)    ((port_info[(unit)] != (struct ops_port_info *) NULL) ? \
                                  &(port_info[(unit)][(port)]) : (struct ops_port_info *)NULL)

#define MAX_QSFP_SPLIT_PORT_COUNT           4

struct port_cfg {
    /* configured or intended state */
    int   enable;
    int   autoneg;
    int   cfg_speed;
    int   duplex;
    int   pause_rx;
    int   pause_tx;
    int   max_frame_sz;
    opennsl_port_if_t   intf_type;

    /* current status */
    int   link_status;
    int   link_speed;
};

struct ops_port_info {
    char    *name;
    int     hw_unit;        /* Hardware unit number. */
    int     hw_port;        /* Hardware port number. */

    /* ------- Subport/lane split config (e.g. QSFP+) -------
     * Subport count & lane split status. These are valid for
     * primary port only.  We currently only support port split
     * on QSFP ports, and each port can be split into 4 separate
     * ports.  By definition, the 4 lanes of a QSFP+ port must
     * be consecutively numbered.
     */
    uint32_t    split_port_count;
    bool        lanes_split_status;
};

extern struct ops_port_info *port_info[MAX_SWITCH_UNITS];

extern int ops_port_init(int hw_unit);
extern opennsl_pbmp_t ops_get_link_up_pbm(int unit);

extern int bcmsdk_port_kernel_if_init(char *name, int hw_unit, opennsl_port_t hw_port,
                                      struct ether_addr *mac);
extern int bcmsdk_port_kernel_if_deinit(char *name, int hw_unit, opennsl_port_t hw_port);

extern int split_port_lane_config(struct ops_port_info *p_info, bool is_split_needed);

extern int bcmsdk_set_port_config(int hw_unit, opennsl_port_t hw_port, const struct port_cfg *pcfg);
extern int bcmsdk_set_enable_state(int hw_unit, opennsl_port_t hw_port, int enable);
extern int bcmsdk_get_enable_state(int hw_unit, opennsl_port_t hw_port, int *enable);
extern int bcmsdk_get_link_status(int hw_unit, opennsl_port_t hw_port, int *linkup);
extern int bcmsdk_get_port_config(int hw_unit, opennsl_port_t hw_port, struct port_cfg *pcfg);

#endif /* __OPS_PORT_H__ */
