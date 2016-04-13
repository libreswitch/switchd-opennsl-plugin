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
 * File: ops-debug.h
 *
 * Purpose: This file provides public definitions for switchd debugging.
 *
 */

#ifndef __OPS_DEBUG_H__
#define __OPS_DEBUG_H__ 1

#include <shared/pbmp.h>
#include <opennsl/field.h>
#include <opennsl/pkt.h>
#include <opennsl/types.h>
#include <opennsl/cosq.h>

extern uint32 slog_level;

#define SWITCHD_DBG         (SWITCHD_INIT_DBG | SWITCHD_PORT_DBG | SWITCHD_VLAN_DBG)
#define SWITCHD_INIT_DBG    0x00001
#define SWITCHD_PORT_DBG    0x00002
#define SWITCHD_LAG_DBG     0x00004
#define SWITCHD_VLAN_DBG    0x00008
#define SWITCHD_L3_DBG      0x00010
#define MAX_STAT_TYPES      8

#define DBG_SLOG(level, format, ...)                          \
do {                                                          \
        int __enabled=slog_level & level;                     \
        if (__enabled) {                                      \
            VLOG_INFO("%s(%d): "format,                       \
                      __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        }                                                     \
} while (0)

// OPS_TODO - rework these to simply use ovs-appctl to turn
// debugging on/off for each subsystem.
#define SW_INIT_DBG(format...)   DBG_SLOG(SWITCHD_INIT_DBG, format)
#define SW_PORT_DBG(format...)   DBG_SLOG(SWITCHD_PORT_DBG, format)
#define SW_LAG_DBG(format...)    DBG_SLOG(SWITCHD_LAG_DBG, format)
#define SW_VLAN_DBG(format...)   DBG_SLOG(SWITCHD_VLAN_DBG, format)
#define SW_L3_DBG(format...)     DBG_SLOG(SWITCHD_L3_DBG, format)

#define SW_INIT_DBG_ENABLED()   (slog_level & SWITCHD_INIT_DBG)
#define SW_PORT_DBG_ENABLED()   (slog_level & SWITCHD_PORT_DBG)
#define SW_LAG_DBG_ENABLED()    (slog_level & SWITCHD_LAG_DBG)
#define SW_VLAN_DBG_ENABLED()   (slog_level & SWITCHD_VLAN_DBG)
#define SW_L3_DBG_ENABLED()     (slog_level & SWITCHD_L3_DBG)

typedef struct ops_debug_s {
    char            *sub_system;
    unsigned int    value;
} ops_debug_t;

extern int ops_debug_init(void);
typedef struct enum_to_str_s {
    int   action_type;
    char  *api_str;
} enum_to_str_t;

#endif // __OPS_DEBUG_H__
