/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    halon_debug.h
 *
 * Purpose: This file provides public definitions for switchd debugging.
 *
 */

#ifndef __HALON_DEBUG_H__
#define __HALON_DEBUG_H__ 1

#include <shared/pbmp.h>

extern uint32 slog_level;

#define SWITCHD_DBG         (SWITCHD_INIT_DBG | SWITCHD_PORT_DBG | SWITCHD_VLAN_DBG)
#define SWITCHD_INIT_DBG    0x00001
#define SWITCHD_PORT_DBG    0x00002
#define SWITCHD_LAG_DBG     0x00004
#define SWITCHD_VLAN_DBG    0x00008
#define SWITCHD_L3_DBG      0x00010

#define DBG_SLOG(level, format, ...)                          \
do {                                                          \
        int __enabled=slog_level & level;                     \
        if (__enabled) {                                      \
            VLOG_INFO("%s(%d): "format,                       \
                      __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        }                                                     \
} while (0)

// HALON_TODO - rework these to simply use ovs-appctl to turn
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

typedef struct hc_debug_s {
    char            *sub_system;
    unsigned int    value;
} hc_debug_t;

extern int hc_debug_init(void);

#endif // __HALON_DEBUG_H__
