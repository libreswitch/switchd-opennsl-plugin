/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    platform-defines.h
 *
 * Purpose: This file provides platform related #defines & constants.
 *
 */
#ifndef __PLATFORM_DEFINES_H__
#define __PLATFORM_DEFINES_H__ 1

/* Halon global defines. */
#define MAX_SWITCH_UNITS     1
#define MAX_SWITCH_UNIT_ID   (MAX_SWITCH_UNITS - 1)

/* HALON_TODO: these are no longer available in OpenNSL.
 * Maybe add build-time variable to customize these, if neeeded. */
#define MAX_HW_PORTS         128
#define MAX_PORTS(unit)      128
#define CPU_PORT(unit)       0

#define VALID_HW_UNIT(hw_unit)      (((hw_unit) >= 0) && ((hw_unit) < MAX_SWITCH_UNITS))

/*********************************************************************
 * hc-debug.c: returns BCMSDK datapath version.
 ********************************************************************/
extern char * bcmsdk_datapath_version(void);

#endif /* __PLATFORM_DEFINES_H__ */
