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
 * File: platform-defines.h
 *
 * Purpose: This file provides platform related #defines & constants.
 */

#ifndef __PLATFORM_DEFINES_H__
#define __PLATFORM_DEFINES_H__ 1

/* OpenSwitch global defines. */
#define MAX_SWITCH_UNITS     1
#define MAX_SWITCH_UNIT_ID   (MAX_SWITCH_UNITS - 1)

/* OPS_TODO: these are no longer available in OpenNSL.
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
