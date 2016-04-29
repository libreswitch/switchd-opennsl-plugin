/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Company, L.P.
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
 * File: ops-bcm-init.h
 */

#ifndef __OPS_BCM_INIT_H__
#define __OPS_BCM_INIT_H__ 1

/* This function initializes switchd application threads within the SDK. */
#define BCM_DIAG_SHELL_CUSTOM_INIT_F        ops_bcm_appl_init

/* Number of RX packets per second.
 * This limit is enforced in the user space SDK. */
#define OPS_RX_GLOBAL_PPS            30000

#define OPS_RX_PRIORITY_MAX          100

extern int ops_switch_main(int argc, char *argv[]);

#endif // __OPS_BCM_INIT_H__
