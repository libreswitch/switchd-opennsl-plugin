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
 * File: ops-fp.h
 *
 * Purpose: This file provides public definitions for FP functionality.
 *
 */

#ifndef __OPS_FP_H__
#define __OPS_FP_H__ 1

enum ops_fp_grp_prio {
    FP_GROUP_PRIORITY_0 = 0, /* for L3 FP */
    FP_GROUP_PRIORITY_1,     /* for Classifier FP */
    FP_GROUP_PRIORITY_2      /* for COPP and OSPF */
};

#endif
