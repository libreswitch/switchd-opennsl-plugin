/*
 * (C) Copyright 2016 Broadcom Limited
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
 * File: ofproto-ofdpa.h
 */
#ifndef OFPROTO_OFDPA_H
#define OFPROTO_OFDPA_H 1

#include "ofp-util.h"
#include "opennsl/ofdpa_datatypes.h"
#include "opennsl/ofdpa_api.h"

#define OFDPA_DATAPATH_TYPE "ofdpa"

typedef struct ovs_ofdpa_group_bucket_s
{
  uint32_t        outputPort;
  uint32_t        popVlanTag;

} ovs_ofdpa_group_bucket_t;

#endif /* ofproto-ofdpa.h */
