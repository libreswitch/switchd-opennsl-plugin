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
 * File: ops-mirrors.h
 *
 * Purpose: This file has code to manage mirrors/span sessions for
 *          BCM hardware.  It uses the opennsl interface for all
 *          hw related operations.
 */

#ifndef __OPS_MIRRORS_H__
#define __OPS_MIRRORS_H__ 1

#include <inttypes.h>
#include <errno.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/switch.h>
#include <opennsl/mirror.h>
#include <ofproto/ofproto-provider.h>
#include <openvswitch/vlog.h>
#include "ofproto-bcm-provider.h"
#include "netdev-bcmsdk.h"
#include "platform-defines.h"
#include "plugin-extensions.h"
#include "ofproto-bcm-provider.h"
#include "eventlog.h"
#include "ops-stats.h"

extern int
bcmsdk_mirrors_init(int unit);

extern void
mirror_object_destroy_with_mtp (struct ofbundle *mtp);

extern int
mirror_set__ (struct ofproto *ofproto_,
    void *aux, const struct ofproto_mirror_settings *s);

extern int
mirror_get_stats__ (struct ofproto *ofproto_,
    void *aux, uint64_t *packets, uint64_t *bytes);

extern bool
is_mirror_output_bundle (const struct ofproto *ofproto_, void *aux);

#endif /* __OPS_MIRRORS_H__ */
