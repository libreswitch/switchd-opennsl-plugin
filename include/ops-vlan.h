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
 * File: ops-vlan.h
 *
 * Purpose: This file provides public definitions for BCMSDK VLAN applications.
 */

#ifndef __OPS_VLAN_H__
#define __OPS_VLAN_H__ 1

#include <ovs/dynamic-string.h>
#include <opennsl/types.h>

extern void ops_vlan_dump(struct ds *ds, int vid);
extern int ops_vlan_init(int hw_unit);

extern int bcmsdk_create_vlan(int vid, bool internal);
extern int bcmsdk_destroy_vlan(int vid, bool internal);

extern int bcmsdk_add_access_ports(int vid, opennsl_pbmp_t *pbm);
extern int bcmsdk_del_access_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_add_trunk_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_del_trunk_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_add_native_tagged_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_del_native_tagged_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_add_native_untagged_ports(int vid, opennsl_pbmp_t *pbm, bool internal);
extern void bcmsdk_del_native_untagged_ports(int vid, opennsl_pbmp_t *pbm, bool internal);
extern void bcmsdk_add_subinterface_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_del_subinterface_ports(int vid, opennsl_pbmp_t *pbm);

extern void vlan_reconfig_on_link_change(int unit, opennsl_port_t hw_port, int link_is_up);
extern bool is_vlan_membership_empty(int vid);
extern bool is_user_created_vlan(int vid);
extern void set_created_by_user(int vid, bool status);

#endif /* __OPS_VLAN_H__ */
