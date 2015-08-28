/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    hc_vlan.h
 *
 * Purpose: This file provides public definitions for BCMSDK VLAN applications.
 *
 */
#ifndef __HC_VLAN_H__
#define __HC_VLAN_H__ 1

#include <ovs/dynamic-string.h>
#include <opennsl/types.h>

extern void hc_vlan_dump(struct ds *ds, int vid);
extern int hc_vlan_init(int hw_unit);

extern int bcmsdk_create_vlan(int vid, bool internal);
extern int bcmsdk_destroy_vlan(int vid, bool internal);

extern int bcmsdk_add_access_ports(int vid, opennsl_pbmp_t *pbm, bool internal);
extern int bcmsdk_del_access_ports(int vid, opennsl_pbmp_t *pbm, bool internal);
extern void bcmsdk_add_trunk_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_del_trunk_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_add_native_tagged_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_del_native_tagged_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_add_native_untagged_ports(int vid, opennsl_pbmp_t *pbm);
extern void bcmsdk_del_native_untagged_ports(int vid, opennsl_pbmp_t *pbm);

extern void vlan_reconfig_on_link_change(int unit, opennsl_port_t hw_port, int link_is_up);

#endif /* __HC_VLAN_H__ */
