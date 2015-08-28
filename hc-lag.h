/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    hc_lag.h
 *
 * Purpose: This file provides public definitions for OpenHalon LAG applications.
 *
 */
#ifndef __HC_LAG_H__
#define __HC_LAG_H__ 1

#include <ovs/dynamic-string.h>

#include <opennsl/types.h>
#include <opennsl/trunk.h>

extern void hc_lag_dump(struct ds *ds, opennsl_trunk_t lagid);

extern void bcmsdk_create_lag(opennsl_trunk_t *lag_id);
extern void bcmsdk_destroy_lag(opennsl_trunk_t lag_id);
extern void bcmsdk_attach_ports_to_lag(opennsl_trunk_t lag_id, opennsl_pbmp_t *pbm);
extern void bcmsdk_egress_enable_lag_ports(opennsl_trunk_t lag_id, opennsl_pbmp_t *pbm);
extern void bcmsdk_set_lag_balance_mode(opennsl_trunk_t lag_id, int lag_mode);

#endif /* __HC_LAG_H__ */
