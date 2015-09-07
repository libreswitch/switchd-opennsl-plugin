/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    hc-pbmp.h
 *
 * Purpose: This file provides public definitions for OpenHalon port bitmap abstraction.
 *
 */
#ifndef __HC_PBMP_H__
#define __HC_PBMP_H__ 1

#include <opennsl/types.h>

// Allocates port bitmap structure for all switch chip units.
extern opennsl_pbmp_t * bcmsdk_alloc_pbmp(void);
extern void bcmsdk_destroy_pbmp(opennsl_pbmp_t *pbm);
extern void bcmsdk_clear_pbmp(opennsl_pbmp_t *pbm);

// Add/del hw_ports to unit-specific bitmap.
extern void bcmsdk_pbmp_add_hw_port(opennsl_pbmp_t *pbm, int hw_unit, int hw_id);
extern void bcmsdk_pbmp_del_hw_port(opennsl_pbmp_t *pbm, int hw_unit, int hw_id);

// Returns 1 if the pbm is empty for all units.
extern int  bcmsdk_pbmp_is_empty(opennsl_pbmp_t *pbm);

// Removes "del_pbm" bits from "src_pbm" and places the resulting
// port bitmap in "dest_pbm".  Does not modify either src or del pbms.
extern void bcmsdk_pbmp_remove(opennsl_pbmp_t *dst_pbm,
                               const opennsl_pbmp_t *src_pbm,
                               const opennsl_pbmp_t *del_pbm);

// ANDs "src_pbm_1" and "src_pbm_2" bits and places the resulting
// port bitmap in "dest_pbm".  Does not modify either src pbms.
extern void bcmsdk_pbmp_and(opennsl_pbmp_t *dst_pbm,
                            const opennsl_pbmp_t *src_pbm_1,
                            const opennsl_pbmp_t *src_pbm_2);

#endif /* __HC_PBMP_H__ */
