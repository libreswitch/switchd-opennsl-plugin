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
 * File: ops-pbmp.c
 *
 * Purpose: This file contains OpenSwitch port bitmap abstraction.
 *          It extends OpenNSL port bitmaps to support multiple switch chip units.
 */

#include <stdlib.h>
#include <ovs/util.h>

#include "platform-defines.h"
#include "ops-pbmp.h"

opennsl_pbmp_t *
bcmsdk_alloc_pbmp(void)
{
    int unit;
    opennsl_pbmp_t *pbm;

    pbm = (opennsl_pbmp_t *)xmalloc(sizeof(opennsl_pbmp_t) * MAX_SWITCH_UNITS);

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        OPENNSL_PBMP_CLEAR(pbm[unit]);
    }

    return pbm;

} // bcmsdk_alloc_pbmp

void
bcmsdk_clear_pbmp(opennsl_pbmp_t *pbm)
{
    int unit;

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        OPENNSL_PBMP_CLEAR(pbm[unit]);
    }

} // bcmsdk_clear_pbmp

void
bcmsdk_destroy_pbmp(opennsl_pbmp_t *pbm)
{
    free(pbm);

} // bcmsdk_destroy_pbmp

void
bcmsdk_pbmp_add_hw_port(opennsl_pbmp_t *pbm, int hw_unit, int hw_id)
{
    OPENNSL_PBMP_PORT_ADD(pbm[hw_unit], hw_id);

} // bcmsdk_pbmp_add_hw_port

void
bcmsdk_pbmp_del_hw_port(opennsl_pbmp_t *pbm, int hw_unit, int hw_id)
{
    OPENNSL_PBMP_PORT_REMOVE(pbm[hw_unit], hw_id);

} // bcmsdk_pbmp_del_hw_port

int
bcmsdk_pbmp_is_empty(opennsl_pbmp_t *pbm)
{
    int unit;
    int empty = 1;

    // Returns 1 if the pbm is empty for all units.
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        if (!OPENNSL_PBMP_IS_NULL(pbm[unit])) {
            empty = 0;
            break;
        }
    }

    return empty;

} // bcmsdk_pbmp_is_empty

void
bcmsdk_pbmp_remove(opennsl_pbmp_t *dst_pbm, const opennsl_pbmp_t *src_pbm,
                   const opennsl_pbmp_t *del_pbm)
{
    int unit;

    // Removes "del_pbm" bits from "src_pbm" and places
    // the resulting port bitmap in "dest_pbm".  This
    // function does not modify either src or del pbms.
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        OPENNSL_PBMP_ASSIGN(dst_pbm[unit], src_pbm[unit]);
        OPENNSL_PBMP_REMOVE(dst_pbm[unit], del_pbm[unit]);
    }

} // bcmsdk_pbmp_remove

void
bcmsdk_pbmp_and(opennsl_pbmp_t *dst_pbm, const opennsl_pbmp_t *src_pbm_1,
                const opennsl_pbmp_t *src_pbm_2)
{
    int unit;

    // ANDs "src_pbm_1" and "src_pbm_2" bits and places
    // the resulting port bitmap in "dest_pbm".  Does not
    // modify either src pbms.
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        OPENNSL_PBMP_ASSIGN(dst_pbm[unit], src_pbm_1[unit]);
        OPENNSL_PBMP_AND(dst_pbm[unit], src_pbm_2[unit]);
    }

} // bcmsdk_pbmp_and
