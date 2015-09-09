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
 * File: ops-vlan.c
 *
 * Purpose: This file contains OpenSwitch VLAN related application code in the Broadcom SDK.
 */

#include <stdio.h>
#include <stdlib.h>

#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/port.h>
#include <opennsl/vlan.h>

#include "platform-defines.h"
#include "ops-debug.h"
#include "ops-pbmp.h"
#include "ops-port.h"
#include "ops-vlan.h"

VLOG_DEFINE_THIS_MODULE(ops_vlan);

#define OPS_VLAN_MIN       0
#define OPS_VLAN_MAX       4095
#define OPS_VLAN_COUNT     (OPS_VLAN_MAX - OPS_VLAN_MIN + 1)
#define OPS_VLAN_VALID(v)  ((v)>OPS_VLAN_MIN && (v)<OPS_VLAN_MAX)

typedef struct ops_vlan_data {

    int vid;
    int hw_created;  // Boolean indicating if this VLAN
                     // has been created in VLAN table,
                     // which implies it exists in h/w.

    // Bitmaps of interfaces configured for this VLAN.
    opennsl_pbmp_t cfg_access_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t cfg_trunk_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t cfg_native_tag_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t cfg_native_untag_ports[MAX_SWITCH_UNITS];

    // Bitmaps of interfaces actually installed in h/w.
    // Only interfaces that are linked up are installed.
    opennsl_pbmp_t hw_access_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t hw_trunk_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t hw_native_tag_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t hw_native_untag_ports[MAX_SWITCH_UNITS];

} ops_vlan_data_t;

// Global empty port bitmap.
opennsl_pbmp_t g_empty_pbm;

// To keep things simple & for fast access, just create
// an array of VLAN data pointers.  A counter is included
// to help optimize looping through all VIDs, where loop
// can be stopped when all VLANs have been seen.
// Note that valid VID range is only 1-4094.
unsigned int ops_vlan_count = 0;
ops_vlan_data_t *ops_vlans[OPS_VLAN_COUNT] = { NULL };

unsigned int ops_internal_vlan_count = 0;
ops_vlan_data_t *ops_internal_vlans[OPS_VLAN_COUNT] = { NULL };
////////////////////////////////// DEBUG ///////////////////////////////////

static void
show_vlan_data(struct ds *ds, ops_vlan_data_t *vlanp)
{
    int unit;
    char pfmt[_SHR_PBMP_FMT_LEN];

    ds_put_format(ds, "VLAN %d:\n", vlanp->vid);
    ds_put_format(ds, "  hw_created=%d\n", vlanp->hw_created);
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        ds_put_format(ds, "  configured access ports=%s\n",
                      _SHR_PBMP_FMT(vlanp->cfg_access_ports[unit], pfmt));
        ds_put_format(ds, "  configured trunk ports=%s\n",
                      _SHR_PBMP_FMT(vlanp->cfg_trunk_ports[unit], pfmt));
        ds_put_format(ds, "  configured native tagged ports=%s\n",
                      _SHR_PBMP_FMT(vlanp->cfg_native_tag_ports[unit], pfmt));
        ds_put_format(ds, "  configured native untagged ports=%s\n",
                      _SHR_PBMP_FMT(vlanp->cfg_native_untag_ports[unit], pfmt));
        ds_put_format(ds, "\n");
        ds_put_format(ds, "  installed access ports=%s\n",
                      _SHR_PBMP_FMT(vlanp->hw_access_ports[unit], pfmt));
        ds_put_format(ds, "  installed trunk ports=%s\n",
                      _SHR_PBMP_FMT(vlanp->hw_trunk_ports[unit], pfmt));
        ds_put_format(ds, "  installed native tagged ports=%s\n",
                      _SHR_PBMP_FMT(vlanp->hw_native_tag_ports[unit], pfmt));
        ds_put_format(ds, "  installed native untagged ports=%s\n",
                      _SHR_PBMP_FMT(vlanp->hw_native_untag_ports[unit], pfmt));
    }
    ds_put_format(ds, "\n");

} // show_vlan_data

void
ops_vlan_dump(struct ds *ds, int vid)
{
    int unit;
    char pfmt[_SHR_PBMP_FMT_LEN];

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        ds_put_format(ds, "Unit %d linked up ports = %s\n", unit,
                      _SHR_PBMP_FMT(ops_get_link_up_pbm(unit), pfmt));
    }

    if (OPS_VLAN_VALID(vid)) {
        if (ops_vlans[vid] != NULL) {
            show_vlan_data(ds, ops_vlans[vid]);
        } else {
            ds_put_format(ds, "VLAN %d does not exist.\n", vid);
        }
    } else {
        int vid, count;
        ds_put_format(ds, "Dumping all VLANs (count=%d)...\n", ops_vlan_count);
        for (vid=0, count=0; vid<OPS_VLAN_COUNT && count<ops_vlan_count; vid++) {
            if (ops_vlans[vid] != NULL) {
                count++;
                show_vlan_data(ds, ops_vlans[vid]);
            }
        }
    }

} // ops_vlan_dump

////////////////////////////////// HW API //////////////////////////////////

static opennsl_error_t
enable_vlan_translation(int unit, opennsl_port_t hw_port)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    SW_VLAN_DBG("Enabling VLAN xlate, unit=%d, hw_port=%d", unit, hw_port);

    // Enable VLAN translations for both ingress and egress.
    rc = opennsl_vlan_control_port_set(unit, hw_port, opennslVlanTranslateIngressEnable, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error enabling translations on ingress for hw_port=%d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return rc;
    }
    rc = opennsl_vlan_control_port_set(unit, hw_port, opennslVlanTranslateIngressMissDrop, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error setting xlate miss-drop on ingress for hw_port=%d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return rc;
    }
    rc = opennsl_vlan_control_port_set(unit, hw_port, opennslVlanTranslateEgressEnable, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error enabling translations on egress for hw_port=%d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return rc;
    }
    rc = opennsl_vlan_control_port_set(unit, hw_port, opennslVlanTranslateEgressMissDrop, 1);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error setting xlate miss-drop on egress for hw_port=%d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return rc;
    }

    // Set up port's double tagging mode.
    rc = opennsl_port_dtag_mode_set(unit, hw_port, OPENNSL_PORT_DTAG_MODE_INTERNAL);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error setting dtag mode internal for hw_port=%d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return rc;
    }

    return rc;

} // enable_vlan_translation

static opennsl_error_t
clear_vlan_translation(int unit, opennsl_port_t hw_port)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    SW_VLAN_DBG("Disabling VLAN xlate, unit=%d, hw_port=%d", unit, hw_port);

    // Disable VLAN translations for both ingress and egress.
    rc = opennsl_vlan_control_port_set(unit, hw_port, opennslVlanTranslateEgressMissDrop, 0);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error clearing xlate miss-drop on egress for hw_port=%d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return rc;
    }
    rc = opennsl_vlan_control_port_set(unit, hw_port, opennslVlanTranslateEgressEnable, 0);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error disabling translations on egress for hw_port=%d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return rc;
    }
    rc = opennsl_vlan_control_port_set(unit, hw_port, opennslVlanTranslateIngressMissDrop, 0);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error clearing xlate miss-drop on ingress for hw_port=%d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return rc;
    }
    rc = opennsl_vlan_control_port_set(unit, hw_port, opennslVlanTranslateIngressEnable, 0);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Error disabling translations on ingress for hw_port=%d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return rc;
    }

    return rc;

} // clear_vlan_translation

static void
native_vlan_set(int unit, int vid, opennsl_pbmp_t bmp, int strictly_untagged)
{
    opennsl_port_t hw_port;
    opennsl_error_t rc = OPENNSL_E_NONE;

    if (SW_VLAN_DBG_ENABLED()) {
        char pfmt[_SHR_PBMP_FMT_LEN];
        SW_VLAN_DBG("NATIVE VLAN SET: vid=%d, pbm=%s, strict=%d",
                    vid, _SHR_PBMP_FMT(bmp, pfmt), strictly_untagged);
    }

    OPENNSL_PBMP_ITER(bmp, hw_port) {
        rc = opennsl_port_untagged_vlan_set(unit, hw_port, vid);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Error setting native vlan on unit=%d "
                     "hw_port=%d vid=%d, rc=%s",
                     unit, hw_port, vid, opennsl_errmsg(rc));
            // Don't exit.  Keep setting the other ports.
        }

        // If strictly untagged option is set, we want to enable VLAN
        // translation & set up miss-drop flags on this port (although
        // we won't need any actual old VID to new VID mapping).  This
        // is to prevent external frames with VID that happened to match
        // the internal VID to be accepted.  In other words, if a port
        // is strictly untagged, only untagged frame will be allowed.
        if (strictly_untagged) {
            rc = enable_vlan_translation(unit, hw_port);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Error enabling vlan xlate for strictly "
                         "untagged, unit=%d, hw_port=%d, vid=%d, rc=%s",
                         unit, hw_port, vid, opennsl_errmsg(rc));
            }
        }
    }

} // native_vlan_set

static void
native_vlan_clear(int unit, opennsl_pbmp_t bmp, int strictly_untagged)
{
    opennsl_port_t hw_port;
    opennsl_vlan_t def_vid;
    opennsl_error_t rc = OPENNSL_E_NONE;

    if (SW_VLAN_DBG_ENABLED()) {
        char pfmt[_SHR_PBMP_FMT_LEN];
        SW_VLAN_DBG("NATIVE VLAN CLEAR: pbm=%s",
                    _SHR_PBMP_FMT(bmp, pfmt));
    }

    // Get the switch's default vid.
    rc = opennsl_vlan_default_get(unit, &def_vid);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_WARN("Error getting default vlan, using %d, rc=%s",
                  OPENNSL_VLAN_DEFAULT, opennsl_errmsg(rc));
        def_vid = OPENNSL_VLAN_DEFAULT;
    }

    OPENNSL_PBMP_ITER(bmp, hw_port) {
        rc = opennsl_port_untagged_vlan_set(unit, hw_port, def_vid);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Error setting native vlan on unit=%d "
                     "hw_port=%d vid=%d, rc=%s",
                     unit, hw_port, def_vid, opennsl_errmsg(rc));
        }

        // Also clear translation settings if this port
        // was strictly untagged.
        if (strictly_untagged) {
            rc = clear_vlan_translation(unit, hw_port);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Error clearing vlan xlate, "
                         "unit=%d, hw_port=%d, rc=%s",
                         unit, hw_port, opennsl_errmsg(rc));
            }
        }
    }

} // native_vlan_clear

static void
hw_create_vlan(int unit, int vid)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    SW_VLAN_DBG("entry: unit=%d, vid=%d", unit, vid);

    rc = opennsl_vlan_create(unit, vid);
    if (OPENNSL_FAILURE(rc) && (rc != OPENNSL_E_EXISTS)) {
        // Ignore duplicated create requests.
        VLOG_ERR("Unit %d VLAN %d create error, rc=%d (%s)",
                 unit, vid, rc, opennsl_errmsg(rc));
    }

    SW_VLAN_DBG("done: rc=%s", opennsl_errmsg(rc));

} // hw_create_vlan

static void
hw_destroy_vlan(int unit, int vid)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    SW_VLAN_DBG("entry: unit=%d, vid=%d", unit, vid);

    rc = opennsl_vlan_destroy(unit, vid);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Unit %d, VLAN %d destroy error, rc=%d (%s)",
                 unit, vid, rc, opennsl_errmsg(rc));
    }

    SW_VLAN_DBG("done: rc=%s", opennsl_errmsg(rc));

} // hw_destroy_vlan

static void
hw_add_ports_to_vlan(int unit, opennsl_pbmp_t all_bmp, opennsl_pbmp_t untagged_bmp,
                     int vid, int strictly_untagged)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    if (SW_VLAN_DBG_ENABLED()) {
        char a_pfmt[_SHR_PBMP_FMT_LEN];
        char u_pfmt[_SHR_PBMP_FMT_LEN];
        SW_VLAN_DBG("entry: unit=%d, vid=%d, all_bmp=%s, untagged_bmp=%s,"
                    " strictly_untagged=%d", unit, vid,
                    _SHR_PBMP_FMT(all_bmp, a_pfmt),
                    _SHR_PBMP_FMT(untagged_bmp, u_pfmt),
                    strictly_untagged);
    }

    // Update default VLAN ID of the ports if untagged.
    if (OPENNSL_PBMP_NOT_NULL(untagged_bmp)) {
        native_vlan_set(unit, vid, untagged_bmp, strictly_untagged);
    }

    // Finally, add ports to VLAN.
    if (OPENNSL_PBMP_NOT_NULL(all_bmp)) {
        rc = opennsl_vlan_port_add(unit, vid, all_bmp, untagged_bmp);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Error adding ports to vlan vid=%d, rc=%s",
                     vid, opennsl_errmsg(rc));
        }
    }

    SW_VLAN_DBG("done");

} // hw_add_ports_to_vlan

static void
hw_del_ports_from_vlan(int unit, opennsl_pbmp_t all_bmp, opennsl_pbmp_t untagged_bmp,
                       int vid, int strictly_untagged)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    if (SW_VLAN_DBG_ENABLED()) {
        char a_pfmt[_SHR_PBMP_FMT_LEN];
        char u_pfmt[_SHR_PBMP_FMT_LEN];
        SW_VLAN_DBG("entry: unit=%d, vid=%d, all_bmp=%s, untagged_bmp=%s,"
                    " strictly_untagged=%d", unit, vid,
                    _SHR_PBMP_FMT(all_bmp, a_pfmt),
                    _SHR_PBMP_FMT(untagged_bmp, u_pfmt),
                    strictly_untagged);
    }

    // Remove ports from VLAN.
    if (OPENNSL_PBMP_NOT_NULL(all_bmp)) {
        rc = opennsl_vlan_port_remove(unit, vid, all_bmp);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Error removing ports from vlan vid=%d, rc=%s",
                     vid, opennsl_errmsg(rc));
        }
    }

    // Update default VLAN ID of the ports if untagged.
    if (OPENNSL_PBMP_NOT_NULL(untagged_bmp)) {
        native_vlan_clear(unit, untagged_bmp, strictly_untagged);
    }

    SW_VLAN_DBG("done");

} // hw_del_ports_from_vlan

////////////////////////////// INTERNAL API ///////////////////////////////

static ops_vlan_data_t *
get_vlan_data(int vid, bool internal)
{
    int unit;
    ops_vlan_data_t *vlanp = NULL;

    if (internal && ops_internal_vlans[vid] != NULL) {
        return ops_internal_vlans[vid];
    }

    if (ops_vlans[vid] != NULL) {
        return ops_vlans[vid];
    }

    // VLAN data hasn't been created yet.
    vlanp = malloc(sizeof(ops_vlan_data_t));
    if (!vlanp) {
        VLOG_ERR("Failed to allocate memory for %s VLAN vid=%d",
                 internal ? "internal" : "", vid);
        return NULL;
    }

    vlanp->vid = vid;
    vlanp->hw_created = 0;

    if (internal) {
        ops_internal_vlans[vid] = vlanp;
        ops_internal_vlan_count++;
    } else {
        ops_vlans[vid] = vlanp;
        ops_vlan_count++;
    }

    // Initialize member port bitmaps
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        OPENNSL_PBMP_CLEAR(vlanp->cfg_access_ports[unit]);
        OPENNSL_PBMP_CLEAR(vlanp->cfg_trunk_ports[unit]);
        OPENNSL_PBMP_CLEAR(vlanp->cfg_native_tag_ports[unit]);
        OPENNSL_PBMP_CLEAR(vlanp->cfg_native_untag_ports[unit]);
        OPENNSL_PBMP_CLEAR(vlanp->hw_access_ports[unit]);
        OPENNSL_PBMP_CLEAR(vlanp->hw_trunk_ports[unit]);
        OPENNSL_PBMP_CLEAR(vlanp->hw_native_tag_ports[unit]);
        OPENNSL_PBMP_CLEAR(vlanp->hw_native_untag_ports[unit]);
    }

    return vlanp;

} // get_vlan_data

static void
free_vlan_data(int vid, bool internal)
{
    int unit;
    int any_member;
    ops_vlan_data_t *vlanp = NULL;

    vlanp = internal ? ops_internal_vlans[vid] : ops_vlans[vid];
    if (!vlanp) {
        VLOG_ERR("Trying to free non-existent %s VLAN data (vid=%d)!",
                 internal ? "internal" : "", vid);
        return;
    }

    if (vlanp->hw_created) {
        // Do not destroy data if VLAN is configured in h/w.
        return;
    }

    any_member = 0;
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID && !any_member; unit++) {
        if (OPENNSL_PBMP_NOT_NULL(vlanp->cfg_access_ports[unit])     ||
            OPENNSL_PBMP_NOT_NULL(vlanp->cfg_trunk_ports[unit])      ||
            OPENNSL_PBMP_NOT_NULL(vlanp->cfg_native_tag_ports[unit]) ||
            OPENNSL_PBMP_NOT_NULL(vlanp->cfg_native_untag_ports[unit])) {
            any_member = 1;
        }
    }

    // Only destroy VLAN data struct if there isn't
    // any configured member port left.
    if (!any_member) {
        free(vlanp);
        if (internal) {
            ops_internal_vlans[vid] = NULL;
            ops_internal_vlan_count--;
        } else {
            ops_vlans[vid] = NULL;
            ops_vlan_count--;
        }
    }

} // free_vlan_data

//////////////////////////////// Public API //////////////////////////////

int
bcmsdk_create_vlan(int vid, bool internal)
{
    int unit;
    ops_vlan_data_t *vlanp;

    SW_VLAN_DBG("%s entry: vid=%d", __FUNCTION__, vid);

    vlanp = get_vlan_data(vid, internal);
    if (!vlanp) {
        VLOG_ERR("Failed to get VLAN data for VID %d", vid);
        return -1;
    }

    if (vlanp->hw_created) {
        VLOG_WARN("Duplicated %s VLAN creation request, VID=%d", internal ? "inetrnal" : "", vid);
    }

    // Create VLAN in h/w & configure any existing member ports.
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        opennsl_pbmp_t bcm_pbm;
        opennsl_pbmp_t linkup_pbm;

        linkup_pbm = ops_get_link_up_pbm(unit);

        hw_create_vlan(unit, vid);
        vlanp->hw_created = 1;

        if (internal) {
            continue;
        }

        bcm_pbm = vlanp->cfg_access_ports[unit];
        OPENNSL_PBMP_AND(bcm_pbm, linkup_pbm);
        if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
            // Add access ports as strictly untagged members of the VLAN.
            hw_add_ports_to_vlan(unit, bcm_pbm, bcm_pbm, vid, 1);
            vlanp->hw_access_ports[unit] = bcm_pbm;
        }

        bcm_pbm = vlanp->cfg_trunk_ports[unit];
        OPENNSL_PBMP_AND(bcm_pbm, linkup_pbm);
        if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
            // Add the ports as tagged members of the VLAN.
            hw_add_ports_to_vlan(unit, bcm_pbm, g_empty_pbm, vid, 0);
            vlanp->hw_trunk_ports[unit] = bcm_pbm;
        }

        bcm_pbm = vlanp->cfg_native_tag_ports[unit];
        OPENNSL_PBMP_AND(bcm_pbm, linkup_pbm);
        if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
            // Add the ports as tagged members of the VLAN.
            hw_add_ports_to_vlan(unit, bcm_pbm, g_empty_pbm, vid, 0);
            vlanp->hw_native_tag_ports[unit] = bcm_pbm;

            // Set native VLAN on the ports.
            native_vlan_set(unit, vid, bcm_pbm, 0);
        }

        bcm_pbm = vlanp->cfg_native_untag_ports[unit];
        OPENNSL_PBMP_AND(bcm_pbm, linkup_pbm);
        if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
            // Add the ports as regular untagged members of the VLAN.
            // (not strictly untagged).
            hw_add_ports_to_vlan(unit, bcm_pbm, bcm_pbm, vid, 0);
            vlanp->hw_native_untag_ports[unit] = bcm_pbm;
        }
    }

    SW_VLAN_DBG("done");
    return 0;

} // bcmsdk_create_vlan

int
bcmsdk_destroy_vlan(int vid, bool internal)
{
    int unit;
    ops_vlan_data_t *vlanp = ops_vlans[vid];

    vlanp = internal ? ops_internal_vlans[vid] : ops_vlans[vid];

    if (vlanp) {
        opennsl_pbmp_t bcm_pbm;

        // Unconfigure all member ports & destroy
        // VLAN in h/w on all switch chip units.
        for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
            bcm_pbm = vlanp->hw_access_ports[unit];
            if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
                hw_del_ports_from_vlan(unit, bcm_pbm, bcm_pbm, vid, 1);
                OPENNSL_PBMP_CLEAR(vlanp->hw_access_ports[unit]);
            }

            bcm_pbm = vlanp->hw_trunk_ports[unit];
            if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
                hw_del_ports_from_vlan(unit, bcm_pbm, g_empty_pbm, vid, 0);
                OPENNSL_PBMP_CLEAR(vlanp->hw_trunk_ports[unit]);
            }

            bcm_pbm = vlanp->hw_native_tag_ports[unit];
            if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
                hw_del_ports_from_vlan(unit, bcm_pbm, g_empty_pbm, vid, 0);
                OPENNSL_PBMP_CLEAR(vlanp->hw_native_tag_ports[unit]);

                // Clear native VLAN on the ports.
                native_vlan_clear(unit, bcm_pbm, 0);
            }

            bcm_pbm = vlanp->hw_native_untag_ports[unit];
            if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
                hw_del_ports_from_vlan(unit, bcm_pbm, bcm_pbm, vid, 0);
                OPENNSL_PBMP_CLEAR(vlanp->hw_native_untag_ports[unit]);
            }

            hw_destroy_vlan(unit, vid);
            vlanp->hw_created = 0;
        }

        free_vlan_data(vid, internal);

    } else {
        VLOG_INFO("Deleting non-existing VLAN, VID=%d", vid);
    }

    SW_VLAN_DBG("done");
    return 0;

} // bcmsdk_destroy_vlan

int
bcmsdk_add_access_ports(int vid, opennsl_pbmp_t *pbm, bool internal)
{
    int unit;
    ops_vlan_data_t *vlanp = NULL;

    // An ACCESS port carries packets on exactly one VLAN specified
    // in the tag column.  Packets egressing on an access port have
    // no 802.1Q header.
    //
    // Any packet with an 802.1Q header with a nonzero VLAN ID
    // that ingresses on an access port is dropped, regardless of
    // whether the VLAN ID in the header is the access port's
    // VLAN ID.

    SW_VLAN_DBG("%s entry: vid=%d", __FUNCTION__, vid);

    vlanp = get_vlan_data(vid, internal);
    if (!vlanp) {
        VLOG_ERR("Failed to allocate & save access ports "
                 "for %s VID %d", internal ? "internal" : "", vid);
        return -1;
    }

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        opennsl_pbmp_t bcm_pbm;

        // Save access port membership info.
        bcm_pbm = pbm[unit];
        OPENNSL_PBMP_OR(vlanp->cfg_access_ports[unit], bcm_pbm);

        // Filter out ports that are not linked up.
        if (!internal) {
            OPENNSL_PBMP_AND(bcm_pbm, ops_get_link_up_pbm(unit));
        }

        // If any port is left, and VLAN is already created
        // in h/w, go ahead and configure it.
        if (vlanp->hw_created && OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
            // Add access ports as strictly untagged members of the VLAN.
            hw_add_ports_to_vlan(unit, bcm_pbm, bcm_pbm, vid, 1);
            OPENNSL_PBMP_OR(vlanp->hw_access_ports[unit], bcm_pbm);
        }
    }

    SW_VLAN_DBG("done");
    return 0;

} // bcmsdk_add_access_ports

int
bcmsdk_del_access_ports(int vid, opennsl_pbmp_t *pbm, bool internal)
{
    SW_VLAN_DBG("%s entry: vid=%d", __FUNCTION__, vid);

    if ((internal && ops_internal_vlans[vid] != NULL) ||
        (!internal && ops_vlans[vid] != NULL)) {
        int unit;
        ops_vlan_data_t *vlanp;

        vlanp = internal ? ops_internal_vlans[vid] : ops_vlans[vid];

        for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
            opennsl_pbmp_t bcm_pbm;

            // Update access port membership info.
            bcm_pbm = pbm[unit];
            OPENNSL_PBMP_REMOVE(vlanp->cfg_access_ports[unit], bcm_pbm);

            // Only need to worry about ports that are actually
            // configured in h/w.
            OPENNSL_PBMP_AND(bcm_pbm, vlanp->hw_access_ports[unit]);
            if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
                hw_del_ports_from_vlan(unit, bcm_pbm, bcm_pbm, vid, 1);
                OPENNSL_PBMP_REMOVE(vlanp->hw_access_ports[unit], bcm_pbm);
            }
        }

        // Free VLAN data if necessary.
        free_vlan_data(vid, internal);

    } else {
        VLOG_WARN("Trying to delete access port on %s VLAN %d, "
                  "but VLAN does not exist.", internal ? "internal" : "", vid);
    }

    SW_VLAN_DBG("done");
    return 0;

} // bcmsdk_del_access_ports

void
bcmsdk_add_trunk_ports(int vid, opennsl_pbmp_t *pbm)
{
    int unit;
    ops_vlan_data_t *vlanp = NULL;

    // A TRUNK port carries packets on one or more specified
    // VLANs specified in the trunks column (often,  on  every
    // VLAN).  A packet that ingresses on a trunk port is in the
    // VLAN specified in its 802.1Q header, or VLAN 0 if the
    // packet has no 802.1Q header.  A packet that egresses
    // through a trunk port will have an 802.1Q header if it has
    // a nonzero VLAN ID.
    //
    // Any packet that ingresses on a trunk port tagged with a
    // VLAN that the port does not trunk is dropped.
    //
    // OpenSwitch NOTE: h/w switches does not support VLAN 0.

    SW_VLAN_DBG("%s entry: vid=%d", __FUNCTION__, vid);

    vlanp = get_vlan_data(vid, false);
    if (!vlanp) {
        VLOG_ERR("Failed to allocate & save trunk ports "
                 "for VID %d", vid);
        return;
    }

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        opennsl_pbmp_t bcm_pbm;

        // Save trunk port membership info.
        bcm_pbm = pbm[unit];
        OPENNSL_PBMP_OR(vlanp->cfg_trunk_ports[unit], bcm_pbm);

        // Filter out ports that are not linked up.
        OPENNSL_PBMP_AND(bcm_pbm, ops_get_link_up_pbm(unit));

        // If any port is left, and VLAN is already created
        // in h/w, go ahead and configure it.
        if (vlanp->hw_created && OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
            // Add the ports as tagged members of the VLAN.
            hw_add_ports_to_vlan(unit, bcm_pbm, g_empty_pbm, vid, 0);
            OPENNSL_PBMP_OR(vlanp->hw_trunk_ports[unit], bcm_pbm);
        }
    }

    SW_VLAN_DBG("done");

} // bcmsdk_add_trunk_ports

void
bcmsdk_del_trunk_ports(int vid, opennsl_pbmp_t *pbm)
{
    SW_VLAN_DBG("%s entry: vid=%d", __FUNCTION__, vid);

    if (ops_vlans[vid] != NULL) {
        int unit;
        ops_vlan_data_t *vlanp = ops_vlans[vid];

        for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
            opennsl_pbmp_t bcm_pbm;

            // Update trunk port membership info.
            bcm_pbm = pbm[unit];
            OPENNSL_PBMP_REMOVE(vlanp->cfg_trunk_ports[unit], bcm_pbm);

            // Only need to worry about ports that are actually
            // configured in h/w.
            OPENNSL_PBMP_AND(bcm_pbm, vlanp->hw_trunk_ports[unit]);
            if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
                hw_del_ports_from_vlan(unit, bcm_pbm, g_empty_pbm, vid, 0);
                OPENNSL_PBMP_REMOVE(vlanp->hw_trunk_ports[unit], bcm_pbm);
            }
        }

        // Free VLAN data if necessary.
        free_vlan_data(vid, false);

    } else {
        VLOG_WARN("Trying to delete trunk port on VLAN %d, "
                  "but VLAN does not exist.", vid);
    }

    SW_VLAN_DBG("done");

} // bcmsdk_del_trunk_ports

void
bcmsdk_add_native_tagged_ports(int vid, opennsl_pbmp_t *pbm)
{
    int unit;
    ops_vlan_data_t *vlanp = NULL;

    // A NATIVE-TAGGED port resembles a trunk port, with the
    // exception that a packet without an 802.1Q header that
    // ingresses on a native-tagged port is in the "native
    // VLAN" (specified in the tag column).

    SW_VLAN_DBG("%s entry: vid=%d", __FUNCTION__, vid);

    vlanp = get_vlan_data(vid, false);
    if (!vlanp) {
        VLOG_ERR("Failed to allocate & save native-tagged "
                 "ports for VID %d", vid);
        return;
    }

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        opennsl_pbmp_t bcm_pbm;

        // Save native tagged port membership info.
        bcm_pbm = pbm[unit];
        OPENNSL_PBMP_OR(vlanp->cfg_native_tag_ports[unit], bcm_pbm);

        // Filter out ports that are not linked up.
        OPENNSL_PBMP_AND(bcm_pbm, ops_get_link_up_pbm(unit));

        // If any port is left, and VLAN is already created
        // in h/w, go ahead and configure it.
        if (vlanp->hw_created && OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
            // Add the ports as tagged members of the VLAN.
            hw_add_ports_to_vlan(unit, bcm_pbm, g_empty_pbm, vid, 0);
            OPENNSL_PBMP_OR(vlanp->hw_native_tag_ports[unit], bcm_pbm);

            // Set native VLAN on the ports.
            native_vlan_set(unit, vid, bcm_pbm, 0);
        }
    }

    SW_VLAN_DBG("done");

} // bcmsdk_add_native_tagged_ports

void
bcmsdk_del_native_tagged_ports(int vid, opennsl_pbmp_t *pbm)
{
    SW_VLAN_DBG("%s entry: vid=%d", __FUNCTION__, vid);

    if (ops_vlans[vid] != NULL) {
        int unit;
        ops_vlan_data_t *vlanp = ops_vlans[vid];

        for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
            opennsl_pbmp_t bcm_pbm;

            // Update native tagged port membership info.
            bcm_pbm = pbm[unit];
            OPENNSL_PBMP_REMOVE(vlanp->cfg_native_tag_ports[unit], bcm_pbm);

            // Only need to worry about ports that are actually
            // configured in h/w.
            OPENNSL_PBMP_AND(bcm_pbm, vlanp->hw_native_tag_ports[unit]);
            if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
                hw_del_ports_from_vlan(unit, bcm_pbm, g_empty_pbm, vid, 0);
                OPENNSL_PBMP_REMOVE(vlanp->hw_native_tag_ports[unit], bcm_pbm);

                // Clear native VLAN on the ports.
                native_vlan_clear(unit, bcm_pbm, 0);
            }
        }

        // Free VLAN data if necessary.
        free_vlan_data(vid, false);

    } else {
        VLOG_WARN("Trying to delete native tagged port on VLAN %d, "
                  "but VLAN does not exist.", vid);
    }

    SW_VLAN_DBG("done");

} // bcmsdk_del_native_tagged_ports

void
bcmsdk_add_native_untagged_ports(int vid, opennsl_pbmp_t *pbm)
{
    int unit;
    ops_vlan_data_t *vlanp = NULL;

    // A NATIVE-UNTAGGED port resembles a native-tagged port,
    // with the exception that a packet that egresses on a
    // native-untagged port in the native VLAN will not have
    // an 802.1Q header.

    SW_VLAN_DBG("%s entry: vid=%d", __FUNCTION__, vid);

    vlanp = get_vlan_data(vid, false);
    if (!vlanp) {
        VLOG_ERR("Failed to allocate & save native-untagged "
                 "ports for VID %d", vid);
        return;
    }

    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        opennsl_pbmp_t bcm_pbm;

        // Save native untagged port membership info.
        bcm_pbm = pbm[unit];
        OPENNSL_PBMP_OR(vlanp->cfg_native_untag_ports[unit], bcm_pbm);

        // Filter out ports that are not linked up.
        OPENNSL_PBMP_AND(bcm_pbm, ops_get_link_up_pbm(unit));

        // If any port is left, and VLAN is already created
        // in h/w, go ahead and configure it.
        if (vlanp->hw_created && OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
            // Add the ports as regular untagged members of the VLAN.
            // (not strictly untagged).
            hw_add_ports_to_vlan(unit, bcm_pbm, bcm_pbm, vid, 0);
            OPENNSL_PBMP_OR(vlanp->hw_native_untag_ports[unit], bcm_pbm);
        }
    }

    SW_VLAN_DBG("done");

} // bcmsdk_add_native_untagged_ports

void
bcmsdk_del_native_untagged_ports(int vid, opennsl_pbmp_t *pbm)
{
    SW_VLAN_DBG("%s entry: vid=%d", __FUNCTION__, vid);

    if (ops_vlans[vid] != NULL) {
        int unit;
        ops_vlan_data_t *vlanp = ops_vlans[vid];

        for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
            opennsl_pbmp_t bcm_pbm;

            // Update native untagged port membership info.
            bcm_pbm = pbm[unit];
            OPENNSL_PBMP_REMOVE(vlanp->cfg_native_untag_ports[unit], bcm_pbm);

            // Only need to worry about ports that are actually
            // configured in h/w.
            OPENNSL_PBMP_AND(bcm_pbm, vlanp->hw_native_untag_ports[unit]);
            if (OPENNSL_PBMP_NOT_NULL(bcm_pbm)) {
                hw_del_ports_from_vlan(unit, bcm_pbm, bcm_pbm, vid, 0);
                OPENNSL_PBMP_REMOVE(vlanp->hw_native_untag_ports[unit], bcm_pbm);
            }
        }

        // Free VLAN data if necessary.
        free_vlan_data(vid, false);

    } else {
        VLOG_WARN("Trying to delete native untagged port on VLAN %d, "
                  "but VLAN does not exist.", vid);
    }

    SW_VLAN_DBG("done");

} // bcmsdk_del_native_untagged_ports

void
vlan_reconfig_on_link_change(int unit, opennsl_port_t hw_port, int link_is_up)
{
    int vid, count;
    opennsl_pbmp_t pbm;
    ops_vlan_data_t *vlanp;

    OPENNSL_PBMP_CLEAR(pbm);
    OPENNSL_PBMP_PORT_ADD(pbm, hw_port);

    for (vid=0, count=0; vid<OPS_VLAN_COUNT && count<ops_vlan_count; vid++) {
        if (ops_vlans[vid] != NULL) {
            count++;
            vlanp = ops_vlans[vid];
            if (vlanp->hw_created) {
                if (link_is_up) {
                    // Link has come up.
                    if (OPENNSL_PBMP_MEMBER(vlanp->cfg_access_ports[unit], hw_port)) {
                        hw_add_ports_to_vlan(unit, pbm, pbm, vid, 1);
                        OPENNSL_PBMP_OR(vlanp->hw_access_ports[unit], pbm);

                    } else if (OPENNSL_PBMP_MEMBER(vlanp->cfg_trunk_ports[unit], hw_port)) {
                        hw_add_ports_to_vlan(unit, pbm, g_empty_pbm, vid, 0);
                        OPENNSL_PBMP_OR(vlanp->hw_trunk_ports[unit], pbm);

                    } else if (OPENNSL_PBMP_MEMBER(vlanp->cfg_native_tag_ports[unit], hw_port)) {
                        hw_add_ports_to_vlan(unit, pbm, g_empty_pbm, vid, 0);
                        OPENNSL_PBMP_OR(vlanp->hw_native_tag_ports[unit], pbm);
                        native_vlan_set(unit, vid, pbm, 0);

                    } else if (OPENNSL_PBMP_MEMBER(vlanp->cfg_native_untag_ports[unit], hw_port)) {
                        hw_add_ports_to_vlan(unit, pbm, pbm, vid, 0);
                        OPENNSL_PBMP_OR(vlanp->hw_native_untag_ports[unit], pbm);
                    }
                } else {
                    // Link has gone down.
                    if (OPENNSL_PBMP_MEMBER(vlanp->hw_access_ports[unit], hw_port)) {
                        hw_del_ports_from_vlan(unit, pbm, pbm, vid, 1);
                        OPENNSL_PBMP_PORT_REMOVE(vlanp->hw_access_ports[unit], hw_port);

                    } else if (OPENNSL_PBMP_MEMBER(vlanp->hw_trunk_ports[unit], hw_port)) {
                        hw_del_ports_from_vlan(unit, pbm, g_empty_pbm, vid, 0);
                        OPENNSL_PBMP_PORT_REMOVE(vlanp->hw_trunk_ports[unit], hw_port);

                    } else if (OPENNSL_PBMP_MEMBER(vlanp->hw_native_tag_ports[unit], hw_port)) {
                        hw_del_ports_from_vlan(unit, pbm, g_empty_pbm, vid, 0);
                        OPENNSL_PBMP_PORT_REMOVE(vlanp->hw_native_tag_ports[unit], hw_port);
                        native_vlan_clear(unit, pbm, 0);

                    } else if (OPENNSL_PBMP_MEMBER(vlanp->hw_native_untag_ports[unit], hw_port)) {
                        hw_del_ports_from_vlan(unit, pbm, pbm, vid, 0);
                        OPENNSL_PBMP_PORT_REMOVE(vlanp->hw_native_untag_ports[unit], hw_port);
                    }
                }
            }
        }
    }

} // vlan_reconfig_on_link_change


///////////////////////////////// INIT /////////////////////////////////

int
ops_vlan_init(int hw_unit)
{
    OPENNSL_PBMP_CLEAR(g_empty_pbm);
    return 0;

} // ops_vlan_init
