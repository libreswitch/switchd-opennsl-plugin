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
 * File: ops-port.c
 *
 * Purpose: This file contains OpenSwitch application code in the Broadcom SDK.
 */

#include <stdlib.h>
#include <string.h>

#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/link.h>
#include <opennsl/port.h>

#include "platform-defines.h"
#include "ops-debug.h"
#include "ops-knet.h"
#include "ops-vlan.h"
#include "ops-port.h"

VLOG_DEFINE_THIS_MODULE(ops_port);

#define JUMBO_SZ        0x2400
#define JUMBO_10G_SZ    0x3fe4

/* netdev_bcmsdk_link_state_callback is defined in
 * ovs/lib/netdev-bcmsdk.c.
 * This function is callback to inform vswitchd that
 * status of a port is changed. */
extern void netdev_bcmsdk_link_state_callback(int unit, int hw_id, int link_status);


/* This struct should only be written by the Broadcom linkscan thread. */
opennsl_pbmp_t linked_up_ports[MAX_SWITCH_UNITS];

struct ops_port_info *port_info[MAX_SWITCH_UNITS];

/////////////////////////////////////////////////////////////////////////////
//                    Link State Notification Handler                      //
//                                                                         //
//  NOTE: This is called back from Broadcom linkscan thread.               //
/////////////////////////////////////////////////////////////////////////////
void
ops_link_state_callback(int unit, opennsl_port_t hw_port, opennsl_port_info_t *info)
{
    int link_status = 0;

    // Save physical port link status for use later.
    // Also update VLAN membership configuration.
    if (OPENNSL_PORT_LINK_STATUS_UP == info->linkstatus) {

        link_status = 1;
        OPENNSL_PBMP_PORT_ADD(linked_up_ports[unit], hw_port);

        // OPS_TODO: need MUTEX since this is a different thread?
        vlan_reconfig_on_link_change(unit, hw_port, 1);

    } else {
        // OPS_TODO: Flush MACs on link down.
        //flush_learned_macs(unit, hw_port);

        OPENNSL_PBMP_PORT_REMOVE(linked_up_ports[unit], hw_port);

        // OPS_TODO: need MUTEX since this is a different thread?
        vlan_reconfig_on_link_change(unit, hw_port, 0);
    }

    netdev_bcmsdk_link_state_callback(unit, (int)hw_port, link_status);

} // ops_link_state_callback

opennsl_pbmp_t
ops_get_link_up_pbm(int unit)
{
    if (unit >= 0 && unit < MAX_SWITCH_UNITS) {
        return linked_up_ports[unit];

    } else {
        opennsl_pbmp_t empty_pbm;
        OPENNSL_PBMP_CLEAR(empty_pbm);
        return empty_pbm;
    }
} // ops_get_link_up_pbm

/////////////////////// PHYSICAL INTERFACE CONFIG ///////////////////////////


static opennsl_error_t
split_port_linkscan_update(int hw_unit, int hw_port, int lane_count, int active)
{
    int i = 0, rc = 0;
    int ls_mode;

    ls_mode = active ? OPENNSL_LINKSCAN_MODE_SW : OPENNSL_LINKSCAN_MODE_NONE;

    // Linkscan thread update.
    for (i = 1; i < lane_count; i++) {
        rc = opennsl_linkscan_mode_set(hw_unit, (hw_port + i), ls_mode);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to update linkscan for hw port=%d, active=%d, rc=%s",
                     (hw_port + i), active, opennsl_errmsg(rc));
            return rc;
        }
    }

    return OPENNSL_E_NONE;

} // split_port_linkscan_update

int
split_port_lane_config(struct ops_port_info *p_info, bool is_split_needed)
{
    int                 i = 0;
    opennsl_error_t     rc = OPENNSL_E_NONE;

    // This function is only called if we're enabling a splittable port.
    // We won't bother with splits if all primary & subports are disabled.
    SW_PORT_DBG("Port split -- port=%d split_state=%d", p_info->hw_port, is_split_needed);

    if (is_split_needed == p_info->lanes_split_status) {
        // We're already in the correct lane split state.
        SW_PORT_DBG("Port is already in the correct split status."
                    "hw_port=%d, Current State=%d",
                    p_info->hw_port, is_split_needed);
        return 0;
    }

    // We need to split the port and it is not currently split.
    // Disable primary port in the group first,
    // then change number of lanes to 1.
    if (is_split_needed == TRUE) {

        rc = opennsl_port_enable_set(p_info->hw_unit, p_info->hw_port, FALSE);
        if (OPENNSL_FAILURE(rc)){
            VLOG_ERR("Failed to disable primary port. unit=%d, port=%d  rc=%s",
                     p_info->hw_unit, p_info->hw_port, opennsl_errmsg(rc));
            // Don't exit here.  Keep trying to update the configuration anyway.
        }

        // Change # of lanes first to make the previously inactive
        // split subports active again.
        rc = opennsl_port_control_set(p_info->hw_unit, p_info->hw_port,
                                      opennslPortControlLanes, 1);
        if (OPENNSL_FAILURE(rc)){
            VLOG_ERR("Failed to change # of lanes to 1 on unit=%d, port=%d rc=%s",
                     p_info->hw_unit, p_info->hw_port, opennsl_errmsg(rc));
            // No point in continuing if this fails.
            return -1;
        }

        // Enable linkscan & counters for the previously inactive ports.
        split_port_linkscan_update(p_info->hw_unit, p_info->hw_port,
                                   p_info->split_port_count, TRUE);

    // We need to unsplit the port and it is currently split.
    // Disable all ports in the group first, including the
    // primary, then change number of lanes to 4.
    } else {
        for (i = 0; i < p_info->split_port_count; i++) {
            rc = opennsl_port_enable_set(p_info->hw_unit, (p_info->hw_port + i), FALSE);
            if (OPENNSL_FAILURE(rc)){
                VLOG_ERR("Failed to disable port=%d, rc=%s",
                         (p_info->hw_port + i), opennsl_errmsg(rc));
                // Don't exit here.  Keep trying to
                // update the configuration anyway.
            }
        }

        // Disable linkscan & counters for the previously inactive ports.
        // This needs to be done before changing number of lanes since
        // these ports would be inaccessible after that.
        split_port_linkscan_update(p_info->hw_unit, p_info->hw_port,
                                   p_info->split_port_count, FALSE);

        // Change # of lanes.
        rc = opennsl_port_control_set(p_info->hw_unit, p_info->hw_port,
                                      opennslPortControlLanes,
                                      p_info->split_port_count);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to change # of lanes to %d on port=%d rc=%s",
                     p_info->split_port_count, p_info->hw_port, opennsl_errmsg(rc));
            // No point in continuing if this fails.
            return -1;
        }
    }

    p_info->lanes_split_status = is_split_needed;

    return 0;

} // split_port_lane_config

int
bcmsdk_set_port_config(int hw_unit, opennsl_port_t hw_port, const struct port_cfg *pcfg)
{
    opennsl_error_t     rc = OPENNSL_E_NONE;
    opennsl_port_info_t bcm_pinfo;
    struct ops_port_info *p_info;

    p_info = PORT_INFO(hw_unit, hw_port);
    if (p_info == NULL) {
        VLOG_ERR("Invalid port_info struct. unit=%d port=%d.",
                 hw_unit, hw_port);
        return 1;
    }

    opennsl_port_info_t_init(&bcm_pinfo);

    // Whether we are enabling or disabling, we need to
    // set the operational state (ENABLE) flag.
    bcm_pinfo.action_mask |= OPENNSL_PORT_ATTR_ENABLE_MASK;

    if (pcfg->enable) {

        SW_PORT_DBG("Enabling hw_port=%d, autoneg=%d, duplex=%d",
                    hw_port, pcfg->autoneg, pcfg->duplex);

        bcm_pinfo.enable = 1;

        // Set the max frame size if requested by the user.
        if (pcfg->max_frame_sz) {
            if (pcfg->cfg_speed >= 10000) {
                if ((pcfg->max_frame_sz > 0) && (pcfg->max_frame_sz <= JUMBO_10G_SZ)) {
                    bcm_pinfo.frame_max    = pcfg->max_frame_sz;
                    bcm_pinfo.action_mask |= OPENNSL_PORT_ATTR_FRAME_MAX_MASK;
                }
            } else {
                if ((pcfg->max_frame_sz > 0) && (pcfg->max_frame_sz <= JUMBO_SZ)) {
                    bcm_pinfo.frame_max    = pcfg->max_frame_sz;
                    bcm_pinfo.action_mask |= OPENNSL_PORT_ATTR_FRAME_MAX_MASK;
                }
            }
        }

        // We are enabling the port, so need to configure speed,
        // duplex, pause, and autoneg as requested.
        // NOTE: half-duplex is not supported.
        if (pcfg->autoneg) {
            opennsl_port_ability_t port_ability;
            opennsl_port_ability_t advert_ability;

            opennsl_port_ability_t_init(&port_ability);
            opennsl_port_ability_t_init(&advert_ability);

            /* OPS_TODO: We only support advertising one speed or
             * all possible speeds at the moment. */
            if (0 == pcfg->cfg_speed) {
                // Full autonegotiation desired.  Get all possible speed/duplex
                // values for this port from h/w, then filter out HD support.
                rc = opennsl_port_ability_local_get(hw_unit, hw_port,
                                                    &port_ability);
                if (OPENNSL_SUCCESS(rc)) {
                    // Mask out half-duplex support.
                    port_ability.speed_half_duplex = 0;
                } else {
                    VLOG_ERR("Failed to get port %d ability", hw_port);
                    // Assume typical 10G port setting.
                    // Can't be worse than just exiting...
                    port_ability.speed_full_duplex = OPENNSL_PORT_ABILITY_10GB;
                }

            } else if (1000 == pcfg->cfg_speed) {
                port_ability.speed_full_duplex = OPENNSL_PORT_ABILITY_1000MB;

            } else if (10000 == pcfg->cfg_speed) {
                port_ability.speed_full_duplex = OPENNSL_PORT_ABILITY_10GB;

            } else if (20000 == pcfg->cfg_speed) {
                port_ability.speed_full_duplex = OPENNSL_PORT_ABILITY_20GB;

            } else if (40000 == pcfg->cfg_speed) {
                port_ability.speed_full_duplex = OPENNSL_PORT_ABILITY_40GB;

            } else {
                // Unsupported speed.
                VLOG_ERR("Failed to configure unavailable speed %d",
                         pcfg->cfg_speed);
                return 1;
            }

            rc = opennsl_port_ability_advert_get(hw_unit, hw_port, &advert_ability);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to get port %d local advert", hw_port);
                // Assume typical advertised ability.
                advert_ability.pause = OPENNSL_PORT_ABILITY_PAUSE;
            }

            // Only change speed/duplex part of advertisement.
            advert_ability.speed_full_duplex = port_ability.speed_full_duplex;
            advert_ability.speed_half_duplex = port_ability.speed_half_duplex;

            // Update flow control (pause) advertisement.
            if (pcfg->pause_rx) {
                advert_ability.pause |= OPENNSL_PORT_ABILITY_PAUSE_RX;
            } else {
                advert_ability.pause &= ~OPENNSL_PORT_ABILITY_PAUSE_RX;
            }

            if (pcfg->pause_tx) {
                advert_ability.pause |= OPENNSL_PORT_ABILITY_PAUSE_TX;
            } else {
                advert_ability.pause &= ~OPENNSL_PORT_ABILITY_PAUSE_TX;
            }

            bcm_pinfo.local_ability = advert_ability;
            bcm_pinfo.autoneg       = TRUE;
            bcm_pinfo.action_mask  |= (OPENNSL_PORT_ATTR_LOCAL_ADVERT_MASK |
                                       OPENNSL_PORT_ATTR_AUTONEG_MASK );
            bcm_pinfo.action_mask2 |= OPENNSL_PORT_ATTR2_PORT_ABILITY;

        } else {
            // Autoneg is not requested.
            bcm_pinfo.speed        = pcfg->cfg_speed;
            bcm_pinfo.duplex       = pcfg->duplex;
            bcm_pinfo.pause_rx     = pcfg->pause_rx;
            bcm_pinfo.pause_tx     = pcfg->pause_tx;

            bcm_pinfo.action_mask |= ( OPENNSL_PORT_ATTR_SPEED_MASK    |
                                       OPENNSL_PORT_ATTR_DUPLEX_MASK   |
                                       OPENNSL_PORT_ATTR_PAUSE_RX_MASK |
                                       OPENNSL_PORT_ATTR_PAUSE_TX_MASK );
        }

        // Configure interface type if it is a supported interface.
        if (OPENNSL_PORT_IF_NULL != pcfg->intf_type) {
            rc = opennsl_port_interface_set(hw_unit, hw_port, pcfg->intf_type);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to set interface type "
                         "for port %d, bcm_intf=%d, rc=%s",
                         hw_port, pcfg->intf_type, opennsl_errmsg(rc));
            }
        }

    // if (pcfg->enable == FALSE)
    } else {
        SW_PORT_DBG("Disabling hw_port=%d", hw_port);
        bcm_pinfo.enable = 0;
    }

    // Program h/w with the given values.
    rc = opennsl_port_selective_set(hw_unit, hw_port, &bcm_pinfo);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to program h/w for unit %d, port %d, rc=%s",
                 hw_unit, hw_port, opennsl_errmsg(rc));
        return 1;
    }

    return 0;

} // bcmsdk_set_port_config

int
bcmsdk_set_enable_state(int hw_unit, opennsl_port_t hw_port, int enable)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    rc = opennsl_port_enable_set(hw_unit, hw_port, enable);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set port enable state for %d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
    }

    return rc;

} // bcmsdk_set_enable_state

int
bcmsdk_get_enable_state(int hw_unit, opennsl_port_t hw_port, int *enable)
{
    opennsl_error_t rc = OPENNSL_E_NONE;

    rc = opennsl_port_enable_get(hw_unit, hw_port, enable);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get port enable state for %d, rc=%s",
                 hw_port, opennsl_errmsg(rc));
        return 1;
    }

    return 0;

} // bcmsdk_get_enable_state

int
bcmsdk_get_link_status(int hw_unit, opennsl_port_t hw_port, int *linkup)
{
    if (OPENNSL_PBMP_MEMBER(linked_up_ports[hw_unit], hw_port)) {
            *linkup = 1;
    } else {
            *linkup = 0;
    }

    return 0;

} // bcmsdk_get_link_status

int
bcmsdk_get_port_config(int hw_unit, opennsl_port_t hw_port, struct port_cfg *pcfg)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_port_info_t port_info;

    opennsl_port_info_t_init(&port_info);
    port_info.action_mask = OPENNSL_PORT_ATTR_ALL_MASK;
    rc = opennsl_port_selective_get(hw_unit, hw_port, &port_info);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to get port info for unit %d port %d, rc=%s",
                 hw_unit, hw_port, opennsl_errmsg(rc));
        return 1;
    }

    pcfg->enable        = port_info.enable;
    pcfg->autoneg       = port_info.autoneg;
    pcfg->duplex        = port_info.duplex;
    pcfg->max_frame_sz  = port_info.frame_max;
    pcfg->pause_rx      = port_info.pause_rx;
    pcfg->pause_tx      = port_info.pause_tx;

    pcfg->link_status   = port_info.linkstatus;
    if (pcfg->link_status) {
        pcfg->link_speed    = port_info.speed;
    } else {
        pcfg->link_speed    = 0;
    }

    return 0;

} // bcmsdk_get_port_config

/////////////////////////////// INITIALIZATION ///////////////////////////////////

int
ops_port_init(int hw_unit)
{
    opennsl_port_t hw_port;
    opennsl_port_config_t pcfg;
    opennsl_error_t rc = OPENNSL_E_NONE;

    // Allocate memory for MAX_PORTS(hw_unit) number of ports
    port_info[hw_unit] = calloc(MAX_PORTS(hw_unit), sizeof(struct ops_port_info));
    if (port_info[hw_unit] == NULL) {
        VLOG_ERR("Unable to allocate memory for port info struct."
                 "unit=%d max_ports=%d", hw_unit, MAX_PORTS(hw_unit));
        return 1;
    }

    // Update CPU port's L2 learning behavior to forward frames with
    // unknown src MACs.  This is the way it's always been, but the
    // default changed somehow when we upgraded from SDK-5.6.2 to
    // 5.9.0.  See Broadcom support case #382115.
    rc = opennsl_port_control_set(hw_unit,
                                  CPU_PORT(hw_unit),
                                  opennslPortControlL2Move,
                                  OPENNSL_PORT_LEARN_FWD);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("CPU L2 setting failed! err=%d (%s)",
                 rc, opennsl_errmsg(rc));
        return 1;
    }

    // Initialize bitmap of linked up ports.
    OPENNSL_PBMP_CLEAR(linked_up_ports[hw_unit]);

    // Register for link state change notifications.
    // Note that all ports come up by default in a disabled
    // state.  So until intfd is ready to enable the ports,
    // we should not get any callbacks.
    rc = opennsl_linkscan_register(hw_unit, ops_link_state_callback);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Linkscan registration error, err=%d (%s)",
                 rc, opennsl_errmsg(rc));
        return 1;
    }

    // Enable both ingress and egress VLAN filtering mode
    // for all Ethernet interfaces defined in the system.
    if (OPENNSL_SUCCESS(opennsl_port_config_get(hw_unit, &pcfg))) {
        OPENNSL_PBMP_ITER(pcfg.e, hw_port) {
            rc = opennsl_port_vlan_member_set(hw_unit, hw_port,
                                              (OPENNSL_PORT_VLAN_MEMBER_INGRESS |
                                               OPENNSL_PORT_VLAN_MEMBER_EGRESS));
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to set unit %d hw_port %d VLAN filter "
                         "mode, err=%d (%s)",
                         hw_unit, hw_port, rc, opennsl_errmsg(rc));
            }
        }
    } else {
        VLOG_ERR("Failed to get switch port configuration");
        return 1;
    }

    return 0;

} // ops_port_init
