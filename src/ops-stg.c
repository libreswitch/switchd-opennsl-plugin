/*
 * Copyright (C) 2015-2016 Hewlett-Packard Development Company, L.P.
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
 * File: ops-stg.c
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/port.h>
#include <opennsl/vlan.h>
#include <opennsl/stg.h>
#include <opennsl/l2.h>
#include <ofproto/ofproto.h>
#include "netdev-bcmsdk.h"
#include "ops-debug.h"
#include "ops-port.h"
#include "ops-vlan.h"
#include "ops-stg.h"

VLOG_DEFINE_THIS_MODULE(ops_stg);

unsigned int stp_enabled = 0;
unsigned int ops_stg_count = 0;
ops_stg_data_t *ops_stg[OPS_STG_COUNT+2] = { NULL };

////////////////////////////////// DEBUG ///////////////////////////////////
/*-----------------------------------------------------------------------------
| Function: show_stg_vlan_data
| Description:  displays ops_stg_data object  vlan details
| Parameters[in]: ops_stg_data_t object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/

static void
show_stg_vlan_data(struct ds *ds, ops_stg_data_t *pstg)
{
    ops_stg_vlan_t *p_stg_vlan = NULL, *p_next_stg_vlan = NULL;

    if (!ds || !pstg) {
       /* invalid param */
       VLOG_ERR("%s: invalid param", __FUNCTION__);
       return;
    }

    ds_put_format(ds, "Vlan Count %d:\n", pstg->n_vlans);
    ds_put_format(ds, "Vlan  id's: ");
    HMAP_FOR_EACH_SAFE (p_stg_vlan, p_next_stg_vlan, node, &pstg->vlans) {
        ds_put_format(ds, " %d", p_stg_vlan->vlan_id);
    }
    ds_put_format(ds, "\n");

}


////////////////////////////////// DEBUG ///////////////////////////////////
/*-----------------------------------------------------------------------------
| Function: show_stg_data
| Description:  displays ops_stg_data object details
| Parameters[in]: ops_stg_data_t object
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/

static void
show_stg_data(struct ds *ds, ops_stg_data_t *pstg)
{
    int unit;
    char pfmt[_SHR_PBMP_FMT_LEN];

    if (!ds || !pstg) {
        /* invalid param */
        VLOG_ERR("%s: invalid param", __FUNCTION__);
        return;
    }

    ds_put_format(ds, "STG %d:\n", pstg->stg_id);
    show_stg_vlan_data(ds, pstg);
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        ds_put_format(ds, "  disabled ports=%s\n",
                      _SHR_PBMP_FMT(pstg->disabled_ports[unit], pfmt));
        ds_put_format(ds, "  blocked ports=%s\n",
                      _SHR_PBMP_FMT(pstg->blocked_ports[unit], pfmt));
        ds_put_format(ds, "  learning ports=%s\n",
                      _SHR_PBMP_FMT(pstg->learning_ports[unit], pfmt));
        ds_put_format(ds, "  forwarding ports=%s\n",
                      _SHR_PBMP_FMT(pstg->forwarding_ports[unit], pfmt));
        ds_put_format(ds, "\n");
    }
    ds_put_format(ds, "\n");

}

/*-----------------------------------------------------------------------------
| Function: ops_stg_dump
| Description:  dumps all stg groups data
| Parameters[in]: stgid: spanning tree group id
|.Parameters[out]:  dynamic string object
| Return: None
-----------------------------------------------------------------------------*/

void
ops_stg_dump(struct ds *ds, int stgid)
{
    if (OPS_STG_VALID(stgid)) {
        if (ops_stg[stgid] != NULL) {
            show_stg_data(ds, ops_stg[stgid]);
        } else {
            ds_put_format(ds, "STG %d does not exist.\n", stgid);
        }
    } else {
        int stgid, count;
        ds_put_format(ds, "Dumping all STGs (count=%d)...\n", ops_stg_count);
        for (stgid=0, count=0; stgid<=OPS_STG_COUNT; stgid++) {
            if (ops_stg[stgid] != NULL) {
                count++;
                show_stg_data(ds, ops_stg[stgid]);
            }
        }
    }
}

/*-----------------------------------------------------------------------------
| Function: ops_stg_hw_dump
| Description:  dumps all stg groups data from hw
| Parameters[in]: stgid: spanning tree group id
|.Parameters[out]:  dynamic string object
| Return: None
-----------------------------------------------------------------------------*/

void
ops_stg_hw_dump(struct ds *ds, int stgid)
{
    int unit = 0;
    char pfmt[_SHR_PBMP_FMT_LEN];
    opennsl_vlan_t *vlan_list = NULL;
    int stg_vlan_count = 0;
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_pbmp_t disabled_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t blocked_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t learning_ports[MAX_SWITCH_UNITS];
    opennsl_pbmp_t forwarding_ports[MAX_SWITCH_UNITS];
    opennsl_port_t portid;

    int port_state = -1;


    if (!ds) {
        /* invalid param */
        VLOG_ERR("%s: invalid param", __FUNCTION__);
        return;
    }

    /* check range of hw stg id */
    if ((stgid < 1) || (stgid > 511)) {
        ds_put_format(ds, "Invalid hw stg id %d", stgid);
        return;
    }

    ds_put_format(ds, "STG %d:\n", stgid);
    rc = opennsl_stg_vlan_list(unit, stgid, &vlan_list, &stg_vlan_count);
    if (OPENNSL_FAILURE(rc)) {
        ds_put_format(ds, "Unit %d, stg get vlan error, rc=%d (%s)\n",
                 unit, rc, opennsl_errmsg(rc));
        return ;
    }

    ds_put_format(ds, "Vlan count %d:\n", stg_vlan_count);
    if (stg_vlan_count) {
        ds_put_format(ds, "Vlan  id's: ");
        for(int i =0; i<stg_vlan_count ; i++) {
            ds_put_format(ds, " %d", vlan_list[i]);
        }
        rc = OPENNSL_E_NONE;
        rc = opennsl_stg_vlan_list_destroy(unit, vlan_list, stg_vlan_count);
        if (OPENNSL_FAILURE(rc)) {
            ds_put_format(ds, "Unit %d, stg destroy vlan list error, rc=%d (%s)\n",
                     unit, rc, opennsl_errmsg(rc));
            return ;
        }
        ds_put_format(ds, "\n");
    }
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {

        OPENNSL_PBMP_CLEAR(disabled_ports[unit]);
        OPENNSL_PBMP_CLEAR(blocked_ports[unit]);
        OPENNSL_PBMP_CLEAR(learning_ports[unit]);
        OPENNSL_PBMP_CLEAR(forwarding_ports[unit]);

        for (portid =0; portid <=105; portid++) {
            port_state = -1;
            opennsl_stg_stp_get(unit, stgid, portid, &port_state);
            switch (port_state) {
                case OPS_STG_PORT_STATE_BLOCKED:
                    OPENNSL_PBMP_PORT_ADD(blocked_ports[unit],
                                          portid);
                    break;
                case OPS_STG_PORT_STATE_DISABLED:
                    OPENNSL_PBMP_PORT_ADD(disabled_ports[unit],
                                          portid);
                    break;
                case OPS_STG_PORT_STATE_LEARNING:
                    OPENNSL_PBMP_PORT_ADD(learning_ports[unit],
                                          portid);
                    break;
                case OPS_STG_PORT_STATE_FORWARDING:
                    OPENNSL_PBMP_PORT_ADD(forwarding_ports[unit],
                                          portid);
                    break;
                default:
                    break;
            }
        }

        ds_put_format(ds, "  disabled ports=%s\n",
                      _SHR_PBMP_FMT(disabled_ports[unit], pfmt));
        ds_put_format(ds, "  blocked ports=%s\n",
                      _SHR_PBMP_FMT(blocked_ports[unit], pfmt));
        ds_put_format(ds, "  learning ports=%s\n",
                      _SHR_PBMP_FMT(learning_ports[unit], pfmt));
        ds_put_format(ds, "  forwarding ports=%s\n",
                      _SHR_PBMP_FMT(forwarding_ports[unit], pfmt));
        ds_put_format(ds, "\n");
    }

    ds_put_format(ds, "\n");

}

/*-----------------------------------------------------------------------------
| Function: stg_data_find_create
| Description: lookup stg data for given stgid, if not found create stg data for given stgid
| Parameters[in]: stgid: spanning tree group id
| Parameters[in]:bool : true to create stg data, else do only lookup
| Parameters[out]:
| Return: ops_stg_data object
-----------------------------------------------------------------------------*/
static ops_stg_data_t *
stg_data_find_create(int stgid, bool create)
{
    int unit;
    ops_stg_data_t *p_stg_data = NULL;

    if (ops_stg[stgid] != NULL) {
        return ops_stg[stgid];
    }

    if (false == create) {
        return NULL;
    }

    // STG Entry data hasn't been created yet.
    p_stg_data = xzalloc(sizeof(ops_stg_data_t));
    if (!p_stg_data) {
        VLOG_ERR("Failed to allocate memory for STG id =%d",
                 stgid);
        return NULL;
    }

    p_stg_data->stg_id = stgid;

    ops_stg[stgid] = p_stg_data;
    ops_stg_count++;

    p_stg_data->n_vlans = 0;
    /* initialize stg entry vlan hash map */
    hmap_init(&p_stg_data->vlans);

    // Initialize member port bitmaps
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        OPENNSL_PBMP_CLEAR(p_stg_data->disabled_ports[unit]);
        OPENNSL_PBMP_CLEAR(p_stg_data->blocked_ports[unit]);
        OPENNSL_PBMP_CLEAR(p_stg_data->learning_ports[unit]);
        OPENNSL_PBMP_CLEAR(p_stg_data->forwarding_ports[unit]);
    }

    return p_stg_data;

} // stg_data_get

/*-----------------------------------------------------------------------------
| Function: stg_data_free
| Description: free stg group data
| Parameters[in]: stgid: spanning tree group id
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
static void
stg_data_free(int stgid)
{
    ops_stg_data_t *p_stg_data = NULL;
    ops_stg_vlan_t *p_stg_vlan, *p_next_stg_vlan;

    p_stg_data = ops_stg[stgid];
    if (!p_stg_data) {
        VLOG_ERR("Trying to free non-existent STG data (stgid=%d)!",
                 stgid);
        return;
    }

    HMAP_FOR_EACH_SAFE(p_stg_vlan, p_next_stg_vlan, node, &p_stg_data->vlans) {
        hmap_remove(&p_stg_data->vlans, &p_stg_vlan->node);
        free(p_stg_vlan);
        p_stg_data->n_vlans--;
    }

    free(p_stg_data);

    ops_stg[stgid] = NULL;
    ops_stg_count--;


}

/*-----------------------------------------------------------------------------
| Function: stg_data_add_vlan
| Description: add vlan to stg data
| Parameters[in]:  stgid: spanning tree group id
| Parameters[out]: vlanid:
| Return: None
-----------------------------------------------------------------------------*/
static void
stg_data_add_vlan(int stgid, int vlanid)
{
    ops_stg_data_t *p_stg_data = NULL;
    ops_stg_vlan_t *p_stg_vlan = NULL;

    p_stg_data = ops_stg[stgid];
    if (!p_stg_data) {
        VLOG_ERR("Trying to add vlan to  non-existent STG data (stgid=%d)!",
                 stgid);
        return;
    }

    HMAP_FOR_EACH_WITH_HASH(p_stg_vlan, node, hash_int(vlanid, 0),
                            &p_stg_data->vlans) {
        if (vlanid == p_stg_vlan->vlan_id){
            break;
        }
    }

    if(p_stg_vlan) {
        VLOG_DBG("vlan id %d found in stg id %d", p_stg_vlan->vlan_id,
                  p_stg_data->stg_id);
        return;
    }

    p_stg_vlan = xzalloc(sizeof(*p_stg_vlan));
    if (!p_stg_vlan) {
        VLOG_ERR("Failed to allocate memory for vlan id =%d, in STG %d",
                 vlanid, stgid);
        return;
    }
    p_stg_vlan->vlan_id = vlanid;

    hmap_insert(&p_stg_data->vlans, &p_stg_vlan->node, hash_int(vlanid, 0));
    p_stg_data->n_vlans++;
    VLOG_DBG("vlan id %d added to stg id %d", p_stg_vlan->vlan_id,
             p_stg_data->stg_id);
}

/*-----------------------------------------------------------------------------
| Function: stg_data_remove_vlan
| Description: removes vlan fron stg group
| Parameters[in]: stgid: spanning tree grouop id
| Parameters[in]: vlanid
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/

static void
stg_data_remove_vlan(int stgid, int vlanid)
{
    ops_stg_data_t *p_stg_data = NULL;
    ops_stg_vlan_t *p_stg_vlan = NULL;

    p_stg_data = ops_stg[stgid];
    if (!p_stg_data) {
        VLOG_ERR("Trying to remove vlan from non-existent STG data (stgid=%d)",
                 stgid);
        return;
    }

    HMAP_FOR_EACH_WITH_HASH(p_stg_vlan, node, hash_int(vlanid, 0),
                            &p_stg_data->vlans) {
        if (vlanid == p_stg_vlan->vlan_id){
            break;
        }
    }

    if(!p_stg_vlan) {
        VLOG_DBG("vlan id %d not found in stg id %d", vlanid, p_stg_data->stg_id);
        return;
    }

    VLOG_DBG("Delete vlan id %d from stg id %d", p_stg_vlan->vlan_id,
              p_stg_data->stg_id);
    hmap_remove(&p_stg_data->vlans, &p_stg_vlan->node);
    free(p_stg_vlan);
    p_stg_data->n_vlans--;
}

/*-----------------------------------------------------------------------------
| Function: stg_data_set_port_state
| Description: set port state in spanning tree group
| Parameters[in]:stgid: spanning tree group id
| Parameters[in]:portid
| Parameters[in]: port_state.
| Parameters[out]: None
| Return: None
-----------------------------------------------------------------------------*/
static void
stg_data_set_port_state(int stgid, int portid,
                           ops_stg_port_state_t port_state)
{
    ops_stg_data_t *p_stg_data = NULL;
    int unit = 0;
    opennsl_port_t hw_port;

    p_stg_data = ops_stg[stgid];
    if (!p_stg_data) {
        VLOG_ERR("Trying to set port sate for portid %d"
                 "to non-existent STG data (stgid=%d)!",
                 portid, stgid);
        return;
    }


    /* remove port from all port map list. */
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        OPENNSL_PBMP_ITER(p_stg_data->blocked_ports[unit], hw_port) {
            if (portid == hw_port) {
                OPENNSL_PBMP_PORT_REMOVE(p_stg_data->blocked_ports[unit],
                                         hw_port);
                VLOG_DBG("port id %d removed from blocked port"
                         "list of stg id %d",
                         portid, stgid);
            }
        }
        OPENNSL_PBMP_ITER(p_stg_data->disabled_ports[unit], hw_port) {
            if (portid == hw_port) {
                OPENNSL_PBMP_PORT_REMOVE(p_stg_data->disabled_ports[unit],
                                         hw_port);
                VLOG_DBG("port id %d removed from disabled port"
                         "list of stg id %d",
                        portid, stgid);
            }
        }
        OPENNSL_PBMP_ITER(p_stg_data->learning_ports[unit], hw_port) {
            if (portid == hw_port) {
                OPENNSL_PBMP_PORT_REMOVE(p_stg_data->learning_ports[unit],
                                         hw_port);
                VLOG_DBG("port id %d removed from learning port"
                         "list of stg id %d",
                         portid, stgid);
                }
            }
        OPENNSL_PBMP_ITER(p_stg_data->forwarding_ports[unit], hw_port) {
            if (portid == hw_port) {
                OPENNSL_PBMP_PORT_REMOVE(p_stg_data->forwarding_ports[unit],
                                         hw_port);
                VLOG_DBG("port id %d removed from forwarding port"
                         "list of stg id %d",
                    portid, stgid);
                }
            }
    }

    /* add port to respective ste port map list */
    for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
        switch (port_state) {
            case OPS_STG_PORT_STATE_BLOCKED:
                OPENNSL_PBMP_PORT_ADD(p_stg_data->blocked_ports[unit],
                                      portid);
                VLOG_DBG("port id %d set to blocked port list of stg id %d",
                    portid, stgid);
                break;
                case OPS_STG_PORT_STATE_DISABLED:
                    OPENNSL_PBMP_PORT_ADD(p_stg_data->disabled_ports[unit],
                                          portid);
                    VLOG_DBG("port id %d set to disabled port"
                             "list of stg id %d",
                        portid, stgid);
                    break;
                case OPS_STG_PORT_STATE_LEARNING:
                    OPENNSL_PBMP_PORT_ADD(p_stg_data->learning_ports[unit],
                                          portid);
                    VLOG_DBG("port id %d set to learning port"
                             "list of stg id %d",
                             portid, stgid);
                    break;
                case OPS_STG_PORT_STATE_FORWARDING:
                    OPENNSL_PBMP_PORT_ADD(p_stg_data->forwarding_ports[unit],
                                          portid);
                    VLOG_DBG("port id %d set to forwarding port"
                             "list of stg id %d",
                             portid, stgid);
                    break;
                default:
                    VLOG_DBG("invalid port state");
                    break;
        }
    }

}

/*-----------------------------------------------------------------------------
| Function: ops_stg_default_get
| Description: get default stg group
| Parameters[in]: None
| Parameters[out]: opennsl_stg_t object
| Return: error  value
-----------------------------------------------------------------------------*/
int ops_stg_default_get(opennsl_stg_t *p_stg)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int unit = 0;

    if (!p_stg) {
        VLOG_ERR("Invalid stg ptr param");
        return -1;
    }

    rc = opennsl_stg_default_get(unit, p_stg);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Unit %d, default stg get error, rc=%d (%s)",
                 unit, rc, opennsl_errmsg(rc));
        return -1;
    }
    return 0;
}

/*-----------------------------------------------------------------------------
| Function: ops_stg_vlan_add
| Description:  Add vlan to spanning tree group
| Parameters[in]: opennsl_stg_t : spanning tree group id
| Parameters[in]: opennsl_vlan_t: vlan id
| Parameters[out]: None
| Return: error value
-----------------------------------------------------------------------------*/
int ops_stg_vlan_add(opennsl_stg_t stgid, opennsl_vlan_t vid)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int unit = 0;
    ops_stg_data_t *p_stg_data = NULL;

    if (!OPS_STG_VALID(stgid)) {
        VLOG_ERR("Invalid stgid param");
        return -1;
    }

    if (!OPS_VLAN_VALID(vid)) {
        VLOG_ERR("Invalid vid param");
        return -1;
    }

    p_stg_data = stg_data_find_create(stgid, false);
    if (NULL == p_stg_data) {
        VLOG_ERR("vlan add to non existing stg data for stg id %d",
                 stgid);
        return -1;
    }

    VLOG_DBG("opennsl_stg_vlan_add called with stgid %d vid %d", stgid,
             vid);
    rc = opennsl_stg_vlan_add(unit, stgid, vid);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Unit %d, stg vlan add error, rc=%d (%s)",
                 unit, rc, opennsl_errmsg(rc));
        return -1;
    }

    stg_data_add_vlan(stgid, vid);
    return 0;
}

/*-----------------------------------------------------------------------------
| Function: ops_stg_vlan_remove
| Description:  Remove vlan from spanning tree group
| Parameters[in]: opennsl_stg_t : spanning tree group id
| Parameters[in]: opennsl_vlan_t: vlan id
| Parameters[out]: None
| Return: error value
-----------------------------------------------------------------------------*/
int ops_stg_vlan_remove(opennsl_stg_t stgid, opennsl_vlan_t vid)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int unit = 0;

    ops_stg_data_t *p_stg_data = NULL;

    if (!OPS_STG_VALID(stgid)) {
        VLOG_ERR("Invalid stgid param");
        return -1;
    }

    if (!OPS_VLAN_VALID(vid)) {
        VLOG_ERR("Invalid vid param");
        return -1;
    }

    p_stg_data = stg_data_find_create(stgid, false);
    if (NULL == p_stg_data) {
        VLOG_ERR("vlan remove from non existing stg data for stg id %d",
                 stgid);
        return -1;
    }

    VLOG_DBG("opennsl_stg_vlan_remove called with stgid %d, vid %d", stgid,
             vid);

    rc = opennsl_stg_vlan_remove(unit, stgid, vid);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Unit %d, stg vlan add error, rc=%d (%s)",
                 unit, rc, opennsl_errmsg(rc));
        return -1;
    }

    stg_data_remove_vlan(stgid, vid);
    return 0;
}

/*-----------------------------------------------------------------------------
| Function: ops_stg_create
| Description: create spanning tree group
| Parameters[in]: None
| Parameters[out]:opennsl_stg_t object
| Return: error value
-----------------------------------------------------------------------------*/
int ops_stg_create(opennsl_stg_t *pstgid)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int unit = 0;
    VLOG_DBG("ops_stg_create_stg called");
    if (!pstgid) {
        VLOG_ERR("Invalid pstgid param");
        return -1;
    }

    if (ops_stg_count == OPS_STG_MAX) {
        VLOG_DBG("Max instances reached");
        return -1;
    }

    VLOG_DBG("opennsl_stg_create called");
    rc = opennsl_stg_create(unit, pstgid);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Unit %d, create stg error, rc=%d (%s)",
                 unit, rc, opennsl_errmsg(rc));
        return -1;
    }

    VLOG_DBG("opennsl_stg_create returned stg %d", *pstgid);
    if (NULL != stg_data_find_create(*pstgid, true)) {
        VLOG_DBG("stg data entry created for stg id %d",
                 *pstgid);
    }
    else {
        VLOG_DBG("stg data entry creation failed for stg id %d",
                 *pstgid);
    }

    return 0;
}

/*-----------------------------------------------------------------------------
| Function: ops_stg_delete
| Description: delete stg from spanning tree group
| Parameters[in]: opennsl_stg_t: spanning tree group id
| Parameters[out]: None
| Return: error value
-----------------------------------------------------------------------------*/
int ops_stg_delete(opennsl_stg_t stgid)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int unit = 0;

    if (!OPS_STG_VALID(stgid)) {
        VLOG_ERR("Invalid stgid param");
        return -1;
    }

    if (OPS_STG_DEFAULT == stgid) {
        VLOG_ERR("default stg id %d shouldn't be deleted",
                 OPS_STG_DEFAULT);
        return -1;
    }

    if (NULL == stg_data_find_create(stgid, false)) {
        VLOG_ERR("stg data not found for given stgid %d",
                 stgid);
        return -1;
    }
    VLOG_DBG("opennsl_stg_destroy called with stgid %d", stgid);
    rc = opennsl_stg_destroy(unit, stgid);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Unit %d, delete stg error, rc=%d (%s)",
                 unit, rc, opennsl_errmsg(rc));
        return -1;
    }

    stg_data_free(stgid);
    return 0;
}

/*-----------------------------------------------------------------------------
| Function:  ops_stg_stp_set
| Description:  set port state in spanning tree group
| Parameters[in]: opennsl_stg_t : spanning tree group id
|.Parameters[in]: opennsl_port_t object
|.Parameters[in]: stp_state: port stp state
|.Parameters[in]:port_stp_set:
|                        True: if port first timetransitioning to forward state  or
                                   port blockec in all instances or
                                   single instance
                          else False.
| Parameters[out]: None
| Return:error value
-----------------------------------------------------------------------------*/
int ops_stg_stp_set(opennsl_stg_t stgid, opennsl_port_t port, int stp_state,
                       bool port_stp_set)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int unit = 0;
    ops_stg_data_t *p_stg_data = NULL;

    if (!OPS_STG_VALID(stgid)) {
        VLOG_ERR("Invalid stgid param");
        return -1;
    }

    p_stg_data = stg_data_find_create(stgid, false);
    if (NULL == p_stg_data) {
        VLOG_ERR("port state set to non existing stg data for stg id %d",
                 stgid);
        return -1;
    }
    VLOG_DBG("opennsl_stg_stp_set called with stg %d port %d stp_state %d",
             stgid, port, stp_state);
    rc = opennsl_stg_stp_set(unit, stgid, port, stp_state);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Unit %d, stg %d port %d state %d set error, rc=%d (%s)",
                 unit, stgid, port, stp_state, rc, opennsl_errmsg(rc));
        return -1;
    }

    if (port_stp_set) {
        VLOG_DBG("opennsl_port_stp_set called with port %d stp_state %d",
                 port, stp_state);
        rc = opennsl_port_stp_set(unit, port, stp_state);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Unit %d, port state set error, rc=%d (%s)",
                     unit, rc, opennsl_errmsg(rc));
            return -1;
        }
    }

    stg_data_set_port_state(stgid, port, stp_state);
    return 0;
}

/*-----------------------------------------------------------------------------
| Function: ops_stg_stp_get
| Description: get port state in spanning tree group
| Parameters[in]:opennsl_stg_t : spanning tree group id
| Parameters[in]: opennsl_port_t object
| Parameters[out]: p_stp_state: port stp state
| Return: error value
-----------------------------------------------------------------------------*/
int ops_stg_stp_get(opennsl_stg_t stgid, opennsl_port_t port, int *p_stp_state)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int unit = 0;

    if (!stgid) {
        VLOG_ERR("Invalid stgid param");
        return -1;
    }

    rc = opennsl_stg_stp_get(unit, stgid, port, p_stp_state);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Unit %d, stg port state get error, rc=%d (%s)",
                 unit, rc, opennsl_errmsg(rc));
        return -1;
    }
    return 0;
}

///////////////////////////////// INIT /////////////////////////////////
/*-----------------------------------------------------------------------------
| Function: ops_stg_init
| Description:initialization routine
| Parameters[in]:None
| Parameters[out]: None
| Return: error value
-----------------------------------------------------------------------------*/

int
ops_stg_init(int hw_unit)
{
    if (NULL == stg_data_find_create(OPS_STG_DEFAULT, true)) {
        VLOG_ERR("stg data create error for default stgid %d",
                 OPS_STG_DEFAULT);
        return -1;
    }
    VLOG_INFO("STG data created for stg-id %d", OPS_STG_DEFAULT);
    return 0;

}

///////////////////////////Plugin extension routines /////////////////////////////*/
/*-----------------------------------------------------------------------------
| Function: create_stg
| Description:plugin extension routine
| Parameters[in]:None
| Parameters[out]:  stg object
| Return: error value
-----------------------------------------------------------------------------*/
int
create_stg(int *p_stg)
{
    opennsl_stg_t stgid = 0;

    VLOG_DBG("%s: create stg entry called", __FUNCTION__);
    /* Create  stg and associate valn to stg. */
     ops_stg_create(&stgid);
    if (0 != stgid) {
        *p_stg = stgid;
        VLOG_DBG("%s: create stg entry, val=%d", __FUNCTION__, stgid);
        return 0;
    }
    else {
        VLOG_ERR("%s: create stg entry failed", __FUNCTION__);
        return -1;
    }

}

/*-----------------------------------------------------------------------------
| Function: delete_stg
| Description:plugin extension routine to delete STG
| Parameters[in]: stg id
| Parameters[out]: None
| Return: error value
-----------------------------------------------------------------------------*/
int
delete_stg(int stg)
{

    VLOG_DBG("%s: entry, stg=%d", __FUNCTION__, stg);
    /* Delete  stg. */
     ops_stg_delete(stg);
    return 0;
}

/*-----------------------------------------------------------------------------
| Function: add_stg_vlan
| Description: plugin extension routine to add vlan to stg
| Parameters[in]: stg id
| Parameters[in]: vlan id
| Parameters[out]: None
| Return: error value
-----------------------------------------------------------------------------*/
int
add_stg_vlan(int stg, int vid)
{
    ops_stg_vlan_add(stg, vid);
    return 0;
}

/*-----------------------------------------------------------------------------
| Function: remove_stg_vlan
| Description:plugin extension routine  to remove vlan from STG
| Parameters[in]:None
| Parameters[out]: None
| Return: error value
-----------------------------------------------------------------------------*/
int
remove_stg_vlan(int stg, int vid)
{
    ops_stg_vlan_remove(stg, vid);
    return 0;
}

/*-----------------------------------------------------------------------------
| Function: set_stg_port_state
| Description:plugin extension routine  to set port state in STG
| Parameters[in]:port name
| Parameters[in]:stg id
| Parameters[in]:port state
| Parameters[in]:set global port state
| Parameters[out]: None
| Return: error value
-----------------------------------------------------------------------------*/
int
set_stg_port_state(char *port_name, int stg,
                     int port_state, bool port_stp_set)
{
    int hw_id = 0, hw_unit =0;

    VLOG_DBG("%s: called", __FUNCTION__);
    if (false == netdev_hw_id_from_name(port_name, &hw_unit, &hw_id)) {
        VLOG_ERR("%s: unable to find netdev for port %s", __FUNCTION__,
                 port_name);
        return -1;
    }

    VLOG_DBG("%s: stg=%d, port=%d, port_state=%d", __FUNCTION__,
             stg, hw_id, port_state);
    /* set stg port state. */
    ops_stg_stp_set(stg, hw_id, port_state, port_stp_set);
    return 0;
}

/*-----------------------------------------------------------------------------
| Function:  get_stg_port_state
| Description:plugin extension routine  to get port state in STG
| Parameters[in]:port name
| Parameters[in]:stg id
| Parameters[out]: port state object
| Return: error value
-----------------------------------------------------------------------------*/
int
get_stg_port_state(char *port_name, int stg, int *p_port_state)
{
    int hw_id = 0, hw_unit =0;

    VLOG_DBG("%s: called", __FUNCTION__);
    if (false == netdev_hw_id_from_name(port_name, &hw_unit, &hw_id)) {
        VLOG_ERR("%s: unable to find netdev for port %s", __FUNCTION__, port_name);
        return -1;
    }

    VLOG_DBG("%s: stg=%d, port=%d", __FUNCTION__, stg, hw_id);
    /* Get stg port state. */
    ops_stg_stp_get(stg, hw_id, p_port_state);
    return 0;
}

/*-----------------------------------------------------------------------------
| Function: get_stg_default
| Description: plugin extension routine to get default STG.
| Parameters[in]:None
| Parameters[out]: stg object
| Return: error value
-----------------------------------------------------------------------------*/
int
get_stg_default(int *p_stg)
{
   /* Get default stg */
   ops_stg_default_get(p_stg);
   return 0;
}
