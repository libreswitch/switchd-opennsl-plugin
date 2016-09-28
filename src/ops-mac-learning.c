/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Development Company, L.P.
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
 * File: ops-mac-learning.c
 */
#include "hmap.h"
#include "ofproto/ofproto.h"
#include "packets.h"
#include "errno.h"
#include "ops-mac-learning.h"
#include "ovs-thread.h"
#include "netdev-bcmsdk.h"
#include "platform-defines.h"
#include <netinet/ether.h>
#include "ops-lag.h"

VLOG_DEFINE_THIS_MODULE(ops_mac_learning);
static struct vlog_rate_limit mac_learning_rl = VLOG_RATE_LIMIT_INIT(5, 20);
/*
 * The buffers are defined as 2 because:
 *    To allow simultaneous read access to bridge.c and ops-mac-learning.c code
 *    threads will be: bcm_init thread, switchd main thread and thread created for
 *    bcm callback without worrying about wait for acquiring the lock.
 */
#define MAX_BUFFERS   2

/*
 * mlearn_mutex is the mutex going to be used to access the all_macs_learnt and
 * what hmap is currently in use.
 */
struct ovs_mutex mlearn_mutex = OVS_MUTEX_INITIALIZER;

/*
 * all_macs_learnt:
 *      It is for storing the MACs learnt.
 *
 * Threads that can access this data structure: bcm thread, bcm timer thead,
 * bcm thread created by ASIC for the traversal.
 */
struct mlearn_hmap all_macs_learnt[MAX_BUFFERS] OVS_GUARDED_BY(mlearn_mutex);

static int current_hmap_in_use = 0 OVS_GUARDED_BY(mlearn_mutex);

static struct mac_learning_plugin_interface *p_mlearn_plugin_interface = NULL;

static struct mac_learning_plugin_interface *
get_plugin_mac_learning_interface (void)
{
    struct plugin_extension_interface *p_extension = NULL;

    if (p_mlearn_plugin_interface) {
        return (p_mlearn_plugin_interface);
    }

    if (!find_plugin_extension(MAC_LEARNING_PLUGIN_INTERFACE_NAME,
                               MAC_LEARNING_PLUGIN_INTERFACE_MAJOR,
                               MAC_LEARNING_PLUGIN_INTERFACE_MINOR,
                               &p_extension)) {
        if (p_extension) {
            p_mlearn_plugin_interface = p_extension->plugin_interface;
            return (p_extension->plugin_interface);
        }
    }
    return NULL;
}

/*
 * Function: mlearn_table_hash_calc
 *
 * This function calculates the hash based on MAC address, vlan and hardware unit number.
 */
static uint32_t mlearn_table_hash_calc(const struct eth_addr mac,
                                       const uint16_t vlan,
                                       int hw_unit)
{
    uint32_t hash =
        hash_2words(hash_uint64_basis(eth_addr_vlan_to_uint64(mac, vlan), 0),
                hw_unit);
    return (hash);
}

/*
 * Function: ops_mac_table_is_full
 *
 * This function is used to find if the hmap has reached it's capacity or not.
 */
static bool ops_mac_table_is_full(const struct mlearn_hmap *mlearn_hmap)
{
    return ((mlearn_hmap->buffer).actual_size == (mlearn_hmap->buffer).size);
}

/*
 * Function: ops_mac_learning_get_port_name
 *
 * This function is to get the port name based on opennsl_l2_addr_t params
 */
void ops_mac_learning_get_port_name(int hw_unit, uint32_t flags,
                                    const int port_id, opennsl_trunk_t tgid,
                                    char *port_name)
{
    if (!port_name) {
        return;
    }

    /*
     * To change to OPENNSL_L2_TRUNK_MEMBER later.
     */
    if (flags & 128) {
        ops_lag_get_port_name(hw_unit, tgid, port_name);
    } else {
        netdev_port_name_from_hw_id(hw_unit, port_id, port_name);
    }
}

/*
 * Function: ops_mac_entry_add
 *
 * This function is used to add the entries in the all_macs_learnt hmap.
 *
 * If the entry is already present, it is modified or else it's created.
 */
static void ops_mac_entry_add(
        struct mlearn_hmap *hmap_entry,
        const uint8_t mac[ETH_ADDR_LEN],
        const int16_t vlan,
        const int port_id,
        opennsl_trunk_t tgid,
        int hw_unit,
        const mac_event event,
        bool move_event,
        uint32_t flags)
{
    struct mlearn_hmap_node *entry = NULL;
    struct eth_addr mac_eth;
    uint32_t hash = 0;
    int actual_size = 0;
    char port_name[PORT_NAME_SIZE];
    bool update = false;

    memcpy(mac_eth.ea, mac, sizeof(mac_eth.ea));
    hash = mlearn_table_hash_calc(mac_eth, vlan, hw_unit);
    actual_size = (hmap_entry->buffer).actual_size;
    memset((void*)port_name, 0, sizeof(port_name));

    ops_mac_learning_get_port_name(hw_unit, flags, port_id, tgid, port_name);

    if (!strlen(port_name)) {
        VLOG_ERR("%s: not able to find port name for port_id: %d "
                 "hw_unit: %d", __FUNCTION__, port_id, hw_unit);
        return;
    }

    VLOG_DBG("%s: port: %d, oper: %d, hw_unit: %d, vlan: %d, MAC: %s",
             __FUNCTION__, port_id, event, hw_unit, vlan,
             ether_ntoa((struct ether_addr *)mac));

    /* NOTE: hmap_insert always inserts node at beggining for the same hash value.
     * So same MAC and VLAN node has different operation, then HMAP_FOR_EACH_WITH_HASH
     * will return the nodes  last in first out. This will impact the MAC events order
     * to avoid that loop through the HMAP and make sure always only one MAC element
     * with latest event in the HAMP(MAC & VLAN as hash key).
     * Example event1: MAC1, VLAN1, Port1, DELETE(ageout)
     *         event2: MAC1, VLAN1, Port1, ADD
     * In the above example both nodes in the hmap, then events can go in out of order.
     * So to avoid this behaviour always check same node is already in the hmap and
     * update node with latest values.
     */

    /* Step1: MAC ADD events, If node is already in the hash map and entry->operation
     *        will be set based on the move flags.
     *
     * Step2: MAC DEL events, if the node is already in the hash map check "port id"
     *        of the current event and old node, if both belong to the same port then
     *        remove this node from the hmap to suppress the events.
     *
     * Step3: MAC MOVE Events, SDK set the move flags and genetaes two events.
     *        MAC DELETE event with old port and MAC ADD event with the new port
     *        for MOVE case.In this case If the node is already found in the hmap MAC
     *        ADD event with move flags will overwrite the old MAC DELETE event node
     *        in the hmap with operation as MOVE and sets the new port.
     */
    HMAP_FOR_EACH_WITH_HASH (entry, hmap_node, hash,
                             &(hmap_entry->table)) {

        if ((entry->vlan == vlan) && eth_addr_equals(entry->mac, mac_eth) &&
            (entry->hw_unit == hw_unit)) {
            if (event == MLEARN_DEL) {
                /* remove this entry from hmap */
                update = true;
                if (port_id == entry->port &&
                    (hmap_entry->buffer).actual_size > 0) {
                    /* Remove the node from the hmap table */
                    hmap_remove(&hmap_entry->table, &(entry->hmap_node));
                    VLOG_DBG("%s: MAC: %s vlan: %d found removing ",
                             __FUNCTION__, ether_ntoa((struct ether_addr *)mac),
                             vlan);
                }
            } else {
                /* Operation is MOVE or ADD? */
                entry->port = port_id;
                entry->oper = move_event ? MLEARN_MOVE : event;
                strncpy(entry->port_name, port_name, PORT_NAME_SIZE);
                update = true;
                VLOG_DBG("%s: MAC: %s vlan: %d update ",
                         __FUNCTION__, ether_ntoa((struct ether_addr *)mac),
                         vlan);
            }
        }
    }

    if (!update) {
        if (actual_size < (hmap_entry->buffer).size) {
            struct mlearn_hmap_node *mlearn_node =
                                    &((hmap_entry->buffer).nodes[actual_size]);
            VLOG_DBG("%s: new event, port: %d, oper: %d, hw_unit: %d,"
                     " vlan: %d, MAC: %s", __FUNCTION__, port_id,
                     event, hw_unit, vlan,
                     ether_ntoa((struct ether_addr *)mac));
            memcpy(&mlearn_node->mac, &mac_eth, sizeof(mac_eth));
            mlearn_node->port = port_id;
            mlearn_node->vlan = vlan;
            mlearn_node->hw_unit = hw_unit;
            /* Check is it MOVE event? */
            mlearn_node->oper = move_event && event == MLEARN_ADD ? MLEARN_MOVE : event;
            strncpy(mlearn_node->port_name, port_name, PORT_NAME_SIZE);
            hmap_insert(&hmap_entry->table,
                        &(mlearn_node->hmap_node),
                        hash);
            (hmap_entry->buffer).actual_size++;
        } else {
            VLOG_ERR_RL(&mac_learning_rl,"Error: MAC event miss, hmap size is: %u\n",
                        hmap_entry->buffer.actual_size);
        }
    }
}

/*
 * Function: ops_clear_mlearn_hmap
 *
 * This function clears the hmap and the buffer for storing the hmap nodes.
 */
void ops_clear_mlearn_hmap (struct mlearn_hmap *mhmap)
{
    if (mhmap) {
        memset(&(mhmap->buffer), 0, sizeof(mhmap->buffer));
        mhmap->buffer.size = BUFFER_SIZE;
        hmap_clear(&(mhmap->table));
    }
}

/*
 * Function: ops_mac_learning_run
 *
 * This function will be invoked when either of the two conditions
 * are satisfied:
 * 1. current in use hmap for storing all macs learnt is full
 * 2. timer thread times out
 *
 * This function will check if there is any new MACs learnt, if yes,
 * then it triggers callback from bridge.
 * Also it changes the current hmap in use.
 *
 * current_hmap_in_use = current_hmap_in_use ^ 1 is used to toggle
 * the current hmap in use as the buffers are 2.
 */
int ops_mac_learning_run ()
{
    struct mac_learning_plugin_interface *p_mlearn_interface = NULL;
    p_mlearn_interface = get_plugin_mac_learning_interface();
    if (p_mlearn_interface) {
        ovs_mutex_lock(&mlearn_mutex);
        if (hmap_count(&(all_macs_learnt[current_hmap_in_use].table))) {
            p_mlearn_interface->mac_learning_trigger_callback();
            current_hmap_in_use = current_hmap_in_use ^ 1;
            ops_clear_mlearn_hmap(&all_macs_learnt[current_hmap_in_use]);
        }
        ovs_mutex_unlock(&mlearn_mutex);
    } else {
        VLOG_ERR("%s: Unable to find mac learning plugin interface",
                 __FUNCTION__);
    }

    return (0);
}

/*
 * This function is for getting callback from ASIC
 * for MAC learning.
 */
void
ops_mac_learn_cb(int   unit,
                 opennsl_l2_addr_t  *l2addr,
                 int    operation,
                 void   *userdata)
{
    if (l2addr == NULL) {
        VLOG_ERR("%s: Invalid arguments. l2-addr is NULL", __FUNCTION__);
        return;
    }

    switch (operation) {
        case OPENNSL_L2_CALLBACK_ADD:
            ovs_mutex_lock(&mlearn_mutex);
            ops_mac_entry_add(&all_macs_learnt[current_hmap_in_use],
                              l2addr->mac,
                              l2addr->vid,
                              l2addr->port,
                              l2addr->tgid,
                              unit,
                              MLEARN_ADD,
                              (l2addr->flags & OPENNSL_L2_MOVE_PORT),
                              l2addr->flags);
            ovs_mutex_unlock(&mlearn_mutex);
            ops_l3_mac_move_add(unit, l2addr, userdata);
            break;
        case OPENNSL_L2_CALLBACK_DELETE:
            ovs_mutex_lock(&mlearn_mutex);
             ops_mac_entry_add(&all_macs_learnt[current_hmap_in_use],
                               l2addr->mac,
                               l2addr->vid,
                               l2addr->port,
                               l2addr->tgid,
                               unit,
                               MLEARN_DEL,
                               (l2addr->flags & OPENNSL_L2_MOVE_PORT),
                               l2addr->flags);
             ovs_mutex_unlock(&mlearn_mutex);
             ops_l3_mac_move_delete(unit, l2addr, userdata);
            break;
        default:
            break;
    }

    /*
     * notify vswitchd
     */
    if (ops_mac_table_is_full(&all_macs_learnt[current_hmap_in_use])) {
        ops_mac_learning_run();
    }
}

/*
 * Function: ops_l2_traverse_cb
 *
 * This function is triggered during the initialization. Currently,
 * when switchd process restarts, it resets the ASIC, but when HA
 * will be in place, this function will traverse the already learnt
 * entries in the hardware.
 */
int
ops_l2_traverse_cb (int unit,
                    opennsl_l2_addr_t *l2addr,
                    void *user_data)
{
     if (l2addr == NULL) {
        VLOG_ERR("%s: Invalid arguments. l2-addr is NULL", __FUNCTION__);
        return (EINVAL);
     }

     ovs_mutex_lock(&mlearn_mutex);
     ops_mac_entry_add(&all_macs_learnt[current_hmap_in_use],
                       l2addr->mac,
                       l2addr->vid,
                       l2addr->port,
                       l2addr->tgid,
                       unit,
                       MLEARN_ADD,
                       false,
                       l2addr->flags);
     ovs_mutex_unlock(&mlearn_mutex);
     return (0);
}

/*
 * Function: ops_mac_learning_get_hmap
 *
 * This function will be invoked by the mac learning plugin code,
 * so that the switchd main thread can get the new MACs learnt/deleted
 * and can update the MAC table in the OVSDB accordingly.
 */
int ops_mac_learning_get_hmap(struct mlearn_hmap **mhmap)
{
    if (!mhmap) {
        VLOG_ERR("%s: Invalid argument", __FUNCTION__);
        return (EINVAL);
    }

    ovs_mutex_lock(&mlearn_mutex);
    if (hmap_count(&(all_macs_learnt[current_hmap_in_use ^ 1].table))) {
        *mhmap = &all_macs_learnt[current_hmap_in_use ^ 1];
    } else {
        *mhmap = NULL;
    }
    ovs_mutex_unlock(&mlearn_mutex);

    return (0);
}

/*
 * Function: ops_mac_learning_init
 *
 * This function is invoked in the bcm init.
 *
 * It initializes the hmaps, reserves the buffer capacity of the hmap
 * to avoid the time spent in the malloc and free.
 *
 * It also registers for the initial traversal of the MACs already
 * learnt in the ASIC for all hw_units.
 */
int
ops_mac_learning_init()
{
    int idx = 0;
    int rc = 0;

    for (; idx < MAX_BUFFERS; idx++) {
        hmap_init(&(all_macs_learnt[idx].table));
        all_macs_learnt[idx].buffer.actual_size = 0;
        all_macs_learnt[idx].buffer.size = BUFFER_SIZE;
        hmap_reserve(&(all_macs_learnt[idx].table), BUFFER_SIZE);
    }

    for (idx = 0; idx < MAX_SWITCH_UNITS; idx++) {
        rc = opennsl_l2_traverse(idx,
                                 ops_l2_traverse_cb,
                                 NULL);
        if (rc != 0) {
            VLOG_ERR("%s: error: %d\n", __FUNCTION__, rc);
            return (rc);
        }
        rc = opennsl_l2_addr_register(idx, ops_mac_learn_cb, NULL);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("L2 address registration failed");
            return 1;
        }
    }

    return (0);
}

/*
 * Function: ops_l2_addr_flush_handler
 *
 * This function is invoked to flush MAC table entries on VLAN/PORT
 *
 */
int
ops_l2_addr_flush_handler(mac_flush_params_t *settings)
{
    int rc = 0;
    uint32 flags = 0;
    int unit = 0;
    opennsl_port_t port = 0;
    opennsl_module_t mod = -1;

    /* Get Harware Port */
    if (settings->options == L2MAC_FLUSH_BY_PORT
        || settings->options == L2MAC_FLUSH_BY_PORT_VLAN) {
        rc = netdev_hw_id_from_name(settings->port_name, &unit, &port);
        if (rc == false) {
            VLOG_ERR_RL(&mac_learning_rl, "%s: %s name not found flags %u mode %d",
                        __FUNCTION__, settings->port_name,
                        settings->flags,
                        settings->options);

            return -1; /* Return error */
        }
    }

    switch (settings->options) {
    case L2MAC_FLUSH_BY_VLAN:
        for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
            rc =  opennsl_l2_addr_delete_by_vlan(unit, settings->vlan, flags);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR_RL(&mac_learning_rl, "%s: vlan %d flags %u rc %d opt %d",
                            __FUNCTION__, settings->vlan,
                            settings->flags, rc, settings->options);

                return -1; /* Return error */
            }
        }
        break;
    case L2MAC_FLUSH_BY_PORT:
        rc = opennsl_l2_addr_delete_by_port(unit, mod, port, flags);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR_RL(&mac_learning_rl, "%s: port: %d name %s flags %u rc %d opt %d",
                        __FUNCTION__, port, settings->port_name,
                        settings->flags, rc, settings->options);

            return -1; /* Return error */
        }
        break;
    case L2MAC_FLUSH_BY_PORT_VLAN:
        rc = opennsl_l2_addr_delete_by_vlan_port(unit, settings->vlan,
                                                 mod, port, flags);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR_RL(&mac_learning_rl, "%s: port: %d name %s vlan %d flags %u opt %d",
                        __FUNCTION__, port, settings->port_name, settings->vlan,
                        settings->flags, settings->options);

            return -1; /* Return error */
        }
        break;
    case L2MAC_FLUSH_BY_TRUNK:
        rc = opennsl_l2_addr_delete_by_trunk(unit, settings->tgid, flags);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR_RL(&mac_learning_rl, "%s: name %s tgid %d flags %u opt %d",
                        __FUNCTION__, settings->port_name,
                        settings->tgid, settings->flags, settings->options);
            return -1; /* Return error */
        }
        break;
    case L2MAC_FLUSH_BY_TRUNK_VLAN:
        rc = opennsl_l2_addr_delete_by_vlan_trunk(unit, settings->vlan,
                                                  settings->tgid, flags);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR_RL(&mac_learning_rl, "%s: name %s vlan %d tgid %d flags %u opt %d",
                        __FUNCTION__, settings->port_name, settings->vlan,
                        settings->tgid, settings->flags, settings->options);
            return -1; /* Return error */
        }
        break;
     default:
        VLOG_ERR("%s: Unknown flush mode %d", __FUNCTION__, settings->options);
        return -1;
    }

    return rc;
}
