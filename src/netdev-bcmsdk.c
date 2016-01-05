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
 * File: netdev-bcmsdk.c
 */

#include <config.h>
#include <errno.h>
#include <linux/ethtool.h>
#include <netinet/ether.h>

#include <netdev-provider.h>
#include <openvswitch/vlog.h>
#include <openflow/openflow.h>
#include <openswitch-idl.h>
#include <openswitch-dflt.h>

#include <opennsl/port.h>

#include "ops-port.h"
#include "ops-knet.h"
#include "ops-stats.h"
#include "platform-defines.h"
#include "netdev-bcmsdk.h"
#include "ops-routing.h"

VLOG_DEFINE_THIS_MODULE(netdev_bcmsdk);


/* Protects 'bcmsdk_list'. */
static struct ovs_mutex bcmsdk_list_mutex = OVS_MUTEX_INITIALIZER;

/* Contains all 'struct bcmsdk_dev's. */
static struct ovs_list bcmsdk_list OVS_GUARDED_BY(bcmsdk_list_mutex)
    = OVS_LIST_INITIALIZER(&bcmsdk_list);

struct netdev_bcmsdk {
    struct netdev up;

    /* In bcmsdk_list. */
    struct ovs_list list_node OVS_GUARDED_BY(bcmsdk_list_mutex);

    /* Protects all members below. */
    struct ovs_mutex mutex OVS_ACQ_AFTER(bcmsdk_list_mutex);

    uint8_t hwaddr[ETH_ADDR_LEN] OVS_GUARDED;
    int mtu OVS_GUARDED;
    struct netdev_stats stats OVS_GUARDED;
    enum netdev_flags flags OVS_GUARDED;
    long long int link_resets OVS_GUARDED;

    int hw_unit;
    int hw_id;
    int l3_intf_id;
    int knet_if_id;             /* BCM KNET interface ID. */
    int knet_filter_id;         /* BCM KNET filter ID. */

    bool intf_initialized;

    /* Port Configuration. */
    struct port_cfg pcfg;

    /* Port info structure. */
    struct ops_port_info *port_info;

    /* ----- Subport/lane split config (e.g. QSFP+) ----- */

     /* Boolean indicating if this is a split parent or subport:
     *  - Parent port refers to the base port that is not split.
     *  - Subports refers to all individual ports after the
     *    parent port is split.
     * Note that these two booleans can never both be true at the
     * same time, and the parent port and the first subport are
     * mutually exclusive since they map to the same h/w port.
     */
    bool is_split_parent;
    bool is_split_subport;

    /* Pointer to parent port port_info data.
     * Valid for split children ports only. */
    struct ops_port_info *split_parent_portp;

};

static int netdev_bcmsdk_construct(struct netdev *);

static bool
is_bcmsdk_class(const struct netdev_class *class)
{
    return class->construct == netdev_bcmsdk_construct;
}

static struct netdev_bcmsdk *
netdev_bcmsdk_cast(const struct netdev *netdev)
{
    ovs_assert(is_bcmsdk_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_bcmsdk, up);
}

void
netdev_bcmsdk_get_hw_info(struct netdev *netdev, int *hw_unit, int *hw_id,
                          uint8_t *hwaddr)
{
    struct netdev_bcmsdk *nb = netdev_bcmsdk_cast(netdev);
    ovs_assert(is_bcmsdk_class(netdev_get_class(netdev)));

    *hw_unit = nb->hw_unit;
    *hw_id = nb->hw_id;
    if (hwaddr) {
        memcpy(hwaddr, nb->hwaddr, ETH_ADDR_LEN);
    }
}

static struct netdev_bcmsdk *
netdev_from_hw_id(int hw_unit, int hw_id)
{
    struct netdev_bcmsdk *netdev = NULL;
    bool found = false;

    ovs_mutex_lock(&bcmsdk_list_mutex);
    LIST_FOR_EACH(netdev, list_node, &bcmsdk_list) {
        if ((netdev->hw_unit == hw_unit) &&
            (netdev->hw_id == hw_id)) {

            /* If the port is splittable, and it is
             * split into child ports, then skip it. */
            if (netdev->is_split_parent &&
                netdev->port_info->lanes_split_status == true) {
                continue;
            }
            found = true;
            break;
        }
    }
    ovs_mutex_unlock(&bcmsdk_list_mutex);
    return (found == true) ? netdev : NULL;
}

static struct netdev *
netdev_bcmsdk_alloc(void)
{
    struct netdev_bcmsdk *netdev = xzalloc(sizeof *netdev);
    VLOG_DBG("Netdev alloc called");
    return &netdev->up;
}

static int
netdev_bcmsdk_construct(struct netdev *netdev_)
{
    static atomic_count next_n = ATOMIC_COUNT_INIT(0xaa550000);
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    unsigned int n;

    VLOG_DBG("Netdev construct called");
    n = atomic_count_inc(&next_n);

    ovs_mutex_init(&netdev->mutex);
    ovs_mutex_lock(&netdev->mutex);

    /* XXX: We should use MAC address defined in the
     * INTERFACE table instead of a randomly generated one. */
    netdev->hwaddr[0] = 0xaa;
    netdev->hwaddr[1] = 0x55;
    netdev->hwaddr[2] = n >> 24;
    netdev->hwaddr[3] = n >> 16;
    netdev->hwaddr[4] = n >> 8;
    netdev->hwaddr[5] = n;
    netdev->mtu = 1500;
    netdev->flags = 0;

    netdev->hw_unit = -1;
    netdev->hw_id = -1;
    netdev->knet_if_id = 0;
    netdev->knet_filter_id = 0;
    netdev->port_info = NULL;
    netdev->intf_initialized = false;

    netdev->is_split_parent = false;
    netdev->is_split_subport = false;
    netdev->split_parent_portp = NULL;

    ovs_mutex_unlock(&netdev->mutex);

    ovs_mutex_lock(&bcmsdk_list_mutex);
    list_push_back(&bcmsdk_list, &netdev->list_node);
    ovs_mutex_unlock(&bcmsdk_list_mutex);

    return 0;
}

static void
netdev_bcmsdk_destruct(struct netdev *netdev_)
{
    int rc = 0;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    VLOG_DBG("Calling Netdev destruct. name=%s unit=%d port=%d",
             netdev->up.name, netdev->hw_unit, netdev->hw_id);
    ovs_mutex_lock(&bcmsdk_list_mutex);

    if(netdev->knet_if_id) {
        rc = bcmsdk_knet_if_delete(netdev->up.name, netdev->hw_unit, netdev->knet_if_id);
    }

    if (rc) {
        VLOG_ERR("Failed to delete kernel KNET interface %s", netdev->up.name);
    }

    list_remove(&netdev->list_node);
    ovs_mutex_unlock(&bcmsdk_list_mutex);
}

static void
netdev_bcmsdk_dealloc(struct netdev *netdev_)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    free(netdev);
}

static int
netdev_bcmsdk_set_hw_intf_info(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    struct netdev *p_netdev_ = NULL;
    struct netdev_bcmsdk *p_netdev = NULL;
    struct ops_port_info *p_info = NULL;
    struct ether_addr ZERO_MAC = {{0}};
    struct ether_addr *ether_mac = NULL;
    int rc = 0;

    const char *hw_unit = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_SWITCH_UNIT);
    const char *hw_id = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_SWITCH_INTF_ID);
    const char *mac_addr = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_MAC_ADDR);
    const char *is_splittable = smap_get(args, INTERFACE_HW_INTF_INFO_MAP_SPLIT_4);
    const char *split_parent = smap_get(args, INTERFACE_HW_INTF_INFO_SPLIT_PARENT);

    VLOG_DBG("netdev set_hw_intf_info for interace %s", netdev->up.name);

    ovs_mutex_lock(&netdev->mutex);

    if (netdev->intf_initialized == false) {

        netdev->hw_unit = (hw_unit) ? atoi(hw_unit) : -1;
        if (!VALID_HW_UNIT(netdev->hw_unit)) {
            VLOG_ERR("Invalid switch unit id %s", hw_unit);
            goto error;
        }

        netdev->hw_id = (hw_id) ? atoi(hw_id) : -1;
        if (netdev->hw_id <= 0) {
            VLOG_ERR("Invalid switch port id %s", hw_id);
            goto error;
        }

        if (mac_addr) {
            ether_mac = ether_aton(mac_addr);
            if (ether_mac != NULL) {
                memcpy(netdev->hwaddr, ether_mac, ETH_ALEN);
            } else {
                ether_mac = &ZERO_MAC;
            }
        }

        /* Get the port_info struct for a given hardware unit & port number. */
        p_info = PORT_INFO(netdev->hw_unit, netdev->hw_id);
        if (NULL == p_info) {
            VLOG_ERR("Unable to get port info struct for "
                     "Interface=%s, hw_unit=%d, hw_id=%d",
                     netdev->up.name, netdev->hw_unit, netdev->hw_id);
            goto error;
        }

        /* Save the port_info porinter in netdev struct. */
        netdev->port_info = p_info;

        /* Save the hardware unit & port number in port_info struct. */
        p_info->hw_unit = netdev->hw_unit;
        p_info->hw_port = netdev->hw_id;
        p_info->name = xstrdup(netdev->up.name);

        /* For all the ports that can be split into multiple
         * subports, 'split_4' property is set to true.
         * This is set only on the parent ports. */
        if (STR_EQ(is_splittable, "true")) {

            netdev->is_split_parent = true;
            p_info->split_port_count = MAX_QSFP_SPLIT_PORT_COUNT;
            p_info->lanes_split_status = false;

        } else {

            /* For all the split children ports 'split_parent'
             * property is set to the name of the parent port.
             * This is done in subsystem.c file. */
            if (split_parent != NULL) {

                netdev->is_split_subport = true;

                /* Get parent ports netdev struct. */
                p_netdev_ = netdev_from_name(split_parent);
                if (p_netdev_ != NULL) {
                    p_netdev = netdev_bcmsdk_cast(p_netdev_);

                    /* Save pointer to parent port's port_info struct. */
                    netdev->split_parent_portp = p_netdev->port_info;

                    /* netdev_from_name() opens a reference, so we need to close it here. */
                    netdev_close(p_netdev_);

                } else {
                    VLOG_ERR("Unable to find the netdev for the parent port. "
                             "intf_name=%s parent_name=%s",
                             netdev->up.name, split_parent);
                    goto error;
                }
            }
        }

        rc = bcmsdk_knet_if_create(netdev->up.name, netdev->hw_unit,
                                   netdev->hw_id, ether_mac,
                                   &(netdev->knet_if_id));
        if (rc) {
            VLOG_ERR("Failed to initialize interface %s", netdev->up.name);
        } else {
            netdev->intf_initialized = true;
        }
    }
    ovs_mutex_unlock(&netdev->mutex);
    return 0;

error:
    ovs_mutex_unlock(&netdev->mutex);

    rc = -EINVAL;
    return rc;
}

static void
get_interface_autoneg_config(const char *autoneg_cfg, int *autoneg)
{
        /* Auto negotiation configuration. */
        if (STR_EQ(autoneg_cfg, INTERFACE_HW_INTF_CONFIG_MAP_AUTONEG_ON)) {
            *autoneg = true;
        } else {
            *autoneg = false;
        }
}

static void
get_interface_duplex_config(const char *duplex_cfg, int *duplex)
{
        /* Duplex configuration. */
        if (STR_EQ(duplex_cfg, INTERFACE_HW_INTF_CONFIG_MAP_DUPLEX_FULL)) {
            *duplex = OPENNSL_PORT_DUPLEX_FULL;
        } else {
            *duplex = OPENNSL_PORT_DUPLEX_HALF;
        }
}

static void
get_interface_pause_config(const char *pause_cfg, int *pause_rx, int *pause_tx)
{
    *pause_rx = false;
    *pause_tx = false;

        /* Pause configuration. */
    if (STR_EQ(pause_cfg, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE_RX)) {
        *pause_rx = true;
    } else if (STR_EQ(pause_cfg, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE_TX)) {
        *pause_tx = true;
    } else if (STR_EQ(pause_cfg, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE_RXTX)) {
        *pause_rx = true;
        *pause_tx = true;
    }
}

static void
get_interface_connector_type(const char *interface_type, opennsl_port_if_t *iface_port_if)
{
    opennsl_port_if_t port_if;

    if (interface_type) {
        if (!strcmp(interface_type,
                    INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_BACKPLANE)) {
            port_if = OPENNSL_PORT_IF_NULL;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_1GBASE_SX)) {
            port_if = OPENNSL_PORT_IF_GMII;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_1GBASE_T)) {
            port_if = OPENNSL_PORT_IF_GMII;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_10GBASE_CR)) {
            port_if = OPENNSL_PORT_IF_CR;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_10GBASE_SR)) {
            port_if = OPENNSL_PORT_IF_SR;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_10GBASE_LR)) {
            port_if = OPENNSL_PORT_IF_LR;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_10GBASE_LRM)) {
            port_if = OPENNSL_PORT_IF_LR;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_40GBASE_CR4)) {
            port_if = OPENNSL_PORT_IF_CR4;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_40GBASE_SR4)) {
            port_if = OPENNSL_PORT_IF_SR4;
        } else if (!strcmp(interface_type,
                           INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE_40GBASE_LR4)) {
            port_if = OPENNSL_PORT_IF_LR4;
        } else {
            port_if = OPENNSL_PORT_IF_NULL;
        }
    } else {
        port_if = OPENNSL_PORT_IF_NULL;
    }

    *iface_port_if = port_if;
}

static void
handle_bcmsdk_knet_filters(struct netdev_bcmsdk *netdev, int enable)
{
    if ((enable == true) && (netdev->knet_filter_id == 0)) {

        bcmsdk_knet_port_filter_create(netdev->up.name, netdev->hw_unit, netdev->hw_id,
                                       netdev->knet_if_id, &(netdev->knet_filter_id));

    } else if ((enable == false) && (netdev->knet_filter_id != 0)) {

        bcmsdk_knet_filter_delete(netdev->up.name, netdev->hw_unit, netdev->knet_filter_id);
        netdev->knet_filter_id = 0;
    }
}

/* Compare the existing port configuration,
 * and check if anything changed. */
static int
is_port_config_changed(const struct port_cfg *cur_pcfg, const struct port_cfg *pcfg)
{
    if ((cur_pcfg->enable != pcfg->enable) ||
        (cur_pcfg->autoneg != pcfg->autoneg) ||
        (cur_pcfg->cfg_speed != pcfg->cfg_speed) ||
        (cur_pcfg->duplex != pcfg->duplex) ||
        (cur_pcfg->pause_rx != pcfg->pause_rx) ||
        (cur_pcfg->pause_tx != pcfg->pause_tx) ||
        (cur_pcfg->max_frame_sz != pcfg->max_frame_sz) ||
        (cur_pcfg->intf_type != pcfg->intf_type)) {

        return 1;
    }
    return 0;

} // is_port_config_changed

static void
update_port_config(struct port_cfg *netdev_pcfg, const struct port_cfg *new_pcfg)
{
    netdev_pcfg->enable = new_pcfg->enable;
    netdev_pcfg->autoneg = new_pcfg->autoneg;
    netdev_pcfg->cfg_speed = new_pcfg->cfg_speed;
    netdev_pcfg->duplex = new_pcfg->duplex;
    netdev_pcfg->pause_rx = new_pcfg->pause_rx;
    netdev_pcfg->pause_tx = new_pcfg->pause_tx;
    netdev_pcfg->max_frame_sz = new_pcfg->max_frame_sz;
    netdev_pcfg->intf_type = new_pcfg->intf_type;

} // update_port_config

static int
netdev_bcmsdk_set_hw_intf_config(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    int rc = 0;
    struct port_cfg *pcfg = NULL;

    const char *hw_enable = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_ENABLE);
    const char *autoneg = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_AUTONEG);
    const char *duplex = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_DUPLEX);
    const char *pause = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_PAUSE);
    const char *interface_type = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_INTERFACE_TYPE);
    const int mtu = smap_get_int(args, INTERFACE_HW_INTF_CONFIG_MAP_MTU, 0);

    VLOG_DBG("netdev set_hw_intf_config called for interface %s", netdev->up.name);

    if (netdev->intf_initialized == false) {
        VLOG_WARN("netdev interface %s is not initialized.", netdev->up.name);
        return 1;
    }

    pcfg = xcalloc(1, sizeof *pcfg);


    /* If interface is enabled */
    if (STR_EQ(hw_enable, INTERFACE_HW_INTF_CONFIG_MAP_ENABLE_TRUE)) {

        pcfg->enable = true;

        get_interface_autoneg_config(autoneg, &(pcfg->autoneg));
        get_interface_duplex_config(duplex, &(pcfg->duplex));
        get_interface_pause_config(pause, &(pcfg->pause_rx), &(pcfg->pause_tx));
        get_interface_connector_type(interface_type, &(pcfg->intf_type));
        pcfg->max_frame_sz = (mtu == 0) ? 0 : mtu + BCMSDK_MTU_TO_MAXFRAMESIZE_PAD;

    } else {
        /* Treat the absence of hw_enable info as a "disable" action. */
        pcfg->enable = false;
    }

    if (!is_port_config_changed(&(netdev->pcfg), pcfg)) {
        VLOG_DBG("port config is not changed. Intf=%s, unit=%d port=%d",
                 netdev->up.name, netdev->hw_unit, netdev->hw_id);
        return 0;
    }

    // Update the netdev struct with new config.
    update_port_config(&(netdev->pcfg), pcfg);

    ovs_mutex_lock(&netdev->mutex);

     /* Splittable port lane configuration. */
    if (pcfg->enable == true) {
        if (netdev->is_split_parent) {
            split_port_lane_config(netdev->port_info, false);
        } else if (netdev->is_split_subport) {
            split_port_lane_config(netdev->split_parent_portp, true);
        }
    }

    /* If interface is being enabled, add a KNET filter rule
     * to send the incoming frames on the corresponding
     * KNET virtual interface, otherwise delete the rule. */
    handle_bcmsdk_knet_filters(netdev, pcfg->enable);

    rc = bcmsdk_set_port_config(netdev->hw_unit, netdev->hw_id, pcfg);
    if (rc) {
        VLOG_WARN("Failed to configure netdev interface %s.", netdev->up.name);
    }

    netdev_change_seq_changed(netdev_);

    ovs_mutex_unlock(&netdev->mutex);

    free(pcfg);

    return rc;
}

static int
netdev_bcmsdk_set_etheraddr(struct netdev *netdev,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_bcmsdk *dev = netdev_bcmsdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (!eth_addr_equals(dev->hwaddr, mac)) {
        memcpy(dev->hwaddr, mac, ETH_ADDR_LEN);
        netdev_change_seq_changed(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_bcmsdk_get_etheraddr(const struct netdev *netdev,
                           uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_bcmsdk *dev = netdev_bcmsdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    memcpy(mac, dev->hwaddr, ETH_ADDR_LEN);
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_bcmsdk_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    int status;

    ovs_mutex_lock(&netdev->mutex);
    bcmsdk_get_link_status(netdev->hw_unit, netdev->hw_id, &status);
    *carrier = status;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static long long int
netdev_bcmsdk_get_carrier_resets(const struct netdev *netdev_)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    long long int link_resets = 0;

    ovs_mutex_lock(&netdev->mutex);
    link_resets = netdev->link_resets;
    ovs_mutex_unlock(&netdev->mutex);

    return link_resets;
}

static int
netdev_bcmsdk_get_mtu(const struct netdev *netdev_, int *mtup)
{
    int rc = 0;
    struct port_cfg pcfg;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    memset(&pcfg, 0, sizeof(struct port_cfg));

    rc = bcmsdk_get_port_config(netdev->hw_unit, netdev->hw_id, &pcfg);
    if (rc) {
        VLOG_WARN("Unable to get the interface %s config", netdev->up.name);
        return rc;
    }

    if (pcfg.max_frame_sz) {
        *mtup = (pcfg.max_frame_sz - BCMSDK_MTU_TO_MAXFRAMESIZE_PAD);
    }

    return rc;
}

static int
netdev_bcmsdk_get_stats(const struct netdev *netdev_, struct netdev_stats *stats)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    return bcmsdk_get_port_stats(netdev->hw_unit, netdev->hw_id, stats);
}

static int
netdev_bcmsdk_get_features(const struct netdev *netdev_,
                           enum netdev_features *current,
                           enum netdev_features *advertised,
                           enum netdev_features *supported,
                           enum netdev_features *peer)
{
    int rc = 0;
    uint32_t speed;
    struct port_cfg pcfg;
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    *current = *advertised = *supported = *peer = (enum netdev_features) 0;

    memset(&pcfg, 0, sizeof(struct port_cfg));
    rc = bcmsdk_get_port_config(netdev->hw_unit, netdev->hw_id, &pcfg);
    if (rc) {
        VLOG_WARN("Unable to get the interface %s config", netdev->up.name);
        return rc;
    }

    /* Current settings. */
    speed = pcfg.link_speed;
    if (speed == SPEED_10) {
        *current |= pcfg.duplex ? NETDEV_F_10MB_FD : NETDEV_F_10MB_HD;
    } else if (speed == SPEED_100) {
        *current |= pcfg.duplex ? NETDEV_F_100MB_FD : NETDEV_F_100MB_HD;
    } else if (speed == SPEED_1000) {
        *current |= pcfg.duplex ? NETDEV_F_1GB_FD : NETDEV_F_1GB_HD;
    } else if (speed == SPEED_10000) {
        *current |= NETDEV_F_10GB_FD;
    } else if (speed == 40000) {
        *current |= NETDEV_F_40GB_FD;
    } else if (speed == 100000) {
        *current |= NETDEV_F_100GB_FD;
    }

    if (pcfg.autoneg) {
        *current |= NETDEV_F_AUTONEG;
    }

    if (pcfg.pause_tx && pcfg.pause_rx) {
        *current |= NETDEV_F_PAUSE;
    } else if (pcfg.pause_rx) {
        *current |= NETDEV_F_PAUSE;
        *current |= NETDEV_F_PAUSE_ASYM;
    } else if (pcfg.pause_tx) {
        *current |= NETDEV_F_PAUSE_ASYM;
    }

    return rc;
}

static int
netdev_bcmsdk_update_flags(struct netdev *netdev_,
                           enum netdev_flags off,
                           enum netdev_flags on,
                           enum netdev_flags *old_flagsp)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    int rc = 0;
    int state = 0;

    if ((off | on) & ~NETDEV_UP) {
        return EOPNOTSUPP;
    }

    ovs_mutex_lock(&netdev->mutex);

    /* Get the current state to update the old flags. */
    rc = bcmsdk_get_enable_state(netdev->hw_unit, netdev->hw_id, &state);
    if (!rc) {
        if (state) {
            *old_flagsp |= NETDEV_UP;
        } else {
            *old_flagsp &= ~NETDEV_UP;
        }

        /* Set the new state to that which is desired. */
        if (on & NETDEV_UP) {
            rc = bcmsdk_set_enable_state(netdev->hw_unit, netdev->hw_id, true);
        } else if (off & NETDEV_UP) {
            rc = bcmsdk_set_enable_state(netdev->hw_unit, netdev->hw_id, false);
        }
    }

    ovs_mutex_unlock(&netdev->mutex);

    return rc;
}

void
netdev_bcmsdk_link_state_callback(int hw_unit, int hw_id, int link_status)
{
    struct netdev_bcmsdk *netdev = netdev_from_hw_id(hw_unit, hw_id);

    if (link_status) {
        netdev->link_resets++;
    }

    if (netdev != NULL) {
        netdev_change_seq_changed((struct netdev *)&(netdev->up));
    }

    // Wakeup poll_block() function.
    seq_change(connectivity_seq_get());
}

/* Helper functions. */

static const struct netdev_class bcmsdk_class = {
    "system",
    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_bcmsdk_alloc,
    netdev_bcmsdk_construct,
    netdev_bcmsdk_destruct,
    netdev_bcmsdk_dealloc,
    NULL,                       /* get_config */
    NULL,                       /* set_config */
    netdev_bcmsdk_set_hw_intf_info,
    netdev_bcmsdk_set_hw_intf_config,
    NULL,                       /* get_tunnel_config */
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_bcmsdk_set_etheraddr,
    netdev_bcmsdk_get_etheraddr,
    netdev_bcmsdk_get_mtu,
    NULL,                       /* set_mtu */
    NULL,                       /* get_ifindex */
    netdev_bcmsdk_get_carrier,
    netdev_bcmsdk_get_carrier_resets,
    NULL,                       /* get_miimon */
    netdev_bcmsdk_get_stats,

    netdev_bcmsdk_get_features,
    NULL,                       /* set_advertisements */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* queue_dump_start */
    NULL,                       /* queue_dump_next */
    NULL,                       /* queue_dump_done */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_bcmsdk_update_flags,

    NULL,                       /* rxq_alloc */
    NULL,                       /* rxq_construct */
    NULL,                       /* rxq_destruct */
    NULL,                       /* rxq_dealloc */
    NULL,                       /* rxq_recv */
    NULL,                       /* rxq_wait */
    NULL,                       /* rxq_drain */
};

static int
netdev_internal_bcmsdk_set_hw_intf_info(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    int rc = 0;
    struct ether_addr *ether_mac = NULL;
    bool is_bridge_interface = smap_get_bool(args, INTERFACE_HW_INTF_INFO_MAP_BRIDGE, DFLT_INTERFACE_HW_INTF_INFO_MAP_BRIDGE);

    VLOG_DBG("netdev set_hw_intf_info for interace %s", netdev->up.name);

    ovs_mutex_lock(&netdev->mutex);

    if (netdev->intf_initialized == false) {
        netdev->hw_unit = 0;
        netdev->hw_id = -1;
        if(is_bridge_interface) {
            ether_mac = (struct ether_addr *) netdev->hwaddr;
            rc = bcmsdk_knet_if_create(netdev->up.name, netdev->hw_unit, netdev->hw_id, ether_mac,
                    &(netdev->knet_if_id));
            if (rc) {
                VLOG_ERR("Failed to initialize interface %s", netdev->up.name);
                goto error;
            } else {
                netdev->intf_initialized = true;
            }
        } else {
            netdev->intf_initialized = true;
        }
    }

    ovs_mutex_unlock(&netdev->mutex);
    return 0;

error:
    ovs_mutex_unlock(&netdev->mutex);
    rc = -EINVAL;
    return rc;
}


static int
netdev_internal_bcmsdk_update_flags(struct netdev *netdev_,
                                    enum netdev_flags off,
                                    enum netdev_flags on,
                                    enum netdev_flags *old_flagsp)
{
    /* XXX: Not yet supported for internal interfaces */
    return EOPNOTSUPP;
}

static const struct netdev_class bcmsdk_internal_class = {
    "internal",
    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_bcmsdk_alloc,
    netdev_bcmsdk_construct,
    netdev_bcmsdk_destruct,
    netdev_bcmsdk_dealloc,
    NULL,                       /* get_config */
    NULL,                       /* set_config */
    netdev_internal_bcmsdk_set_hw_intf_info,
    NULL,
    NULL,                       /* get_tunnel_config */
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_bcmsdk_set_etheraddr,
    netdev_bcmsdk_get_etheraddr,
    NULL,                       /* get_mtu */
    NULL,                       /* set_mtu */
    NULL,                       /* get_ifindex */
    NULL,                       /* get_carrier */
    NULL,                       /* get_carrier_resets */
    NULL,                       /* get_miimon */
    NULL,                       /* get_stats */

    NULL,                       /* get_features */
    NULL,                       /* set_advertisements */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* queue_dump_start */
    NULL,                       /* queue_dump_next */
    NULL,                       /* queue_dump_done */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_internal_bcmsdk_update_flags,

    NULL,                       /* rxq_alloc */
    NULL,                       /* rxq_construct */
    NULL,                       /* rxq_destruct */
    NULL,                       /* rxq_dealloc */
    NULL,                       /* rxq_recv */
    NULL,                       /* rxq_wait */
    NULL,                       /* rxq_drain */
};

static const struct netdev_class bcmsdk_l3_loopback_class = {
    "loopback",
    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_bcmsdk_alloc,
    netdev_bcmsdk_construct,
    netdev_bcmsdk_destruct,
    netdev_bcmsdk_dealloc,
    NULL,                       /* get_config */
    NULL,                       /* set_config */
    NULL,                       /* set_hw_intf_info */
    NULL,                       /* set_hw_intf_config */
    NULL,                       /* get_tunnel_config */
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */

    NULL,                       /* send */
    NULL,                       /* send_wait */

    netdev_bcmsdk_set_etheraddr,
    netdev_bcmsdk_get_etheraddr,
    NULL,                       /* get_mtu */
    NULL,                       /* set_mtu */
    NULL,                       /* get_ifindex */
    NULL,                       /* get_carrier */
    NULL,                       /* get_carrier_resets */
    NULL,                       /* get_miimon */
    NULL,                       /* get_stats */

    NULL,                       /* get_features */
    NULL,                       /* set_advertisements */

    NULL,                       /* set_policing */
    NULL,                       /* get_qos_types */
    NULL,                       /* get_qos_capabilities */
    NULL,                       /* get_qos */
    NULL,                       /* set_qos */
    NULL,                       /* get_queue */
    NULL,                       /* set_queue */
    NULL,                       /* delete_queue */
    NULL,                       /* get_queue_stats */
    NULL,                       /* queue_dump_start */
    NULL,                       /* queue_dump_next */
    NULL,                       /* queue_dump_done */
    NULL,                       /* dump_queue_stats */

    NULL,                       /* get_in4 */
    NULL,                       /* set_in4 */
    NULL,                       /* get_in6 */
    NULL,                       /* add_router */
    NULL,                       /* get_next_hop */
    NULL,                       /* get_status */
    NULL,                       /* arp_lookup */

    netdev_internal_bcmsdk_update_flags,

    NULL,                       /* rxq_alloc */
    NULL,                       /* rxq_construct */
    NULL,                       /* rxq_destruct */
    NULL,                       /* rxq_dealloc */
    NULL,                       /* rxq_recv */
    NULL,                       /* rxq_wait */
    NULL,                       /* rxq_drain */
};

void
netdev_bcmsdk_register(void)
{
    netdev_register_provider(&bcmsdk_class);
    netdev_register_provider(&bcmsdk_internal_class);
    netdev_register_provider(&bcmsdk_l3_loopback_class);
}
