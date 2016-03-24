/*
 * Copyright (C) 2015. 2016 Hewlett-Packard Development Company, L.P.
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
#include "ops-sflow.h"

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
    int knet_bpdu_filter_id;                 /* BCM KNET BPDU filter ID. */
    int knet_l3_port_filter_id;              /* BCM KNET L3 interface filter ID. */
    int knet_subinterface_filter_id;         /* BCM KNET subinterface filter ID. */
    int knet_bridge_normal_filter_id;        /* BCM KNET bridge mormal filter ID. */

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

    opennsl_vlan_t subintf_vlan_id;

    /* Currently being used only by type "internal" interfaces */
    int link_state;
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

void
netdev_bcmsdk_get_hw_info_from_name(const char *name, int *hw_unit,
                                    int *hw_id)
{
    struct netdev *netdev = NULL;
    netdev = netdev_from_name(name);
    if (netdev != NULL) {
        struct netdev_bcmsdk *nb = netdev_bcmsdk_cast(netdev);
        ovs_assert(is_bcmsdk_class(netdev_get_class(netdev)));
        *hw_unit = nb->hw_unit;
        *hw_id = nb->hw_id;
    } else {
        VLOG_ERR("Unable to get netdev for interface %s", name);
    }
}

void
netdev_bcmsdk_get_subintf_vlan(struct netdev *netdev, opennsl_vlan_t *vlan)
{
    struct netdev_bcmsdk *nb = netdev_bcmsdk_cast(netdev);
    ovs_assert(is_bcmsdk_class(netdev_get_class(netdev)));

    VLOG_DBG("get subinterface vlan as %d\n", nb->subintf_vlan_id);
    *vlan = nb->subintf_vlan_id;
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
    netdev->port_info = NULL;
    netdev->intf_initialized = false;
    memset(&netdev->stats, 0, sizeof(struct netdev_stats));

    netdev->is_split_parent = false;
    netdev->is_split_subport = false;
    netdev->split_parent_portp = NULL;
    netdev->subintf_vlan_id = 0;
    netdev->link_state = 0;

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
netdev_bcmsdk_set_config(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    struct netdev *parent = NULL;
    struct netdev_bcmsdk *parent_netdev = NULL;
    const char *parent_intf_name = NULL;
    int vlanid = 0;

    ovs_mutex_lock(&netdev->mutex);
    parent_intf_name = smap_get(args, "parent_intf_name");
    vlanid = smap_get_int(args, "vlan", 0);

    if (parent_intf_name != NULL) {
        VLOG_DBG("netdev set_config gets info for parent interface %s, and vlan = %d",
                parent_intf_name, vlanid);
        parent = netdev_from_name(parent_intf_name);
        if (parent != NULL) {
            parent_netdev = netdev_bcmsdk_cast(parent);
            if (parent_netdev != NULL) {
                netdev->hw_id = parent_netdev->hw_id;
                netdev->hw_unit = parent_netdev->hw_unit;
                memcpy(netdev->hwaddr, parent_netdev->hwaddr, ETH_ALEN);
                netdev->subintf_vlan_id = vlanid;
                netdev->knet_if_id = parent_netdev->knet_if_id;
            }
        }
    }

    ovs_mutex_unlock(&netdev->mutex);
    return 0;
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
handle_bcmsdk_knet_bpdu_filters(struct netdev_bcmsdk *netdev, int enable)
{
    if (enable == true && netdev->knet_bpdu_filter_id == 0) {
        /*
         * Add any other packets that we need when port is enabled
         * Currently sending BPDUs on interfaec enable
         * All other packets will go to bridge interface
         * */
        bcmsdk_knet_port_bpdu_filter_create(netdev->up.name, netdev->hw_unit, netdev->hw_id,
                netdev->knet_if_id, &(netdev->knet_bpdu_filter_id));
    } else if ((enable == false) && (netdev->knet_bpdu_filter_id != 0)) {
        bcmsdk_knet_filter_delete(netdev->up.name, netdev->hw_unit, netdev->knet_bpdu_filter_id);
        netdev->knet_bpdu_filter_id = 0;
    }

}

void
handle_bcmsdk_knet_l3_port_filters(struct netdev *netdev_, opennsl_vlan_t vlan_id, bool enable)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    if (enable == true && netdev->knet_l3_port_filter_id == 0) {
        VLOG_DBG("Create l3 port knet filter\n");
        bcmsdk_knet_l3_port_filter_create(netdev->hw_unit, vlan_id, netdev->hw_id,
                netdev->knet_if_id, &(netdev->knet_l3_port_filter_id));
    } else if ((enable == false) && (netdev->knet_l3_port_filter_id != 0)) {
        VLOG_DBG("Destroy l3 port knet filter\n");
        bcmsdk_knet_filter_delete(netdev->up.name,
                                  netdev->hw_unit,
                                  netdev->knet_l3_port_filter_id);
        netdev->knet_l3_port_filter_id = 0;
    }

}

void
handle_bcmsdk_knet_subinterface_filters(struct netdev *netdev_, bool enable)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    if (enable == true && netdev->knet_subinterface_filter_id == 0) {
        VLOG_DBG("Create subinterface knet filter\n");
        netdev->hw_unit = 0;
        bcmsdk_knet_subinterface_filter_create(netdev->hw_unit, netdev->hw_id,
                netdev->knet_if_id, &(netdev->knet_subinterface_filter_id));
    } else if ((enable == false) && (netdev->knet_subinterface_filter_id != 0)) {
        VLOG_DBG("Destroy subinterface knet filter\n");
        bcmsdk_knet_filter_delete(netdev->up.name, netdev->hw_unit, netdev->knet_subinterface_filter_id);
        netdev->knet_subinterface_filter_id = 0;
    }
}

static void
handle_bcmsdk_knet_bridge_normal_filters(struct netdev *netdev_, bool enable)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    if (enable == true && netdev->knet_bridge_normal_filter_id == 0) {
        VLOG_DBG("Create bridge normal knet filter\n");
        bcmsdk_knet_bridge_normal_filter_create(netdev->up.name, &(netdev->knet_bridge_normal_filter_id));
    } else if ((enable == false) && (netdev->knet_bridge_normal_filter_id != 0)) {
        VLOG_DBG("Destroy bridge normal knet filter\n");
        bcmsdk_knet_filter_delete(netdev->up.name, netdev->hw_unit, netdev->knet_bridge_normal_filter_id);
        netdev->knet_bpdu_filter_id = 0;
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
    handle_bcmsdk_knet_bpdu_filters(netdev, pcfg->enable);

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
                            const struct eth_addr mac)
{
    struct netdev_bcmsdk *dev = netdev_bcmsdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    if (memcmp(dev->hwaddr, mac.ea, ETH_ADDR_LEN)) {
        memcpy(dev->hwaddr, mac.ea, ETH_ADDR_LEN);
        netdev_change_seq_changed(netdev);
    }
    ovs_mutex_unlock(&dev->mutex);

    return 0;
}

static int
netdev_bcmsdk_get_etheraddr(const struct netdev *netdev,
                            struct eth_addr *mac)
{
    struct netdev_bcmsdk *dev = netdev_bcmsdk_cast(netdev);

    ovs_mutex_lock(&dev->mutex);
    memcpy(mac->ea, dev->hwaddr, ETH_ADDR_LEN);
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

/*
 * This function is used to populate the sampling stats for sFlow
 * per interface(netdev).
 *
 * Arguments:
 * ---------
 * bool ingress     : Packet sampled at ingress or egress of the interface.
 * char *name       : Interface where the packet was sampled.
 * uint64_t bytes   : Length of sampled packet
 */
void
netdev_bcmsdk_populate_sflow_stats(bool ingress, const char *name,
                                   uint64_t bytes)
{
    struct netdev *netdev = NULL;
    struct netdev_bcmsdk *netdev_bcm = NULL;

    if (bytes == 0)
        return;

    netdev = netdev_from_name(name);
    if (netdev != NULL) {
         netdev_bcm = netdev_bcmsdk_cast(netdev);
         ovs_mutex_lock(&netdev_bcm->mutex);
         if (ingress) {
             netdev_bcm->stats.sflow_ingress_packets++;
             netdev_bcm->stats.sflow_ingress_bytes += bytes;
         } else {
             netdev_bcm->stats.sflow_egress_packets++;
             netdev_bcm->stats.sflow_egress_bytes += bytes;
         }
         ovs_mutex_unlock(&netdev_bcm->mutex);
         netdev_close(netdev);
    } else {
        VLOG_ERR("Unable to get netdev for interface %s", name);
    }
}

/*
 * This function will update the statistics for sFlow which was previously
 * populated into the netdev_bcmsdk->stats structure.
 */
static void
netdev_bcmsdk_get_sflow_stats(const struct netdev_bcmsdk *netdev_bcm,
                              struct netdev_stats *stats)
{
    ovs_mutex_lock(&netdev_bcm->mutex);
    stats->sflow_ingress_packets = netdev_bcm->stats.sflow_ingress_packets;
    stats->sflow_ingress_bytes = netdev_bcm->stats.sflow_ingress_bytes;
    stats->sflow_egress_packets = netdev_bcm->stats.sflow_egress_packets;
    stats->sflow_egress_bytes = netdev_bcm->stats.sflow_egress_bytes;
    ovs_mutex_unlock(&netdev_bcm->mutex);
}

static int
netdev_bcmsdk_get_stats(const struct netdev *netdev_, struct netdev_stats *stats)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    /* Call the function to populate sFlow statistics */
    netdev_bcmsdk_get_sflow_stats(netdev, stats);
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

static struct netdev_bcmsdk *
netdev_find_name(const char *name)
{
    struct netdev_bcmsdk *netdev = NULL;
    bool found = false;

    ovs_mutex_lock(&bcmsdk_list_mutex);
    LIST_FOR_EACH(netdev, list_node, &bcmsdk_list) {
        if (strcmp(netdev->up.name, name) == 0) {
            found = true;
            break;
        }
    }
    ovs_mutex_unlock(&bcmsdk_list_mutex);
    return (found == true) ? netdev : NULL;
}

bool netdev_hw_id_from_name(const char *name, int *hw_unit, int *hw_id)
{
    struct netdev_bcmsdk *netdev = NULL;

    if (!name || !hw_unit || !hw_id) {
        return false;
    }

    netdev = netdev_find_name(name);

    if (netdev) {
        *hw_unit = netdev->hw_unit;
        *hw_id = netdev->hw_id;
        return true;
    }
    else {
        return false;
    }
}

/* populate sflow related netdev info */
void
netdev_bcmsdk_get_sflow_intf_info(int hw_unit, int hw_id, uint32_t *index,
                                  uint64_t *speed, uint32_t *direction,
                                  uint32_t *status)
{
    int state = 0;
    bool link_state = false;
    enum netdev_features current, adv, supp, peer;
    struct netdev_bcmsdk *netdev = netdev_from_hw_id(hw_unit, hw_id);

    *index = hw_id; /* physical port number */

    if (netdev &&
        !netdev_bcmsdk_get_features(&netdev->up, &current, &adv, &supp, &peer)) {
        *speed = netdev_features_to_bps(current, 0);
        *direction = (netdev_features_is_full_duplex(current) ? 1 : 2);
    } else {
        *speed = SFLOW_CNTR_SAMPLE_SPEED_DEFAULT;
        *direction = SFLOW_CNTR_SAMPLE_DIRECTION_DEFAULT;
    }

    if (!bcmsdk_get_enable_state(hw_unit, hw_id, &state)) {
        if (state) {
            *status = SFLOW_CNTR_SAMPLE_ADMIN_STATE_UP; /* ifAdminStatus up. */
        }
        if (netdev && !netdev_bcmsdk_get_carrier(&netdev->up, &link_state)) {
            if (link_state) {
                *status |= SFLOW_CNTR_SAMPLE_OPER_STATE_UP; /* ifOperStatus up. */
            }
        }
    } else {
        *status = SFLOW_CNTR_SAMPLE_STATE_DOWN;
    }
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
                handle_bcmsdk_knet_bridge_normal_filters(netdev_, true);
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
netdev_internal_bcmsdk_set_hw_intf_config(struct netdev *netdev_, const struct smap *args)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    const char *hw_enable = smap_get(args, INTERFACE_HW_INTF_CONFIG_MAP_ENABLE);

    VLOG_DBG("netdev set_hw_intf_config called for interface %s", netdev->up.name);
    ovs_mutex_lock(&netdev->mutex);

    /* If interface is enabled */
    if (STR_EQ(hw_enable, INTERFACE_HW_INTF_CONFIG_MAP_ENABLE_TRUE)) {
        netdev->flags |= NETDEV_UP;
        netdev->link_state = 1;
    } else {
        netdev->flags &= ~NETDEV_UP;
        netdev->link_state = 0;
    }

    netdev_change_seq_changed(netdev_);

    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

static int
netdev_internal_bcmsdk_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    *carrier = netdev->link_state;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static int
netdev_internal_bcmsdk_update_flags(struct netdev *netdev_,
                                    enum netdev_flags off,
                                    enum netdev_flags on,
                                    enum netdev_flags *old_flagsp)
{
    /*  We ignore the incoming flags as the underlying hardware responsible to
     *  change the status of the flags is absent. Thus, we set new flags to
     *  preconfigured values. */
    struct netdev_bcmsdk *netdev = netdev_bcmsdk_cast(netdev_);
    if ((off | on) & ~NETDEV_UP) {
        return EOPNOTSUPP;
    }

    ovs_mutex_lock(&netdev->mutex);
    *old_flagsp = netdev->flags;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
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
    netdev_internal_bcmsdk_set_hw_intf_config,
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
    netdev_internal_bcmsdk_get_carrier,
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

static const struct netdev_class bcmsdk_subintf_class = {
    "vlansubint",
    NULL,                       /* init */
    NULL,                       /* run */
    NULL,                       /* wait */

    netdev_bcmsdk_alloc,
    netdev_bcmsdk_construct,
    netdev_bcmsdk_destruct,
    netdev_bcmsdk_dealloc,
    NULL,                       /* get_config */
    netdev_bcmsdk_set_config,   /* set_config */
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

void
netdev_bcmsdk_register(void)
{
    netdev_register_provider(&bcmsdk_class);
    netdev_register_provider(&bcmsdk_internal_class);
    netdev_register_provider(&bcmsdk_l3_loopback_class);
    netdev_register_provider(&bcmsdk_subintf_class);
}
