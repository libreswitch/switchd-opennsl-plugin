/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
 * Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 */

#include <errno.h>

#include <seq.h>
#include <coverage.h>
#include <vlan-bitmap.h>
#include <ofproto/ofproto-provider.h>
#include <ofproto/bond.h>
#include <ofproto/tunnel.h>
#include <openvswitch/vlog.h>

#include <vswitch-idl.h>
#include <openswitch-idl.h>

#include "ops-pbmp.h"
#include "ops-vlan.h"
#include "ops-lag.h"
#include "ops-routing.h"
#include "ops-knet.h"
#include "netdev-bcmsdk.h"
#include "platform-defines.h"
#include "ofproto-bcm-provider.h"

VLOG_DEFINE_THIS_MODULE(ofproto_bcm_provider);

COVERAGE_DEFINE(ofproto_bcm_provider_expired);
COVERAGE_DEFINE(rev_reconfigure_bcm);
COVERAGE_DEFINE(rev_bond_bcm);
COVERAGE_DEFINE(rev_port_toggled_bcm);

static void rule_get_stats(struct rule *, uint64_t *packets,
                           uint64_t *bytes, long long int *used);
static void bundle_remove(struct ofport *);
static struct bcmsdk_provider_ofport_node *get_ofp_port(
                          const struct bcmsdk_provider_node *ofproto,
                          ofp_port_t ofp_port);

static void available_vrf_ids_init(void);
static size_t allocate_vrf_id(void);
static void release_vrf_id(size_t);
static void port_unconfigure_ips(struct ofbundle *bundle);

/* vrf id avalability bitmap */
static unsigned long *available_vrf_ids = NULL;

static void
available_vrf_ids_init() {
    available_vrf_ids = bitmap_allocate(BCM_MAX_VRFS);
}

static size_t
allocate_vrf_id() {
    size_t vrf_id;

    vrf_id = bitmap_scan(available_vrf_ids, 0, 0, BCM_MAX_VRFS);
    if (vrf_id == BCM_MAX_VRFS) {
        VLOG_DBG("Couldn't allocate VRF ID\n");
        return BCM_MAX_VRFS;
    }

    bitmap_set1(available_vrf_ids, vrf_id);
    return vrf_id;
}

static void
release_vrf_id(size_t vrf_id) {
    bitmap_set0(available_vrf_ids, vrf_id);
}

static struct bcmsdk_provider_ofport_node *
bcmsdk_provider_ofport_node_cast(const struct ofport *ofport)
{
    return ofport ?
           CONTAINER_OF(ofport, struct bcmsdk_provider_ofport_node, up) : NULL;
}

static inline struct bcmsdk_provider_node *
bcmsdk_provider_node_cast(const struct ofproto *ofproto)
{
    ovs_assert(ofproto->ofproto_class == &ofproto_bcm_provider_class);
    return CONTAINER_OF(ofproto, struct bcmsdk_provider_node, up);
}

/* All existing ofproto provider instances, indexed by ->up.name. */
static struct hmap all_bcmsdk_provider_nodes =
              HMAP_INITIALIZER(&all_bcmsdk_provider_nodes);

/* Factory functions. */

static void
init(const struct shash *iface_hints)
{
    VLOG_DBG("%s::%d init %p", __FUNCTION__, __LINE__, iface_hints);
    available_vrf_ids_init();
    return;
}

static void
enumerate_types(struct sset *types)
{
    sset_add(types, "system");
    sset_add(types, "vrf");
}

static int
enumerate_names(const char *type, struct sset *names)
{
    struct bcmsdk_provider_node *ofproto;

    sset_clear(names);
    HMAP_FOR_EACH (ofproto,
                   all_bcmsdk_provider_node, &all_bcmsdk_provider_nodes) {
        if (strcmp(type, ofproto->up.type)) {
            continue;
        }

        sset_add(names, ofproto->up.name);
        VLOG_DBG("Enumerating bridge %s for type %s", ofproto->up.name, type);
    }

    return 0;
}

static int
del(const char *type OVS_UNUSED, const char *name OVS_UNUSED)
{
    return 0;
}

static const char *
port_open_type(const char *datapath_type OVS_UNUSED, const char *port_type)
{
    if(strcmp(port_type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0) {
        return port_type;
    }
    return "system";
}

/* Basic life-cycle. */

static struct ofproto *
alloc(void)
{
    struct bcmsdk_provider_node *ofproto = xmalloc(sizeof *ofproto);
    return &ofproto->up;
}

static void
dealloc(struct ofproto *ofproto_)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    free(ofproto);
}

static int
construct(struct ofproto *ofproto_)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    int error=0;

    VLOG_DBG("constructing ofproto - %s", ofproto->up.name);

    if (!strcmp(ofproto_->type, "vrf")) {
        ofproto->vrf = true;
        ofproto->vrf_id = allocate_vrf_id();
        if (ofproto->vrf_id == BCM_MAX_VRFS) {
            error = 1;
            goto out;
        }

        VLOG_DBG("Allocated VRF ID %zu for VRF %s\n",
                 ofproto->vrf_id, ofproto_->name);
    } else {
        ofproto->vrf = false;
    }

    ofproto->netflow = NULL;
    ofproto->stp = NULL;
    ofproto->rstp = NULL;
    ofproto->dump_seq = 0;
    hmap_init(&ofproto->bundles);
    ofproto->ms = NULL;
    ofproto->has_bonded_bundles = false;
    ofproto->lacp_enabled = false;
    ofproto_tunnel_init();
    ovs_mutex_init_adaptive(&ofproto->stats_mutex);
    ovs_mutex_init(&ofproto->vsp_mutex);

    guarded_list_init(&ofproto->pins);

    sset_init(&ofproto->ports);
    sset_init(&ofproto->ghost_ports);
    sset_init(&ofproto->port_poll_set);
    ofproto->port_poll_errno = 0;
    ofproto->change_seq = 0;
    ofproto->pins_seq = seq_create();
    ofproto->pins_seqno = seq_read(ofproto->pins_seq);

    hmap_insert(&all_bcmsdk_provider_nodes, &ofproto->all_bcmsdk_provider_node,
                hash_string(ofproto->up.name, 0));
    memset(&ofproto->stats, 0, sizeof ofproto->stats);

    ofproto_init_tables(ofproto_, N_TABLES);

    ofproto->up.tables[TBL_INTERNAL].flags = OFTABLE_HIDDEN | OFTABLE_READONLY;

out:
    return error;
}

static void
destruct(struct ofproto *ofproto_ OVS_UNUSED)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);

    hmap_remove(&all_bcmsdk_provider_nodes, &ofproto->all_bcmsdk_provider_node);

    hmap_destroy(&ofproto->bundles);

    sset_destroy(&ofproto->ports);
    sset_destroy(&ofproto->ghost_ports);
    sset_destroy(&ofproto->port_poll_set);

    if (ofproto->vrf) {
        release_vrf_id(ofproto->vrf_id);
    }

    ovs_mutex_destroy(&ofproto->stats_mutex);
    ovs_mutex_destroy(&ofproto->vsp_mutex);

    return;
}

static int
run(struct ofproto *ofproto_ OVS_UNUSED)
{
    return 0;
}

static void
wait(struct ofproto *ofproto_ OVS_UNUSED)
{
    return;
}

static void
query_tables(struct ofproto *ofproto,
             struct ofputil_table_features *features,
             struct ofputil_table_stats *stats)
{
    VLOG_DBG("query_tables %p %p %p", ofproto,features,stats);
    return;
}

static struct ofport *
port_alloc(void)
{
    struct bcmsdk_provider_ofport_node *port = xmalloc(sizeof *port);
    return &port->up;
}

static void
port_dealloc(struct ofport *port_)
{
    struct bcmsdk_provider_ofport_node *port =
           bcmsdk_provider_ofport_node_cast(port_);
    free(port);
}

static int
port_construct(struct ofport *port_)
{
    struct bcmsdk_provider_ofport_node *port =
           bcmsdk_provider_ofport_node_cast(port_);
    VLOG_DBG("construct port %s", netdev_get_name(port->up.netdev));

    port->bundle = NULL;

    return 0;
}

static void
port_destruct(struct ofport *port_ OVS_UNUSED)
{
    return;
}

static void
port_reconfigured(struct ofport *port_, enum ofputil_port_config old_config)
{
    VLOG_DBG("port_reconfigured %p %d", port_, old_config);
    return;
}

static bool
cfm_status_changed(struct ofport *ofport_)
{
    VLOG_DBG("cfm_status_changed %p", ofport_);
    return false;
}

static bool
bfd_status_changed(struct ofport *ofport_ OVS_UNUSED)
{
    return false;
}

/* Bundles. */

static void
add_trunked_vlans(unsigned long *vlan_list, opennsl_pbmp_t *pbm)
{
    int vid;

    if (vlan_list) {
        BITMAP_FOR_EACH_1(vid, VLAN_BITMAP_SIZE, vlan_list) {
            bcmsdk_add_trunk_ports(vid, pbm);
        }
    }
}

static void
del_trunked_vlans(unsigned long *vlan_list, opennsl_pbmp_t *pbm)
{
    int vid;

    if (vlan_list) {
        BITMAP_FOR_EACH_1(vid, VLAN_BITMAP_SIZE, vlan_list) {
            bcmsdk_del_trunk_ports(vid, pbm);
        }
    }
}

static void
config_all_vlans(enum port_vlan_mode vlan_mode, int vlan,
                 unsigned long *trunks, opennsl_pbmp_t *pbm)
{
    VLOG_DBG("%s: entry, vlan_mode=%d, tag=%d, trunks=%p, pbm=%p",
             __FUNCTION__, (int)vlan_mode, vlan, trunks, pbm);

    if ((pbm == NULL) || bcmsdk_pbmp_is_empty(pbm)) {
        return;
    }

    switch (vlan_mode) {
    case PORT_VLAN_ACCESS:
        if (vlan != -1) {
            bcmsdk_add_access_ports(vlan, pbm, false);
        }
        break;

    case PORT_VLAN_TRUNK:
        add_trunked_vlans(trunks, pbm);
        break;

    case PORT_VLAN_NATIVE_TAGGED:
        if (vlan != -1) {
            bcmsdk_add_native_tagged_ports(vlan, pbm);
        }

        add_trunked_vlans(trunks, pbm);
        break;

    case PORT_VLAN_NATIVE_UNTAGGED:
        if (vlan != -1) {
            bcmsdk_add_native_untagged_ports(vlan, pbm);
        }

        add_trunked_vlans(trunks, pbm);
        break;

    default:
        /* Should not happen. */
        VLOG_ERR("Invalid VLAN mode (%d).", vlan_mode);
        break;
    }

}

static void
unconfig_all_vlans(enum port_vlan_mode vlan_mode, int vlan,
                   unsigned long *trunks, opennsl_pbmp_t *pbm)
{
    VLOG_DBG("%s: entry, vlan_mode=%d, tag=%d, trunks=%p, pbm=%p",
             __FUNCTION__, (int)vlan_mode, vlan, trunks, pbm);

    if ((pbm == NULL) || bcmsdk_pbmp_is_empty(pbm)) {
        return;
    }

    switch (vlan_mode) {
    case PORT_VLAN_ACCESS:
        if (vlan != -1) {
            bcmsdk_del_access_ports(vlan, pbm, false);
        }
        break;

    case PORT_VLAN_TRUNK:
        del_trunked_vlans(trunks, pbm);
        break;

    case PORT_VLAN_NATIVE_TAGGED:
        if (vlan != -1) {
            bcmsdk_del_native_tagged_ports(vlan, pbm);
        }

        del_trunked_vlans(trunks, pbm);
        break;

    case PORT_VLAN_NATIVE_UNTAGGED:
        if (vlan != -1) {
            bcmsdk_del_native_untagged_ports(vlan, pbm);
        }

        del_trunked_vlans(trunks, pbm);
        break;

    default:
        /* Should not happen. */
        VLOG_ERR("Invalid VLAN mode (%d).", vlan_mode);
        break;
    }

}

static void
handle_trunk_vlan_changes(unsigned long *old_trunks, unsigned long *new_trunks,
                          opennsl_pbmp_t *pbm, enum port_vlan_mode old_mode,
                          enum port_vlan_mode new_mode)
{
    int vid;
    bool removed_vlans_found = false;
    bool added_vlans_found = false;
    unsigned long *removed_vlans = bitmap_allocate(VLAN_BITMAP_SIZE);
    unsigned long *added_vlans = bitmap_allocate(VLAN_BITMAP_SIZE);

    if (old_trunks) {
        BITMAP_FOR_EACH_1(vid, VLAN_BITMAP_SIZE, old_trunks) {
            if (!new_trunks || !bitmap_is_set(new_trunks, vid)) {
                VLOG_DBG("Found a deleted VLAN %d", vid);
                bitmap_set1(removed_vlans, vid);
                removed_vlans_found = true;
            }
        }
        /* Remove VLANs based on old mode. */
        if (removed_vlans_found) {
            unconfig_all_vlans(old_mode, -1, removed_vlans, pbm);
        }
    }

    if (new_trunks) {
        BITMAP_FOR_EACH_1(vid, VLAN_BITMAP_SIZE, new_trunks) {
            if (!old_trunks || !bitmap_is_set(old_trunks, vid)) {
                VLOG_DBG("Found an added VLAN %d", vid);
                bitmap_set1(added_vlans, vid);
                added_vlans_found = true;
            }
        }
        /* Configure new VLANs based on new mode. */
        if (added_vlans_found) {
            config_all_vlans(new_mode, -1, added_vlans, pbm);
        }
    }

    /* Done with these bitmaps. */
    bitmap_free(removed_vlans);
    bitmap_free(added_vlans);
}

static struct ofbundle *
bundle_lookup(const struct bcmsdk_provider_node *ofproto, void *aux)
{
    struct ofbundle *bundle;

    HMAP_FOR_EACH_IN_BUCKET (bundle, hmap_node, hash_pointer(aux, 0),
                             &ofproto->bundles) {
        if (bundle->aux == aux) {
            return bundle;
        }
    }
    return NULL;
}

static void
bundle_del_port(struct bcmsdk_provider_ofport_node *port)
{
    list_remove(&port->bundle_node);
    port->bundle = NULL;
}

static bool
bundle_add_port(struct ofbundle *bundle, ofp_port_t ofp_port,
                struct lacp_slave_settings *lacp OVS_UNUSED)
{
    struct bcmsdk_provider_ofport_node *port;

    port = get_ofp_port(bundle->ofproto, ofp_port);
    if (!port) {
        return false;
    }

    if (port->bundle != bundle) {
        if (port->bundle) {
            bundle_remove(&port->up);
        }
        port->bundle = bundle;
        list_push_back(&bundle->ports, &port->bundle_node);
    }

    return true;
}

static void
bundle_destroy(struct ofbundle *bundle)
{
    struct bcmsdk_provider_node *ofproto = bundle->ofproto;;
    struct bcmsdk_provider_ofport_node *port, *next_port;

    if (!bundle) {
        return;
    }

    /* Delete the KNET vlan filters if they were configured */
    if(bundle->vlan_knet_filter_ids[0]) {
        bcmsdk_knet_filter_delete(NULL, bundle->hw_unit,
                                  bundle->vlan_knet_filter_ids[0]);
    }

    if(bundle->vlan_knet_filter_ids[1]) {
        bcmsdk_knet_filter_delete(NULL, bundle->hw_unit,
                                  bundle->vlan_knet_filter_ids[1]);
    }

    if(bundle->vlan_knet_filter_ids[2]) {
        bcmsdk_knet_filter_delete(NULL, bundle->hw_unit,
                                  bundle->vlan_knet_filter_ids[2]);
    }

    memset(bundle->vlan_knet_filter_ids, 0, sizeof(bundle->vlan_knet_filter_ids));

    /* Unconfigure and free the l3 port/bundle ip related stuff */
    port_unconfigure_ips(bundle);

    if (bundle->l3_intf) {
        ops_routing_disable_l3_interface(bundle->hw_unit,
                                        bundle->hw_port,
                                        bundle->l3_intf);
        bundle->l3_intf = NULL;
    }

    /* Unconfigure any existing VLAN in h/w. */
    unconfig_all_vlans(bundle->vlan_mode, bundle->vlan,
                       bundle->trunks, bundle->pbm);

    VLOG_DBG("%s: Deallocate bond_hw_handle# %d for port %s",
             __FUNCTION__, bundle->bond_hw_handle, bundle->name);

    if (bundle->bond_hw_handle != -1) {
        bcmsdk_destroy_lag(bundle->bond_hw_handle);
    }
    ofproto = bundle->ofproto;

    LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
        bundle_del_port(port);
    }

    hmap_remove(&ofproto->bundles, &bundle->hmap_node);
    bitmap_free(bundle->trunks);
    free(bundle->name);
    free(bundle);
}

static void
port_list_to_hw_pbm(struct ofproto *ofproto_, opennsl_pbmp_t *pbm,
                    ofp_port_t *port_list, size_t n_ports)
{
    const struct ofport *ofport;
    int i, ofp_port, hw_unit, hw_id;

    for (i = 0; i < n_ports; i++) {
        ofport = ofproto_get_port(ofproto_, port_list[i]);
        ofp_port = ofport ? ofport->ofp_port : OFPP_NONE;
        if (ofp_port == OFPP_NONE) {
            VLOG_WARN("Null ofport for port list member# %d", i);
            continue;
        }
        netdev_bcmsdk_get_hw_info(ofport->netdev, &hw_unit, &hw_id, NULL);
        ovs_assert(hw_unit <= MAX_SWITCH_UNIT_ID);
        bcmsdk_pbmp_add_hw_port(pbm, hw_unit, hw_id);

        VLOG_DBG("member# %d port %s internal port# %d, hw_unit# %d, hw_id# %d",
                 i, netdev_get_name(ofport->netdev), ofp_port, hw_unit, hw_id);
    }
}

/* Host Functions */
/* Function to configure local host ip */
static int
port_l3_host_add(struct ofproto *ofproto_, bool is_ipv6, char *ip_addr)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    struct ofproto_l3_host host_info;

    VLOG_DBG("ofproto_host_add called for ip %s", ip_addr);

    /* Update the host info for ofproto action */
    host_info.family = is_ipv6 ? OFPROTO_ROUTE_IPV6 : OFPROTO_ROUTE_IPV4;
    host_info.ip_address = ip_addr;

    /* Call Provider */
    if (!ops_routing_host_entry_action(0, ofproto->vrf_id, OFPROTO_HOST_ADD,
                                       &host_info) ) {
        VLOG_DBG("Added host entry for %s", ip_addr);
        return 0;
    } else {
        VLOG_ERR("!ops_routing_host_entry_action for add failed");
        return 1;
    }
} /* port_l3_host_add */

/* Function to unconfigure local host ip */
static int
port_l3_host_delete(struct ofproto *ofproto_, bool is_ipv6, char *ip_addr)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    struct ofproto_l3_host host_info;

    VLOG_DBG("ofproto_host_delete called for ip %s", ip_addr);

    /* Update the host info for ofproto action */
    host_info.family = is_ipv6 ? OFPROTO_ROUTE_IPV6 : OFPROTO_ROUTE_IPV4;
    host_info.ip_address = ip_addr;

    /* Call Provider */
    if (!ops_routing_host_entry_action(0, ofproto->vrf_id, OFPROTO_HOST_DELETE,
                                       &host_info) ) {
        VLOG_DBG("Deleted host entry for %s", ip_addr);
        return 0;
    } else {
        VLOG_ERR("!ops_routing_host_entry_action for delete failed");
        return 1;
    }
} /* port_l3_host_delete */

/* Function to unconfigure and free all port ip's */
static void
port_unconfigure_ips(struct ofbundle *bundle)
{
    struct ofproto *ofproto;
    bool is_ipv6 = false;
    struct net_address *addr, *next;

    ofproto = &bundle->ofproto->up;

    /* Unconfigure primary ipv4 address and free */
    if (bundle->ip4_address) {
        port_l3_host_delete(ofproto, is_ipv6, bundle->ip4_address);
        free(bundle->ip4_address);
    }

    /* Unconfigure primary ipv6 address and free */
    if (bundle->ip6_address) {
        port_l3_host_delete(ofproto, is_ipv6, bundle->ip6_address);
        free(bundle->ip6_address);
    }

    /* Unconfigure secondary ipv4 address and free the hash */
    HMAP_FOR_EACH_SAFE (addr, next, addr_node, &bundle->secondary_ip4addr) {
        port_l3_host_delete(ofproto, is_ipv6, addr->address);
        hmap_remove(&bundle->secondary_ip4addr, &addr->addr_node);
        free(addr->address);
        free(addr);
    }
    hmap_destroy( &bundle->secondary_ip4addr);

    /* Unconfigure secondary ipv6 address and free the hash */
    is_ipv6 = true;
    HMAP_FOR_EACH_SAFE (addr, next, addr_node, &bundle->secondary_ip6addr) {
        port_l3_host_delete(ofproto, is_ipv6, addr->address);
        hmap_remove(&bundle->secondary_ip6addr, &addr->addr_node);
        free(addr->address);
        free(addr);
    }
    hmap_destroy( &bundle->secondary_ip6addr);

} /* port_unconfigure_ips */

/*
** Function to find if the ipv4 secondary address already exist in the hash.
*/
static struct net_address *
port_ip4_addr_find(struct ofbundle *bundle, const char *address)
{
    struct net_address *addr;

    HMAP_FOR_EACH_WITH_HASH (addr, addr_node, hash_string(address, 0),
                             &bundle->secondary_ip4addr) {
        if (!strcmp(addr->address, address)) {
            return addr;
        }
    }

    return NULL;
} /* port_ip4_addr_find */

/*
** Function to find if the ipv6 secondary address already exist in the hash.
*/
static struct net_address *
port_ip6_addr_find(struct ofbundle *bundle, const char *address)
{
    struct net_address *addr;

    HMAP_FOR_EACH_WITH_HASH (addr, addr_node, hash_string(address, 0),
                             &bundle->secondary_ip6addr) {
        if (!strcmp(addr->address, address)) {
            return addr;
        }
    }

    return NULL;
} /* port_ip6_addr_find */

/*
** Function to check for changes in secondary ipv4 configuration of a
** given port
*/
static void
port_config_secondary_ipv4_addr(struct ofproto *ofproto,
                                struct ofbundle *bundle,
                                const struct ofproto_bundle_settings *s)
{
    struct shash new_ip_list;
    struct net_address *addr, *next;
    struct shash_node *addr_node;
    int i;
    bool is_ipv6 = false;

    shash_init(&new_ip_list);

    /* Create hash of the current secondary ip's */
    for (i = 0; i < s->n_ip4_address_secondary; i++) {
       if(!shash_add_once(&new_ip_list, s->ip4_address_secondary[i],
                           s->ip4_address_secondary[i])) {
            VLOG_WARN("Duplicate address in secondary list %s\n",
                      s->ip4_address_secondary[i]);
        }
    }

    /* Compare current and old to delete any obselete one's */
    HMAP_FOR_EACH_SAFE (addr, next, addr_node, &bundle->secondary_ip4addr) {
        if (!shash_find_data(&new_ip_list, addr->address)) {
            hmap_remove(&bundle->secondary_ip4addr, &addr->addr_node);
            port_l3_host_delete(ofproto, is_ipv6, addr->address);
            free(addr->address);
            free(addr);
        }
    }

    /* Add the newly added addresses to the list */
    SHASH_FOR_EACH (addr_node, &new_ip_list) {
        struct net_address *addr;
        const char *address = addr_node->data;
        if (!port_ip4_addr_find(bundle, address)) {
            /*
             * Add the new address to the list
             */
            addr = xzalloc(sizeof *addr);
            addr->address = xstrdup(address);
            hmap_insert(&bundle->secondary_ip4addr, &addr->addr_node,
                        hash_string(addr->address, 0));
            port_l3_host_add(ofproto, is_ipv6, addr->address);
        }
    }
} /* port_config_secondary_ipv4_addr */

/*
** Function to check for changes in secondary ipv6 configuration of a
** given port
*/
static void
port_config_secondary_ipv6_addr(struct ofproto *ofproto,
                                struct ofbundle *bundle,
                                const struct ofproto_bundle_settings *s)
{
    struct shash new_ip6_list;
    struct net_address *addr, *next;
    struct shash_node *addr_node;
    int i;
    bool is_ipv6 = true;

    shash_init(&new_ip6_list);

    /* Create hash of the current secondary ip's */
    for (i = 0; i < s->n_ip6_address_secondary; i++) {
        if(!shash_add_once(&new_ip6_list, s->ip6_address_secondary[i],
                           s->ip6_address_secondary[i])) {
            VLOG_WARN("Duplicate address in secondary list %s\n",
                      s->ip6_address_secondary[i]);
        }
    }

    /* Compare current and old to delete any obselete one's */
    HMAP_FOR_EACH_SAFE (addr, next, addr_node, &bundle->secondary_ip6addr) {
        if (!shash_find_data(&new_ip6_list, addr->address)) {
            hmap_remove(&bundle->secondary_ip6addr, &addr->addr_node);
            port_l3_host_delete(ofproto, is_ipv6, addr->address);
            free(addr->address);
            free(addr);
        }
    }

    /* Add the newly added addresses to the list */
    SHASH_FOR_EACH (addr_node, &new_ip6_list) {
        struct net_address *addr;
        const char *address = addr_node->data;
        if (!port_ip6_addr_find(bundle, address)) {
            /*
             * Add the new address to the list
             */
            addr = xzalloc(sizeof *addr);
            addr->address = xstrdup(address);
            hmap_insert(&bundle->secondary_ip6addr, &addr->addr_node,
                        hash_string(addr->address, 0));
            port_l3_host_add(ofproto, is_ipv6, addr->address);
        }
    }
}

/* Function to check for changes in ip configuration of a given port */
static int
port_ip_reconfigure(struct ofproto *ofproto, struct ofbundle *bundle,
                    const struct ofproto_bundle_settings *s)
{
    bool is_ipv6 = false;

    VLOG_DBG("In port_ip_reconfigure with ip_change val=0x%x", s->ip_change);
    /* If primary ipv4 got added/deleted/modified */
    if (s->ip_change & PORT_PRIMARY_IPv4_CHANGED) {
        if (s->ip4_address) {
            if (bundle->ip4_address) {
                if (strcmp(bundle->ip4_address, s->ip4_address) != 0) {
                    /* If current and earlier are different, delete old */
                    port_l3_host_delete(ofproto, is_ipv6,
                                        bundle->ip4_address);
                    free(bundle->ip4_address);

                    /* Add new */
                    bundle->ip4_address = xstrdup(s->ip4_address);
                    port_l3_host_add(ofproto, is_ipv6,
                                     bundle->ip4_address);
                }
                /* else no change */
            } else {
                /* Earlier primary was not there, just add new */
                bundle->ip4_address = xstrdup(s->ip4_address);
                port_l3_host_add(ofproto, is_ipv6, bundle->ip4_address);
            }
        } else {
            /* Primary got removed, earlier if it was there then remove it */
            if (bundle->ip4_address != NULL) {
                port_l3_host_delete(ofproto, is_ipv6, bundle->ip4_address);
                free(bundle->ip4_address);
                bundle->ip4_address = NULL;
            }
        }
    }

    /* If primary ipv6 got added/deleted/modified */
    if (s->ip_change & PORT_PRIMARY_IPv6_CHANGED) {
        is_ipv6 = true;
        if (s->ip6_address) {
            if (bundle->ip6_address) {
                if (strcmp(bundle->ip6_address, s->ip6_address) !=0) {
                    /* If current and earlier are different, delete old */
                    port_l3_host_delete(ofproto, is_ipv6, bundle->ip6_address);
                    free(bundle->ip6_address);

                    /* Add new */
                    bundle->ip6_address = xstrdup(s->ip6_address);
                    port_l3_host_add(ofproto, is_ipv6, bundle->ip6_address);

                }
                /* else no change */
            } else {

                /* Earlier primary was not there, just add new */
                bundle->ip6_address = xstrdup(s->ip6_address);
                port_l3_host_add(ofproto, is_ipv6, bundle->ip6_address);
            }
        } else {
            /* Primary got removed, earlier if it was there then remove it */
            if (bundle->ip6_address != NULL) {
                port_l3_host_delete(ofproto, is_ipv6, bundle->ip6_address);
                free(bundle->ip6_address);
                bundle->ip6_address = NULL;
            }
        }
    }

    /* If any secondary ipv4 addr added/deleted/modified */
    if (s->ip_change & PORT_SECONDARY_IPv4_CHANGED) {
        VLOG_DBG("ip4_address_secondary modified");
        port_config_secondary_ipv4_addr(ofproto, bundle, s);
    }

    if (s->ip_change & PORT_SECONDARY_IPv6_CHANGED) {
        VLOG_DBG("ip6_address_secondary modified");
        port_config_secondary_ipv6_addr(ofproto, bundle, s);
    }

    return 0;
}

static int
bundle_set(struct ofproto *ofproto_, void *aux,
           const struct ofproto_bundle_settings *s)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    int i;
    const char *opt_arg;
    opennsl_pbmp_t *all_pbm;
    opennsl_pbmp_t *temp_pbm;
    unsigned long *new_trunks = NULL;
    bool trunk_all_vlans = false;
    struct bcmsdk_provider_ofport_node *port;
    struct ofbundle *bundle;
    bool ok;

    VLOG_DBG("%s: entry, ofproto_=%p, aux=%p, s=%p",
             __FUNCTION__, ofproto_, aux, s);

    bundle = bundle_lookup(ofproto, aux);

    if (s == NULL) {
        if (bundle != NULL) {
            VLOG_DBG("  deleting bundle %s", bundle->name);
            bundle_destroy(bundle);
        }
        return 0;
    }

    if (!bundle) {
        VLOG_DBG("  creating NEW bundle %s", s->name);

        bundle = xmalloc(sizeof *bundle);

        bundle->ofproto = ofproto;
        hmap_insert(&ofproto->bundles, &bundle->hmap_node,
                    hash_pointer(aux, 0));
        bundle->aux = aux;
        bundle->name = NULL;
        bundle->l3_intf = NULL;
        bundle->hw_unit = 0;
        bundle->hw_port = -1;

        list_init(&bundle->ports);
        bundle->vlan_mode = PORT_VLAN_ACCESS;
        bundle->vlan = -1;
        bundle->trunks = NULL;
        bundle->trunk_all_vlans = false;
        bundle->pbm = NULL;
        bundle->bond_hw_handle = -1;
        bundle->lacp = NULL;
        bundle->bond = NULL;
        memset(bundle->vlan_knet_filter_ids, 0, sizeof(bundle->vlan_knet_filter_ids));

        bundle->ip4_address = NULL;
        bundle->ip6_address = NULL;
        hmap_init(&bundle->secondary_ip4addr);
        hmap_init(&bundle->secondary_ip6addr);
    }

    if (!bundle->name || strcmp(s->name, bundle->name)) {
        free(bundle->name);
        bundle->name = xstrdup(s->name);
    }

    VLOG_DBG("%s: bundle->name=%s, bundle->bond_hw_handle=%d, "
             "n_slaves=%d, s->bond=%p, "
             "s->hw_bond_should_exist=%d, "
             "s->bond_handle_alloc_only=%d",
             __FUNCTION__, bundle->name, bundle->bond_hw_handle,
             (int) s->n_slaves, s->bond,
             s->hw_bond_should_exist,
             s->bond_handle_alloc_only);

    /* Allocate Broadcom hw port bitmap. */
    all_pbm = bcmsdk_alloc_pbmp();
    if (all_pbm == NULL) {
        return ENOMEM;
    }

    if ((-1 == bundle->bond_hw_handle) &&
        (s->hw_bond_should_exist || (s->bond_handle_alloc_only))) {
        /* Create a h/w LAG if there is more than one member present
           in the bundle or if requested by upper layer. */
        bcmsdk_create_lag(&bundle->bond_hw_handle);
        VLOG_DBG("%s: Allocated bond_hw_handle# %d for port %s",
                 __FUNCTION__, bundle->bond_hw_handle, s->name);
        if (s->bond_handle_alloc_only) {
            return 0;
        }
    } else if ((-1 != bundle->bond_hw_handle) &&
               (false == s->hw_bond_should_exist)) {
        /* LAG should not exist in h/w any more. */
        bcmsdk_destroy_lag(bundle->bond_hw_handle);
        bundle->bond_hw_handle = -1;
    }

    /* Update set of ports. */
    ok = true;
    for (i = 0; i < s->n_slaves; i++) {
        if (!bundle_add_port(bundle, s->slaves[i], NULL)) {
            ok = false;
        }
    }
    if (!ok || list_size(&bundle->ports) != s->n_slaves) {
        struct bcmsdk_provider_ofport_node *next_port;

        LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
            for (i = 0; i < s->n_slaves; i++) {
                if (s->slaves[i] == port->up.ofp_port) {
                    goto found;
                }
            }

            bundle_del_port(port);
        found: ;
        }
    }
    ovs_assert(list_size(&bundle->ports) <= s->n_slaves);

    if (list_is_empty(&bundle->ports)) {
        bundle_destroy(bundle);
        return 0;
    }

    VLOG_INFO("s->n_slaves: %zu\n", s->n_slaves);

    /*
     * Configure  KNET filter for vlan interfaces in bridge
     * Vlan ports will have a single interface of type
     * internal and have vlan_id set.
     * Skip this for bridge internal interface which will have same
     * name as bridge (ofproto->up.name)
     * */
    if(!ofproto->vrf && s->n_slaves == 1 && strcmp(bundle->name, ofproto->up.name)) {
        struct bcmsdk_provider_ofport_node *port;
        opennsl_vlan_t vlan_id;
        const char *type;

        port = get_ofp_port(bundle->ofproto, s->slaves[0]);
        type = netdev_get_type(port->up.netdev);
        vlan_id = s->vlan;

        VLOG_DBG("bridge %s interface type %s vland id %d", ofproto->up.name, type, vlan_id);
        if((strcmp(type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0) && vlan_id &&
           (bundle->vlan_knet_filter_ids[0] == 0)) {
            VLOG_INFO("Creating KNET filters for vlan interface vlan%d", vlan_id);
            bcmsdk_knet_vlan_interface_filter_create(ofproto->up.name, vlan_id,
                                                     &bundle->vlan_knet_filter_ids[0]);
            /* Configuration for internal vlan interface is done */
            goto done;
        }
    }

    /* for now, we don't support L3 on top of LAG */
    if (ofproto->vrf &&
        (ofproto->vrf_id != BCM_MAX_VRFS)
        && s->n_slaves == 1) {
        struct bcmsdk_provider_ofport_node *port;
        int hw_unit, hw_port;
        opennsl_vlan_t vlan_id;
        uint8_t mac[ETH_ADDR_LEN];
        const char *type = NULL;

        port = get_ofp_port(bundle->ofproto, s->slaves[0]);
        if (!port) {
            VLOG_ERR("slave is not in the ports");
        }

        type = netdev_get_type(port->up.netdev);
        netdev_bcmsdk_get_hw_info(port->up.netdev, &hw_unit, &hw_port, mac);

        /* For internal vlan interfaces, we get vlanid from tag column
         * For regular l3 interfaces we will get from internal vlan id from
         * hw_config column
         */
        if(strcmp(type, OVSREC_INTERFACE_TYPE_INTERNAL) == 0) {
            vlan_id = s->vlan;
        } else {
            vlan_id = smap_get_int(s->port_options[PORT_HW_CONFIG], "internal_vlan_id", 0);
        }

        if (bundle->l3_intf) {
            /* if reserved vlan changed or removed */
            if (bundle->l3_intf->l3a_vid != vlan_id) {
                ops_routing_disable_l3_interface(hw_unit, hw_port, bundle->l3_intf);
                bundle->l3_intf = NULL;
                bundle->hw_unit = 0;
                bundle->hw_port = -1;
            }
        }

        if (vlan_id && !bundle->l3_intf) {

            /* If interface type is not internal create l3 interface, else
             * create an l3 vlan interface on every hw_unit. */
            if(strcmp(type, OVSREC_INTERFACE_TYPE_INTERNAL) != 0) {
                bundle->l3_intf = ops_routing_enable_l3_interface(
                        hw_unit, hw_port, ofproto->vrf_id, vlan_id,
                        mac);
                if (bundle->l3_intf) {
                    bundle->hw_unit = hw_unit;
                    bundle->hw_port = hw_port;
                }
            } else {
                int unit = 0;
                for (unit = 0; unit <= MAX_SWITCH_UNIT_ID; unit++) {
                    bundle->l3_intf = ops_routing_enable_l3_vlan_interface(
                            unit, ofproto->vrf_id, vlan_id,
                            mac);
                }
            }
        }
    }

    /* Check for ip changes */
    /* if ( (bundle->l3_intf) ) */
    port_ip_reconfigure(ofproto_, bundle, s);

    /* Look for port configuration options
     * FIXME: - fill up stubs with actual actions */
    opt_arg = smap_get(s->port_options[PORT_OPT_VLAN], "vlan_options_p0");
    if (opt_arg != NULL) {
       VLOG_DBG("VLAN config options option_arg= %s", opt_arg);
    }

    opt_arg = smap_get(s->port_options[PORT_OPT_BOND], "bond_options_p0");
    if (opt_arg != NULL) {
       VLOG_DBG("BOND config options option_arg= %s", opt_arg);
    }


    /* Go through the list of physical interfaces (slaves) that
     * belong to this logical port, and construct a corresponding
     * hw port bitmap so we can configure the VLAN(s) all at once. */
    port_list_to_hw_pbm(ofproto_, all_pbm, s->slaves, s->n_slaves);

    /* Apply LAG configuration if the bundle is a LAG. */
    if (bundle->bond_hw_handle != -1) {
        opennsl_pbmp_t *tx_en_pbm = NULL;
        int lag_mode = 0;

        if (s->bond) {
            /* update LAG balance mode. */
            switch (s->bond->balance) {
            case BM_L2_SRC_DST_HASH:
                lag_mode = OPENNSL_TRUNK_PSC_SRCDSTMAC;
                break;
            case BM_L3_SRC_DST_HASH:
                lag_mode = OPENNSL_TRUNK_PSC_SRCDSTIP;
                break;
            default:
                break;
            }
            if (lag_mode != 0) {
                bcmsdk_set_lag_balance_mode(bundle->bond_hw_handle, lag_mode);
            }
        }

        /* Attach ports to the LAG. */
        bcmsdk_attach_ports_to_lag(bundle->bond_hw_handle, all_pbm);

        /* Allocate another port bitmap for LAG's tx_enabled members. */
        tx_en_pbm = bcmsdk_alloc_pbmp();
        if (NULL == tx_en_pbm) {
            bcmsdk_destroy_pbmp(all_pbm);
            return ENOMEM;
        }

        port_list_to_hw_pbm(ofproto_, tx_en_pbm, s->slaves_tx_enable,
                            s->n_slaves_tx_enable);

        bcmsdk_egress_enable_lag_ports(bundle->bond_hw_handle,
                                       tx_en_pbm);
        bcmsdk_destroy_pbmp(tx_en_pbm);
    }

    /* NOTE: "bundle" holds previous VLAN configuration (if any).
     * "s" holds current desired VLAN configuration. */

    /* Figure out the new set of VLANs to configure.  If bundle's
     * vlan_mode is one of trunks (trunk, native_tagged, native_untagged),
     * and s->trunks is NULL, that means the bundle is implicitly trunking
     * all VLANs.  Use the global bitmap of all VLANs.
     */
    if (s->vlan_mode != PORT_VLAN_ACCESS) {
        if (s->trunks != NULL) {
            new_trunks = s->trunks;
        } else {
            new_trunks = ofproto_->vlans_bmp;
            trunk_all_vlans = true;
        }
    }

    /* If no interface was configured before, just
     * configure everything on the new ports. */
    if (bundle->pbm == NULL || bcmsdk_pbmp_is_empty(bundle->pbm)) {
        config_all_vlans(s->vlan_mode, s->vlan, new_trunks, all_pbm);
        goto done;
    }

    /* Allocate temporary port bitmap to figure out
     * what interfaces have been added/deleted from port. */
    temp_pbm = bcmsdk_alloc_pbmp();
    if (temp_pbm == NULL) {
        return ENOMEM;
    }

    /* First, unconfigure any physical interface that has
     * been removed from this logical port. */
    bcmsdk_pbmp_remove(temp_pbm, bundle->pbm, all_pbm);
    if (!bcmsdk_pbmp_is_empty(temp_pbm)) {
        unconfig_all_vlans(bundle->vlan_mode, bundle->vlan,
                           bundle->trunks, temp_pbm);
        bcmsdk_clear_pbmp(temp_pbm);
    }

    /* Next, configure all VLANs on any new interface. */
    bcmsdk_pbmp_remove(temp_pbm, all_pbm, bundle->pbm);
    if (!bcmsdk_pbmp_is_empty(temp_pbm)) {
        config_all_vlans(s->vlan_mode, s->vlan, new_trunks, temp_pbm);
        bcmsdk_clear_pbmp(temp_pbm);
    }

    /* For existing interfaces, configure only changed VLANs. */
    bcmsdk_pbmp_and(temp_pbm, all_pbm, bundle->pbm);
    if (!bcmsdk_pbmp_is_empty(temp_pbm)) {
        int mode_changed = (bundle->vlan_mode != s->vlan_mode);
        int tag_changed = (bundle->vlan != s->vlan);

        /* Check for mode changes first. */
        if (mode_changed) {
            if (bundle->vlan_mode == PORT_VLAN_ACCESS) {
                /* Was ACCESS type, becoming one of the TRUNK types. */
                if (bundle->vlan != -1) {
                    bcmsdk_del_access_ports(bundle->vlan, temp_pbm, false);
                }

                /* Add all new trunk VLANs. */
                config_all_vlans(s->vlan_mode, s->vlan,
                                 new_trunks, temp_pbm);

                /* Should have nothing else to do... */
                goto done;

            } else if (s->vlan_mode == PORT_VLAN_ACCESS) {
                /* Was one of the TRUNK types (trunk, native-tagged,
                 * or native-untagged), becoming ACCESS type. */
                unconfig_all_vlans(bundle->vlan_mode, bundle->vlan,
                                   bundle->trunks, temp_pbm);

                /* Add new access VLAN. */
                if (s->vlan != -1) {
                    bcmsdk_add_access_ports(s->vlan, temp_pbm, false);
                }

                /* Should have nothing else to do... */
                goto done;

            } else {
                /* Changing modes among one of the TRUNK types (trunk,
                 * native-tagged, or native-untagged). */

                /* Unconfigure old native tag settings first. */
                switch (bundle->vlan_mode) {
                case PORT_VLAN_NATIVE_TAGGED:
                    if (bundle->vlan != -1) {
                        bcmsdk_del_native_tagged_ports(bundle->vlan, temp_pbm);

                        /* If the native VLAN we just unconfigured is also listed
                         * explicitly as part of the trunks, need to add it back. */
                        if (bitmap_is_set(bundle->trunks, bundle->vlan)) {
                            bcmsdk_add_trunk_ports(bundle->vlan, temp_pbm);
                        }
                    }
                    break;
                case PORT_VLAN_NATIVE_UNTAGGED:
                    if (bundle->vlan != -1) {
                        bcmsdk_del_native_untagged_ports(bundle->vlan, temp_pbm);

                        /* If the native VLAN we just unconfigured is also listed
                         * explicitly as part of the trunks, need to add it back. */
                        if (bitmap_is_set(bundle->trunks, bundle->vlan)) {
                            bcmsdk_add_trunk_ports(bundle->vlan, temp_pbm);
                        }
                    }
                    break;
                case PORT_VLAN_ACCESS:
                case PORT_VLAN_TRUNK:
                default:
                    break;
                }

                /* Configure new native tag settings. */
                switch (s->vlan_mode) {
                case PORT_VLAN_NATIVE_TAGGED:
                    if (s->vlan != -1) {
                        bcmsdk_add_native_tagged_ports(s->vlan, temp_pbm);
                    }
                    break;
                case PORT_VLAN_NATIVE_UNTAGGED:
                    if (s->vlan != -1) {
                        bcmsdk_add_native_untagged_ports(s->vlan, temp_pbm);
                    }
                    break;
                case PORT_VLAN_ACCESS:
                case PORT_VLAN_TRUNK:
                default:
                    break;
                }
            } /* Changing modes among one of the TRUNK types */

        } else if (tag_changed) {
            /* VLAN mode didn't change, but VLAN tag changed. */
            switch (bundle->vlan_mode) {
            case PORT_VLAN_ACCESS:
                if (bundle->vlan != -1) {
                    bcmsdk_del_access_ports(bundle->vlan, temp_pbm, false);
                }
                if (s->vlan != -1) {
                    bcmsdk_add_access_ports(s->vlan, temp_pbm, false);
                }
                /* For ACCESS ports, nothing more to do. */
                goto done;
                break;
            case PORT_VLAN_NATIVE_TAGGED:
                if (bundle->vlan != -1) {
                    bcmsdk_del_native_tagged_ports(bundle->vlan, temp_pbm);
                    /* If the native VLAN we just unconfigured is also listed
                     * explicitly as part of the trunks, need to add it back. */
                    if (bitmap_is_set(bundle->trunks, bundle->vlan)) {
                        bcmsdk_add_trunk_ports(bundle->vlan, temp_pbm);
                    }
                }
                if (s->vlan != -1) {
                    bcmsdk_add_native_tagged_ports(bundle->vlan, temp_pbm);
                }
                break;
            case PORT_VLAN_NATIVE_UNTAGGED:
                if (bundle->vlan != -1) {
                    bcmsdk_del_native_untagged_ports(bundle->vlan, temp_pbm);
                    /* If the native VLAN we just unconfigured is also listed
                     * explicitly as part of the trunks, need to add it back. */
                    if (bitmap_is_set(bundle->trunks, bundle->vlan)) {
                        bcmsdk_add_trunk_ports(bundle->vlan, temp_pbm);
                    }
                }
                if (s->vlan != -1) {
                    bcmsdk_add_native_untagged_ports(bundle->vlan, temp_pbm);
                }
                break;
            case PORT_VLAN_TRUNK:
            default:
                break;
            }
        }

        /* Now that we've handled VLAN mode or VLAN tag changes, check &
           update the rest of TRUNK VLANs (tagged VLANs only). */
        if (s->vlan_mode != PORT_VLAN_ACCESS) {
            handle_trunk_vlan_changes(bundle->trunks, new_trunks, temp_pbm,
                                      bundle->vlan_mode, s->vlan_mode);
        }
    }

    /* Done with temp_pbm. */
    bcmsdk_destroy_pbmp(temp_pbm);

done:
    /* Done with VLAN configuration.  Save the new information. */
    bundle->vlan_mode = s->vlan_mode;
    bundle->vlan = s->vlan;
    if (bundle->pbm != NULL) {
        bcmsdk_destroy_pbmp(bundle->pbm);
    }
    bundle->pbm = all_pbm;
    if (bundle->trunks != NULL) {
        bitmap_free(bundle->trunks);
    }
    bundle->trunks = vlan_bitmap_clone(new_trunks);
    bundle->trunk_all_vlans = trunk_all_vlans;

    return 0;
}

static void
bundle_remove(struct ofport *port_ OVS_UNUSED)
{
    struct bcmsdk_provider_ofport_node *port =
        bcmsdk_provider_ofport_node_cast(port_);
    struct ofbundle *bundle = port->bundle;

    if (bundle) {
        bundle_del_port(port);
        if (list_is_empty(&bundle->ports)) {
            bundle_destroy(bundle);
        }
    }
}

static int
bundle_get(struct ofproto *ofproto_, void *aux, int *bundle_handle)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    struct ofbundle *bundle;

    bundle = bundle_lookup(ofproto, aux);
    if (bundle) {
        *bundle_handle = bundle->bond_hw_handle;
    } else {
        *bundle_handle = -1;
    }

    return 0;
}

/* VLANs. */

static int
set_vlan(struct ofproto *ofproto, int vid, bool add)
{
    struct ofbundle *bundle;
    struct bcmsdk_provider_node *bcm_ofproto = bcmsdk_provider_node_cast(ofproto);

    VLOG_DBG("%s: entry, vid=%d, oper=%s", __FUNCTION__, vid, (add ? "add":"del"));

    if (add) {
        /* Create VLAN first. */
        bcmsdk_create_vlan(vid, false);

        /* Add this VLAN to any port that's implicitly trunking all VLANs. */
        HMAP_FOR_EACH (bundle, hmap_node, &bcm_ofproto->bundles) {
            if (bundle->trunk_all_vlans) {
                bcmsdk_add_trunk_ports(vid, bundle->pbm);
                bitmap_set1(bundle->trunks, vid);
            }
        }

    } else {
        /* Delete this VLAN from any port that's implicitly trunking all VLANs. */
        HMAP_FOR_EACH (bundle, hmap_node, &bcm_ofproto->bundles) {
            if (bundle->trunk_all_vlans) {
                bitmap_set0(bundle->trunks, vid);
                bcmsdk_del_trunk_ports(vid, bundle->pbm);
            }
        }

        /* Delete VLAN. */
        bcmsdk_destroy_vlan(vid, false);
    }
    return 0;
}

/* Mirrors. */

static int
mirror_get_stats__(struct ofproto *ofproto OVS_UNUSED, void *aux OVS_UNUSED,
                   uint64_t *packets OVS_UNUSED, uint64_t *bytes OVS_UNUSED)
{
    return 0;
}

static bool
is_mirror_output_bundle(const struct ofproto *ofproto_ OVS_UNUSED, void *aux OVS_UNUSED)
{
    return false;
}

static void
forward_bpdu_changed(struct ofproto *ofproto_ OVS_UNUSED)
{
    return;
}

/* Ports. */

static struct bcmsdk_provider_ofport_node *
get_ofp_port(const struct bcmsdk_provider_node *ofproto, ofp_port_t ofp_port)
{
    struct ofport *ofport = ofproto_get_port(&ofproto->up, ofp_port);
    return ofport ? bcmsdk_provider_ofport_node_cast(ofport) : NULL;
}

static int
port_query_by_name(const struct ofproto *ofproto_, const char *devname,
                   struct ofproto_port *ofproto_port)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    const char *type = netdev_get_type_from_name(devname);

    VLOG_DBG("port_query_by_name - %s", devname);

    /* We must get the name and type from the netdev layer directly. */
    if (type) {
        const struct ofport *ofport;

        ofport = shash_find_data(&ofproto->up.port_by_name, devname);
        ofproto_port->ofp_port = ofport ? ofport->ofp_port : OFPP_NONE;
        ofproto_port->name = xstrdup(devname);
        ofproto_port->type = xstrdup(type);
        VLOG_DBG("get_ofp_port name= %s type= %s flow# %d",
                   ofproto_port->name, ofproto_port->type, ofproto_port->ofp_port);
        return 0;
    }
    return ENODEV;

}

static int
port_add(struct ofproto *ofproto_, struct netdev *netdev)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    const char *devname = netdev_get_name(netdev);

    sset_add(&ofproto->ports, devname);
    return 0;
}

static int
port_del(struct ofproto *ofproto_, ofp_port_t ofp_port)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    struct bcmsdk_provider_ofport_node *ofport OVS_UNUSED =
           get_ofp_port(ofproto, ofp_port);
    int error = 0;

    return error;
}

static int
port_get_stats(const struct ofport *ofport_, struct netdev_stats *stats)
{
    struct bcmsdk_provider_ofport_node *ofport =
           bcmsdk_provider_ofport_node_cast(ofport_);
    int error;

    error = netdev_get_stats(ofport->up.netdev, stats);

    if (!error && ofport_->ofp_port == OFPP_LOCAL) {
        struct bcmsdk_provider_node *ofproto =
               bcmsdk_provider_node_cast(ofport->up.ofproto);

        ovs_mutex_lock(&ofproto->stats_mutex);
        /* ofproto->stats.tx_packets represents packets that we created
         * internally and sent to some port
         * Account for them as if they had come from OFPP_LOCAL and
         * got forwarded.
         */

        if (stats->rx_packets != UINT64_MAX) {
            stats->rx_packets += ofproto->stats.tx_packets;
        }

        if (stats->rx_bytes != UINT64_MAX) {
            stats->rx_bytes += ofproto->stats.tx_bytes;
        }

        /* ofproto->stats.rx_packets represents packets that were received on
         * some port and we processed internally and dropped (e.g. STP).
         * Account for them as if they had been forwarded to OFPP_LOCAL.
         */

        if (stats->tx_packets != UINT64_MAX) {
            stats->tx_packets += ofproto->stats.rx_packets;
        }

        if (stats->tx_bytes != UINT64_MAX) {
            stats->tx_bytes += ofproto->stats.rx_bytes;
        }
        ovs_mutex_unlock(&ofproto->stats_mutex);
    }

    return error;
}

static int
port_dump_start(const struct ofproto *ofproto_ OVS_UNUSED, void **statep)
{
    VLOG_DBG("%s", __FUNCTION__);
    *statep = xzalloc(sizeof(struct bcmsdk_provider_port_dump_state));
    return 0;
}

static int
port_dump_next(const struct ofproto *ofproto_, void *state_,
               struct ofproto_port *port)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    struct bcmsdk_provider_port_dump_state *state = state_;
    const struct sset *sset;
    struct sset_node *node;

    if (state->has_port) {
        ofproto_port_destroy(&state->port);
        state->has_port = false;
    }
    sset = state->ghost ? &ofproto->ghost_ports : &ofproto->ports;
    while ((node = sset_at_position(sset, &state->bucket, &state->offset))) {
        int error;

        VLOG_DBG("port dump loop detecting port %s", node->name);

        error = port_query_by_name(ofproto_, node->name, &state->port);
        if (!error) {
            VLOG_DBG("port dump loop reporting port struct %s",
                       state->port.name);
            *port = state->port;
            state->has_port = true;
            return 0;
        } else if (error != ENODEV) {
            return error;
        }
    }

    if (!state->ghost) {
        state->ghost = true;
        state->bucket = 0;
        state->offset = 0;
        return port_dump_next(ofproto_, state_, port);
    }

    return EOF;
}

static int
port_dump_done(const struct ofproto *ofproto_ OVS_UNUSED, void *state_)
{
    struct bcmsdk_provider_port_dump_state *state = state_;
    VLOG_DBG("%s", __FUNCTION__);

    if (state->has_port) {
        ofproto_port_destroy(&state->port);
    }
    free(state);
    return 0;
}

static struct bcmsdk_provider_rule
              *bcmsdk_provider_rule_cast(const struct rule *rule OVS_UNUSED)
{
    return NULL;
}

static struct rule *
rule_alloc(void)
{
    struct bcmsdk_provider_rule *rule = xmalloc(sizeof *rule);
    return &rule->up;
}

static void
rule_dealloc(struct rule *rule_)
{
    struct bcmsdk_provider_rule *rule = bcmsdk_provider_rule_cast(rule_);
    free(rule);
}

static enum ofperr
rule_construct(struct rule *rule_ OVS_UNUSED)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    return 0;
}

static enum ofperr
rule_insert(struct rule *rule_ OVS_UNUSED)
    OVS_REQUIRES(ofproto_mutex)
{
    return 0;
}

static void
rule_delete(struct rule *rule_ OVS_UNUSED)
    OVS_REQUIRES(ofproto_mutex)
{
    return;
}

static void
rule_destruct(struct rule *rule_ OVS_UNUSED)
{
    return;
}

static void
rule_get_stats(struct rule *rule_ OVS_UNUSED, uint64_t *packets OVS_UNUSED,
               uint64_t *bytes OVS_UNUSED, long long int *used OVS_UNUSED)
{
    return;
}

static enum ofperr
rule_execute(struct rule *rule OVS_UNUSED, const struct flow *flow OVS_UNUSED,
             struct ofpbuf *packet OVS_UNUSED)
{
    return 0;
}

static void
rule_modify_actions(struct rule *rule_ OVS_UNUSED, bool reset_counters OVS_UNUSED)
    OVS_REQUIRES(ofproto_mutex)
{
    return;
}

static struct bcmsdk_provider_group
              *bcmsdk_provider_group_cast(const struct ofgroup *group)
{
    return group ?
           CONTAINER_OF(group, struct bcmsdk_provider_group, up) : NULL;
}

static struct ofgroup *
group_alloc(void)
{
    struct bcmsdk_provider_group *group = xzalloc(sizeof *group);
    return &group->up;
}

static void
group_dealloc(struct ofgroup *group_)
{
    struct bcmsdk_provider_group *group = bcmsdk_provider_group_cast(group_);
    free(group);
}

static enum ofperr
group_construct(struct ofgroup *group_ OVS_UNUSED)
{
    return 0;
}

static void
group_destruct(struct ofgroup *group_ OVS_UNUSED)
{
    return;
}

static enum ofperr
group_modify(struct ofgroup *group_ OVS_UNUSED)
{
    return 0;
}

static enum ofperr
group_get_stats(const struct ofgroup *group_ OVS_UNUSED,
                struct ofputil_group_stats *ogs OVS_UNUSED)
{
    return 0;
}

static const char *
get_datapath_version(const struct ofproto *ofproto_ OVS_UNUSED)
{
    return bcmsdk_datapath_version();
}

static bool
set_frag_handling(struct ofproto *ofproto_ OVS_UNUSED,
                  enum ofp_config_flags frag_handling OVS_UNUSED)
{
    return false;
}

static enum ofperr
packet_out(struct ofproto *ofproto_ OVS_UNUSED, struct ofpbuf *packet OVS_UNUSED,
           const struct flow *flow OVS_UNUSED,
           const struct ofpact *ofpacts OVS_UNUSED, size_t ofpacts_len OVS_UNUSED)
{
    return 0;
}

static void
get_netflow_ids(const struct ofproto *ofproto_ OVS_UNUSED,
                uint8_t *engine_type OVS_UNUSED, uint8_t *engine_id OVS_UNUSED)
{
    return;
}

/* Ft to add l3 host entry */
static int
add_l3_host_entry(const struct ofproto *ofproto_, void *aux,
                  bool is_ipv6_addr, char *ip_addr,
                  char *next_hop_mac_addr, int *l3_egress_id)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    struct ofbundle *port_bundle;
    int rc = 0;

    port_bundle = bundle_lookup(ofproto, aux);
    if ( (port_bundle == NULL) ||
         (port_bundle->l3_intf == NULL) ) {
        VLOG_ERR("Failed to get port bundle/l3_intf not configured");
        return 1; /* Return error */
    }

    rc = ops_routing_add_host_entry(port_bundle->hw_unit, port_bundle->hw_port,
                                   ofproto->vrf_id, is_ipv6_addr,
                                   ip_addr, next_hop_mac_addr,
                                   port_bundle->l3_intf->l3a_intf_id,
                                   l3_egress_id,
                                   port_bundle->l3_intf->l3a_vid);
    if (rc) {
        VLOG_ERR("Failed to add L3 host entry for ip %s", ip_addr);
    }


    return rc;
} /* add_l3_host_entry */

/* Ft to delete l3 host entry */
static int
delete_l3_host_entry(const struct ofproto *ofproto_, void *aux,
                     bool is_ipv6_addr, char *ip_addr, int *l3_egress_id)

{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    struct ofbundle *port_bundle;
    int rc = 0;

    port_bundle = bundle_lookup(ofproto, aux);
    if (port_bundle == NULL) {
        VLOG_ERR("Failed to get port bundle");
        return 1; /* Return error */
    }

    rc = ops_routing_delete_host_entry(port_bundle->hw_unit,
                                      port_bundle->hw_port,
                                      ofproto->vrf_id, is_ipv6_addr, ip_addr,
                                      l3_egress_id);
    if (rc) {
        VLOG_ERR("Failed to delete L3 host entry for ip %s", ip_addr);
    }

    return rc;
} /* delete_l3_host_entry */

/* Ft to get BCM host data-path hit-bit */
static int
get_l3_host_hit_bit(const struct ofproto *ofproto_, void *aux,
                    bool is_ipv6_addr, char *ip_addr, bool *hit_bit)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);
    struct ofbundle *port_bundle;
    int rc = 0;

    port_bundle = bundle_lookup(ofproto, aux);
    if (port_bundle == NULL) {
        VLOG_ERR("Failed to get port bundle");
        return 1; /* Return error */
    }

    rc = ops_routing_get_host_hit(port_bundle->hw_unit, ofproto->vrf_id,
                                 is_ipv6_addr, ip_addr, hit_bit);
    if (rc) {
        VLOG_ERR("Failed to get L3 host hit for ip %s", ip_addr);
    }

    return rc;
} /* netdev_bcmsdk_get_host_hit */

/* Function to add, update, delete l3 route */
static int
l3_route_action(const struct ofproto *ofprotop,
                enum ofproto_route_action action,
                struct ofproto_route *routep)
{
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofprotop);

    return ops_routing_route_entry_action(0, ofproto->vrf_id, action, routep);
}

/* Function to enable/disable ECMP */
int
l3_ecmp_set(const struct ofproto *ofprotop, bool enable)
{
    return ops_routing_ecmp_set(0, enable);
}

/* Function to enable/disable ECMP hash configs */
int
l3_ecmp_hash_set(const struct ofproto *ofprotop, unsigned int hash, bool enable)
{
    return ops_routing_ecmp_hash_set(0, hash, enable);
}

const struct ofproto_class ofproto_bcm_provider_class = {
    init,
    enumerate_types,
    enumerate_names,
    del,
    port_open_type,
    NULL,                       /* may implement type_run */
    NULL,                       /* may implement type_wait */
    alloc,
    construct,
    destruct,
    dealloc,
    run,
    wait,
    NULL,                       /* get_memory_usage */
    NULL,                       /* may implement type_get_memory_usage */
    NULL,                       /* may implement flush */
    query_tables,
    port_alloc,
    port_construct,
    port_destruct,
    port_dealloc,
    NULL,                       /* may implement port_modified */
    port_reconfigured,
    port_query_by_name,
    port_add,
    port_del,
    port_get_stats,
    port_dump_start,
    port_dump_next,
    port_dump_done,
    NULL,                       /* may implement port_poll */
    NULL,                       /* may implement port_poll_wait */
    NULL,                       /* may implement port_is_lacp_current */
    NULL,                       /* may implement port_get_lacp_stats */
    NULL,                       /* rule_choose_table */
    rule_alloc,
    rule_construct,
    rule_insert,
    rule_delete,
    rule_destruct,
    rule_dealloc,
    rule_get_stats,
    rule_execute,
    NULL,                       /* rule_premodify_actions */
    rule_modify_actions,
    set_frag_handling,
    packet_out,
    NULL,                       /* may implement set_netflow */
    get_netflow_ids,
    NULL,                       /* may implement set_sflow */
    NULL,                       /* may implement set_ipfix */
    NULL,                       /* may implement set_cfm */
    cfm_status_changed,
    NULL,                       /* may implement get_cfm_status */
    NULL,                       /* may implement set_bfd */
    bfd_status_changed,
    NULL,                       /* may implement get_bfd_status */
    NULL,                       /* may implement set_stp */
    NULL,                       /* may implement get_stp_status */
    NULL,                       /* may implement set_stp_port */
    NULL,                       /* may implement get_stp_port_status */
    NULL,                       /* may implement get_stp_port_stats */
    NULL,                       /* may implement set_rstp */
    NULL,                       /* may implement get_rstp_status */
    NULL,                       /* may implement set_rstp_port */
    NULL,                       /* may implement get_rstp_port_status */
    NULL,                       /* may implement set_queues */
    bundle_set,
    bundle_remove,
    bundle_get,
    set_vlan,
    NULL,                       /* may implement mirror_set__ */
    mirror_get_stats__,
    NULL,                       /* may implement set_flood_vlans */
    is_mirror_output_bundle,
    forward_bpdu_changed,
    NULL,                       /* may implement set_mac_table_config */
    NULL,                       /* may implement set_mcast_snooping */
    NULL,                       /* may implement set_mcast_snooping_port */
    NULL,                       /* set_realdev, is unused */
    NULL,                       /* meter_get_features */
    NULL,                       /* meter_set */
    NULL,                       /* meter_get */
    NULL,                       /* meter_del */
    group_alloc,                /* group_alloc */
    group_construct,            /* group_construct */
    group_destruct,             /* group_destruct */
    group_dealloc,              /* group_dealloc */
    group_modify,               /* group_modify */
    group_get_stats,            /* group_get_stats */
    get_datapath_version,       /* get_datapath_version */
    add_l3_host_entry,          /* Add l3 host entry */
    delete_l3_host_entry,       /* Delete l3 host entry */
    get_l3_host_hit_bit,        /* Get l3 host entry hit bits */
    l3_route_action,            /* l3 route action - install, update, delete */
    l3_ecmp_set,                /* enable/disable ECMP globally */
    l3_ecmp_hash_set,           /* enable/disable ECMP hash configs */
};
