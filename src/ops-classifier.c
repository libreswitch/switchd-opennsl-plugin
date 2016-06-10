/*
 * Copyright (C) 2015, 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <util.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <openvswitch/vlog.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/switch.h>
#include <opennsl/vlan.h>
#include <opennsl/l3.h>
#include <opennsl/l2.h>
#include <ofproto/ofproto.h>
#include <ovs/list.h>
#include <opennsl/port.h>
#include <opennsl/field.h>
#include <opennsl/rx.h>

#include <ofproto/ofproto-provider.h>
#include <openvswitch/types.h>
#include <openvswitch/vlog.h>
#include <uuid.h>

#include "bcm.h"
#include "netdev-bcmsdk.h"
/* Broadcom provider */
#include "ofproto-bcm-provider.h"
#include "ops-copp.h"
#include "ops-knet.h"
#include "ops-cls-asic-plugin.h"
#include "platform-defines.h"
#include "plugin-extensions.h"
#include "seq.h"
#include "ops-classifier.h"
#include "mac-learning-plugin.h" /* PORT_NAME_SIZE */

/* Private header for ACL data structure */
#include "ops-classifier-private.h"

#define ACL_LOGGING_MIN_MS_BETWEEN_PKTS 1000 /**< ignore ACL logging packets
                                               received within this many ms of
                                               the previous packet */

/** Define a module for VLOG_ functionality */
VLOG_DEFINE_THIS_MODULE(ops_classifier);

/* hash map to store ACL */
struct hmap classifier_map;

/* IFP slice for ipv4 ACL */
opennsl_field_group_t ip_group[MAX_SWITCH_UNITS];

/* keeps track of installed IPV4 ACL rules in IFP slice  */
int cls_ingress_ipv4_rule_count[MAX_SWITCH_UNITS];

/*
 * ops_cls_get_ingress_group_id_for_hw_unit
 *
* This function returns the group-id for the Classifier ingress FP rules for
* the given hardware unit.
*/
opennsl_field_group_t ops_cls_get_ingress_group_id_for_hw_unit(int unit)
{
    if (!ip_group[unit] || unit < 0) {
        return(-1);
    }

    return(ip_group[unit]);
}

/**
 * Function pointer to handle ACL logging packet data set functionality.
 * A callback is registered from PI at the init time to this function.
 * PD code needs to call this function when logging ACL packets.
 */
void (*acl_pd_log_pkt_data_set)(struct acl_log_info *);

/**************************************************************************//**
 * OPS_CLS plugin interface definition. This is the instance containing all
 * implementations of ops_cls plugin on this platform.
 *****************************************************************************/
static struct ops_cls_plugin_interface ops_cls_plugin = {
    ops_cls_opennsl_apply,
    ops_cls_opennsl_remove,
    ops_cls_opennsl_replace,
    ops_cls_opennsl_list_update,
    ops_cls_opennsl_statistics_get,
    ops_cls_opennsl_statistics_clear,
    ops_cls_opennsl_statistics_clear_all,
    ops_cls_opennsl_acl_log_pkt_register_cb
};

/**************************************************************************//**
 * Ofproto plugin extension for OPS_CLS plugin. Holds the name, version and
 * plugin interface information.
 *****************************************************************************/
static struct plugin_extension_interface ops_cls_extension = {
    OPS_CLS_ASIC_PLUGIN_INTERFACE_NAME,
    OPS_CLS_ASIC_PLUGIN_INTERFACE_MAJOR,
    OPS_CLS_ASIC_PLUGIN_INTERFACE_MINOR,
    (void *)&ops_cls_plugin
};

/*
 * Init function (IFP initialization)
 */
int
ops_classifier_init(int unit)
{
    int rc;
    opennsl_field_qset_t qset;
    int knet_acl_log_filter_id;

     /* Initialize QSET */
    OPENNSL_FIELD_QSET_INIT(qset);

    /* Select IFP and create group*/

    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyStageIngress);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyInPorts);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifySrcIp);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyDstIp);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyIpProtocol);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyL4SrcPort);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyL4DstPort);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyRangeCheck);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyL3Routable);
    OPENNSL_FIELD_QSET_ADD(qset, opennslFieldQualifyEtherType);

    rc = opennsl_field_group_create(unit, qset, OPS_GROUP_PRI_IPv4, &ip_group[unit]);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to create group: unit=%d, group= %d,  rc=%s",
                 unit, ip_group[unit], opennsl_errmsg(rc));
         return rc;
    } else {
        VLOG_DBG("Created group %d successfully", ip_group[unit]);
    }

    bcmsdk_knet_acl_logging_filter_create("AclLog", &knet_acl_log_filter_id);
    VLOG_DBG("ACL logging knet filter id: %d", knet_acl_log_filter_id);

    /* Initialize the classifier hash map */
    hmap_init(&classifier_map);

    cls_ingress_ipv4_rule_count[unit] = 0;

    return rc;
}

/*
 * Classifier lookup in hash table
 */
static struct ops_classifier*
ops_cls_lookup(const struct uuid *cls_id)
{
    struct ops_classifier *cls = NULL;

    uint32_t id = uuid_hash(cls_id);

    HMAP_FOR_EACH_WITH_HASH(cls, node, id, &classifier_map) {
        if (uuid_equals(&cls->id, cls_id)) {
            return cls;
        }
    }
    return NULL;
}

/*
 * Copy classifier rule entries and store in list
 */
static void
ops_cls_populate_entries(struct ops_classifier  *cls,
                         struct ovs_list        *list,
                         struct ops_cls_list    *clist)
{
    for (int i = 0; i < clist->num_entries; i++) {
        struct ops_cls_entry *entry =
            xzalloc(sizeof(struct ops_cls_entry));
        struct ops_cls_list_entry *cls_entry = &clist->entries[i];

        memcpy(&entry->entry_fields, &cls_entry->entry_fields,
               sizeof(struct ops_cls_list_entry_match_fields));
        memcpy(&entry->entry_actions, &cls_entry->entry_actions,
                sizeof(struct ops_cls_list_entry_actions));

        list_push_back(list, &entry->node);
    }
}

/*
 * Clean up classifier rule entries
 */
static void
ops_cls_cleanup_entries(struct ovs_list *list)
{
    struct ops_cls_entry *entry = NULL, *next_entry;

    LIST_FOR_EACH_SAFE (entry, next_entry,  node, list) {
        list_remove(&entry->node);
        free(entry);
    }
}

/*
 * Initialize orig list
 */
static void
ops_cls_init_orig_list(struct ops_cls_hw_info *hw_cls)
{
    list_init(&hw_cls->rule_index_list);
    list_init(&hw_cls->stats_index_list);
    list_init(&hw_cls->range_index_list);
}

/*
 * Initialize update list
 */
static void
ops_cls_init_update_list(struct ops_cls_hw_info *hw_cls)
{
    list_init(&hw_cls->rule_index_update_list);
    list_init(&hw_cls->stats_index_update_list);
    list_init(&hw_cls->range_index_update_list);
}

/*
 * Initialize list for port, routed,  clasiifier
 */
static void
ops_cls_init_hw_info(struct ops_cls_hw_info *hw_cls)
{
    hw_cls->in_asic = false;
    OPENNSL_PBMP_CLEAR(hw_cls->pbmp);

    ops_cls_init_orig_list(hw_cls);
    ops_cls_init_update_list(hw_cls);
}

/*
 * Add classifier in hash (key uuid)
 */
static struct ops_classifier*
ops_cls_add(struct ops_cls_list  *clist)
{
    struct ops_classifier *cls;

    if (!clist) {
        return NULL;
    }

    cls = xzalloc(sizeof(struct ops_classifier));

    cls->id = clist->list_id;
    cls->name = xstrdup(clist->list_name);
    cls->type = clist->list_type;

    list_init(&cls->cls_entry_list);
    list_init(&cls->cls_entry_update_list);

    /* Init classifer hardware list entry list */
    ops_cls_init_hw_info(&cls->port_cls);
    ops_cls_init_hw_info(&cls->route_cls);

    if (clist->num_entries > 0) {
        VLOG_DBG("%s has %d rule entries", cls->name, clist->num_entries);
        ops_cls_populate_entries(cls, &cls->cls_entry_list, clist);
    }

    hmap_insert(&classifier_map, &cls->node, uuid_hash(&clist->list_id));

    VLOG_DBG("Added classifer %s in hashmap", cls->name);
    return cls;
}

/*
 * Delete classifier rule entries
 */
static void
ops_cls_delete_rule_entries(struct ovs_list *list)
{
    struct ops_cls_rule_entry *entry, *next_entry;

    LIST_FOR_EACH_SAFE (entry, next_entry,  node, list) {
        list_remove(&entry->node);
        free(entry);
    }

}

/*
 * Delete stats entries
 */
static void
ops_cls_delete_stats_entries(struct ovs_list *list)
{
    struct ops_cls_stats_entry *sentry = NULL, *next_sentry;

    LIST_FOR_EACH_SAFE (sentry, next_sentry,  node, list) {
        list_remove(&sentry->node);
        free(sentry);
    }

}

/*
 * Delete range entries
 */
static void
ops_cls_delete_range_entries(struct ovs_list *list)
{
    struct ops_cls_range_entry *rentry = NULL, *next_rentry;

    LIST_FOR_EACH_SAFE (rentry, next_rentry,  node, list) {
        list_remove(&rentry->node);
        free(rentry);
    }
}

/*
 * Delete original entires of classifier
 */
static void
ops_cls_delete_orig_entries(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    ops_cls_delete_rule_entries(&cls->port_cls.rule_index_list);
    ops_cls_delete_stats_entries(&cls->port_cls.stats_index_list);
    ops_cls_delete_range_entries(&cls->port_cls.range_index_list);

    ops_cls_delete_rule_entries(&cls->route_cls.rule_index_list);
    ops_cls_delete_stats_entries(&cls->route_cls.stats_index_list);
    ops_cls_delete_range_entries(&cls->route_cls.range_index_list);

    ops_cls_cleanup_entries(&cls->cls_entry_list);
}

/*
 * Delete updated entries of classifier
 */

static void
ops_cls_delete_updated_entries(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    ops_cls_delete_rule_entries(&cls->port_cls.rule_index_update_list);
    ops_cls_delete_stats_entries(&cls->port_cls.stats_index_update_list);
    ops_cls_delete_range_entries(&cls->port_cls.range_index_update_list);

    ops_cls_delete_rule_entries(&cls->route_cls.rule_index_update_list);
    ops_cls_delete_stats_entries(&cls->route_cls.stats_index_update_list);
    ops_cls_delete_range_entries(&cls->route_cls.range_index_update_list);

    ops_cls_cleanup_entries(&cls->cls_entry_update_list);
}


/*
 * Delete classifier from hash table
 */
static void
ops_cls_delete(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    ops_cls_delete_orig_entries(cls);
    ops_cls_delete_updated_entries(cls);

    hmap_remove(&classifier_map, &cls->node);
    VLOG_DBG("Removed ACL %s in hashmap", cls->name);
    free(cls->name);
    free(cls);
}

/*
 * Update hardware info list
 */
static void
ops_cls_update_hw_info(struct ops_cls_hw_info *hw_info)
{
    list_move(&hw_info->rule_index_list, &hw_info->rule_index_update_list);
    list_move(&hw_info->stats_index_list, &hw_info->stats_index_update_list);
    list_move(&hw_info->range_index_list, &hw_info->range_index_update_list);
}

/*
 * Assign updated entries of classifer to original entires
 */

static void
ops_cls_update_entries(struct ops_classifier *cls)
{
    if (!cls) {
        return;
    }

    /* move the installed update entries to original list */
    ops_cls_update_hw_info(&cls->port_cls);
    ops_cls_update_hw_info(&cls->route_cls);
    list_move(&cls->cls_entry_list, &cls->cls_entry_update_list);

    /* reinitialize update list for next update */
    ops_cls_init_update_list(&cls->port_cls);
    ops_cls_init_update_list(&cls->route_cls);
    list_init(&cls->cls_entry_update_list);
}

/*
 * Get port(s) from bundle and add to bit map
 */
static int
ops_cls_get_port_bitmap(struct ofproto *ofproto_,
                        void           *aux,
                        int            *hw_unit,
                        opennsl_pbmp_t *pbmp)
{
    int unit = 0;
    int hw_port;
    struct bcmsdk_provider_node *ofproto = bcmsdk_provider_node_cast(ofproto_);

    struct ofbundle *bundle = bundle_lookup(ofproto, aux);
    if (bundle == NULL) {
        VLOG_ERR("Failed to get port bundle");
        return OPS_CLS_FAIL;
    }

    struct bcmsdk_provider_ofport_node *port, *next_port;
    LIST_FOR_EACH_SAFE (port, next_port, bundle_node, &bundle->ports) {
        netdev_bcmsdk_get_hw_info(port->up.netdev, &unit, &hw_port, NULL);
        VLOG_DBG("Hardware unit: %d, Hardware port: %d\n", unit, hw_port);
        OPENNSL_PBMP_PORT_ADD(*pbmp, hw_port);
    }

    if (OPENNSL_PBMP_IS_NULL(*pbmp)) {
        VLOG_ERR("Port bundle has no ports");
        return OPS_CLS_FAIL;
    }

    *hw_unit = unit;
    return OPS_CLS_OK;
}

/*
 * Set rule action
 */
static int
ops_cls_set_action(int                          unit,
                   opennsl_field_entry_t        entry,
                   struct ops_classifier       *cls,
                   struct ops_cls_entry        *cls_entry,
                   int                         *stat_index,
                   bool                        *isStatEnabled)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_field_stat_t stats_type = opennslFieldStatPackets;
    int stat_id;

    VLOG_DBG("Classifier list entry action flag: 0x%x", cls_entry->act_flags);

    if (cls_entry->act_flags & OPS_CLS_ACTION_DENY) {
        rc = opennsl_field_action_add(unit, entry, opennslFieldActionDrop,
                                      0, 0);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set drop action at entry 0x%x: rc=%s", entry,
                     opennsl_errmsg(rc));
            return rc;
        } else {
            VLOG_DBG("Drop action added at entry 0x%x.", entry);
        }
    }

    if (cls_entry->act_flags & OPS_CLS_ACTION_COUNT) {
        rc = opennsl_field_stat_create(unit, ip_group[unit], 1, &stats_type, &stat_id);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to create stats for ACL %s at entry 0x%x rc=%s",
                     cls->name, entry, opennsl_errmsg(rc));
            return rc;
        } else {
            VLOG_DBG("Stat index %d attached to entry 0x%x.", stat_id, entry);
        }

        rc = opennsl_field_entry_stat_attach(unit, entry, stat_id);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to attach stats %d to entry 0x%x in ACL %s rc=%s",
                     stat_id, entry, cls->name, opennsl_errmsg(rc));
            rc = opennsl_field_stat_destroy(unit, stat_id);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to destroy stats %d for ACL %s rc=%s",
                          stat_id, cls->name, opennsl_errmsg(rc));
            }
            return rc;
        }

        VLOG_DBG("Attached stats %d to entry 0x%x in ACL %s",
                 stat_id, entry, cls->name);

        *stat_index = stat_id;
        *isStatEnabled = TRUE;
    }

    if (cls_entry->act_flags & OPS_CLS_ACTION_LOG) {
        rc = opennsl_field_action_add(unit, entry, opennslFieldActionCopyToCpu,
                                      1, ACL_LOG_RULE_ID);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set copy action at entry 0x%x: rc=%s", entry,
                     opennsl_errmsg(rc));
            return rc;
        } else {
            rc = opennsl_field_action_add(unit, entry,
                                          opennslFieldActionCosQCpuNew,
                                          OPS_COPP_QOS_QUEUE_ACL_LOGGING, 0);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to set queue for copy action at entry 0x%x: "
                         "rc=%s", entry, opennsl_errmsg(rc));
                return rc;
            } else {
                VLOG_DBG("Log action added at entry 0x%x", entry);
            }
        }
    }

    return rc;
}

/*
 * Display ports
 */
static char*
ops_cls_display_port_bit_map(opennsl_pbmp_t *pbmp,
                             char           *buffer,
                             int             bufsize)
{
    int offset = 0, count;
    opennsl_port_t port;

    memset(buffer, 0 ,bufsize);
    OPENNSL_PBMP_ITER(*pbmp, port) {
        count = snprintf(buffer + offset, bufsize - offset, "%d ", port);
        if (count >= bufsize - offset) {
            buffer[bufsize-1] = '\0';
            break;
        }
        offset += count;
    }
    return buffer;
}

/*
 * Set PI error code
 */
static void
ops_cls_set_pd_status(int                        rc,
                      int                        fail_index,
                      struct ops_cls_pd_status  *pd_status)
{

    VLOG_DBG("ops classifier error: %d ", rc);
    pd_status->entry_id = fail_index;

    switch (rc) {
    case OPENNSL_E_INTERNAL:
        pd_status->status_code = OPS_CLS_STATUS_HW_INTERNAL_ERR;
        break;
    case OPENNSL_E_MEMORY:
        pd_status->status_code = OPS_CLS_STATUS_HW_MEMORY_ERR;
        break;
    case OPENNSL_E_UNIT:
        pd_status->status_code = OPS_CLS_STATUS_HW_UNIT_ERR;
        break;
    case OPENNSL_E_PARAM:
        pd_status->status_code = OPS_CLS_STATUS_HW_PARAM_ERR;
        break;
    case OPENNSL_E_EMPTY:
        pd_status->status_code = OPS_CLS_STATUS_HW_EMPTY_ERR;
        break;
    case OPENNSL_E_FULL:
        pd_status->status_code = OPS_CLS_STATUS_HW_FULL_ERR;
        break;
    case OPENNSL_E_NOT_FOUND:
        pd_status->status_code = OPS_CLS_STATUS_HW_NOT_FOUND_ERR;
        break;
    case OPENNSL_E_EXISTS:
        pd_status->status_code = OPS_CLS_STATUS_HW_EXISTS_ERR;
        break;
    case OPENNSL_E_TIMEOUT:
        pd_status->status_code = OPS_CLS_STATUS_HW_TIMEOUT_ERR;
        break;
    case OPENNSL_E_BUSY:
        pd_status->status_code = OPS_CLS_STATUS_HW_BUSY_ERR;
        break;
    case OPS_CLS_FAIL:
    case OPENNSL_E_FAIL:
        pd_status->status_code = OPS_CLS_STATUS_HW_FAIL_ERR;
        break;
    case OPENNSL_E_DISABLED:
        pd_status->status_code = OPS_CLS_STATUS_HW_DISABLED_ERR;
        break;
    case OPENNSL_E_BADID:
        pd_status->status_code = OPS_CLS_STATUS_HW_BADID_ERR;
        break;
    case OPENNSL_E_RESOURCE:
        pd_status->status_code = OPS_CLS_STATUS_HW_RESOURCE_ERR;
        break;
    case OPENNSL_E_CONFIG:
        pd_status->status_code = OPS_CLS_STATUS_HW_CONFIG_ERR;
        break;
    case OPENNSL_E_UNAVAIL:
        pd_status->status_code = OPS_CLS_STATUS_HW_UNAVAIL_ERR;
        break;
    case OPENNSL_E_INIT:
        pd_status->status_code = OPS_CLS_STATUS_HW_INIT_ERR;
        break;
    case OPENNSL_E_PORT:
        pd_status->status_code = OPS_CLS_STATUS_HW_PORT_ERR;
        break;
    case OPS_CLS_HW_UNSUPPORTED_ERR:
        pd_status->status_code = OPS_CLS_STATUS_HW_UNSUPPORTED_ERR;
        break;
    case OPS_CLS_LIST_PARSE_ERR:
        pd_status->status_code = OPS_CLS_STATUS_LIST_PARSE_ERR;
        break;
    default:
        pd_status->status_code = OPS_CLS_STATUS_HW_UNKNOWN_ERR;
        VLOG_DBG("Unsupported (%d) error type", rc);
        break;
    }
}

/*
 * Set PI (list) error code
 */
static void
ops_cls_set_pd_list_status(int                             rc,
                           int                             fail_index,
                           struct ops_cls_pd_list_status  *status)
{

    VLOG_DBG("ops list error: %d ", rc);
    status->entry_id = fail_index;

    switch (rc) {
    case OPENNSL_E_INTERNAL:
        status->status_code = OPS_CLS_STATUS_HW_INTERNAL_ERR;
        break;
    case OPENNSL_E_MEMORY:
        status->status_code = OPS_CLS_STATUS_HW_MEMORY_ERR;
        break;
    case OPENNSL_E_UNIT:
        status->status_code = OPS_CLS_STATUS_HW_UNIT_ERR;
        break;
    case OPENNSL_E_PARAM:
        status->status_code = OPS_CLS_STATUS_HW_PARAM_ERR;
        break;
    case OPENNSL_E_EMPTY:
        status->status_code = OPS_CLS_STATUS_HW_EMPTY_ERR;
        break;
    case OPENNSL_E_FULL:
        status->status_code = OPS_CLS_STATUS_HW_FULL_ERR;
        break;
    case OPENNSL_E_NOT_FOUND:
        status->status_code = OPS_CLS_STATUS_HW_NOT_FOUND_ERR;
        break;
    case OPENNSL_E_EXISTS:
        status->status_code = OPS_CLS_STATUS_HW_EXISTS_ERR;
        break;
    case OPENNSL_E_TIMEOUT:
        status->status_code = OPS_CLS_STATUS_HW_TIMEOUT_ERR;
        break;
    case OPENNSL_E_BUSY:
        status->status_code = OPS_CLS_STATUS_HW_BUSY_ERR;
        break;
    case OPS_CLS_FAIL:
    case OPENNSL_E_FAIL:
        status->status_code = OPS_CLS_STATUS_HW_FAIL_ERR;
        break;
    case OPENNSL_E_DISABLED:
        status->status_code = OPS_CLS_STATUS_HW_DISABLED_ERR;
        break;
    case OPENNSL_E_BADID:
        status->status_code = OPS_CLS_STATUS_HW_BADID_ERR;
        break;
    case OPENNSL_E_RESOURCE:
        status->status_code = OPS_CLS_STATUS_HW_RESOURCE_ERR;
        break;
    case OPENNSL_E_CONFIG:
        status->status_code = OPS_CLS_STATUS_HW_CONFIG_ERR;
        break;
    case OPENNSL_E_UNAVAIL:
        status->status_code = OPS_CLS_STATUS_HW_UNAVAIL_ERR;
        break;
    case OPENNSL_E_INIT:
        status->status_code = OPS_CLS_STATUS_HW_INIT_ERR;
        break;
    case OPENNSL_E_PORT:
        status->status_code = OPS_CLS_STATUS_HW_PORT_ERR;
        break;
    case OPS_CLS_HW_UNSUPPORTED_ERR:
        status->status_code = OPS_CLS_STATUS_HW_UNSUPPORTED_ERR;
        break;
    case OPS_CLS_LIST_PARSE_ERR:
        status->status_code = OPS_CLS_STATUS_LIST_PARSE_ERR;
        break;
    default:
        status->status_code = OPS_CLS_STATUS_HW_UNKNOWN_ERR;
        VLOG_DBG("Unsupported (%d) error type", rc);
        break;
    }
}

/*
 * Get the source port range from classifier
 */
static void
ops_cls_get_src_port_range(struct ops_cls_list_entry_match_fields *field,
                           uint16_t                               *port_min,
                           uint16_t                               *port_max)
{
    if(field->L4_src_port_op == OPS_CLS_L4_PORT_OP_RANGE) {
        *port_min = field->L4_src_port_min;
        *port_max = field->L4_src_port_max;
    } else if (field->L4_src_port_op == OPS_CLS_L4_PORT_OP_RANGE) {
        *port_min = 0;
        *port_max = field->L4_src_port_max;
    } else {
        *port_min = field->L4_src_port_min;
        *port_max = 65535;
    }
}

/*
 * Get the destination port range from classifier
 */
static void
ops_cls_get_dst_port_range(struct ops_cls_list_entry_match_fields *field,
                           uint16_t                               *port_min,
                           uint16_t                               *port_max)
{
    if(field->L4_dst_port_op == OPS_CLS_L4_PORT_OP_RANGE) {
        *port_min = field->L4_dst_port_min;
        *port_max = field->L4_dst_port_max;
    } else if (field->L4_dst_port_op == OPS_CLS_L4_PORT_OP_RANGE) {
        *port_min = 0;
        *port_max = field->L4_dst_port_max;
    } else {
        *port_min = field->L4_dst_port_min;
        *port_max = 65535;
    }
}

/*
 * Add rule in FP
 */
static int
ops_cls_install_rule_in_asic(int                            unit,
                             struct ops_classifier         *cls,
                             struct ops_cls_entry          *cls_entry,
                             opennsl_pbmp_t                *pbmp,
                             int                            index,
                             struct ops_cls_interface_info *intf_info,
                             bool                           isUpdate)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    opennsl_field_entry_t entry;
    opennsl_field_range_t src_range, dst_range;
    opennsl_pbmp_t pbmp_mask;
    uint16_t port_mask = 0xFFFF;
    uint8_t protocol_mask = 0XFF;
    uint16_t min_port, max_port;
    int stat_index = 0;
    bool statEnabled = FALSE;
    bool src_rangeEnabled = FALSE;
    bool dst_rangeEnabled = FALSE;
    struct ops_cls_rule_entry *rulep;
    struct ops_cls_stats_entry *sentry;
    struct ops_cls_range_entry *rentry;
    struct ovs_list *listp;
    struct ops_cls_hw_info *hw_info;

    struct ops_cls_list_entry_match_fields *match = &cls_entry->entry_fields;


    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        hw_info = &cls->route_cls;
    } else {
        hw_info = &cls->port_cls;
    }

    /* According to vswitch.xml:
     * 'If no action is specified the ACE will not be programmed in hw.'
     */
    if (!cls_entry->act_flags) {
        return rc;
    }

    if (cls_ingress_ipv4_rule_count[unit] >= MAX_INGRESS_IPv4_ACL_RULES) {
        VLOG_ERR("ACEs max entry count reached");
        return OPS_CLS_FAIL;
    }

    rc = opennsl_field_entry_create(unit, ip_group[unit], &entry);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to create entry for classifier %s rc=%s", cls->name,
                 opennsl_errmsg(rc));
        return rc;
    }

    VLOG_DBG("Classifier %s entry id 0x%x", cls->name, entry);

    rc = opennsl_field_qualify_EtherType(unit, entry, OPS_ETHER_TYPE_IP,
                                         OPS_ETHER_TYPE_MASK);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to set Ether Type IP rc=%s", opennsl_errmsg(rc));
        return rc;
    }

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        rc = opennsl_field_qualify_L3Routable(unit, entry, 0x01, 0x01);
         if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set routable bit rc=%s",
                      opennsl_errmsg(rc));
            goto cleanup;
         }
         VLOG_DBG("L3 Routable bit set");
    }

    /* Ingress port(s) */
    if (OPENNSL_PBMP_NOT_NULL(*pbmp)) {
        char pbmp_string[200];

        OPENNSL_PBMP_CLEAR(pbmp_mask);
        OPENNSL_PBMP_NEGATE(pbmp_mask, pbmp_mask);

        VLOG_DBG("Ingress port(s): [ %s ]",
                 ops_cls_display_port_bit_map(pbmp, pbmp_string, 200));
        rc = opennsl_field_qualify_InPorts(unit, entry, *pbmp, pbmp_mask);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set ingress port(s) [%s]: rc=%s",
                     pbmp_string, opennsl_errmsg(rc));
            goto cleanup;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_SRC_IPADDR_VALID) {
        VLOG_DBG("Src ipv4 addr 0x%x and mask 0x%x", htonl(cls_entry->src_ip),
                 htonl(cls_entry->src_mask));

        rc = opennsl_field_qualify_SrcIp(unit, entry, htonl(cls_entry->src_ip),
                                         htonl(cls_entry->src_mask));
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Add entry src ipv4 0x%x and mask 0x%x failed: rc=%s",
                     htonl(cls_entry->src_ip), htonl(cls_entry->src_mask),
                     opennsl_errmsg(rc));
            goto cleanup;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_DEST_IPADDR_VALID) {
        VLOG_DBG("Dst ipv4 addr 0x%x and mask 0x%x",
                 htonl(cls_entry->dst_ip), htonl(cls_entry->dst_mask));

        rc = opennsl_field_qualify_DstIp(unit, entry, htonl(cls_entry->dst_ip),
                                         htonl(cls_entry->dst_mask));
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Add entry dst ipv4 0x%x and mask 0x%x failed: rc=%s",
                     htonl(cls_entry->dst_ip), htonl(cls_entry->dst_mask),
                     opennsl_errmsg(rc));
            goto cleanup;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_PROTOCOL_VALID) {
        VLOG_DBG("IP protocol: 0x%x", match->protocol);

        rc = opennsl_field_qualify_IpProtocol(unit,
                                              entry,
                                              match->protocol,
                                              protocol_mask);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to add entry ip protocol 0x%x and mask 0x%x: "
                     "rc=%s", match->protocol, protocol_mask,
                     opennsl_errmsg(rc));
            goto cleanup;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_L4_SRC_PORT_VALID) {
        VLOG_DBG("L4 src port min: 0x%x max: 0x%x ops %d",
                 match->L4_src_port_min, match->L4_src_port_max,
                 match->L4_src_port_op);

        switch (match->L4_src_port_op) {
        case OPS_CLS_L4_PORT_OP_EQ:
            rc = opennsl_field_qualify_L4SrcPort(unit, entry,
                                                 match->L4_src_port_min,
                                                 port_mask);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to add entry L4 src port 0x%x and mask 0x%x: "
                         "rc=%s", match->L4_src_port_min, port_mask,
                         opennsl_errmsg(rc));
                goto cleanup;
            }
            break;

        case OPS_CLS_L4_PORT_OP_RANGE:
        case OPS_CLS_L4_PORT_OP_LT:
        case OPS_CLS_L4_PORT_OP_GT:
            ops_cls_get_src_port_range(match, &min_port, &max_port);

            rc = opennsl_field_range_create(unit, &src_range,
                                            OPENNSL_FIELD_RANGE_SRCPORT,
                                            min_port, max_port);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to create L4 src port range min %d, max %d rc=%s",
                         min_port, max_port, opennsl_errmsg(rc));
                goto cleanup;
            } else {
                VLOG_DBG("Src range index 0x%x for min %d, max %d", src_range,
                          min_port, max_port);
            }


            rc = opennsl_field_qualify_RangeCheck(unit, entry, src_range, 0);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to add L4 src port range min %d, max %d rc=%s",
                         min_port, max_port, opennsl_errmsg(rc));
                rc = opennsl_field_range_destroy(unit, src_range);
                if (OPENNSL_FAILURE(rc)) {
                    VLOG_ERR("Failed to destroy L4 src port range %d rc= %s",
                             src_range, opennsl_errmsg(rc));
                }
                goto cleanup;
            }
            src_rangeEnabled = TRUE;
            break;

        case OPS_CLS_L4_PORT_OP_NONE:
        case OPS_CLS_L4_PORT_OP_NEQ:
        default:
            VLOG_DBG("L4 src port operation %d not supported",
                      match->L4_src_port_op);
            rc = OPS_CLS_HW_UNSUPPORTED_ERR;
            goto cleanup;
        }
    }

    if (cls_entry->match_flags & OPS_CLS_L4_DEST_PORT_VALID) {
        VLOG_DBG("L4 dst port min: 0x%x max: 0x%x ops %d",
                 match->L4_dst_port_min, match->L4_dst_port_max,
                 match->L4_dst_port_op);

        switch (match->L4_dst_port_op) {
        case OPS_CLS_L4_PORT_OP_EQ:
            rc = opennsl_field_qualify_L4DstPort(unit, entry,
                                                 match->L4_dst_port_min,
                                                 port_mask);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to add entry L4 dst port 0x%x and mask 0x%x: "
                         "rc=%s", match->L4_dst_port_min, port_mask,
                         opennsl_errmsg(rc));
                goto cleanup;
            }
            break;

        case OPS_CLS_L4_PORT_OP_RANGE:
        case OPS_CLS_L4_PORT_OP_LT:
        case OPS_CLS_L4_PORT_OP_GT:
            ops_cls_get_dst_port_range(match, &min_port, &max_port);

            rc = opennsl_field_range_create(unit, &dst_range,
                                            OPENNSL_FIELD_RANGE_DSTPORT,
                                            min_port, max_port);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to create L4 dst port range min %d, max %d rc=%s",
                         min_port, max_port, opennsl_errmsg(rc));
                goto cleanup;
            } else {
                VLOG_DBG("Dst range index 0x%x for min %d, max %d", dst_range,
                          min_port, max_port);
            }

            rc = opennsl_field_qualify_RangeCheck(unit, entry, dst_range, 0);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to add L4 dst port range min %d, max %d rc=%s",
                         min_port, max_port, opennsl_errmsg(rc));
                rc = opennsl_field_range_destroy(unit, dst_range);
                if (OPENNSL_FAILURE(rc)) {
                    VLOG_ERR("Failed to destroy L4 dst port range %d rc= %s",
                              dst_range, opennsl_errmsg(rc));
                }
                goto cleanup;
            }
            dst_rangeEnabled = TRUE;
            break;

        case OPS_CLS_L4_PORT_OP_NONE:
        case OPS_CLS_L4_PORT_OP_NEQ:
        default:
            VLOG_DBG("L4 dst port operation %d not supported",
                      match->L4_dst_port_op);
            rc = OPS_CLS_HW_UNSUPPORTED_ERR;
            goto cleanup;
        }
    }

    /* Set the actions */
    rc = ops_cls_set_action(unit, entry, cls, cls_entry, &stat_index,
                            &statEnabled);
    if(OPENNSL_FAILURE(rc)) {
        goto cleanup;
    }

    /* Install the entry */
    rc = opennsl_field_entry_install(unit, entry);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to install entry 0x%x rc=%s", entry,opennsl_errmsg(rc));
        goto cleanup;
    }

    VLOG_DBG("Classifier %s rule id 0x%x successfully installed",
             cls->name, entry);

    /* store stats entry */
    if (statEnabled) {
        /* add it in range list of acl entry */
        sentry = xzalloc(sizeof(struct ops_cls_stats_entry));
        sentry->index = stat_index;
        sentry->rule_index = index;
        listp = isUpdate ? &hw_info->stats_index_update_list
                            : &hw_info->stats_index_list;
        list_push_back(listp, &sentry->node);
    }

    /* store range entry */
    if (src_rangeEnabled) {
        rentry = xzalloc(sizeof(struct ops_cls_range_entry));
        rentry->index = src_range;
        listp = isUpdate ? &hw_info->range_index_update_list
                            : &hw_info->range_index_list;
        list_push_back(listp, &rentry->node);
    }

    if (dst_rangeEnabled) {
        rentry = xzalloc(sizeof(struct ops_cls_range_entry));
        rentry->index = dst_range;
        listp = isUpdate ? &hw_info->range_index_update_list
                            : &hw_info->range_index_list;
        list_push_back(listp, &rentry->node);
    }

    /* Save the entry id in  field */
    rulep =  xzalloc(sizeof(struct ops_cls_rule_entry));
    rulep->index = entry;
    listp = isUpdate ? &hw_info->rule_index_update_list
                        : &hw_info->rule_index_list;
    list_push_back(listp, &rulep->node);

    cls_ingress_ipv4_rule_count[unit]++;

    return rc;

cleanup:

    if (src_rangeEnabled) {
        rc = opennsl_field_range_destroy(unit, src_range);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy L4 src port range %d rc= %s",
                      src_range, opennsl_errmsg(rc));
        }
    }

    if (dst_rangeEnabled) {
        rc = opennsl_field_range_destroy(unit, dst_range);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy L4 dst port range %d rc= %s",
                      dst_range, opennsl_errmsg(rc));
        }
    }

    if (statEnabled) {
        rc = opennsl_field_stat_destroy(unit, stat_index);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy stats 0x%x for ACL %s rc=%s",
                      stat_index, cls->name, opennsl_errmsg(rc));
        }
    }

    /* destroy entry and return rc */
    opennsl_field_entry_destroy(unit, entry);
    return rc;

}

/*
 * Add classifier rules in FP
 */
static int
ops_cls_install_classifier_in_asic(int                             hw_unit,
                                   struct ops_classifier          *cls,
                                   struct ovs_list                *list,
                                   opennsl_pbmp_t                 *port_bmp,
                                   int                            *fail_index,
                                   bool                            isUpdate,
                                   struct ops_cls_interface_info  *intf_info)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_cls_entry *cls_entry = NULL, *next_cls_entry;
    struct ops_cls_hw_info *hw_info;

    /* Install in ASIC */
    LIST_FOR_EACH_SAFE(cls_entry, next_cls_entry, node, list) {
        rc = ops_cls_install_rule_in_asic(hw_unit, cls, cls_entry, port_bmp,
                                          *fail_index, intf_info, isUpdate);
        if (ops_cls_error(rc)) {
            VLOG_ERR("Failed to install classifier %s rule(s) ", cls->name);
            return rc;
        }
        (*fail_index)++;
    }

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        hw_info = &cls->route_cls;
    } else {
        hw_info = &cls->port_cls;
    }

    hw_info->in_asic = true;

    /* save the port bit map */
    OPENNSL_PBMP_ASSIGN(hw_info->pbmp, *port_bmp);

    VLOG_DBG("Classifier %s successfully installed in asic", cls->name);
    return rc;
}

/*
 * Update rule(s) port bitmap in FP
 */
static int
ops_cls_pbmp_update(int                             hw_unit,
                    struct ops_classifier          *cls,
                    opennsl_pbmp_t                 *port_bmp,
                    int                            *fail_index,
                    struct ops_cls_interface_info  *intf_info)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_cls_rule_entry *rule_entry = NULL, *next_rule_entry;
    opennsl_pbmp_t pbmp_mask;
    char pbmp_string[200];
    int entry;
    struct ovs_list *listp;

    OPENNSL_PBMP_CLEAR(pbmp_mask);
    OPENNSL_PBMP_NEGATE(pbmp_mask, pbmp_mask);

    VLOG_DBG("Updated port bit map: [ %s ]",
             ops_cls_display_port_bit_map(port_bmp, pbmp_string, 200));

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        listp =  &cls->route_cls.rule_index_list;
    } else {
        listp =  &cls->port_cls.rule_index_list;
    }

    LIST_FOR_EACH_SAFE(rule_entry, next_rule_entry, node, listp) {
        entry = rule_entry->index;
        rc = opennsl_field_qualify_InPorts(hw_unit, entry, *port_bmp,
                                           pbmp_mask);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to update classifier %s rule port bitmask rc:%s",
                     cls->name, opennsl_errmsg(rc));
            return rc;
        }

        /*
         * Reinstall entry to update the port bitmap in asic
         */
        rc = opennsl_field_entry_reinstall(hw_unit, entry);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to reinstall classifier %s rule entry 0x%x rc:%s",
                     cls->name, entry, opennsl_errmsg(rc));
            return rc;
        }

        (*fail_index)++;
    }
    return rc;
}

/*
 * Delete rules in asic
 */
static int
ops_cls_delete_rules_in_asic(int                             hw_unit,
                             struct ops_classifier          *cls,
                             int                            *fail_index,
                             struct ops_cls_interface_info  *intf_info,
                             bool                            isUpdate)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_cls_rule_entry *rule_entry = NULL, *next_rule_entry;
    struct ops_cls_range_entry *rentry = NULL, *next_rentry;
    struct ops_cls_stats_entry *sentry = NULL, *next_sentry;
    struct ovs_list *rule_index_list, *range_index_list, *stats_index_list;
    struct ops_cls_hw_info *hw_info;
    int entry;
    int index = 0;

    if (!cls) {
        return OPS_CLS_FAIL;
    }

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        hw_info = &cls->route_cls;
    } else {
        hw_info = &cls->port_cls;
    }

    rule_index_list = isUpdate ? &hw_info->rule_index_update_list
                                  : &hw_info->rule_index_list;
    range_index_list = isUpdate ? &hw_info->range_index_update_list
                                   : &hw_info->range_index_list;
    stats_index_list = isUpdate ? &hw_info->stats_index_update_list
                                   : &hw_info->stats_index_list;

    LIST_FOR_EACH_SAFE(rule_entry, next_rule_entry, node, rule_index_list) {
        cls_ingress_ipv4_rule_count[hw_unit]-- ;
        entry = rule_entry->index;
        rc =  opennsl_field_entry_destroy(hw_unit, entry);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy classifier %s entry 0x%x rc:%s",
                     cls->name, entry, opennsl_errmsg(rc));
            if (*fail_index == 0) {
                *fail_index = index;
            }
        }
        index++;
    }

    LIST_FOR_EACH_SAFE(rentry, next_rentry, node, range_index_list) {
        entry = rentry->index;
        rc = opennsl_field_range_destroy(hw_unit, entry);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy classifier %s range 0x%x rc:%s",
                     cls->name, entry, opennsl_errmsg(rc));
        }
    }

    LIST_FOR_EACH_SAFE(sentry, next_sentry, node, stats_index_list) {
        entry = sentry->index;
        rc = opennsl_field_stat_destroy(hw_unit, entry);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to destroy classifier %s stats 0x%x rc:%s",
                     cls->name, entry, opennsl_errmsg(rc));
        }
    }

    return rc;
}


/*
 * Update port bitmap of classifier
 */
static int
ops_cls_update_classifier_in_asic(int                             hw_unit,
                                  struct ops_classifier          *cls,
                                  opennsl_pbmp_t                 *port_bmp,
                                  enum ops_update_pbmp            action,
                                  int                            *fail_index,
                                  struct ops_cls_interface_info  *intf_info)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_cls_hw_info *hw_info;
    opennsl_pbmp_t pbmp;

    if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        hw_info = &cls->route_cls;
    } else {
        hw_info = &cls->port_cls;
    }

    OPENNSL_PBMP_CLEAR(pbmp);
    OPENNSL_PBMP_OR(pbmp, hw_info->pbmp);
    switch (action) {
    case OPS_PBMP_ADD:
        OPENNSL_PBMP_OR(pbmp, *port_bmp);
        rc = ops_cls_pbmp_update(hw_unit, cls, &pbmp, fail_index, intf_info);
        if (OPENNSL_SUCCESS(rc)) {
            OPENNSL_PBMP_ASSIGN(hw_info->pbmp, pbmp);
        }
        break;

    case OPS_PBMP_DEL:
        /* check clasiifier is used as routed (L3) or port (L2) */
        OPENNSL_PBMP_XOR(pbmp, *port_bmp);
        if (OPENNSL_PBMP_IS_NULL(pbmp)) {
            if (intf_info && (intf_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
                VLOG_DBG("Routed port bit map is NULL, remove classifier %s "
                          "routed rules in asic", cls->name);
            } else {
                VLOG_DBG("Port bit map is NULL, remove classifier %s "
                          "port rules in asic", cls->name);
            }
            rc = ops_cls_delete_rules_in_asic(hw_unit, cls, fail_index,
                                              intf_info, FALSE);
        } else {
            rc = ops_cls_pbmp_update(hw_unit, cls, &pbmp, fail_index,
                                     intf_info);
        }

        if (OPENNSL_SUCCESS(rc)) {
            OPENNSL_PBMP_ASSIGN(hw_info->pbmp, pbmp);
        }

        if (OPENNSL_PBMP_IS_NULL(cls->port_cls.pbmp) &&
            OPENNSL_PBMP_IS_NULL(cls->route_cls.pbmp)) {
            VLOG_DBG("All port bit is NULL, remove classifer %s from hash",
                     cls->name);
            ops_cls_delete(cls);
        }

        break;

    default:
        break;

    }

    return rc;
}

/*
 * Apply classifier to a port
 */
int
ops_cls_opennsl_apply(struct ops_cls_list            *list,
                      struct ofproto                 *ofproto,
                      void                           *aux,
                      struct ops_cls_interface_info  *interface_info,
                      enum ops_cls_direction          direction,
                      struct ops_cls_pd_status       *pd_status)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int hw_unit;
    opennsl_pbmp_t port_bmp;
    struct ops_classifier *cls = NULL;
    char pbmp_string[200];
    int fail_index = 0; /* rule index to PI on failure */
    bool in_asic;

    VLOG_DBG("Apply classifier "UUID_FMT" (%s)",
              UUID_ARGS(&list->list_id), list->list_name);

    OPENNSL_PBMP_CLEAR(port_bmp);
    cls = ops_cls_lookup(&list->list_id);
    if (!cls) {
        cls = ops_cls_add(list);
        if (!cls) {
            VLOG_ERR ("Failed to add classifier "UUID_FMT" (%s) in hashmap",
                       UUID_ARGS(&list->list_id), list->list_name);
            rc = OPS_CLS_FAIL;
            goto apply_fail;
        }
    } else {
        VLOG_DBG("Classifier %s exist in hashmap", list->list_name);
    }

    /* get the port bits_map */
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_CLS_FAIL;
        goto apply_fail;
    }

    VLOG_DBG("Apply classifier %s on port(s) [ %s ]", cls->name,
              ops_cls_display_port_bit_map(&port_bmp, pbmp_string, 200));

    if (interface_info && (interface_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        VLOG_DBG("Apply %s as routed classifier", cls->name);
        in_asic = cls->route_cls.in_asic;
    } else {
        VLOG_DBG("Apply %s as port classifier", cls->name);
        in_asic = cls->port_cls.in_asic;
    }

    if (!in_asic) {
        /* first binding of classifier*/
        rc = ops_cls_install_classifier_in_asic(hw_unit, cls, &cls->cls_entry_list,
                                                &port_bmp, &fail_index, FALSE,
                                                interface_info);
        if (ops_cls_error(rc)) {
            int index = 0;
            ops_cls_delete_rules_in_asic(hw_unit, cls, &index,
                                         interface_info, FALSE);
            if (!cls->route_cls.in_asic && !cls->port_cls.in_asic) {
                ops_cls_delete(cls);
            }
            goto apply_fail;
        }
    } else {
        /* already in asic update port bitmap */
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls, &port_bmp,
                                               OPS_PBMP_ADD, &fail_index,
                                               interface_info);
        if (OPENNSL_FAILURE(rc)) {
            goto apply_fail;
        }
    }

    return OPS_CLS_OK;

apply_fail:
    ops_cls_set_pd_status(rc, fail_index, pd_status);
    return OPS_CLS_FAIL;
}

/*
 * Remove classifier from port
 */
int
ops_cls_opennsl_remove(const struct uuid                *list_id,
                       const char                       *list_name OVS_UNUSED,
                       enum ops_cls_type                 list_type OVS_UNUSED,
                       struct ofproto                   *ofproto,
                       void                             *aux,
                       struct ops_cls_interface_info    *interface_info,
                       enum ops_cls_direction            direction,
                       struct ops_cls_pd_status         *pd_status)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int hw_unit;
    opennsl_pbmp_t port_bmp;
    struct ops_classifier *cls = NULL;
    char pbmp_string[200];
    int fail_index = 0; /* rule index to PI on failure */
    bool in_asic = false;

    VLOG_DBG("Remove classifier "UUID_FMT"", UUID_ARGS(list_id));

    OPENNSL_PBMP_CLEAR(port_bmp);
    cls = ops_cls_lookup(list_id);
    if (!cls) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",  UUID_ARGS(list_id));
        rc = OPS_CLS_FAIL;
        goto remove_fail;
    }

    /* get the port bits_map */
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_CLS_FAIL;
        goto remove_fail;
    }

    VLOG_DBG("Remove classifier %s on port(s) [ %s ]", cls->name,
              ops_cls_display_port_bit_map(&port_bmp, pbmp_string, 200));

    if (interface_info && (interface_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        VLOG_DBG("Remove %s as routed classifier", cls->name);
        in_asic = cls->route_cls.in_asic;
    } else {
        VLOG_DBG("Remove %s as port classifier", cls->name);
        in_asic = cls->port_cls.in_asic;
    }

    if (!in_asic) {
        VLOG_ERR("Remove failed, classifier %s not in asic", cls->name);
        rc = OPS_CLS_FAIL;
        goto remove_fail;
    } else {
        /* already in asic update port bitmap */
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls, &port_bmp,
                                               OPS_PBMP_DEL, &fail_index,
                                               interface_info);
        if(OPENNSL_FAILURE(rc)) {
            goto remove_fail;
        }
    }

    return OPS_CLS_OK;

remove_fail:
    ops_cls_set_pd_status(rc, fail_index, pd_status);
    return OPS_CLS_FAIL;
}

/*
 * Attach port to different classifier
 */
int
ops_cls_opennsl_replace(const struct uuid               *list_id_orig,
                        const char                      *list_name_orig OVS_UNUSED,
                        struct ops_cls_list             *list_new,
                        struct ofproto                  *ofproto,
                        void                            *aux,
                        struct ops_cls_interface_info   *interface_info,
                        enum ops_cls_direction           direction,
                        struct ops_cls_pd_status        *pd_status)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    int hw_unit;
    opennsl_pbmp_t port_bmp;
    struct ops_classifier *cls_orig = NULL, *cls_new = NULL;
    char pbmp_string[200];
    int fail_index = 0; /* rule index to PI on failure */
    bool *in_asic_orig = false;
    bool *in_asic_new = false;

    VLOG_DBG("Replace classifier "UUID_FMT" by "UUID_FMT"",
              UUID_ARGS(list_id_orig), UUID_ARGS(&list_new->list_id));

    cls_orig = ops_cls_lookup(list_id_orig);
    if (!cls_orig) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",
                 UUID_ARGS(list_id_orig));
        rc = OPS_CLS_FAIL;
        goto replace_fail;
    }

    cls_new = ops_cls_lookup(&list_new->list_id);
    if (!cls_new) {
        cls_new = ops_cls_add(list_new);
        if (!cls_new) {
            VLOG_ERR ("Failed to add classifier "UUID_FMT" (%s) in hashmap",
                       UUID_ARGS(&list_new->list_id), list_new->list_name);
            rc =  OPS_CLS_FAIL;
            goto replace_fail;
        }
    } else {
        VLOG_DBG("Replace classifier "UUID_FMT" (%s) exist in hashmap",
                  UUID_ARGS(&list_new->list_id), list_new->list_name);
    }

    OPENNSL_PBMP_CLEAR(port_bmp);
    /* get the port bits_map */
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_CLS_FAIL;
        goto replace_fail;
    }

    VLOG_DBG("Replace classifier %s with %s on port(s) [ %s ]",
             cls_orig->name, cls_new->name,
             ops_cls_display_port_bit_map(&port_bmp, pbmp_string, 200));

    if (interface_info && (interface_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        VLOG_DBG("Replace %s classifier and apply %s as routed classifier",
                  cls_orig->name, cls_new->name);
        in_asic_orig = &cls_orig->route_cls.in_asic;
        in_asic_new = &cls_new->route_cls.in_asic;
    } else {
        VLOG_DBG("Replace %s classifier and  apply %s as port classifier",
                  cls_orig->name, cls_new->name);
        in_asic_orig = &cls_orig->port_cls.in_asic;
        in_asic_new = &cls_new->port_cls.in_asic;
    }


    if (!(*in_asic_new)) {
        /* first binding of classifier*/
        rc = ops_cls_install_classifier_in_asic(hw_unit, cls_new,
                                                &cls_new->cls_entry_list,
                                                &port_bmp, &fail_index,
                                                FALSE, interface_info);
        if (ops_cls_error(rc)) {
            int index = 0;
            ops_cls_delete_rules_in_asic(hw_unit, cls_new, &index,
                                         interface_info, FALSE);
            goto replace_fail;
        }
    } else {
        /* already in asic update port bitmap */
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls_new, &port_bmp,
                                               OPS_PBMP_ADD, &fail_index,
                                               interface_info);
        if (OPENNSL_FAILURE(rc)) {
            goto replace_fail;
        }
    }

    if (in_asic_orig) {
        /* already in asic update port bitmap */
        fail_index = 0;
        rc = ops_cls_update_classifier_in_asic(hw_unit, cls_orig, &port_bmp,
                                               OPS_PBMP_DEL, &fail_index,
                                               interface_info);
        if(OPENNSL_FAILURE(rc)) {
            goto replace_fail;
        }
    }

    return OPS_CLS_OK;

replace_fail:
    ops_cls_set_pd_status(rc, fail_index, pd_status);
    return OPS_CLS_FAIL;
}

/*
 * Create a new ACL.
 */
int
ops_cls_opennsl_list_update(struct ops_cls_list                 *list,
                            struct ops_cls_pd_list_status       *status)
{
    opennsl_error_t rc = OPENNSL_E_NONE;
    struct ops_classifier *cls = NULL;
    int hw_unit =  0;
    opennsl_pbmp_t port_bmp;
    int fail_index = 0; /* rule index to PI on failure */
    struct ops_cls_interface_info intf_info;

    VLOG_DBG("Update classifier "UUID_FMT" (%s)", UUID_ARGS(&list->list_id),
             list->list_name);

    cls = ops_cls_lookup(&list->list_id);
    if (!cls) {
        VLOG_ERR ("Failed to find classifier %s in hashmap", list->list_name);
        rc = OPS_CLS_FAIL;
        goto update_fail;
    } else {
        VLOG_DBG("Classifier %s exist in haspmap", list->list_name);
    }

    if (cls->route_cls.in_asic) {
        intf_info.flags = OPS_CLS_INTERFACE_L3ONLY;
    }

   VLOG_DBG("Total rules %d in classifier update", list->num_entries);

   if (list->num_entries > 0) {
        /*
         * Install updated ACL in FP, if it fails, remove
         * the updated ACL and leave original ACL. On successful
         * update remove the original ACL entries.
         */

        ops_cls_populate_entries(cls, &cls->cls_entry_update_list, list);

        if (cls->port_cls.in_asic) {
            OPENNSL_PBMP_CLEAR(port_bmp);
            OPENNSL_PBMP_ASSIGN(port_bmp, cls->port_cls.pbmp);

            rc = ops_cls_install_classifier_in_asic(hw_unit, cls,
                                                    &cls->cls_entry_update_list,
                                                    &port_bmp, &fail_index,
                                                    TRUE, NULL);
        }

        if (!ops_cls_error(rc) && cls->route_cls.in_asic) {
            OPENNSL_PBMP_CLEAR(port_bmp);
            OPENNSL_PBMP_ASSIGN(port_bmp, cls->route_cls.pbmp);
            rc = ops_cls_install_classifier_in_asic(hw_unit, cls,
                                                    &cls->cls_entry_update_list,
                                                    &port_bmp, &fail_index,
                                                    TRUE, &intf_info);
        }

        int index = 0;
        if(ops_cls_error(rc)) {
            if (cls->port_cls.in_asic) {
                ops_cls_delete_rules_in_asic(hw_unit, cls, &index,
                                             NULL, TRUE);
            }

            if (cls->route_cls.in_asic) {
                ops_cls_delete_rules_in_asic(hw_unit, cls, &index,
                                             &intf_info, TRUE);
            }
            ops_cls_delete_updated_entries(cls);
            goto update_fail;
        } else {
            if (cls->port_cls.in_asic) {
                ops_cls_delete_rules_in_asic(hw_unit, cls, &index,
                                             NULL, FALSE);
            }

            if (cls->route_cls.in_asic) {
                ops_cls_delete_rules_in_asic(hw_unit, cls, &index,
                                             &intf_info, FALSE);
            }
            ops_cls_delete_orig_entries(cls);
            ops_cls_update_entries(cls);
        }

    }
    return OPS_CLS_OK;

update_fail:
    ops_cls_set_pd_list_status(rc, fail_index, status);
    return OPS_CLS_FAIL;
}

/*
 * Get statistics of FP entries
 */
int
ops_cls_opennsl_statistics_get(const struct uuid              *list_id,
                               const char                     *list_name,
                               enum ops_cls_type              list_type,
                               struct ofproto                 *ofproto,
                               void                           *aux,
                               struct ops_cls_interface_info  *interface_info,
                               enum ops_cls_direction         direction,
                               struct ops_cls_statistics      *statistics,
                               int                            num_entries,
                               struct ops_cls_pd_list_status  *status)
{
    struct ops_classifier *cls;
    int hw_unit, rc, fail_index = 0;
    opennsl_pbmp_t port_bmp;
    uint64 packets = 0;
    struct ops_cls_stats_entry *sentry = NULL, *next_sentry;
    opennsl_field_stat_t stats_type = opennslFieldStatPackets;
    struct ovs_list *stats_index_listp;

    VLOG_DBG("Get stats classifier "UUID_FMT"", UUID_ARGS(list_id));

    cls = ops_cls_lookup(list_id);
    if (!cls) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",  UUID_ARGS(list_id));
        rc = OPS_CLS_FAIL;
        goto stats_get_fail;
    }

    VLOG_DBG("Classifier %s hit count request", cls->name);

    /* get the hardware unit */
    OPENNSL_PBMP_CLEAR(port_bmp);
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_CLS_FAIL;
        goto stats_get_fail;
    }

    if (interface_info && (interface_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        stats_index_listp = &cls->route_cls.stats_index_list;
    } else {
        stats_index_listp = &cls->port_cls.stats_index_list;
    }


    LIST_FOR_EACH_SAFE(sentry, next_sentry, node, stats_index_listp) {
        if (sentry && sentry->rule_index < num_entries) {
            rc = opennsl_field_stat_get(hw_unit, sentry->index, stats_type, &packets);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to get packets stats for stats index"
                         " %d in classifier %s rc:%s",
                         sentry->index, cls->name, opennsl_errmsg(rc));
                fail_index = sentry->rule_index;
                goto stats_get_fail;
            }
            VLOG_DBG("Hit count: stats index %d, packets %llu", sentry->index, packets);
            statistics[sentry->rule_index].stats_enabled = TRUE;
            statistics[sentry->rule_index].hitcounts = packets;
        }
    }

    return OPS_CLS_OK;

stats_get_fail:
    ops_cls_set_pd_list_status(rc, fail_index, status);
    return OPS_CLS_FAIL;
}


/*
 * Clear statistics of FP entries
 */
int
ops_cls_opennsl_statistics_clear(const struct uuid               *list_id,
                                 const char                      *list_name,
                                 enum ops_cls_type               list_type,
                                 struct ofproto                  *ofproto,
                                 void                            *aux,
                                 struct ops_cls_interface_info   *interface_info,
                                 enum ops_cls_direction          direction,
                                 struct ops_cls_pd_list_status   *status)
{
    struct ops_classifier *cls;
    int hw_unit, rc, fail_index = 0;
    opennsl_pbmp_t port_bmp;
    uint64 value = 0;
    struct ops_cls_stats_entry *sentry = NULL, *next_sentry;
    struct ovs_list *stats_index_listp;

    VLOG_DBG("Clear stats classifier "UUID_FMT" ", UUID_ARGS(list_id));

    cls = ops_cls_lookup(list_id);
    if (!cls) {
        VLOG_ERR("Classifier "UUID_FMT" not in hash map",  UUID_ARGS(list_id));
        rc = OPS_CLS_FAIL;
        goto stats_clear_fail;
    }

    VLOG_DBG("Classifier %s clear hit count request", cls->name);

    /* get the hardware unit */
    OPENNSL_PBMP_CLEAR(port_bmp);
    if (ops_cls_get_port_bitmap(ofproto, aux, &hw_unit, &port_bmp)) {
        rc = OPS_CLS_FAIL;
        goto stats_clear_fail;
    }

    if (interface_info && (interface_info->flags & OPS_CLS_INTERFACE_L3ONLY)) {
        stats_index_listp = &cls->route_cls.stats_index_list;
    } else {
        stats_index_listp = &cls->port_cls.stats_index_list;
    }

    LIST_FOR_EACH_SAFE(sentry, next_sentry, node, stats_index_listp) {
        rc = opennsl_field_stat_all_set(hw_unit, sentry->index, value);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set  packets stats for stats index"
                     " %d in classifier %s rc:%s",
                     sentry->index, cls->name, opennsl_errmsg(rc));
            fail_index = sentry->rule_index;
            goto stats_clear_fail;
        }
        VLOG_DBG("Clear hit count: stats index %d", sentry->index);
    }

    return OPS_CLS_OK;

stats_clear_fail:
    ops_cls_set_pd_list_status(rc, fail_index, status);
    return OPS_CLS_FAIL;
}


int
ops_cls_opennsl_statistics_clear_all(struct ops_cls_pd_list_status *status)
{
    VLOG_ERR("%s unimplemented", __func__);
    return OPS_CLS_FAIL;
}

int
ops_cls_opennsl_acl_log_pkt_register_cb(void (*callback_handler)(struct acl_log_info *))
{
    if (!callback_handler) {
        VLOG_ERR("No ACL logging callback provided");
        return OPS_CLS_FAIL;
    }
    acl_pd_log_pkt_data_set = callback_handler;
    return OPS_CLS_OK;
}

int
register_ops_cls_plugin()
{
    return (register_plugin_extension(&ops_cls_extension));
}

void
acl_log_handle_rx_event(opennsl_pkt_t *pkt)
{
    static long long int last_pkt_rxd_time = 0;
    long long int cur_time;
    static uint64_t pkt_counter = 0;

    if (!pkt) {
        VLOG_ERR("Acl logging received invalid pkt from the ASIC");
        return;
    }

    pkt_counter++;
    cur_time = time_msec();
    /* ignore packets received within a small time window after the last ACL
     * logging packet
     */
    if (cur_time >= (last_pkt_rxd_time + ACL_LOGGING_MIN_MS_BETWEEN_PKTS)) {
        struct acl_log_info pkt_info = { .valid_fields = 0 };
        char   port_name[PORT_NAME_SIZE+1] = { 0 };

        VLOG_DBG("ACL logging packet of length %d received; "
                "total packets received so far %lu", pkt->pkt_len, pkt_counter);
        last_pkt_rxd_time = cur_time;

        /* fill in the acl_log_info struct */
        /* first fill in fields only available from the ASIC */
        pkt_info.ingress_port  = pkt->src_port;
        netdev_port_name_from_hw_id(pkt->unit, pkt->src_port,
                                    port_name);
        snprintf(pkt_info.ingress_port_name,
                 sizeof(pkt_info.ingress_port_name), port_name);
        pkt_info.ingress_port_name[sizeof(pkt_info.ingress_port_name)-1] = 0;
        pkt_info.valid_fields |= ACL_LOG_INGRESS_PORT;
        pkt_info.egress_port   = pkt->dest_port;
        pkt_info.valid_fields |= ACL_LOG_EGRESS_PORT;
        pkt_info.ingress_vlan  = pkt->vlan;
        pkt_info.valid_fields |= ACL_LOG_INGRESS_VLAN;
        pkt_info.node          = pkt->unit;
        pkt_info.valid_fields |= ACL_LOG_NODE;
        pkt_info.in_cos        = pkt->cos;
        pkt_info.valid_fields |= ACL_LOG_IN_COS;

        /* fill in fields related to packet data */
        pkt_info.total_pkt_len = pkt->tot_len;
        pkt_info.pkt_buffer_len = MIN(pkt->pkt_len, sizeof(pkt_info.pkt_data));
        pkt_info.pkt_buffer_len =
            MIN(pkt->pkt_data[0].len, pkt_info.pkt_buffer_len);
        memcpy(&pkt_info.pkt_data, pkt->pkt_data[0].data,
                pkt_info.pkt_buffer_len);

        /* submit packet data for PI code to retrieve */
        (*acl_pd_log_pkt_data_set)(&pkt_info);
    }
}
