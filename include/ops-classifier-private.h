/*
 * Copyright (C) 2015, 2016 Hewlett Packard Enterprise Development LP
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
 */
#ifndef __OPS_CLASSIFIER_PRIVATE_H__
#define __OPS_CLASSIFIER__PRIVATE_H__ 1

#include "ops-cls-asic-plugin.h"

/*
 * The header file contains data sturtures private to classifier code.
 */

/* Return code */
enum ops_cls_status_code {
    OPS_CLS_OK = 0,
    OPS_CLS_FAIL,
    OPS_CLS_HW_UNSUPPORTED_ERR,
    OPS_CLS_LIST_PARSE_ERR
};

inline int ops_cls_error (int rc) {
    return (OPENNSL_FAILURE(rc) ||
            rc == OPS_CLS_FAIL ||
            rc == OPS_CLS_HW_UNSUPPORTED_ERR ||
            rc == OPS_CLS_LIST_PARSE_ERR);
}

struct ops_cls_hw_info {
    bool in_asic;                              /* classifer already in asic */
    opennsl_pbmp_t pbmp;                       /* port classifier is applied */
    struct ovs_list rule_index_list;           /* list of hardware rule index */
    struct ovs_list range_index_list;          /* list of hardware range index */
    struct ovs_list stats_index_list;          /* list of hardware stats index */
    struct ovs_list rule_index_update_list;    /* updated list of rule index */
    struct ovs_list range_index_update_list;   /* updated list of range index */
    struct ovs_list stats_index_update_list;   /* updated list of stats index */
};

struct ops_classifier {
    struct hmap_node node;
    struct uuid id;
    char *name;                                /* name of classifier list */
    enum ops_cls_type type;                    /* type of classifier list - aclv4, aclv6 */
    struct ovs_list cls_entry_list;            /* list of ops_cls_entry */
    struct ovs_list cls_entry_update_list;     /* list of updated ops_cls_entry */

    struct ops_cls_hw_info port_cls;           /* port classifier */
    struct ops_cls_hw_info route_cls;          /* routed classifier */
};

struct ops_cls_entry {
    struct ovs_list node;
#define match_flags entry_fields.entry_flags
#define src_ip      entry_fields.src_ip_address.v4.s_addr
#define src_mask    entry_fields.src_ip_address_mask.v4.s_addr
#define dst_ip      entry_fields.dst_ip_address.v4.s_addr
#define dst_mask    entry_fields.dst_ip_address_mask.v4.s_addr
#define act_flags   entry_actions.action_flags
    struct ops_cls_list_entry_match_fields entry_fields;   /* field(s)/value(s) to match */
    struct ops_cls_list_entry_actions entry_actions;        /* action(s) to take */
};

struct ops_cls_rule_entry {
    struct ovs_list node;
    uint32_t index;                     /* classifier index*/
};

struct ops_cls_range_entry {
    struct ovs_list node;
    uint32_t index;                     /* range index */
};

struct ops_cls_stats_entry {
    struct ovs_list node;
    uint32_t index;                     /* stats index */
    uint16_t rule_index;                /* rule index of PI classifier*/
};

enum ops_update_pbmp {
    OPS_PBMP_ADD = 0,
    OPS_PBMP_DEL,
};

#endif /* __OPS_CLASSIFIER_PRIVATE_H__ */
