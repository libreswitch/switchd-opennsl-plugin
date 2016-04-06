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
 * File: ops-debug.c
 *
 * Purpose: Main file for the implementation of OpenSwitch specific BCM shell debug commands.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ovs/unixctl.h>
#include <ovs/dynamic-string.h>
#include <openvswitch/vlog.h>
#include <ovs/util.h>
#include <ovs/hmap.h>
#include <ovs/shash.h>

#include <shared/pbmp.h>
#include <opennsl/error.h>
#include <opennsl/types.h>
#include <opennsl/l2.h>

#include "ops-lag.h"
#include "platform-defines.h"
#include "ops-vlan.h"
#include "ops-debug.h"
#include "ops-routing.h"
#include "ops-knet.h"
#include "ofproto-bcm-provider.h"
#include "ops-port.h"
#include "ops-stg.h"

VLOG_DEFINE_THIS_MODULE(ops_debug);

#define MAX_PACKET_RES_STRING_LEN 50

uint32 slog_level = 0x0;

// OPS_TODO: for BPDU TX/RX debugging.
int pkt_debug = 0;

ops_debug_t ops_debug_list[] = {

    {"rx_tx_pkt",   0},         // to print RX/TX packets on BCM shell
    {"ops_init", SWITCHD_INIT_DBG},
    {"port",    SWITCHD_PORT_DBG},
    {"lag",     SWITCHD_LAG_DBG},
    {"vlan",    SWITCHD_VLAN_DBG},
    {"l3",      SWITCHD_L3_DBG},
};

// Broadcom shell debug command.
char cmd_hp_usage[] =
"Usage:\n\t"
"ovs-appctl plugin/debug <cmds> - Run HP OpenSwitch BCM Plugin specific debug commands.\n"
"\n"
"   debug [[+/-]<option> ...] [all/none] - enable/disable debugging.\n"
"   vlan <vid> - displays OpenSwitch VLAN info.\n"
"   knet [netif | filter] - displays knet information\n"
"   l3intf [<interface id>] - display OpenSwitch interface info.\n"
"   l3host - display OpenSwitch l3 host info.\n"
"   l3v6host - display OpenSwitch l3 IPv6 host info.\n"
"   l3route - display OpenSwitch l3 Routes.\n"
"   l3v6route - display OpenSwitch l3 IPv6 Routes.\n"
"   l3egress [<entry>] - display an egress object info.\n"
"   l3ecmp [<entry>] - display an ecmp egress object info.\n"
"   lag [<lagid>] - displays OpenSwitch LAG info.\n"
"   fp - displays programmed fp rules.\n"
"   help - displays this help text.\n"
;

/*the action list that needs to be defined for checking if defined per entry*/
enum_to_str_t fp_action_list[] = {
    {opennslFieldActionCopyToCpu, "Copy To CPU"},
    {opennslFieldActionDrop, "DROP"},
    {opennslFieldActionCosQCpuNew, "CosQ CPU New"},
};

#define STAT_TYPE_STRINGS \
{ \
    "Bytes", \
    "Packets", \
    "Green Bytes", \
    "Green Packets", \
    "Red Bytes", \
    "Red Packets", \
    "Dropped Bytes", \
    "Dropped Packets" \
}

static opennsl_field_stat_t stat_arr[MAX_STAT_TYPES] = {
    opennslFieldStatBytes,
    opennslFieldStatPackets,
    opennslFieldStatGreenBytes,
    opennslFieldStatGreenPackets,
    opennslFieldStatRedBytes,
    opennslFieldStatRedPackets,
    opennslFieldStatDroppedBytes,
    opennslFieldStatDroppedPackets,
};

void PacketRes_toString(int packetRes, char *packet_res_string )
{
    switch(packetRes)
    {
        case OPENNSL_FIELD_PKT_RES_L3MCUNKNOWN:
            snprintf(packet_res_string, MAX_PACKET_RES_STRING_LEN,
                     "Unknown L3 multicast");
            break;
        case OPENNSL_FIELD_PKT_RES_L3MCKNOWN:
            snprintf(packet_res_string, MAX_PACKET_RES_STRING_LEN,
                     "Known L3 multicast");
            break;
        case OPENNSL_FIELD_PKT_RES_L3UCKNOWN:
            snprintf(packet_res_string, MAX_PACKET_RES_STRING_LEN,
                     "Known L3 unicast");
            break;
       case OPENNSL_FIELD_PKT_RES_L3UCUNKNOWN:
            snprintf(packet_res_string, MAX_PACKET_RES_STRING_LEN,
                     "UnKnown L3 unicast");
            break;
        default:
            snprintf(packet_res_string, MAX_PACKET_RES_STRING_LEN,
                     "Unknown");
            break;
    }

}

char *
bcmsdk_datapath_version(void)
{
    // We can't just pass back "_build_release" global variable
    // since bcmsdk is being built as a shared library.  Need
    // to make a copy so OVS code can use it properly.
    static char *rel_version = NULL;

    if (NULL == rel_version) {
        // OPS_TODO: need to automate this.
        //rel_version = strdup(_build_release);
        rel_version = strdup("6.4.5.5");
    }
    return rel_version;

} // bcmsdk_datapath_version

////////////////////////////////////////////////////////////////////////

#define NEXT_ARG()  ((arg_idx < argc) ? argv[arg_idx++] : NULL)

static void
handle_ops_debug(struct ds *ds, int arg_idx, int argc, const char *argv[])
{
    char        c = '\0';
    const char *ch = NULL;
    uint8       i = 0;
    uint8       count = 1;
    uint8       found = 0;
    uint8       dbg_list_sz = 0;
    ops_debug_t  *dbg = NULL;

    dbg_list_sz = (sizeof(ops_debug_list)/sizeof(ops_debug_t));

    // If no parameters are given.
    if (arg_idx >= argc) {

        ds_put_format(ds, "slog_level = 0x%x\n", slog_level);

        // print the list of debug enabled subsystems
        ds_put_format(ds, "Debugging is enabled for the following subsystems:\n");

        if (pkt_debug) {
            ds_put_format(ds, "rx_tx_pkt  ");
        }

        for (i=0; i < dbg_list_sz; i++) {
            dbg = &ops_debug_list[i];
            if (slog_level & dbg->value) {
                ds_put_format(ds, "%s  ", dbg->sub_system);
                count++;
            }
            if (0 == (count % 5)) {
                ds_put_format(ds, "\n");
            }
        }
        ds_put_format(ds, "\n\n");

        // print the rest of the subsystems
        ds_put_format(ds, "Debugging is disabled for the following subsystems:\n");
        count = 1;
        for (i=0; i < dbg_list_sz; i++) {
            dbg = &ops_debug_list[i];
            if (!(slog_level & dbg->value)) {
                ds_put_format(ds, "%s  ", dbg->sub_system);
                count++;
            }
            if (0 == (count % 5)) {
                ds_put_format(ds, "\n");
            }
        }
        ds_put_format(ds, "\n\n");

    } else {
        while ((ch = NEXT_ARG()) != NULL) {
            if (0 == strcmp(ch, "none")) {
                slog_level = 0;
                break;
            } else if (0 == strcmp(ch, "all")) {
                for (i=0; i < dbg_list_sz; i++) {
                    dbg = &ops_debug_list[i];
                    slog_level |= dbg->value;
                }
                break;
            } else if (0 == strcmp(ch, "rx_tx_pkt")) {
                pkt_debug = !pkt_debug;
                break;
            } else {
                c = *ch;
                if (('+' == c) || ('-' == c)) {
                    ch++;
                }

                // search for the subsystem.
                found = 0;
                for (i=0; i < dbg_list_sz; i++) {
                    dbg = &ops_debug_list[i];
                    if (0 == strcmp(ch, dbg->sub_system)) {
                        switch(c) {
                        case '+':                       /* OR */
                            slog_level |= dbg->value;
                            break;
                        case '-':                       /* AND */
                            slog_level &= ~dbg->value;
                            break;
                        default:                        /* XOR */
                            slog_level ^= dbg->value;
                            break;
                        }
                        found = 1;
                        break;
                    }
                }
                if (0 == found) {
                    ds_put_format(ds, "debug: unknown option: %s\n", ch);
                }
            }
        }
    }
} // handle_ops_debug

static void
fp_entries_show (int unit, opennsl_field_group_t group, struct ds *ds)
{
    int entry_size  = 0;
    int entry_index = 0;
    int entry_count = 0;
    int ret         = 0;
    enum_to_str_t *fp_action_iter = NULL;
    opennsl_field_qset_t  qset;
    opennsl_field_entry_t *entry_array = NULL;
    uint64 data, mask, data_modid, mask_modid;
    int stat_id, stat_index, action_index, fp_action_list_size;
    uint64 stat_value;
    uint32 p0, p1;
    static char *stat_type_str[] = STAT_TYPE_STRINGS;

    ds_put_format(ds, "Group ID = %d\n", group);
    /* First get th entry count for this group */
    ret = opennsl_field_entry_multi_get(unit, group, 0, NULL, &entry_count);
    if (entry_count <= 0 || OPENNSL_FAILURE(ret)) {
        VLOG_ERR(" Error fetching the number of entries");
        goto done;
    }

    /* Allocate memory for all entries */
    entry_array = (opennsl_field_entry_t *) xzalloc(entry_count *
                                            sizeof(opennsl_field_entry_t));
    /* fetches the entries per group */
    ret = opennsl_field_entry_multi_get(unit, group, entry_count, entry_array,
                                        &entry_size);
    if (OPENNSL_FAILURE(ret)) {
        VLOG_ERR(" Error fetching the entries");
        goto err;
    }

    OPENNSL_FIELD_QSET_INIT(qset);
    ret = opennsl_field_group_get(unit, group, &qset);
    if (OPENNSL_FAILURE(ret)) {
        VLOG_ERR(" Error fetching the qualifier set");
        goto err;
    }

    for (entry_index = 0; entry_index < entry_count; ++entry_index)
    {
        stat_id = 0, stat_index =0;
        stat_value = 0;
        data = 0;
        mask = 0;
        data_modid = 0;
        mask_modid = 0;
        p0 = 0;
        p1 = 0;
        action_index = 0;
        fp_action_list_size = (sizeof(fp_action_list)/sizeof(enum_to_str_t));
        ds_put_format(ds, "entry ID = %d in group = %d\n",
                           entry_array[entry_index], group);
        if( OPENNSL_FIELD_QSET_TEST(qset, opennslFieldQualifyStageIngress)) {
            ds_put_format(ds, "\tQualifier Stage is Ingress\n");
        }

        if( OPENNSL_FIELD_QSET_TEST(qset, opennslFieldQualifyInPort)) {
            ret = opennsl_field_qualify_InPort_get(unit,
                  entry_array[entry_index],(int *) &data,(int *) &mask);
            if (!OPENNSL_FAILURE(ret)) {
                ds_put_format(ds, "\t    Qualifier is Inport - ");
                ds_put_format(ds, "0x%02x mask 0x%02x\n", (int)data,
                                  (int)mask);
            }
            data = 0;
            mask = 0;
        }

        if( OPENNSL_FIELD_QSET_TEST(qset, opennslFieldQualifyDstPort)) {
            ret = opennsl_field_qualify_DstPort_get(unit,
                  entry_array[entry_index], (int *) &data_modid,
                  (int *) &mask_modid, (int *) &data, (int *) &mask);
            if (!OPENNSL_FAILURE(ret)) {
                ds_put_format(ds, "\t    Qualifier is DstPort - ");
                ds_put_format(ds, "0x%02x mask - 0x%02x data_modid - 0x%02x \
                                    mask_modid - 0x%02x \n",
                                   (int)data, (int)mask,
                                   (int) data_modid, (int) mask_modid);
            }
            data = 0;
            mask = 0;
            data_modid = 0;
            mask_modid = 0;
        }

        if( OPENNSL_FIELD_QSET_TEST(qset, opennslFieldQualifyDstIp)) {
            char ip_str[IPV4_BUFFER_LEN];
            ret = opennsl_field_qualify_DstIp_get(unit,
                          entry_array[entry_index],(opennsl_ip_t *)&data,
                          (opennsl_ip_t *)&mask);
            if (!OPENNSL_FAILURE(ret)) {
                ds_put_format(ds, "\t    Qualifier is DstIp - ");
                sprintf(ip_str, "%d.%d.%d.%d",
                 ((int) data >> 24) & 0xff, ((int) data >> 16) & 0xff,
                 ((int) data >> 8) & 0xff,(int) data & 0xff);
                ds_put_format(ds,"%-16s\n", ip_str);
            }
            data = 0;
            mask = 0;
        }

        if( OPENNSL_FIELD_QSET_TEST(qset, opennslFieldQualifyL3Ingress)) {
            ret = opennsl_field_qualify_L3Ingress_get(unit,
                          entry_array[entry_index],(uint32 *)&data,
                          (uint32 *)&mask);
            if (!OPENNSL_FAILURE(ret)) {
                ds_put_format(ds, "\t    Qualifier is L3Ingress - ");
                ds_put_format(ds, "0x%02x mask 0x%02x\n", (uint32) data,
                                  (uint32)  mask);
            }
            data = 0;
            mask = 0;
        }

        if( OPENNSL_FIELD_QSET_TEST(qset, opennslFieldQualifyIpType)) {
            opennsl_field_IpType_t IpType = 0;
            ret = opennsl_field_qualify_IpType_get(unit,
                          entry_array[entry_index], &IpType);
            if (!OPENNSL_FAILURE(ret)) {
                if (IpType == opennslFieldIpTypeIpv6) {
                         ds_put_format(ds, "\t    Qualifier is IpType - "\
                                           "IPv6 packet\n");
                } else if(IpType == opennslFieldIpTypeIpv4Any ) {
                         ds_put_format(ds, "\t    Qualifier is IpType - "\
                                           "Any IPv4 packet\n");
                }
            }
        }

        if( OPENNSL_FIELD_QSET_TEST(qset, opennslFieldQualifyPacketRes)) {
            char packet_res_str[MAX_PACKET_RES_STRING_LEN];
            ret = opennsl_field_qualify_PacketRes_get(unit,
                          entry_array[entry_index],(uint32 *)&data,
                          (uint32 *)&mask);
            if (!OPENNSL_FAILURE(ret)) {
                ds_put_format(ds, "\t    Qualifier is PacketRes - ");
                PacketRes_toString(data,packet_res_str);
                ds_put_format(ds, "%s mask 0x%02x\n",
                                packet_res_str, (uint32)  mask);
            }
            data = 0;
            mask = 0;
        }

        if (OPENNSL_FIELD_QSET_TEST(qset, opennslFieldQualifyDstMac)) {
            char mac_str[SAL_MACADDR_STR_LEN];
            char mask_str[SAL_MACADDR_STR_LEN];
            ret = opennsl_field_qualify_DstMac_get(unit,
                  entry_array[entry_index], (opennsl_mac_t *) &data,
                  (opennsl_mac_t *) &mask);
            if (!OPENNSL_FAILURE(ret)) {
                snprintf(mac_str, SAL_MACADDR_STR_LEN, "%s",
                          ether_ntoa((struct ether_addr*)&data));
                snprintf(mask_str, SAL_MACADDR_STR_LEN, "%s",
                          ether_ntoa((struct ether_addr*)&mask));
                ds_put_format(ds, "\t    Qualifier is DstMac - ");
                ds_put_format(ds, "%-18s Mask %-18s\n",
                                   mac_str, mask_str);
            }
            data = 0;
            mask = 0;
        }

        if (OPENNSL_FIELD_QSET_TEST(qset, opennslFieldQualifyIpProtocol)) {
            ret = opennsl_field_qualify_IpProtocol_get(unit,
                  entry_array[entry_index], (uint8 *)&data, (uint8 *)&mask);
            if (!OPENNSL_FAILURE(ret)) {
                ds_put_format(ds, "\t    Qualifier is IpProtocol - ");
                ds_put_format(ds, "0x%02x mask 0x%02x \n", (uint8) data,
                                  (uint8)  mask);
            }
            data = 0;
            mask = 0;
        }

        /*Checking for the actions available in the entry*/
        for(action_index = 0;action_index < fp_action_list_size;action_index++){
            fp_action_iter = &fp_action_list[action_index];
            ret = opennsl_field_action_get(0,entry_array[entry_index],
                            fp_action_iter->action_type, &p0, &p1);
            if (!OPENNSL_FAILURE(ret)) {
                ds_put_format(ds, "\tAction is %s\n",fp_action_iter->api_str);
                ds_put_format(ds, "\t    p0 %u p1 %u\n", p0,p1);
            }
        }
        /* retrieving the stats for the entry */
        ret = opennsl_field_entry_stat_get(0, entry_array[entry_index],
                                           &stat_id);
        ds_put_format(ds, "\tStatistics: ");
        if(stat_id > 0) {
            ds_put_format(ds, "\n\t    Stat id = %d for entry %d\n", stat_id,
                          entry_array[entry_index]);
            for(stat_index=0; stat_index< MAX_STAT_TYPES;stat_index++){
                ret = opennsl_field_stat_get(unit, stat_id,
                                             stat_arr[stat_index],&stat_value);
                if (!OPENNSL_FAILURE(ret)) {
                    ds_put_format(ds, "\t    stat type :%s value is %llu\n",
                                     stat_type_str[stat_index], stat_value);
                }
            }
        } else {
            ds_put_format(ds, "NULL\n");
        }
    }

err:
    free(entry_array);
done:
    ds_put_format(ds, "Done traversing through group id = %d\n", group );
} /* fp_entries_show */

static int
fp_field_group_traverse_cb (int unit, opennsl_field_group_t group, void *user_data)
{
    struct knet_user_data *params = (struct knet_user_data *)user_data;
    struct ds *ds = params->ds;

    /* To display the FP Group  and entry information */
    fp_entries_show(unit, group, ds);
    params->count++;

    return OPENNSL_E_NONE;
} /* fp_field_traverse_cb */

static void
ops_fp_show_dump(struct ds *ds)
{
    struct knet_user_data user_data;
    int unit = 0;
    int ret;

    user_data.ds = ds;
    user_data.count = 0;
    /* the per fp group traversal function and this is for every hw unit*/
    for(unit =0; unit < MAX_SWITCH_UNITS; unit++) {
        ret = opennsl_field_group_traverse (unit, fp_field_group_traverse_cb,
                                               &user_data);
        if (OPENNSL_FAILURE(ret)) {
            VLOG_ERR("FP show groups traversal failure");
        }
        if (user_data.count == 0) {
            ds_put_format(ds, "No  fp groups \n");
        }
    }
} /* ops_fp_show_dump */

static void
bcm_plugin_debug(struct unixctl_conn *conn, int argc,
                 const char *argv[], void *aux OVS_UNUSED)
{
    const char *ch;
    struct ds ds = DS_EMPTY_INITIALIZER;

    // arg[0] should simply be the ovs-appctl option
    // "plugin/debug", so start at arg index 1
    int arg_idx = 1;

    if (argc <= arg_idx) {
        ds_put_format(&ds, "%s", cmd_hp_usage);
        goto done;

    } else {
        ch = NEXT_ARG();

        if (0 == strcmp(ch, "debug")) {
            handle_ops_debug(&ds, arg_idx, argc, argv);
            goto done;
        } else if (!strcmp(ch, "fp")) {
            ds_put_format(&ds, "Programmed FP rules are \n");
            ops_fp_show_dump(&ds);
            goto done;
        } else if (!strcmp(ch, "vlan")) {
            int vid = -1;

            if (NULL != (ch = NEXT_ARG())) {
                vid = atoi(ch);
            }
            ops_vlan_dump(&ds, vid);
            goto done;

        } else if (!strcmp(ch, "stg")) {
            int stgid = -1;

            if (NULL != (ch = NEXT_ARG())) {
                stgid = atoi(ch);
            }
            ops_stg_dump(&ds, stgid);
            goto done;

        } else if (!strcmp(ch, "knet")) {
            if (NULL != (ch = NEXT_ARG())) {
                if (!strcmp(ch, "netif")) {
                    /* KNET netif information */
                    ops_knet_dump(&ds, KNET_DEBUG_NETIF);
                } else if (!strcmp(ch, "filter")) {
                    /* KNET filter information */
                    ops_knet_dump(&ds, KNET_DEBUG_FILTER);
                } else {
                    ds_put_format(&ds, "Unsupported knet command - %s.\n", ch);
                }
            } else {
                ds_put_format(&ds, "Knet command requires a valid subcommand.\n");
            }
            goto done;

        } else if (!strcmp(ch, "l3intf")) {
            int intfid = -1;
            if (NULL != (ch = NEXT_ARG())) {
                intfid = atoi(ch);
            }
            ops_l3intf_dump(&ds, intfid);
            goto done;

        } else if (!strcmp(ch, "l3host")) {
            ops_l3host_dump(&ds, FALSE);
            goto done;

        } else if (!strcmp(ch, "l3v6host")) {
            ops_l3host_dump(&ds, TRUE);
            goto done;

        } else if (!strcmp(ch, "l3route")) {
            ops_l3route_dump(&ds, FALSE);
            goto done;

        } else if (!strcmp(ch, "l3v6route")) {
            ops_l3route_dump(&ds, TRUE);
            goto done;

        } else if (!strcmp(ch, "l3egress")) {
            int egressid = -1;
            if (NULL != (ch = NEXT_ARG())) {
                egressid = atoi(ch);
            }
            ops_l3egress_dump(&ds, egressid);
            goto done;

        } else if (!strcmp(ch, "l3ecmp")) {
            int ecmpid = -1;
            if (NULL != (ch = NEXT_ARG())) {
                ecmpid = atoi(ch);
            }
            ops_l3ecmp_egress_dump(&ds, ecmpid);
            goto done;

        } else if (!strcmp(ch, "lag")) {
            opennsl_trunk_t lagid = -1;

            if (NULL != (ch = NEXT_ARG())) {
                lagid = atoi(ch);
            }
            ops_lag_dump(&ds, lagid);
            goto done;

        } else if (!strcmp(ch, "help")) {
            ds_put_format(&ds, "%s", cmd_hp_usage);
            goto done;

        } else {
            ds_put_format(&ds, "Unknown or unsupported command - %s.\n", ch);
            goto done;
        }
    }

done:
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

} // bcm_plugin_debug

char cmd_mac_usage[] =
"Usage:\n\t"
"ovs-appctl plugin/dump-mac-table [ port|vlan <id list> ]\n"
"\n"
"   Without args, dumps all MAC table entries.\n"
"   With ports, displays MAC table entries that match the ports.\n"
"   With vlans, displays MAC table entries that match the vlans.\n"
"\n"
"   The identifier list for ports is a comma-separated list of the named ports.\n"
"   The identifier list for vlans is a comma-separated list of vlan ranges,\n"
"   where a range can be a single vlan or a low-high pair.\n"
;

#define MAX_VLAN_IDS    4096

enum mac_match_type { MATCH_NONE, MATCH_VLAN, MATCH_PORT };

typedef struct {
    enum mac_match_type type;
    bool *match_factor_vlan;
    char **match_factor_port;
} mac_match_t;

typedef bool (*mac_filter_t)(opennsl_l2_addr_t *, mac_match_t *, const char *name);

typedef struct {
    mac_match_t *match;
    mac_filter_t filter;
    struct ds   *ds;
} l2_traverse_data_t;

struct hw_addr {
    int hw_unit;
    int hw_id;
};

static bool
port_filter(opennsl_l2_addr_t *result, mac_match_t *match, const char *name)
{
    int idx;

    if (match->match_factor_port) {
        for (idx = 0; match->match_factor_port[idx] != NULL; idx++) {
            if (strcmp(name, match->match_factor_port[idx]) == 0) {
                return true;
            }
        }
    }

    return false;
} // port_filter

static bool
vlan_filter(opennsl_l2_addr_t *result, mac_match_t *match, const char *name __attribute__((unused)))
{
    if (match->match_factor_vlan &&
        result->vid < MAX_VLAN_IDS &&
        match->match_factor_vlan[result->vid] == true) {
        return true;
    }

    return false;
} // vlan_filter

static bool
no_filter(opennsl_l2_addr_t *result __attribute__((unused)),
          mac_match_t *match __attribute__((unused)),
          const char *name __attribute__((unused)))
{
    return true;
} // no_filter

static int
process_mac_table_cb(int unit, opennsl_l2_addr_t *addr, void *ptr)
{
    l2_traverse_data_t *user_data = (l2_traverse_data_t *)ptr;
    struct ops_port_info *p_info = PORT_INFO(unit, addr->port);

    if (p_info == NULL || p_info->name == NULL) {
        return 0;
    }
    if (user_data->filter(addr, user_data->match, p_info->name)) {
        ds_put_format(user_data->ds,
                      "%4d %02x:%02x:%02x:%02x:%02x:%02x %7s %5d %s\n",
                      addr->vid,
                      addr->mac[0],
                      addr->mac[1],
                      addr->mac[2],
                      addr->mac[3],
                      addr->mac[4],
                      addr->mac[5],
                      (addr->flags & OPENNSL_L2_STATIC) == 0 ? "DYNAMIC" : "STATIC ",
                      addr->tgid,
                      p_info->name);
    }

    return 0;
} // process_mac_table_cb

static void
process_mac_table(mac_match_t *match, mac_filter_t filter, struct ds *ds)
{
    l2_traverse_data_t user_data;
    int idx;

    for (idx = 0; idx < MAX_SWITCH_UNITS; idx++) {
        if (port_info[idx] != NULL) {
            int age_seconds;
            if (opennsl_l2_age_timer_get(idx, &age_seconds) == OPENNSL_E_NONE) {
                ds_put_format(ds, "MAC age timer: unit=%d seconds=%d\n",
                              idx, age_seconds);
            }
        }
    }

    ds_put_format(ds, "%4s %17s %7s %5s %9s\n",
                  " VID",
                  "MAC ADDRESS      ",
                  "TYPE   ",
                  "TRUNK",
                  "PORT NAME");
    user_data.match = match;
    user_data.filter = filter;
    user_data.ds = ds;
    for (idx = 0; idx < MAX_SWITCH_UNITS; idx++) {
        if (port_info[idx] != NULL) {
            opennsl_l2_traverse(idx, process_mac_table_cb, &user_data);
        }
    }
} // process_mac_table

static int
parse_port_ids(const char *ports, mac_match_t *match)
{
    char *working;
    char *end;
    const char *ptr = ports;
    int idx;
    int count;

    count = 1;

    for (ptr = ports; *ptr != 0; ptr++) {
        if (*ptr == ',') {
            count++;
        }
    }

    match->match_factor_port = (char **)calloc(count + 1, sizeof(char *));

    ptr = ports;
    idx = 0;

    while (*ptr != 0) {
        /* split string by commas */
        end = strchr(ptr, ',');
        if (end == NULL) {
            working = strdup(ptr);
            ptr += strlen(working);
        } else {
            working = strndup(ptr, end - ptr);
            ptr += strlen(working) + 1;
        }

        match->match_factor_port[idx] = working;
        idx++;
    }

    return 0;
} // parse_port_ids

static int
parse_vlan_ids(const char *vlans, mac_match_t *match)
{
    char *working;
    char *end;
    const char *ptr = vlans;
    int start, stop, vid;

    while (*ptr != 0) {
        if (strchr("0123456789,-", *ptr) == NULL) {
            return -1;
        }
        ptr++;
    }

    ptr = vlans;

    while (*ptr != 0) {
        /* split string by commas */
        end = strchr(ptr, ',');
        if (end == NULL) {
            working = strdup(ptr);
            ptr += strlen(working);
        } else {
            working = strndup(ptr, end - ptr);
            ptr += strlen(working) + 1;
        }

        /* for each item, split item by single hyphen (if present) */
        end = strchr(working, '-');

        if (end == NULL) {
            start = stop = strtol(working, 0, 0);
        } else {
            *end = 0;
            end += 1;
            start = strtol(working, 0, 0);
            stop = strtol(end, 0, 0);
        }
        for (vid = start; vid < MAX_VLAN_IDS && vid <= stop; vid++) {
            match->match_factor_vlan[vid] = true;
        }

        free(working);
    }
    return 0;
} // parse_vlan_ids

static void
bcm_mac_debug(struct unixctl_conn *conn, int argc,
              const char *argv[], void *aux OVS_UNUSED)
{
    int rc;
    struct ds ds = DS_EMPTY_INITIALIZER;
    mac_match_t match;
    mac_filter_t filter;
    int idx;

    memset(&match, 0, sizeof(match));

    if (argc == 1) {
        match.type = MATCH_NONE;
        filter = no_filter;
    } else if (argc != 3) {
        ds_put_format(&ds, "%s", cmd_mac_usage);
        goto done;
    } else if (strcmp(argv[1], "vlan") == 0) {
        match.type = MATCH_VLAN;
        match.match_factor_vlan = (bool *)xcalloc(MAX_VLAN_IDS, sizeof(bool));
        rc = parse_vlan_ids(argv[2], &match);
        if (rc < 0) {
            ds_put_format(&ds, "Invalid VLAN specification: %s", argv[2]);
            goto done;
        }
        filter = vlan_filter;
    } else if (strcmp(argv[1], "port") == 0) {
        match.type = MATCH_PORT;
        match.match_factor_port = NULL;
        rc = parse_port_ids(argv[2], &match);
        if (rc < 0) {
            ds_put_format(&ds, "Invalid PORT specification: %s", argv[2]);
            goto done;
        }
        filter = port_filter;
    } else {
        ds_put_format(&ds, "%s", cmd_mac_usage);
        goto done;
    }

    process_mac_table(&match, filter, &ds);

    /* free any allocated memory */
    free(match.match_factor_vlan);
    for (idx = 0; match.match_factor_port != NULL &&
                  match.match_factor_port[idx] != NULL; idx++) {
        free(match.match_factor_port[idx]);
    }
    free(match.match_factor_port);

done:
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
} // bcm_mac_debug

///////////////////////////////// INIT /////////////////////////////////

int
ops_debug_init(void)
{
    unixctl_command_register("plugin/debug", "[cmds]", 0, INT_MAX,
                             bcm_plugin_debug, NULL);
    unixctl_command_register("plugin/dump-mac-table", "[port|vlan <id list>]",
                             0 , 2, bcm_mac_debug, NULL);

    return 0;

} // ops_debug_init
