/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    hc_debug.c
 *
 * Purpose: Main file for the implementation of HP Open Halon specific BCM shell debug commands.
 *
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

#include "hc-lag.h"
#include "platform-defines.h"
#include "hc-vlan.h"
#include "hc-debug.h"
#include "hc-routing.h"
#include "ofproto-bcm-provider.h"
#include "hc-port.h"

VLOG_DEFINE_THIS_MODULE(hc_debug);


uint32 slog_level = 0x0;

// HALON_TODO: for BPDU TX/RX debugging.
int pkt_debug = 0;

hc_debug_t hc_debug_list[] = {

    {"rx_tx_pkt",   0},         // to print RX/TX packets on BCM shell
    {"hc_init", SWITCHD_INIT_DBG},
    {"port",    SWITCHD_PORT_DBG},
    {"lag",     SWITCHD_LAG_DBG},
    {"vlan",    SWITCHD_VLAN_DBG},
    {"l3",      SWITCHD_L3_DBG},
};

// Broadcom shell debug command.
char cmd_hp_usage[] =
"Usage:\n\t"
"ovs-appctl plugin/debug <cmds> - Run HP OpenHalon BCM Plugin specific debug commands.\n"
"\n"
"   debug [[+/-]<option> ...] [all/none] - enable/disable debugging.\n"
"   vlan <vid> - displays Halon VLAN info.\n"
"   l3intf [<interface id>] - display Halon interface info.\n"
"   l3host - display Halon l3 host info.\n"
"   l3v6host - display Halon l3 IPv6 host info.\n"
"   l3route - display Halon l3 Routes.\n"
"   l3v6route - display Halon l3 IPv6 Routes.\n"
"   lag [<lagid>] - displays Halon LAG info.\n"
"   help - displays this help text.\n"
;

char *
bcmsdk_datapath_version(void)
{
    // We can't just pass back "_build_release" global variable
    // since bcmsdk is being built as a shared library.  Need
    // to make a copy so OVS code can use it properly.
    static char *rel_version = NULL;

    if (NULL == rel_version) {
        // HALON_TODO: need to automate this.
        //rel_version = strdup(_build_release);
        rel_version = strdup("6.4.5.5");
    }
    return rel_version;

} // bcmsdk_datapath_version

////////////////////////////////////////////////////////////////////////

#define NEXT_ARG()  ((arg_idx < argc) ? argv[arg_idx++] : NULL)

static void
handle_hc_debug(struct ds *ds, int arg_idx, int argc, const char *argv[])
{
    char        c = '\0';
    const char *ch = NULL;
    uint8       i = 0;
    uint8       count = 1;
    uint8       found = 0;
    uint8       dbg_list_sz = 0;
    hc_debug_t  *dbg = NULL;

    dbg_list_sz = (sizeof(hc_debug_list)/sizeof(hc_debug_t));

    // If no parameters are given.
    if (arg_idx >= argc) {

        ds_put_format(ds, "slog_level = 0x%x\n", slog_level);

        // print the list of debug enabled subsystems
        ds_put_format(ds, "Debugging is enabled for the following subsystems:\n");

        if (pkt_debug) {
            ds_put_format(ds, "rx_tx_pkt  ");
        }

        for (i=0; i < dbg_list_sz; i++) {
            dbg = &hc_debug_list[i];
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
            dbg = &hc_debug_list[i];
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
                    dbg = &hc_debug_list[i];
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
                    dbg = &hc_debug_list[i];
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
} // handle_hc_debug

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
            handle_hc_debug(&ds, arg_idx, argc, argv);
            goto done;
        } else if (!strcmp(ch, "vlan")) {
            int vid = -1;

            if (NULL != (ch = NEXT_ARG())) {
                vid = atoi(ch);
            }
            hc_vlan_dump(&ds, vid);
            goto done;

        } else if (!strcmp(ch, "l3intf")) {
            int intfid = -1;
            if (NULL != (ch = NEXT_ARG())) {
                intfid = atoi(ch);
            }
            hc_l3intf_dump(&ds, intfid);
            goto done;

        } else if (!strcmp(ch, "l3host")) {
            hc_l3host_dump(&ds, FALSE);
            goto done;

        } else if (!strcmp(ch, "l3v6host")) {
            hc_l3host_dump(&ds, TRUE);
            goto done;

        } else if (!strcmp(ch, "l3route")) {
            hc_l3route_dump(&ds, FALSE);
            goto done;

        } else if (!strcmp(ch, "l3v6route")) {
            hc_l3route_dump(&ds, TRUE);
            goto done;

        } else if (!strcmp(ch, "lag")) {
            opennsl_trunk_t lagid = -1;

            if (NULL != (ch = NEXT_ARG())) {
                lagid = atoi(ch);
            }
            hc_lag_dump(&ds, lagid);
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
    struct hc_port_info *p_info = PORT_INFO(unit, addr->port);

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
hc_debug_init(void)
{
    unixctl_command_register("plugin/debug", "[cmds]", 0, INT_MAX,
                             bcm_plugin_debug, NULL);
    unixctl_command_register("plugin/dump-mac-table", "[port|vlan <id list>]",
                             0 , 2, bcm_mac_debug, NULL);

    return 0;

} // hc_debug_init
