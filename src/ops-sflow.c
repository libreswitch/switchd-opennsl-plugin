/*
 * (C) Copyright 2015-2016 Hewlett Packard Enterprise Development Company, L.P.
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
 * File: ops-sflow.c
 *
 * Purpose: sflow configuration implementation in BCM shell and show output.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <platform-defines.h>

#include "ofproto/collectors.h"
#include "ops-stats.h"
#include "ops-sflow.h"
#include "ops-routing.h"
#include "netdev-bcmsdk.h"

VLOG_DEFINE_THIS_MODULE(ops_sflow);

/* sFlow parameters - TODO make these per ofproto */
SFLAgent *ops_sflow_agent = NULL;
struct ofproto_sflow_options *sflow_options = NULL;
struct collectors *sflow_collectors = NULL;

/* sFlow knet filter id's */
int knet_sflow_source_filter_id;
int knet_sflow_dest_filter_id;

static struct ovs_mutex mutex;

/* callbacks registered during sFlow initialization; used for various
 * utilities.
 */
void *
ops_sflow_agent_alloc_cb(void *magic OVS_UNUSED,
                        SFLAgent *ops_agent OVS_UNUSED,
                        size_t sz)
{
    return xmalloc(sz);
}

int
ops_sflow_agent_free_cb(void *magic OVS_UNUSED,
                        SFLAgent *ops_agent OVS_UNUSED,
                        void *obj)
{
    free(obj);
    return 0;
}

void
ops_sflow_agent_error_cb(void *magic OVS_UNUSED, SFLAgent *ops_agent OVS_UNUSED,
                        char *err)
{
    VLOG_ERR("%s", err);
}

/* sFlow library callback to send datagram. */
static void
ops_sflow_agent_pkt_tx_cb(void *ds_, SFLAgent *agent OVS_UNUSED,
                          SFLReceiver *receiver OVS_UNUSED, u_char *pkt,
                          uint32_t pktLen)
{
    collectors_send(sflow_collectors, pkt, pktLen);
}


static bool
string_is_equal(char *str1, char *str2)
{
    if (str1 && str2) {
        return !strcmp(str1, str2);
    } else {
        return (!str1 && !str2);
    }
}

bool
ops_sflow_options_equal(const struct ofproto_sflow_options *oso1,
                        const struct ofproto_sflow_options *oso2)
{
    return (sset_equals(&oso1->targets, &oso2->targets) &&
            (oso1->sampling_rate == oso2->sampling_rate) &&
            (oso1->polling_interval == oso2->polling_interval) &&
            (oso1->header_len == oso2->header_len) &&
            string_is_equal(oso1->agent_device, oso2->agent_device));
}

/* Ethernet Hdr (18 bytes)
 *  DMAC SMAC EtherType VLAN EtherTYpe
 *   6    6       2      2     2   <-- bytes
 */
/* IPv4 Hdr (14 fields, of which 13 are required. Minimum 16 bytes)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
void
print_pkt(const opennsl_pkt_t *pkt)
{
    uint8   i;

    if (pkt == NULL) {
        return;
    }

    VLOG_DBG("[%s:%d]; # of blocks=%d, pkt_len=%d, tot_len=%d",
            __FUNCTION__, __LINE__, pkt->blk_count,
            pkt->pkt_len, pkt->tot_len);

    VLOG_DBG("[%s:%d]; vlan=%d, src_port=%d, dest_port=%d, "
            "rx_port=%d, untagged=%d, vtag0=%d, vtag1=%d, "
            "vtag2=%d, vtag3=%d", __FUNCTION__, __LINE__,
            pkt->vlan, pkt->src_port, pkt->dest_port, pkt->rx_port,
            pkt->rx_untagged, pkt->_vtag[0], pkt->_vtag[1],
            pkt->_vtag[2], pkt->_vtag[3]);

#define PKT pkt->pkt_data[i].data

    for(i=0; i<pkt->blk_count; i++) {
        VLOG_DBG("[%s:%d]; blk num=%d, blk len=%d", __FUNCTION__, __LINE__,
                i, pkt->pkt_data[i].len);

        VLOG_DBG("==============ETHERNET HEADER===============");
        VLOG_DBG("DMAC: %02X:%02X:%02X:%02X:%02X:%02X",
                pkt->pkt_data[i].data[0], pkt->pkt_data[i].data[1],
                pkt->pkt_data[i].data[2], pkt->pkt_data[i].data[3],
                pkt->pkt_data[i].data[4], pkt->pkt_data[i].data[5]);

        VLOG_DBG("SMAC: %02X:%02X:%02X:%02X:%02X:%02X",
                pkt->pkt_data[i].data[6], pkt->pkt_data[i].data[7],
                pkt->pkt_data[i].data[8], pkt->pkt_data[i].data[9],
                pkt->pkt_data[i].data[10], pkt->pkt_data[i].data[11]);

        VLOG_DBG("EtherType: %02X%02X Vlan: %02X%02X EtherType: %02X%02X",
                pkt->pkt_data[i].data[12], pkt->pkt_data[i].data[13],
                pkt->pkt_data[i].data[14], pkt->pkt_data[i].data[15],
                pkt->pkt_data[i].data[16], pkt->pkt_data[i].data[17]);

        VLOG_DBG("==============IPv4  HEADER===============");
        VLOG_DBG("Ver/IHL: %02X ToS: %02X Len: %02X%02X",
                pkt->pkt_data[i].data[18], pkt->pkt_data[i].data[19],
                pkt->pkt_data[i].data[20], pkt->pkt_data[i].data[21]);

        VLOG_DBG("Src: %02X.%02X.%02X.%02X",
                pkt->pkt_data[i].data[30], pkt->pkt_data[i].data[31],
                pkt->pkt_data[i].data[32], pkt->pkt_data[i].data[33]);

        VLOG_DBG("Dest: %02X.%02X.%02X.%02X",
                pkt->pkt_data[i].data[34], pkt->pkt_data[i].data[35],
                pkt->pkt_data[i].data[36], pkt->pkt_data[i].data[37]);
    }
}

/* Fn to write received sample pkt to buffer. Wrapper for
 * sfl_sampler_writeFlowSample() routine. */
void ops_sflow_write_sampled_pkt(opennsl_pkt_t *pkt)
{
    SFL_FLOW_SAMPLE_TYPE    fs;
    SFLFlow_sample_element  hdrElem;
    SFLSampled_header       *header;
    SFLSampler              *sampler;

    if (pkt == NULL) {
        VLOG_ERR("NULL sFlow pkt received. Can't be buffered.");
        return;
    }

    /* sFlow Agent is uninitialized. Error condition or it's not enabled
     * yet. */
    if (ops_sflow_agent == NULL) {
        VLOG_ERR("sFlow Agent uninitialized.");
        return;
    }

    sampler = ops_sflow_agent->samplers;
    if (sampler == NULL) {
        VLOG_ERR("Sampler on sFlow Agent uninitialized.");
        return;
    }

    ovs_mutex_lock(&mutex);

    memset(&fs, 0, sizeof fs);

    /* Sampled header. */
    memset(&hdrElem, 0, sizeof hdrElem);
    hdrElem.tag = SFLFLOW_HEADER;
    header = &hdrElem.flowType.header;
    header->header_protocol = SFLHEADER_ETHERNET_ISO8023;

    /* The frame_length is original length of packet before it was sampled
     * (tot_len).
     */
    header->frame_length = pkt->tot_len;

    /* Ethernet FCS stripped off. */
    header->stripped = 4;
    header->header_length = MIN(header->frame_length,
                                sampler->sFlowFsMaximumHeaderSize);

    /* TODO: OpenNSL saves incoming data as an array of structs
     * containing {len, data} pairs. For each element of the struct, 'data'
     * can be up to 65535 bytes long. Run traffic to test these boundary
     * conditions (Jumbo Frames?). */
    header->header_bytes = (uint8_t *)pkt->pkt_data[0].data;

    fs.input = pkt->src_port;
    fs.output = pkt->dest_port;

    /* Submit the flow sample to be encoded into the next datagram. */
    SFLADD_ELEMENT(&fs, &hdrElem);
    sfl_sampler_writeFlowSample(sampler, &fs);

    ovs_mutex_unlock(&mutex);
}

/* Set sampling rate on a port. This only sets the rate if sFlow is
 * configured globally. Otherwise, this is a no-op. */
void
ops_sflow_set_per_interface (const int unit, const int port, bool set)
{
    int rc;
    SFLSampler  *sampler;
    uint32_t    dsIndex;
    SFLDataSource_instance  dsi;
    int ingress_rate, egress_rate;

    if (port <= 0) {
        VLOG_ERR("Invalid port number (%d). Cannot enable/disable "
                "sFlow on it.", port);
        return;
    }

    if (ops_sflow_agent == NULL) {
        VLOG_DBG("sFlow is not configured globally. Can't [en/dis]able sFlow "
                "on port: %d.", port);
        return;
    }

    /* sFlow agent exists (sFlow is configured on switch globally). */

    /* enable sFlow on port. This is default config. When sFlow is enabled
     * globally, it's enabled on all ports by default. */
    if (set) {
        dsIndex = 1000 + sflow_options->sub_id;
        SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, dsIndex, 0);
        sampler = sfl_agent_getSampler(ops_sflow_agent, &dsi);

        if (sampler == NULL) {
            VLOG_ERR("There is no Sampler for sFlow Agent.");
            return;
        }

        ingress_rate = egress_rate = sampler->sFlowFsPacketSamplingRate;
        rc = opennsl_port_sample_rate_set(unit, port, ingress_rate, egress_rate);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set sampling rate on port: %d, (error-%s).",
                    port, opennsl_errmsg(rc));
            return;
        }
    } else {
        /* zero rate clears sampling on ASIC */
        rc = opennsl_port_sample_rate_set(unit, port, 0, 0);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set sampling rate on port: %d, (error-%s).",
                    port, opennsl_errmsg(rc));
            return;
        }
    }
}

/* callback function to get the per-port interface counters */
static void
ops_sflow_get_port_counters(void *arg, SFLPoller *poller,
                            SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    uint64_t speed;
    uint32_t hw_unit = 0, hw_port = 0;
    uint32_t index, direction, status;
    struct ops_sflow_port_stats stats;
    SFLCounters_sample_element elem;
    SFLIf_counters *counters;

    ovs_mutex_lock(&mutex);
    hw_unit = (poller->bridgePort & 0xFFFF0000) >> 16;
    hw_port = poller->bridgePort & 0x0000FFFF;


    netdev_bcmsdk_get_sflow_intf_info(hw_unit, hw_port, &index, &speed,
                                      &direction, &status);
    bcmsdk_get_sflow_port_stats(hw_unit, hw_port, &stats);

    elem.tag = SFLCOUNTERS_GENERIC;
    counters = &elem.counterBlock.generic;
    counters->ifIndex = index;
    counters->ifType = 6;
    counters->ifSpeed = speed;
    counters->ifDirection = direction;
    counters->ifStatus = status;
    counters->ifInOctets = stats.in_octets;
    counters->ifInUcastPkts = stats.in_ucastpkts;
    counters->ifInMulticastPkts = stats.in_multicastpkts;
    counters->ifInBroadcastPkts = stats.in_broadcastpkts;
    counters->ifInDiscards = stats.in_discards;
    counters->ifInErrors = stats.in_errors;
    counters->ifInUnknownProtos = stats.in_unknownprotos;
    counters->ifOutOctets = stats.out_octets;
    counters->ifOutUcastPkts = stats.out_ucastpkts;
    counters->ifOutMulticastPkts = stats.out_multicastpkts;
    counters->ifOutBroadcastPkts = stats.out_broadcastpkts;
    counters->ifOutDiscards = stats.out_discards;
    counters->ifOutErrors = stats.out_errors;
    counters->ifPromiscuousMode = 0;

    VLOG_DBG("sflow stats %d,%d [%d, %d, %d, %d, %d/%d, %d, %d, %d/%d, %d, %d]\n",
             hw_unit, hw_port, index, (int)speed, direction, status,
             stats.in_ucastpkts, (int)stats.in_octets, stats.in_discards,
             stats.in_errors, stats.out_ucastpkts, (int)stats.out_octets,
             stats.out_discards, stats.out_errors);

    SFLADD_ELEMENT(cs, &elem);

    sfl_poller_writeCountersSample(poller, cs);

    ovs_mutex_unlock(&mutex);
}

static void
ops_sflow_set_dsi(SFLDataSource_instance *dsi, int hw_unit, int hw_port)
{
    uint32_t dsIndex;
    dsIndex = 1000 + sflow_options->sub_id +
                     (hw_unit * MAX_PORTS(hw_unit)) + hw_port;
    SFL_DS_SET(*dsi, SFL_DSCLASS_PHYSICAL_ENTITY, dsIndex, 0);
}

/* Configure polling per interface */
static void
ops_sflow_set_polling_per_interface(int hw_unit, int hw_port, int interval)
{
    SFLPoller *poller;
    uint32_t unit_port = 0;
    SFLDataSource_instance dsi;

    VLOG_DBG("Config polling for hw_unit %d, hw_port %d, interval %d\n",
              hw_unit, hw_port, interval);

    if (!ops_sflow_agent || hw_port == -1) { /* -1 set for some virtual intf */
        return;
    }

    ops_sflow_set_dsi(&dsi, hw_unit, hw_port);
    poller = sfl_agent_addPoller(ops_sflow_agent, &dsi, NULL,
                                 ops_sflow_get_port_counters);
    sfl_poller_set_sFlowCpInterval(poller, interval);
    sfl_poller_set_sFlowCpReceiver(poller, SFLOW_RECEIVER_INDEX);
    poller->lastPolled = time(NULL);
    /* store hw_unit and hw_port into a single uint32 to use in the callback.
     * take the 16 LSB from both and fit into the uint32
     */
    unit_port = ((hw_unit & 0x0000FFFF) << 16) | (hw_port & 0x0000FFFF);
    sfl_poller_set_bridgePort(poller, unit_port);
}


void
ops_sflow_add_port(struct netdev *netdev)
{
    int hw_unit = 0, hw_port = 0;
    if (netdev && sflow_options) {
        netdev_bcmsdk_get_hw_info(netdev, &hw_unit, &hw_port, NULL);
        ops_sflow_set_polling_per_interface(hw_unit, hw_port,
                                            sflow_options->polling_interval);
    }
}

/* Update polling interval for all the configured interfaces in the system. */
void
ops_sflow_set_polling_interval(struct bcmsdk_provider_node *ofproto, int interval)
{
    struct ofbundle *bundle;
    int hw_unit = 0, hw_port = 0;
    struct bcmsdk_provider_ofport_node *port = NULL, *next_port = NULL;

    if (ops_sflow_agent) {
        HMAP_FOR_EACH(bundle, hmap_node, &ofproto->bundles) {
            LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {
                if (port->sflow_polling_interval != interval) {
                    netdev_bcmsdk_get_hw_info(port->up.netdev, &hw_unit, &hw_port, NULL);
                    ops_sflow_set_polling_per_interface(hw_unit, hw_port, interval);
                    port->sflow_polling_interval = interval;
                }
            }
        }
    }
}

/* Set sampling rate in sFlow Agent and also in ASIC. */
void
ops_sflow_set_sampling_rate(const int unit, const int port,
                            const int ingress_rate, const int egress_rate)
{
    int rc;
    opennsl_port_t tempPort = 0;
    opennsl_port_config_t port_config;
    SFLSampler  *sampler;
    uint32_t    dsIndex;
    SFLDataSource_instance  dsi;

    VLOG_DBG("%s:%d, port: %d, ing: %d, egr: %d", __FUNCTION__, __LINE__, port,
            ingress_rate, egress_rate);

    /* Retrieve the port configuration of the unit */
    rc = opennsl_port_config_get (unit, &port_config);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to retrieve port config. Can't set sampling rate. "
                "(rc=%s)", opennsl_errmsg(rc));
        return;
    }

    if (port) { /* set for specific port */
        rc = opennsl_port_sample_rate_set(unit, port, ingress_rate, egress_rate);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set sampling rate on port: %d, (error-%s).",
                    port, opennsl_errmsg(rc));
            return;
        }

    } else { /* set globally, on all ports */
        /* Iterate over all front-panel (e - ethernet) ports */
        OPENNSL_PBMP_ITER (port_config.e, tempPort) {
            opennsl_port_sample_rate_set(unit, tempPort, ingress_rate,
                                    egress_rate);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to set sampling rate on port: %d, (error-%s)",
                        port, opennsl_errmsg(rc));
                return;
            }
        }
    }

    /* set sampling rate on Sampler corresponding to 'port' */
    if (ops_sflow_agent) {
        dsIndex = 1000 + sflow_options->sub_id;
        SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, dsIndex, 0);
        sampler = sfl_agent_getSampler(ops_sflow_agent, &dsi);

        if (sampler == NULL) {
            VLOG_ERR("There is no Sampler for sFlow Agent.");
            return;
        }

        sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, ingress_rate);
    }
}

static void
ops_sflow_set_rate(struct unixctl_conn *conn, int argc, const char *argv[],
                   void *aux OVS_UNUSED)
{
    int ingress_rate, egress_rate;
    int hw_unit, hw_id;

    if (strncmp(argv[1], "global", 6) == 0) {
        hw_id = 0; /* invalid port # */
        hw_unit = 0;
    } else {
        netdev_bcmsdk_get_hw_info_from_name(argv[1], &hw_unit,
                                            &hw_id);
    }

    ingress_rate = atoi(argv[2]);
    egress_rate = atoi(argv[3]);

    ops_sflow_set_sampling_rate(hw_unit, hw_id, ingress_rate, egress_rate);

    unixctl_command_reply(conn, '\0');
}

static void
ops_sflow_show (struct unixctl_conn *conn, int argc, const char *argv[],
              void *aux OVS_UNUSED)
{
    int rc;
    struct ds ds = DS_EMPTY_INITIALIZER;
    int ingress_rate, egress_rate;
    int port=0;
    opennsl_port_t tempPort = 0;
    opennsl_port_config_t port_config;

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    ds_put_format(&ds, "\t\t SFLOW SETTINGS\n");
    ds_put_format(&ds, "\t\t ==============\n");

    ds_put_format(&ds, "\tPORT\tINGRESS RATE\tEGRESS RATE\n");
    ds_put_format(&ds, "\t====\t============\t===========\n");

    /* Retrieve the port configuration of the unit */
    rc = opennsl_port_config_get (0, &port_config);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to retrieve port config. Can't get sampling rate. "
                "(rc=%s)", opennsl_errmsg(rc));
        return;
    }

    if (port) { /* sflow for specific port */
        rc = opennsl_port_sample_rate_get(0, port, &ingress_rate, &egress_rate);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to get sample rate for port: %d (error-%s)",
                    port, opennsl_errmsg(rc));
            goto done;
        }
        ds_put_format(&ds, "\t%2d\t%6d\t\t%6d\n", port, ingress_rate, egress_rate);
    } else { /* sflow on all ports of switch */
        OPENNSL_PBMP_ITER (port_config.e, tempPort) {
            rc = opennsl_port_sample_rate_get(0, tempPort, &ingress_rate, &egress_rate);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed on port (%d) while getting global sample rate "
                        "(error-%s)", tempPort, opennsl_errmsg(rc));
                goto done;
            }
            ds_put_format(&ds, "\t%2d\t%6d\t\t%6d\n", tempPort, ingress_rate, egress_rate);
        }
    }

done:
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
ops_sflow_options_init(struct ofproto_sflow_options *oso)
{
    sset_init(&(oso->targets));
    oso->sampling_rate = SFL_DEFAULT_SAMPLING_RATE;
    oso->polling_interval = SFL_DEFAULT_POLLING_INTERVAL;
    oso->header_len = SFL_DEFAULT_HEADER_SIZE;
    oso->control_ip = NULL;
}

/* Initial creation of sFlow Agent. Creates an Agent only once. */
static SFLAgent *
ops_sflow_alloc(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    SFLAgent *sfl_agent;

    if (ovsthread_once_start(&once)) {
        ovs_mutex_init_recursive(&mutex);
        ovsthread_once_done(&once);
    }

    sfl_agent = xmalloc(sizeof (SFLAgent));
    return sfl_agent;
}

/* Setup an sFlow Agent. For now, have only one receiver/sampler/poller and
 * enhance later. 'oso' is used to feed Agent fields. For first time, 'oso'
 * is NULL. sFlow Agent must be created only once.
 */
void
ops_sflow_agent_enable(struct bcmsdk_provider_node *ofproto,
                       struct ofproto_sflow_options *oso)
{
    SFLReceiver *receiver;
    SFLSampler  *sampler;
    SFLDataSource_instance dsi;
    SFLAddress  agentIP;
    struct in_addr myIP;
    struct in6_addr myIP6;
    uint32_t    dsIndex;
    time_t      now;
    uint32_t    rate;
    int         af;
    void        *addr;

    if (!ofproto) {
        return;
    }

    if (sflow_options == NULL) {
        VLOG_DBG("ofproto_sflow_options is NULL. Create new options.");
        sflow_options = xmalloc(sizeof *sflow_options);
        memset (sflow_options, 0, sizeof *sflow_options);

        if (oso) {
            memcpy(sflow_options, oso, sizeof *oso);
            sset_init(&sflow_options->targets);
            sset_clone(&sflow_options->targets, &oso->targets);
        } else {
            ops_sflow_options_init(sflow_options);
        }
    }

    /* create/enable sFlow Agent */
    if (ops_sflow_agent == NULL) {
        ops_sflow_agent = ops_sflow_alloc();
    } else {
        VLOG_DBG("sFlow Agent is already created. Nothing to do.");
        return;
    }

    memset(&agentIP, 0, sizeof agentIP);

    /* set IP on sFlow agent. */
    if (oso->agent_ip) {
        if (strchr(oso->agent_ip, ':'))  {
            memset(&myIP6, 0, sizeof myIP6);
            af = AF_INET6;
            agentIP.type = SFLADDRESSTYPE_IP_V6;
            addr = &myIP6;
        } else {
            memset(&myIP, 0, sizeof myIP);
            af = AF_INET;
            agentIP.type = SFLADDRESSTYPE_IP_V4;
            addr = &myIP;
        }

        if (inet_pton(af, oso->agent_ip, addr) != 1) {
            /* This error condition should not happen. */
            VLOG_ERR("sFlow Agent device IP is malformed:%s", oso->agent_ip);
        }

        if (agentIP.type == SFLADDRESSTYPE_IP_V4) {
            agentIP.address.ip_v4.addr = myIP.s_addr;
        } else {
            memcpy(agentIP.address.ip_v6.addr, myIP6.s6_addr, 16);
        }
    }

    time (&now);    /* current time. */

    /* AGENT: init sFlow Agent */
    sfl_agent_init(ops_sflow_agent, /* global instance of sFlow Agent */
            &agentIP,   /* Agents src IP */
            sflow_options->sub_id,
            now,    /* Boot time */
            now,    /* Current time (same as Boot time) */
            0,      /* TODO: Unclear how 'magic' param is used. Setting to 0 for now. */
            ops_sflow_agent_alloc_cb,
            ops_sflow_agent_free_cb,
            ops_sflow_agent_error_cb,
            ops_sflow_agent_pkt_tx_cb);

    /* RECEIVER: aka Collector */
    receiver = sfl_agent_addReceiver(ops_sflow_agent);
    sfl_receiver_set_sFlowRcvrOwner(receiver, "Openswitch sFlow Receiver");
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xffffffff);

    ops_sflow_set_collectors(&sflow_options->targets);

    /* SAMPLER: OvS lib for sFlow seems to encourage one Sampler per
     * interface. Currently, OPS will have only one Sampler for all
     * interfaces. This may change when per-interface sampling is enabled. */
    dsIndex = 1000 + sflow_options->sub_id;
    SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, dsIndex, 0);
    sampler = sfl_agent_addSampler(ops_sflow_agent, &dsi);

    if (sflow_options->sampling_rate) {
        rate = sflow_options->sampling_rate;
    } else {
        rate = SFL_DEFAULT_SAMPLING_RATE;
    }

    sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, rate);

    ops_sflow_set_sampling_rate(0, 0, rate, rate);  // download the rate to ASIC

    sfl_sampler_set_sFlowFsMaximumHeaderSize(sampler, SFL_DEFAULT_HEADER_SIZE);
    sfl_sampler_set_sFlowFsReceiver(sampler, SFLOW_RECEIVER_INDEX);

    ops_sflow_set_polling_interval(ofproto, sflow_options->polling_interval);

    /* Install KNET filters for source and destination sampling */
    bcmsdk_knet_sflow_filter_create(&knet_sflow_source_filter_id,
            opennslRxReasonSampleSource, "sFlow Source Sample");
    bcmsdk_knet_sflow_filter_create(&knet_sflow_dest_filter_id,
            opennslRxReasonSampleDest, "sFlow Dest Sample");

    VLOG_DBG("knet filter id --> source:%d, dest:%d", knet_sflow_source_filter_id, knet_sflow_dest_filter_id);
}

void
ops_sflow_agent_disable(struct bcmsdk_provider_node *ofproto)
{
    struct ofbundle *bundle;
    struct bcmsdk_provider_ofport_node *port = NULL, *next_port = NULL;

    if (!ofproto) {
        return;
    }

    /* clear the polling interval config from each port */
    HMAP_FOR_EACH(bundle, hmap_node, &ofproto->bundles) {
        LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {
            port->sflow_polling_interval = 0;
        }
    }

    if (ops_sflow_agent) {
        VLOG_DBG("KNET filter IDs: source %d, dest %d",
                knet_sflow_source_filter_id, knet_sflow_dest_filter_id);

        if (knet_sflow_source_filter_id || knet_sflow_dest_filter_id) {
            /* passing 0 ingress and egress rates will clear the sampling
             * rates on ASIC. */
            ops_sflow_set_sampling_rate(0, 0, 0, 0);
        }

        /* Remove KNET filters */
        if (knet_sflow_source_filter_id) {
            bcmsdk_knet_filter_delete("sflow source filter", 0, knet_sflow_source_filter_id);
            knet_sflow_source_filter_id = 0;
        }

        if (knet_sflow_dest_filter_id) {
            bcmsdk_knet_filter_delete("sflow dest filter", 0, knet_sflow_dest_filter_id);
            knet_sflow_dest_filter_id = 0;
        }

        /* Delete sFlow Agent */
        sfl_agent_release(ops_sflow_agent);
        ops_sflow_agent = NULL;
    }
}

static void
ops_sflow_agent_fn(struct unixctl_conn *conn, int argc, const char *argv[],
                void *aux OVS_UNUSED)
{
    if (strncmp(argv[1], "yes", 3) == 0) {
        ops_sflow_agent_enable(NULL, NULL);
    } else if (strncmp(argv[1], "no", 2) == 0) {
        ops_sflow_agent_disable(NULL);

    } else {
        /* Error condition */
    }

    unixctl_command_reply(conn, '\0');
}

void
ops_sflow_agent_ip(const char *ip)
{
    struct  in_addr addr;
    struct  in6_addr addr6;
    void    *ptr;
    int     af;

    SFLAddress  myIP;
    SFLReceiver *receiver;

    if (ops_sflow_agent == NULL) {
        VLOG_DBG("sFlow Agent is not running. Can't set Agent Address.");
        return;
    }

    memset(&myIP, 0, sizeof myIP);

    /* This is possible. User provided interface that doesn't have IP
     * configured. */
    if (ip == NULL) {
        myIP.type = SFLADDRESSTYPE_IP_V4;
        myIP.address.ip_v4.addr = 0;

        goto assign;
    }

    /* IP is non-NULL. */
    if (strchr(ip, ':')) {  /* v6 */
        af = AF_INET6;
        ptr = &addr6;
    } else {    /* v4 */
        af = AF_INET;
        ptr = &addr;
    }

    /* validate input IP addr. Will not happen. Placed for safety. */
    if (inet_pton(af, ip, ptr) <= 0) {
        VLOG_ERR("Invalid IP address(%s). Failed to assign IP.", ip);
        return;
    }

    if (af == AF_INET6) {
        myIP.type = SFLADDRESSTYPE_IP_V6;
        memcpy(myIP.address.ip_v6.addr, addr6.s6_addr, 16);
    } else {
        myIP.type = SFLADDRESSTYPE_IP_V4;
        myIP.address.ip_v4.addr = addr.s_addr;
    }

assign:
    sfl_agent_set_agentAddress(ops_sflow_agent, &myIP);

    receiver = sfl_agent_getReceiver(ops_sflow_agent, 1); /* 1 = receiver index */
    if (receiver == NULL) {
        VLOG_ERR("Got NULL Receiver from sflow agent. Something is "
                "incorrectly configured.");
        return;
    }

    sfl_receiver_replaceAgentAddress(receiver, &myIP);
}

/* Set an IP address on receiver/collector. */
void
ops_sflow_set_collector_ip(const char *ip, const char *port)
{
    SFLReceiver *receiver;
    SFLAddress  receiverIP;
    struct in_addr myIP;
    struct in6_addr myIP6;
    uint32_t    portN;

    if (ops_sflow_agent == NULL) {
        VLOG_ERR("sFlow Agent uninitialized.");
        return;
    }

    receiver = sfl_agent_getReceiver(ops_sflow_agent, 1); // Currently support one receiver.

    /* v6 address */
    if (strchr(ip, ':')) {
        memset(&myIP6, 0, sizeof myIP6);
        if (inet_pton(AF_INET6, ip, &myIP6) <= 0) {
            VLOG_ERR("Invalid collector IP:%s", ip);
            return;
        }
        receiverIP.type = SFLADDRESSTYPE_IP_V6;
        memcpy(receiverIP.address.ip_v6.addr, myIP6.s6_addr, 16);
    } else { /* v4 address */
        memset(&myIP, 0, sizeof myIP);
        if (inet_pton(AF_INET, ip, &myIP) <= 0) {
            VLOG_ERR("Invalid collector IP:%s", ip);
            return;
        }
        receiverIP.type = SFLADDRESSTYPE_IP_V4;
        receiverIP.address.ip_v4.addr = myIP.s_addr;
    }

    sfl_receiver_set_sFlowRcvrAddress(receiver, &receiverIP);

    if (port) {
        portN = atoi(port);
    } else {
        portN = atoi(SFLOW_COLLECTOR_DFLT_PORT);
    }

    sfl_receiver_set_sFlowRcvrPort(receiver, portN);

    VLOG_DBG("Set IP/port (%s/%d) on receiver", ip, portN);
}

/* Configure the collectors */
void
ops_sflow_set_collectors(struct sset *ops_targets)
{
    char *port, *vrf;
    struct sset targets;
    int target_count = 0;
    const char *collector_ip;
    char buf[IPV6_BUFFER_LEN + PORT_BUF_LEN + 5]; /* 5 for the separators */

    if (!ops_targets) {
        return;
    }

    sset_init(&targets);
    collectors_destroy(sflow_collectors);
    /* ops_targets is in the form <IP>/<port>.
     * need to convert it to <IP>:<port> as expected by collectors util.
     */
    /* Collector ip -- could be of form ip/port/vrf */
    SSET_FOR_EACH(collector_ip, ops_targets) {
        char *tmp_ip = xstrdup(collector_ip); /* so we don't modify ops_targets */
        /* retreive port info, if configured */
        if ((port = strchr(tmp_ip, '/')) != NULL) {
            *port = '\0';
            port++;
            /* save vrf name */
            if ((vrf = strchr(port, '/')) != NULL) {
                *vrf = '\0';
                vrf++;
            }
        } else {
            port = SFLOW_COLLECTOR_DFLT_PORT;
        }

        snprintf(buf, IPV6_BUFFER_LEN + PORT_BUF_LEN + 5 - 1,
                 "[%s]:[%s]", tmp_ip, port);
        sset_add(&targets, buf);
        free(tmp_ip);
        VLOG_DBG("sflow: adding collector [%d] : '%s'", target_count++, buf);
    }
    collectors_create(&targets, atoi(SFLOW_COLLECTOR_DFLT_PORT),
                      &sflow_collectors);
}

/* This function creates a receiver and sets an IP for it. */
static void
ops_sflow_collector(struct unixctl_conn *conn, int argc, const char *argv[],
                        void *aux OVS_UNUSED)
{
    char *ip, *port;

    ip  = (char *) argv[1];

    if (argc == 2) {
        port = (char *) argv[2];
    } else {
        port = SFLOW_COLLECTOR_DFLT_PORT;
    }

    ops_sflow_set_collector_ip(ip, port);

    unixctl_command_reply(conn, '\0');
}

/* Send a UDP pkt to collector ip (input) on a port (optional input, default
 * port is 6343). Test purposes only. */
    static void
ops_sflow_send_test_pkt(struct unixctl_conn *conn, int argc, const char *argv[],
        void *aux OVS_UNUSED)
{
    int sockfd;
    struct addrinfo params, *serv_list, *p;
    int rv;
    int numbytes;

    memset(&params, 0, sizeof params);
    params.ai_family = AF_UNSPEC; // Any protocol type works.
    params.ai_socktype = SOCK_DGRAM;

    if ((rv = getaddrinfo(argv[1], (argv[2]?argv[2]:SFLOW_COLLECTOR_DFLT_PORT),
                &params, &serv_list)) != 0) {
        VLOG_ERR("getaddrinfo: %s\n", gai_strerror(rv));
        goto done;
    }

    for(p = serv_list; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                        p->ai_protocol)) == -1) {
            VLOG_ERR("socket open failed: %s", strerror(errno));
            continue;
        }
        break;
    }

    if (p == NULL) {
        VLOG_ERR("bind socket has failed\n");
        goto done;
    }

    if ((numbytes = sendto(sockfd, "Hello", 5, 0, p->ai_addr,
                    p->ai_addrlen)) == -1) {
        VLOG_ERR("Failed to send data: %s", strerror(errno));
        goto cleanup;
    }

cleanup:
    freeaddrinfo(serv_list);
    VLOG_DBG("sent %d bytes to %s\n", numbytes, argv[1]);
    close(sockfd);

done:
    unixctl_command_reply(conn, '\0');
}

static void sflow_main()
{
    unixctl_command_register("sflow/set-rate", "[port-id | global] ingress-rate egress-rate", 2, 3, ops_sflow_set_rate, NULL);
    unixctl_command_register("sflow/show-rate", "[port-id]", 0 , 1, ops_sflow_show, NULL);

    unixctl_command_register("sflow/enable-agent", "[yes|no]", 1 , 1, ops_sflow_agent_fn, NULL);
    unixctl_command_register("sflow/set-collector-ip", "collector-ip [port]", 1 , 2, ops_sflow_collector, NULL);
    unixctl_command_register("sflow/send-test-pkt", "collector-ip [port]", 1 , 2, ops_sflow_send_test_pkt, NULL);
}

void
ops_sflow_run(struct bcmsdk_provider_node *ofproto)
{
    time_t now;
    SFLPoller *pl;
    SFLReceiver *rcv;
    SFL_COUNTERS_SAMPLE_TYPE cs;

    if (ops_sflow_agent) {
        now = time(NULL);
        pl = ops_sflow_agent->pollers;
        for(; pl != NULL; pl = pl->nxt) {
            if ((pl->countersCountdown == 0) ||
                (pl->sFlowCpReceiver == 0) ||
                (!pl->getCountersFn)) {
                continue;
            }
            if ((now - pl->lastPolled) >= pl->countersCountdown) {
                memset(&cs, 0, sizeof(cs));
                pl->getCountersFn(pl->magic, pl, &cs);
                pl->lastPolled = now;
                /* after the first random distribution, reset everyone to
                 * configured polling interval.
                 */
                if (pl->countersCountdown != pl->sFlowCpInterval) {
                    pl->countersCountdown = pl->sFlowCpInterval;
                }
            }
        }
        /* receivers use ticks to flush send data */
        rcv = ops_sflow_agent->receivers;
        for(; rcv != NULL; rcv = rcv->nxt) {
            sfl_receiver_tick(rcv, now);
        }
    }
}


///////////////////////////////// INIT /////////////////////////////////

int
ops_sflow_init (int unit OVS_UNUSED)
{
    /* TODO: Make this in to a thread so as to read messages from callback
     * function in Rx thread. */

    sflow_main();

    return 0;
}
