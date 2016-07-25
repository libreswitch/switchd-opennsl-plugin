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
#include <diag_dump.h>

#include "ofproto/collectors.h"
#include "ops-stats.h"
#include "ops-sflow.h"
#include "ops-routing.h"
#include "netdev-bcmsdk.h"
#include "eventlog.h"

VLOG_DEFINE_THIS_MODULE(ops_sflow);

#define DIAGNOSTIC_BUFFER_LEN   16000
#define VLAN_HEADER_SIZE        4

#define LAG_PORT_NAME_PREFIX            "lag"
#define LAG_PORT_NAME_PREFIX_LENGTH     3
#define LAG_AGGREGATE_ID_LENGTH         5

/* Refer to IANAifType-MIB for LAG interface */
#define LAG_INTERFACE_TYPE              161
#define LACP_CNTR_DEFAULT_VALUE         0

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
            (oso1->max_datagram == oso2->max_datagram) &&
            string_is_equal((char *)oso1->agent_ip, (char *)oso2->agent_ip) &&
            sset_equals(&oso1->ports, &oso2->ports));
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
void ops_sflow_write_sampled_pkt(int unit, opennsl_pkt_t *pkt)
{
    SFL_FLOW_SAMPLE_TYPE    fs;
    SFLFlow_sample_element  hdrElem;
    SFLSampled_header       *header;
    SFLSampler              *sampler;
    struct ops_sflow_port_stats stats;

    memset(&stats, 0, sizeof stats);

    if (pkt == NULL) {
        VLOG_ERR("NULL sFlow pkt received. Can't be buffered.");
        log_event("SFLOW_SAMPLED_PKT_FAILURE", NULL);
        return;
    }

    /* sFlow Agent is uninitialized. Error condition or it's not enabled
     * yet. */
    if (ops_sflow_agent == NULL) {
        VLOG_ERR("sFlow Agent uninitialized.");
        log_event("SFLOW_AGENT_FAILURE", NULL);
        return;
    }

    sampler = ops_sflow_agent->samplers;
    if (sampler == NULL) {
        VLOG_ERR("Sampler on sFlow Agent uninitialized.");
        log_event("SFLOW_SAMPLER_FAILURE", NULL);
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

    if (pkt->vlan && ops_routing_is_internal_vlan(pkt->vlan)) {
        VLOG_DBG("Internal VLAN from sampled packet (in hex): %02X%02X",
                 pkt->pkt_data[0].data[14],
                 pkt->pkt_data[0].data[15]);

        /* Strip internal VLAN ID from the packet and
         * right shift DMAC and SMAC by 4 bytes. */

        uint8 *new_data = pkt->pkt_data[0].data;
        pkt->pkt_data[0].data = pkt->pkt_data[0].data + VLAN_HEADER_SIZE;
        /* Copy SMAC and DMAC (12 bytes) */
        memmove(pkt->pkt_data[0].data, new_data, 2 * ETHER_ADDR_LEN);
        /* We stripped VLAN header so reduce frame_length by 4 */
        header->frame_length = header->frame_length - VLAN_HEADER_SIZE;
    }

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

    /* Calculate the sample pool data by gathering interface statistics
     * from ASIC and aggregating unicast, multicast and broadcast packets.
     * NOTE: Packet counters will wrap around (this is expected behavior). */
    if (OPENNSL_RX_REASON_GET(pkt->rx_reasons,
                              opennslRxReasonSampleSource)) {
       /* Packets were sampled at ingress so sample pool will include
        * all RX packets. */
       bcmsdk_get_sflow_port_stats(unit, pkt->src_port, &stats);
       fs.sample_pool = (uint32_t)(stats.in_ucastpkts +
                                   stats.in_multicastpkts +
                                   stats.in_broadcastpkts);
    }
    if (OPENNSL_RX_REASON_GET(pkt->rx_reasons,
                              opennslRxReasonSampleDest)) {
       /* Packets sampled at egress so sample pool will include
        * all TX packets. */
       bcmsdk_get_sflow_port_stats(unit, pkt->dest_port, &stats);
       fs.sample_pool = (uint32_t)(stats.out_ucastpkts +
                                   stats.out_multicastpkts +
                                   stats.out_broadcastpkts);
    }

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
        log_event("SFLOW_INVALID_PORT_FAILURE",
                  EV_KV("port", "%d", port));
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
            log_event("SFLOW_SAMPLER_MISSING_FAILURE",
                      EV_KV("port", "%d", port));
            return;
        }

        ingress_rate = egress_rate = sflow_options->sampling_rate;

        rc = opennsl_port_sample_rate_set(unit, port, ingress_rate, egress_rate);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set sampling rate on port: %d, (error-%s).",
                    port, opennsl_errmsg(rc));
            log_event("SFLOW_SET_SAMPLING_RATE_FAILURE",
                      EV_KV("port", "%d", port),
                      EV_KV("error", "%s", opennsl_errmsg(rc)));
            return;
        }
    } else {
        /* zero rate clears sampling on ASIC */
        rc = opennsl_port_sample_rate_set(unit, port, 0, 0);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set sampling rate on port: %d, (error-%s).",
                    port, opennsl_errmsg(rc));
            log_event("SFLOW_SET_SAMPLING_RATE_FAILURE",
                      EV_KV("port", "%d", port),
                      EV_KV("error", "%s", opennsl_errmsg(rc)));
            return;
        }
    }
}

/**
 * Function to extract the aggregate id from the
 * LAG name. (i.e.) lag_name="lag1000" -> aggregate_id=1000
 */
static uint32_t
ops_sflow_get_lag_aggregate_id(const char *lag_name)
{
    char aggr_key[LAG_AGGREGATE_ID_LENGTH];
    uint32_t aggregate_id = 0;

    snprintf(aggr_key, LAG_AGGREGATE_ID_LENGTH, "%s",
             lag_name + LAG_PORT_NAME_PREFIX_LENGTH);
    aggregate_id = (uint32_t)atoi(aggr_key);
    return aggregate_id;
}

/* callback function to get the per-port interface counters */
static void
ops_sflow_get_port_counters(void *arg, SFLPoller *poller,
                            SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    uint64_t speed;
    uint32_t hw_unit = 0, hw_port = 0;
    uint32_t index = 0, direction = 0, status = 0;
    struct ops_sflow_port_stats stats;
    SFLCounters_sample_element elem, lacp_elem;
    SFLIf_counters *counters;
    SFLLACP_counters *lacp_counters;
    char *bundle_name = NULL;
    uint32_t aggregate_id = 0;
    struct eth_addr mac_addr;

    if (arg != NULL) {
        bundle_name = (char *)arg;
    }

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

    /* Check if the interface is part of a bundle that is a LAG and
     * send the LACP counters.
     * TODO : LACP counters are not available in the DB so for now
     *        sending default values of 0 for all LACP counters.
     */
    if (bundle_name != NULL &&
        strncmp(bundle_name, LAG_PORT_NAME_PREFIX,
                LAG_PORT_NAME_PREFIX_LENGTH) == 0) {

        VLOG_DBG("Port %d is part of LAG %s", hw_port, bundle_name);

        memset(&mac_addr, 0, sizeof(struct eth_addr));
        aggregate_id = ops_sflow_get_lag_aggregate_id(bundle_name);

        lacp_elem.tag = SFLCOUNTERS_LACP;
        lacp_counters = &lacp_elem.counterBlock.lacp;
        lacp_counters->actorSystemID = mac_addr;
        lacp_counters->partnerSystemID = mac_addr;
        lacp_counters->attachedAggID = aggregate_id;
        lacp_counters->portState.v.actorAdmin = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->portState.v.actorOper = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->portState.v.partnerAdmin = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->portState.v.partnerOper = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->LACPDUsRx = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->markerPDUsRx = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->markerResponsePDUsRx = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->unknownRx = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->illegalRx = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->LACPDUsTx = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->markerPDUsTx = LACP_CNTR_DEFAULT_VALUE;
        lacp_counters->markerResponsePDUsTx = LACP_CNTR_DEFAULT_VALUE;
        SFLADD_ELEMENT(cs, &lacp_elem);
    }

    sfl_poller_writeCountersSample(poller, cs);

    ovs_mutex_unlock(&mutex);
}

/**
 * Callback function to get the LAG interface counters and
 * send to sFlow collector.
 */
static void
ops_sflow_get_lag_counters(void *arg, SFLPoller *poller,
                            SFL_COUNTERS_SAMPLE_TYPE *cs)
{
    uint64_t port_speed = 0, lag_speed = 0;
    int hw_unit = 0, hw_port = 0;
    uint32_t index = 0, direction = 0, status = 0;
    struct ops_sflow_port_stats port_stats, lag_stats;
    SFLCounters_sample_element elem;
    SFLIf_counters *counters;
    struct ofbundle *lag_bundle = NULL;
    struct bcmsdk_provider_ofport_node *port = NULL, *next_port = NULL;
    uint32_t aggregate_id = 0;

    ovs_mutex_lock(&mutex);
    lag_bundle = (struct ofbundle *)arg;
    memset(&lag_stats, 0, sizeof(struct ops_sflow_port_stats));

    aggregate_id = ops_sflow_get_lag_aggregate_id(lag_bundle->name);

    LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &lag_bundle->ports) {
        netdev_bcmsdk_get_hw_info(port->up.netdev, &hw_unit, &hw_port, NULL);
        VLOG_DBG("LAG %s member port : %d", lag_bundle->name, hw_port);
        netdev_bcmsdk_get_sflow_intf_info(hw_unit, hw_port,
                                          &index, &port_speed,
                                          &direction, &status);
        bcmsdk_get_sflow_port_stats(hw_unit, hw_port, &port_stats);
        lag_stats.in_octets += port_stats.in_octets;
        lag_stats.in_ucastpkts += port_stats.in_ucastpkts;
        lag_stats.in_multicastpkts += port_stats.in_multicastpkts;
        lag_stats.in_broadcastpkts += port_stats.in_broadcastpkts;
        lag_stats.in_discards += port_stats.in_discards;
        lag_stats.in_errors += port_stats.in_errors;
        lag_stats.in_unknownprotos += port_stats.in_unknownprotos;
        lag_stats.out_octets += port_stats.out_octets;
        lag_stats.out_ucastpkts += port_stats.out_ucastpkts;
        lag_stats.out_multicastpkts += port_stats.out_multicastpkts;
        lag_stats.out_broadcastpkts += port_stats.out_broadcastpkts;
        lag_stats.out_discards += port_stats.out_discards;
        lag_stats.out_errors += port_stats.out_errors;
        lag_speed += port_speed;
    }

    elem.tag = SFLCOUNTERS_GENERIC;
    counters = &elem.counterBlock.generic;
    counters->ifIndex = aggregate_id;
    counters->ifType = LAG_INTERFACE_TYPE;
    counters->ifSpeed = lag_speed;
    counters->ifDirection = direction;
    counters->ifStatus = status;
    counters->ifInOctets = lag_stats.in_octets;
    counters->ifInUcastPkts = lag_stats.in_ucastpkts;
    counters->ifInMulticastPkts = lag_stats.in_multicastpkts;
    counters->ifInBroadcastPkts = lag_stats.in_broadcastpkts;
    counters->ifInDiscards = lag_stats.in_discards;
    counters->ifInErrors = lag_stats.in_errors;
    counters->ifInUnknownProtos = lag_stats.in_unknownprotos;
    counters->ifOutOctets = lag_stats.out_octets;
    counters->ifOutUcastPkts = lag_stats.out_ucastpkts;
    counters->ifOutMulticastPkts = lag_stats.out_multicastpkts;
    counters->ifOutBroadcastPkts = lag_stats.out_broadcastpkts;
    counters->ifOutDiscards = lag_stats.out_discards;
    counters->ifOutErrors = lag_stats.out_errors;
    counters->ifPromiscuousMode = 0;

    VLOG_DBG("sFlow LAG stats %d [%d, %d, %d, %d/%d, %d, %d, %d/%d, %d, %d]\n",
             aggregate_id, (int)lag_speed, direction, status,
             lag_stats.in_ucastpkts, (int)lag_stats.in_octets,
             lag_stats.in_discards, lag_stats.in_errors,
             lag_stats.out_ucastpkts, (int)lag_stats.out_octets,
             lag_stats.out_discards, lag_stats.out_errors);

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

static void
ops_sflow_set_dsi_for_lag_interface(SFLDataSource_instance *dsi,
                                    int aggregate_id)
{
    uint32_t dsIndex;
    dsIndex = 1000 + sflow_options->sub_id + aggregate_id;
    SFL_DS_SET(*dsi, SFL_DSCLASS_LOGICAL_ENTITY, dsIndex, 0);
}

/* Configure polling per interface */
static void
ops_sflow_set_polling_per_interface(int hw_unit, int hw_port,
                                    char *bundle_name,
                                    int interval)
{
    SFLPoller *poller;
    uint32_t unit_port = 0;
    SFLDataSource_instance dsi;

    VLOG_DBG("Configure polling interval for hw_unit %d, hw_port %d, "
             "interval %d\n",hw_unit, hw_port, interval);

    if (!ops_sflow_agent || hw_port == -1) { /* -1 set for some virtual intf */
        return;
    }

    ops_sflow_set_dsi(&dsi, hw_unit, hw_port);
    poller = sfl_agent_addPoller(ops_sflow_agent, &dsi, bundle_name,
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

/**
 * Function to configure polling on LAG interface
 */
static void
ops_sflow_set_polling_interval_on_lag_interface(struct ofbundle *lag_bundle,
                                                int interval)
{
    SFLPoller *poller;
    SFLDataSource_instance dsi;
    uint32_t aggregate_id = 0;

    VLOG_DBG("Configure polling interval for LAG %s, interval %d\n",
              lag_bundle->name, interval);

    if (!ops_sflow_agent) {
        return;
    }

    ovs_mutex_lock(&mutex);
    aggregate_id = ops_sflow_get_lag_aggregate_id(lag_bundle->name);
    ovs_mutex_unlock(&mutex);
    ops_sflow_set_dsi_for_lag_interface(&dsi, aggregate_id);

    poller = sfl_agent_addPoller(ops_sflow_agent, &dsi, lag_bundle,
                                 ops_sflow_get_lag_counters);
    sfl_poller_set_sFlowCpInterval(poller, interval);
    sfl_poller_set_sFlowCpReceiver(poller, SFLOW_RECEIVER_INDEX);
    poller->lastPolled = time(NULL);
}

/**
 * Function to remove polling on a LAG interface
 */
void
ops_sflow_remove_polling_on_lag_interface(struct ofbundle *lag_bundle)
{
    SFLDataSource_instance dsi;
    uint32_t aggregate_id = 0;

    VLOG_DBG("Remove polling functionality for LAG %s",lag_bundle->name);

    if (!ops_sflow_agent) {
        return;
    }

    ovs_mutex_lock(&mutex);
    aggregate_id = ops_sflow_get_lag_aggregate_id(lag_bundle->name);
    ovs_mutex_unlock(&mutex);

    ops_sflow_set_dsi_for_lag_interface(&dsi, aggregate_id);

    sfl_agent_removePoller(ops_sflow_agent, &dsi);
}


void
ops_sflow_add_port(struct netdev *netdev)
{
    int hw_unit = 0, hw_port = 0;
    if (netdev && sflow_options) {
        netdev_bcmsdk_get_hw_info(netdev, &hw_unit, &hw_port, NULL);
        ops_sflow_set_polling_per_interface(hw_unit, hw_port, NULL,
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
            if (strncmp(bundle->name, LAG_PORT_NAME_PREFIX,
                        LAG_PORT_NAME_PREFIX_LENGTH) == 0) {
                if (bundle->lag_sflow_polling_interval != interval) {
                    ops_sflow_set_polling_interval_on_lag_interface(bundle,
                                                                    interval);
                    bundle->lag_sflow_polling_interval = interval;
                }
            }
            LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {
                if (port->sflow_polling_interval != interval) {
                    netdev_bcmsdk_get_hw_info(port->up.netdev, &hw_unit,
                                              &hw_port, NULL);
                    ops_sflow_set_polling_per_interface(hw_unit, hw_port,
                                                        port->bundle->name,
                                                        interval);
                    port->sflow_polling_interval = interval;
                }
            }
        }
    }
}

/**
 * Function updates 'ports' list within sflow_options.
 */
void
sflow_options_update_ports_list(const char *port_name, bool sflow_is_enabled)
{
    if (sflow_options == NULL) {
        VLOG_DBG("sflow_options is not initialized. Incorrect call.");
        return;
    }

    if (port_name == NULL) {
        VLOG_DBG("NULL port name is passed to function.");
        return;
    }

    if (sflow_is_enabled) {
        /* sflow is enabled on 'port_name'. Remove it from list in
         * sflow_options. */
        sset_find_and_delete(&sflow_options->ports, port_name);
    } else {
        /* sflow is disabled on 'port_name'. If not already present, add it to
         * ports list. */
        if (sset_contains(&sflow_options->ports, port_name) == false) {
            sset_add(&sflow_options->ports, port_name);
        }
    }
}

/**
 * Function to check if port is already in the list
 * of ports on which sflow has been disabled.
 */
static bool
ops_sflow_port_in_disabled_list(const char *port_name)
{
    if (sflow_options == NULL) {
        VLOG_DBG("sflow_options is not initialized. Incorrect call.");
        return false;
    }

    if (port_name == NULL) {
        VLOG_DBG("NULL port name is passed to function.");
        return false;
    }

    return sset_contains(&sflow_options->ports, port_name);
}

/**
 * Function to check if sFlow configuration has changed since the last time.
 * (i.e) sFlow was previously enabled and is now being disabled or vice-versa.
 */
bool
ops_sflow_port_config_changed(const char *port_name, bool sflow_enabled)
{
    if (port_name == NULL) {
        VLOG_DBG("NULL port name is passed to function.");
        return false;
    }
    return (!sflow_enabled &&
            !ops_sflow_port_in_disabled_list(port_name)) ||
           (sflow_enabled &&
            ops_sflow_port_in_disabled_list(port_name));
}

/* Given a front panel port number, verify if sFlow is disabled on that
 * port.
 *  true - sFlow is disabled on it
 *  false - sFlow is enabled on it
 */
static bool
sflow_is_disabled_on_port(opennsl_port_t fp_port)
{
    const char *port_name;
    int hw_unit, hw_port;

    if (sflow_options == NULL) {
        VLOG_ERR("sFlow options are NULL. Incorrect call to function: %s", __FUNCTION__);
        return false;
    }

    SSET_FOR_EACH(port_name, &sflow_options->ports) {
        hw_unit = hw_port = -1;
        netdev_bcmsdk_get_hw_info_from_name(port_name, &hw_unit, &hw_port);

        /* virtual interface, continue */
        if (hw_port == -1) {
            continue;
        }

        if (hw_port == fp_port) {
            VLOG_DBG("Found port:%d on which sFlow is disabled", hw_port);
            return true;
        }
    }

    return false;
}

/* Set sampling rate in sFlow Agent and also in ASIC. */
void
ops_sflow_set_sampling_rate(const int unit, const int port,
                            const int ingress_rate, const int egress_rate)
{
    int rc;
    opennsl_port_t fp_port = 0;
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
        log_event("SFLOW_FETCH_PORT_CONFIG_FAILURE",
                  EV_KV("error", "%s", opennsl_errmsg(rc)));
        return;
    }

    if (port) { /* set for specific port */
        rc = opennsl_port_sample_rate_set(unit, port, ingress_rate, egress_rate);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to set sampling rate on port: %d, (error-%s).",
                    port, opennsl_errmsg(rc));
            log_event("SFLOW_SET_SAMPLING_RATE_FAILURE",
                      EV_KV("port", "%d", port),
                      EV_KV("error", "%s", opennsl_errmsg(rc)));
            return;
        }
        /* sFlow needs the following explicit configuration on
           Tomahawk to sample ingress packets. This setting
           might not be supported on Trident2.
           So check for appropriate error message. */
        rc = opennsl_port_control_set(unit, port,
                                      opennslPortControlSampleIngressDest,
                                      OPENNSL_PORT_CONTROL_SAMPLE_DEST_CPU);
        if (OPENNSL_FAILURE(rc) && rc != OPENNSL_E_UNAVAIL) {
            VLOG_ERR("Failed to set ingress sampling on port: %d, (error-%s).",
                    port, opennsl_errmsg(rc));
            log_event("SFLOW_SET_SAMPLING_RATE_FAILURE",
                      EV_KV("port", "%d", port),
                      EV_KV("error", "%s", opennsl_errmsg(rc)));
            return;
        }

    } else { /* set globally, on all ports */
        /* Iterate over all front-panel (e - ethernet) ports */
        OPENNSL_PBMP_ITER (port_config.e, fp_port) {

            /* sFlow is disabled on this port. */
            if (sflow_is_disabled_on_port(fp_port)) {
                continue;
            }

            rc = opennsl_port_sample_rate_set(unit, fp_port, ingress_rate,
                                              egress_rate);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed to set sampling rate on port: %d, (error-%s)",
                         fp_port, opennsl_errmsg(rc));
                log_event("SFLOW_SET_SAMPLING_RATE_FAILURE",
                          EV_KV("port", "%d", fp_port),
                          EV_KV("error", "%s", opennsl_errmsg(rc)));
                return;
            }
            /* sFlow needs the following explicit configuration on
               Tomahawk to sample ingress packets. This setting
               might not be supported on Trident2.
               So check for appropriate error message. */
            rc = opennsl_port_control_set(unit, fp_port,
                                          opennslPortControlSampleIngressDest,
                                          OPENNSL_PORT_CONTROL_SAMPLE_DEST_CPU);
            if (OPENNSL_FAILURE(rc) && rc != OPENNSL_E_UNAVAIL) {
                VLOG_ERR("Failed to set ingress sampling on port: %d, (error-%s).",
                         fp_port, opennsl_errmsg(rc));
                log_event("SFLOW_SET_SAMPLING_RATE_FAILURE",
                          EV_KV("port", "%d", fp_port),
                          EV_KV("error", "%s", opennsl_errmsg(rc)));
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
            log_event("SFLOW_SAMPLER_MISSING_FAILURE",
                      EV_KV("port", "%d", port));
            return;
        }

        sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, ingress_rate);
    }
}

void
ops_sflow_set_max_datagram_size(const int size)
{
    SFLReceiver *receiver;

    /* set max datagram size on Receiver corresponding to 'port' */
    if (ops_sflow_agent) {
        receiver = sfl_agent_getReceiver(ops_sflow_agent, 1);
        if (receiver == NULL) {
             VLOG_ERR("Got NULL Receiver from sflow agent. Something is "
                      "incorrectly configured.");
             log_event("SFLOW_RECEIVER_MISSING_FAILURE", NULL);
             return;
        }
        sfl_receiver_set_sFlowRcvrMaximumDatagramSize(receiver, size);
    }
}

void
ops_sflow_set_header_size(const int size)
{
    SFLSampler  *sampler;
    uint32_t    dsIndex;
    SFLDataSource_instance  dsi;

    /* set header size on Sampler corresponding to 'port' */
    if (ops_sflow_agent) {
        dsIndex = 1000 + sflow_options->sub_id;
        SFL_DS_SET(dsi, SFL_DSCLASS_PHYSICAL_ENTITY, dsIndex, 0);
        sampler = sfl_agent_getSampler(ops_sflow_agent, &dsi);

        if (sampler == NULL) {
            VLOG_ERR("There is no Sampler for sFlow Agent.");
            log_event("SFLOW_SAMPLER_MISSING_FAILURE", NULL);
            return;
        }
        sfl_sampler_set_sFlowFsMaximumHeaderSize(sampler, size);
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

/**
 * @details
 * Dumps sflow rates for all ports or an individual specific port.
 */
void
ops_sflow_show_all(struct ds *ds, int argc, const char *argv[])
{
    opennsl_port_t tempPort = 0;
    opennsl_port_config_t port_config;
    int port=0;
    int ingress_rate, egress_rate;
    int rc;
    char out[32];

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    /* Retrieve the port configuration of the unit */
    rc = opennsl_port_config_get (0, &port_config);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("Failed to retrieve port config. Can't get sampling rate. "
                 "(rc=%s)", opennsl_errmsg(rc));
        log_event("SFLOW_FETCH_PORT_CONFIG_FAILURE",
                  EV_KV("error", "%s", opennsl_errmsg(rc)));
        return;
    }

    if (port) { /* sflow for specific port */
        rc = opennsl_port_sample_rate_get(0, port, &ingress_rate, &egress_rate);
        if (OPENNSL_FAILURE(rc)) {
            VLOG_ERR("Failed to get sample rate for port: %d (error-%s)",
                     port, opennsl_errmsg(rc));
            log_event("SFLOW_GET_SAMPLING_RATE_FAILURE",
                      EV_KV("port", "%d", port),
                      EV_KV("error", "%s", opennsl_errmsg(rc)));
            return;
        }
        ds_put_format(ds, "%-14s:%d\n", "Port", port);
        ds_put_format(ds, "%-14s:%d\n", "Ingress Rate", ingress_rate);
        ds_put_format(ds, "%-14s:%d\n", "Egress Rate", egress_rate);
    } else {
        ds_put_format(ds, "\t\t\tPort Number(Ingress Rate, Egress Rate)\n");
        ds_put_format(ds, "\t\t\t======================================\n");

        OPENNSL_PBMP_ITER (port_config.e, tempPort) {
            rc = opennsl_port_sample_rate_get(0, tempPort, &ingress_rate, &egress_rate);
            if (OPENNSL_FAILURE(rc)) {
                VLOG_ERR("Failed on port (%d) while getting global sample rate "
                         "(error-%s)", tempPort, opennsl_errmsg(rc));
                log_event("SFLOW_GET_SAMPLING_RATE_FAILURE",
                          EV_KV("port", "%d", tempPort),
                          EV_KV("error", "%s", opennsl_errmsg(rc)));
                return;
            }
            snprintf(out, 31, "%d(%d,%d)", tempPort, ingress_rate, egress_rate);
            ds_put_format(ds, "%15s  ", out);

            if (tempPort%5 == 0) {
                ds_put_format(ds, "\n");
            }
        }
    }
    return;
}

/**
 * callback handler function for diagnostic dump basic
 * it allocates memory as per requirement and populates data.
 * INIT_DIAG_DUMP_BASIC will free allocated memory.
 *
 * @param feature name of the feature.
 * @param buf pointer to the buffer.
 */
void
sflow_diag_dump_basic_cb(struct ds *ds)
{
    /* populate basic diagnostic data to buffer */
    /* sflow on all ports of switch */
    ds_put_format(ds, "Output for SFLOW information:\n");
    ops_sflow_show_all(ds, 0, NULL);
    ds_put_format(ds, "\n\n");
    return;
}

static void
ops_sflow_show (struct unixctl_conn *conn, int argc, const char *argv[],
                void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    int port=0;

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    if(!port) { /* sflow on all ports of switch */
        ops_sflow_show_all(&ds, 0, NULL);
    }
    else { /* sflow for specific port */
        ops_sflow_show_all(&ds, argc, argv);
    }
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
    oso->max_datagram = SFL_DEFAULT_DATAGRAM_SIZE;
    oso->control_ip = NULL;
}

/* Initial creation of sFlow Agent. Creates an Agent only once. */
static SFLAgent *
ops_sflow_alloc(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    SFLAgent *sfl_agent;

    if (ovsthread_once_start(&once)) {
        ovs_mutex_init(&mutex);
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
    uint32_t    header;
    uint32_t    datagram;
    int         ret;

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

            sset_init(&sflow_options->ports);
            sset_clone(&sflow_options->ports, &oso->ports);
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
            log_event("SFLOW_AGENT_IP_CONFIG_FAILURE",
                      EV_KV("ip_address", "%s", oso->agent_ip));
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

    if (sflow_options->max_datagram) {
        datagram = sflow_options->max_datagram;
    } else {
        datagram = SFL_DEFAULT_DATAGRAM_SIZE;
    }

    /* RECEIVER: aka Collector */
    receiver = sfl_agent_addReceiver(ops_sflow_agent);
    sfl_receiver_set_sFlowRcvrOwner(receiver, "Openswitch sFlow Receiver");
    sfl_receiver_set_sFlowRcvrTimeout(receiver, 0xffffffff);
    sfl_receiver_set_sFlowRcvrMaximumDatagramSize(receiver, datagram);
    if ((ret = ops_sflow_set_collectors(&sflow_options->targets)) != 0) {
        /* we will try to configure collectors again at next set_sflow() */
        VLOG_DBG("sFlow: couldn't configure collectors. ret %d", ret);
        sset_clear(&sflow_options->targets);
    }

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

    if (sflow_options->header_len) {
        header = sflow_options->header_len;
    } else {
        header = SFL_DEFAULT_HEADER_SIZE;
    }

    sfl_sampler_set_sFlowFsPacketSamplingRate(sampler, rate);

    /* Enable sampling globally */
    ops_sflow_set_sampling_rate(0, 0, rate, rate);

    sfl_sampler_set_sFlowFsMaximumHeaderSize(sampler, header);
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
        /* Clear the polling interval if bundle is a LAG */
        if (strncmp(bundle->name, LAG_PORT_NAME_PREFIX,
                    LAG_PORT_NAME_PREFIX_LENGTH) == 0) {
            bundle->lag_sflow_polling_interval = 0;
        }
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
        log_event("SFLOW_AGENT_IP_CONFIG_FAILURE",
                  EV_KV("ip_address", "%s", ip));
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
        log_event("SFLOW_RECEIVER_MISSING_FAILURE", NULL);
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
        log_event("SFLOW_AGENT_FAILURE", NULL);
        return;
    }
    receiver = sfl_agent_getReceiver(ops_sflow_agent, 1); // Currently support one receiver.

    /* v6 address */
    if (strchr(ip, ':')) {
        memset(&myIP6, 0, sizeof myIP6);
        if (inet_pton(AF_INET6, ip, &myIP6) <= 0) {
            VLOG_ERR("Invalid collector IP:%s", ip);
            log_event("SFLOW_COLLECTOR_IP_CONFIG_FAILURE",
                      EV_KV("ip_address", "%s", ip));
            return;
        }
        receiverIP.type = SFLADDRESSTYPE_IP_V6;
        memcpy(receiverIP.address.ip_v6.addr, myIP6.s6_addr, 16);
    } else { /* v4 address */
        memset(&myIP, 0, sizeof myIP);
        if (inet_pton(AF_INET, ip, &myIP) <= 0) {
            VLOG_ERR("Invalid collector IP:%s", ip);
            log_event("SFLOW_COLLECTOR_IP_CONFIG_FAILURE",
                      EV_KV("ip_address", "%s", ip));
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
int
ops_sflow_set_collectors(struct sset *ops_targets)
{
    int ret;
    char *port, *vrf;
    struct sset targets;
    int target_count = 0;
    const char *collector_ip;
    char buf[IPV6_BUFFER_LEN + PORT_BUF_LEN + 5]; /* 5 for the separators */

    if (!ops_targets) {
        return -1;
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
    ret = collectors_create(&targets, atoi(SFLOW_COLLECTOR_DFLT_PORT),
                            &sflow_collectors);
    return ret;
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
        /* Set the current time in the sFlow agent to calculate and set
         * 'sysUpTime' field in the sFlow datagram. */
        ops_sflow_agent->now = now;
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
        /*
         * A mutex lock/unlock is needed before calling the sflow_receiver_tick
         * which flushes the receiver and sends the packets to the sFlow
         * collectors. This was needed to avoid race conditions when
         * FLOW/CNTR packets are being populated into the receiver's buffer
         * and the data gets unexpectedly flushed out causing datagram to be
         * malformed.
         */
        ovs_mutex_lock(&mutex);
        /* receivers use ticks to flush send data */
        rcv = ops_sflow_agent->receivers;
        for(; rcv != NULL; rcv = rcv->nxt) {
            sfl_receiver_tick(rcv, now);
        }
        ovs_mutex_unlock(&mutex);
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
