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
 * File: ofproto-bcm-provider.h
 */

#ifndef OFPROTO_BCM_PROVIDER_H
#define OFPROTO_BCM_PROVIDER_H 1

#include <ofproto/ofproto-provider.h>
#include <opennsl/types.h>
#include <opennsl/l3.h>

/* No bfd/cfm status change. */
#define NO_STATUS_CHANGE -1

/* vrf */
#define BCM_MAX_VRFS 1024

struct bcmsdk_provider_rule {
    struct rule up;
    struct ovs_mutex stats_mutex;
    uint32_t recirc_id;
};

struct bcmsdk_provider_group {
    struct ofgroup up;
    struct ovs_mutex stats_mutex;
    uint64_t packet_count OVS_GUARDED;  /* Number of packets received. */
    uint64_t byte_count OVS_GUARDED;    /* Number of bytes received. */
};

struct ofbundle {
    struct hmap_node hmap_node; /* In struct ofproto's "bundles" hmap. */
    struct bcmsdk_provider_node *ofproto; /* Owning ofproto. */
    void *aux;                  /* Key supplied by ofproto's client. */
    char *name;                 /* Identifier for log messages. */

    /* Configuration. */
    struct ovs_list ports;      /* Contains "struct ofport"s. */
    enum port_vlan_mode vlan_mode; /* VLAN mode */
    int vlan;                   /* -1=trunk port, else a 12-bit VLAN ID. */
    unsigned long *trunks;      /* Bitmap of trunked VLANs, if 'vlan' == -1.
                                 * NULL if all VLANs are trunked. */
    bool trunk_all_vlans;       /* Indicates whether this port is implicitly
                                   trunking all VLANs defined in VLAN table. */
    opennsl_pbmp_t *pbm;        /* Bitmap of ports in this bundle that have
                                   VLANs configured. */
    struct lacp *lacp;          /* LACP if LACP is enabled, otherwise NULL. */
    struct bond *bond;          /* Nonnull iff more than one port. */
    bool use_priority_tags;     /* Use 802.1p tag for frames in VLAN 0? */

    /* Status. */
    bool floodable;             /* True if no port has OFPUTIL_PC_NO_FLOOD set. */

    int bond_hw_handle;         /* Allocated bond id in hardware. */
    int hw_unit, hw_port;       /* HW identification of L3 interfaces, might change
                                 * when L3 on top of LAGs would be introduced */

    /* L3 Routing */
    opennsl_l3_intf_t *l3_intf;  /* L3 interface pointer. NULL if not L3 */

    /* L3 port ip's */
    char *ip4_address;
    char *ip6_address;
    struct hmap secondary_ip4addr; /* List of secondary IP address */
    struct hmap secondary_ip6addr; /* List of secondary IPv6 address */

    int vlan_knet_filter_ids[3]; /* Filter ID for vlan interface */
};

struct bcmsdk_provider_ofport_node {
    struct hmap_node odp_port_node;
    struct ofport up;

    odp_port_t odp_port;
    struct ofbundle *bundle;    /* Bundle that contains this port, if any. */
    struct ovs_list bundle_node;/* In struct ofbundle's "ports" list. */
    struct cfm *cfm;            /* Connectivity Fault Management, if any. */
    struct bfd *bfd;            /* BFD, if any. */
    bool may_enable;            /* May be enabled in bonds. */
    bool is_tunnel;             /* This port is a tunnel. */
    bool is_layer3;             /* This is a layer 3 port. */
    long long int carrier_seq;  /* Carrier status changes. */
    struct bcmsdk_provider_ofport_node *peer;   /* Peer if patch port. */

   /* Spanning tree. */
    struct stp_port *stp_port;  /* Spanning Tree Protocol, if any. */
    enum stp_state stp_state;   /* Always STP_DISABLED if STP not in use. */
    long long int stp_state_entered;

    /* Rapid Spanning Tree. */
    struct rstp_port *rstp_port; /* Rapid Spanning Tree Protocol, if any. */
    enum rstp_state rstp_state; /* Always RSTP_DISABLED if RSTP not in use. */

    /* Queue to DSCP mapping. */
    struct ofproto_port_queue *qdscp;
    size_t n_qdscp;

    /* Linux VLAN device support (e.g. "eth0.10" for VLAN 10.)
     *
     * This is deprecated.  It is only for compatibility with broken device */
    ofp_port_t realdev_ofp_port;
    int vlandev_vid;
};

struct bcmsdk_provider_node {
    struct hmap_node all_bcmsdk_provider_node; /* In 'all_ofproto_provider'. */
    struct ofproto up;

    uint64_t dump_seq; /* Last read of dump_seq(). */

    /* Special OpenFlow rules. */
    struct bcmsdk_provider_rule *miss_rule;         /* Sends flow table misses
                                                       to controller. */
    struct bcmsdk_provider_rule *no_packet_in_rule; /* Drops flow table
                                                       misses. */
    struct bcmsdk_provider_rule *drop_frags_rule;   /* Used in OFPC_FRAG_DROP
                                                       mode. */

    /* Bridging. */
    struct netflow *netflow;
    struct hmap bundles;        /* Contains "struct ofbundle"s. */
    struct mac_learning *ml;
    struct mcast_snooping *ms;
    bool has_bonded_bundles;
    bool lacp_enabled;
    struct mbridge *mbridge;

    struct ovs_mutex stats_mutex;
    struct netdev_stats stats OVS_GUARDED; /* To account packets generated and
                                            * consumed in userspace. */
    /* VRF */
    bool vrf;                   /* Specifies whether specific ofproto instance
                                 * is backing up VRF and not bridge */
    size_t vrf_id;              /* If vrf is true, then specifies hw vrf_id
                                 * for the specific ofproto instance */


    /* Spanning tree. */
    struct stp *stp;
    long long int stp_last_tick;

    /* Rapid Spanning Tree. */
    struct rstp *rstp;
    long long int rstp_last_tick;

    /* VLAN splinters. */
    struct ovs_mutex vsp_mutex;
    struct hmap realdev_vid_map OVS_GUARDED; /* (realdev,vid) -> vlandev. */
    struct hmap vlandev_map OVS_GUARDED;     /* vlandev -> (realdev,vid). */

    /* Ports. */
    struct sset ports;             /* Set of standard port names. */
    struct sset ghost_ports;       /* Ports with no datapath port. */
    struct sset port_poll_set;     /* Queued names for port_poll() reply. */
    int port_poll_errno;           /* Last errno for port_poll() reply. */
    uint64_t change_seq;           /* Connectivity status changes. */

    /* Work queues. */
    struct guarded_list pins;      /* Contains "struct ofputil_packet_in"s. */
    struct seq *pins_seq;          /* For notifying 'pins' reception. */
    uint64_t pins_seqno;
};

struct bcmsdk_provider_port_dump_state {
    uint32_t bucket;
    uint32_t offset;
    bool ghost;

    struct ofproto_port port;
    bool has_port;
};

enum { N_TABLES = 255 };
enum { TBL_INTERNAL = N_TABLES - 1 };    /* Used for internal hidden rules. */

extern const struct ofproto_class ofproto_bcm_provider_class;

#endif  /* ofproto-bcm-provider.h */
