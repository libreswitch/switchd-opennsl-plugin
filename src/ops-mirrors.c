
/*
 * Copyright (C) 2016 Hewlett-Packard Enterprise Company, L.P.
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
 * File: ops-mirrors.c
 *
 * Purpose: This file has code to manage mirrors/span sessions for
 *          BCM hardware.  It uses the opennsl interface for all
 *          hw related operations.
 */

#include <stdio.h>
#include <openvswitch/vlog.h>
#include "ops-mirrors.h"

VLOG_DEFINE_THIS_MODULE(ops_mirrors);

/*
 * Always call this to initialize the mirroring subsystem
 */
int
bcmsdk_mirrors_init (int unit)
{
    opennsl_error_t rc;

    VLOG_DBG("initializing mirroring/span subsystem");

    rc = opennsl_switch_control_set(unit, opennslSwitchDirectedMirroring, TRUE);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("opennsl_switch_control_set FAILED: unit %d: %s (%d)",
                unit, opennsl_errmsg(rc), rc);
        return 1;
    }

    rc = opennsl_mirror_init(unit);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("opennsl_mirror_init FAILED: unit %d: %s (%d)",
                unit, opennsl_errmsg(rc), rc);
        return 1;
    }

    VLOG_DBG("mirroring subsystem succesfully initialized");
    return 0;
}

/*
 * Creates a mirror end point where the 'mirror to port' is a simple interface.
 */
static int
bcmsdk_simple_port_mirror_endpoint_create (
        int unit,                               /* which chip the endpoint is at */
        opennsl_port_t port,                    /* port id */
        opennsl_mirror_destination_t *mdestp)   /* supplied by/returned to caller */
{
    opennsl_error_t rc;

    VLOG_DBG("creating a simple port mirror endpoint; unit %d port %d",
            unit, port);

    /* apparently this never fails */
    opennsl_mirror_destination_t_init(mdestp);

    rc = opennsl_port_gport_get(unit, port, &mdestp->gport);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("opennsl_port_gport_get FAILED: "
                 "unit %d port %d: %s (%d)",
                     unit, port, opennsl_errmsg(rc), rc);
        return 1;
    }

    rc = opennsl_mirror_destination_create(unit, mdestp);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("opennsl_mirror_destination_create FAILED: "
                 "unit %d port %d: %s (%d)",
                    unit, port, opennsl_errmsg(rc), rc);
        return 1;
    }

    return 0;
}

/*
 * Creates a mirror end point where the mirror to port is a lag.
 * Note that since a lag can stretch over multiple chips, there
 * is no 'unit' parameter in this case.
 */
static int
bcmsdk_lag_mirror_endpoint_create (
        opennsl_port_t lag_id,                  /* port id */
        opennsl_mirror_destination_t *mdestp)   /* returned to caller */
{
    int rc;
    opennsl_gport_t gport = 0;

    VLOG_DBG("creating a lag mirror endpoint; lag id %d", lag_id);

    /* apparently this never fails */
    opennsl_mirror_destination_t_init(mdestp);

    OPENNSL_GPORT_TRUNK_SET(gport, lag_id);

    mdestp->gport = gport;
    rc = opennsl_mirror_destination_create(0, mdestp);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("bcmsdk_lag_mirror_endpoint_create FAILED: lag id %d: %s (%d)",
                    lag_id, opennsl_errmsg(rc), rc);
        return 1;
    }

    return 0;
}

static int
bcmsdk_mirror_add_source_port (
        int unit,                   /* chip number of the port to be added */
        opennsl_port_t port,        /* port number */
        uint32 flags,               /* ingress, egress or both */
        opennsl_gport_t mdest_id)   /* mirror destination to add to */
{
    opennsl_error_t rc;

    rc = opennsl_mirror_port_dest_add(unit, port, flags, mdest_id);
    if (OPENNSL_SUCCESS(rc)) {
        VLOG_DBG("SUCCESS: added source hw unit %d hw port %d "
                "flags 0x%x to bcm mdestid %d",
                unit, port, flags, mdest_id);
        return 0;
    }

    VLOG_ERR("opennsl_mirror_port_dest_add FAILED: "
             "unit %d port %d flags 0x%x mdest_id %d: %s (%d)",
                unit, port, flags, mdest_id,
                opennsl_errmsg(rc), rc);

    return 1;
}

static int
bcmsdk_mirror_delete_source_port (
        int unit,                       /* which unit the port is on */
        opennsl_port_t port,            /* port to be deleted */
        uint32 flags,                   /* which flags to be deleted with */
        opennsl_gport_t mdest_id)       /* which MTP to be deleted from */
{
    opennsl_error_t rc;

    rc = opennsl_mirror_port_dest_delete(unit, port, flags, mdest_id);
    if (OPENNSL_SUCCESS(rc)) {
        VLOG_DBG("SUCCESS: deleted source hw unit %d hw port %d "
                "flags 0x%x from bcm mdestid %d",
                unit, port, flags, mdest_id);
        return 0;
    }

    VLOG_ERR("opennsl_mirror_port_dest_delete FAILED: "
             "unit %d port %d mdest_id %d: %s (%d) flags 0x%x",
                unit, port, mdest_id,
                opennsl_errmsg(rc), rc, flags);

    return 1;
}

/*
 * Destroy a specified mirror endpoint.
 */
static int
bcmsdk_mirror_endpoint_destroy (
        int unit,                           /* which chip the endpoint is */
        opennsl_gport_t mirror_endpoint_id) /* actual endpoint to be destroyed */
{
    opennsl_error_t rc;

    rc = opennsl_mirror_destination_destroy(unit, mirror_endpoint_id);
    if (OPENNSL_FAILURE(rc)) {
        VLOG_ERR("opennsl_mirror_destination_destroy FAILED: "
                 "unit %d mirror_endpoint_id %d: %s (%d)",
                    unit, mirror_endpoint_id, opennsl_errmsg(rc), rc);
        return 1;
    }

    return 0;
}

#define INTERNAL_ERROR          EFAULT      /* an internal inconsistency */
#define EXTERNAL_ERROR          ENXIO       /* wrong parameters passed in */
#define RESOURCE_ERROR          ENOMEM      /* out of required resources */

/* how many max mirrored ports in one mirror */
#define MAX_MIRROR_SOURCES      128

/* max no of 'mirror to' ports for BCM */
#define MAX_MIRRORS             4

/* every unique mirror has a name; its size in chars */
#define MIRROR_NAME_SIZE        66

/*
 * BCM supports mirroring only on the first 8 ports of a lag
 */
#define LAG_PORT_LIMIT   8

/* OPS_TODO:
 * There is an exact replica of this structure defined in bridge.c, so
 * make sure when one gets changed, the other one is in sync with it.
 * Eventually, this structure definition should be moved to ofproto.h and
 * deleted from here and bridge.c files since it is common to both.
 */
struct ofproto_mirror_bundle {
    struct ofproto *ofproto;
    void *aux;
};

/*
 * This structure represents a 'compacted' form of a mirrored port.
 * The 'flags' is constructed from a combination of whether the
 * port is included in the 'srcs' (ingress) and/or 'dsts' (egress)
 * lists.  We need the flags since we use them when we disassociate
 * a port from the MTP.  Unless the EXACT same flags used in the
 * association phase are not specied during disassociation, BCM
 * rejects the call.
 */
typedef struct mirrored_port_s {

    struct bcmsdk_provider_ofport_node *ofport;
    int bcm_unit, bcm_port;
    uint32 flags;

} mirrored_port_t;

/*
 * This structure is used as a lookup between aux <--> endpoint bundle
 * which define the mirror.  Requests from higher layers usually have
 * the opaque 'aux' pointer (key).  So we store this in a lookup table
 * to obtain the the rest of the mirroring information when needed.
 *
 * Since BCM mtp deletion first requires all source ports to be deleted
 * from the mtp, we also unfortunately MUST keep the list of ingress
 * and egress source ports so we can refer to them during mtp deletion.
 */
typedef struct mirror_object_s {

    /* name of the mirror object, used for debugging */
    char name [MIRROR_NAME_SIZE];

    /* 'higher' level mirror object.  Treat it as a 'unique key' */
    void *aux;

    /* The endpoint bundle of this mirror object */
    struct ofproto_mirror_bundle *mout;
    struct ofbundle *mtp;

    /* set of ingress/egress ports to be mirrored */
    int n_mirrored;
    mirrored_port_t mirrored_ports [MAX_MIRROR_SOURCES];

    /* base numbers when stats begin */
    uint64_t tx_base_packets, tx_base_bytes;

} mirror_object_t;

/*
 * all the mirrors in the system
 */
static mirror_object_t all_mirrors [MAX_MIRRORS] = {{{ 0 }}};

/*
 * find the mirror object, given its name
 */
static mirror_object_t *
find_mirror_with_name (const char *name)
{
    int i;
    mirror_object_t *m;

    VLOG_DBG("searching mirror object with name %s", name);
    for (i = 0; i < MAX_MIRRORS; i++) {
        m = &all_mirrors[i];
        if (m->aux && m->mtp) {
            if (0 == strncmp(name, m->name, MIRROR_NAME_SIZE)) {
                VLOG_DBG("found mirror with name %s at index %d",
                        name, i);
                return m;
            }
        }
    }
    VLOG_DBG("could NOT find mirror object with name %s", name);
    return NULL;
}

/*
 * given the 'aux' user opaque pointer (key), finds the
 * corresponding mirror object
 */
static mirror_object_t *
find_mirror_with_aux (void *aux)
{
    int i;

    VLOG_DBG("searching mirror object with aux 0x%p", aux);
    for (i = 0; i < MAX_MIRRORS; i++) {
        if (aux == all_mirrors[i].aux) {
            VLOG_DBG("found mirror with aux 0x%p at index %d", aux, i);
            return &all_mirrors[i];
        }
    }
    VLOG_DBG("could NOT find mirror object with aux 0x%p", aux);
    return NULL;
}

/*
 * similar to above but finds the mirror based on its mtp bundle
 */
static mirror_object_t *
find_mirror_with_mtp (struct ofbundle *mtp)
{
    int i;

    VLOG_DBG("searching mirror with mtp %s", mtp->name);
    for (i = 0; i < MAX_MIRRORS; i++) {
        if (mtp == all_mirrors[i].mtp) {
            VLOG_DBG("found mirror with mtp %s at index %d", mtp->name, i);
            return &all_mirrors[i];
        }
    }
    VLOG_DBG("could NOT find mirror with mtp %s", mtp->name);
    return NULL;
}

/*
 * is the array entry considered empty ? a new slot
 */
static bool
mirror_slot_is_free (mirror_object_t *m)
{
    return
        (NULL == m->aux) && (NULL == m->mtp);
}

/*
 * Returns the first un-used slot in the array.
 * This is called in preparation to add a new
 * entry to the array.
 */
static mirror_object_t *
mirror_object_allocate (void)
{
    int i;
    mirror_object_t *m;

    for (i = 0; i < MAX_MIRRORS; i++) {
        m = &all_mirrors[i];
        if (mirror_slot_is_free(m)) {
            VLOG_DBG("created a new empty mirror object at index %d", i);
            m->n_mirrored = 0;
            m->tx_base_packets = 0;
            m->tx_base_bytes = 0;
            return m;
        }
    }
    VLOG_ERR("could NOT create a new mirror object, out of memory");
    return NULL;
}

static void
mirror_object_free (mirror_object_t *m)
{
    m->aux = NULL;
    if (m->mtp) {
        if (m->mtp->mirror_data) {
            free(m->mtp->mirror_data);
            m->mtp->mirror_data = NULL;
        }
        m->mtp = NULL;
    }
    m->n_mirrored = 0;
}

/*
 * find if the specified bundle pointer exists in
 * an arbitrary array of bundle pointers
 */
static bool
bundle_present (struct ofbundle *searched_bundle,
        struct ofbundle **bundle_list, int count)
{
    int i;

    for (i = 0; i < count; i++) {
        if (searched_bundle == bundle_list[i]) {
            return true;
        }
    }
    return false;
}

/*
 * returns true if the specified bundle is a lag/bond/trunk/ether channel
 */
static bool
bundle_is_a_lag (struct ofbundle *bundle)
{
    return
        bundle->bond_hw_handle >= 0;
}

/*
 * expand the bundle to its individual ports and obtain
 * the corresponding bcmsdk_provider_ofport_nodes, unit numbers
 * and port numbers along the way.  The function returns how
 * many total ports are in the bundle but will only fill up
 * to limit entries.
 */
static int
bundle_expand (struct ofbundle *bundle, int limit,
        /* params below here are returned to caller */
        struct bcmsdk_provider_ofport_node **ports,
        int *bcm_units,
        int *bcm_ports)
{
    struct bcmsdk_provider_ofport_node *port, *next_port;
    int hw_unit, hw_port;
    int count = 0;

    LIST_FOR_EACH_SAFE(port, next_port, bundle_node, &bundle->ports) {
        if (count < limit) {
            netdev_bcmsdk_get_hw_info(port->up.netdev, &hw_unit, &hw_port, NULL);
            if (ports) ports[count] = port;
            bcm_units[count] = hw_unit;
            bcm_ports[count] = hw_port;
            VLOG_DBG("bundle %s port expanded %d: hw unit %d hw port %d",
                    bundle->name, count, hw_unit, hw_port);
        }
        count++;
    }
    return count;
}

/*
 * for an MTP, lag id is returned if the bundle is a lag and
 * the 'normal' port unit & number is returned otherwise.
 * Since lag id is returned if it is a lag, it is an error
 * if this expands to more than one port.
 */
static void
mtp_get_hw_info (struct ofbundle *bundle,
        int *hw_unit, int *hw_port)
{
    int n;

    VLOG_DBG("mtp_get_hw_info called for bundle %s (0x%p)",
            bundle->name, bundle);

    /* for lags, use the lag id */
    if (bundle_is_a_lag(bundle)) {
        *hw_unit = 0;
        *hw_port = bundle->bond_hw_handle;
        VLOG_DBG("mtp bundle %s (0x%p) *IS* a lag (lagid %d)",
                bundle->name, bundle, bundle->bond_hw_handle);
        return;
    }

    /* if they are already cached, use those values */
    if ((bundle->hw_unit != -1) && (bundle->hw_port != -1)) {
        VLOG_DBG("using cached values hw_unit %d hw_port %d for mtp port %s",
            bundle->hw_unit, bundle->hw_port, bundle->name);
        *hw_unit = bundle->hw_unit;
        *hw_port = bundle->hw_port;
        return;
    }

    /* ok normal port whose bcm hw values are not cached */
    n = bundle_expand(bundle, 1, NULL, hw_unit, hw_port);
    if (n != 1) {
        VLOG_ERR("ERROR: port list size is %d for NON LAG bundle %s",
                n, bundle->name);
        return;
    }

    VLOG_DBG("bundle %s (0x%p): obtained hw_unit %d hw_port %d",
            bundle->name, bundle, *hw_unit, *hw_port);
    return;
}

/*
 * return the bcm hw particulars for a source port.  If source is
 * a lag port, it gets expanded out to each individual port and
 * the expanded values are placed into 'ofports', 'bcm_units' and
 * 'bcm_ports' respectively.
 */
static int
source_bundle_get_hw_info (struct ofbundle *bundle,
        int limit,
        struct bcmsdk_provider_ofport_node **ofports,
        int *bcm_units,
        int *bcm_ports)
{
    int count;

    VLOG_DBG("source_bundle_get_hw_info called for bundle %s (0x%p)",
            bundle->name, bundle);
    count = bundle_expand(bundle, limit, ofports, bcm_units, bcm_ports);
    VLOG_DBG("bundle %s (0x%p): expanded to %d individual ports",
            bundle->name, bundle, count);
    return count;
}

/*
 * Disassociate a mirrored port from the mirror (hence the mtp).
 * We dont care if this fails, since it may be called repeatedly
 * on the same port.  Hence we dont return an error code.
 */
static void
mirror_delete_source_port (mirror_object_t *mirror, mirrored_port_t *mport)
{
    int rc;
    struct ofbundle *mtp = mirror->mtp;

    /* is the specified port actually an MTP */
    if (NULL == mtp->mirror_data) {
        VLOG_DBG("mirror %s did NOT have a valid mirror endpoint",
                mirror->name);
        return;
    }

    VLOG_DBG("deleting source unit %d port %d from mirror (%s mtp %s mdestid %d)",
            mport->bcm_unit, mport->bcm_port,
            mirror->name, mtp->name,
            mtp->mirror_data->mirror_dest_id);

    rc = bcmsdk_mirror_delete_source_port(mport->bcm_unit, mport->bcm_port,
            mport->flags, mtp->mirror_data->mirror_dest_id);
    if (OPENNSL_SUCCESS(rc)) {
        VLOG_DBG("deleting unit %d port %d from mirror "
                "(%s mtp %s mdestid %d) SUCCEEDED",
                mport->bcm_unit, mport->bcm_port,
                mirror->name, mtp->name, mtp->mirror_data->mirror_dest_id);
        mirror->n_mirrored--;
    } else {
        VLOG_DBG("deleting unit %d port %d from mirror (%s mtp %s mdestid %d) "
                "FAILED: rc %d rc %s",
                mport->bcm_unit, mport->bcm_port,
                mirror->name, mtp->name, mtp->mirror_data->mirror_dest_id,
                rc, opennsl_errmsg(rc));
    }
}

static void
mirror_delete_all_source_ports (mirror_object_t *mirror)
{
    int i, port_count;

    /* we cache this since n_mirrored will change as ports get dis-associated */
    port_count = mirror->n_mirrored;

    for (i = 0; i < port_count; i++) {
        mirror_delete_source_port(mirror, &mirror->mirrored_ports[i]);
    }
}

/*
 * A mirror object can be destroyed in one of following ways:
 *
 * - mirror object itself is directly specified OR
 * - its name is specified OR
 * - the 'aux' is supplied OR
 * - the corresponding mirror endpoint 'mtp' is supplied
 *
 * The precedence is as listed above.  At least one parameter
 * is needed and should not be NULL.
 */
static void
mirror_object_destroy (mirror_object_t *mirror,
        const char *name, void *aux, struct ofbundle *mtp_specified)
{
    int rc, unit, port;
    struct ofbundle *mtp;

    VLOG_DBG("mirror with ptr %s name %s aux 0x%p mtp %s being destroyed",
            mirror ? mirror->name : "NULL",
            name ? name : "NULL",
            aux,
            mtp_specified ? mtp_specified->name : "NULL");

    if (NULL == mirror) {
        if (name) {
            mirror = find_mirror_with_name(name);
        } else if (aux) {
            mirror = find_mirror_with_aux(aux);
        } else if (mtp_specified) {
            mirror = find_mirror_with_mtp(mtp_specified);
        }

        /* still could not be found */
        if (NULL == mirror) {
            VLOG_DBG("mirror with name %s aux 0x%p mtp %s NOT found",
                    name ? name : "NULL",
                    aux,
                    mtp_specified ? mtp_specified->name : "NULL");
            return;
        }
    }

    /* cached for convenience */
    mtp = mirror->mtp;

    VLOG_DBG("mirror %s with mtp %s found; being destroyed",
            mirror->name, mtp->name);

    /* no-op, NOT an error */
    if (NULL == mtp->mirror_data) {
        VLOG_DBG("mirror %s mtp %s was NOT an mtp anyway",
                mirror->name, mtp->name);
        return;
    }

    /*
     * Disassociate all mirrored ports from mtp first.
     * BCM requires this before a mirror can be deleted
     */
    mirror_delete_all_source_ports(mirror);

    VLOG_DBG("now destroying mtp HW %s for mirror %s",
            mtp->name, mirror->name);
    mtp_get_hw_info(mtp, &unit, &port);
    rc = bcmsdk_mirror_endpoint_destroy(unit, mtp->mirror_data->mirror_dest_id);
    if (OPENNSL_SUCCESS(rc)) {
        VLOG_DBG("mirror %s hw endpoint %s also destroyed successfully",
                mirror->name, mtp->name);
    } else {
        VLOG_ERR("mirror %s HW endpoint %s destroy FAILURE <%s (%d)>",
                mirror->name, mtp->name, opennsl_errmsg(rc), rc);
    }

    VLOG_DBG("mirror %s completely destroyed", mirror->name);

    /* now free the storage it occupied */
    mirror_object_free(mirror);
}

static void
mirror_object_direct_destroy (mirror_object_t *mirror)
{
    mirror_object_destroy(mirror, NULL, NULL, NULL);
}

/* not used yet but may come useful later */
#if 0
static void
mirror_object_destroy_with_name (const char *name)
{
    mirror_object_destroy(NULL, name, NULL, NULL);
}

#endif

static void
mirror_object_destroy_with_aux (void *aux)
{
    mirror_object_destroy(NULL, NULL, aux, NULL);
}

/*
 * used externally, do NOT make static
 */
void
mirror_object_destroy_with_mtp (struct ofbundle *mtp)
{
    mirror_object_destroy(NULL, NULL, NULL, mtp);
}

/*
 * when a destination is a lag, we have to collect all the
 * counters of all the lag members and add them up for the result
 */
static int
mirror_get_stats (struct ofbundle *mtp, uint64_t *packets, uint64_t *bytes)
{
    struct netdev_stats stats;
    int hw_units[LAG_PORT_LIMIT];
    int hw_ports[LAG_PORT_LIMIT];
    int i, n;

    n = bundle_expand(mtp, LAG_PORT_LIMIT, NULL, hw_units, hw_ports);
    if (n > LAG_PORT_LIMIT) n = LAG_PORT_LIMIT;
    *packets = *bytes = 0;
    for (i = 0; i < n; i++) {
        if (bcmsdk_get_port_stats(hw_units[i], hw_ports[i], &stats)) {
            VLOG_ERR("bcmsdk_get_port_stats FAILED for unit %d port %d",
                    hw_units[i], hw_ports[i]);
            continue;
        }
        VLOG_DBG("adding %"PRIu64" packets & %"PRIu64" bytes to "
                "final stats from unit %d port %d",
                stats.tx_packets, stats.tx_bytes, hw_units[i], hw_ports[i]);
        *packets += stats.tx_packets;
        *bytes += stats.tx_bytes;
    }

    VLOG_DBG("base stats for mtp %s set: packets %"PRIu64", "
            "bytes %"PRIu64"", mtp->name, *packets, *bytes);

    return 0;
}

static int
mirror_object_create (const char *name,
        void *aux, struct ofproto_mirror_bundle *mout, struct ofbundle *mtp,
        mirror_object_t **mirror_created)
{
    int rc, hw_unit, hw_port;
    mirror_object_t *mirror_from_name,
                    *mirror_from_aux,
                    *mirror_from_mtp;
    mirror_object_t *mirror;

    ovs_assert(mtp);

    VLOG_DBG("started creating mirror %s with aux 0x%p mtp %s",
            name, aux, mtp->name);

    mirror = *mirror_created = NULL;

    mirror_from_name = find_mirror_with_name(name);
    mirror_from_aux = find_mirror_with_aux(aux);
    mirror_from_mtp = find_mirror_with_mtp(mtp);

    /*
     * do same sanity checking of the parameters.
     * if either 'mirror_from_name' or 'mirror_from_aux' is
     * available, they MUST imply the same mirror.
     */
    if (mirror_from_name || mirror_from_aux) {

        /* these must match up */
        if (mirror_from_name != mirror_from_aux) {
            VLOG_ERR("mirror name %s and mirror 'aux' 0x%p mismatch",
                name, aux);
            return EXTERNAL_ERROR;
        }

        /* pick either one */
        mirror = mirror_from_name;

        /*
         * if these dont match, it means the destination port (mtp)
         * of an existing mirror is being changed.  If so, blow
         * the whole thing away and re-construct the mirror from scratch.
         */
        if (mirror->mtp != mtp) {
            VLOG_DBG("mtp for mirror %s being changed from %s to %s",
                mirror->name, mirror->mtp->name, mtp->name);
            mirror_object_direct_destroy(mirror);
            mirror = NULL;
        }

    } else {

        /* this cannot be around without a matching name and aux */
        if (mirror_from_mtp) {
            VLOG_ERR("mirror mtp 0x%p (%s) exists without a name or aux",
                mtp, mtp->name);
            return EXTERNAL_ERROR;
        }
    }

    if (mirror) {
        VLOG_DBG("reconfiguring mirror %s", mirror->name);
        mirror_delete_all_source_ports(mirror);
        VLOG_DBG("mirror %s already exists", name);
        *mirror_created = mirror;
        return 0;
    }

    ovs_assert(NULL == mtp->mirror_data);

    /* get new space and check for 'too many mirrors' */
    VLOG_DBG("creating a new fresh mirror with name %s", name);
    mirror = mirror_object_allocate();
    if (NULL == mirror) {
        VLOG_ERR("no more space left to create mirror %s", name);
        return RESOURCE_ERROR;
    }

    /* we have to create these now */
    mtp->mirror_data = xmalloc(sizeof(opennsl_mirror_destination_t));
    strncpy(mirror->name, name, MIRROR_NAME_SIZE);
    mirror->aux = aux;
    mirror->mout = mout;
    mirror->mtp = mtp;

    /* obtain the bcm unit and port id */

    /* create the mirror destination in hardware */
    if (bundle_is_a_lag(mtp)) {
        rc = bcmsdk_lag_mirror_endpoint_create(mtp->bond_hw_handle,
                mtp->mirror_data);
    } else {
        mtp_get_hw_info(mtp, &hw_unit, &hw_port);
        rc = bcmsdk_simple_port_mirror_endpoint_create(hw_unit, hw_port,
                mtp->mirror_data);
    }

    if (rc) {
        VLOG_ERR("creating the hw endpoint for mirror %s mtp %s FAILED",
                mirror->name, mtp->name);
        mirror_object_free(mirror);
        return INTERNAL_ERROR;
    }

    /* if we are here, mirror endpoint has successfully been created */
    *mirror_created = mirror;

    /* set the base stats of the mirror output port */
    mirror_get_stats(mtp, &mirror->tx_base_packets, &mirror->tx_base_bytes);
    VLOG_DBG("mirror %s base stats set to packets %"PRIu64" bytes %"PRIu64"",
        mirror->name, mirror->tx_base_packets, mirror->tx_base_bytes);

    VLOG_DBG("succesfully created mirror %s with mirror_dest_id %d",
            name, mtp->mirror_data->mirror_dest_id);

    return 0;
}

/*
 * add a mirror SOURCE port to an existing OUTPUT (MTP)
 * with the specified flags.  If the source port is a lag,
 * then expand the lag into its individual ports and record
 * those one by one.
 */
static int
mirror_add_source_port (mirror_object_t *mirror,
        struct ofbundle *source, uint32 flags)
{
    struct ofbundle *mtp = mirror->mtp;
    int i, rc, n;
    int hw_units[LAG_PORT_LIMIT], hw_ports[LAG_PORT_LIMIT];
    struct bcmsdk_provider_ofport_node *ofports[LAG_PORT_LIMIT];
    mirrored_port_t *mport;

    VLOG_DBG("adding src port %s (0x%p) to MTP %s (0x%p), flags:%s%s%s (%d)",
            source->name, source, mtp->name, mtp,
            flags & OPENNSL_MIRROR_PORT_INGRESS ? " ingress" : "",
            flags & OPENNSL_MIRROR_PORT_EGRESS ? " egress" : "",
            flags & OPENNSL_MIRROR_PORT_DEST_TRUNK ? " trunk" : "",
            flags);

    /* is the specified MTP a fully functional mirror endpoint ? */
    if (NULL == mtp->mirror_data) {
        VLOG_ERR("bundle %s (0x%p) is not a valid mirror destination",
                mtp->name, mtp);
        return INTERNAL_ERROR;
    }

    /* this expands to individual ports if source is a lag */
    n = source_bundle_get_hw_info(source, LAG_PORT_LIMIT,
            ofports, hw_units, hw_ports);

    /* trim down to BCM limits */
    if (n > LAG_PORT_LIMIT) n = LAG_PORT_LIMIT;

    /* now add one port at a time, also recording the info */
    for (i = 0; i < n; i++) {
        rc = bcmsdk_mirror_add_source_port(hw_units[i], hw_ports[i], flags,
                mtp->mirror_data->mirror_dest_id);
        if (OPENNSL_SUCCESS(rc)) {
            mport = &mirror->mirrored_ports[mirror->n_mirrored];
            mport->ofport = ofports[i];
            mport->bcm_unit = hw_units[i];
            mport->bcm_port = hw_ports[i];
            mport->flags = flags;
            mirror->n_mirrored++;
        }
    }

    return 0;
}

static int
mirror_object_setup (struct mbridge *mbridge, void *aux, const char *name,
        struct ofbundle **srcs, size_t n_srcs,
        struct ofbundle **dsts, size_t n_dsts,
        unsigned long *src_vlans, struct ofproto_mirror_bundle *mout,
        struct ofbundle *mtp, uint16_t out_vlan)
{
    int rc, i, flag;
    bool output_is_lag = false;
    mirror_object_t *mirror;

    VLOG_DBG("mirror_object_setup name %s n_srcs %d n_dsts %d mtp %s",
            name, (int) n_srcs, (int) n_dsts, mtp->name);

    rc = mirror_object_create(name, aux, mout, mtp, &mirror);
    if (rc) return rc;

    output_is_lag = bundle_is_a_lag(mtp);

    /*
     * this logic will add ingress mirrors AND ingress+egress mirrors
     * to the mirror.  Once this is complete, the only remaining ones
     * are only the egress ports alone which will be added in the 2nd
     * loop after this one.
     */
    for (i = 0; i < n_srcs; i++) {

        /* a mirrored port cannot also be a mirror endpoint */
        if (srcs[i]->mirror_data) {
            VLOG_ERR("src %s is also an MTP", srcs[i]->name);
            continue;
        }

        flag = OPENNSL_MIRROR_PORT_INGRESS;
        if (bundle_present(srcs[i], dsts, n_dsts)) {
            flag |= OPENNSL_MIRROR_PORT_EGRESS;
        }

        /* bcm seems to need this if MTP is a trunk */
        if (output_is_lag)
            flag |= OPENNSL_MIRROR_PORT_DEST_TRUNK;

        mirror_add_source_port(mirror, srcs[i], flag);
    }

    /*
     * this logic adds ONLY egress ports to the mirror.  The ingress
     * ones AND ingress+egress ones have already been added above.
     * Only egress ones remain and so only search for those.
     */
    for (i = 0; i < n_dsts; i++) {

        /* a mirrored port cannot also be a mirror endpoint */
        if (dsts[i]->mirror_data) {
            VLOG_ERR("src %s is also an MTP", dsts[i]->name);
            continue;
        }

        /* if ingress+egress, skip it, it was already added above */
        if (bundle_present(dsts[i], srcs, n_srcs)) {
            continue;
        }

        /* this can only be from an egress mirror port */
        flag = OPENNSL_MIRROR_PORT_EGRESS;

        /* bcm seems to need this if MTP is a trunk */
        if (output_is_lag)
            flag |= OPENNSL_MIRROR_PORT_DEST_TRUNK;

        mirror_add_source_port(mirror, dsts[i], flag);
    }

    return 0;
}

int
mirror_set__ (struct ofproto *ofproto_,
    void *aux, const struct ofproto_mirror_settings *s)
{
    struct ofproto_mirror_bundle *msrcs, *mdsts, *mout;
    struct bcmsdk_provider_node *ofproto;
    struct ofbundle **srcs, **dsts, *out;
    int error = 0;
    int i;

    VLOG_DBG("*****************************************************");
    VLOG_DBG("**************** MIRROR CALL ************************");
    VLOG_DBG("*****************************************************");
    VLOG_DBG("mirror_set__ called");

    /* aux MUST always be available */
    if (NULL == aux) {
        VLOG_ERR("something wrong, aux is NULL");
        return EXTERNAL_ERROR;
    }

    if (NULL == s) {
        VLOG_DBG("s is NULL, destroying mirror with aux 0x%p", aux);
        mirror_object_destroy_with_aux(aux);
        return 0;
    }

    /* out_bundle is a pointer to a buffer containing a *ofproto,*aux tuple */
    mout = (struct ofproto_mirror_bundle *)(s->out_bundle);
    out = bundle_lookup(bcmsdk_provider_node_cast(mout->ofproto), mout->aux);
    if (NULL == out) {
        VLOG_ERR("Mirror output port not found");
        return EXTERNAL_ERROR;
    }

    VLOG_DBG("    n_srcs %d, n_dsts %d, out_vlan %u",
            (int) s->n_srcs, (int) s->n_dsts, s->out_vlan);

    srcs = xmalloc(s->n_srcs * sizeof *srcs);
    dsts = xmalloc(s->n_dsts * sizeof *dsts);

    /* srcs is a pointer to an array of N *ofproto,*aux tuples */
    msrcs = (struct ofproto_mirror_bundle *)(s->srcs);
    for (i = 0; (!error && (i < s->n_srcs)); i++) {
        ofproto = bcmsdk_provider_node_cast(msrcs[i].ofproto);
        srcs[i] = bundle_lookup(ofproto, msrcs[i].aux);
        if (NULL == srcs[i]) {
            VLOG_ERR("Mirror RX port %d of %d not found",
                i+1, (int) s->n_srcs);
            error = EXTERNAL_ERROR;
            break;
        }
    }

    /* dsts is a pointer to an array of N *ofproto,*aux tuples */
    mdsts = (struct ofproto_mirror_bundle *)(s->dsts);
    for (i = 0; (!error && (i < s->n_dsts)); i++) {
        ofproto = bcmsdk_provider_node_cast(mdsts[i].ofproto);
        dsts[i] = bundle_lookup(ofproto, mdsts[i].aux);
        if (NULL == dsts[i]) {
            VLOG_ERR("Mirror TX port %d of %d not found",
                i+1, (int) s->n_dsts);
            error = EXTERNAL_ERROR;
            break;
        }
    }

    if (!error) {
        error = mirror_object_setup(ofproto->mbridge, aux, s->name,
                    srcs, s->n_srcs, dsts, s->n_dsts, s->src_vlans,
                    mout, out, s->out_vlan);
    }

    free(srcs);
    free(dsts);

    return error;
}

int
mirror_get_stats__ (struct ofproto *ofproto_,
    void *aux, uint64_t *packets, uint64_t *bytes)
{
    mirror_object_t *mirror;

    VLOG_DBG("*****************************************************");
    VLOG_DBG("**************** STATS CALL *************************");
    VLOG_DBG("*****************************************************");
    VLOG_DBG("getting stats for mirror aux 0x%p", aux);

    mirror = find_mirror_with_aux(aux);
    if (NULL == mirror) return EXTERNAL_ERROR;

    VLOG_DBG("getting stats for mirror %s", mirror->name);

    if (mirror_get_stats(mirror->mtp, packets, bytes))
        return INTERNAL_ERROR;

    *packets -= mirror->tx_base_packets;
    *bytes -= mirror->tx_base_bytes;

    VLOG_DBG("returning stats for mirror %s mtp %s; "
            "tx packets %"PRIu64", bytes %"PRIu64"",
            mirror->name, mirror->mtp->name, *packets, *bytes);

    return 0;
}

bool
is_mirror_output_bundle (const struct ofproto *ofproto_, void *aux)
{
    int i;
    mirror_object_t *m;

    VLOG_DBG("is_mirror_output_bundle called");
    for (i = 0; i < MAX_MIRRORS; i++) {
        m = &all_mirrors[i];
        if (mirror_slot_is_free(m)) continue;
        if (m->mout->aux == aux) return true;
    }
    return false;
}

/************************ End of Mirror related functions ***********************/
