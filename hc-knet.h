/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    hc-knet.h
 *
 */
#ifndef __HC_KNET_H__
#define __HC_KNET_H__ 1

#include <netinet/ether.h>
#include <opennsl/types.h>

/* BCM KNET filter priorities.
 * Filters with priority 0 are applied only on RX channel 0.
 * Filters with priority 1 are applied only on RX channel 1.
 * Filters with priority 2 and above are applied to both RX channels.
 */
#define KNET_FILTER_PRIO        2

extern int hc_knet_init(int unit);
extern int bcmsdk_knet_if_create(char *name, int unit, opennsl_port_t port,
                                 struct ether_addr *mac, int *knet_if_id);
extern int bcmsdk_knet_if_delete(char *name, int unit, int knet_if_id);

extern void bcmsdk_knet_filter_create(char *name, int unit, opennsl_port_t port,
                                      int knet_if_id, int *knet_filter_id);
extern void bcmsdk_knet_filter_delete(char *name, int unit, int knet_filter_id);

#endif /* __HC_KNET_H__ */
