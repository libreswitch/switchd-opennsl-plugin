/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    hc_stats.h
 *
 * Purpose: This file provides public definitions for Interface statistics API.
 *
 */
#ifndef __HC_STAT_H__
#define __HC_STAT_H__ 1

extern int bcmsdk_get_port_stats(int hw_unit, int hw_port, struct netdev_stats *stats);

#endif /* __HC_STAT_H__ */
