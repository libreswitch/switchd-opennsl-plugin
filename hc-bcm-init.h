/*
 * Hewlett-Packard Company Confidential (C) Copyright 2015 Hewlett-Packard Development Company, L.P.
 *
 * File:    hc-bcm-init.h
 *
 * Purpose: This file provides public definitions for Broadcom SDK initialization.
 *
 */

#ifndef __HALON_BCM_INIT_H__
#define __HALON_BCM_INIT_H__ 1

/* This function initializes Halon switchd application threads within the SDK. */
#define BCM_DIAG_SHELL_CUSTOM_INIT_F        hc_bcm_appl_init

/* Number of RX packets per second.
 * This limit is enforced in the user space SDK. */
#define HC_RX_GLOBAL_PPS            10000

extern int halon_main(int argc, char *argv[]);

#endif // __HALON_BCM_INIT_H__
