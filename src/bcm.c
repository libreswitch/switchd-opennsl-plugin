/*
 * Copyright (C) 2015-2016 Hewlett-Packard Enterprise Development Company, L.P.
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
 * File: bcm.c
 */
#include <ovs-thread.h>
#include <ovs-rcu.h>
#include <openvswitch/vlog.h>

#include "bcm.h"
#include "ops-bcm-init.h"

VLOG_DEFINE_THIS_MODULE(bcm);

#define TIMER_THREAD_TIMEOUT 60

static pthread_t bcm_main_thread;
static pthread_t bcm_timer_thread;
static struct ovs_barrier bcm_init_barrier;

extern int ops_mac_learning_run(void);

static void *
bcm_main(void * args OVS_UNUSED)
{
    VLOG_INFO("bcm main thread created");

    ovsrcu_quiesce_start();

    ops_switch_main(0, NULL);

    VLOG_INFO("bcm main thread terminated");

    return NULL;
}

static void *
bcm_timer_main (void * args OVS_UNUSED)
{
    while (true) {
        xsleep(TIMER_THREAD_TIMEOUT); /* in seconds */
        ops_mac_learning_run();
    }

    return (NULL);
}

void
ovs_bcm_init(void)
{
    ovs_barrier_init(&bcm_init_barrier, 2);
    bcm_main_thread = ovs_thread_create("ovs-bcm", bcm_main, NULL);
    bcm_timer_thread = ovs_thread_create("ovs-bcm-timer", bcm_timer_main, NULL);
    ovs_barrier_block(&bcm_init_barrier);
    VLOG_INFO("bcm initialization complete");
    ovs_barrier_destroy(&bcm_init_barrier);
}

/* This function is called from the BCM SDK. */
void
ovs_bcm_init_done(void)
{
    VLOG_INFO("bcm init done thread");
    ovs_barrier_block(&bcm_init_barrier);
}
