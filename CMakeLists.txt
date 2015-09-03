# Copyright (C) 2015 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

project (ovs_bcm_plugin)
cmake_minimum_required (VERSION 2.8)

# Define sources
set (SOURCES bcm.c
             bcm-plugins.c
             bufmon-bcm-provider.c
             hc-bcm-init.c
             hc-bufmon.c
             hc-debug.c
             hc-knet.c
             hc-lag.c
             hc-pbmp.c
             hc-port.c
             hc-stats.c
             hc-vlan.c
             hc-routing.c
             netdev-bcmsdk.c
             ofproto-bcm-provider.c
    )

# Define and locate needed libraries and includes
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)
pkg_check_modules(OPENNSL REQUIRED opennsl)

# Define compile flags
set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPENNSL_CFLAGS} -DINCLUDE_L3 -std=gnu99 -Wall -Werror")

include_directories(${CMAKE_SOURCE_DIR} ${OVSCOMMON_INCLUDE_DIRS}
	            ${OPENNSL_INCLUDE_DIRS})

# Create our library
add_library (ovs_bcm_plugin SHARED ${SOURCES})

target_link_libraries (ovs_bcm_plugin ${OVSCOMMON_LIBRARIES} ${OPENNSL_LIBRARIES})

# Installation
install(TARGETS ovs_bcm_plugin
        LIBRARY DESTINATION lib/openvswitch/plugins
       )
