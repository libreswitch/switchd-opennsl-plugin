# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from pytest import mark

TOPOLOGY = """
#
# +-------+
# |  sw1  |
# +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
"""


def ecmp_hash_check_status(switch, is_ipv4, is_enabled):
    if (is_ipv4):
        appctl_command = 'ovs-appctl plugin/debug l3route'
        ret_struct = switch(appctl_command, shell='bash')
        switch(' ')
        log_ip_str = "IPv4"
    else:
        appctl_command = 'ovs-appctl plugin/debug l3v6route'
        ret_struct = switch(appctl_command, shell='bash')
        log_ip_str = "IPv6"
    if (is_enabled):
        ecmp_hash_status = 'Y'
        log_enable_str = "enable"
    else:
        ecmp_hash_status = 'N'
        log_enable_str = "disable"

    ecmp_hash_start = 0
    ecmp_hash_line_count = 0
    buf = ret_struct
    for curLine in buf.split('\n'):
        if "Src Addr" in curLine:
            ecmp_hash_start = 1
        if ecmp_hash_start == 1:
            ecmp_hash_line_count += 1
        if ecmp_hash_line_count == 3:
            hash_fields = curLine.split()
            if hash_fields[0] != ecmp_hash_status\
               or hash_fields[1] != ecmp_hash_status \
               or hash_fields[2] != ecmp_hash_status \
               or hash_fields[3] != ecmp_hash_status:
                print("error", "Could not %s ECMP %s hash in ASIC" %
                      (log_enable_str, log_ip_str))


@mark.platform_incompatible(['docker'])
def test_switchd_opennsl_plugin_ecmp_hash(topology):
    sw1 = topology.get('sw1')

    assert sw1 is not None

    sw1('configure terminal')
    sw1("ip ecmp load-balance src-ip disable")
    sw1("ip ecmp load-balance dst-ip disable")
    sw1("ip ecmp load-balance src-port disable")
    sw1("ip ecmp load-balance dst-port disable")
    sw1('exit')

    ecmp_hash_check_status(sw1, True, False)
    ecmp_hash_check_status(sw1, False, False)

    sw1('configure terminal')
    sw1("no ip ecmp load-balance src-ip disable")
    sw1("no ip ecmp load-balance dst-ip disable")
    sw1("no ip ecmp load-balance src-port disable")
    sw1("no ip ecmp load-balance dst-port disable")
    sw1('exit')

    ecmp_hash_check_status(sw1, True, True)
    ecmp_hash_check_status(sw1, False, True)
