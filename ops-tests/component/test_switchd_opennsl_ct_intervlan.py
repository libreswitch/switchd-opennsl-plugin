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


@mark.platform_incompatible(['docker'])
def test_switchd_opennsl_plugin_intervlan_knet(topology, step):
    sw1 = topology.get('sw1')

    assert sw1 is not None

    system_mac = None
    buf = sw1("ovs-vsctl list system", shell='bash')

    for cur_line in buf.split('\n'):
        # Match the systemMac
        if "system_mac" in cur_line:
            system_mac = cur_line.split()[2]

    system_mac = system_mac.replace('"', '')
    # Remove preceding 0s in mac
    system_mac = system_mac.replace(':0', ':')

    step("Verify bridge_normal knet interface creation")
    appctl_command = "ovs-appctl plugin/debug knet netif"
    buf = sw1(appctl_command, shell='bash')
    assert "bridge_normal" in buf
    step("Verified bridge_normal knet interface")

    step("Configure vlan interface 10")
    sw1('configure terminal')
    sw1('vlan 10')
    sw1('no shutdown')
    sw1('int vlan 10')
    sw1('ip add 10.0.0.1/24')
    sw1('ipv6 add 1000::1/120')
    sw1('end')

    step("Verify vlan interface in ASIC")
    appctl_command = "ovs-appctl plugin/debug l3intf"
    buf = sw1(appctl_command, shell='bash')
    assert system_mac in buf

    step("Verified vlan interface in ASIC")

    step("Uncofiguring VLAN interface")
    sw1('configure terminal')
    sw1("no interface vlan10")
    sw1('end')

    # Verify L3 interface is deleted in ASIC
    step("Verify vlan interface is deleted in ASIC")
    appctl_command = "ovs-appctl plugin/debug l3intf"
    buf = sw1(appctl_command, shell='bash')
    assert system_mac not in buf

    step("\nConfigure interface vlan20 and bring it 'up'")
    count = 0
    sw1('configure terminal')
    sw1('vlan 20')
    sw1('no shutdown')
    sw1('int vlan 20')
    sw1('ip add 20.0.0.1/24')
    sw1('no shutdown')
    sw1('end')

    step("Get the admin and link states for interface vlan20")
    cmd_get = "ovs-vsctl get interface vlan20 admin_state link_state"
    buf = sw1(cmd_get, shell='bash')

    buf = buf.splitlines()
    for line in buf:
        if "up" in line:
            count += 1
    assert count == 2

    step("Bring interface vlan20 down")
    sw1('configure terminal')
    sw1('int vlan 20')
    sw1('shutdown')
    sw1('end')

    count = 0
    step("Get the admin and link states for interface vlan20")
    cmd_get = "ovs-vsctl get interface vlan20 admin_state link_state"
    buf = sw1(cmd_get, shell='bash')

    buf = buf.splitlines()
    for line in buf:
        if "down" in line:
            count += 1
    assert count == 2
