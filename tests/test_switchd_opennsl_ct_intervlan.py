#!/usr/bin/python

# (c) Copyright 2015 Hewlett Packard Enterprise Development LP
#
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import pytest
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch.OVS import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoType": "physical",
            "topoTarget": "dut01",
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}


def intervlan_knet_test(**kwargs):

    switch = kwargs.get('switch', None)

    systemMac = None
    retStruct = switch.DeviceInteract(command="ovs-vsctl list open_vswitch")
    buf = retStruct.get('buffer')

    for curLine in buf.split('\n'):
        # Match the systemMac
        if "system_mac" in curLine:
            systemMac = curLine.split()[2]

    systemMac = systemMac.replace('"', '')
    # Remove preceding 0s in mac
    systemMac = systemMac.replace(':0', ':')

    LogOutput("info", "Verify bridge_normal knet interface creation")
    appctl_command = "ovs-appctl plugin/debug knet netif"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')
    assert "bridge_normal" in buf, 'bridge_normal interface not created'
    LogOutput('info', "Verified bridge_normal knet interface")

    LogOutput('info', "Configure vlan interface 10")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=10, addr="10.0.0.1",
                                  mask=24, config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, 'Failed to configure an ipv4 address on vlan address'

    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=10, addr="1000::1",
                                  mask=120, ipv6flag=True, config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0,  "Failed to configure an ipv6 address on vlan"

    LogOutput('info', "Configured vlan interface successfully")

    LogOutput('info', "Verify vlan interface in ASIC")

    appctl_command = "ovs-appctl plugin/debug l3intf"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')
    assert systemMac in buf, 'Failed to enable interface vlan10'

    LogOutput('info', "Verified vlan interface in ASIC")

    LogOutput('info', "Verify knet filters in ASIC")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')

    assert "knet_filter_arp_vlan10" in buf, \
           'ARP filter for intervlan not configured in ASIC'
    assert "knet_filter_ipv4_vlan10" in buf, \
           'IPv4 filter for intervlan not configured in ASIC'
    assert "knet_filter_ipv6_vlan10" in buf, \
           'IPv6 filter for intervlan not configured in ASIC'

    LogOutput('info', "Verify knet filters in ASIC")

    LogOutput('info', "Uncofiguring VLAN interface")

    switch.VtyshShell(enter=True)
    switch.DeviceInteract(command="conf t")
    switch.DeviceInteract(command="no interface vlan10")
    switch.DeviceInteract(command="exit")
    switch.VtyshShell(enter=False)

    # Verify L3 interface is deleted in ASIC
    LogOutput('info', "Verify vlan interface is deleted in ASIC")
    appctl_command = "ovs-appctl plugin/debug l3intf"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')
    assert systemMac not in buf, 'Failed to enable l3 on port 1'
    LogOutput('info', "Interface vlan10 interface deleted successfully")

    # Verify Knet filters are deleted in ASIC
    LogOutput('info', "Verify knet filters in ASIC")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')

    assert "knet_filter_arp_vlan10" not in buf, \
           'ARP filter for intervlan not configured in ASIC'
    assert "knet_filter_ipv4_vlan10" not in buf, \
           'IPv4 filter for intervlan not configured in ASIC'
    assert "knet_filter_ipv6_vlan10" not in buf, \
           'IPv6 filter for intervlan not configured in ASIC'

    LogOutput('info', "KNET filters successfully deleted "
                      "from ASIC for vlan interface")


class Test_intervlan_ct:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_intervlan_ct.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_intervlan_ct.topoObj = Test_intervlan_ct.testObj.topoObjGet()

    def teardown_class(cls):
        Test_intervlan_ct.topoObj.terminate_nodes()

    def test_intervlan_ct(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        retValue = intervlan_knet_test(switch=dut01Obj)
        if retValue != 0:
            assert "Test failed"
        else:
            LogOutput('info', "\n### Test Passed ###\n")
