#!/usr/bin/python

# (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
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
    retStruct = switch.DeviceInteract(command="ovs-vsctl list system")
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

def intervlan_admin_and_link_state_test(**kwargs):

    switch = kwargs.get('switch', None)
    count = 0

    LogOutput('info', "\nConfigure interface vlan20 and bring it 'up'")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=20, addr="20.0.0.1",
                                  mask=24, config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, 'Failed to configure vlan interface'

    retStruct = InterfaceEnable(deviceObj=switch, enable=True, vlan=20)
    retCode = retStruct.returnCode()
    assert retCode == 0, 'Failed to bring up the vlan interface'

    LogOutput('info', "Get the admin and link states for interface vlan20")
    cmd_get = "ovs-vsctl get interface vlan20 admin_state link_state"
    retStruct = switch.DeviceInteract(command=cmd_get)
    retCode = retStruct['returnCode']
    assert retCode == 0, 'Failed to execute the ovs-vsctl command, cmd = %s' % cmd_get

    buf = retStruct.get('buffer').splitlines()
    for line in buf:
        if "up" in line:
            count += 1
    assert count==2, 'Failed to bring up the interface vlan20'
    LogOutput('info', "Admin and link states are verified as 'up' successfully")

    LogOutput('info', "Bring interface vlan20 down")
    retStruct = InterfaceEnable(deviceObj=switch, enable=False, vlan=20)
    retCode = retStruct.returnCode()
    assert retCode == 0, 'Failed to bring down the vlan interface'

    count = 0
    LogOutput('info', "Get the admin and link states for interface vlan20")
    cmd_get = "ovs-vsctl get interface vlan20 admin_state link_state"
    retStruct = switch.DeviceInteract(command=cmd_get)
    retCode = retStruct['returnCode']
    assert retCode == 0, 'Failed to execute the ovs-vsctl command, cmd = %s' % cmd_get

    buf = retStruct.get('buffer').splitlines()
    for line in buf:
        if "down" in line:
            count += 1
    assert count==2, 'Failed to bring down the interface vlan20'
    LogOutput('info', "Admin and link states are verified as 'down' successfully")

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
        intervlan_knet_test(switch=dut01Obj)

    def test_intervlan_admin_and_link_state_test(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        intervlan_admin_and_link_state_test(switch=dut01Obj)
