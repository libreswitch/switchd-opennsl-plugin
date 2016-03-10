#!/usr/bin/env python

# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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

# The test case verifies addition and deletion of loopback interface.
#
# The following topology is used:
#
# +----------------+         +----------------+
# |                |         |                |
# |                |         |                |
# |      Host      +---------+     Switch     |
# |                |         |                |
# |                |         |                |
# +----------------+         +----------------+

# Topology definition
topoDict = {
    "topoExecution": 1000,
    "topoType": "physical",
    "topoTarget": "dut01",
    "topoDevices": "dut01 wrkston01",
    "topoLinks": "lnk01:dut01:wrkston01",
    "topoFilters": "dut01:system-category:switch, \
                    wrkston01:system-category:workstation"}


def loopback_creation(**kwargs):
    switch = kwargs.get('switch', None)
    host1 = kwargs.get('host1', None)

    # Enabling interfaces
    LogOutput('info', "Enabling interface1 on switch")
    retStruct = InterfaceEnable(
        deviceObj=switch,
        enable=True,
        interface=switch.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface1 on switch1"

    LogOutput('info', "Configuring ipv4 address 10.0.10.1 on interface 1")
    retStruct = InterfaceIpConfig(
        deviceObj=switch,
        interface=switch.linkPortMapping['lnk01'],
        addr="10.0.10.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 1"

    #Get port 1 uuid
    command = "ovs-vsctl get port 1 _uuid"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    uuid = bufferout.splitlines()
    #print uuid

    # From loopback interface with port1 uuid and add to vrf
    loopback_command = """ovsdb-client transact '[ "OpenSwitch",
         {
             "op" : "insert",
             "table" : "Interface",
             "row" : {
                 "type" : "loopback",
                 "name" : "lo:1"
             },
             "uuid-name" : "new_iface01"
         },
       {
             "op" : "insert",
             "table" : "Port",
             "row" : {
                 "name": "lo:1",
                 "interfaces" : [
                     "set",
                     [
                         [
                             "named-uuid",
                             "new_iface01"
                         ]
                     ]
                 ]
             },
             "uuid-name" : "new_port01"
          },
        {
             "op" : "update",
             "table" : "VRF",
             "where":[["name","==","vrf_default"]],
             "row" : {
                 "ports" : [
                     "set",
                     [
                         ["uuid", "%s"],
                         [
                             "named-uuid",
                             "new_port01"
                         ]
                     ]
                 ]
             }
          }
]'""" % (uuid[1])

    #print loopback_command

    # Create loopback interface with port1 uuid and add to vrf
    LogOutput('info', "Create loopback interface lo:1")
    returnStructure = switch.DeviceInteract(command=loopback_command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Failed to add loopback interface/port"
    retCode = returnStructure['returnCode']
    if retCode:
        LogOutput('error', "couldn't create loopback interface lo:1");

    command = \
        "ovs-vsctl list port lo:1"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Failed to add loopback interface/port"

    interface1 = int(switch.linkPortMapping['lnk01'])

    #loopback1 = int(switch.linkPortMapping['lo:1'])

    LogOutput('info', "Configuring ipv4 address 2.2.2.1 on loopback interface")
    retStruct = InterfaceIpConfig(
        deviceObj=switch,
        interface='lo:1',
        addr="2.2.2.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on loopback intf"

    returnStructure = switch.ConfigVtyShell(enter=False)
    returnStructure = switch.VtyshShell(enter=False)

    # Configure host1
    retStruct = host1.DeviceInteract(command="ifconfig eth1 up")
    retCode = retStruct['returnCode']
    assert retCode == 0, "Failed to bring up eth1 of host1"

    LogOutput('info', "\n\n\nConfiguring IPv4 address on host1 on eth1")
    retStruct = host1.NetworkConfig(
        ipAddr="10.0.10.2",
        netMask="255.255.255.0",
        interface=host1.linkPortMapping['lnk01'],
        broadcast="10.0.10.255",
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an IPv4 address on host1"

    # Configure a default IPv4 route
    LogOutput('info', "Configuring default route for IPv4 on host1")
    retStruct = host1.IPRoutesConfig(
        config=True,
        destNetwork="0.0.0.0",
        netMask=24,
        gateway="10.0.10.1")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure IPv4 default route on host1")
        caseReturnCode = 1

    # TEST: IPv4 ping from host1 to interface 1 ip
    LogOutput('info', "\n\n\nTEST: IPv4 ping from host1 to interface 1")
    retStruct = host1.Ping(ipAddr="10.0.10.1", packetCount=1)
    retCode = retStruct.returnCode()
    assert retCode == 0, "\n#### FAIL: IPv4 ping from host1 to loopback interface. ####"
    LogOutput('info', "\n#### PASS: IPv4 ping from host1 to loopback interface. ####")

    # TEST: IPv4 ping from host1 to loopback interface ip
    LogOutput('info', "\n\n\nTEST: IPv4 ping from host1 to loopback interface")
    retStruct = host1.Ping(ipAddr="2.2.2.1", packetCount=1)
    retCode = retStruct.returnCode()
    assert retCode == 0, "\n#### FAIL: IPv4 ping to loopback failed. ####"
    LogOutput('info', "\n#### PASS: IPv4 ping to loopback passed. ####")

    # Delete loopback interface
    LogOutput('info', "Deleting loopback interface lo:1")
    loopback_command = """ovsdb-client transact '[ "OpenSwitch",
       {
             "op" : "delete",
             "table" : "Port",
             "where":[["name","==","lo:1"]]
        },
        {
             "op" : "update",
             "table" : "VRF",
             "where":[["name","==","vrf_default"]],
             "row" : {
                 "ports" : [
                     "set",
                     [
                         ["uuid", "%s"]
                     ]
                 ]
             }
          }
]'""" % (uuid[1])
    #print loopback_command

    returnStructure = switch.DeviceInteract(command=loopback_command)
    retCode = returnStructure.get('returnCode')
    assert retCode == 0, "Failed to delete loopback interface/port"
    retCode = returnStructure['returnCode']
    if retCode:
        LogOutput('error', "couldn't create loopback interface lo:1");


    # TEST: IPv4 ping from host1 to loopback interface ip
    LogOutput('info', "\n\n\nTEST: IPv4 ping from host1 to loopback interface")
    retStruct = host1.Ping(ipAddr="2.2.2.1", packetCount=1)
    retCode = retStruct.returnCode()
    assert retCode != 0, "\n#### FAIL: IPv4 ping to loopback passed. ####"
    LogOutput('info', "\n#### PASS: IPv4 ping to loopback failed. ####")


@pytest.mark.timeout(1000)
@pytest.mark.skipif(True, reason="Disabling old tests")
class Test_loopback_creation:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_loopback_creation.testObj = testEnviron(topoDict=topoDict)
        #    Get topology object
        Test_loopback_creation.topoObj = Test_loopback_creation.testObj.topoObjGet()

    def teardown_class(cls):
        Test_loopback_creation.topoObj.terminate_nodes()

    def test_loopback_creation(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        wrkston01Obj = self.topoObj.deviceObjGet(device="wrkston01")
        loopback_creation(
            switch=dut01Obj,
            host1=wrkston01Obj)
