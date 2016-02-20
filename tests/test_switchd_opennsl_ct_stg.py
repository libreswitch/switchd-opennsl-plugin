#!/usr/bin/python

# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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


def stg_test(**kwargs):

    switch = kwargs.get('switch', None)

    switch.VtyshShell(enter=True)
    switch.ConfigVtyShell(enter=True)
    switch.DeviceInteract(command="interface 1")
    switch.DeviceInteract(command="no routing")
    switch.DeviceInteract(command="no shutdown")
    switch.DeviceInteract(command="vlan 10")
    switch.DeviceInteract(command="no shutdown")
    switch.DeviceInteract(command="exit")
    switch.DeviceInteract(command="spanning-tree instance 1 vlan 10")
    switch.DeviceInteract(command="spanning-tree")
    switch.ConfigVtyShell(enter=False)
    switch.VtyshShell(enter=False)

# Verify STG 1 creation and port bit map using appctl

    LogOutput("info","#Check STG 1 with intf 1 in disabled state ##")
    output_stg_disabled = "disabled ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    output_stg_blocked = "blocked ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    output_stg_learning = "learning ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    output_stg_forwarding = "forwarding ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    command = \
    "ovs-appctl plugin/debug stg 1"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_stg_disabled in bufferout,"intf 1 added to STG 1 in disabled state"
    assert output_stg_blocked in bufferout,"intf 1 not added to STG 1 in blocked state"
    assert output_stg_learning in bufferout,"intf 1 added to STG 1 in learning state"
    assert output_stg_forwarding in bufferout,"intf 1 added to STG 1 in forwarding state"
    LogOutput('info', "Verified: intf 1 added to STG 1 with state as blocked")

# Verify STG 2 creation and port bit map using appctl

    LogOutput("info","#Check STG 2 with intf 1 in disabled state ##")
    output_stg_disabled = "disabled ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    output_stg_blocked = "blocked ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    output_stg_learning = "learning ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    output_stg_forwarding = "forwarding ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    command = \
    "ovs-appctl plugin/debug stg 2"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_stg_disabled in bufferout,"intf 1 added to STG 2 in disabled state"
    assert output_stg_blocked in bufferout,"intf 1 not added to STG 2 in blocked state"
    assert output_stg_learning in bufferout,"intf 1 added to STG 2 in learning state"
    assert output_stg_forwarding in bufferout,"intf 1 added to STG 2 in forwarding state"
    LogOutput('info', "Verified: intf 1 added to STG 2 with state as blocked")

class Test_stg_ct:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_stg_ct.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_stg_ct.topoObj = Test_stg_ct.testObj.topoObjGet()

    def teardown_class(cls):
        Test_stg_ct.topoObj.terminate_nodes()

    def test_stg_ct(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        retValue = stg_test(switch=dut01Obj)
        if retValue != 0:
            assert "Test failed"
        else:
            LogOutput('info', "\n### Test Passed ###\n")
