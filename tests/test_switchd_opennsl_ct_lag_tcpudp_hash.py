#(c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

import re
import pytest
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch.OVS import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoType": "physical",
            "topoTarget": "dut01 dut02",
            "topoDevices": "dut01 dut02",
            "topoLinks": "lnk01:dut01:dut02, \
                          lnk02:dut01:dut02",
            "topoFilters": "dut01:system-category:switch, \
                            dut02:system-category:switch"}

def lag_tcpudp_hash_check_status(switch1):
    appctl_command = "ovs-appctl plugin/debug lag"
    retStruct = switch1.DeviceInteract(command=appctl_command)

    buf = retStruct.get('buffer')
    lag_mode = re.findall(r"l4-src-dst", buf)
    if lag_mode == "l4-src-dst":
        return 0
    else:
        return -1

def lag_tcpudp_hash_test(**kwargs):

    switch1 = kwargs.get('switch1', None)
    switch2 = kwargs.get('switch2', None)

    # Entering vtysh prompt
    retStruct = switch1.VtyshShell(enter=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to enter vtysh prompt on SW1"

    # Entering config terminal
    retStruct = switch1.ConfigVtyShell(enter=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to enter config terminal on SW1"

    # Configuring lag interface
    retStruct = switch1.DeviceInteract(command="interface lag 100")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to configure lag interface on SW1"

    # Configuring lag hash mode
    retStruct = switch1.DeviceInteract(command="hash l4-src-dst")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to configure lag hash mode on SW1"

    # Entering interface
    retStruct = switch1.DeviceInteract(command="interface "
                                       + str(switch1.linkPortMapping['lnk01']))
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to enter interface on SW1"

    # Adding interface to lag
    retStruct = switch1.DeviceInteract(command="lag 100")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to add interface to lag on SW1"

    # Enbaling interface
    retStruct = switch1.DeviceInteract(command="no shutdown")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to enable interface on SW1"

    # Entering interface
    retStruct = switch1.DeviceInteract(command="interface "
                           + str(switch1.linkPortMapping['lnk02']))
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to enter interface on SW1"

    # Adding interface to lag
    retStruct = switch1.DeviceInteract(command="lag 100")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to add interface to lag on SW1"

    # Enabling interface
    retStruct = switch1.DeviceInteract(command="no shutdown")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to enable interface on SW1"

    # Exiting interface
    retStruct = switch1.DeviceInteract(command="exit")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to exit interface on SW1"

    # Exiting config terminal
    retStruct = switch1.ConfigVtyShell(enter=False)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to exit configure terminal on SW1"

    # Exiting vtysh prompt
    retStruct = switch1.VtyshShell(enter=False)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to exit vtysh prompt on SW1"

    # Entering vtysh prompt
    retStruct = switch2.VtyshShell(enter=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to enter vtysh prompt on SW2"

    # Entering config terminal
    retStruct = switch2.ConfigVtyShell(enter=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to enter config terminal on SW2"

    # Configuring lag interface
    retStruct = switch2.DeviceInteract(command="interface lag 100")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to configure lag interface on SW2"

    # Configuring lag hash mode
    retStruct = switch2.DeviceInteract(command="hash l4-src-dst")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to configure lag hash mode on SW2"

    # Entering interface
    retStruct = switch2.DeviceInteract(command="interface "
                                       + str(switch2.linkPortMapping['lnk01']))
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to enter interface on SW2"

    # Adding interface to lag
    retStruct = switch2.DeviceInteract(command="lag 100")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to add interface to lag on SW2"

    # Enbaling interface
    retStruct = switch2.DeviceInteract(command="no shutdown")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to enable interface on SW2"

    # Entering interface
    retStruct = switch2.DeviceInteract(command="interface "
                                       + str(switch2.linkPortMapping['lnk02']))
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to enter interface on SW2"

    # Adding interface to lag
    retStruct = switch2.DeviceInteract(command="lag 100")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to add interface to lag on SW2"

    # Enabling interface
    retStruct = switch2.DeviceInteract(command="no shutdown")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to enable interface on SW2"

    # Exiting interface
    retStruct = switch2.DeviceInteract(command="exit")
    retCode = retStruct.get('returnCode')
    assert retCode == 0, "Failed to exit interface on SW2"

    # Exiting config terminal
    retStruct = switch2.ConfigVtyShell(enter=False)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to exit configure terminal on SW2"

    # Exiting vtysh prompt
    retStruct = switch2.VtyshShell(enter=False)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to exit vtysh prompt on SW2"

    lag_tcpudp_hash_check_status(switch1)

@pytest.mark.skipif(True, reason="Disabling old tests")
class Test_lag_tcpudp_hash_ct:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_lag_tcpudp_hash_ct.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_lag_tcpudp_hash_ct.topoObj = Test_lag_tcpudp_hash_ct.testObj.topoObjGet()

    def teardown_class(cls):
        Test_lag_tcpudp_hash_ct.topoObj.terminate_nodes()

    def test_lag_tcpudp_hash_ct(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")

        retValue = lag_tcpudp_hash_test(switch1=dut01Obj, switch2=dut02Obj)
        if retValue != 0:
            assert "Test failed"
        else:
            LogOutput('info', "\n### Test Passed ###\n")
