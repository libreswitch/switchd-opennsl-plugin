#!/usr/bin/env python

# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

"""Layer 3 test file.

Name:
    test_layer3_ct_lagl3_interface

Objective:
    To verify the correct functionality of a layer 3 configuration over a
    configured LAG.

Topology:
    2 switches
"""

from opstestfw.switch.CLI import (
    InterfaceEnable,
    InterfaceLagIdConfig,
    lagCreation,
    time
)

from opstestfw.testEnviron import LogOutput, testEnviron
import pytest


# Topology definition
topoDict = {'topoExecution': 1000,
            'topoTarget': 'dut01 dut02',
            'topoDevices': 'dut01 dut02',
            'topoLinks': 'lnk01:dut01:dut02,'
                         'lnk02:dut01:dut02',
            'topoFilters': 'dut01:system-category:switch,'
                           'dut02:system-category:switch'}


def verify_lag_membership(**kwargs):
    """Test description.

    Topology:

        [s1] <-----> [s2]

    Objective:
        Test creation using appctl for the following LAG creation,
        internal VLAN creation, bitmap updates.

    Cases:
        - Verify LAG creation using appctl
        - Verify internal vlan creation using appctl
        - Verify knet filter
        - Verify vlan bitmap updated with member ports using shut, no shut
        - Verify vlan bitmap updated with member ports using "no lag" command
    """
    switch = kwargs.get('device1', None)
    vlan_id = "1024"
    test_lag_id = 100

    ###########################################################################
    #                                                                         #
    #                   [Switch1] ------- LAG -------> [Switch2]                       #
    #                                                                         #
    ###########################################################################

   # Verifing Switch 1
   # Verify the bitmap changes for LAG

    LogOutput("info","Check l3 ports bitmap update for LAG100")
    enable_ports = "Egress enabled ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000006"
    created_hw_output = "hw_created=1"

    command = \
    "ovs-appctl plugin/debug lag"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert enable_ports in bufferout,"Bitmap not deleted for LAG"
    assert created_hw_output in bufferout,"Bitmap not deleted for lag"
    LogOutput('info', "Verified: LAG created and ports deleted in bitmap for lag")

    # Verify vlan creation and bit map using appctl

    LogOutput("info","Check l3 ports bitmap for Vlan %s" % vlan_id)
    output_trunk = "installed native untagged ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000006"
    command = \
    "ovs-appctl plugin/debug vlan " + vlan_id
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to internal vlan"
    LogOutput('info', "Verified: ports added in vlan bitmap for lag")

    # Verify knet filter for L3 interface
    LogOutput("info", "Check knet_filter_l3 knet creation")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')
    output = "knet_filter_l3_" + vlan_id
    assert output in buf, 'l3 interface filter not created'
    LogOutput('info', "Verified: l3 interface knet filter is created")
    assert "ingport=1" in buf, 'l3 interface filter not created for port 1'
    LogOutput('info', "Verified: l3 interface knet filter is created for port 1")
    assert "ingport=2" in buf, 'l3 interface filter not created for port 2'
    LogOutput('info', "Verified: l3 interface knet filter is created for port 2")

   #Disable interface 1
    LogOutput('info',
              'Disabling interface %s on device' % 'lnk01')

    ret_struct = InterfaceEnable(
                    deviceObj=switch,
                    enable=False,
                    interface=switch.linkPortMapping['lnk01'])
    assert not ret_struct.returnCode(), \
        'Unable to disable interface %s on device' % 'lnk01'

    #Waiting for interfaces to go down
    time.sleep(2)

   # Verify the bitmap changes for internal vlan

    LogOutput("info","Check l3 ports bitmap update for Vlan %s" % vlan_id)
    if switch.linkPortMapping['lnk01'] == 1:
        output_trunk = "installed native untagged ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000004"
    else :
        output_trunk = "installed native untagged ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    command = \
    "ovs-appctl plugin/debug vlan " + vlan_id
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap are deleted from internal vlan"
    LogOutput('info', "Verified: ports updated in vlan bitmap for lag")

   # Verify the bitmap changes for LAG

    LogOutput("info","Check l3 ports bitmap update for LAG100")
    if switch.linkPortMapping['lnk01'] == 1:
        enable_ports = "Egress enabled ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000004"
    else :
        enable_ports = "Egress enabled ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"

    created_hw_output = "hw_created=1"

    command = \
    "ovs-appctl plugin/debug lag"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert enable_ports in bufferout,"Bitmap not deleted for LAG"
    assert created_hw_output in bufferout,"LAG is not created"
    LogOutput('info', "Verified: LAG created and disable port is deleted in bitmap for lag")

   #Disable interface 2
    LogOutput('info',
              'Disabling interface %s on device' % 'lnk02')

    ret_struct = InterfaceEnable(
                    deviceObj=switch,
                    enable=False,
                    interface=switch.linkPortMapping['lnk02'])
    assert not ret_struct.returnCode(), \
        'Unable to disable interface %s on device' % 'lnk02'

    #Waiting for interfaces to go down
    time.sleep(2)

   # Verify the bitmap changes for internal vlan

    LogOutput("info","Check l3 ports bitmap update for Vlan %s" % vlan_id)
    vlan_creation_output = "VLAN " + vlan_id + " does not exist."

    command = \
    "ovs-appctl plugin/debug vlan " + vlan_id
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert vlan_creation_output in bufferout,"Internal vlan exists"
    LogOutput('info', "Verified: Vlan deleted once all members of the LAG are down")

   # Verify the bitmap changes for LAG

    LogOutput("info","Check l3 ports bitmap update for LAG100")
    enable_ports = "Egress enabled ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    created_hw_output = "hw_created=1"

    command = \
    "ovs-appctl plugin/debug lag"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert enable_ports in bufferout,"Bitmap not deleted for LAG"
    assert created_hw_output in bufferout,"LAG deleted"
    LogOutput('info', "Verified: LAG is not destroyed and ports are deleted in bitmap for lag")
    LogOutput('info', "Verified: As the member ports are disabled the LAG is not destroyed")

    # Enable interface 1
    LogOutput('info',
              'Enabling interface %s on device' % 'lnk01')

    ret_struct = InterfaceEnable(
                    deviceObj=switch,
                    enable=True,
                    interface=switch.linkPortMapping['lnk01'])
    assert not ret_struct.returnCode(), \
        'Unable to enable interface %s on device' % 'lnk01'

    # Enable interface 2
    LogOutput('info',
              'Enabling interface %s on device' % 'lnk02')

    ret_struct = InterfaceEnable(
                    deviceObj=switch,
                    enable=True,
                    interface=switch.linkPortMapping['lnk02'])
    assert not ret_struct.returnCode(), \
        'Unable to enable interface %s on device' % 'lnk02'

    #Waiting for interfaces to come up
    time.sleep(5)

    # Verify vlan creation and bit map using appctl

    LogOutput("info","Check l3 ports bitmap for Vlan %s" % vlan_id)
    output_trunk = "installed native untagged ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000006"
    command = \
    "ovs-appctl plugin/debug vlan " + vlan_id
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to internal vlan"
    LogOutput('info', "Verified: ports added in vlan bitmap for lag")

    # Remove interface 1 from LAG
    LogOutput('info',
              'Remove interface %s from LAG %s' % ('lnk01',test_lag_id))

    ret_struct = InterfaceLagIdConfig(
                    deviceObj=switch,
                    interface=switch.linkPortMapping['lnk01'],
                    lagId=test_lag_id,
                    enable=False)
    assert not ret_struct.returnCode(), \
        'Unable to remove interface %s from LAG %s' % ('lnk01',test_lag_id)

   # Verify the bitmap changes for internal vlan

    LogOutput("info","Check l3 ports bitmap update for Vlan %s" % vlan_id)
    if switch.linkPortMapping['lnk01'] == 1:
        output_trunk = "installed native untagged ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000004"
    else :
        output_trunk = "installed native untagged ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    command = \
    "ovs-appctl plugin/debug vlan " + vlan_id
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to internal vlan"
    LogOutput('info', "Verified: ports added in vlan bitmap for lag")

   # Verify the bitmap changes for LAG

    LogOutput("info","Check l3 ports bitmap update for LAG100")
    if switch.linkPortMapping['lnk01'] == 1:
        enable_ports = "Egress enabled ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000004"
    else :
        enable_ports = "Egress enabled ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    created_hw_output = "hw_created=1"

    command = \
    "ovs-appctl plugin/debug lag"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert enable_ports in bufferout,"Bitmap not deleted for LAG"
    assert created_hw_output in bufferout,"LAG is not created"
    LogOutput('info', "Verified: LAG created and ports deleted in bitmap for lag")

    # Remove interface 2 from LAG
    LogOutput('info',
              'Remove interface %s from LAG %s' % ('lnk02',test_lag_id))

    ret_struct = InterfaceLagIdConfig(
                    deviceObj=switch,
                    interface=switch.linkPortMapping['lnk02'],
                    lagId=test_lag_id,
                    enable=False)
    assert not ret_struct.returnCode(), \
        'Unable to remove interface %s from LAG %s' % ('lnk02',test_lag_id)

   # Verify the bitmap changes for internal vlan

    LogOutput("info","Check l3 ports bitmap update for Vlan %s" % vlan_id)
    vlan_creation_output = "VLAN %s does not exist." % vlan_id

    command = \
    "ovs-appctl plugin/debug vlan " + vlan_id
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert vlan_creation_output in bufferout,"Internal vlan exists"
    LogOutput('info', "Verified: Vlan deleted once all members of the LAG are down")

   # Verify the bitmap changes for LAG

    LogOutput("info","Check l3 ports bitmap update for LAG100")
    enable_ports = "Egress enabled ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    created_hw_output = "hw_created=1"

    command = \
    "ovs-appctl plugin/debug lag"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert enable_ports not in bufferout,"Bitmap exists for LAG"
    assert created_hw_output not in bufferout,"LAG exists"
    LogOutput('info', "Verified: LAG is destroyed and ports are deleted in bitmap for lag")
    LogOutput('info', "Verified: As the member ports are removed from the LAG it is destroyed")

@pytest.mark.skipif(True, reason="Disabling old tests")
class Test_verifylagl3membership:
    """Test Configuration Class for Fastpath Ping.

    Topology:
        - Switch 1
        - Switch 2

    Test Cases:
        - test_fastpath_ping
    """

    @classmethod
    def setup_class(cls):
        """Class configuration method executed after class is instantiated.

        Test topology is created and Topology object is stored as topoObj
        """
        # Test object will parse command line and formulate the env
        Test_verifylagl3membership.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_verifylagl3membership.topoObj = Test_verifylagl3membership.testObj.topoObjGet()

    @classmethod
    def teardown_class(cls):
        """Class configuration executed before class is destroyed.

        All docker containers are destroyed
        """
        Test_verifylagl3membership.topoObj.terminate_nodes()

    def setup_method(self, method):
        """Class configuration method executed before running all test cases.

        All devices will be configured before running test cases.
        """
        dut01 = self.topoObj.deviceObjGet(device='dut01')
        dut02 = self.topoObj.deviceObjGet(device='dut02')

        test_lag_id = 100

        ######################################################################
        # Configuration switch 1
        ######################################################################

        # Create LAG 100
        LogOutput('info', 'Creating LAG %s on switch 1' % test_lag_id)
        ret_struct = lagCreation(deviceObj=dut01,
                                 lagId=test_lag_id,
                                 configFlag=True)
        assert not ret_struct.returnCode(), \
            'Unable to create LAG %s on device' % test_lag_id

        # Enable interface 1
        LogOutput('info',
                  'Enabling interface %s on device' % 'lnk01')

        ret_struct = InterfaceEnable(
                        deviceObj=dut01,
                        enable=True,
                        interface=dut01.linkPortMapping['lnk01'])
        assert not ret_struct.returnCode(), \
            'Unable to enable interface %s on device' % 'lnk01'

        # Enable interface 2
        LogOutput('info',
                  'Enabling interface %s on device' % 'lnk02')

        ret_struct = InterfaceEnable(
                        deviceObj=dut01,
                        enable=True,
                        interface=dut01.linkPortMapping['lnk02'])
        assert not ret_struct.returnCode(), \
            'Unable to enable interface %s on device' % 'lnk02'

        # Configure LAG to interface 1
        LogOutput('info',
                  'Configuring LAG %s to interface %s' % (test_lag_id,
                                                          'lnk01'))

        ret_struct = InterfaceLagIdConfig(
                        deviceObj=dut01,
                        interface=dut01.linkPortMapping['lnk01'],
                        lagId=test_lag_id,
                        enable=True)
        assert not ret_struct.returnCode(), \
            'Unable to configure LAG %s to interface %s' % (test_lag_id,
                                                            'lnk01')

        # Configure LAG to interface 2
        LogOutput('info',
                  'Configuring LAG %s to interface %s' % (test_lag_id,
                                                          'lnk02'))

        ret_struct = InterfaceLagIdConfig(
                        deviceObj=dut01,
                        interface=dut01.linkPortMapping['lnk02'],
                        lagId=test_lag_id,
                        enable=True)
        assert not ret_struct.returnCode(), \
            'Unable to configure LAG %s to interface %s' % (test_lag_id,
                                                            'lnk02')

        ######################################################################
        # Configuration switch 2
        ######################################################################

        # Create LAG 100
        LogOutput('info', 'Creating LAG %s on switch 2' % test_lag_id)
        ret_struct = lagCreation(deviceObj=dut02,
                                 lagId=test_lag_id,
                                 configFlag=True)
        assert not ret_struct.returnCode(), \
            'Unable to create LAG %s on device' % test_lag_id

        # Enable interface 1
        LogOutput('info',
                  'Enabling interface %s on device' % 'lnk01')

        ret_struct = InterfaceEnable(
                        deviceObj=dut02,
                        enable=True,
                        interface=dut02.linkPortMapping['lnk01'])
        assert not ret_struct.returnCode(), \
            'Unable to enable interface %s on device' % 'lnk01'

        # Enable interface 2
        LogOutput('info',
                  'Enabling interface %s on device' % 'lnk02')

        ret_struct = InterfaceEnable(
                        deviceObj=dut02,
                        enable=True,
                        interface=dut02.linkPortMapping['lnk02'])
        assert not ret_struct.returnCode(), \
            'Unable to enable interface %s on device' % 'lnk02'

        # Configure LAG to interface 1
        LogOutput('info',
                  'Configuring LAG %s to interface %s' % (test_lag_id,
                                                          'lnk01'))

        ret_struct = InterfaceLagIdConfig(
                        deviceObj=dut02,
                        interface=dut02.linkPortMapping['lnk01'],
                        lagId=test_lag_id,
                        enable=True)
        assert not ret_struct.returnCode(), \
            'Unable to configure LAG %s to interface %s' % (test_lag_id,
                                                            'lnk01')

        # Configure LAG to interface 2
        LogOutput('info',
                  'Configuring LAG %s to interface %s' % (test_lag_id,
                                                          'lnk02'))

        ret_struct = InterfaceLagIdConfig(
                        deviceObj=dut02,
                        interface=dut02.linkPortMapping['lnk02'],
                        lagId=test_lag_id,
                        enable=True)
        assert not ret_struct.returnCode(), \
            'Unable to configure LAG %s to interface %s' % (test_lag_id,
                                                            'lnk02')

    def test_verifylagl3membership(self):
        """CT lag l3 test.

        Topology:
            - dut01: Switch 1
            - dut02: Switch 2
        """
        dut01 = self.topoObj.deviceObjGet(device='dut01')
        dut02 = self.topoObj.deviceObjGet(device='dut02')
        verify_lag_membership(device1=dut01)
