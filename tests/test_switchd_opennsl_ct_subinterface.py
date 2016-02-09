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

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoType": "physical",
            "topoTarget": "dut01",
            "topoDevices": "dut01 wrkston01",
            "topoLinks": "lnk01:dut01:wrkston01",
            "topoFilters": "dut01:system-category:switch,\
                            wrkston01:system-category:workstation"}

def subinterface_creation(**kwargs):
    switch = kwargs.get('switch', None)
    host1 = kwargs.get('host1', None)

# Enabling interfaces 1
    LogOutput('info', "Enabling interface 1 on switch")
    retStruct = InterfaceEnable(
              deviceObj=switch,
              enable=True,
              interface=switch.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface1 on switch1"

    LogOutput('info', "################### Configuring ipv4 address 10.0.10.1 on interface 1 #######################")
    retStruct = InterfaceIpConfig(
            deviceObj=switch,
            interface=switch.linkPortMapping['lnk01'],
            addr="10.0.10.1",
            mask=24,
            config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 1"

# Enable host 1 eth1
    LogOutput('info', "################### Enable host 1 interface eth1 #######################")
    retStruct = host1.DeviceInteract(command="ifconfig eth1 up")
    retCode = retStruct['returnCode']
    assert retCode == 0, "Failed to bring up eth1 of host1"

#Get port 1 uuid
    LogOutput('info', "################ Get the port 1 uuid #######################")
    command = "ovs-vsctl get port 1 _uuid"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    port_1_uuid = bufferout.splitlines()

#Get interface 1 uuid
    LogOutput('info', "################ Get the interface 1 uuid #######################")
    command = "ovs-vsctl get interface 1 _uuid"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    interface_1_uuid = bufferout.splitlines()

# From subinterface interface with port1 uuid and add to vrf
    LogOutput('info', "################ Create subinterface interface 1.10 #######################")
    subinterface_command = """ovsdb-client transact '[ "OpenSwitch",
    {
        "op" : "insert",
        "table" : "Interface",
        "row" : {
            "type" : "vlansubint",
            "name" : "1.10",
            "subintf_parent" : [
                "map",
            [
                [
                10,
            [  "uuid", "%s" ]
                ]
                ]
                ],
            "user_config" : [
                "map",
            [
                [
                "admin",
            "up"
                ]
                ]
                ]
        },
        "uuid-name" : "new_iface01"
    },
    {
        "op" : "insert",
        "table" : "Port",
        "row" : {
            "name": "1.10",
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
                [  "uuid", "%s" ],
            [
                "named-uuid",
            "new_port01"
                ]
                ]
                ]
        }
    }
    ]'""" % (interface_1_uuid[1], port_1_uuid[1])

# Create subinterface interface with port1 uuid and add to vrf
    returnStructure = switch.DeviceInteract(command=subinterface_command)

    LogOutput('info', "#################### Configuring ipv4 address 2.2.2.1 on subinterface ###################")
    retStruct = InterfaceIpConfig(
                deviceObj=switch,
                interface='1.10',
                addr="2.2.2.1",
                mask=24,
                config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on subinterface intf"

# Verify vlan creation and bit map using appctl

    LogOutput("info","####################### Check l3 ports bitmap for Vlan 10 #######################")
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000000000000000000002"
    command = \
    "ovs-appctl plugin/debug vlan 10"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to vlan for trunk"
    assert output_subinterface in bufferout,"Bitmap not added to vlan for subinterface"
    LogOutput('info', "Verified: parent port added in vlan trunk and subinterface bitmap")

# Verify knet filter for subinterface
    LogOutput("info", "#################### Check knet_filter_subinterface knet creation ##########################")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')
    assert "knet_filter_subinterface" in buf, 'subinterface filter not created'
    LogOutput('info', "Verified: subinterface knet filter is created")

# Verify knet filter for L3 interface
    LogOutput("info", "#################### Check knet_filter_l3 knet creation ##########################")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')
    assert "knet_filter_l3" in buf, 'l3 interface filter not created'
    LogOutput('info', "Verified: l3 interface knet filter is created")

# Verify knet filter for bridge normal
    LogOutput("info", "#################### Check knet_filter_bridge_normal knet creation ##########################")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')
    assert "knet_filter_bridge_normal" in buf, 'bridge_normal filter not created'
    LogOutput('info', "Verified: bridge_normal knet filter is created")

# Verify knet filter for bpdu
    LogOutput("info", "#################### Check knet_filter_bpdu knet creation ##########################")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')
    assert "knet_filter_bpdu" in buf, 'bpdu filter not created'
    LogOutput('info', "Verified: bpdu knet filter is created")

# Disable the subinterface
    LogOutput("info","####################### Disable the subinterface 1.10 #######################")
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "interface 1.10"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    switch.VtyshShell(enter=False)

# Verify vlan deletion and bit map using appctl

    LogOutput("info","####################### Check Vlan 10 exists #######################")
    output = "VLAN 10 does not exist."
    command = \
    "ovs-appctl plugin/debug vlan 10"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output in bufferout, "Vlan not deleted"
    LogOutput('info', "Verified: subinterface deletion would delete the vlan")

# Enable the subinterface
    LogOutput("info","####################### Enable subinterface 1.10 #######################")
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "interface 1.10"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "no shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    switch.VtyshShell(enter=False)

# Verify vlan creation and bit map using appctl

    LogOutput("info","####################### Check l3 port bitmap for Vlan 10 #######################")
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000000000000000000002"
    command = \
    "ovs-appctl plugin/debug vlan 10"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to vlan for trunk"
    assert output_subinterface in bufferout,"Bitmap not added to vlan for subinterface"
    LogOutput('info', "Verified: parent port added in vlan trunk and subinterface bitmap")

#Shut the parent interface, verify if the bitmap for subinterface changes
    LogOutput("info","####################### Disable parent interface 1 #######################")
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "interface 1"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    switch.VtyshShell(enter=False)

# Verify vlan creation and bit map using appctl

    LogOutput("info","####################### Check bitmap l3 port for vlan 10 #######################")
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000000000000000000000"
    command = \
    "ovs-appctl plugin/debug vlan 10"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to vlan for trunk"
    assert output_subinterface in bufferout,"Bitmap not added to vlan for subinterface"
    LogOutput('info', "Verified:: parent port not a part of any bitmap as the link is down")

#Enable the parent interface, verify if the bitmap for subinterface changes
    LogOutput("info","####################### Enable parent interface 1 #######################")
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "interface 1"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "no shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    switch.VtyshShell(enter=False)

# Verify vlan creation and bit map using appctl

    LogOutput("info","####################### Check bitmap of l3 port #######################")
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000000000000000000002"
    command = \
    "ovs-appctl plugin/debug vlan 10"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to vlan for trunk"
    assert output_subinterface in bufferout,"Bitmap not added to vlan for subinterface"
    LogOutput('info', "Verified: parent port added in vlan trunk and subinterface bitmap")

# Change the vlan associated to the subinterface 1.10
    LogOutput('info', "################ Change vlan for subinterface interface 1.10 from vlan 10 to vlan 30 #######################")
    subinterface_command = """ovsdb-client transact '[ "OpenSwitch",
    {
        "op" : "update",
        "table" : "Interface",
        "where":[["name","==","1.10"]],
        "row" : {
            "subintf_parent" : [
                "map",
            [
                [
                30,
            [  "uuid", "%s" ]
                ]
                ]
                ]
        }
    }
    ]'""" % (interface_1_uuid[1])

# Modify subinterface with new vlan tag 30
    returnStructure = switch.DeviceInteract(command=subinterface_command)

# Verify vlan 10 has been deleted and vlan 30 created with bit map of parent interface using appctl

    LogOutput("info","####################### Check bitmap of l3 port for Vlan 30 #######################")
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000000000000000000002"
    command = \
    "ovs-appctl plugin/debug vlan 30"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to vlan for trunk"
    assert output_subinterface in bufferout,"Bitmap not added to vlan for subinterface"
    LogOutput('info', "Verified: parent port added in vlan trunk and subinterface bitmap")

# Verify vlan 10 has been deleted

    LogOutput("info","####################### Check Vlan 10 exists #######################")
    output = "VLAN 10 does not exist."
    command = \
    "ovs-appctl plugin/debug vlan 10"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output in bufferout, "Vlan not deleted"
    LogOutput('info', "Verified: subinterface deletion would delete the vlan")

#Create vlan 20
    LogOutput("info","####################### Create vlan 20 #######################")
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "vlan 20"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "no shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    switch.VtyshShell(enter=False)

#Associate l2 interface 2 to the vlan 20
    LogOutput("info","####################### Associate interface 2 to vlan 20 #######################")
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "interface 2"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "no routing"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "no shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "vlan access 20"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    switch.VtyshShell(enter=False)

#Associate l2 interface 3 to the vlan 20
    LogOutput("info","####################### Associate interface 3 to vlan 20 #######################")
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "interface 3"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "no routing"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "no shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "vlan access 20"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    switch.VtyshShell(enter=False)

#Create subinterface associated with Vlan 20

    #Get port 1.10 uuid
    LogOutput("info","####################### Create subinterface 1.20 using ovs command #######################")
    command = "ovs-vsctl get port 1.10 _uuid"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    port_110_uuid = bufferout.splitlines()

    subinterface_command = """ovsdb-client transact '[ "OpenSwitch",
    {
        "op" : "insert",
        "table" : "Interface",
        "row" : {
            "type" : "vlansubint",
            "name" : "1.20",
            "subintf_parent" : [
                "map",
            [
                [
                20,
            [  "uuid", "%s" ]
                ]
                ]
                ],
            "user_config" : [
                "map",
            [
                [
                "admin",
            "up"
                ]
                ]
                ]
        },
        "uuid-name" : "new_iface01"
    },
    {
        "op" : "insert",
        "table" : "Port",
        "row" : {
            "name": "1.20",
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
                [  "uuid", "%s" ],
                [  "uuid", "%s" ],
            [
                "named-uuid",
            "new_port01"
                ]
                ]
                ]
        }
    }
    ]'""" % (interface_1_uuid[1], port_1_uuid[1], port_110_uuid[1])

# Create subinterface interface with port1 uuid and add to vrf
    returnStructure = switch.DeviceInteract(command=subinterface_command)

# Verify vlan creation and bit map using appctl

    LogOutput('info', "############################# Check bitmap for all l2 and l3 ports #######################")
    l2_port_bitmap = "configured access ports=" \
                     "0x000000000000000000000000000000000000000000000000000000000000000c"
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000000000000000000002"
    command = \
    "ovs-appctl plugin/debug vlan 20"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to vlan for trunk"
    assert output_subinterface in bufferout,"Bitmap not added to vlan for subinterface"
    assert l2_port_bitmap in bufferout,"Bitmap not added to vlan for access"
    LogOutput('info', "Verified: l2 and l3 port are added in vlan access, trunk and subinterface bitmap")

# Shut the subinterface
    LogOutput("info","####################### Shut the subinterface 1.20 #######################")
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "interface 1.20"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    switch.VtyshShell(enter=False)

# Verify vlan bit map using appctl, only l2 ports should remain

    LogOutput('info', "###################### Check Bitmap for only l2 ports ########################")
    l2_port_bitmap = "configured access ports=" \
                     "0x000000000000000000000000000000000000000000000000000000000000000c"
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000000"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000000000000000000000"
    command = \
    "ovs-appctl plugin/debug vlan 20"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to vlan for trunk"
    assert output_subinterface in bufferout,"Bitmap not added to vlan for subinterface"
    assert l2_port_bitmap in bufferout,"Bitmap not added to vlan for access"
    LogOutput('info', "Verified: only l2 port are added in vlan access bitmap")

# enable the subinterface
    LogOutput("info","####################### Enable subinterface 1.20 #######################")
    returnStructure = switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "interface 1.20"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "no shutdown"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to enable subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    returnStructure = switch.VtyshShell(enter=False)

# Verify vlan creation and bit map using appctl

    LogOutput('info', "######################## Check bitmap for all l2 and l3 ports #######################")
    l2_port_bitmap = "configured access ports=" \
                     "0x000000000000000000000000000000000000000000000000000000000000000c"
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000000000000000000002"
    command = \
    "ovs-appctl plugin/debug vlan 20"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to vlan for trunk"
    assert output_subinterface in bufferout,"Bitmap not added to vlan for subinterface"
    assert l2_port_bitmap in bufferout,"Bitmap not added to vlan for access"
    LogOutput('info', "Verified: l2 and l3 port are added in vlan access, trunk and subinterface bitmap")

#Delete vlan 20
    LogOutput("info","####################### Delete the Vlan #######################")
    switch.VtyshShell(enter=True)
    retStruct = switch.ConfigVtyShell(enter=True)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to enter vtysh config prompt")
        assert(False)
    cmd = "no vlan 20"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to configure subinterface")
        assert(False)
    cmd = "end"
    retStruct = switch.DeviceInteract(command=cmd)
    if retStruct.get('returnCode') != 0:
        LogOutput('error', "Failed to disable subinterface")
        assert(False)
    retStruct = switch.ConfigVtyShell(enter=False)
    if retStruct.returnCode() != 0:
        LogOutput('error', "Failed to exit vtysh config prompt")
        assert(False)
    switch.VtyshShell(enter=False)

# Verify vlan and bit map using appctl, only l3 subinterface bit should be set

    LogOutput("info","####################### Check the vlan exists #######################")
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000000000000000000002"
    command = \
    "ovs-appctl plugin/debug vlan 20"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output_trunk in bufferout,"Bitmap not added to vlan for trunk"
    assert output_subinterface in bufferout,"Bitmap not added to vlan for subinterface"
    LogOutput('info', "Verified: vlan exists as subinterface 1.20 is still enabled")

# Delete the subinterface 1.20
    LogOutput("info","####################### Delete subinterface 1.20 #######################")
    subinterface_command = """ovsdb-client transact '[ "OpenSwitch",
    {
        "op" : "delete",
        "table" : "Port",
        "where":[["name","==","1.20"]]
    },
    {
        "op" : "update",
        "table" : "VRF",
        "where":[["name","==","vrf_default"]],
        "row" : {
            "ports" : [
                "set",
            [
                [  "uuid", "%s" ],
                [  "uuid", "%s" ]
                ]
                ]
        }
    }
    ]'""" % (port_1_uuid[1], port_110_uuid[1])

# Create subinterface interface with port1 uuid and add to vrf
    returnStructure = switch.DeviceInteract(command=subinterface_command)

# Verify vlan deletion and bit map using appctl

    LogOutput("info","####################### Check Vlan 20 exists after deleting subinterface #######################")
    output = "VLAN 20 does not exist."
    command = \
    "ovs-appctl plugin/debug vlan 20"
    returnStructure = switch.DeviceInteract(command=command)
    bufferout = returnStructure.get('buffer')
    assert output in bufferout, "Vlan not deleted"
    LogOutput('info', "Verified: subinterface deletion would delete the vlan")

@pytest.mark.timeout(1000)
class Test_subinterface_creation:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_subinterface_creation.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_subinterface_creation.topoObj = Test_subinterface_creation.testObj.topoObjGet()

    def teardown_class(cls):
        Test_subinterface_creation.topoObj.terminate_nodes()

    def test_subinterface_creation(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        wrkston01Obj = self.topoObj.deviceObjGet(device="wrkston01")
        subinterface_creation(switch=dut01Obj, host1=wrkston01Obj)
