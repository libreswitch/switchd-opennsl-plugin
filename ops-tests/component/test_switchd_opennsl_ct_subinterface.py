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

from time import sleep
from pytest import mark

TOPOLOGY = """
#
# +-------+
# |       |     +-------+
# |  hs1  <----->  sw1  |
# |       |     +-------+
# +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host name="host 1"] h1

# Links
sw1:if01 -- h1:if01

"""


@mark.platform_incompatible(['docker'])
def test_switchd_opennsl_plugin_subinterface_creation(topology, step):
    sw1 = topology.get('sw1')
    h1 = topology.get('h1')

    assert sw1 is not None
    assert h1 is not None

    sw1p1 = sw1.ports['if01']
    h1p1 = h1.ports['if01']

    # Enabling interfaces 1
    step("Enabling interface 1 on switch")
    sw1('configure terminal')
    sw1('interface {sw1p1}'.format(**locals()))
    sw1('no shutdown')

    step("### Configuring ipv4 address 10.0.10.1 on interface {sw1p1}"
         "###".format(**locals()))
    sw1('ip add 10.0.10.1/24')
    sw1('end')

    # Enable host 1 eth1
    step("### Enable host 1 interface eth1 ###")
    h1.libs.ip.interface('if01', up=True)

    # Get port 1 uuid
    step("### Get the port {sw1p1} uuid ###".format(**locals()))
    command = "ovs-vsctl get port {sw1p1} _uuid".format(**locals())
    bufferout = sw1(command, shell='bash')
    port_1_uuid = bufferout.splitlines()

    # Get interface 1 uuid
    step("### Get the interface {sw1p1} uuid ###".format(**locals()))
    command = "ovs-vsctl get interface {sw1p1} _uuid".format(**locals())
    bufferout = sw1(command, shell='bash')
    interface_1_uuid = bufferout.splitlines()

    # From subinterface interface with port1 uuid and add to vrf
    step("### Create subinterface interface 1.10 ###")
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
    ]'""" % (interface_1_uuid[0], port_1_uuid[0])

    # Create subinterface interface with port1 uuid and add to vrf
    sw1(subinterface_command, shell='bash')

    step("### Configuring ipv4 address 2.2.2.1 on subinterface ###")
    sw1('configure terminal')
    sw1('interface 1.10')
    sw1('ip address 2.2.2.1/24')
    sw1('end')

    # Verify vlan creation and bit map using appctl
    step("### Check l3 ports bitmap for Vlan 10 ###")
    output_trunk = "installed trunk ports=" \
                   "0x00000000000000000000000000000000000000000000000" \
                   "00000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000" \
                          "000000000000000000000002"
    command = "ovs-appctl plugin/debug vlan 10"
    bufferout = sw1(command, shell='bash')
    assert output_trunk in bufferout
    assert output_subinterface in bufferout

    # Verify knet filter for subinterface
    step("### Check knet_filter_subinterface knet creation ###")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    buf = sw1(appctl_command, shell='bash')
    assert "knet_filter_subinterface" in buf

    # Verify knet filter for L3 interface
    step("### Check knet_filter_l3 knet creation ###")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    buf = sw1(appctl_command, shell='bash')
    assert "knet_filter_l3" in buf

    # Verify knet filter for bridge normal
    step("### Check knet_filter_bridge_normal knet creation ###")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    buf = sw1(appctl_command, shell='bash')
    assert "knet_filter_bridge_normal" in buf

    # Verify knet filter for bpdu
    step("### Check knet_filter_bpdu knet creation ###")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    buf = sw1(appctl_command, shell='bash')
    assert "knet_filter_bpdu" in buf

    # Disable the subinterface
    step("### Disable the subinterface 1.10 ###")
    sw1('configure terminal')
    sw1('interface 1.10')
    sw1('shutdown')
    sw1('end')

    # Verify vlan deletion and bit map using appctl
    step("### Check Vlan 10 exists ###")
    output = "VLAN 10 does not exist."
    command = "ovs-appctl plugin/debug vlan 10"
    bufferout = sw1(command, shell='bash')
    assert output in bufferout

    # Enable the subinterface
    step("### Enable subinterface 1.10 ###")
    sw1('configure terminal')
    sw1('interface 1.10')
    sw1('no shutdown')
    sw1('end')

    # Verify vlan creation and bit map using appctl
    step("### Check l3 port bitmap for Vlan 10 ###")
    output_trunk = "installed trunk ports=" \
                   "0x00000000000000000000000000000000000000" \
                   "00000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x00000000000000000000000000000000" \
                          "00000000000000000000000000000002"
    command = "ovs-appctl plugin/debug vlan 10"
    bufferout = sw1(command, shell='bash')
    assert output_trunk in bufferout
    assert output_subinterface in bufferout

    # Shut the parent interface, verify if the bitmap for subinterface changes
    step("### Disable parent interface 1 ###")
    sw1('configure terminal')
    sw1('interface 1')
    sw1('shutdown')
    sw1('end')

    # Verify vlan creation and bit map using appctl
    step("### Check bitmap l3 port for vlan 10 ###")
    output_trunk = "installed trunk ports=" \
                   "0x00000000000000000000000000000000000000000000" \
                   "00000000000000000000"
    output_subinterface = "installed subinterface ports=" \
                          "0x000000000000000000000000000000000000000" \
                          "0000000000000000000000000"
    command = "ovs-appctl plugin/debug vlan 10"
    bufferout = sw1(command, shell='bash')
    assert output_trunk in bufferout
    assert output_subinterface in bufferout

    # Enable the parent interface, verify if the bitmap for
    # subinterface changes
    step("### Enable parent interface 1 ###")
    sw1('configure terminal')
    sw1('interface 1')
    sw1('no shutdown')
    sw1('end')

    # Verify vlan creation and bit map using appctl
    step("### Check bitmap of l3 port ###")
    output_trunk = "installed trunk ports=" \
                   "0x00000000000000000000000000000000000000000" \
                   "00000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x00000000000000000000000000000000000" \
                          "00000000000000000000000000002"
    command = "ovs-appctl plugin/debug vlan 10"
    sleep(5)
    bufferout = sw1(command, shell='bash')
    assert output_trunk in bufferout
    assert output_subinterface in bufferout

    # Change the vlan associated to the subinterface 1.10
    step("### Change vlan for subinterface interface 1.10 from vlan"
         "10 to vlan 30 ###")
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
    ]'""" % (interface_1_uuid[0])

    # Modify subinterface with new vlan tag 30
    sw1(subinterface_command, shell='bash')

    # Verify vlan 10 has been deleted and vlan 30 created with bit map
    # of parent interface using appctl
    step("### Check bitmap of l3 port for Vlan 30 ###")
    output_trunk = "installed trunk ports=" \
                   "0x0000000000000000000000000000000000000000" \
                   "000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x000000000000000000000000000000000" \
                          "0000000000000000000000000000002"
    command = "ovs-appctl plugin/debug vlan 30"
    sleep(5)
    bufferout = sw1(command, shell='bash')
    assert output_trunk in bufferout
    assert output_subinterface in bufferout

    # Verify vlan 10 has been deleted
    step("### Check Vlan 10 exists ###")
    output = "VLAN 10 does not exist."
    command = "ovs-appctl plugin/debug vlan 10"
    bufferout = sw1(command, shell='bash')
    assert output in bufferout

    # Create vlan 20
    step("### Create vlan 20 ###")
    sw1('configure terminal')
    sw1('vlan 20')
    sw1('no shutdown')

    # Associate l2 interface 2 to the vlan 20
    step("### Associate interface 2 to vlan 20 ###")
    sw1('interface 2')
    sw1('no routing')
    sw1('no shutdown')
    sw1('vlan access 20')

    # Associate l2 interface 3 to the vlan 20
    step("### Associate interface 3 to vlan 20 ###")
    sw1('interface 3')
    sw1('no routing')
    sw1('no shutdown')
    sw1('vlan access 20')
    sw1('end')

    # Create subinterface associated with Vlan 20
    # Get port 1.10 uuid
    step("### Create subinterface 1.20 using ovs command ###")
    command = "ovs-vsctl get port 1.10 _uuid"
    bufferout = sw1(command, shell='bash')
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
    ]'""" % (interface_1_uuid[0], port_1_uuid[0], port_110_uuid[0])

    # Create subinterface interface with port1 uuid and add to vrf
    sw1(subinterface_command, shell='bash')

    # Verify vlan creation and bit map using appctl
    step("### Check bitmap for all l2 and l3 ports ###")
    l2_port_bitmap = "configured access ports=" \
                     "0x0000000000000000000000000000000000000000000" \
                     "00000000000000000000c"
    output_trunk = "installed trunk ports=" \
                   "0x000000000000000000000000000000000000000000000" \
                   "0000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x000000000000000000000000000000000000000" \
                          "0000000000000000000000002"
    command = "ovs-appctl plugin/debug vlan 20"
    bufferout = sw1(command, shell='bash')
    assert output_trunk in bufferout
    assert output_subinterface in bufferout
    assert l2_port_bitmap in bufferout

    # Shut the subinterface
    step("### Shut the subinterface 1.20 ###")
    sw1('configure terminal')
    sw1('interface 1.20')
    sw1('shutdown')
    sw1('end')

    # Verify vlan bit map using appctl, only l2 ports should remain
    step("### Check Bitmap for only l2 ports ###")
    l2_port_bitmap = "configured access ports=" \
                     "0x0000000000000000000000000000000000000000000000000" \
                     "00000000000000c"
    output_trunk = "installed trunk ports=" \
                   "0x000000000000000000000000000000000000000000000000000" \
                   "0000000000000"
    output_subinterface = "installed subinterface ports=" \
                          "0x00000000000000000000000000000000000000000000" \
                          "00000000000000000000"
    command = "ovs-appctl plugin/debug vlan 20"
    bufferout = sw1(command, shell='bash')
    assert output_trunk in bufferout
    assert output_subinterface in bufferout
    assert l2_port_bitmap in bufferout

    # enable the subinterface
    step("### Enable subinterface 1.20 ###")
    sw1('configure terminal')
    sw1('interface 1.20')
    sw1('no shutdown')
    sw1('end')

    # Verify vlan creation and bit map using appctl
    step("### Check bitmap for all l2 and l3 ports ###")
    l2_port_bitmap = "configured access ports=" \
                     "0x0000000000000000000000000000000000000000000000000000" \
                     "00000000000c"
    output_trunk = "installed trunk ports=" \
                   "0x000000000000000000000000000000000000000000000000000000" \
                   "0000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x0000000000000000000000000000000000000000000000" \
                          "000000000000000002"
    command = "ovs-appctl plugin/debug vlan 20"
    bufferout = sw1(command, shell='bash')
    assert output_trunk in bufferout
    assert output_subinterface in bufferout
    assert l2_port_bitmap in bufferout

    # Delete vlan 20
    step("### Delete the Vlan ###")
    sw1('configure terminal')
    sw1('no vlan 20')
    sw1('end')

    # Verify vlan and bit map using appctl, only l3 subinterface
    # bit should be set
    step("### Check the vlan exists ###")
    output_trunk = "installed trunk ports=" \
                   "0x000000000000000000000000000000000000000" \
                   "0000000000000000000000002"
    output_subinterface = "installed subinterface ports=" \
                          "0x00000000000000000000000000000000" \
                          "00000000000000000000000000000002"
    command = "ovs-appctl plugin/debug vlan 20"
    bufferout = sw1(command, shell='bash')
    assert output_trunk in bufferout
    assert output_subinterface in bufferout

    # Delete the subinterface 1.20
    step("### Delete subinterface 1.20 ###")
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
    ]'""" % (port_1_uuid[0], port_110_uuid[0])

    # Create subinterface interface with port1 uuid and add to vrf
    sw1(subinterface_command, shell='bash')

    # Verify vlan deletion and bit map using appctl
    step("### Check Vlan 20 exists after deleting subinterface ###")
    output = "VLAN 20 does not exist."
    command = "ovs-appctl plugin/debug vlan 20"
    bufferout = sw1(command, shell='bash')
    assert output in bufferout
