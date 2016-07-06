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

from time import sleep
from pytest import mark
import re

TOPOLOGY = """
#
# +-------+     +-------+
# |  sw1  <----->  sw2  |
# +-------+     +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=openswitch name="Switch 2"] sw2

# Links
sw1:if01 -- sw2:if01
sw1:if02 -- sw2:if02

"""


def get_bitcount(port):
    result = re.match(r'\d+-+\d+', port, re.DOTALL)
    if result:
        intf = port.split('-')
        bit_count = (int(intf[0]) - 1) * 4 + int(intf[1])
        print(bit_count)
    else:
        bit_count = int(port)
    return bit_count


def create_bitmap(port):
    bitmap = 0x1 << get_bitcount(port)
    return bitmap


def verify_lag_membership(sw1):
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
    vlan_id = "1024"
    test_lag_id = 100
    sw1p1 = sw1.ports['if01']
    sw1p2 = sw1.ports['if02']
    ###########################################################################
    #                                                                         #
    #                   [Switch1] ------- LAG -------> [Switch2]              #
    #                                                                         #
    ###########################################################################

    # Verifing Switch 1
    # Verify the bitmap changes for LAG

    print("Check l3 ports bitmap update for LAG100")
    bitmap = create_bitmap(sw1p1)
    print(hex(bitmap))
    bitmap |= create_bitmap(sw1p2)
    print(hex(bitmap))
    final_bitmap = "0x""{0:064X}".format(bitmap)
    print(final_bitmap)
    enable_ports = "Egress enabled ports=" + final_bitmap
    output_trunk = "installed native untagged ports=" + final_bitmap
    sleep(4)
    created_hw_output = "hw_created=1"

    command = "ovs-appctl plugin/debug lag"
    bufferout = sw1(command, shell='bash')

    assert enable_ports in bufferout
    assert created_hw_output in bufferout

    # Verify vlan creation and bit map using appctl
    print("Check l3 ports bitmap for Vlan %s" % vlan_id)
    command = "ovs-appctl plugin/debug vlan " + vlan_id
    bufferout = sw1(command, shell='bash')

    assert output_trunk in bufferout

    # Verify knet filter for L3 interface
    print("Check knet_filter_l3 knet creation")
    appctl_command = "ovs-appctl plugin/debug knet filter"
    buf = sw1(appctl_command, shell='bash')
    output = "knet_filter_l3_" + vlan_id
    interface1 = get_bitcount(sw1p1)
    interface2 = get_bitcount(sw1p2)
    output_int1 = "ingport=" + str(interface1)
    output_int2 = "ingport=" + str(interface2)

    assert output in buf
    print("Verified: l3 interface knet filter is created")
    assert output_int1 in buf
    print('info', "Verified: l3 interface knet filter is created for port 1")
    assert output_int2 in buf
    print('info', "Verified: l3 interface knet filter is created for port 2")

    # Disable interface 1
    print('Disabling interface {sw1p1} on device'.format(**locals()))
    sw1('configure terminal')
    sw1("interface {sw1p1}".format(**locals()))
    sw1("shutdown")
    sw1('end')
    bitmap &= ~create_bitmap(sw1p1)
    print(hex(bitmap))
    final_bitmap = "0x""{0:064X}".format(bitmap)
    print(final_bitmap)
    output_trunk = "installed native untagged ports=" + final_bitmap
    enable_ports = "Egress enabled ports=" + final_bitmap

    # Waiting for interfaces to go down
    sleep(2)

    # Verify the bitmap changes for internal vlan
    print("Check l3 ports bitmap update for Vlan %s" % vlan_id)
    command = "ovs-appctl plugin/debug vlan " + vlan_id
    bufferout = sw1(command, shell='bash')

    assert output_trunk in bufferout
    print("Verified: ports updated in vlan bitmap for lag")

    # Verify the bitmap changes for LAG
    print("Check l3 ports bitmap update for LAG100")

    created_hw_output = "hw_created=1"

    command = "ovs-appctl plugin/debug lag"
    bufferout = sw1(command, shell='bash')

    assert enable_ports in bufferout
    assert created_hw_output in bufferout
    print("Verified: LAG created and disable port is deleted in bitmap for"
          " lag")

    # Disable interface 2
    print('Disabling interface {sw1p2} on device'.format(**locals()))
    sw1('configure terminal')
    sw1("interface {sw1p2}".format(**locals()))
    sw1("shutdown")
    sw1('end')
    bitmap &= ~create_bitmap(sw1p2)
    print(hex(bitmap))
    final_bitmap = "0x""{0:064X}".format(bitmap)
    print(final_bitmap)
    output_trunk = "installed native untagged ports=" + final_bitmap
    enable_ports = "Egress enabled ports=" + final_bitmap

    # Waiting for interfaces to go down
    sleep(2)

    # Verify the bitmap changes for internal vlan
    print("Check l3 ports bitmap update for Vlan %s" % vlan_id)
    vlan_creation_output = "VLAN " + vlan_id + " does not exist."

    command = "ovs-appctl plugin/debug vlan " + vlan_id
    bufferout = sw1(command, shell='bash')

    assert vlan_creation_output in bufferout
    print("Verified: Vlan deleted once all members of the LAG are down")

    # Verify the bitmap changes for LAG
    print("Check l3 ports bitmap update for LAG100")
    created_hw_output = "hw_created=1"

    command = "ovs-appctl plugin/debug lag"
    bufferout = sw1(command, shell='bash')

    assert enable_ports in bufferout
    assert created_hw_output in bufferout
    print("Verified: LAG is not destroyed and ports are deleted in "
          "bitmap for lag")
    print("Verified: As the member ports are disabled the LAG is "
          "not destroyed")

    # Enable interface 1
    print('Enabling interface {sw1p1} on device'.format(**locals()))
    sw1('configure terminal')
    sw1("interface {sw1p1}".format(**locals()))
    sw1("no shutdown")
    bitmap = create_bitmap(sw1p1)
    print(hex(bitmap))

    # Enable interface 2
    print('Enabling interface {sw1p2} on device'.format(**locals()))
    sw1("interface {sw1p2}".format(**locals()))
    sw1("no shutdown")
    sw1('end')
    bitmap |= create_bitmap(sw1p2)
    print(hex(bitmap))
    final_bitmap = "0x""{0:064X}".format(bitmap)
    print(final_bitmap)
    output_trunk = "installed native untagged ports=" + final_bitmap

    # Waiting for interfaces to come up
    sleep(5)

    # Verify vlan creation and bit map using appctl
    print("Check l3 ports bitmap for Vlan %s" % vlan_id)
    command = "ovs-appctl plugin/debug vlan " + vlan_id
    bufferout = sw1(command, shell='bash')

    assert output_trunk in bufferout
    print("Verified: ports added in vlan bitmap for lag")

    # Remove interface 1 from LAG
    print('Remove interface {sw1p1} from LAG %s'.format(**locals())
          % test_lag_id)
    sw1('configure terminal')
    sw1("interface {sw1p1}".format(**locals()))
    sw1('no lag %s' % test_lag_id)
    sw1('end')
    bitmap &= ~create_bitmap(sw1p1)
    print(hex(bitmap))
    final_bitmap = "0x""{0:064X}".format(bitmap)
    print(final_bitmap)
    output_trunk = "installed native untagged ports=" + final_bitmap
    enable_ports = "Egress enabled ports=" + final_bitmap

    # Verify the bitmap changes for internal vlan
    print("Check l3 ports bitmap update for Vlan %s" % vlan_id)
    command = "ovs-appctl plugin/debug vlan " + vlan_id
    bufferout = sw1(command, shell='bash')

    assert output_trunk in bufferout
    print("Verified: ports added in vlan bitmap for lag")

    # Verify the bitmap changes for LAG
    print("Check l3 ports bitmap update for LAG100")
    created_hw_output = "hw_created=1"

    command = "ovs-appctl plugin/debug lag"
    bufferout = sw1(command, shell='bash')

    assert enable_ports in bufferout
    assert created_hw_output in bufferout
    print("Verified: LAG created and ports deleted in bitmap for lag")

    # Remove interface 2 from LAG
    print('Remove interface {sw1p2} from LAG %s'.format(**locals())
          % test_lag_id)
    sw1('configure terminal')
    sw1("interface {sw1p2}".format(**locals()))
    sw1('no lag %s' % test_lag_id)
    sw1('end')
    bitmap &= ~create_bitmap(sw1p2)
    print(hex(bitmap))
    final_bitmap = "0x""{0:064X}".format(bitmap)
    print(final_bitmap)
    enable_ports = "Egress enabled ports=" + final_bitmap

    # Verify the bitmap changes for internal vlan
    print("Check l3 ports bitmap update for Vlan %s" % vlan_id)
    vlan_creation_output = "VLAN %s does not exist." % vlan_id

    command = "ovs-appctl plugin/debug vlan " + vlan_id
    bufferout = sw1(command, shell='bash')

    assert vlan_creation_output in bufferout
    print("Verified: Vlan deleted once all members of the LAG are down")

    # Verify the bitmap changes for LAG
    print("Check l3 ports bitmap update for LAG100")
    created_hw_output = "hw_created=1"

    command = "ovs-appctl plugin/debug lag"
    bufferout = sw1(command, shell='bash')

    assert enable_ports not in bufferout
    assert created_hw_output not in bufferout
    print("Verified: LAG is destroyed and ports are deleted in bitmap for lag")
    print("Verified: As the member ports are removed from the LAG it is"
          " destroyed")


@mark.platform_incompatible(['docker'])
def test_switchd_opennsl_plugin_verify_lag_l3_membership(topology, step):
    """Test Configuration Class for Fastpath Ping.

    Topology:
        - Switch 1
        - Switch 2

    Test Cases:
        - test_fastpath_ping
    """

    sw1 = topology.get('sw1')
    sw2 = topology.get('sw2')

    assert sw1 is not None
    assert sw2 is not None

    sw1p1 = sw1.ports['if01']
    sw1p2 = sw1.ports['if02']
    sw2p1 = sw2.ports['if01']
    sw2p2 = sw2.ports['if02']
    test_lag_id = 100

    ######################################################################
    # Configuration switch 1
    ######################################################################

    # Create LAG 100
    step('Creating LAG %s on switch 1' % test_lag_id)
    sw1('configure terminal')
    sw1('interface lag %s' % test_lag_id)
    sw1('end')

    # Enable interface 1
    print('Enabling interface {sw1p1} on device'.format(**locals()))
    sw1('configure terminal')
    sw1('interface {sw1p1}'.format(**locals()))
    sw1('no shutdown')

    # Enable interface 2
    print('Enabling interface {sw1p2} on device'.format(**locals()))
    sw1('interface {sw1p2}'.format(**locals()))
    sw1('no shutdown')

    # Configure LAG to interface 1
    print('Configuring LAG %s to interface {sw1p1}'.format(**locals())
          % test_lag_id)
    sw1('interface {sw1p1}'.format(**locals()))
    sw1('lag %s' % test_lag_id)

    # Configure LAG to interface 2
    print('Configuring LAG %s to interface {sw1p2}'.format(**locals())
          % test_lag_id)
    sw1('interface {sw1p2}'.format(**locals()))
    sw1('lag %s' % test_lag_id)
    sw1('end')

    ######################################################################
    # Configuration switch 2
    ######################################################################

    # Create LAG 100
    print('Creating LAG %s on switch 2' % test_lag_id)
    sw2('configure terminal')
    sw2('interface lag %s' % test_lag_id)
    sw2('end')

    # Enable interface 1
    print('Enabling interface {sw2p1} on device'.format(**locals()))
    sw2('configure terminal')
    sw2('interface {sw2p1}'.format(**locals()))
    sw2('no shutdown')

    # Enable interface 2
    print('Enabling interface {sw2p2} on device'.format(**locals()))
    sw2('interface {sw2p2}'.format(**locals()))
    sw2('no shutdown')

    # Configure LAG to interface 1
    print('Configuring LAG %s to interface {sw2p1}'.format(**locals())
          % test_lag_id)
    sw2('interface {sw2p1}'.format(**locals()))
    sw2('lag %s' % test_lag_id)

    # Configure LAG to interface 2
    print('Configuring LAG %s to interface {sw2p2}'.format(**locals())
          % test_lag_id)
    sw2('interface {sw2p2}'.format(**locals()))
    sw2('lag %s' % test_lag_id)
    sw2('end')

    verify_lag_membership(sw1)
