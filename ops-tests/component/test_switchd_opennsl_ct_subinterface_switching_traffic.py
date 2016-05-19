# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

##########################################################################
# Name:        test_switchd_opennsl_ct_subinterface_switching_traffic.py
#
# Objective:   To verify that subinterface FP entry is installed correctly.
#
# Topology:    1 switch connected by 2 interface to 2 hosts
#
##########################################################################

"""
OpenSwitch Tests for subinterface route test using hosts
"""

from pytest import mark
import re

TOPOLOGY = """
#
# +-------+
# |  sw1  |
# +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1

"""


def calculate_bitmap(port):
    bit_count = int(port)
    bitmap = 0x1 << bit_count
    return bitmap


def check_pattern(pattern, bufferout):
    lines = bufferout.split('\n')
    match = None
    for line in lines:
        match = re.match(pattern, line)
        if match is not None:
            return True
    return match


def configure_subinterface(sw, interface, ip_addr, vlan):
    with sw.libs.vtysh.ConfigSubinterface(interface, vlan) as ctx:
        ctx.no_shutdown()
        ctx.ip_address(ip_addr)
        ctx.encapsulation_dot1_q(vlan)


def delete_subinterface(sw, interface, vlan):
    with sw.libs.vtysh.Configure() as ctx:
        ctx.no_interface(interface, vlan)


@mark.platform_incompatible(['docker'])
def test_subinterface_switching(topology):
    """Test description.

    Topology:

        [s1]

    Objective:
        Test if subinterface creation installs an FP which
        drops all packets, if destination mac does not match interface mac.

    Cases:
        - Execute appctl command.
    """
    sw1 = topology.get('sw1')

    assert sw1 is not None

    port = '1'
    sw1_subinterface1_ip = '1.1.1.1'
    sw1_subinterface2_ip = '2.2.2.2'
    sw1_subinterface3_ip = '3.3.3.3'
    mask = '/24'

    with sw1.libs.vtysh.ConfigInterface(port) as ctx:
        ctx.no_shutdown()

    print("Create subinterface")
    configure_subinterface(sw1, port,
                           sw1_subinterface1_ip + mask,
                           '10')

    bitmap = calculate_bitmap(port)
    final_bitmap = "0x""{0:064X}".format(bitmap)
    bitmap_pattern = "(.*)Inports(.*)-(.*)%s" % (final_bitmap)
    mystation_pattern = "(.*)MyStationHit(.*)-(.*)NOT HIT"
    action_pattern = "(.*)Action(.*)-(.*)DROP"
    command = "ovs-appctl plugin/debug fp l3-subinterface"
    bufferout = sw1(command, shell='bash')
    inports_match = check_pattern(bitmap_pattern, bufferout)
    mystationhit_match = check_pattern(mystation_pattern, bufferout)
    action_match = check_pattern(action_pattern, bufferout)
    assert inports_match is not None and\
        mystationhit_match is not None and\
        action_match is not None,\
        'No FP entry created for subinterface'

    print("Create subinterface")
    configure_subinterface(sw1, port,
                           sw1_subinterface2_ip + mask,
                           '20')

    bitmap |= calculate_bitmap(port)
    final_bitmap = "0x""{0:064X}".format(bitmap)
    bitmap_pattern = "(.*)Inports(.*)-(.*)%s" % (final_bitmap)
    mystation_pattern = "(.*)MyStationHit(.*)-(.*)NOT HIT"
    action_pattern = "(.*)Action(.*)-(.*)DROP"
    command = "ovs-appctl plugin/debug fp l3-subinterface"
    bufferout = sw1(command, shell='bash')
    inports_match = check_pattern(bitmap_pattern, bufferout)
    mystationhit_match = check_pattern(mystation_pattern, bufferout)
    action_match = check_pattern(action_pattern, bufferout)
    assert inports_match is not None and\
        mystationhit_match is not None and\
        action_match is not None,\
        'No FP entry created for subinterface'

    with sw1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.no_shutdown()

    print("Create subinterface")
    configure_subinterface(sw1, '2',
                           sw1_subinterface3_ip + mask,
                           '30')

    bitmap |= calculate_bitmap('2')
    final_bitmap = "0x""{0:064X}".format(bitmap)
    bitmap_pattern = "(.*)Inports(.*)-(.*)%s" % (final_bitmap)
    mystation_pattern = "(.*)MyStationHit(.*)-(.*)NOT HIT"
    action_pattern = "(.*)Action(.*)-(.*)DROP"
    command = "ovs-appctl plugin/debug fp l3-subinterface"
    bufferout = sw1(command, shell='bash')
    inports_match = check_pattern(bitmap_pattern, bufferout)
    mystationhit_match = check_pattern(mystation_pattern, bufferout)
    action_match = check_pattern(action_pattern, bufferout)
    assert inports_match is not None and\
        mystationhit_match is not None and\
        action_match is not None,\
        'No FP entry created for subinterface'

    print("Delete subinterface 2.30")
    delete_subinterface(sw1, '2', '30')

    bitmap &= ~calculate_bitmap('2')
    final_bitmap = "0x""{0:064X}".format(bitmap)
    bitmap_pattern = "(.*)Inports(.*)-(.*)%s" % (final_bitmap)
    mystation_pattern = "(.*)MyStationHit(.*)-(.*)NOT HIT"
    action_pattern = "(.*)Action(.*)-(.*)DROP"
    command = "ovs-appctl plugin/debug fp l3-subinterface"
    bufferout = sw1(command, shell='bash')
    inports_match = check_pattern(bitmap_pattern, bufferout)
    mystationhit_match = check_pattern(mystation_pattern, bufferout)
    action_match = check_pattern(action_pattern, bufferout)
    assert inports_match is not None and\
        mystationhit_match is not None and\
        action_match is not None,\
        'No FP entry created for subinterface'

    print("Delete subinterface 1.10")
    delete_subinterface(sw1, '1', '10')

    bitmap = calculate_bitmap('1')
    final_bitmap = "0x""{0:064X}".format(bitmap)
    bitmap_pattern = "(.*)Inports(.*)-(.*)%s" % (final_bitmap)
    mystation_pattern = "(.*)MyStationHit(.*)-(.*)NOT HIT"
    action_pattern = "(.*)Action(.*)-(.*)DROP"
    command = "ovs-appctl plugin/debug fp l3-subinterface"
    bufferout = sw1(command, shell='bash')
    inports_match = check_pattern(bitmap_pattern, bufferout)
    mystationhit_match = check_pattern(mystation_pattern, bufferout)
    action_match = check_pattern(action_pattern, bufferout)
    assert inports_match is not None and\
        mystationhit_match is not None and\
        action_match is not None,\
        'No FP entry created for subinterface'

    print("Delete subinterface 1.20")
    delete_subinterface(sw1, '1', '20')

    bitmap &= ~calculate_bitmap('1')
    final_bitmap = "0x""{0:064X}".format(bitmap)
    bitmap_pattern = "(.*)Inports(.*)-(.*)%s" % (final_bitmap)
    mystation_pattern = "(.*)MyStationHit(.*)-(.*)NOT HIT"
    action_pattern = "(.*)Action(.*)-(.*)DROP"
    command = "ovs-appctl plugin/debug fp l3-subinterface"
    bufferout = sw1(command, shell='bash')
    inports_match = check_pattern(bitmap_pattern, bufferout)
    mystationhit_match = check_pattern(mystation_pattern, bufferout)
    action_match = check_pattern(action_pattern, bufferout)
    assert inports_match is None and\
        mystationhit_match is None and\
        action_match is None,\
        'No FP entry created for subinterface'
