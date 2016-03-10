# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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
def test_switchd_opennsl_plugin_loopback_creation(topology, step):
    sw1 = topology.get('sw1')
    h1 = topology.get('h1')

    assert sw1 is not None
    assert h1 is not None

    # Enabling interfaces
    step("Enabling interface1 on switch")
    sw1p1 = sw1.ports['if01']

    sw1('configure terminal')
    sw1('interface {sw1p1}'.format(**locals()))
    sw1('no shutdown')

    step("Configuring ipv4 address 10.0.10.1 on interface 1")
    sw1('ip add 10.0.10.1/24')
    sw1('end')

    # Get port 1 uuid
    command = "ovs-vsctl get port 1 _uuid"
    bufferout = sw1(command, shell='bash')
    uuid = bufferout.splitlines()
    # print(uuid)

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
]'""" % (uuid[0])

    # print loopback_command

    # Create loopback interface with port1 uuid and add to vrf
    step("Create loopback interface lo:1")
    sw1(loopback_command, shell='bash')

    command = "ovs-vsctl list port lo:1"
    sw1(command, shell='bash')

    step("Configuring ipv4 address 2.2.2.1 on loopback interface")
    sw1('configure terminal')
    sw1('interface lo:1')
    sw1('ip add 2.2.2.1/24')
    sw1('end')

    # Configure host1
    h1("ifconfig eth1 up")

    step("\n\n\nConfiguring IPv4 address on host1 on eth1")
    h1.libs.ip.interface('if01', addr='10.0.10.2/24', up=True)

    # Configure a default IPv4 route
    step("Configuring default route for IPv4 on host1")
    h1("ip -4 route add default via 10.0.10.1")

    # TEST: IPv4 ping from host1 to interface 1 ip
    step("\n\n\nTEST: IPv4 ping from host1 to interface 1")
    out = h1.libs.ping.ping(1, "10.0.10.1")
    assert out['transmitted'] == out['received']

    # TEST: IPv4 ping from host1 to loopback interface ip
    step("\n\n\nTEST: IPv4 ping from host1 to loopback interface")
    out = h1.libs.ping.ping(1, "2.2.2.1")
    assert out['transmitted'] == out['received']

    # Delete loopback interface
    step("Deleting loopback interface lo:1")
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
]'""" % (uuid[0])
    # print loopback_command

    sw1(loopback_command, shell='bash')

    # TEST: IPv4 ping from host1 to loopback interface ip
    step("\n\n\nTEST: IPv4 ping from host1 to loopback interface")
    out = h1.libs.ping.ping(1, "2.2.2.1")
    assert out['transmitted'] != out['received']
