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

from time import sleep
from pytest import mark

TOPOLOGY = """
#                   |-------------------|
# +-------+         |        +-------+  |  +-------+
# |       |     +---v---+    |       |  |  |       |
# |  hs1  <----->  sw1  <---->  hs2  |  |-->  hs3  |
# |       |     +-------+    |       |     |       |
# +-------+                  +-------+     +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host name="host 1"] h1
[type=host name="host 2"] h2
[type=host name="host 3"] h3

# Links
sw1:if01 -- h1:if01
sw1:if02 -- h2:if01
sw1:if03 -- h3:if01
"""


@mark.platform_incompatible(['docker'])
def test_switchd_opennsl_plugin_mac_move(topology, step):
    sw1 = topology.get('sw1')
    h1 = topology.get('h1')
    h2 = topology.get('h2')
    h3 = topology.get('h3')

    assert sw1 is not None
    assert h1 is not None
    assert h2 is not None
    assert h3 is not None

    sw1p1 = sw1.ports['if01']
    sw1p2 = sw1.ports['if02']
    sw1p3 = sw1.ports['if03']
    h1p1 = h1.ports['if01']
    h2p1 = h2.ports['if01']
    h3p1 = h3.ports['if01']

    # Enabling interfaces
    step("Enabling interface1 on switch")
    sw1('configure terminal')
    sw1('interface {sw1p1}'.format(**locals()))
    sw1('no shutdown')

    # Create interface2 but put it in shut state so that MAC's are not learnt
    # on it.
    step("Create interface2, but in 'shutdown' state")
    sw1('interface {sw1p2}'.format(**locals()))

    step("Enabling interface3 on switch")
    sw1('interface {sw1p3}'.format(**locals()))
    sw1('no shutdown')

    step("Enabling interface vlan 10 on switch")
    sw1('interface vlan 10')
    sw1('no shutdown')

    step("Enabling interface vlan 20 on switch")
    sw1('interface vlan 20')
    sw1('no shutdown')

    step("Configuring vlan 10")
    sw1('vlan 10')
    sw1('no shutdown')

    step("Configuring vlan 20")
    sw1('vlan 20')
    sw1('no shutdown')

    # Add interface 1 to vlan 10
    step("Configuring interface {sw1p1} to vlan 10".format(**locals()))
    sw1('interface {sw1p1}'.format(**locals()))
    sw1('no routing')
    sw1('no shutdown')
    sw1('vlan access 10')

    # Add interface 2 to vlan 10
    step("Configuring interface {sw1p2} to vlan 10".format(**locals()))
    sw1('interface {sw1p2}'.format(**locals()))
    sw1('no routing')
    sw1('vlan access 10')

    # Add interface 3 to vlan 20
    step("Configuring interface {sw1p3} to vlan 20".format(**locals()))
    sw1('interface {sw1p3}'.format(**locals()))
    sw1('no routing')
    sw1('no shutdown')
    sw1('vlan access 20')

    step("Configuring ipv4 address 10.0.0.1 on interface vlan10")
    sw1('interface vlan 10')
    sw1('ip address 10.0.0.1/24')

    step("Configuring ipv6 address 1000::1 on interface vlan10")
    sw1('ipv6 address 1000::1/120')

    step("Configuring ipv4 address 11.0.0.1 on interface vlan20")
    sw1('interface vlan 20')
    sw1('ip address 11.0.0.1/24')

    step("Configuring ipv6 address 2000::1 on interface vlan20")
    sw1('ipv6 address 2000::1/120')

    out = sw1("do show run")
    assert "vlan 10" and "no shutdown" and "vlan 20" and "interface vlan10" \
        and "ip address 10.0.0.1/24" and "ipv6 address 1000::1/120" and \
        "interface vlan20" and "ip address 11.0.0.1/24" \
        and "ipv6 address 2000::1/120" \
        and "vlan access 10" and "vlan access 20" and "no routing" in out

    # Configure host1
    # Reprogram mac-addr on host1 and host2 to be same, simulating mac-move.
    h1.libs.ip.interface('if01', up=False)

    h1("ip link set dev {h1p1} addr 00:01:02:03:04:05".format(**locals()))

    h1.libs.ip.interface('if01', up=True)

    step("\n\n\nConfiguring IPv4 address on host1 on eth1")
    h1.libs.ip.interface('if01', addr='10.0.0.2/24', up=True)

    step("Configuring IPv6 address on host1 on eth1")
    h1.libs.ip.interface('if01', addr='1000::2/120', up=True)

    # Configure a default IPv4 route
    step("Configuring default route for IPv4 on host1")
    h1("ip -4 route add default via 10.0.0.1")

    # Configure a default routes for IPv6
    step("Configuring default route for IPv6 on host1")
    h1("ip -6 route add default via 1000::1")

    out = h1("ifconfig {h1p1}".format(**locals()))
    assert "HWaddr 00:01:02:03:04:05" and "inet addr:10.0.0.2" and \
        "Mask:255.255.255.0" and "inet6 addr: 1000::2/120 Scope:Global" in out

    # Configure host2
    # Reprogram mac-addr on host1 and host2 to be same, simulating mac-move.
    h2.libs.ip.interface('if01', up=False)

    h2("ip link set dev {h2p1} addr 00:01:02:03:04:05".format(**locals()))

    h2.libs.ip.interface('if01', up=True)

    step("\n\nConfiguring host2 IPv4")
    h2.libs.ip.interface('if01', addr='10.0.0.3/24', up=True)

    step("Configuring host2 IPv6")
    h2.libs.ip.interface('if01', addr='1000::3/120', up=True)

    step("Configuring default route for IPv4 on host2")
    h2("ip -4 route add default via 10.0.0.1")

    step("Configuring default route for IPv6 on host2")
    h2("ip -6 route add default via 1000::1")

    out = h2("ifconfig {h2p1}".format(**locals()))
    assert "HWaddr 00:01:02:03:04:05" and "inet addr:10.0.0.3" and \
        "Mask:255.255.255.0" and "inet6 addr: 1000::3/120 Scope:Global" in out

    # Configure host3
    step("\n\n\nConfiguring host3 IPv4")
    h3.libs.ip.interface('if01', addr='11.0.0.2/24', up=True)

    step("Configuring host3 ipv6")
    h3.libs.ip.interface('if01', addr='2000::2/120', up=True)

    step("Configuring default route for IPv4 on host3")
    h3("ip -4 route add default via 11.0.0.1")

    step("Configuring default route for IPv6 on host3")
    h3("ip -6 route add default via 2000::1")

    out = h3("ifconfig {h3p1}".format(**locals()))
    assert "inet addr:11.0.0.2" and "Mask:255.255.255.0" and \
        "inet6 addr: 2000::2/120 Scope:Global" in out

    # TEST: IPv4 ping from host1 to host3
    step("\n\n\nTEST: IPv4 ping from host1 to host3")
    out = h1.libs.ping.ping(1, "11.0.0.2")
    assert out['transmitted'] == out['received']

    # TEST: IPv6 ping from host1 to gateway
    step("\n\n\nTEST: IPv6 ping from host1 to default gateway")
    out = h1.libs.ping.ping(1, "1000::1")
    assert out['transmitted'] == out['received']

    step("\n\n\nTEST: IPv6 ping from host1 to host3")
    out = h1.libs.ping.ping(1, "2000::2")
    assert out['transmitted'] == out['received']

    # shutdown interface 1 on switch and no-shut interface 2.
    # Ping from host2 to host3
    step("Shutdown interface1 on switch")
    sw1('interface {sw1p1}'.format(**locals()))
    sw1('shutdown')

    step("no-shutdown interface2 on switch")
    sw1('interface {sw1p2}'.format(**locals()))
    sw1('no shutdown')

    # TEST: IPv4 Ping from host2 to host3
    step("\n\n\nTEST: IPv4 ping from host2 to host3")
    sleep(5)
    out = h2.libs.ping.ping(1, "11.0.0.2")
    assert out['transmitted'] == out['received']

    # TEST: IPv6 Ping from host2 to host3
    step("\n\n\nTEST: IPv6 ping from host2 to host3")
    sleep(5)
    out = h2.libs.ping.ping(1, "2000::2")
    assert out['transmitted'] == out['received']
