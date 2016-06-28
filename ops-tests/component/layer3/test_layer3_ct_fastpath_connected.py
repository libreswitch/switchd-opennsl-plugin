# -*- coding: utf-8 -*-

# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
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

import layer3_common as lib
from time import sleep
from ipaddress import ip_address
from pytest import mark

TOPOLOGY = """
# +-------+     +--------+     +-------+
# |  hs1  <----->  ops1  <----->  hs2  |
# +-------+     +--------+     +-------+

# Nodes
[type=openswitch] ops1
[type=host] hs1
[type=host] hs2

# Links
hs1:eth0 -- ops1:if01
ops1:if02 -- hs2:eth0
"""


@mark.timeout(500)
@mark.platform_incompatible(['docker'])
def test_fastpath_routed(topology, step):
    """
    Directly Connected Hosts Fast Path Ping Test
    """

    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    ops1 = topology.get('ops1')

    assert hs1 is not None
    assert hs2 is not None
    assert ops1 is not None

    # ----------Configure Switches and Hosts----------

    step('Configure Switches and Hosts')
    with ops1.libs.vtysh.Configure():
        ops1("vlan internal range 400 500 ascending", shell=None)

    lib.switch_cfg_iface(ops1, 'if01', '10.0.0.1/24', '2000::1/120')
    lib.switch_cfg_iface(ops1, 'if02', '11.0.0.1/24', '2002::1/120')
    sleep(10)

    lib.host_cfg_iface(hs1, 'eth0', '10.0.0.10/24', '2000::2/120')
    lib.host_cfg_iface(hs2, 'eth0', '11.0.0.10/24', '2002::2/120')

    lib.host_add_route(hs1, '0.0.0.0/0', '10.0.0.1')
    lib.host_add_route(hs2, '0.0.0.0/0', '11.0.0.1')
    lib.host_add_route(hs1, '::/0', '2000::1')
    lib.host_add_route(hs2, '::/0', '2002::1')

    # ---------- IPv4 ping between workstations ----------

    step("IPv4 ping between workstations")
    lib.host_ping_expect_success(10, hs2, hs1, '10.0.0.10')
    lib.host_ping_expect_success(10, hs1, hs2, '11.0.0.10')

    # ---------- Verifying HIT Bit in ASIC for IPv4 ping ----------

    step("Verifying HIT Bit in ASIC for IPv4 ping")
    lib.host_ping_expect_success(10, hs1, hs2, '11.0.0.10')
    verify_ipv4_hit_bit(ops1, '10.0.0.10', '11.0.0.10')

    # ---------- IPv6 ping between workstations ----------

    step("IPv6 ping between workstations")
    lib.host_ping_expect_success(10, hs2, hs1, '2000::2')
    lib.host_ping_expect_success(10, hs1, hs2, '2002::2')

    # ---------- Verifying HIT Bit in ASIC for IPv6 ping ----------

    step("Verifying HIT Bit in ASIC for IPv6 ping")
    lib.host_ping_expect_success(10, hs1, hs2, '2002::2')
    verify_ipv6_hit_bit(ops1, '2000::2', '2002::2')

    # ---------- IPv4 and IPv6 ping between switch and workstations ----------

    step("IPv4 and IPv6 ping between switch and workstations")
    lib.host_ping_expect_success(10, hs1, ops1, '10.0.0.1')
    lib.host_ping_expect_success(10, hs1, ops1, '2000::1')
    lib.host_ping_expect_success(10, hs2, ops1, '11.0.0.1')
    lib.host_ping_expect_success(10, hs2, ops1, '2002::1')


def verify_ipv4_hit_bit(switch, dest_subnet_1, dest_subnet_2):
    header = 'Verifying HIT Bit for IPv4 ping on {0}'
    print(header.format(switch.identifier))

    dphit_host1 = None
    dphit_host2 = None

    for i in range(1, 3):
        result = switch('ovs-appctl plugin/debug l3host', shell='bash')
        assert result, 'could not get l3host debug\n'

        rows = result.split('\n')

        host1row = None
        host2row = None

        for row in rows:
            if dest_subnet_1 in row:
                host1row = row
            if dest_subnet_2 in row:
                host2row = row

    assert host1row is not None, 'host 1 not programmed in ASIC\n'
    assert host2row is not None, 'host 2 not programmed in ASIC\n'

    columns = host1row.split()
    dphit_host1 = columns[5]

    columns = host2row.split()
    dphit_host2 = columns[5]

    assert dphit_host1 == 'y', 'DP hit was not set for host 1\n'
    assert dphit_host2 == 'y', 'DP hit was not set for host 2\n'


def verify_ipv6_hit_bit(switch, dest_subnet_1, dest_subnet_2):
    header = 'Verifying HIT Bit for IPv6 ping on {0}'
    print(header.format(switch.identifier))

    dphit_host1 = None
    dphit_host2 = None
    dest_subnet_1 = ip_address(dest_subnet_1).exploded
    dest_subnet_2 = ip_address(dest_subnet_2).exploded

    for i in range(1, 3):
        result = switch('ovs-appctl plugin/debug l3v6host', shell='bash')
        assert result, 'could not get l3v6host debug\n'

        rows = result.split('\n')

        host1row = None
        host2row = None

        for row in rows:
            if dest_subnet_1 in row:
                host1row = row
            if dest_subnet_2 in row:
                host2row = row

    assert host1row is not None, 'host 1 not programmed in ASIC\n'
    assert host2row is not None, 'host 2 not programmed in ASIC\n'

    columns = host1row.split()
    dphit_host1 = columns[5]

    columns = host2row.split()
    dphit_host2 = columns[5]

    assert dphit_host1 == 'y', 'DP hit was not set for host 1\n'
    assert dphit_host2 == 'y', 'DP hit was not set for host 2\n'
