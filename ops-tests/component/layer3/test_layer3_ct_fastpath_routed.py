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
from pytest import mark

TOPOLOGY = """
# +-------+     +--------+     +--------+     +-------+
# |  hs1  <----->  ops1  <----->  ops2  <----->  hs2  |
# +-------+     +--------+     +--------+     +-------+

# Nodes
[type=openswitch] ops1
[type=openswitch] ops2
[type=host] hs1
[type=host] hs2

# Links
hs1:eth0 -- ops1:if01
ops1:if02 -- ops2:if02
ops2:if01 -- hs2:eth0
"""

PING_BYTES = 84


@mark.timeout(500)
@mark.platform_incompatible(['docker'])
def test_fastpath_routed(topology, step):
    """
    OpenSwitch Test for simple static routes between nodes.
    """

    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    ops1 = topology.get('ops1')
    ops2 = topology.get('ops2')

    assert hs1 is not None
    assert hs2 is not None
    assert ops1 is not None
    assert ops2 is not None

    # ----------Configure Switches and Hosts----------

    step('Configure Switches and Hosts')
    lib.switch_cfg_iface(ops1, 'if01', '10.0.10.2/24', '2000::2/120')
    lib.switch_cfg_iface(ops1, 'if02', '10.0.20.1/24', '2001::1/120')
    lib.switch_cfg_iface(ops2, 'if01', '10.0.30.2/24', '2002::2/120')
    lib.switch_cfg_iface(ops2, 'if02', '10.0.20.2/24', '2001::2/120')
    sleep(10)

    lib.host_cfg_iface(hs1, 'eth0', '10.0.10.1/24', '2000::1/120')
    lib.host_cfg_iface(hs2, 'eth0', '10.0.30.1/24', '2002::1/120')

    lib.host_add_route(hs1, '10.0.20.0/24', '10.0.10.2')
    lib.host_add_route(hs1, '10.0.30.0/24', '10.0.10.2')
    lib.host_add_route(hs2, '10.0.10.0/24', '10.0.30.2')
    lib.host_add_route(hs2, '10.0.20.0/24', '10.0.30.2')
    lib.host_add_route(hs1, '2001::/120', '2000::2')
    lib.host_add_route(hs1, '2002::/120', '2000::2')
    lib.host_add_route(hs2, '2000::/120', '2002::2')
    lib.host_add_route(hs2, '2001::/120', '2002::2')

    # ----------Add IPv4 and IPv6 static routes to switches----------

    step('Add IPv4 and IPv6 static routes to switches')
    lib.switch_add_ipv4_route(ops1, '10.0.30.0/24', '10.0.20.2')
    lib.switch_add_ipv4_route(ops2, '10.0.10.0/24', '10.0.20.1')
    lib.switch_add_ipv6_route(ops1, '2002::/120', '2001::2')
    lib.switch_add_ipv6_route(ops2, '2000::/120', '2001::1')

    # --------------Baseline rx tx statistics---------------

    base_stats_ops1 = ops1.libs.vtysh.show_interface("if02")
    base_stats_ops2 = ops2.libs.vtysh.show_interface("if02")

    # ----------Test Ping after adding static routes----------

    step('Test Ping after adding static routes')
    lib.host_ping_expect_success(1, hs1, hs2, '10.0.30.1')
    lib.host_ping_expect_success(1, hs1, hs2, '2002::1')
    lib.host_ping_expect_success(1, hs2, hs1, '10.0.10.1')
    lib.host_ping_expect_success(1, hs2, hs1, '2000::1')

    """
    # ----------Verifying Hit bit in ASIC for IPv4 ping----------

    step('Verifying Hit bit in ASIC for IPv4 ping')
    verify_hit_bit(ops1, '10.0.30.0')
    verify_hit_bit(ops2, '10.0.10.0')
    """

    # ----------Verifying rx tx stats after IPv4 ping----------

    sleep(10)
    step('Verifying rx tx stats after IPv4 ping')
    # Though the above code tries to send 1 ping, 2 pings go out
    verify_l3_stats(ops1, "if02", base_stats_ops1, 4)
    verify_l3_stats(ops2, "if02", base_stats_ops2, 4)

    # ----------Remove IPv4 and IPv6 static routes from switches----------

    step('Remove IPv4 and IPv6 static routes from switches')
    lib.switch_remove_ipv4_route(ops1, '10.0.30.0/24', '10.0.20.2')
    lib.switch_remove_ipv4_route(ops2, '10.0.10.0/24', '10.0.20.1')
    lib.switch_remove_ipv6_route(ops1, '2002::/120', '2001::2')
    lib.switch_remove_ipv6_route(ops2, '2000::/120', '2001::1')

    # ----------Test Ping after removing static routes----------

    step('RTest Ping after removing static routes')
    lib.host_ping_expect_failure(1, hs1, hs2, '10.0.30.1')
    lib.host_ping_expect_failure(1, hs1, hs2, '2002::1')
    lib.host_ping_expect_failure(1, hs2, hs1, '10.0.10.1')
    lib.host_ping_expect_failure(1, hs2, hs1, '2000::1')


def verify_hit_bit(switch, dest_subnet):
    header = 'Verifying HIT Bit for IPv4 ping on {0}'
    print(header.format(switch.identifier))

    result = switch('ovs-appctl plugin/debug l3route', shell='bash')
    assert result, 'could not get l3route debug\n'

    rows = result.split('\n')
    route_row = None
    for row in rows:
        if dest_subnet in row:
            route_row = row

    assert route_row is not None, 'route not programmed in ASIC\n'

    columns = route_row.split()
    route_hit = columns[5]
    assert route_hit == 'Y', 'route not selected in ASIC\n'


def verify_l3_stats(switch, iface, base_stats, ping_cnt):
    # Retry loop around tx and rx stats.
    for iteration in range(0, 5):
        pass_cases = 0
        stats = switch.libs.vtysh.show_interface(iface)

        rx_packets = stats['rx_l3_ucast_packets']
        tx_packets = stats['tx_l3_ucast_packets']
        rx_bytes = stats['rx_l3_ucast_bytes']
        tx_bytes = stats['tx_l3_ucast_bytes']
        base_rx_packets = base_stats['rx_l3_ucast_packets']
        base_tx_packets = base_stats['tx_l3_ucast_packets']
        base_rx_bytes = base_stats['rx_l3_ucast_bytes']
        base_tx_bytes = base_stats['tx_l3_ucast_bytes']

        if rx_packets < (ping_cnt + base_rx_packets):
            print("Retrying statistic - waiting for rx packets to update")
            continue
        pass_cases = pass_cases + 1
        if tx_packets < (ping_cnt + base_tx_packets):
            print("Retrying statistic - waiting for tx packets to update")
            sleep(5)
            continue
        pass_cases = pass_cases + 1
        if rx_bytes < ((ping_cnt * PING_BYTES) + base_rx_bytes):
            print("Retrying statistic - waiting for rx bytes to update")
            sleep(5)
            continue
        pass_cases = pass_cases + 1
        if tx_bytes < ((ping_cnt * PING_BYTES) + base_tx_bytes):
            print("Retrying statistic - waiting for tx bytes to update")
            sleep(5)
            continue
        pass_cases = pass_cases + 1
        if pass_cases == 4:
            break

    # Verify RX_packets
    assert rx_packets >= (ping_cnt + base_rx_packets), "rx_packets wrong."
    # Verify TX_packets
    assert tx_packets >= (ping_cnt + base_tx_packets), "tx_packets wrong."
    # Verify RX_bytes
    assert rx_bytes >= ((ping_cnt * PING_BYTES) + base_rx_bytes), (
        "rx_bytes wrong.")
    # Verify TX_bytes
    assert tx_bytes >= ((ping_cnt * PING_BYTES) + base_tx_bytes), (
        "tx_bytes wrong.")
