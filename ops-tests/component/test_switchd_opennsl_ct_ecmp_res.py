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
sw1:if03 -- sw2:if03

"""


def ecmp_resilient_config_creation(sw1, sw2):
    # Enabling interfaces on switch1
    # Enabling interface 1 on switch1
    print("Enabling interface1 on switch01")
    sw1p1 = sw1.ports['if01']
    sw1p2 = sw1.ports['if02']
    sw1p3 = sw1.ports['if03']
    sw2p1 = sw2.ports['if01']
    sw2p2 = sw2.ports['if02']
    sw2p3 = sw2.ports['if03']

    sw1('configure terminal')
    sw1('interface {sw1p1}'.format(**locals()))
    sw1('no shutdown')

    print("Configuring ipv4 address 1.0.0.1 on interface 1")
    sw1('ip address 1.0.0.1/24')

    print("Configuring ipv6 address 1010::2/120 on interface 1")
    sw1('ipv6 address 1010::2/120')

    # Enabling interface 2 on switch1
    print("Enabling interface2 on switch01")
    sw1('interface {sw1p2}'.format(**locals()))
    sw1('no shutdown')

    print("Configuring ipv4 address 2.0.0.1 on interface 2 switch 1")
    sw1('ip address 2.0.0.1/24')

    print('Configuring ipv6 address 1020::2/120 on interface 2')
    sw1('ipv6 address 1020::2/120')

    # Enabling interface 3 on switch1
    print("Enabling interface3 on switch01")
    sw1('interface {sw1p3}'.format(**locals()))
    sw1('no shutdown')

    print("Configuring ipv4 address 3.0.0.1 on interface 3 switch 1")
    sw1('ip address 3.0.0.1/24')

    print("Configuring ipv6 address 1030::2/120 on interface 3")
    sw1('ipv6 address 1030::2/120')
    sw1('exit')

    # Enabling interfaces on switch2
    # Enabling interface 1 on switch2
    print("Enabling interface1 on switch02")
    sw2('configure terminal')
    sw2('interface {sw2p1}'.format(**locals()))
    sw2('no shutdown')

    print("Configuring ipv4 address 1.0.0.2 on interface 1")
    sw2('ip address 1.0.0.2/24')

    print("Configuring ipv6 address 1010::1/120 on interface 1")
    sw2("ipv6 address 1010::1/120")

    # Enabling interface 2 on switch2
    print("Enabling interface2 on switch02")
    sw2('interface {sw2p2}'.format(**locals()))
    sw2('no shutdown')

    print("Configuring ipv4 address 2.0.0.2 on interface 2 switch 2")
    sw2('ip address 2.0.0.2/24')

    print("Configuring ipv6 address 1020::1/120 on interface 2")
    sw2('ipv6 address 1020::1/120')

    # Enabling interface 3 on switch2
    print("Enabling interface3 on switch02")
    sw2('interface {sw2p3}'.format(**locals()))
    sw2('no shutdown')

    print("Configuring ipv4 address 3.0.0.2 on interface 3 switch 2")
    sw2('ip address 3.0.0.2/24')

    print("Configuring ipv6 address 1030::1/120 on interface 2")
    sw2('ipv6 address 1030::1/120')
    sw2('exit')

    # Enabling static routes on switch1
    sw1("ip route 70.0.0.0/24 1.0.0.2")
    sw1("ip route 70.0.0.0/24 2.0.0.2")
    sw1("ip route 70.0.0.0/24 3.0.0.2")
    out = sw1('do show run')
    assert "ip route 70.0.0.0/24 3.0.0.2" and "ip \
        route 70.0.0.0/24 1.0.0.2" \
        and "ip route 70.0.0.0/24 2.0.0.2" in out

    # Enabling static IPv6 routes on switch1
    sw1("ipv6 route 1090::/120 1030::2")
    sw1("ipv6 route 1090::/120 1020::2")
    sw1("ipv6 route 1090::/120 1040::2")
    out = sw1('do show run')
    assert "ipv6 route 1090::/120 1030::2" and \
        "ipv6 route 1090::/120 1020::2" and \
        "ipv6 route 1090::/120 1040::2" in out


def ecmp_resilient_check_status(switch, is_enabled):
    appctl_command = "ovs-appctl plugin/debug l3ecmp"
    ret_struct = switch(appctl_command, shell='bash')
    if (is_enabled):
        ecmp_res_status = 'TRUE'
        ecmp_dynamic_size = 512
    else:
        ecmp_res_status = 'FALSE'
        ecmp_dynamic_size = 0

    buf = ret_struct
    for cur_line in buf.split('\n'):
        if "ECMP Resilient" in cur_line:
            str_tok = cur_line.split()
            if str_tok[2] != ecmp_res_status:
                print("error", "ECMP  resilient not working properly")
        if "dynamic size" in cur_line:
            str_tok = cur_line.split()
            if str_tok[2] != ecmp_dynamic_size:
                print("error", "ECMP  resilient not working properly")


@mark.platform_incompatible(['docker'])
def test_switchd_opennsl_plugin_ecmp_resilient(topology):
    sw1 = topology.get('sw1')
    sw2 = topology.get('sw2')

    assert sw1 is not None
    assert sw2 is not None

    ecmp_resilient_config_creation(sw1, sw2)

    sw1("ip ecmp load-balance resilient disable")
    sw1('exit')

    ecmp_resilient_check_status(sw1, False)

    sw1('configure terminal')
    sw1("no ip ecmp load-balance resilient disable")
    sw1('exit')

    ecmp_resilient_check_status(sw1, True)
