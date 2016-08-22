# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

from pytest import mark

TOPOLOGY = """
#
# +-------+
# |  sw1  |
# +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
"""

all_routers_ip = "224.0.0.5"
designated_routers_ip = "224.0.0.6"
all_routers_mac = "1:0:5e:0:0:5"
designated_routers_mac = "1:0:5e:0:0:6"
ospf_protocol = "0x59"

bfd_single_hop = "0xec8"
bfd_multi_hop = "0x12b0"
destination_ip_local = "0x01"
bfd_protocol = "0x11"


@mark.platform_incompatible(['docker'])
def test_ospf_fp(topology, step):
    sw1 = topology.get('sw1')

    assert sw1 is not None

    print('Verify OSPF FPs are programmed in ASIC')
    appctl_command = "ovs-appctl plugin/debug fp cpu-rx-group"
    buf = sw1(appctl_command, shell="bash")
    print(str(buf))
    lines = buf.split('\n')

    # These counters are used to ensure correct count of
    # OSPF field processor entries in the output of ovs-appctl command
    ospf_protocol_count = 0
    all_routers_ip_count = 0
    all_routers_mac_count = 0
    designated_routers_ip_count = 0
    designated_routers_mac_count = 0

    for line in lines:
        if 'IpProtocol' in line and ospf_protocol in line:
            ospf_protocol_count = ospf_protocol_count + 1
        if 'DstIp' in line and all_routers_ip in line:
            all_routers_ip_count = all_routers_ip_count + 1
        if 'DstMac' in line and all_routers_mac in line:
            all_routers_mac_count = all_routers_mac_count + 1
        if 'DstIp' in line and designated_routers_ip in line:
            designated_routers_ip_count = designated_routers_ip_count + 1
        if 'DstMac' in line and designated_routers_mac in line:
            designated_routers_mac_count = designated_routers_mac_count + 1

    assert ospf_protocol in buf, 'OSPF Protocol mising'
    print('Verified OSPF Protocol entry')

    assert ospf_protocol_count == 2, 'More than 2 occurences of OSPF Protocol'
    print('Verified OSPF Protocol count')

    assert all_routers_ip in buf and all_routers_mac in buf, \
        'All Routers OSPF field entry missing'
    print('Verified All Routers OSPF field entry')

    assert all_routers_ip_count == 1 and all_routers_mac_count == 1,\
        'More than 1 occurence of All Routers OSPF field entry'
    print('Verified All Routers OSPF field entry count')

    assert designated_routers_ip in buf and designated_routers_mac in buf,\
        'Designated Routers OSPF field entry missing'
    print('Verified Designated Routers OSPF field entry')

    assert designated_routers_ip_count == 1 and \
        designated_routers_mac_count == 1,\
        'More than 1 occurence of Designated Routers OSPF field entry'
    print('Verified Designated Routers OSPF field entry count')


@mark.platform_incompatible(['docker'])
def test_bfd_fp(topology, step):
    sw1 = topology.get('sw1')

    assert sw1 is not None

    print('Verify BFD FPs are programmed in ASIC')
    appctl_command = "ovs-appctl plugin/debug fp cpu-rx-group"
    buf = sw1(appctl_command, shell="bash")
    print(str(buf))
    lines = buf.split('\n')

    # These counters are used to ensure correct count of
    # BFD field processor entries in the output of ovs-appctl command
    bfd_protocol_count = 0
    destination_ip_local_count = 0
    bfd_single_hop_count = 0
    bfd_multi_hop_count = 0

    for line in lines:
        if 'IpProtocol' in line and bfd_protocol in line:
            bfd_protocol_count = bfd_protocol_count + 1
        if 'DstIpLocal' in line and destination_ip_local in line:
            destination_ip_local_count = destination_ip_local_count + 1
        if 'L4DstPort' in line and bfd_single_hop in line:
            bfd_single_hop_count = bfd_single_hop_count + 1
        if 'L4DstPort' in line and bfd_multi_hop in line:
            bfd_multi_hop_count = bfd_multi_hop_count + 1

    assert bfd_protocol in buf, 'BFD Protocol mising'
    print('Verified BFD Protocol entry')

    assert bfd_protocol_count == 2, 'More than 2 occurences of BFD Protocol'
    print('Verified BFD Protocol count')

    assert destination_ip_local in buf, \
        'Destination Ip Local BFD field entry missing'
    print('Verified Destination Ip Local BFD field entry')

    assert destination_ip_local_count == 2,\
        'More than 2 occurence of Destination Ip Local BFD field entry'
    print('Verified Destination Ip Local BFD field entry count')

    assert bfd_single_hop in buf,\
        'Single hop BFD field entry missing'
    print('Verified single hop BFD field entry')

    assert bfd_single_hop_count == 1,\
        'More than 1 occurence of single hop BFD field entry'
    print('Verified single hop BFD field entry count')

    assert bfd_multi_hop in buf,\
        'Multi hop BFD field entry missing'
    print('Verified multi hop BFD field entry')

    assert bfd_single_hop_count == 1,\
        'More than 1 occurence of multi hop BFD field entry'
    print('Verified multi hop BFD field entry count')
