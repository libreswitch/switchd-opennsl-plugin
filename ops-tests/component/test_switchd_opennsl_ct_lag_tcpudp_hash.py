# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

import re
from time import sleep

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


def lag_tcpudp_hash_check_status(sw1):
    appctl_command = "ovs-appctl plugin/debug lag"
    buf = sw1(appctl_command, shell='bash')

    lag_mode = re.findall(r"l4-src-dst", buf)
    if lag_mode == "l4-src-dst":
        return 0
    else:
        return -1


def test_switchd_opennsl_plugin_lag_tcpudp_hash(topology, step):
    sw1 = topology.get('sw1')
    sw2 = topology.get('sw2')

    assert sw1 is not None
    assert sw2 is not None

    sw1p1 = sw1.ports['if01']
    sw1p2 = sw1.ports['if02']
    sw2p1 = sw2.ports['if01']
    sw2p2 = sw2.ports['if02']

    # Configuring lag interface
    sw1('configure terminal')
    sw1("interface lag 100")

    # Configuring lag hash mode
    sw1("hash l4-src-dst")

    # Entering interface
    sw1("interface {sw1p1}".format(**locals()))

    # Adding interface to lag
    sw1("lag 100")

    # Enbaling interface
    sw1("no shutdown")

    # Entering interface
    sw1("interface {sw1p2}".format(**locals()))

    # Adding interface to lag
    sw1("lag 100")

    # Enabling interface
    sw1("no shutdown")
    sw1('end')

    # Entering config terminal
    sw2('configure terminal')

    # Configuring lag interface
    sw2("interface lag 100")

    # Configuring lag hash mode
    sw2("hash l4-src-dst")

    # Entering interface
    sw2("interface {sw2p1}".format(**locals()))

    # Adding interface to lag
    sw2("lag 100")

    # Enbaling interface
    sw2("no shutdown")

    # Entering interface
    sw2("interface {sw2p2}".format(**locals()))

    # Adding interface to lag
    sw2("lag 100")

    # Enabling interface
    sw2("no shutdown")
    sw2('end')

    sleep(5)
    lag_tcpudp_hash_check_status(sw1)
