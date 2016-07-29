# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
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

"""
Component Test to Verify sFlow Configuration in ASIC.
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
[type=openswitch name="OpenSwitch"] ops1
"""


@mark.platform_incompatible(['docker'])
def test_opennsl_ct_sflow(topology, step):
    ops1 = topology.get('ops1')

    assert ops1 is not None

    # sflow configuration values
    sampling_rate = 100
    collector_ip = '10.10.10.2'
    regex_string = '(\d+)\((\d+)\,(\d+)\)'
    ingress_index = 2
    egress_index = 3

    # Configure one interface on the switch to act as agent IP for sFlow agent
    # on the switch
    step("Configuring interface 1 of switch")
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.ip_address('10.10.10.1/24')
        ctx.no_shutdown()

    # Configuring sflow globally
    step("### Configuring sFlow ###")
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.sflow_enable()
        ctx.sflow_sampling(sampling_rate)
        ctx.sflow_collector(collector_ip)

    collector = {}
    collector['ip'] = '10.10.10.2'
    collector['port'] = '6343'
    collector['vrf'] = 'vrf_default'

    # Comparing values stored in DB with expected values
    sflow_config = ops1.libs.vtysh.show_sflow()
    print(sflow_config)
    assert sflow_config['sflow'] == 'enabled'
    assert int(sflow_config['sampling_rate']) == sampling_rate
    assert sflow_config['collector'][0] == collector

    step("### Verifying sampling rate for displayed interfaces ###")
    ret = ops1("ovs-appctl -t ops-switchd sflow/show-rate", shell="bash")

    # Sample appctl output
    #      	Port Number(Ingress Rate, Egress Rate)
    #  	    ======================================
    #  1(0,0)         2(0,0)         3(0,0)         4(0,0)         5(0,0)
    #  6(0,0)         7(0,0)         8(0,0)         9(0,0)        10(0,0)

    appctl_output = ret.splitlines()
    # Skipping headings from the output of ovs-appctl command
    appctl_output = appctl_output[2:]

    # Parse the appctl_output to get interface specific data as an array
    # i.e. ['1(0,0)', '2(0,0)', '3(0,0)']
    all_intfs = []
    for item in appctl_output:
        intfs = item.strip().split()
        all_intfs.extend(intfs)

    # Loop through interface array and use regex to get the ingress and egress
    # sampling rates
    for intf in all_intfs:
        m = re.search(regex_string, intf)
        assert m, "Sampling rate regex match failed"
        # Check for programmed ingress and egress sampling rates
        assert int(m.group(ingress_index)) == sampling_rate, \
            "Ingress sampling rate mismatch. Expected=" + \
            str(sampling_rate) + " Actual=" + str(m.group(ingress_index))
        assert int(m.group(egress_index)) == sampling_rate, \
            "Egress sampling rate mismatch. Expected=" + \
            str(sampling_rate) + " Actual=" + str(m.group(egress_index))

    step("### Verifying sFlow knet filters ###")
    knet_output = ops1("ovs-appctl plugin/debug knet filter", shell="bash")
    assert 'sFlow Source Sample' in knet_output
    assert 'sFlow Dest Sample' in knet_output
