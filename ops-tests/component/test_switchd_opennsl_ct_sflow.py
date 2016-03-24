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
    collector_ip = '10.10.10.1'

    # Configuring sflow globally
    step("### Configuring sFlow ###")
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.sflow_enable()
        ctx.sflow_sampling(sampling_rate)
        ctx.sflow_collector(collector_ip)

    collector = {}
    collector['ip'] = '10.10.10.1'
    collector['port'] = '6343'
    collector['vrf'] = 'vrf_default'

    # Comparing values stored in DB with expected values
    sflow_config = ops1.libs.vtysh.show_sflow()
    assert sflow_config['sflow'] == 'enabled'
    assert int(sflow_config['sampling_rate']) == sampling_rate
    assert sflow_config['collector'][0] == collector

    # Verifying whether sampling rate is correctly set in ASIC for the
    # displayed interfaces
    step("### Verifying sampling rate for displayed interfaces ###")
    step("### Issuing ovs-appctl command to get the sflow sampling rate ###")
    ret = ops1("ovs-appctl -t ops-switchd sflow/show-rate", shell="bash")

    appctl_output = ret.splitlines()
    # Skipping headings from the output of ovs-appctl command
    appctl_output = appctl_output[4:]

    for intf in appctl_output:
        # Each line contains sampling rate information per interface:
        # [Interface name, Ingress sampling rate, Egress sampling rate]
        # We expect same samping rate on ingress and egress
        step(str(intf))
        intf_sampling_rates = intf.split()
        assert int(intf_sampling_rates[1]) == sampling_rate
        assert int(intf_sampling_rates[2]) == sampling_rate

    step("### Verifying sFlow knet filters ###")
    knet_output = ops1("ovs-appctl plugin/debug knet filter", shell="bash")
    assert 'sFlow Source Sample' in knet_output
    assert 'sFlow Dest Sample' in knet_output
