#!/usr/bin/python
#
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

"""
Component test to verify QoS configuration in ASIC.
"""

from pytest import mark
from time import sleep

TOPOLOGY = """
#
# +--------+
# |  ops1  |
# +--------+
#

# Nodes
[type=openswitch name="OpenSwitch"] ops1
"""


def ops_qos_config_creation(ops1, step):
    # Configure qos cos-map config
    step("### Configuring QoS COS map ###")

    # OPS_TODO: Use vtysh library for this
    ops1('configure terminal')
    ops1('qos cos-map 0 local-priority 7')
    ops1('qos cos-map 1 local-priority 6')
    ops1('qos cos-map 2 local-priority 5')
    ops1('qos cos-map 3 local-priority 4')
    ops1('qos cos-map 4 local-priority 5')
    ops1('qos cos-map 5 local-priority 2')
    ops1('qos cos-map 6 local-priority 1')
    ops1('qos cos-map 7 local-priority 0')

    # Configure qos dscp-map config
    step("### Configuring QoS DSCP map ###")

    ops1('qos dscp-map 0 local-priority 7')
    ops1('qos dscp-map 1 local-priority 6')
    ops1('qos dscp-map 2 local-priority 5')
    ops1('qos dscp-map 3 local-priority 4')
    ops1('qos dscp-map 4 local-priority 3')
    ops1('qos dscp-map 5 local-priority 2')
    ops1('qos dscp-map 6 local-priority 1')

    # Configure qos dscp override & trust
    step("### Configuring QoS DSCP override & trust ###")

    ops1('interface 1')
    ops1('qos trust none')
    ops1('qos dscp 7')
    ops1('exit')

    # Configure qos queuing & scheduling
    step("### Configuring QoS Queuing & Scheduling ###")

    ops1('qos queue-profile ops-qos-test')
    ops1('map queue 0 local-priority 7')
    ops1('map queue 1 local-priority 6')
    ops1('map queue 2 local-priority 5')
    ops1('map queue 3 local-priority 4')
    ops1('map queue 4 local-priority 3')
    ops1('map queue 5 local-priority 2')
    ops1('map queue 6 local-priority 1')
    ops1('map queue 7 local-priority 0')
    ops1('exit')

    ops1('qos schedule-profile ops-qos-test')
    ops1('strict queue 0')
    ops1('strict queue 1')
    ops1('strict queue 2')
    ops1('strict queue 3')
    ops1('strict queue 4')
    ops1('strict queue 5')
    ops1('strict queue 6')
    ops1('strict queue 7')
    ops1('exit')

    ops1('apply qos queue-profile ops-qos-test schedule-profile ops-qos-test')
    ops1('exit')

    appctl_command = "ovs-appctl plugin/debug qos port-config"
    output = ops1(appctl_command, shell='bash')
    print(output)


@mark.platform_incompatible(['docker'])
def test_switchd_opennsl_ct_qos(topology, step):
    ops1 = topology.get('ops1')

    assert ops1 is not None

    # First complete the necessary qos config
    step("### Configuring QoS ###")
    ops_qos_config_creation(ops1, step)

    # After configuration, wait for 10 seconds for the config
    # to get pushed down to the hardware
    sleep(10)

    # Verify COS map config in ASIC
    # As the COS map id that is created in hardware depends on type of ASIC
    # and its resource, just make sure it has a valid map id.
    step("### Verifying QoS cos map config ###")
    appctl_command = "ovs-appctl plugin/debug qos cos-map"
    output = ops1(appctl_command, shell='bash')

    appctl_output = output.splitlines()
    # Skipping headings from the output of ovs-appctl command
    appctl_output = appctl_output[2:]

    valid_cos_map_id_flag = False
    valid_cos_map_id_default_flag = False

    for output_line in appctl_output:
        # Verify the outputs for default COS map id and
        # system config COS map id
        step(str(output_line))

        if 'Default COS map ID' in output_line and '-1' not in output_line:
            valid_cos_map_id_default_flag = True

        if 'System config COS map ID' in output_line and \
           '-1' not in output_line:
            valid_cos_map_id_flag = True

    assert valid_cos_map_id_flag is True
    assert valid_cos_map_id_default_flag is True

    step('### Verified QoS cos map config - SUCCESS ###')

    # Verify DSCP map config in ASIC
    # As the DSCP map id that is created in hardware depends on type of ASIC
    # and its resource, just make sure it has a valid map id.
    step("### Verifying QoS dscp map config ###")
    appctl_command = "ovs-appctl plugin/debug qos dscp-map"
    output = ops1(appctl_command, shell='bash')

    appctl_output = output.splitlines()
    # Skipping headings from the output of ovs-appctl command
    appctl_output = appctl_output[2:]

    valid_dscp_map_id_flag = False

    for output_line in appctl_output:
        # Verify the outputs for DSCP map id
        step(str(output_line))

        if 'DSCP map ID' in output_line and '-1' not in output_line:
            valid_dscp_map_id_flag = True

    assert valid_dscp_map_id_flag is True

    step('### Verified QoS dscp map config - SUCCESS ###')

    # Verify DSCP override config in ASIC
    step("### Verifying QoS dscp override config ###")
    appctl_command = "ovs-appctl plugin/debug qos dscp-override"
    output = ops1(appctl_command, shell='bash')

    appctl_output = output.splitlines()
    # Skipping headings from the output of ovs-appctl command
    appctl_output = appctl_output[2:]

    dscp_map_mode_flag = False
    dscp_override_value_flag = False

    for output_line in appctl_output:
        # Verify the outputs for DSCP override
        step(str(output_line))

        if 'DSCP map mode' in output_line and '2' in output_line:
            dscp_map_mode_flag = True

        if 'DSCP override value' in output_line and '7' in output_line:
            dscp_override_value_flag = True

    assert dscp_map_mode_flag is True
    assert dscp_override_value_flag is True

    step('### Verified QoS dscp override config - SUCCESS ###')

    # Verify Queuing config in ASIC
    step("### Verifying QoS queuing config ###")
    appctl_command = "ovs-appctl plugin/debug qos queuing"
    output = ops1(appctl_command, shell='bash')

    appctl_output = output.splitlines()
    # Skipping headings from the output of ovs-appctl command
    appctl_output = appctl_output[4:]

    valid_queue_map_found = 0
    valid_queue_map_expected = 8

    for output_line in appctl_output:
        # Verify the outputs for queue map
        step(str(output_line))

        if '0' in output_line and '7' in output_line:
            valid_queue_map_found += 1

        if '1' in output_line and '6' in output_line:
            valid_queue_map_found += 1

        if '2' in output_line and '5' in output_line:
            valid_queue_map_found += 1

        if '3' in output_line and '4' in output_line:
            valid_queue_map_found += 1

    assert valid_queue_map_found == valid_queue_map_expected

    step('### Verified QoS queuing config - SUCCESS ###')

    # Verify Scheduling config in ASIC
    step("### Verifying QoS scheduling config ###")
    appctl_command = "ovs-appctl plugin/debug qos scheduling"
    output = ops1(appctl_command, shell='bash')

    appctl_output = output.splitlines()
    # Skipping headings from the output of ovs-appctl command
    appctl_output = appctl_output[4:]

    valid_schedule_mode_found = 0
    valid_schedule_mode_expected = 8
    strict_schedule_mode = '0x1'

    for output_line in appctl_output:
        # Verify the outputs for schedule config
        step(str(output_line))

        if strict_schedule_mode in output_line:
            valid_schedule_mode_found += 1

    assert valid_schedule_mode_found == valid_schedule_mode_expected

    step('### Verified QoS scheduling config - SUCCESS ###')
