#!/usr/bin/env python

# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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

import pytest
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch.OVS import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoType": "physical",
            "topoTarget": "dut01",
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}


def ecmp_hash_check_status(switch, is_ipv4, is_enabled):

    if (is_ipv4):
        appctl_command = "ovs-appctl plugin/debug l3route"
        retStruct = switch.DeviceInteract(command=appctl_command)
        log_ip_str = "IPv4"
    else:
        appctl_command = "ovs-appctl plugin/debug l3v6route"
        retStruct = switch.DeviceInteract(command=appctl_command)
        log_ip_str = "IPv6"
    if (is_enabled):
        ecmp_hash_status = 'Y'
        log_enable_str = "enable"
    else:
        ecmp_hash_status = 'N'
        log_enable_str = "disable"

    ecmp_hash_start = 0
    ecmp_hash_line_count = 0
    buf = retStruct.get('buffer')
    for curLine in buf.split('\n'):
        if "Src Addr" in curLine:
            ecmp_hash_start = 1
        if ecmp_hash_start == 1:
            ecmp_hash_line_count += 1
        if ecmp_hash_line_count == 3:
            hash_fields = curLine.split()
            if hash_fields[0] != ecmp_hash_status\
               or hash_fields[1] != ecmp_hash_status \
               or hash_fields[2] != ecmp_hash_status \
               or hash_fields[3] != ecmp_hash_status:
                LogOutput("error", "Could not %s ECMP %s hash in ASIC" %
                                   (log_enable_str, log_ip_str))


def ecmp_hash_test(**kwargs):

    switch = kwargs.get('switch', None)

    switch.VtyshShell(enter=True)
    switch.ConfigVtyShell(enter=True)
    switch.DeviceInteract(command="ip ecmp load-balance src-ip disable")
    switch.DeviceInteract(command="ip ecmp load-balance dst-ip disable")
    switch.DeviceInteract(command="ip ecmp load-balance src-port disable")
    switch.DeviceInteract(command="ip ecmp load-balance dst-port disable")
    switch.ConfigVtyShell(enter=False)
    switch.VtyshShell(enter=False)

    ecmp_hash_check_status(switch, True, False)
    ecmp_hash_check_status(switch, False, False)

    switch.VtyshShell(enter=True)
    switch.ConfigVtyShell(enter=True)
    switch.DeviceInteract(command="no ip ecmp load-balance src-ip disable")
    switch.DeviceInteract(command="no ip ecmp load-balance dst-ip disable")
    switch.DeviceInteract(command="no ip ecmp load-balance src-port disable")
    switch.DeviceInteract(command="no ip ecmp load-balance dst-port disable")
    switch.ConfigVtyShell(enter=False)
    switch.VtyshShell(enter=False)

    ecmp_hash_check_status(switch, True, True)
    ecmp_hash_check_status(switch, False, True)


class Test_ecmp_hash_ct:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_ecmp_hash_ct.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_ecmp_hash_ct.topoObj = Test_ecmp_hash_ct.testObj.topoObjGet()

    def teardown_class(cls):
        Test_ecmp_hash_ct.topoObj.terminate_nodes()

    def test_ecmp_hash_ct(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        retValue = ecmp_hash_test(switch=dut01Obj)
        if retValue != 0:
            assert "Test failed"
        else:
            LogOutput('info', "\n### Test Passed ###\n")
