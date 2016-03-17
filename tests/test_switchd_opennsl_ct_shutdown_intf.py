#!/usr/bin/python

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

import pytest
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch.OVS import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoType": "physical",
            "topoTarget": "dut01",
            "topoDevices": "dut01 dut02",
            "topoLinks": "lnk01:dut01:dut02, \
                          lnk02:dut01:dut02, \
                          lnk03:dut01:dut02",
            "topoFilters": "dut01:system-category:switch, \
                            dut02:system-category:switch"}

def config_creation(**kwargs):
    switch01 = kwargs.get('switch01', None)
    switch02 = kwargs.get('switch02', None)

    # Enabling interfaces on switch1
    # Enabling interface 1 on switch1
    LogOutput('info', "Enabling interface1 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch01,
        enable=True,
        interface=switch01.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface1 on switch1"

    LogOutput('info', "Configuring ipv4 address 1.0.0.1 on interface 1 on switch 1")
    retStruct = InterfaceIpConfig(
        deviceObj=switch01,
        interface=switch01.linkPortMapping['lnk01'],
        addr="1.0.0.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 1 on switch 1"

    # Enabling interface 2 on switch1
    LogOutput('info', "Enabling interface2 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch01,
        enable=True,
        interface=switch01.linkPortMapping['lnk02'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface2 on switch1"

    LogOutput('info', "Configuring ipv4 address 2.0.0.1 on interface 2 switch 1")
    retStruct = InterfaceIpConfig(
        deviceObj=switch01,
        interface=switch01.linkPortMapping['lnk02'],
        addr="2.0.0.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 2 on switch 1"

    # Enabling interface 3 on switch1
    LogOutput('info', "Enabling interface3 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch01,
        enable=True,
        interface=switch01.linkPortMapping['lnk03'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface2 on switch1"

    LogOutput('info', "Configuring ipv4 address 3.0.0.1 on interface 3 switch 1")
    retStruct = InterfaceIpConfig(
        deviceObj=switch01,
        interface=switch01.linkPortMapping['lnk03'],
        addr="3.0.0.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 3 on switch 1"

    #Enabling static routes on switch1
    LogOutput('info', "Configuring static ecmp route  70.0.0.0/24 next hop 1.0.0.2")
    retStruct = IpRouteConfig(deviceObj=switch01, route="70.0.0.0", mask=24,
                              nexthop="1.0.0.2", config=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('info', "\nFailed to configure ipv4 address route")
        assert(False)

    LogOutput('info', "Configuring static ecmp route  70.0.0.0/24 next hop 2.0.0.2")
    retStruct = IpRouteConfig(deviceObj=switch01, route="70.0.0.0", mask=24,
                              nexthop="2.0.0.2", config=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('info', "\nFailed to configure ipv4 address route")
        assert(False)

    LogOutput('info', "Configuring static ecmp route  70.0.0.0/24 next hop 3.0.0.2")
    retStruct = IpRouteConfig(deviceObj=switch01, route="70.0.0.0", mask=24,
                              nexthop="3.0.0.2", config=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('info', "\nFailed to configure ipv4 address route")
        assert(False)

    LogOutput('info', "Configuring static route  80.0.0.0/24 next hop 1.0.0.2")
    retStruct = IpRouteConfig(deviceObj=switch01, route="80.0.0.0", mask=24,
                              nexthop="1.0.0.2", config=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('info', "\nFailed to configure ipv4 address route")
        assert(False)

# The validate_ecmp_check_status checks for the Interfaces programmed in ASIC
# is same as in sh ip route
# Command output : ovs-appctl plugin/debug l3ecmp
# Multipath Egress Object 200256
# Interfaces: 100002 100002 100002
def validate_ecmp_check_status(switch, number_of_intf):

    appctl_command = "ovs-appctl plugin/debug l3ecmp"
    retStruct = switch.DeviceInteract(command=appctl_command)

    buf = retStruct.get('buffer')
    for curLine in buf.split('\n'):
        if "Interfaces:" in curLine:
            if number_of_intf  !=  len([s for s in re.findall(r'\b\d+\b',str)]):
               LogOutput('error', "ASIC for ECMP object has incorrect number of nexthops\n")
               assert(False)

def intf_shut_noshut_test(**kwargs):

    ExpRouteDictIpv4StaticRoute1_3 = dict()
    ExpRouteDictIpv4StaticRoute1_3['Route'] = '70.0.0.0' + '/' + '24'
    ExpRouteDictIpv4StaticRoute1_3['NumberNexthops'] = '3'
    ExpRouteDictIpv4StaticRoute1_3['1.0.0.2'] = dict()
    ExpRouteDictIpv4StaticRoute1_3['1.0.0.2']['Distance'] = '1'
    ExpRouteDictIpv4StaticRoute1_3['1.0.0.2']['Metric'] = '0'
    ExpRouteDictIpv4StaticRoute1_3['1.0.0.2']['RouteType'] = 'static'
    ExpRouteDictIpv4StaticRoute1_3['2.0.0.2'] = dict()
    ExpRouteDictIpv4StaticRoute1_3['2.0.0.2']['Distance'] = '1'
    ExpRouteDictIpv4StaticRoute1_3['2.0.0.2']['Metric'] = '0'
    ExpRouteDictIpv4StaticRoute1_3['2.0.0.2']['RouteType'] = 'static'
    ExpRouteDictIpv4StaticRoute1_3['3.0.0.2'] = dict()
    ExpRouteDictIpv4StaticRoute1_3['3.0.0.2']['Distance'] = '1'
    ExpRouteDictIpv4StaticRoute1_3['3.0.0.2']['Metric'] = '0'
    ExpRouteDictIpv4StaticRoute1_3['3.0.0.2']['RouteType'] = 'static'

    ExpRouteDictIpv4StaticRoute1_2 = dict()
    ExpRouteDictIpv4StaticRoute1_2['Route'] = '70.0.0.0' + '/' + '24'
    ExpRouteDictIpv4StaticRoute1_2['NumberNexthops'] = '2'
    ExpRouteDictIpv4StaticRoute1_2['1.0.0.2'] = dict()
    ExpRouteDictIpv4StaticRoute1_2['1.0.0.2']['Distance'] = '1'
    ExpRouteDictIpv4StaticRoute1_2['1.0.0.2']['Metric'] = '0'
    ExpRouteDictIpv4StaticRoute1_2['1.0.0.2']['RouteType'] = 'static'
    ExpRouteDictIpv4StaticRoute1_2['3.0.0.2'] = dict()
    ExpRouteDictIpv4StaticRoute1_2['3.0.0.2']['Distance'] = '1'
    ExpRouteDictIpv4StaticRoute1_2['3.0.0.2']['Metric'] = '0'
    ExpRouteDictIpv4StaticRoute1_2['3.0.0.2']['RouteType'] = 'static'

    ExpRouteDictIpv4StaticRoute2 = dict()
    ExpRouteDictIpv4StaticRoute2['Route'] = '80.0.0.0' + '/' + '24'
    ExpRouteDictIpv4StaticRoute2['NumberNexthops'] = '1'
    ExpRouteDictIpv4StaticRoute2['1.0.0.2'] = dict()
    ExpRouteDictIpv4StaticRoute2['1.0.0.2']['Distance'] = '1'
    ExpRouteDictIpv4StaticRoute2['1.0.0.2']['Metric'] = '0'
    ExpRouteDictIpv4StaticRoute2['1.0.0.2']['RouteType'] = 'static'

    LogOutput('info', "Checking for sanity of config in switch01")
    switch = kwargs.get('switch', None)

    #verify the ecmp route in sh ip route
    verify_route_in_show_route(switch, True, ExpRouteDictIpv4StaticRoute1_3, 'static')
    verify_route_in_show_route(switch, True, ExpRouteDictIpv4StaticRoute2, 'static')
    validate_ecmp_check_status(switch, 3)

    LogOutput('info', "Disabling interface1 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch,
        enable=False,
        interface=switch.linkPortMapping['lnk02'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface1 on switch1"

    #verify the ecmp route in sh ip route
    verify_route_in_show_route(switch, True, ExpRouteDictIpv4StaticRoute1_2, 'static')
    verify_route_in_show_route(switch, False, ExpRouteDictIpv4StaticRoute2, 'static')
    validate_ecmp_check_status(switch, 2)

    LogOutput('info', "Enabling interface1 on switch01")
    retStruct = InterfaceEnable(
        deviceObj=switch,
        enable=True,
        interface=switch.linkPortMapping['lnk02'])
    retCode = retStruct.returnCode()
    assert retCode == 0, "Unable to enable interface1 on switch1"

    LogOutput('info', "Configuring ipv4 address 2.0.0.1 on interface 2 switch 1")
    retStruct = InterfaceIpConfig(
        deviceObj=switch,
        interface=switch.linkPortMapping['lnk02'],
        addr="2.0.0.1",
        mask=24,
        config=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to configure an ipv4 address on intf 2 on switch 1"

    #verify the ecmp route in sh ip route
    verify_route_in_show_route(switch, True, ExpRouteDictIpv4StaticRoute1_3, 'static')
    verify_route_in_show_route(switch, True, ExpRouteDictIpv4StaticRoute2, 'static')
    validate_ecmp_check_status(switch, 3)

class Test_interface_shut_noshut_ct:

    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_interface_shut_noshut_ct.testObj = testEnviron(topoDict=topoDict)
        # Get topology object
        Test_interface_shut_noshut_ct.topoObj = Test_interface_shut_noshut_ct.testObj.topoObjGet()

    def teardown_class(cls):
        Test_interface_shut_noshut_ct.topoObj.terminate_nodes()

    def test_interface_shut_noshut_ct(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        dut02Obj = self.topoObj.deviceObjGet(device="dut02")
        config_creation(
            switch01 = dut01Obj,
            switch02 = dut02Obj)
        intf_shut_noshut_test(switch=dut01Obj)
