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
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}


AllRoutersIP = "224.0.0.5"
DesignatedRoutersIP = "224.0.0.6"
AllRoutersMAC = "1:0:5e:0:0:5"
DesignatedRoutersMAC = "1:0:5e:0:0:6"
OSPFProtocol = "0x59"

def ospf_fp_test(**kwargs):

    switch = kwargs.get('switch', None)
    LogOutput('info', 'Verify OSPF FPs are programmed in ASIC')

    appctl_command = "ovs-appctl plugin/debug fp"
    retStruct = switch.DeviceInteract(command=appctl_command)
    buf = retStruct.get('buffer')
    LogOutput('info', str(buf))
    lines = buf.split('\n')

    # These counters are used to ensure correct count of
    # OSPF field processor entries in the output of ovs-appctl command
    OSPFProtocol_count = 0
    AllRoutersIP_count = 0
    AllRoutersMAC_count = 0
    DesignatedRoutersIP_count = 0
    DesignatedRoutersMAC_count = 0

    for line in lines:
        if 'IpProtocol' in line and OSPFProtocol in line:
            OSPFProtocol_count = OSPFProtocol_count + 1
        if 'DstIp' in line and AllRoutersIP in line:
            AllRoutersIP_count = AllRoutersIP_count + 1
        if 'DstMac' in line and AllRoutersMAC in line:
            AllRoutersMAC_count = AllRoutersMAC_count + 1
        if 'DstIp' in line and DesignatedRoutersIP in line:
            DesignatedRoutersIP_count = DesignatedRoutersIP_count + 1
        if 'DstMac' in line and DesignatedRoutersMAC in line:
            DesignatedRoutersMAC_count = DesignatedRoutersMAC_count + 1


    assert OSPFProtocol in buf, 'OSPF Protocol mising'
    LogOutput('info', 'Verified OSPF Protocol entry')

    assert OSPFProtocol_count == 2, 'More than 2 occurences of OSPF Protocol'
    LogOutput('info', 'Verified OSPF Protocol count')

    assert AllRoutersIP in buf and AllRoutersMAC in buf,\
          'All Routers OSPF field entry missing'
    LogOutput('info', 'Verified All Routers OSPF field entry')

    assert AllRoutersIP_count == 1 and AllRoutersMAC_count == 1,\
          'More than 1 occurence of All Routers OSPF field entry'
    LogOutput('info', 'Verified All Routers OSPF field entry count')

    assert DesignatedRoutersIP in buf and DesignatedRoutersMAC in buf,\
           'Designated Routers OSPF field entry missing'
    LogOutput('info', 'Verified Designated Routers OSPF field entry')

    assert DesignatedRoutersIP_count == 1 and DesignatedRoutersMAC_count == 1,\
           'More than 1 occurence of Designated Routers OSPF field entry'
    LogOutput('info', 'Verified Designated Routers OSPF field entry count')


class Test_ospf_ct:

    def setup_class(cls):
        Test_ospf_ct.testObj = testEnviron(topoDict=topoDict)
        Test_ospf_ct.topoObj = Test_ospf_ct.testObj.topoObjGet()

    def teardown_class(cls):
        Test_ospf_ct.topoObj.terminate_nodes()

    def test_ospf(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        ospf_fp_test(switch=dut01Obj)
