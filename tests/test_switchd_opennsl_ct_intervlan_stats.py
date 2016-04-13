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
import time
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch.OVS import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoType": "physical",
            "topoTarget": "dut01",
            "topoDevices": "dut01 wrkston01 wrkston02 wrkston03 wrkston04",
            "topoLinks": "lnk01:dut01:wrkston01,lnk02:dut01:wrkston02,lnk03:dut01:wrkston03,lnk04:dut01:wrkston04",
            "topoFilters": "dut01:system-category:switch,wrkston01:system-category:workstation,wrkston02:system-category:workstation,wrkston03:system-category:workstation,wrkston04:system-category:workstation"}

def ping_vlan(**kwargs):
    switch = kwargs.get('switch',None)
    host1 = kwargs.get('host1',None)
    host2 = kwargs.get('host2',None)
    host3 = kwargs.get('host3',None)
    host4 = kwargs.get('host4',None)



    #TEST_DESCRIPTION = "Virtual Topology / Physical Topology Sample Test"

    #Enabling interfaces
    LogOutput('info', "Enabling interface1 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, interface=switch.linkPortMapping['lnk01'])
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interafce on switch1"


    LogOutput('info', "Enabling interface2 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, interface=switch.linkPortMapping['lnk02'])
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interafce on switch1"

    LogOutput('info', "Enabling interface3 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, interface=switch.linkPortMapping['lnk03'])
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interafce on switch1"

    LogOutput('info', "Enabling interface4 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, interface=switch.linkPortMapping['lnk04'])
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interafce on switch1"


    LogOutput('info', "Enabling interface vlan 10 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, vlan=10)
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interface on switch"

    LogOutput('info', "Enabling interface vlan 20 on switch")
    retStruct = InterfaceEnable(deviceObj=switch, enable=True, vlan=20)
    retCode = retStruct.returnCode()
    assert retCode==0, "Unable to enable interface on switch"

    interface1=int(switch.linkPortMapping['lnk01'])

    interface2=int(switch.linkPortMapping['lnk02'])

    interface3=int(switch.linkPortMapping['lnk03'])

    interface4=int(switch.linkPortMapping['lnk04'])

    returnStructure = switch.VtyshShell(enter=True)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to get vtysh config prompt"

    returnStructure = switch.ConfigVtyShell(enter=True)

    LogOutput('info', "Configuring VLAN 10")
    returnStructure =switch.DeviceInteract(command="vlan 10")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to enter interface context for vlan"

    returnStructure =switch.DeviceInteract(command="no shutdown")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"

    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit vlan"

    LogOutput('info', "Configuring VLAN 20")
    returnStructure =switch.DeviceInteract(command="vlan 20")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to enter interface context for vlan"

    returnStructure =switch.DeviceInteract(command="no shutdown")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"
    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit vlan"

    LogOutput('info', "Configuring interface %d to VLAN 10"%interface1)
    returnStructure =switch.DeviceInteract(command="interface %d"%interface1)
    retCode = returnStructure['returnCode']
    assert returnCode==0, "Failed to enter interface context"

    returnStructure =switch.DeviceInteract(command="no routing")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"

    returnStructure =switch.DeviceInteract(command="no shutdown")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"

    returnStructure =switch.DeviceInteract(command="vlan access 10")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform vlan access"

    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit interface"

    LogOutput('info', "Configuring interface %d to VLAN 10"%interface2)
    returnStructure =switch.DeviceInteract(command="interface %d"%interface2)
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to enter interface context"

    returnStructure =switch.DeviceInteract(command="no routing")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no routing"

    returnStructure =switch.DeviceInteract(command="no shutdown")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"

    returnStructure =switch.DeviceInteract(command="vlan access 10")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform vlan access"

    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit interface"

    LogOutput('info', "Configuring interface %d to VLAN 20"%interface3)
    returnStructure =switch.DeviceInteract(command="interface %d"%interface3)
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to enter interface context"

    returnStructure =switch.DeviceInteract(command="no routing")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no routing"

    returnStructure =switch.DeviceInteract(command="no shutdown")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform no shut"

    returnStructure =switch.DeviceInteract(command="vlan access 20")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to perform vlan access"

    returnStructure = switch.DeviceInteract(command="exit")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to exit interface"

    returnStructure = switch.ConfigVtyShell(enter=False)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to exit vtysh config prompt"

    returnStructure = switch.VtyshShell(enter=False)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to exit vtysh prompt"

    LogOutput('info', "Configuring ipv4 address 10.0.0.1 on interface vlan10")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=10, addr="10.0.0.1", mask=24, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address on vlan address"


    LogOutput('info', "Configuring ipv6 address 1000::1 on interface vlan10")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=10, addr="1000::1", mask=120, ipv6flag=True, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address on vlan"

    LogOutput('info', "Configuring ipv4 address 20.0.0.1 on interface vlan20")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=20, addr="20.0.0.1", mask=24, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address on vlan address"

    LogOutput('info', "Configuring ipv6 address 2000::1 on interface vlan20")
    retStruct = InterfaceIpConfig(deviceObj=switch, vlan=20, addr="2000::1", mask=120, ipv6flag=True, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address on vlan"



    LogOutput('info', "Configuring ipv4 address 30.0.0.1 on interface %s"%switch.linkPortMapping['lnk04'])
    retStruct = InterfaceIpConfig(deviceObj=switch, interface=switch.linkPortMapping['lnk04'], addr="30.0.0.1", mask=24, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address"

    LogOutput('info', "Configuring ipv6 address 3000:1 on interface %s"%switch.linkPortMapping['lnk04'])
    retStruct = InterfaceIpConfig(deviceObj=switch, interface=switch.linkPortMapping['lnk04'], addr="3000::1", mask=120, ipv6flag=True, config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address"


    #Configure host 1

    LogOutput('info',"\n\n\nConfiguring host 1 ipv4")
    retStruct = host1.NetworkConfig(ipAddr="10.0.0.9", netMask="255.255.255.0", interface=host1.linkPortMapping['lnk01'], broadcast="10.255.255.255", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address"

    LogOutput('info',"\n\n\nConfiguring host 1 ipv6")
    retStruct = host1.Network6Config(ipAddr="1000::9", netMask=120, interface=host1.linkPortMapping['lnk01'], broadcast="1000::0", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address"

    retStruct = host1.IPRoutesConfig(config=True, destNetwork="0.0.0.0", netMask=24, gateway="10.0.0.1")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv4 address route")
        caseReturnCode = 1

    retStruct = host1.IPRoutesConfig(config=True, destNetwork="::", netMask=120, gateway="1000::1", ipv6Flag=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv6 address route")
        caseReturnCode = 1

    #Configure host 2

    LogOutput('info',"\n\n\nConfiguring host 2 ipv4")
    retStruct = host2.NetworkConfig(ipAddr="10.0.0.10", netMask="255.255.255.0", interface=host2.linkPortMapping['lnk02'], broadcast="10.255.255.255", config=True )
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address"

    LogOutput('info',"\n\n\nConfiguring host 2 ipv6")
    retStruct = host2.Network6Config(ipAddr="1000::10", netMask=120, interface=host2.linkPortMapping['lnk02'], broadcast="1000::0", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address"

    retStruct = host2.IPRoutesConfig(config=True, destNetwork="0.0.0.0", netMask=24, gateway="10.0.0.1")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv4 address route")
        caseReturnCode = 1

    retStruct = host2.IPRoutesConfig(config=True, destNetwork="::", netMask=120, gateway="1000::1", ipv6Flag=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv6 address route")
        caseReturnCode = 1


    #Configure host 3

    LogOutput('info',"\n\n\nConfiguring host 3 ipv4")
    retStruct = host3.NetworkConfig(ipAddr="20.0.0.10", netMask="255.255.255.0", interface=host3.linkPortMapping['lnk03'], broadcast="20.255.255.255", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address"

    LogOutput('info',"\n\n\nConfiguring host 3 ipv6")
    retStruct = host3.Network6Config(ipAddr="2000::10", netMask=120, interface=host3.linkPortMapping['lnk03'], broadcast="2000::0", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address"

    retStruct = host3.IPRoutesConfig(config=True, destNetwork="0.0.0.0", netMask=24, gateway="20.0.0.1")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv4 address route")
        caseReturnCode = 1

    retStruct = host3.IPRoutesConfig(config=True, destNetwork="::", netMask=120, gateway="2000::1", ipv6Flag=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv6 address route")
        caseReturnCode = 1

    #Configure host 4

    LogOutput('info',"\n\n\nConfiguring host 4 ipv4")
    retStruct = host4.NetworkConfig(ipAddr="30.0.0.10", netMask="255.255.255.0", interface=host4.linkPortMapping['lnk04'], broadcast="30.0.0.0", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv4 address"

    LogOutput('info',"\n\n\nConfiguring host 4 ipv6")
    retStruct = host4.Network6Config(ipAddr="3000::10", netMask=120, interface=host4.linkPortMapping['lnk04'], broadcast="3000::0", config=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "Failed to configure an ipv6 address"

    retStruct = host4.IPRoutesConfig(config=True, destNetwork="0.0.0.0", netMask=24, gateway="30.0.0.1")
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv4 address route")
        caseReturnCode = 1

    retStruct = host4.IPRoutesConfig(config=True, destNetwork="::", netMask=120, gateway="3000::1", ipv6Flag=True)
    retCode = retStruct.returnCode()
    if retCode:
        LogOutput('error', "\nFailed to configure ipv6 address route")
        caseReturnCode = 1


    #Ping From Host1 to Host 2
    retStruct = host1.Ping(ipAddr="10.0.0.10", packetCount=10)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv4 ping 10 packets, Case Failed #####"
    LogOutput('info',"\n##### Ping 10 packets Passed, Case Passed #####\n\n")

    time.sleep(7)
    returnStructure = switch.DeviceInteract(command="ovs-vsctl list interface vlan10")
    buf = returnStructure.get('buffer')
    for curLine in buf.split('\n'):
        if "tx_packets" in curLine:
            txp = curLine.split('tx_packets=')[1]
            actxp = txp.split('}')[0]
            assert int(actxp) < 3, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

        if "rx_packets" in curLine:
            rxp = curLine.split('rx_packets=')[1]
            acrxp = rxp.split(',')[0]
            assert int(acrxp) < 3, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

    retStruct = host1.Ping(ipAddr="1000::10", packetCount=1, ipv6Flag=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv6 ping, Case Failed #####"
    LogOutput('info',"\n##### Ping Passed, Case Passed #####\n\n")

    #Ping from host 1 to host 3
    retStruct = host1.Ping(ipAddr="20.0.0.10", packetCount=10)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv4 ping 10 packets, Case Failed #####"
    LogOutput('info',"\n##### Ping 10 packets Passed, Case Passed #####\n\n")

    time.sleep(7)
    returnStructure = switch.DeviceInteract(command="ovs-vsctl list interface vlan10")
    buf = returnStructure.get('buffer')
    for curLine in buf.split('\n'):
        if "tx_packets" in curLine:
            txp = curLine.split('tx_packets=')[1]
            actxp = txp.split('}')[0]
            assert int(actxp) > 7, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

        if "rx_packets" in curLine:
            rxp = curLine.split('rx_packets=')[1]
            acrxp = rxp.split(',')[0]
            assert int(acrxp) > 7, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

    returnStructure = switch.DeviceInteract(command="ovs-vsctl list interface vlan20")
    buf = returnStructure.get('buffer')
    for curLine in buf.split('\n'):
        if "tx_packets" in curLine:
            txp = curLine.split('tx_packets=')[1]
            actxp = txp.split('}')[0]
            assert int(actxp) > 7, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

        if "rx_packets" in curLine:
            rxp = curLine.split('rx_packets=')[1]
            acrxp = rxp.split(',')[0]
            assert int(acrxp) > 7, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

    retStruct = host1.Ping(ipAddr="2000::10", packetCount=1, ipv6Flag=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv6 ping, Case Failed #####"
    LogOutput('info',"\n##### Ping Passed, Case Passed #####\n\n")

    #Ping form host 1 to host 4
    retStruct = host1.Ping(ipAddr="30.0.0.10", packetCount=10)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv4 ping 10 packets, Case Failed #####"
    LogOutput('info',"\n##### Ping 10 packets Passed, Case Passed #####\n\n")

    time.sleep(7)
    returnStructure = switch.DeviceInteract(command="ovs-vsctl list interface vlan10")
    buf = returnStructure.get('buffer')
    for curLine in buf.split('\n'):
        if "tx_packets" in curLine:
            txp = curLine.split('tx_packets=')[1]
            actxp = txp.split('}')[0]
            assert int(actxp) > 16, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

        if "rx_packets" in curLine:
            rxp = curLine.split('rx_packets=')[1]
            acrxp = rxp.split(',')[0]
            assert int(acrxp) > 16, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

    retStruct = host1.Ping(ipAddr="3000::10", packetCount=1, ipv6Flag=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv6 ping , Case Failed #####"
    LogOutput('info',"\n##### Ping Passed, Case Passed #####\n\n")

    #Ping form host 3 to host 2
    retStruct = host3.Ping(ipAddr="10.0.0.10", packetCount=10)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv4 ping 10 packets, Case Failed #####"
    LogOutput('info',"\n##### Ping 10 packets Passed, Case Passed #####\n\n")

    time.sleep(7)
    returnStructure = switch.DeviceInteract(command="ovs-vsctl list interface vlan10")
    buf = returnStructure.get('buffer')
    for curLine in buf.split('\n'):
        if "tx_packets" in curLine:
            txp = curLine.split('tx_packets=')[1]
            actxp = txp.split('}')[0]
            assert int(actxp) > 26, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

        if "rx_packets" in curLine:
            rxp = curLine.split('rx_packets=')[1]
            acrxp = rxp.split(',')[0]
            assert int(acrxp) > 26, "\n##### Failed stats #####"
            LogOutput('info',"\n##### Passed stats #####\n\n")

    #Unconfiguring vlans

    returnStructure = switch.VtyshShell(enter=True)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to get vtysh config prompt"

    returnStructure = switch.ConfigVtyShell(enter=True)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to get vtysh config prompt"

    LogOutput('info',"Unconfiguring vlan 10\n")
    returnStructure =switch.DeviceInteract(command="no interface vlan 10")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to remove interface vlan"

    LogOutput('info',"Unconfiguring vlan 20\n")
    returnStructure =switch.DeviceInteract(command="no interface vlan 20")
    retCode = returnStructure['returnCode']
    assert retCode==0, "Failed to remove interface vlan"

    returnStructure = switch.ConfigVtyShell(enter=False)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to exit vtysh config prompt"

    returnStructure = switch.VtyshShell(enter=False)
    returnCode = returnStructure.returnCode()
    assert returnCode==0, "Failed to exit vtysh prompt"

    #Testing Ping from Host 1 to Host 2 and Host 1 to Host 3

    LogOutput('info',"\n\n\n########Ping after unconfig#########")

    retStruct = host1.Ping(ipAddr="10.0.0.10", packetCount=1)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv4 ping, Case Failed #####"
    LogOutput('info',"\n##### Ping Passed, Case Passed #####\n\n")


    retStruct = host1.Ping(ipAddr="1000::10", packetCount=1, ipv6Flag=True)
    retCode = retStruct.returnCode()
    assert retCode==0, "\n##### Failed to do IPv6 ping, Case Failed #####"
    LogOutput('info',"\n##### Ping Passed. Case passed #####\n\n")

    #Ping from Host 1 to Host 3
    retStruct = host1.Ping(ipAddr="20.0.0.10", packetCount=1)
    retCode = retStruct.returnCode()
    assert retCode!=0, "\n##### Ping Passed, Case Failed #####"
    LogOutput('info',"\n##### Failed to do IPv6 ping, Case Passed #####\n\n")


    retStruct = host1.Ping(ipAddr="2000::10", packetCount=1, ipv6Flag=True)
    retCode = retStruct.returnCode()
    assert retCode!=0, "\n##### Ping Passed, Case Failed #####"
    LogOutput('info',"\n##### Failed to do IPv6 ping, Case Passed #####\n\n")

class Test_vlan_ping:
    def setup_class (cls):
        # Test object will parse command line and formulate the env
        Test_vlan_ping.testObj = testEnviron(topoDict=topoDict)
        #    Get topology object
        Test_vlan_ping.topoObj = Test_vlan_ping.testObj.topoObjGet()
    def teardown_class (cls):
        Test_vlan_ping.topoObj.terminate_nodes()

    def test_ping_vlan(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        wrkston01Obj = self.topoObj.deviceObjGet(device="wrkston01")
        wrkston02Obj = self.topoObj.deviceObjGet(device="wrkston02")
        wrkston03Obj = self.topoObj.deviceObjGet(device="wrkston03")
        wrkston04Obj = self.topoObj.deviceObjGet(device="wrkston04")
        ping_vlan(switch=dut01Obj, host1=wrkston01Obj, host2=wrkston02Obj, host3=wrkston03Obj, host4=wrkston04Obj)
