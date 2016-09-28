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

from itertools import repeat
import re
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

# Common constants
CPUQueueNewAction = 'CosQ CPU New'
RedPacketsDropAction = 'Red Packets Drop'
OutPortMask = '0x(.*)f'
CPUQueueMask = '0x3f'
IPProtocolTCP = '0x06'
IPProtocolUDP = '0x11'
IPProtocolICMPv4 = '0x01'
IPProtocolICMPv6 = '0x3a'
IPProtocolOSPFv2 = '0x59'
IPBroadcastAddr = '255.255.255.255'
IPMulticastAddr = '224.0.0.0'
IPv6MulticastAddr = 'ff00::'

# OSPF related constants
OSPFAllRoutersIP = '224.0.0.5'
OSPFDesignatedRoutersIP = '224.0.0.6'
OSPFAllRoutersMAC = '1:0:5e:0:0:5'
OSPFDesignatedRoutersMAC = '1:0:5e:0:0:6'

# ARP related constants
ARPEtherType = '0x806'

# LACP related constants
LACPMacAddr = '1:80:c2:0:0:2'

# LLDP related constants
LLDPMacAddr = ['1:80:c2:0:0:e', '1:80:c2:0:0:3', '1:80:c2:0:0:0']
LLDPEtherType = "0x88cc"

# STP related constants
STPMacAddr = '1:80:c2:0:0:0'

# BGP related constants
BGPL4Port = '0xb3'

# DHCPv4 related constants
DHCPv4L4Port = '0x43'

# DHCPv6 related constants
DHCPv6L4Port = '0x223'


# This function takes a "fp show" output (fp_show_dump) and the qualifier
# rule dictionary (fp_rule_dict) and checks if there exists a "fp entry"
# in hardware which contains all the "fp qualifier rules" passed in the
# dictionary (fp_rule_dict).
def if_fp_rule_exists_with_values_in_fp_dump(fp_show_dump, fp_rule_dict):

    # If the show output is not valid, then return False
    # from this function
    if fp_show_dump is None:
        LogOutput('info', 'The show output is None')
        return(False)

    # If the FP rule dictionary is not valid, then return False
    # from this function
    if fp_rule_dict is None:
        LogOutput('info', 'The FP rule dictionary is None')
        return(False)

    # Assume that we did not find any match FP rule in the show
    # output.
    some_matching_rule_found = False

    # Iterate over all the FP rules in the "fp show" command dump.
    # The FP rules are separated by "=====".
    for matchEntry in re.finditer(r'(?=(=====)(.*?)(=====))',
                                  fp_show_dump, re.S):

        # Split the second entry of the matches seen in the
        # regular expression.
        lines = matchEntry.group(2).split('\n')

        # Assume that we have not found any of the FP qualifers
        # in the current FP entry.
        fp_qualifier_present_in_rule = list(repeat(False,
                                                   len(fp_rule_dict)))

        index = 0
        # Iterate through each qualifer in the FP rule dictionary.
        for key, value in fp_rule_dict.items():

            # Prepare the pattern at match on from the FP rule
            # dictionary
            pattern = "(.*)(%s)(.*)(%s)(.*)(%s)(.*)" %(str(key),
                           str(value.get('data')), str(value.get('mask')))

            LogOutput('dbg', "The regex pattern is: " + pattern)

            # Iterate through all the lines in the FP entry to check
            # if the pattern exists in one of the lines.
            for line in lines:

                # Try to match the line against the pattern
                matchedline = re.match(pattern, line)

                # If ta match is found, then record that the FP qualifer
                # is found.
                if matchedline is not None:
                    LogOutput('dbg', "Found a match in line:  " + line)
                    fp_qualifier_present_in_rule[index] = True

            index = index + 1

        # Check if all the FP qualifers were found in the FP entry
        # in the show output
        some_matching_rule_found = True
        for i in range(len(fp_qualifier_present_in_rule)):
            if fp_qualifier_present_in_rule[i] is False:
                some_matching_rule_found =False
                break

        # If a matching entry is found, then break from
        # this loop
        if some_matching_rule_found is True:
            LogOutput('dbg', "The matching FP entry is: " +
                      str(matchEntry.group(2)))
            break

    # Return if a matching entry is found or not.
    return some_matching_rule_found


def add_stat_types_to_fp_rule_dict(fp_rule_dict):

    if fp_rule_dict is None:
        LogOutput('info', 'FP rule dictionary is empty')
        return

    fp_rule_dict['Green Bytes'] = dict()
    fp_rule_dict['Green Bytes']['data'] = ''
    fp_rule_dict['Green Bytes']['mask'] = ''
    fp_rule_dict['Green Packets'] = dict()
    fp_rule_dict['Green Packets']['data'] = ''
    fp_rule_dict['Green Packets']['mask'] = ''
    fp_rule_dict['Red Bytes'] = dict()
    fp_rule_dict['Red Bytes']['data'] = ''
    fp_rule_dict['Red Bytes']['mask'] = ''
    fp_rule_dict['Red Packets'] = dict()
    fp_rule_dict['Red Packets']['data'] = ''
    fp_rule_dict['Red Packets']['mask'] = ''


def fp_ingress_test_broadcast_arp_rule(**kwargs):

    LogOutput('info', 'Verify broadcast ARP FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    broadcast_arp_dict = dict()
    broadcast_arp_dict['Ingress'] = dict()
    broadcast_arp_dict['Ingress']['data'] = ''
    broadcast_arp_dict['Ingress']['mask'] = ''
    broadcast_arp_dict['Ethertype'] = dict()
    broadcast_arp_dict['Ethertype']['data'] = ARPEtherType
    broadcast_arp_dict['Ethertype']['mask'] = '0xffff'
    broadcast_arp_dict['PacketRes'] = dict()
    broadcast_arp_dict['PacketRes']['data'] = 'Broadcast ARP'
    broadcast_arp_dict['PacketRes']['mask'] = '0x3f'
    broadcast_arp_dict['Action'] = dict()
    broadcast_arp_dict['Action']['data'] = CPUQueueNewAction
    broadcast_arp_dict['Action']['mask'] = ''
    broadcast_arp_dict['CPUQueueNumber'] = dict()
    broadcast_arp_dict['CPUQueueNumber']['data'] = '4'
    broadcast_arp_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, broadcast_arp_dict)

    assert ret is True, "Ingress FP rule check failed for broadcast ARP"

    LogOutput('info', "Ingress FP rule check passed for broadcast ARP")


def fp_egress_test_broadcast_arp_rule(**kwargs):

    LogOutput('info', 'Verify broadcast ARP FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    broadcast_arp_dict = dict()
    broadcast_arp_dict['Egress'] = dict()
    broadcast_arp_dict['Egress']['data'] = ''
    broadcast_arp_dict['Egress']['mask'] = ''
    broadcast_arp_dict['Ethertype'] = dict()
    broadcast_arp_dict['Ethertype']['data'] = ARPEtherType
    broadcast_arp_dict['Ethertype']['mask'] = '0xffff'
    broadcast_arp_dict['DstMac'] = dict()
    broadcast_arp_dict['DstMac']['data'] = 'ff:ff:ff:ff:ff:ff'
    broadcast_arp_dict['DstMac']['mask'] = 'ff:ff:ff:ff:ff:ff'
    broadcast_arp_dict['Outport'] = dict()
    broadcast_arp_dict['Outport']['data'] = '0x00'
    broadcast_arp_dict['Outport']['mask'] = OutPortMask
    broadcast_arp_dict['CPUQueue'] = dict()
    broadcast_arp_dict['CPUQueue']['data'] = '0x04'
    broadcast_arp_dict['CPUQueue']['mask'] = CPUQueueMask
    broadcast_arp_dict['Action'] = dict()
    broadcast_arp_dict['Action']['data'] = RedPacketsDropAction
    broadcast_arp_dict['Action']['mask'] = ''
    broadcast_arp_dict['Value'] = dict()
    broadcast_arp_dict['Value']['data'] = '0'
    broadcast_arp_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(broadcast_arp_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, broadcast_arp_dict)

    assert ret is True, "Egress FP rule check failed for broadcast ARP"

    LogOutput('info', "Egress FP rule check passed for broadcast ARP")


def fp_ingress_test_unicast_arp_rule(**kwargs):

    LogOutput('info', 'Verify unicast ARP FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    unicast_arp_dict = dict()
    unicast_arp_dict['Ingress'] = dict()
    unicast_arp_dict['Ingress']['data'] = ''
    unicast_arp_dict['Ingress']['mask'] = ''
    unicast_arp_dict['Ethertype'] = dict()
    unicast_arp_dict['Ethertype']['data'] = ARPEtherType
    unicast_arp_dict['Ethertype']['mask'] = '0xffff'

    # TODO: This needs to be uncommented when the support for
    #       unicast ARP PacketRes API is restored.
    # unicast_arp_dict['PacketRes'] = dict()
    # unicast_arp_dict['PacketRes']['data'] = 'Unicast ARP'
    # unicast_arp_dict['PacketRes']['mask'] = '0x3f'
    unicast_arp_dict['Action'] = dict()
    unicast_arp_dict['Action']['data'] = CPUQueueNewAction
    unicast_arp_dict['Action']['mask'] = ''
    unicast_arp_dict['CPUQueueNumber'] = dict()
    unicast_arp_dict['CPUQueueNumber']['data'] = '5'
    unicast_arp_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, unicast_arp_dict)

    assert ret is True, "Ingress FP rule check failed for unicast ARP"

    LogOutput('info',  "Ingress FP rule check passed for unicast ARP")


def fp_egress_test_unicast_arp_rule(**kwargs):

    LogOutput('info', 'Verify unicast ARP FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    unicast_arp_dict = dict()
    unicast_arp_dict['Egress'] = dict()
    unicast_arp_dict['Egress']['data'] = ''
    unicast_arp_dict['Egress']['mask'] = ''
    unicast_arp_dict['Ethertype'] = dict()
    unicast_arp_dict['Ethertype']['data'] = ARPEtherType
    unicast_arp_dict['Ethertype']['mask'] = '0xffff'
    unicast_arp_dict['Outport'] = dict()
    unicast_arp_dict['Outport']['data'] = '0x00'
    unicast_arp_dict['Outport']['mask'] = OutPortMask
    unicast_arp_dict['CPUQueue'] = dict()
    unicast_arp_dict['CPUQueue']['data'] = '0x05'
    unicast_arp_dict['CPUQueue']['mask'] = CPUQueueMask
    unicast_arp_dict['Action'] = dict()
    unicast_arp_dict['Action']['data'] = RedPacketsDropAction
    unicast_arp_dict['Action']['mask'] = ''
    unicast_arp_dict['Value'] = dict()
    unicast_arp_dict['Value']['data'] = '0'
    unicast_arp_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(unicast_arp_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, unicast_arp_dict)

    assert ret is True, "Egress FP rule check failed for unicast ARP"

    LogOutput('info',  "Egress FP rule check passed for unicast ARP")


def fp_ingress_test_lacp_rule(**kwargs):

    LogOutput('info', 'Verify LACP FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    lacp_dict = dict()
    lacp_dict['Ingress'] = dict()
    lacp_dict['Ingress']['data'] = ''
    lacp_dict['Ingress']['mask'] = ''
    lacp_dict['DstMac'] = dict()
    lacp_dict['DstMac']['data'] = LACPMacAddr
    lacp_dict['DstMac']['mask'] = 'ff:ff:ff:ff:ff:ff'
    lacp_dict['Action'] = dict()
    lacp_dict['Action']['data'] = CPUQueueNewAction
    lacp_dict['Action']['mask'] = ''
    lacp_dict['CPUQueueNumber'] = dict()
    lacp_dict['CPUQueueNumber']['data'] = '8'
    lacp_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, lacp_dict)

    assert ret is True, "Ingress FP rule check failed for LACP"

    LogOutput('info',  "Ingress FP rule check passed for LACP")


def fp_egress_test_lacp_rule(**kwargs):

    LogOutput('info', 'Verify LACP FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    lacp_dict = dict()
    lacp_dict['Egress'] = dict()
    lacp_dict['Egress']['data'] = ''
    lacp_dict['Egress']['mask'] = ''
    lacp_dict['DstMac'] = dict()
    lacp_dict['DstMac']['data'] = LACPMacAddr
    lacp_dict['DstMac']['mask'] = 'ff:ff:ff:ff:ff:ff'
    lacp_dict['Outport'] = dict()
    lacp_dict['Outport']['data'] = '0x00'
    lacp_dict['Outport']['mask'] = OutPortMask
    lacp_dict['CPUQueue'] = dict()
    lacp_dict['CPUQueue']['data'] = '0x08'
    lacp_dict['CPUQueue']['mask'] = CPUQueueMask
    lacp_dict['Action'] = dict()
    lacp_dict['Action']['data'] = RedPacketsDropAction
    lacp_dict['Action']['mask'] = ''
    lacp_dict['Value'] = dict()
    lacp_dict['Value']['data'] = '0'
    lacp_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(lacp_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, lacp_dict)

    assert ret is True, "Egress FP rule check failed for LACP"

    LogOutput('info',  "Egress FP rule check passed for LACP")


def fp_ingress_test_lldp_rule(**kwargs):

    LogOutput('info', 'Verify LLDP FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    for i in range(len(LLDPMacAddr)):
        lldp_dict = dict()
        lldp_dict['Ingress'] = dict()
        lldp_dict['Ingress']['data'] = ''
        lldp_dict['Ingress']['mask'] = ''
        lldp_dict['Ethertype'] = dict()
        lldp_dict['Ethertype']['data'] = LLDPEtherType
        lldp_dict['Ethertype']['mask'] = '0xffff'
        lldp_dict['DstMac'] = dict()
        lldp_dict['DstMac']['data'] = LLDPMacAddr[i]
        lldp_dict['DstMac']['mask'] = 'ff:ff:ff:ff:ff:ff'
        lldp_dict['Action'] = dict()
        lldp_dict['Action']['data'] = CPUQueueNewAction
        lldp_dict['Action']['mask'] = ''
        lldp_dict['CPUQueueNumber'] = dict()
        lldp_dict['CPUQueueNumber']['data'] = '8'
        lldp_dict['CPUQueueNumber']['mask'] = '0'

        ret = if_fp_rule_exists_with_values_in_fp_dump(buf, lldp_dict)

        assert ret is True, "Ingress FP rule check failed for LLDP"

    LogOutput('info',  "Ingress FP rule check passed for LLDP")


def fp_egress_test_lldp_rule(**kwargs):

    LogOutput('info', 'Verify LLDP FPs in Egress pipeline')

    buf = kwargs.get('show_buffer', None)

    lldp_dict = dict()
    lldp_dict['Egress'] = dict()
    lldp_dict['Egress']['data'] = ''
    lldp_dict['Egress']['mask'] = ''
    lldp_dict['Ethertype'] = dict()
    lldp_dict['Ethertype']['data'] = LLDPEtherType
    lldp_dict['Ethertype']['mask'] = '0xffff'
    lldp_dict['Outport'] = dict()
    lldp_dict['Outport']['data'] = '0x00'
    lldp_dict['Outport']['mask'] = OutPortMask
    lldp_dict['CPUQueue'] = dict()
    lldp_dict['CPUQueue']['data'] = '0x08'
    lldp_dict['CPUQueue']['mask'] = CPUQueueMask
    lldp_dict['Action'] = dict()
    lldp_dict['Action']['data'] = RedPacketsDropAction
    lldp_dict['Action']['mask'] = ''
    lldp_dict['Value'] = dict()
    lldp_dict['Value']['data'] = '0'
    lldp_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(lldp_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, lldp_dict)

    assert ret is True, "Egress FP rule check failed for LLDP"

    LogOutput('info',  "Egress FP rule check passed for LLDP")


def fp_ingress_test_stp_rule(**kwargs):

    LogOutput('info', 'Verify STP FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    stp_dict = dict()
    stp_dict['Ingress'] = dict()
    stp_dict['Ingress']['data'] = ''
    stp_dict['Ingress']['mask'] = ''
    stp_dict['DstMac'] = dict()
    stp_dict['DstMac']['data'] = STPMacAddr
    stp_dict['DstMac']['mask'] = 'ff:ff:ff:ff:ff:f7'
    stp_dict['Action'] = dict()
    stp_dict['Action']['data'] = CPUQueueNewAction
    stp_dict['Action']['mask'] = ''
    stp_dict['CPUQueueNumber'] = dict()
    stp_dict['CPUQueueNumber']['data'] = '10'
    stp_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, stp_dict)

    assert ret is True, "Ingress FP rule check failed for STP"

    LogOutput('info',  "Ingress FP rule check passed for STP")


def fp_egress_test_stp_rule(**kwargs):

    LogOutput('info', 'Verify STP FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    stp_dict = dict()
    stp_dict['Egress'] = dict()
    stp_dict['Egress']['data'] = ''
    stp_dict['Egress']['mask'] = ''
    stp_dict['DstMac'] = dict()
    stp_dict['DstMac']['data'] = STPMacAddr
    stp_dict['DstMac']['mask'] = 'ff:ff:ff:ff:ff:f7'
    stp_dict['Outport'] = dict()
    stp_dict['Outport']['data'] = '0x00'
    stp_dict['Outport']['mask'] = OutPortMask
    stp_dict['CPUQueue'] = dict()
    stp_dict['CPUQueue']['data'] = '0x0a'
    stp_dict['CPUQueue']['mask'] = CPUQueueMask
    stp_dict['Action'] = dict()
    stp_dict['Action']['data'] = RedPacketsDropAction
    stp_dict['Action']['mask'] = ''
    stp_dict['Value'] = dict()
    stp_dict['Value']['data'] = '0'
    stp_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(stp_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, stp_dict)

    assert ret is True, "Egress FP rule check failed for STP"

    LogOutput('info',  "Egress FP rule check passed for STP")


def fp_ingress_test_bgp_l4_dst_port_rule(**kwargs):

    LogOutput('info', 'Verify BGP L4 dst port FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    bgp_dict = dict()
    bgp_dict['Ingress'] = dict()
    bgp_dict['Ingress']['data'] = ''
    bgp_dict['Ingress']['mask'] = ''
    bgp_dict['L4DstPort'] = dict()
    bgp_dict['L4DstPort']['data'] = BGPL4Port
    bgp_dict['L4DstPort']['mask'] = '0xffff'
    bgp_dict['DstIpLocal'] = dict()
    bgp_dict['DstIpLocal']['data'] = '0x01'
    bgp_dict['DstIpLocal']['mask'] = '0x01'
    bgp_dict['IpProtocol'] = dict()
    bgp_dict['IpProtocol']['data'] = IPProtocolTCP
    bgp_dict['IpProtocol']['mask'] = '0xff'
    bgp_dict['Action'] = dict()
    bgp_dict['Action']['data'] = CPUQueueNewAction
    bgp_dict['Action']['mask'] = ''
    bgp_dict['CPUQueueNumber'] = dict()
    bgp_dict['CPUQueueNumber']['data'] = '9'
    bgp_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, bgp_dict)

    assert ret is True, "Ingress FP rule check failed for BGP L4 dst port"

    LogOutput('info',  "Ingress FP rule check passed for BGP L4 dst port")


def fp_ingress_test_bgp_l4_src_port_rule(**kwargs):

    LogOutput('info', 'Verify BGP L4 src port FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    bgp_dict = dict()
    bgp_dict['Ingress'] = dict()
    bgp_dict['Ingress']['data'] = ''
    bgp_dict['Ingress']['mask'] = ''
    bgp_dict['L4SrcPort'] = dict()
    bgp_dict['L4SrcPort']['data'] = BGPL4Port
    bgp_dict['L4SrcPort']['mask'] = '0xffff'
    bgp_dict['DstIpLocal'] = dict()
    bgp_dict['DstIpLocal']['data'] = '0x01'
    bgp_dict['DstIpLocal']['mask'] = '0x01'
    bgp_dict['IpProtocol'] = dict()
    bgp_dict['IpProtocol']['data'] = IPProtocolTCP
    bgp_dict['IpProtocol']['mask'] = '0xff'
    bgp_dict['Action'] = dict()
    bgp_dict['Action']['data'] = CPUQueueNewAction
    bgp_dict['Action']['mask'] = ''
    bgp_dict['CPUQueueNumber'] = dict()
    bgp_dict['CPUQueueNumber']['data'] = '9'
    bgp_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, bgp_dict)

    assert ret is True, "Ingress FP rule check failed for BGP L4 src port"

    LogOutput('info',  "Ingress FP rule check passed for BGP L4 src port")


def fp_egress_test_bgp_rule(**kwargs):

    LogOutput('info', 'Verify BGP FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    bgp_dict = dict()
    bgp_dict['Egress'] = dict()
    bgp_dict['Egress']['data'] = ''
    bgp_dict['Egress']['mask'] = ''
    bgp_dict['IpProtocol'] = dict()
    bgp_dict['IpProtocol']['data'] = IPProtocolTCP
    bgp_dict['IpProtocol']['mask'] = '0xff'
    bgp_dict['Outport'] = dict()
    bgp_dict['Outport']['data'] = '0x00'
    bgp_dict['Outport']['mask'] = OutPortMask
    bgp_dict['CPUQueue'] = dict()
    bgp_dict['CPUQueue']['data'] = '0x09'
    bgp_dict['CPUQueue']['mask'] = CPUQueueMask
    bgp_dict['Action'] = dict()
    bgp_dict['Action']['data'] = RedPacketsDropAction
    bgp_dict['Action']['mask'] = ''
    bgp_dict['Value'] = dict()
    bgp_dict['Value']['data'] = '0'
    bgp_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(bgp_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, bgp_dict)

    assert ret is True, "Egress FP rule check failed for BGP"

    LogOutput('info',  "Egress FP rule check passed for BGP")


def fp_ingress_test_dhcpv4_rule(**kwargs):

    LogOutput('info', 'Verify DHCPv4 FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    dhcpv4_dict = dict()
    dhcpv4_dict['Ingress'] = dict()
    dhcpv4_dict['Ingress']['data'] = ''
    dhcpv4_dict['Ingress']['mask'] = ''
    dhcpv4_dict['L4DstPort'] = dict()
    dhcpv4_dict['L4DstPort']['data'] = DHCPv4L4Port
    dhcpv4_dict['L4DstPort']['mask'] = '0xffff'
    dhcpv4_dict['IpType'] = dict()
    dhcpv4_dict['IpType']['data'] = 'Any IPv4 packet'
    dhcpv4_dict['IpType']['mask'] = ''
    dhcpv4_dict['IpProtocol'] = dict()
    dhcpv4_dict['IpProtocol']['data'] = IPProtocolUDP
    dhcpv4_dict['IpProtocol']['mask'] = '0xff'
    dhcpv4_dict['Action'] = dict()
    dhcpv4_dict['Action']['data'] = CPUQueueNewAction
    dhcpv4_dict['Action']['mask'] = ''
    dhcpv4_dict['CPUQueueNumber'] = dict()
    dhcpv4_dict['CPUQueueNumber']['data'] = '4'
    dhcpv4_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, dhcpv4_dict)

    assert ret is True, "Ingress FP rule check failed for DHCPv4"

    LogOutput('info',  "Ingress FP rule check passed for DHCPv4")


def fp_egress_test_dhcpv4_rule(**kwargs):

    LogOutput('info', 'Verify DHCPv4 FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    dhcpv4_dict = dict()
    dhcpv4_dict['Egress'] = dict()
    dhcpv4_dict['Egress']['data'] = ''
    dhcpv4_dict['Egress']['mask'] = ''
    dhcpv4_dict['L4DstPort'] = dict()
    dhcpv4_dict['L4DstPort']['data'] = DHCPv4L4Port
    dhcpv4_dict['L4DstPort']['mask'] = '0xffff'
    dhcpv4_dict['IpType'] = dict()
    dhcpv4_dict['IpType']['data'] = 'Any IPv4 packet'
    dhcpv4_dict['IpType']['mask'] = ''
    dhcpv4_dict['IpProtocol'] = dict()
    dhcpv4_dict['IpProtocol']['data'] = IPProtocolUDP
    dhcpv4_dict['IpProtocol']['mask'] = '0xff'
    dhcpv4_dict['Outport'] = dict()
    dhcpv4_dict['Outport']['data'] = '0x00'
    dhcpv4_dict['Outport']['mask'] = OutPortMask
    dhcpv4_dict['CPUQueue'] = dict()
    dhcpv4_dict['CPUQueue']['data'] = '0x04'
    dhcpv4_dict['CPUQueue']['mask'] = CPUQueueMask
    dhcpv4_dict['Action'] = dict()
    dhcpv4_dict['Action']['data'] = RedPacketsDropAction
    dhcpv4_dict['Action']['mask'] = ''
    dhcpv4_dict['Value'] = dict()
    dhcpv4_dict['Value']['data'] = '0'
    dhcpv4_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(dhcpv4_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, dhcpv4_dict)

    assert ret is True, "Egress FP rule check failed for DHCPv4"

    LogOutput('info',  "Egress FP rule check passed for DHCPv4")


def fp_ingress_test_dhcpv6_rule(**kwargs):

    LogOutput('info', 'Verify DHCPv6 FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    dhcpv6_dict = dict()
    dhcpv6_dict['Ingress'] = dict()
    dhcpv6_dict['Ingress']['data'] = ''
    dhcpv6_dict['Ingress']['mask'] = ''
    dhcpv6_dict['L4DstPort'] = dict()
    dhcpv6_dict['L4DstPort']['data'] = DHCPv6L4Port
    dhcpv6_dict['L4DstPort']['mask'] = '0xffff'
    dhcpv6_dict['IpType'] = dict()
    dhcpv6_dict['IpType']['data'] = 'IPv6 packet'
    dhcpv6_dict['IpType']['mask'] = ''
    dhcpv6_dict['IpProtocol'] = dict()
    dhcpv6_dict['IpProtocol']['data'] = IPProtocolUDP
    dhcpv6_dict['IpProtocol']['mask'] = '0xff'
    dhcpv6_dict['Action'] = dict()
    dhcpv6_dict['Action']['data'] = CPUQueueNewAction
    dhcpv6_dict['Action']['mask'] = ''
    dhcpv6_dict['CPUQueueNumber'] = dict()
    dhcpv6_dict['CPUQueueNumber']['data'] = '4'
    dhcpv6_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, dhcpv6_dict)

    assert ret is True, "Ingress FP rule check failed for DHCPv6"

    LogOutput('info',  "Ingress FP rule check passed for DHCPv6")


def fp_egress_test_dhcpv6_rule(**kwargs):

    LogOutput('info', 'Verify DHCPv6 FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    dhcpv6_dict = dict()
    dhcpv6_dict['Egress'] = dict()
    dhcpv6_dict['Egress']['data'] = ''
    dhcpv6_dict['Egress']['mask'] = ''
    dhcpv6_dict['L4DstPort'] = dict()
    dhcpv6_dict['L4DstPort']['data'] = DHCPv6L4Port
    dhcpv6_dict['L4DstPort']['mask'] = '0xffff'
    dhcpv6_dict['IpType'] = dict()
    dhcpv6_dict['IpType']['data'] = 'IPv6 packet'
    dhcpv6_dict['IpType']['mask'] = ''
    dhcpv6_dict['IpProtocol'] = dict()
    dhcpv6_dict['IpProtocol']['data'] = IPProtocolUDP
    dhcpv6_dict['IpProtocol']['mask'] = '0xff'
    dhcpv6_dict['Outport'] = dict()
    dhcpv6_dict['Outport']['data'] = '0x00'
    dhcpv6_dict['Outport']['mask'] = OutPortMask
    dhcpv6_dict['CPUQueue'] = dict()
    dhcpv6_dict['CPUQueue']['data'] = '0x04'
    dhcpv6_dict['CPUQueue']['mask'] = CPUQueueMask
    dhcpv6_dict['Action'] = dict()
    dhcpv6_dict['Action']['data'] = RedPacketsDropAction
    dhcpv6_dict['Action']['mask'] = ''
    dhcpv6_dict['Value'] = dict()
    dhcpv6_dict['Value']['data'] = '0'
    dhcpv6_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(dhcpv6_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, dhcpv6_dict)

    assert ret is True, "Egress FP rule check failed for DHCPv6"

    LogOutput('info',  "Egress FP rule check passed for DHCPv6")


def fp_ingress_test_icmpv4_ucast_rule(**kwargs):

    LogOutput('info', 'Verify ICMPv4 unicast FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    icmpv4_ucast_dict = dict()
    icmpv4_ucast_dict['Ingress'] = dict()
    icmpv4_ucast_dict['Ingress']['data'] = ''
    icmpv4_ucast_dict['Ingress']['mask'] = ''
    icmpv4_ucast_dict['DstIpLocal'] = dict()
    icmpv4_ucast_dict['DstIpLocal']['data'] = '0x01'
    icmpv4_ucast_dict['DstIpLocal']['mask'] = '0x01'
    icmpv4_ucast_dict['IpType'] = dict()
    icmpv4_ucast_dict['IpType']['data'] = 'Any IPv4 packet'
    icmpv4_ucast_dict['IpType']['mask'] = ''
    icmpv4_ucast_dict['IpProtocol'] = dict()
    icmpv4_ucast_dict['IpProtocol']['data'] = IPProtocolICMPv4
    icmpv4_ucast_dict['IpProtocol']['mask'] = '0xff'
    icmpv4_ucast_dict['Action'] = dict()
    icmpv4_ucast_dict['Action']['data'] = CPUQueueNewAction
    icmpv4_ucast_dict['Action']['mask'] = ''
    icmpv4_ucast_dict['CPUQueueNumber'] = dict()
    icmpv4_ucast_dict['CPUQueueNumber']['data'] = '5'
    icmpv4_ucast_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, icmpv4_ucast_dict)

    assert ret is True, "Ingress FP rule check failed for ICMPv4 unicast"

    LogOutput('info',  "Ingress FP rule check passed for ICMPv4 unicast")


def fp_egress_test_icmpv4_ucast_rule(**kwargs):

    LogOutput('info', 'Verify ICMPv4 unicast FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    icmpv4_ucast_dict = dict()
    icmpv4_ucast_dict['Egress'] = dict()
    icmpv4_ucast_dict['Egress']['data'] = ''
    icmpv4_ucast_dict['Egress']['mask'] = ''
    icmpv4_ucast_dict['IpType'] = dict()
    icmpv4_ucast_dict['IpType']['data'] = 'Any IPv4 packet'
    icmpv4_ucast_dict['IpType']['mask'] = ''
    icmpv4_ucast_dict['IpProtocol'] = dict()
    icmpv4_ucast_dict['IpProtocol']['data'] = IPProtocolICMPv4
    icmpv4_ucast_dict['IpProtocol']['mask'] = '0xff'
    icmpv4_ucast_dict['Outport'] = dict()
    icmpv4_ucast_dict['Outport']['data'] = '0x00'
    icmpv4_ucast_dict['Outport']['mask'] = OutPortMask
    icmpv4_ucast_dict['CPUQueue'] = dict()
    icmpv4_ucast_dict['CPUQueue']['data'] = '0x05'
    icmpv4_ucast_dict['CPUQueue']['mask'] = CPUQueueMask
    icmpv4_ucast_dict['Action'] = dict()
    icmpv4_ucast_dict['Action']['data'] = RedPacketsDropAction
    icmpv4_ucast_dict['Action']['mask'] = ''
    icmpv4_ucast_dict['Value'] = dict()
    icmpv4_ucast_dict['Value']['data'] = '0'
    icmpv4_ucast_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(icmpv4_ucast_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, icmpv4_ucast_dict)

    assert ret is True, "Egress FP rule check failed for ICMPv4 unicast"

    LogOutput('info',  "Egress FP rule check passed for ICMPv4 unicast")


def fp_ingress_test_icmpv4_bcast_rule(**kwargs):

    LogOutput('info', 'Verify ICMPv4 broadcast FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    icmpv4_bcast_dict = dict()
    icmpv4_bcast_dict['Ingress'] = dict()
    icmpv4_bcast_dict['Ingress']['data'] = ''
    icmpv4_bcast_dict['Ingress']['mask'] = ''
    icmpv4_bcast_dict['DstIp'] = dict()
    icmpv4_bcast_dict['DstIp']['data'] = IPBroadcastAddr
    icmpv4_bcast_dict['DstIp']['mask'] = IPBroadcastAddr
    icmpv4_bcast_dict['IpType'] = dict()
    icmpv4_bcast_dict['IpType']['data'] = 'Any IPv4 packet'
    icmpv4_bcast_dict['IpType']['mask'] = ''
    icmpv4_bcast_dict['IpProtocol'] = dict()
    icmpv4_bcast_dict['IpProtocol']['data'] = IPProtocolICMPv4
    icmpv4_bcast_dict['IpProtocol']['mask'] = '0xff'
    icmpv4_bcast_dict['Action'] = dict()
    icmpv4_bcast_dict['Action']['data'] = CPUQueueNewAction
    icmpv4_bcast_dict['Action']['mask'] = ''
    icmpv4_bcast_dict['CPUQueueNumber'] = dict()
    icmpv4_bcast_dict['CPUQueueNumber']['data'] = '4'
    icmpv4_bcast_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, icmpv4_bcast_dict)

    assert ret is True, "Ingress FP rule check failed for ICMPv4 broadcast"

    LogOutput('info',  "Ingress FP rule check passed for ICMPv4 broadcast")


def fp_ingress_test_icmpv4_mcast_rule(**kwargs):

    LogOutput('info', 'Verify ICMPv4 multicast FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    icmpv4_mcast_dict = dict()
    icmpv4_mcast_dict['Ingress'] = dict()
    icmpv4_mcast_dict['Ingress']['data'] = ''
    icmpv4_mcast_dict['Ingress']['mask'] = ''
    icmpv4_mcast_dict['DstIp'] = dict()
    icmpv4_mcast_dict['DstIp']['data'] = IPMulticastAddr
    icmpv4_mcast_dict['DstIp']['mask'] = '240.0.0.0'
    icmpv4_mcast_dict['IpType'] = dict()
    icmpv4_mcast_dict['IpType']['data'] = 'Any IPv4 packet'
    icmpv4_mcast_dict['IpType']['mask'] = ''
    icmpv4_mcast_dict['IpProtocol'] = dict()
    icmpv4_mcast_dict['IpProtocol']['data'] = IPProtocolICMPv4
    icmpv4_mcast_dict['IpProtocol']['mask'] = '0xff'
    icmpv4_mcast_dict['Action'] = dict()
    icmpv4_mcast_dict['Action']['data'] = CPUQueueNewAction
    icmpv4_mcast_dict['Action']['mask'] = ''
    icmpv4_mcast_dict['CPUQueueNumber'] = dict()
    icmpv4_mcast_dict['CPUQueueNumber']['data'] = '4'
    icmpv4_mcast_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, icmpv4_mcast_dict)

    assert ret is True, "Ingress FP rule check failed for ICMPv4 multicast"

    LogOutput('info',  "Ingress FP rule check passed for ICMPv4 multicast")


def fp_egress_test_icmpv4_bcast_mcast_rule(**kwargs):

    LogOutput('info', 'Verify ICMPv4 broadcast/multicast FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    icmpv4_bcast_mcast_dict = dict()
    icmpv4_bcast_mcast_dict['Egress'] = dict()
    icmpv4_bcast_mcast_dict['Egress']['data'] = ''
    icmpv4_bcast_mcast_dict['Egress']['mask'] = ''
    icmpv4_bcast_mcast_dict['IpType'] = dict()
    icmpv4_bcast_mcast_dict['IpType']['data'] = 'Any IPv4 packet'
    icmpv4_bcast_mcast_dict['IpType']['mask'] = ''
    icmpv4_bcast_mcast_dict['IpProtocol'] = dict()
    icmpv4_bcast_mcast_dict['IpProtocol']['data'] = IPProtocolICMPv4
    icmpv4_bcast_mcast_dict['IpProtocol']['mask'] = '0xff'
    icmpv4_bcast_mcast_dict['Outport'] = dict()
    icmpv4_bcast_mcast_dict['Outport']['data'] = '0x00'
    icmpv4_bcast_mcast_dict['Outport']['mask'] = OutPortMask
    icmpv4_bcast_mcast_dict['CPUQueue'] = dict()
    icmpv4_bcast_mcast_dict['CPUQueue']['data'] = '0x04'
    icmpv4_bcast_mcast_dict['CPUQueue']['mask'] = CPUQueueMask
    icmpv4_bcast_mcast_dict['Action'] = dict()
    icmpv4_bcast_mcast_dict['Action']['data'] = RedPacketsDropAction
    icmpv4_bcast_mcast_dict['Action']['mask'] = ''
    icmpv4_bcast_mcast_dict['Value'] = dict()
    icmpv4_bcast_mcast_dict['Value']['data'] = '0'
    icmpv4_bcast_mcast_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(icmpv4_bcast_mcast_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, icmpv4_bcast_mcast_dict)

    assert ret is True, "Egress FP rule check failed for ICMPv4 multicast/broadcast"

    LogOutput('info',  "Egress FP rule check passed for ICMPv4 multicast/broadcast")


def fp_ingress_test_icmpv6_ucast_rule(**kwargs):

    LogOutput('info', 'Verify ICMPv6 unicast FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    icmpv6_ucast_dict = dict()
    icmpv6_ucast_dict['Ingress'] = dict()
    icmpv6_ucast_dict['Ingress']['data'] = ''
    icmpv6_ucast_dict['Ingress']['mask'] = ''
    icmpv6_ucast_dict['DstIpLocal'] = dict()
    icmpv6_ucast_dict['DstIpLocal']['data'] = '0x01'
    icmpv6_ucast_dict['DstIpLocal']['mask'] = '0x01'
    icmpv6_ucast_dict['IpType'] = dict()
    icmpv6_ucast_dict['IpType']['data'] = 'IPv6 packet'
    icmpv6_ucast_dict['IpType']['mask'] = ''
    icmpv6_ucast_dict['IpProtocol'] = dict()
    icmpv6_ucast_dict['IpProtocol']['data'] = IPProtocolICMPv6
    icmpv6_ucast_dict['IpProtocol']['mask'] = '0xff'
    icmpv6_ucast_dict['Action'] = dict()
    icmpv6_ucast_dict['Action']['data'] = CPUQueueNewAction
    icmpv6_ucast_dict['Action']['mask'] = ''
    icmpv6_ucast_dict['CPUQueueNumber'] = dict()
    icmpv6_ucast_dict['CPUQueueNumber']['data'] = '5'
    icmpv6_ucast_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, icmpv6_ucast_dict)

    assert ret is True, "Ingress FP rule check failed for ICMPv6 unicast"

    LogOutput('info',  "Ingress FP rule check passed for ICMPv6 unicast")


def fp_egress_test_icmpv6_ucast_rule(**kwargs):

    LogOutput('info', 'Verify ICMPv6 unicast FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    icmpv6_ucast_dict = dict()
    icmpv6_ucast_dict['Egress'] = dict()
    icmpv6_ucast_dict['Egress']['data'] = ''
    icmpv6_ucast_dict['Egress']['mask'] = ''
    icmpv6_ucast_dict['IpType'] = dict()
    icmpv6_ucast_dict['IpType']['data'] = 'IPv6 packet'
    icmpv6_ucast_dict['IpType']['mask'] = ''
    icmpv6_ucast_dict['IpProtocol'] = dict()
    icmpv6_ucast_dict['IpProtocol']['data'] = IPProtocolICMPv6
    icmpv6_ucast_dict['IpProtocol']['mask'] = '0xff'
    icmpv6_ucast_dict['Outport'] = dict()
    icmpv6_ucast_dict['Outport']['data'] = '0x00'
    icmpv6_ucast_dict['Outport']['mask'] = OutPortMask
    icmpv6_ucast_dict['CPUQueue'] = dict()
    icmpv6_ucast_dict['CPUQueue']['data'] = '0x05'
    icmpv6_ucast_dict['CPUQueue']['mask'] = CPUQueueMask
    icmpv6_ucast_dict['Action'] = dict()
    icmpv6_ucast_dict['Action']['data'] = RedPacketsDropAction
    icmpv6_ucast_dict['Action']['mask'] = ''
    icmpv6_ucast_dict['Value'] = dict()
    icmpv6_ucast_dict['Value']['data'] = '0'
    icmpv6_ucast_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(icmpv6_ucast_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, icmpv6_ucast_dict)

    assert ret is True, "Egress FP rule check failed for ICMPv6 unicast"

    LogOutput('info',  "Egress FP rule check passed for ICMPv6 unicast")


def fp_ingress_test_icmpv6_mcast_rule(**kwargs):

    LogOutput('info', 'Verify ICMPv6 multicast FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    icmpv6_mcast_dict = dict()
    icmpv6_mcast_dict['Ingress'] = dict()
    icmpv6_mcast_dict['Ingress']['data'] = ''
    icmpv6_mcast_dict['Ingress']['mask'] = ''
    icmpv6_mcast_dict['DstIp6'] = dict()
    icmpv6_mcast_dict['DstIp6']['data'] = IPv6MulticastAddr
    icmpv6_mcast_dict['DstIp6']['mask'] = IPv6MulticastAddr
    icmpv6_mcast_dict['IpType'] = dict()
    icmpv6_mcast_dict['IpType']['data'] = 'IPv6 packet'
    icmpv6_mcast_dict['IpType']['mask'] = ''
    icmpv6_mcast_dict['IpProtocol'] = dict()
    icmpv6_mcast_dict['IpProtocol']['data'] = IPProtocolICMPv6
    icmpv6_mcast_dict['IpProtocol']['mask'] = '0xff'
    icmpv6_mcast_dict['Action'] = dict()
    icmpv6_mcast_dict['Action']['data'] = CPUQueueNewAction
    icmpv6_mcast_dict['Action']['mask'] = ''
    icmpv6_mcast_dict['CPUQueueNumber'] = dict()
    icmpv6_mcast_dict['CPUQueueNumber']['data'] = '4'
    icmpv6_mcast_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, icmpv6_mcast_dict)

    assert ret is True, "Ingress FP rule check failed for ICMPv6 multicast"

    LogOutput('info',  "Ingress FP rule check passed for ICMPv6 multicast")


def fp_egress_test_icmpv6_mcast_rule(**kwargs):

    LogOutput('info', 'Verify ICMPv6 multicast FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    icmpv6_mcast_dict = dict()
    icmpv6_mcast_dict['Egress'] = dict()
    icmpv6_mcast_dict['Egress']['data'] = ''
    icmpv6_mcast_dict['Egress']['mask'] = ''
    icmpv6_mcast_dict['IpType'] = dict()
    icmpv6_mcast_dict['IpType']['data'] = 'IPv6 packet'
    icmpv6_mcast_dict['IpType']['mask'] = ''
    icmpv6_mcast_dict['IpProtocol'] = dict()
    icmpv6_mcast_dict['IpProtocol']['data'] = IPProtocolICMPv6
    icmpv6_mcast_dict['IpProtocol']['mask'] = '0xff'
    icmpv6_mcast_dict['Outport'] = dict()
    icmpv6_mcast_dict['Outport']['data'] = '0x00'
    icmpv6_mcast_dict['Outport']['mask'] = OutPortMask
    icmpv6_mcast_dict['CPUQueue'] = dict()
    icmpv6_mcast_dict['CPUQueue']['data'] = '0x04'
    icmpv6_mcast_dict['CPUQueue']['mask'] = CPUQueueMask
    icmpv6_mcast_dict['Action'] = dict()
    icmpv6_mcast_dict['Action']['data'] = RedPacketsDropAction
    icmpv6_mcast_dict['Action']['mask'] = ''
    icmpv6_mcast_dict['Value'] = dict()
    icmpv6_mcast_dict['Value']['data'] = '0'
    icmpv6_mcast_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(icmpv6_mcast_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, icmpv6_mcast_dict)

    assert ret is True, "Egress FP rule check failed for ICMPv6 multicast"

    LogOutput('info',  "Egress FP rule check passed for ICMPv6 multicast")


def fp_ingress_test_ospfv2_mcast_all_rule(**kwargs):

    LogOutput('info', 'Verify OSPFv2 all multicast FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    ospfv2_mcast_all_dict = dict()
    ospfv2_mcast_all_dict['Ingress'] = dict()
    ospfv2_mcast_all_dict['Ingress']['data'] = ''
    ospfv2_mcast_all_dict['Ingress']['mask'] = ''
    ospfv2_mcast_all_dict['DstIp'] = dict()
    ospfv2_mcast_all_dict['DstIp']['data'] = OSPFAllRoutersIP
    ospfv2_mcast_all_dict['DstIp']['mask'] = IPBroadcastAddr
    ospfv2_mcast_all_dict['DstMac'] = dict()
    ospfv2_mcast_all_dict['DstMac']['data'] = OSPFAllRoutersMAC
    ospfv2_mcast_all_dict['DstMac']['mask'] = 'ff:ff:ff:ff:ff:ff'
    ospfv2_mcast_all_dict['IpType'] = dict()
    ospfv2_mcast_all_dict['IpType']['data'] = 'Any IPv4 packet'
    ospfv2_mcast_all_dict['IpType']['mask'] = ''
    ospfv2_mcast_all_dict['IpProtocol'] = dict()
    ospfv2_mcast_all_dict['IpProtocol']['data'] = IPProtocolOSPFv2
    ospfv2_mcast_all_dict['IpProtocol']['mask'] = '0xff'
    ospfv2_mcast_all_dict['Action'] = dict()
    ospfv2_mcast_all_dict['Action']['data'] = CPUQueueNewAction
    ospfv2_mcast_all_dict['Action']['mask'] = ''
    ospfv2_mcast_all_dict['CPUQueueNumber'] = dict()
    ospfv2_mcast_all_dict['CPUQueueNumber']['data'] = '9'
    ospfv2_mcast_all_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, ospfv2_mcast_all_dict)

    assert ret is True, "Ingress FP rule check failed for OSPFv2 all multicast"

    LogOutput('info',  "Ingress FP rule check passed for OSPFv2 all multicast")


def fp_ingress_test_ospfv2_mcast_dr_rule(**kwargs):

    LogOutput('info', 'Verify OSPFv2 dr multicast FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    ospfv2_mcast_dr_dict = dict()
    ospfv2_mcast_dr_dict['Ingress'] = dict()
    ospfv2_mcast_dr_dict['Ingress']['data'] = ''
    ospfv2_mcast_dr_dict['Ingress']['mask'] = ''
    ospfv2_mcast_dr_dict['DstIp'] = dict()
    ospfv2_mcast_dr_dict['DstIp']['data'] = OSPFDesignatedRoutersIP
    ospfv2_mcast_dr_dict['DstIp']['mask'] = IPBroadcastAddr
    ospfv2_mcast_dr_dict['DstMac'] = dict()
    ospfv2_mcast_dr_dict['DstMac']['data'] = OSPFDesignatedRoutersMAC
    ospfv2_mcast_dr_dict['DstMac']['mask'] = 'ff:ff:ff:ff:ff:ff'
    ospfv2_mcast_dr_dict['IpType'] = dict()
    ospfv2_mcast_dr_dict['IpType']['data'] = 'Any IPv4 packet'
    ospfv2_mcast_dr_dict['IpType']['mask'] = ''
    ospfv2_mcast_dr_dict['IpProtocol'] = dict()
    ospfv2_mcast_dr_dict['IpProtocol']['data'] = IPProtocolOSPFv2
    ospfv2_mcast_dr_dict['IpProtocol']['mask'] = '0xff'
    ospfv2_mcast_dr_dict['Action'] = dict()
    ospfv2_mcast_dr_dict['Action']['data'] = CPUQueueNewAction
    ospfv2_mcast_dr_dict['Action']['mask'] = ''
    ospfv2_mcast_dr_dict['CPUQueueNumber'] = dict()
    ospfv2_mcast_dr_dict['CPUQueueNumber']['data'] = '9'
    ospfv2_mcast_dr_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, ospfv2_mcast_dr_dict)

    assert ret is True, "Ingress FP rule check failed for OSPFv2 dr multicast"

    LogOutput('info',  "Ingress FP rule check passed for OSPFv2 dr multicast")


def fp_egress_test_ospfv2_mcast_dr_all_rule(**kwargs):

    LogOutput('info', 'Verify OSPFv2 dr/all multicast FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    ospfv2_mcast_dr_dict = dict()
    ospfv2_mcast_dr_dict['Egress'] = dict()
    ospfv2_mcast_dr_dict['Egress']['data'] = ''
    ospfv2_mcast_dr_dict['Egress']['mask'] = ''
    ospfv2_mcast_dr_dict['DstIp'] = dict()
    ospfv2_mcast_dr_dict['DstIp']['data'] = IPMulticastAddr
    ospfv2_mcast_dr_dict['DstIp']['mask'] = '240.0.0.0'
    ospfv2_mcast_dr_dict['DstMac'] = dict()
    ospfv2_mcast_dr_dict['DstMac']['data'] = '1:0:5e:0:0:0'
    ospfv2_mcast_dr_dict['DstMac']['mask'] = 'ff:ff:ff:ff:ff:0'
    ospfv2_mcast_dr_dict['IpType'] = dict()
    ospfv2_mcast_dr_dict['IpType']['data'] = 'Any IPv4 packet'
    ospfv2_mcast_dr_dict['IpType']['mask'] = ''
    ospfv2_mcast_dr_dict['IpProtocol'] = dict()
    ospfv2_mcast_dr_dict['IpProtocol']['data'] = IPProtocolOSPFv2
    ospfv2_mcast_dr_dict['IpProtocol']['mask'] = '0xff'
    ospfv2_mcast_dr_dict['Outport'] = dict()
    ospfv2_mcast_dr_dict['Outport']['data'] = '0x00'
    ospfv2_mcast_dr_dict['Outport']['mask'] = OutPortMask
    ospfv2_mcast_dr_dict['CPUQueue'] = dict()
    ospfv2_mcast_dr_dict['CPUQueue']['data'] = '0x09'
    ospfv2_mcast_dr_dict['CPUQueue']['mask'] = CPUQueueMask
    ospfv2_mcast_dr_dict['Action'] = dict()
    ospfv2_mcast_dr_dict['Action']['data'] = RedPacketsDropAction
    ospfv2_mcast_dr_dict['Action']['mask'] = ''
    ospfv2_mcast_dr_dict['Value'] = dict()
    ospfv2_mcast_dr_dict['Value']['data'] = '0'
    ospfv2_mcast_dr_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(ospfv2_mcast_dr_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, ospfv2_mcast_dr_dict)

    assert ret is True, "Egress FP rule check failed for OSPFv2 dr/all multicast"

    LogOutput('info',  "Egress FP rule check passed for OSPFv2 dr/all multicast")


def fp_ingress_test_ospfv2_ucast_rule(**kwargs):

    LogOutput('info', 'Verify OSPFv2 unicast FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    ospfv2_ucast_dict = dict()
    ospfv2_ucast_dict['Ingress'] = dict()
    ospfv2_ucast_dict['Ingress']['data'] = ''
    ospfv2_ucast_dict['Ingress']['mask'] = ''
    ospfv2_ucast_dict['DstIpLocal'] = dict()
    ospfv2_ucast_dict['DstIpLocal']['data'] = '0x01'
    ospfv2_ucast_dict['DstIpLocal']['mask'] = '0x01'
    ospfv2_ucast_dict['IpType'] = dict()
    ospfv2_ucast_dict['IpType']['data'] = 'Any IPv4 packet'
    ospfv2_ucast_dict['IpType']['mask'] = ''
    ospfv2_ucast_dict['IpProtocol'] = dict()
    ospfv2_ucast_dict['IpProtocol']['data'] = IPProtocolOSPFv2
    ospfv2_ucast_dict['IpProtocol']['mask'] = '0xff'
    ospfv2_ucast_dict['Action'] = dict()
    ospfv2_ucast_dict['Action']['data'] = CPUQueueNewAction
    ospfv2_ucast_dict['Action']['mask'] = ''
    ospfv2_ucast_dict['CPUQueueNumber'] = dict()
    ospfv2_ucast_dict['CPUQueueNumber']['data'] = '9'
    ospfv2_ucast_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, ospfv2_ucast_dict)

    assert ret is True, "Ingress FP rule check failed for OSPFv2 unicast"

    LogOutput('info',  "Ingress FP rule check passed for OSPFv2 unicast")


def fp_egress_test_ospfv2_ucast_rule(**kwargs):

    LogOutput('info', 'Verify OSPFv2 unicast FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    ospfv2_ucast_dict = dict()
    ospfv2_ucast_dict['Egress'] = dict()
    ospfv2_ucast_dict['Egress']['data'] = ''
    ospfv2_ucast_dict['Egress']['mask'] = ''
    ospfv2_ucast_dict['IpType'] = dict()
    ospfv2_ucast_dict['IpType']['data'] = 'Any IPv4 packet'
    ospfv2_ucast_dict['IpType']['mask'] = ''
    ospfv2_ucast_dict['IpProtocol'] = dict()
    ospfv2_ucast_dict['IpProtocol']['data'] = IPProtocolOSPFv2
    ospfv2_ucast_dict['IpProtocol']['mask'] = '0xff'
    ospfv2_ucast_dict['Outport'] = dict()
    ospfv2_ucast_dict['Outport']['data'] = '0x00'
    ospfv2_ucast_dict['Outport']['mask'] = OutPortMask
    ospfv2_ucast_dict['CPUQueue'] = dict()
    ospfv2_ucast_dict['CPUQueue']['data'] = '0x09'
    ospfv2_ucast_dict['CPUQueue']['mask'] = CPUQueueMask
    ospfv2_ucast_dict['Action'] = dict()
    ospfv2_ucast_dict['Action']['data'] = RedPacketsDropAction
    ospfv2_ucast_dict['Action']['mask'] = ''
    ospfv2_ucast_dict['Value'] = dict()
    ospfv2_ucast_dict['Value']['data'] = '0'
    ospfv2_ucast_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(ospfv2_ucast_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, ospfv2_ucast_dict)

    assert ret is True, "Egress FP rule check failed for OSPFv2 unicast"

    LogOutput('info',  "Egress FP rule check passed for OSPFv2 unicast")


def fp_ingress_test_ipv4_options_rule(**kwargs):

    LogOutput('info', 'Verify IPv4 options FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    ipv4_options_dict = dict()
    ipv4_options_dict['Ingress'] = dict()
    ipv4_options_dict['Ingress']['data'] = ''
    ipv4_options_dict['Ingress']['mask'] = ''
    ipv4_options_dict['IpType'] = dict()
    ipv4_options_dict['IpType']['data'] = 'IPv4 options'
    ipv4_options_dict['IpType']['mask'] = ''
    ipv4_options_dict['Action'] = dict()
    ipv4_options_dict['Action']['data'] = CPUQueueNewAction
    ipv4_options_dict['Action']['mask'] = ''
    ipv4_options_dict['CPUQueueNumber'] = dict()
    ipv4_options_dict['CPUQueueNumber']['data'] = '5'
    ipv4_options_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, ipv4_options_dict)

    assert ret is True, "Ingress FP rule check failed for IPv4 options"

    LogOutput('info',  "Ingress FP rule check passed for IPv4 options")


def fp_egress_test_ipv4_options_rule(**kwargs):

    LogOutput('info', 'Verify IPv4 options FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    ipv4_options_dict = dict()
    ipv4_options_dict['Egress'] = dict()
    ipv4_options_dict['Egress']['data'] = ''
    ipv4_options_dict['Egress']['mask'] = ''
    ipv4_options_dict['IpType'] = dict()
    ipv4_options_dict['IpType']['data'] = 'IPv4 options'
    ipv4_options_dict['IpType']['mask'] = ''
    ipv4_options_dict['Outport'] = dict()
    ipv4_options_dict['Outport']['data'] = '0x00'
    ipv4_options_dict['Outport']['mask'] = OutPortMask
    ipv4_options_dict['CPUQueue'] = dict()
    ipv4_options_dict['CPUQueue']['data'] = '0x05'
    ipv4_options_dict['CPUQueue']['mask'] = CPUQueueMask
    ipv4_options_dict['Action'] = dict()
    ipv4_options_dict['Action']['data'] = RedPacketsDropAction
    ipv4_options_dict['Action']['mask'] = ''
    ipv4_options_dict['Value'] = dict()
    ipv4_options_dict['Value']['data'] = '0'
    ipv4_options_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(ipv4_options_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, ipv4_options_dict)

    assert ret is True, "Egress FP rule check failed for IPv4 options"

    LogOutput('info',  "Egress FP rule check passed for IPv4 options")


def fp_ingress_test_ipv6_options_rule(**kwargs):

    LogOutput('info', 'Verify IPv6 options FPs in ingress pipeline')

    buf = kwargs.get('show_buffer', None)

    ipv6_options_dict = dict()
    ipv6_options_dict['Ingress'] = dict()
    ipv6_options_dict['Ingress']['data'] = ''
    ipv6_options_dict['Ingress']['mask'] = ''
    ipv6_options_dict['IpType'] = dict()
    ipv6_options_dict['IpType']['data'] = 'IPv6 options'
    ipv6_options_dict['IpType']['mask'] = ''
    ipv6_options_dict['Action'] = dict()
    ipv6_options_dict['Action']['data'] = CPUQueueNewAction
    ipv6_options_dict['Action']['mask'] = ''
    ipv6_options_dict['CPUQueueNumber'] = dict()
    ipv6_options_dict['CPUQueueNumber']['data'] = '5'
    ipv6_options_dict['CPUQueueNumber']['mask'] = '0'

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, ipv6_options_dict)

    assert ret is True, "Ingress FP rule check failed for IPv6 options"

    LogOutput('info',  "Ingress FP rule check passed for IPv6 options")


def fp_egress_test_ipv6_options_rule(**kwargs):

    LogOutput('info', 'Verify IPv6 options FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    ipv6_options_dict = dict()
    ipv6_options_dict['Egress'] = dict()
    ipv6_options_dict['Egress']['data'] = ''
    ipv6_options_dict['Egress']['mask'] = ''
    ipv6_options_dict['IpType'] = dict()
    ipv6_options_dict['IpType']['data'] = 'IPv6 options'
    ipv6_options_dict['IpType']['mask'] = ''
    ipv6_options_dict['Action'] = dict()
    ipv6_options_dict['Action']['data'] = CPUQueueNewAction
    ipv6_options_dict['Action']['mask'] = ''
    ipv6_options_dict['Outport'] = dict()
    ipv6_options_dict['Outport']['data'] = '0x00'
    ipv6_options_dict['Outport']['mask'] = OutPortMask
    ipv6_options_dict['CPUQueue'] = dict()
    ipv6_options_dict['CPUQueue']['data'] = '0x05'
    ipv6_options_dict['CPUQueue']['mask'] = CPUQueueMask
    ipv6_options_dict['Action'] = dict()
    ipv6_options_dict['Action']['data'] = RedPacketsDropAction
    ipv6_options_dict['Action']['mask'] = ''
    ipv6_options_dict['Value'] = dict()
    ipv6_options_dict['Value']['data'] = '0'
    ipv6_options_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(ipv6_options_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, ipv6_options_dict)

    assert ret is True, "Egress FP rule check failed for IPv6 options"

    LogOutput('info',  "Egress FP rule check passed for IPv6 options")


def fp_egress_test_unknown_ip_rule(**kwargs):

    LogOutput('info', 'Verify unknown IP FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    unknown_ip_dict = dict()
    unknown_ip_dict['Egress'] = dict()
    unknown_ip_dict['Egress']['data'] = ''
    unknown_ip_dict['Egress']['mask'] = ''
    unknown_ip_dict['Outport'] = dict()
    unknown_ip_dict['Outport']['data'] = '0x00'
    unknown_ip_dict['Outport']['mask'] = OutPortMask
    unknown_ip_dict['CPUQueue'] = dict()
    unknown_ip_dict['CPUQueue']['data'] = '0x06'
    unknown_ip_dict['CPUQueue']['mask'] = CPUQueueMask
    unknown_ip_dict['Action'] = dict()
    unknown_ip_dict['Action']['data'] = RedPacketsDropAction
    unknown_ip_dict['Action']['mask'] = ''
    unknown_ip_dict['Value'] = dict()
    unknown_ip_dict['Value']['data'] = '0'
    unknown_ip_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(unknown_ip_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, unknown_ip_dict)

    assert ret is True, "Egress FP rule check failed for unknown IP"

    LogOutput('info',  "Egress FP rule check passed for unknown IP")


def fp_egress_test_unclassified_rule(**kwargs):

    LogOutput('info', 'Verify unclassified FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    unclassified_dict = dict()
    unclassified_dict['Egress'] = dict()
    unclassified_dict['Egress']['data'] = ''
    unclassified_dict['Egress']['mask'] = ''
    unclassified_dict['Outport'] = dict()
    unclassified_dict['Outport']['data'] = '0x00'
    unclassified_dict['Outport']['mask'] = OutPortMask
    unclassified_dict['CPUQueue'] = dict()
    unclassified_dict['CPUQueue']['data'] = '0x01'
    unclassified_dict['CPUQueue']['mask'] = CPUQueueMask
    unclassified_dict['Action'] = dict()
    unclassified_dict['Action']['data'] = RedPacketsDropAction
    unclassified_dict['Action']['mask'] = ''
    unclassified_dict['Value'] = dict()
    unclassified_dict['Value']['data'] = '0'
    unclassified_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(unclassified_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, unclassified_dict)

    assert ret is True, "Egress FP rule check failed for unclassified"

    LogOutput('info',  "Egress FP rule check passed for unclassified")


def fp_egress_test_acl_logging_rule(**kwargs):

    LogOutput('info', 'Verify ACL Logging FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    acl_logging_dict = dict()
    acl_logging_dict['Egress'] = dict()
    acl_logging_dict['Egress']['data'] = ''
    acl_logging_dict['Egress']['mask'] = ''
    acl_logging_dict['Outport'] = dict()
    acl_logging_dict['Outport']['data'] = '0x00'
    acl_logging_dict['Outport']['mask'] = OutPortMask
    acl_logging_dict['CPUQueue'] = dict()
    acl_logging_dict['CPUQueue']['data'] = '0x00'
    acl_logging_dict['CPUQueue']['mask'] = CPUQueueMask
    acl_logging_dict['Action'] = dict()
    acl_logging_dict['Action']['data'] = RedPacketsDropAction
    acl_logging_dict['Action']['mask'] = ''
    acl_logging_dict['Value'] = dict()
    acl_logging_dict['Value']['data'] = '0'
    acl_logging_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(acl_logging_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, acl_logging_dict)

    assert ret is True, "Egress FP rule check failed for ACL Logging"

    LogOutput('info',  "Egress FP rule check passed for ACL Logging")


def fp_egress_test_sflow_rule(**kwargs):

    LogOutput('info', 'Verify Sflow FPs in egress pipeline')

    buf = kwargs.get('show_buffer', None)

    sflow_dict = dict()
    sflow_dict['Egress'] = dict()
    sflow_dict['Egress']['data'] = ''
    sflow_dict['Egress']['mask'] = ''
    sflow_dict['Outport'] = dict()
    sflow_dict['Outport']['data'] = '0x00'
    sflow_dict['Outport']['mask'] = OutPortMask
    sflow_dict['CPUQueue'] = dict()
    sflow_dict['CPUQueue']['data'] = '0x03'
    sflow_dict['CPUQueue']['mask'] = CPUQueueMask
    sflow_dict['Action'] = dict()
    sflow_dict['Action']['data'] = RedPacketsDropAction
    sflow_dict['Action']['mask'] = ''
    sflow_dict['Value'] = dict()
    sflow_dict['Value']['data'] = '0'
    sflow_dict['Value']['mask'] = '0'

    # Add the stat types to the FP rule dictionary
    add_stat_types_to_fp_rule_dict(sflow_dict)

    ret = if_fp_rule_exists_with_values_in_fp_dump(buf, sflow_dict)

    assert ret is True, "Egress FP rule check failed for Sflow"

    LogOutput('info',  "Egress FP rule check passed for Sflow")


class Test_copp_ct:

    def setup_class(cls):
        Test_copp_ct.testObj = testEnviron(topoDict=topoDict)
        Test_copp_ct.topoObj = Test_copp_ct.testObj.topoObjGet()

        switch =  Test_copp_ct.topoObj.deviceObjGet(device="dut01")

        # Get the ingress fp show output
        appctl_command = "ovs-appctl plugin/debug fp copp-ingress-group"
        retStruct = switch.DeviceInteract(command=appctl_command)
        Test_copp_ct.FpIngressBuffer = retStruct.get('buffer')
        LogOutput('info', str(Test_copp_ct.FpIngressBuffer))

        # Get the Egress fp show output
        appctl_command = "ovs-appctl plugin/debug fp copp-egress-group"
        retStruct = switch.DeviceInteract(command=appctl_command)
        Test_copp_ct.FpEgressBuffer = retStruct.get('buffer')
        LogOutput('info', str(Test_copp_ct.FpEgressBuffer))

    def teardown_class(cls):
        Test_copp_ct.topoObj.terminate_nodes()

    def test_fp_ingress_test_broadcast_arp_rule(self):
        fp_ingress_test_broadcast_arp_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_broadcast_arp_rule(self):
        fp_egress_test_broadcast_arp_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_unicast_arp_rule(self):
        fp_ingress_test_unicast_arp_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_unicast_arp_rule(self):
        fp_egress_test_unicast_arp_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_lacp_rule(self):
        fp_ingress_test_lacp_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_lacp_rule(self):
        fp_egress_test_lacp_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_lldp_rule(self):
        fp_ingress_test_lldp_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_lldp_rule(self):
        fp_egress_test_lldp_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_stp_rule(self):
        fp_ingress_test_stp_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_stp_rule(self):
        fp_egress_test_stp_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_bgp_l4_dst_port_rule(self):
        fp_ingress_test_bgp_l4_dst_port_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_ingress_test_bgp_l4_src_port_rule(self):
        fp_ingress_test_bgp_l4_src_port_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_bgp_rule(self):
        fp_egress_test_bgp_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_dhcpv4_rule(self):
        fp_ingress_test_dhcpv4_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_dhcpv4_rule(self):
        fp_egress_test_dhcpv4_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_dhcpv6_rule(self):
        fp_ingress_test_dhcpv6_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_dhcpv6_rule(self):
        fp_egress_test_dhcpv6_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_icmpv4_ucast_rule(self):
        fp_ingress_test_icmpv4_ucast_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_icmpv4_ucast_rule(self):
        fp_egress_test_icmpv4_ucast_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_icmpv4_bcast_rule(self):
        fp_ingress_test_icmpv4_bcast_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_ingress_test_icmpv4_mcast_rule(self):
        fp_ingress_test_icmpv4_mcast_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_icmpv4_bcast_mcast_rule(self):
        fp_egress_test_icmpv4_bcast_mcast_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_icmpv6_ucast_rule(self):
        fp_ingress_test_icmpv6_ucast_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_icmpv6_ucast_rule(self):
        fp_egress_test_icmpv6_ucast_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_icmpv6_mcast_rule(self):
        fp_ingress_test_icmpv6_mcast_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_icmpv6_mcast_rule(self):
        fp_egress_test_icmpv6_mcast_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def testfp_ingress_test_ospfv2_ucast_rule(self):
        fp_ingress_test_ospfv2_ucast_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def testfp_egress_test_ospfv2_ucast_rule(self):
        fp_egress_test_ospfv2_ucast_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_ospfv2_mcast_all_rule(self):
        fp_ingress_test_ospfv2_mcast_all_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_ingress_test_ospfv2_mcast_dr_rule(self):
        fp_ingress_test_ospfv2_mcast_dr_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_ospfv2_mcast_dr_all_rule(self):
        fp_egress_test_ospfv2_mcast_dr_all_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_ipv4_options_rule(self):
        fp_ingress_test_ipv4_options_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_ipv4_options_rule(self):
        fp_egress_test_ipv4_options_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_ingress_test_ipv6_options_rule(self):
        fp_ingress_test_ipv6_options_rule(show_buffer=Test_copp_ct.FpIngressBuffer)

    def test_fp_egress_test_ipv6_options_rule(self):
        fp_egress_test_ipv6_options_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_egress_test_unknown_ip_rule(self):
        fp_egress_test_unknown_ip_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_egress_test_unclassified_rule(self):
        fp_egress_test_unclassified_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_egress_test_acl_logging_rule(self):
        fp_egress_test_acl_logging_rule(show_buffer=Test_copp_ct.FpEgressBuffer)

    def test_fp_egress_test_sflow_rule(self):
        fp_egress_test_sflow_rule(show_buffer=Test_copp_ct.FpEgressBuffer)
