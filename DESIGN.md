 High-Level Design of the ops-switchd-opennsl-plugin


 Contents

- [Overview](#overview)
- [Terminology](#terminology)
        - [In OVSDB and ops-switchd](#in-ovsdb-and-ops-switchd)
        - [In the switchd-opennsl-plugin](#in-the-switchd-opennsl-plugin)
                - [In the netdev layer](#in-the-netdev-layer)
                - [In the ofproto layer](#in-the-ofproto-layer)
                - [In the bufmon layer](#in-the-bufmon-layer)
                - [In OpenNSL API code](#in-opennsl-api-code)
- [Design](#design)
        - [Physical interface configuration](#physical-interface-configuration)
                - [Trunk/LAG configuration](#trunklag-configuration)
        - [Layer 2 switching](#layer-2-switching)
        - [Layer 3 routing](#layer-3-routing)
        - [Code details](#code-details)
                - [Asynchronous notifications](#asynchronous-notifications)
        - [Buffer monitoring](#buffer-monitoring)
        - [Layer 3 loopback interface](#layer-3-loopback-interface)
        - [Layer 3 subinterface](#layer-3-subinterface)
        - [Layer 3 LAG interface](#layer-3-lag-interface)
        - [Layer 3 interface statistics](#layer-3-interface-statistics)
        - [Multicast traffic](#multicast-traffic)
                - [OSPF](#ospf)
        - [Control Plane Policing](#control-plane-policing)
                - [Ingress traffic](#ingress-traffic)
                - [Egress traffic](#egress-traffic)
                - [CoPP classes](#copp-classes)
                - [Policer mode](#policer-mode)
        - [Spanning Tree Group](#spanning-tree-group)
- [References](#references)

## Overview
OpenSwitch is a database driven network operating system (NOS) for Open Compute Project (OCP) compliant switchs. The OpenSwitch switch driver plugin (ops-switchd-opennsl-plugin), provides support for Broadcom switch ASICs.

The following diagram shows the high-level relationships between various daemons in the OpenSwitch architecture:

```ditaa
+-----------------+  +-------------+  +-----------+
|                 |  |             |  |           |
|  Management     |  |   Layer 2   |  |  Layer 3  |
| CL/REST/Bufmond |  |   Daemons   |  |  Daemons  |
|                 |  |             |  |           |
+--------+--------+  +------+------+  +-----+-----+
         |                  |               |
         --------------+    |    +----------+
                       |    |    |
                       |    |    |
                +------+----+----+-------+
                |         OVSDB          |
                +-----------+------------+
                            |
                    +-------+---------+          ----+
                    |   ops-switchd   |              |
              +-------------+----------------+       |
              |    switchd OpenNSL plugin    |       +-- Switch Driver
              +------------------------------+       |
              |         OpenNSL SDK          |       |
              +------------------------------+   ----+
       +-------------------------------------------+
       |                                           |
       | OpenNSL                                   |
       | Kernel Drivers               Linux        |
       | (knet, bde)                  Kernel       |
       |                                           |
       +-------------------------------------------+
       |                                           |
       |              Switch Hardware              |
       |                                           |
       +-------------------------------------------+
```
In this document, the term *switch driver* is used to refer to ops-switchd, the switchd OpenNSL plugin, and Open NSL SDK. Various daemons (Management + Layer 2 + Layer 3) read the user configuration from the OVSDB and generate the hardware configuration into the OVSDB. The switch driver reads the hardware configuration and then configures the switch ASIC.

In OpenSwitch, the switch driver architecture is based on the Open vSwitch architecture. In the above diagram, ops-switchd is a generic, hardware-independent layer derived from the Open vSwitch/ops-switchd code.

The switchd OpenNSL plugin is a dynamically loadable plugin library. It uses open APIs published in OpenNSL SDK (open source SDK for Broadcom switch ASICs).

This plugin is divided into three layers:
  1. netdev layer
  2. ofproto layer
  3. bufmon layer

The OpenNSL SDK is provided by Broadcom, and is a maintained binary version of their switch development software.

## Terminology
Across the switch driver, different layers use different terminologies.

### In OVSDB and ops-switchd
- **vrf** = layer 3 router.
- **bridge** = layer 2 switch
- **port** = logical layer 2 switch port, trunk/LAG, layer 3 routable port, and layer 3 routable VLAN interface
- **interface** = layer 1 physical interface

### In the switchd-opennsl-plugin
#### In the netdev layer
The primary scope of the netdev layer is layer 1 device configuration.
- **interfaces** = ASIC ports

#### In the ofproto layer
- **vrf** = layer 3 router.
- **bridge** = layer 2 switch
- **bundle** = logical layer 2 switch port, trunk/LAG, layer 3 routable port, and layer 3 routable VLAN interface
- **port** = layer 1 physical interface

#### In the bufmon layer
The bufmon layer provides an API to configure the switch hardware based on the buffer monitoring counter configuration in the database, and counter statistics collected from the switch hardware.

#### In OpenNSL API code
- **port** = layer 1 physical interface and layer 2 logical switch port
- **trunk** = trunk/LAG
- **layer 3 interface** = layer 3 routable port and layer 3 routable VLAN interfaces

## Design
The switchd plugin is responsible for configuring the switch ASIC based on the configuration passed down by ops-switchd. The configuration passed down by ops-switchd is hardware independent. The switchd plugin configures the switch ASIC using a hardware-dependent API based on this configuration.

At a high level, functionality of the OpenNSL switch plugin can be divided into the following categories:


- Physical interface configuration.
   * Layer 1 interface configuration
        * KNET Linux virtual Ethernet interfaces
   * Trunk configuration
- Layer 2 switching
- Layer 3 routing
- Advanced statistics

### Physical interface configuration
In OpenSwitch, the ops-intfd daemon is responsible for physical interface configuration. It derives the hardware configuration based on the user configuration (Interface:user_config), transceiver data, and other interface-related information. The switch plugin configures the switch ASIC, and other peripheral devices like PHYs and MACs, according to the given hardware configuration.

The switchd plugin also creates one Linux virtual Ethernet interface per physical interface present in the ASIC. Protocol BPDUs received in the switch ASIC are readable via these Ethernet interfaces for layer 2 and layer 3 daemon consumption. These daemons also write the protocol BPDUs into these virtual Ethernet devices. These frames should be transmitted out of the switch ASIC interfaces. The opennsl-plugin achieves this functionality by creating virtual Ethernet devices called *KNET interfaces*.

These two functionalities reside in the netdev layer of the opennsl-plugin.

#### Trunk/LAG configuration
OpenSwitch supports both static and dynamic link aggregation. One or more physical switch ASIC interfaces can be grouped to create a trunk. Currently, a maximum of eight interfaces can be grouped as one trunk.
Based on the user configuration, the ops-lacpd daemon updates the Interface:hw_bond_config column in the database. The switchd plugin configures trunks in the hardware based on this information.
Trunk functionality is handled in the ofproto layer of the opennsl-plugin.

### Layer 2 switching
In OpenSwitch, port VLAN information is stored in three important fields:
* Port:tag
* Port:trunks
* Port:vlan_mode

The vlan_mode field has four possible values:
1. **VLAN_ACCESS**: The port carries packets on exactly one VLAN specified in Port:tag. Only untagged packets are accepted on ingress, and all packets are transmitted untagged.
2. **VLAN_TRUNK**: The port carries packets on one or more VLANs specified in Port:trunks. If Port:trunks is empty, then it can carry all VLANS defined in the system. All packets transmitted and received are tagged.
3. **VLAN_NATIVE_TAGGED**: The port resembles a trunk port, with the exception that all untagged packets ingressing the switch go to the native VLAN specified by Port:tag. All packets egressing the switch are tagged, including packets egressing on the native VLAN.
4. **VLAN_NATIVE_UNTAGGED**: The port resembles a native-tagged port, with the exception that packets egressing on the native VLAN are untagged.

This functionality is handled in the ofproto layer.

### Layer 3 routing
The switchd plugin supports layer 3 routing for the IPv4 and IPv6 protocols. The ops-switchd daemon learns route/nexthop from the OVSDB and pushes it down to the switchd plugin. Plugin intern calls the opennsl API to populate the host, the longest prefix match (LPM), and the ECMP table in the ASIC. ECMP hashing currently supports 16-bit CRC-CCITT. By default, the hashing tuple is: source ip, destination ip, source port, and destination port. The tuple element can be included/excuded in the hash calculation by using the CLI.

Layer 3 functionality is handled in the ofproto layer.

### Code details
The most important entry point into the switchd plugin is the **bundle_set()** function. Configuration for the entire switch is passed in a structure called *struct ofproto_bundle_settings*.

The switchd plugin must maintain a local copy of the switch configuration that was passed using the above structure. The **bundle_set()** function is always called with the entire switch configuration. The plugin code compares the switch configuration with its local state, and identifies all changes since the last call.

#### Asynchronous notifications
The switchd plugin cannot directly modify the OVSDB. The ops-switchd layer is the only layer which can read/write to the database. Whenever the switchd plugin writes something to the database, it increases a counter in the *netdev structure* shared between the switchd plugin and the ops-switchd layer. Changing the counter also wakes up the ops-switchd layer's main thread if it is sleeping. When the ops-switchd layer notices a change in the counter value of a netdev device, it queries the entire state of that netdev from the switchd plugin, and updates the state in the OVSDB. Link state changes are updated using this mechanism.

The ops-switchd layer collects basic interface statistics once every five seconds by default. This value can be increased as needed.

### Buffer monitoring
OpenSwitch supports monitoring MMU buffer space consumption (buffer statistics and monitoring) inside the switch hardware. The bufmond Python script is responsible for adding counter details into the OVSDB bufmon table. The ops-switchd daemon configures switch hardware based on the buffer monitoring configuration in the OVSDB bufmon table.

The switchd plugin uses the bufmon layer APIs to configure the switch hardware, and for statistics collection from the switch hardware. In switchd, the thread *bufmon_stats_thread* is responsible for periodically collecting statistics from the switch hardware, and it also monitors for threshold crossed trigger notifications from the switch hardware. The same thread notifies the switchd main thread to push counter statistics into the database.

### Layer 3 loopback interface
The netdev class *l3loopback* is registered to handle layer 3 loopback interfaces. This class has a minimal set of APIs (alloc/construct/distruct/dealloc) registered to handle creation and deletion of layer 3 loopback interfaces. No other configurations are done in the ASIC via netdev for loopback interfaces.

Via ofproto, only IP address configurations are allowed for loopback interfaces. When a loopback interface is deleted, the corresponding IP addresses are removed from the ASIC.

### Layer 3 subinterface
The netdev class *subinterface* is registered to handle layer 3 subinterfaces. This class has APIs to handle basic netdev operations (alloc/construct/distruct/dealloc), and an API *set_config()* to handle configuration of subinterface 802.1q VLAN tag, a MAC address, and a parent hardware port ID.

The following actions are performed during subinterface creation:
- Create a VLAN if it does not already exist.
- Create the layer 3 interface using the VRF, VLAN ID, MAC, and parent hardware port properties. If the VLAN ID is not configured, the layer 3 interface cannot be created.
- Create a KNET filter to retain the VLAN tag.
- Create a field processor (FP) rule on the parent port to drop packets that have a destination MAC that does not match **MyStationTCAM;** to avoid switching on the subinterface VLAN ID.
- Update the parent interface in the trunk bitmap and the subinterface bitmap for the VLAN.
- Configure the IP addresses.

The following actions are performed during subinterface deletion:
- Delete the layer 3 interface created for the subinterface using the netdev **distruct** operation.
- Delete the VLAN, if it has not been created by the user. This means VLANs created for layer 2.
- If the VLAN already exisits, clear just the parent port bit from the trunk and the subinterface bitmap.

The following actions are performed during subinterface VLAN config change:
- If the VLAN of a subinterface is changed, delete the old subinterface and then create a new subinterface with the new VLAN.
- If the new VLAN already exists, add just the parent port bit to the trunk and the subinterface bitmap.
- If the VLAN does not exist, create a new VLAN and update the trunk and the subinterface bitmap with a parent port bit.

If a VLAN is deleted without deleting the subinterface, the VLAN is not deleted from the ASIC, and the parent port bit is left set in the trunk bitmap and subinterface bitmap.

### Layer 3 LAG interface

Layer 3 LAG continues to use the registered class for *system* for its netdev functionality.

Creating layer 3 lag:
- Create layer 3 LAG bundle with internal VLAN.
- Add members to the internal VLAN bitmap created for LAG.
- Add members to the layer 3 LAG bundle.
- Create knet filters for send packets to their corresponding linux interface for each member added.

- Update IP address for LAG.
- If the interface added to LAG is already a layer 3 interface, destroy the bundle for that interface before adding to LAG.
- Update LAG ID in the egress object which is used by the nexthop table.
- The egress object is updated with trunk ID and the flag (OPENNSL_L3_TGID).

Destroing a layer 3 LAG:
- Remove members from the internal VLAN.
- Remove member interfaces from the layer 3 LAG bundle.
- Delete the knet filter that was created for the member.
- If there are no ports in the LAG, then destroy the layer 3 bundle.
- If the CLI destroys the LAG completely, then delete each knet, remove members from the internal VLAN and destroy the layer 3 interface.

### Layer 3 interface statistics
For layer 3 interface statistics, FP packet qualification rules are programmed to count unicast and multicast IPv4 and IPv6 packet types. These FPs are programed when a layer 3 interface is created, and removed when an layer 3 interface is removed. These FPs have statistics objects associated with them that are periodically polled to get the number of layer 3 packets and bytes.

### Multicast traffic
The plugin is responsible for programming the FP entries which enable the ASIC to forward well-known multicast packets to the CPU for further processing.

#### OSPF
The current implementation enables OSPF on a global level. This includes creating a group for OSPF and adding two FP entries with their corresponding stat entries. The FPs forward multicast packets with the following destination IP addresses:

- All OSPF Routers (224.0.0.5)
- OSPF Designated Routers (224.0.0.6)

This is a one-time setup that is done as part of the ops_l3_init process.

### Control Plane Policing
Control plane policing (CoPP) protects usage of the CPU by allowing ingress and egress control plane traffic to be prioritized and rate-limited as follows:

#### Ingress traffic

Field processors are used to assign CPU bound ingress traffic to a specific CPU queue.

```ditaa
+--------------+-----------+---------------------------------+
|  Priority    | CPU Queue | Description                     |
+--------------+-----------+---------------------------------+
| Critical     |    Q10    | xSTP                            |
+--------------+-----------+---------------------------------+
| Important    |    Q9     | OSPF,BGP                        |
+--------------+-----------+---------------------------------+
| LLDP/LACP    |    Q8     | LLDP, LACP                      |
+--------------+-----------+---------------------------------+
| MANAGEMENT   |    Q7     | Currently, inband management    |
|              |           | traffic is not supported.       |
+--------------+-----------+---------------------------------+
| Unknown IP   |    Q6     | Unknown destination IP/IPv6     |
+--------------+-----------+---------------------------------+
| SW-PATH      |    Q5     | Unicast ARP, Unicast ICMP,      |
|              |           | ICMP, ICMPv6, IP options        |
+--------------+-----------+---------------------------------+
| NORMAL       |    Q4     | Broadcast ARP, ICMP, DHCP,      |
|              |           | Broadcast/Multicast             |
+--------------+-----------+---------------------------------+
| sFlow        |    Q3     | Sampled sFlow traffic           |
+--------------+-----------+---------------------------------+
| Snooping     |    Q2     |                                 |
+--------------+-----------+---------------------------------+
| Default      |    Q1     | Unclasssified packets           |
+--------------+-----------+---------------------------------+
| ACL Logging  |    Q0     | ACL logging                     |
+--------------+-----------+---------------------------------+
```
#### Egress traffic
Field processors are used in conjunction with traffic policers to rate limit egress traffic.
```ditaa
+---------------+--------------------------------+---------+-----------------+
| Packet Class  |  Description                   |  Queue  | Rate Limit (PPS)|
+---------------+--------------------------------+---------------------------+
| ACL_LOGGING   |  ACL Logging                   |   Q0    |         5       |
+---------------+--------------------------------+---------+-----------------+
| ARP_BC        |  Broadcast ARP Packets         |   Q4    |      1000       |
+---------------+--------------------------------+---------+-----------------+
| ARP_UC        |  Unicast ARPs                  |   Q5    |      1000       |
+---------------+--------------------------------+---------+-----------------+
| BGP           |  BGP packets                   |   Q9    |      5000       |
+---------------+--------------------------------+---------+-----------------+
| DHCP          |  DHCP packets                  |   Q4    |       500       |
+---------------+--------------------------------+---------+-----------------+
| DHCPV6        |  IPv6 DHCP packets             |   Q4    |       500       |
+---------------+--------------------------------+---------+-----------------+
| ICMP_BC       |  IPv4 broadcast/multicast ICMP |   Q4    |      1000       |
|               |  packets                       |         |                 |
+---------------+--------------------------------+---------+-----------------+
| ICMP_UC       |  IPv4 unicast ICMP packets     |   Q5    |      1000       |
+---------------+--------------------------------+---------+-----------------+
| ICMPV6_MC     |  IPv6 multicast ICMP packets   |   Q4    |      1000       |
+---------------+--------------------------------+---------+-----------------+
| ICMPV6_UC     |  IPv6 unicast ICMP             |   Q5    |      1000       |
+---------------+--------------------------------+---------+-----------------+
| IPOPTIONV4    |  Packets with IPv4 options     |   Q5    |       250       |
+---------------+--------------------------------+---------+-----------------+
| IPOPTIONV6    |  Packets with IPv6 options     |   Q5    |       250       |
+---------------+--------------------------------+---------+-----------------+
| LACP          |  LACP packets                  |   Q8    |      1000       |
+---------------+--------------------------------+---------+-----------------+
| LLDP          |  LLDP packets                  |   Q8    |       500       |
+---------------+--------------------------------+---------+-----------------+
| OSPF_MC       |  Multicast OSPF packets        |   Q9    |      5000       |
+---------------+--------------------------------+---------+-----------------+
| OSPF_UC       |  Unicast OSPF packets          |   Q9    |      5000       |
+---------------+--------------------------------+---------+-----------------+
| sFlow         |  Sampled sFlow packets         |   Q3    |      5000       |
+---------------+--------------------------------+---------+-----------------+
| STP           |  STP packets                   |   Q10   |      1000       |
+---------------+--------------------------------+---------+-----------------+
|UNKNOWN_IP_DEST|  Unknown IPv4 or Ipv6          |   Q6    |      2500       |
|               |  destination                   |         |                 |
+---------------+--------------------------------+---------+-----------------+
|UNCLASSIFIED   |  Unclassified packets          |   Q1    |      5000       |
+------------------------------------------------+---------+-----------------+
```

#### CoPP classes
All the CoPP classes and their defaults are defined in ops-copp-defaults.h using the OPS_DEF_COPP_CLASS macro.

To support a new CoPP class:
- Add a corresponding entry in ops-copp-defaults.h with required defaults and register corresponding ingress and egress functions.
- Implement functions to qualify the packet class in the *ingress* pipeline and assign the CPU queue.
- Implement function to qualify the packet class in the *egress* pipeline to attach a policer which would rate limit the traffic.

#### Policer mode
A color blind tri-color single rate policer is used for CoPP. The committed rate is set as the rate limit numbers shown in the preceeding table. The committed burst size is currently configured to the same value as the rate limit. Packets marked red are dropped.

### Spanning Tree Group(STG)
The switchd-opennsl plugin supports spanning tree group creation/deletion/update. The ops-switchd daemon learns spanning tree instance updates(instance creation, vlan to instance mapping, instance-port states) from the OVSDB and pushes it down to the switchd opennsl plugin. Plugin intern calls the opennsl API to populate the STG table in the ASIC.


Following are the actions done on spanning tree instance creation:
- Create a STG entry in ASIC if it does not already exist.
- update the internal cache.

Following are the actions done on spanning tree instance deletion:
- Delete the STG entry in ASIC if it already exists.
- update the internal cache.

Following are the actions done on spanning tree instance to vlan add:
- update the VLAN table entry with STG_ID associated to vlan.
- update the internal cache

Following are the actions done on spanning tree instance to vlan delete:
- update the VLAN table entry with default STG_ID.
- update the internal cache

Following are the actions done on spanning tree instance port state update:
- update the port state in STG entry with the given port state.
- valid port states are Disabled(2'b00), Blocking(2'b01), Learning(2'b10), Forwarding(2'b11)
- update the internal cache

## References
[OpenvSwitch Porting Guide](http://git.openvswitch.org/cgi-bin/gitweb.cgi?p=openvswitch;a=blob;f=PORTING)
[Broadcom OpenNSL](https://github.com/Broadcom-Switch/OpenNSL)
