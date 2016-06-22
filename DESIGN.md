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
        - [Trunk/LAG configuration](#trunk/lag-configuration)
    - [Layer 2 switching](#layer-2-switching)
    - [Layer 2 mirroring](#layer-2-mirroring)
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
    - [sFlow](#sflow)
    - [MAC Learning](#mac-learning)
        - [Design considerations](#design-considerations)
        - [High Level Design](#high-level-design)
        - [Design detail](#design-detail)
        - [Operations on MAC table](#operations-on-mac-table)
        - [MAC Learning References](#mac-learning-references)
    - [OpenFlow Hybrid Switch Support](#openflow-hybrid-switch-support)
        - [Hybrid Model](#hybrid-model)
        - [OpenFlow Forwarding Pipeline (TTP)](#openflow-forwarding-pipeline-ttp)
        - [OpenNSL APIs for OpenFlow](#opennsl-apis-for-openflow)
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

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

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

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

### Layer 2 mirroring
Openswitch supports simple port mirroring.  Supported mirroring modes are **one to one** which means one source port can be mirrored to one destination port; **one to many** which means that one source port can be mirrored out to multiple destination ports; and **many to one** where many source ports can be mirrored out to one destination port.  Many to many mode is NOT supported.  A destination port can NOT also be a source port.  Both LAG sources and destinations are supported with the understanding that every time a LAG changes (an interface is added to the LAG or deleted from the LAG), the active mirror sessions which contain that LAG as a source, must first be made inactive (shutdown) and re-started again for correct operation.  In addition, further source packet granularity can be achieved by specifying whether received packets or transmitted packets or both types of packets are to be mirrored.  Currently, only a maximum of 4 mirror destination ports can be specified.  This is a hardware limitation.

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

### Layer 3 routing
The switchd plugin supports layer 3 routing for the IPv4 and IPv6 protocols. The ops-switchd daemon learns route/nexthop from the OVSDB and pushes it down to the switchd plugin. Plugin intern calls the opennsl API to populate the host, the longest prefix match (LPM), and the ECMP table in the ASIC. ECMP hashing currently supports 16-bit CRC-CCITT. By default, the hashing tuple is: source ip, destination ip, source port, and destination port. The tuple element can be included/excuded in the hash calculation by using the CLI. ECMP resiliency is enabled by default when the dynamic mode and size are set to true and 64 respectively. Resiliency can be enabled or disabled through CLI.

Layer 3 functionality is handled in the ofproto layer.

#### Code details
The most important entry point into the switchd plugin is the **bundle_set()** function. Configuration for the entire switch is passed in a structure called *struct ofproto_bundle_settings*.

The switchd plugin must maintain a local copy of the switch configuration that was passed using the above structure. The **bundle_set()** function is always called with the entire switch configuration. The plugin code compares the switch configuration with its local state, and identifies all changes since the last call.

##### Asynchronous notifications
The switchd plugin cannot directly modify the OVSDB. The ops-switchd layer is the only layer which can read/write to the database. Whenever the switchd plugin writes something to the database, it increases a counter in the *netdev structure* shared between the switchd plugin and the ops-switchd layer. Changing the counter also wakes up the ops-switchd layer's main thread if it is sleeping. When the ops-switchd layer notices a change in the counter value of a netdev device, it queries the entire state of that netdev from the switchd plugin, and updates the state in the OVSDB. Link state changes are updated using this mechanism.

The ops-switchd layer collects basic interface statistics once every five seconds by default. This value can be increased as needed.

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

### Buffer monitoring
OpenSwitch supports monitoring MMU buffer space consumption (buffer statistics and monitoring) inside the switch hardware. The bufmond Python script is responsible for adding counter details into the OVSDB bufmon table. The ops-switchd daemon configures switch hardware based on the buffer monitoring configuration in the OVSDB bufmon table.

The switchd plugin uses the bufmon layer APIs to configure the switch hardware, and for statistics collection from the switch hardware. In switchd, the thread *bufmon_stats_thread* is responsible for periodically collecting statistics from the switch hardware, and it also monitors for threshold crossed trigger notifications from the switch hardware. The same thread notifies the switchd main thread to push counter statistics into the database.

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

### Layer 3 loopback interface
The netdev class *l3loopback* is registered to handle layer 3 loopback interfaces. This class has a minimal set of APIs (alloc/construct/distruct/dealloc) registered to handle creation and deletion of layer 3 loopback interfaces. No other configurations are done in the ASIC via netdev for loopback interfaces.

Via ofproto, only IP address configurations are allowed for loopback interfaces. When a loopback interface is deleted, the corresponding IP addresses are removed from the ASIC.

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

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

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

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

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

### Layer 3 interface statistics
For layer 3 interface statistics, FP packet qualification rules are programmed to count unicast and multicast IPv4 and IPv6 packet types. These FPs are programed when a layer 3 interface is created, and removed when an layer 3 interface is removed. These FPs have statistics objects associated with them that are periodically polled to get the number of layer 3 packets and bytes.

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

### Multicast traffic
The plugin is responsible for programming the FP entries which enable the ASIC to forward well-known multicast packets to the CPU for further processing.

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

#### OSPF
The current implementation enables OSPF on a global level. This includes creating a group for OSPF and adding two FP entries with their corresponding stat entries. The FPs forward multicast packets with the following destination IP addresses:

- All OSPF Routers (224.0.0.5)
- OSPF Designated Routers (224.0.0.6)

This is a one-time setup that is done as part of the ops_l3_init process.

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

### Control Plane Policing
Control plane policing (CoPP) protects usage of the CPU by prioritizing and rate-limiting control plane traffic as follows:

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

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------
### Spanning Tree Group
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

-------------------------------------------------------------------------------

-------------------------------------------------------------------------------

### sFlow
sFlow protocol samples ingress and egress packets from the physical interface
on the switch and sends these samples as sFlow UDP datagrams to an external
collector.

-   The plugin creates a KNET filter to register for sFlow reason codes.
-   The sampling rates are configured in the ASIC for each interface.
-   For each sampled packet, ASIC would then set the sFlow reason code and send
    the packet to the registered rx callback function.
-   The rx callback function would then use the sFlow libraries in
    `ops-openvswitch` to send out the sampled packet to the collector.
-   The `run()` function of the plugin would periodically poll the interface
    statistics from the ASIC and send them to the collector using the same
    sFlow libraries.
-   The plugin also maintains the number of samples sent to the collector.
    These statistics are published to the database as part of the generic stats
    collection infrastructure.

-----------------------------------------------------------------------------

-----------------------------------------------------------------------------
### MAC Learning
--------------------------------------

- [Design considerations](#design-considerations)
- [High Level Design](#high-level-design)
- [Design detail](#design-detail)
- [Operations on MAC table](#operations-on-mac-table)
- [MAC Learning References](#mac-learning-references)


#### Design considerations
--------------------------

- Reliability
   There is no dynamic memory allocation in the opennsl plugin layer to shorten the time to copy information given by the ASIC so that no entry is missed.
- Performance
  The callback function is running in a separate thread. There is a need to separate the data storage for the main and the callback thread so that the main thread can read and the callback thread can write to different buffers at the same time without any contention.
- Efficiency
 The data structure that is used must have search operation of O(1). This is required because when ASIC learns a MAC address on a port and later it moves to a different port in a relatively short time, the entry will be part of the same hmap. Hence, instead of adding a new entry in the hmap, the older entry is removed.

The hash map used in the opennsl plugin only holds the delta of the recent changes. The final MAC Table is in the OVSDB.


#### High level design
----------------------

```ditaa
                                                                                       ops-switchd process
  +--------------------------------------------------------------------------------------------------------+
  |                                  +------------------------------------------------------------------+  |
  |  +-------------+                 |                       opennsl plugin                             |  |
  |  | vswitchd    |             1   |                                                                  |  |
  |  | main        |-----------------|--------> init()                                                  |  |
  |  | thread      |                 |            |                                                     |  |
  |  +-------------+                 |            |                                                     |  |
  |        ^                         |            |                                                     |  |
  |        |                         |            |                                           2         |  |
  |        |                         |            |                                        +------      |  |
  |        |                         |            v                                        |     |      |  |
  |        |                         |    mac_learning_init +-----> opennsl_l2_addr_reg(cb_fn)   |      |  |
  |        |                         |                      |-----> opennsl_l2_traverse(cb_fun)  +----  |  |
  |        |                         |                                                           |   |  |  |
  |        |                         |                                                           v   |  |  |
  |        |                         |   +--------------+                                 +--+  +--+ |  |  |
  |        |           3             |   |              |                                 |  |  |--| |  |  |
  |        +-------------------------|---|  bcm timer   |                                 |  |  |  | |  |  |
  |        |                         |   |    thread    |                                 +--+  +--+ |  |  |
  |        |                         |   +--------------+                                   HMAPS    |  |  |
  |        |           3             |                                                               |  |  |
  |        +-------------------------|---------------------------------------------------------------+  |  |
  |                                  |                                                                  |  |
  |                                  +------------------------------------------------------------------+  |
  +--------------------------------------------------------------------------------------------------------+

```

The above diagram describes the interaction between the different functions and threads in the ops-switchd process.
1. When the process starts, the main thread creates `bcm init thread` for the initialization that registers for callback functions in the SDK when a L2 address is added or deleted in the L2 table.
2. When entries are changed in ASIC L2 table, the SDK creates new thread and calls the callback function. The callback function then adds entries in the hmap.
3. The notification to the switchd main thread is triggered when either the current hmap in use is full or the timer thread times out, whichever event happens first.


#### Design detail
------------------

The following are the details featured in this design:
- ASIC Plugin changes (ops-switchd, ops-switchd-opennsl-plugin)
   This comprises of the PD implementation of PI-PD API.
- Registering for bcm callback (ops-switchd-opennsl-plugin)
   MACs are learnt by ASIC and are stored in L2 Table in ASIC.
- Callback function, updating the hmap (ops-switchd-opennsl-plugin)
- Use of hmaps
- Notifying switchd main thread (ops-switchd-opennsl-plugin)

##### Details
-------------

1. ASIC Plugin changes
```ditaa
                                               switchd main thread
    +----------------------------------------------------------------------------------------------------+
    |      main() in ovs-vswitchd.c                      |            bcm_plugins.c                      |
    |                                                    |                                               |
    |      plugins_init() -------------------------------|---------------> init()                        |
    |                                                    |                                               |
    |                                                    |            get_mac_learning_hmap (added)      |
    +----------------------------------------------------------------------------------------------------+
```
  Changes involves the addition of a platform-specific function in the ASIC plugin.

2. Registering for BCM callback
```ditaa
    bcm_init thread

    init()   --------> ops_mac_learning_init()  --------> opennsl_l2_addr_register & opennsl_l2_traverse()
```

   The bcm init thread is created by the switchd main thread for the initialization of the ASIC SDK. Initialization for mac learning involves registration of callback for learnt L2 addresses as well as initial traverse of current addresses in L2 table. Right now, there is no benefit of registering for `opennsl_l2_traverse` as whenever the ops-switchd process restarts, the ASIC is reset. But once the HA infrastructure is in place, this function will provide a way to mark and sweep entries when the ops-switchd process restarts, thereby avoiding reset of the hardware and instead applying only incremental changes to the database.

3. Callback function and updating the hmap

   Whenever any L2 entry is added or deleted in the ASIC L2 table, the SDK invokes the registered callback function (Point 2.). There can be thousands of entries changed in the L2 table leading to that many calls to callback function (the callback function does not handle bulk entries). Hence, the main criteria for this callback function is to spend the least amount of time.

   The hash is the combination of MAC address, VLAN and hw_unit.

4. Use of hmaps

   The opennsl plugin writes to the hmap and the MAC learning plugin reads from the hmap. Since the opennsl plugin and MAC learning plugin are part of the same process (ops-switchd), using of two hmaps avoids using lock for reading the hmap. While writing to hmap, the lock is needed as the bcm init thread and the thread created for SDK callback can simultaneously write to the hmap. Using two hmap buffers also provide an advantage in case of burst of the incoming L2 entries that completely fills up the current hmap, leading to an immediate switch of the current hmap in use to avoid any loss of updates from the SDK.

5. Notifying the switchd main thread

   When the updates for L2 entries are received from the SDK, they are stored locally in the opennsl plugin. In order for it to be written in the OVSDB, the updates needs to be received by the switchd main thread. OVS uses seq_change to trigger notification to the thread waiting for that sequence change event.
   The sequence change can occur in the two cases:
   - The current hmap is full.
   - The timer thread times out and there is at least an entry in the hmap.


#### Operations on MAC table
----------------------------

Currently supported operations:

- MAC Address (dynamic) learning
   MAC address is learnt dynamically when a frame received has the source MAC address, VLAN that is not present in the MAC table for the port.
   [For AS5712, the maximum number of MAC addresses supported in the L2 table is 32k]

- MAC Move
   MAC Move occurs when the same MAC address is learnt on a different port in the bridge for the same VLAN.

- MAC address aging
   Dynamically learnt MAC addresses are deleted from the MAC table if no frame is received for the same the MAC address and VLAN on the port by the time age-out timer expires.
   If after the age out time interval (x seconds) the entry is active, the entry is first marked as inactive and after another age out interval, it is removed from the L2 table (2x seconds).

#### Current hard coded values
------------------------------

- Two hmap buffers
- The hmap buffer size is 16K (can be changed to an optimum value after having scale performance testing).
- The timeout of the timer thread to invoke notification to the switchd main thread is one (1) minute.

#### MAC Learning References
----------------------------

* [Feature design](/documents/dev/user/mac_learning_feature_design)



## OpenFlow Hybrid Switch Support

The OpenSwitch switch driver plugin supports programming the Broadcom switch ASIC using OpenFlow. The switch driver implements an OpenFlow agent as part of the capabilities defined in the Open vSwitch implementation. When configured, this OpenFlow agent communicates with one or more OpenFlow controllers allowing configuration and status to be exchanged using the OpenFlow protocol.

Broadcom ASIC configuration originating from OpenSwitch NoS components and from OpenFlow controller applications are integrated using a strategy discussed in the Hybrid Model section below.

The OpenFlow-hybrid support provided by the plugin is based on the OpenFlow Data Plane Abstraction (OF-DPA). OF-DPA is an open specification that enables programming hardware switches using the OpenFlow protocol. The abstraction is based on OpenFlow 1.3.4 employing multiple flow tables and group entries.  OF-DPA provides OpenFlow controller applications access to the capabilities of forwarding engines such as switch ASICs. While the OpenFlow pipeline provided by the OpenFlow-hybrid implementation in OpenSwitch is related to the one documented at the OF-DPA github page, there are differences due to the fact that the former is part of an OpenFlow-hybrid switch and the latter implements an OpenFlow-only switch.

### Hybrid Model

Various models for organizing OpenFlow-hybrid switches are possible. The model employed in the OpenSwitch switch driver plugin is referred to as "Ships in the Night". In this model, the physical switch is partitioned by assigning ports to either the OpenFlow switch or the traditional switch bridge (bridge_normal). In OpenSwitch, this is accomplished using an OVSDB Bridge table entry representing the OpenFlow switch. This bridge entry has the datapath_type column set to "ofdpa". The OpenFlow related code paths in the switch driver plugin use the datapath_type to verify that OpenFlow configuration is installed on ports assigned to the OpenFlow bridge.

According to the OpenFlow Switch Specification, an OpenFlow-hybrid switch should provide a classification mechanism that routes traffic to either the OpenFlow pipeline or the normal pipeline. The mechanism used in the OpenNSL plugin is based on the port the packet enters the switch. A port is configured to be under the control of the OpenFlow pipeline by referring to the port in the bridge table entry whose datapath_type is "ofdpa".

The initial implementation follows a Ships in the Night model that provides isolated dataplanes. This model can also support an "overlay/underlay" model that provides for traffic to cross the boundary between the OpenFlow and normal pipelines.

### OpenFlow Forwarding Pipeline (TTP)

The OpenFlow pipeline supports the configuration of L2 bridges programmed by OpenFlow controllers. The L2 bridges may be programmed to isolate virtual tenant networks on shared network infrastructure.

Packets are assigned to a virtual tenant by classifying packets based on port, or the combination of port and VLAN. This assignment is done by programming the VLAN table to set the Tunnel-ID metadata for the packet. This Tunnel-ID is used analogous to a VLAN ID to look up the forwarding destination. The controller programs a Bridging table flow entry to match the MAC address and the Tunnel-ID.

OpenFlow pipelines are described by their Table Type Pattern (TTP). A TTP is a JSON description method defined by ONF for describing an OpenFlow pipeline. It describes each flow table and what order they are used to process a packet. The flow tables used by the OF-DPA hybrid pipeline are shown in the following diagram.

```ditaa

            +--------+     +--------+    +-------------+    +----------+    +-----------+
            |        |     |        |    |             |    |          |    |           |
+------+    | Ingress|     | VLAN   |    | Termination |    | Bridging |    | Policy    |    +---------+    +------+
| port +----> Port   +----->        +----> MAC         +---->          +----> ACL       +----> actions +----> port |
+------+    |        |     |        |    |             |    |          |    |           |    +---------+    +------+
            |        |     |        |    |             |    |          |    |           |
            |        |     |        |    |             |    |          |    |           |
            +--------+     +--------+    +-------------+    +----------+    +-----------+
```

Not all of the tables in this diagram are active in this version version, some are placeholders for future use. The inactive flow tables have built-in default flow entries for now and cannot be programmed with flow entries. OpenFlow flow entries contain a "Goto-Table" instruction with specific table ID number. Including tables that will be used in future implementations helps preserve backward compatibility with OpenFlow configurations used in the current TTP.

The flow table IDs for each table are:

Table Name | Table ID
-----------|---------
Ingress Port | 0
VLAN | 10
Termination MAC | 20
Bridging | 50
Policy ACL | 60


#### Ingress Port Flow Table

This is a placeholder flow table. No flows are accepted for this table.

#### VLAN Flow Table

Flows in this table match on port or port and VLAN. The port must be assigned to the OF-DPA bridge for the flow to be added. The set-field action setting the tunnel-id metadata is applied to matching packets. The Goto-Table instruction must specify the Termination MAC flow table.

#### Termination MAC Flow Table

This is a placeholder flow table. No flows are accepted for this table.

#### Bridging Flow Table

Flows in this table match on tunnel-id and destination MAC. The flow entry must include a group action in the write-actions instruction. The Goto-Table instruction must specify the Policy ACL flow table.

#### Policy ACL Flow Table

This is a placeholder flow table. No flows are accepted for this table.

#### L2 Interface Group Entry

The current TTP uses one type of group entry. This is called an L2 Interface group.

In OF-DPA, group ID is used to convey information about the group entry contents. Part of this information is the group entry type within OF-DPA. L2 Interface Group enries are assigned type == 0.

The group ID for this type of group entry is made up of the following fields:

bits: |[31:28]|[27:16]|[15:0]
------|-------|-------|------
content:|Type|VLAN ID|Port

As an example, the ID for an L2 Interface group entry that specifies VLAN ID 100 (0x64) and port 7 (0x0007) is 6553607 (0x00640007).

The action bucket for an L2 Interface Group entry specifies the port the packet is transmitted from. The port must be assigned to the OF-DPA bridge. The action set may also include the pop_vlan action which causes packets to be sent untagged.

### OpenNSL APIs for OpenFlow

The OF-DPA Hybrid feature uses APIs provided in the OpenNSL SDK. These APIs are used to add and remove OpenFlow configuration from the ASIC. Information about these APIs is found in the Broadcom OpenNSL reference below.

### Configuration Example

## References
[OpenvSwitch Porting Guide](http://git.openvswitch.org/cgi-bin/gitweb.cgi?p=openvswitch;a=blob;f=PORTING)
[Broadcom OpenNSL](https://github.com/Broadcom-Switch/OpenNSL)
[OpenFlow Switch Specification ver. 1.3.4](https://www.opennetworking.org/images/stories/downloads/sdn-resources/onf-specifications/openflow/openflow-switch-v1.3.4.pdf)
[OpenFlow Data Plan Abstraction](https://github.com/Broadcom-Switch/of-dpa)
[OpenFlow Table Type Patterns 1.0](https://www.opennetworking.org/images/stories/downloads/sdn-resources/onf-specifications/openflow/OpenFlow%20Table%20Type%20Patterns%20v1.0.pdf)
