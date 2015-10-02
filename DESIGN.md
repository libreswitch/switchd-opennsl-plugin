# High level design of ops-switchd-opennsl-plugin
ops-switchd-opennsl-plugin is *OpenSwitch* switch driver plugin for Broadcom switch ASICs.

## Overview
*OpenSwitch* is a database driven network operating system (NOS) for Open Compute Project (OCP) compliant switch hardware.

The following diagram depicts high level relations between various daemons in the OpenSwitch:

```ditaa
+----------------+  +-------------+  +---------------+
|                |  |             |  |               |
|  Management    |  |  Layer2     |  |  Layer3       |
| CL/REST/Bufmond|  |  Daemons    |  |  Daemons      |
|                |  |             |  |               |
+-------------+--+  +----+--------+  +----+----------+
              |          |                |
              +-----+    |      +---------+
                    |    |      |
                    |    |      |
               +----+----+------+-------+
               |                        |
               |         OVS DB         |
               +-----------+------------+
                           |
                   +-------+---------+
                   |   ops-switchd   |
             +-------------+----------------+
             |      switchd OpenNSL plugin  |
             +------------------------------+
             |        OpenNSL SDK           |
             |                              |
             +------------------------------+
     +-------------------------------------------+
     |                                           |
     | OpenNSL                                   |
     | Kernel Drivers               Linux        |
     | (knet, bde)                  Kernel       |
     |                                           |
     +-------------------------------------------+
     |                                           |
     |            Switch Hardware                |
     |                                           |
     +-------------------------------------------+
```
In the above diagram, "ops-switchd + switchd-opennsl-plugin + opennsl SDK" is called switch driver in this document. Various daemons (management + L2 + L3) read the user configuration from ovs-db, and generate hardware configuration into ovs-db. Switch driver reads this configuration and configures the switch ASIC.

In *OpenSwitch* the 'Switch driver' architecture is based on the "Open vSwitch" architecture. In the above diagram, ops-switchd is a generic hardware independent layer, derived from the "Open vSwitch/ops-switchd" code.

"Switchd-opennsl-plugin" is a dynamically loadable Plugin library. It uses open APIs published in OpenNSL SDK (open source SDK for Broadcom switch ASICs).

This plugin is divided into three layers:
  1. netdev layer
  2. ofproto layer
  3. bufmon layer

OpenNSL SDK is Broadcom provided and maintained binary version of their switch development software.

## Terminology
Across the switch driver, different layers uses different terminologies.

### In OVS-DB
Layer 3 router is called "vrf".
Layer 2 switch is called "bridge".
Logical layer 2 switch port, trunk/LAG, layer 3 routable port, layer 3 routable VLAN interface are all identified as "port".
Layer 1 physical interface is called "interface".

### In ops-switchd
ops-switchd uses the same naming convention as ovs-db.

### In switchd-opennsl-plugin
#### In netdev layer
In opennsl-plugin, netdev layer's primary scope is layer 1 device configuration. It calls the ASIC ports as "interfaces".
#### In ofproto layer
Layer 3 router is called "vrf".
Layer 2 switch is called "bridge".
Logical layer 2 switch port, trunk/LAG, layer 3 routable port, layer 3 routable VLAN interface are identified as "bundle".
Layer 1 physical interface is called "port".
#### In bufmon layer
Bufmon layer provides API to configure the switch hardware, based on buffer monitoring counters configuration residing in the database and counter statistics collection from the switch hardware.

#### In OpenNSL API code
Layer 1 physical interface and layer 2 logical switch port are called "port", trunk/LAG are called "trunk", layer 3 routable port and layer3 routable VLAN interface are called "L3 interface".

## Design
Switchd plugin is responsible for configuring the switch ASIC based on configuration passed down by ops-switchd. Configuration passed down by ops-switchd is hardware independent. Switchd plugin configures the switch ASIC using hardware dependent API based on this configuration.

At high level the OpenNSL switch plugin functionality can be divided into the following categories:
1. Physical interface configuration.
   * Layer 1 interface configuration
        * KNET Linux virtual Ethernet interfaces
   * Trunk configuration
2. Layer2 switching
3. Layer3 routing
4. Advanced statistics

### Physical interface configuration
In *OpenSwitch* software "ops-intfd" daemon is responsible for physical interface configuration. It derives hardware configuration based on user configuration (Interface:user_config), transceiver data, and other interface related information. Switch plugin configures the switch ASIC (and other peripheral devices like PHYs and MACs) as per the given hardware configuration.

Switchd plugin should also create one Linux virtual Ethernet interface per physical interface present in the ASIC. Protocol BPDUs received in the switch ASIC should be readable via these Ethernet interfaces for Layer 2 & Layer 3 daemon consumption. These daemons will also write the protocol BPDUs into these virtual Ethernet devices. These frames should be transmitted out of the switch ASIC interfaces. opennsl-plugin achieves this functionality by creating virtual Ethernet devices called "KNET interfaces".

These two functionalities are in the netdev layer of the opennsl-plugin.

#### Trunk/LAG configuration
OpenSwitch supports both static and dynamic link aggregation. One or more physical switch ASIC interfaces can be grouped to create a trunk. Currently a maximum of eight interfaces can be grouped as one trunk.
Based on user configuration "ops-lacpd" daemon updates Interface:hw_bond_config column in the database. Switchd plugin should configure trunks in hardware based on this information.
Trunk functionality is handled in the ofproto layer of the opennsl-plugin.

#### Layer2 switching
In OpenSwitch port VLAN information is stored in three important fields:
* Port:tag
* Port:trunks
* Port:vlan_mode

vlan_mode has four possible values.
1. VLAN_ACCESS: Port carries packets on exactly one VLAN specified in Port:tag.  Only untagged packets are accepted on ingress, and all packets are transmitted untagged.
2. VLAN_TRUNK: Port carries packets on one or more VLANs specified in Port:trunks. If Port:trunks is empty, then it can carry all VLANS defined in the system.  All packets transmitted and received are tagged.
3. VLAN_NATIVE_TAGGED: Port resembles a trunk port, with the exception that all untagged packets ingressing the switch go to the native VLAN specified by Port:tag.  All packets egressing the switch are tagged, including packets egressing the native VLAN.
4. VLAN_NATIVE_UNTAGGED: Port resembles a native-tagged port, with the exception that packets egressing the native VLAN are untagged.

This functionality is handled in ofproto layer.

### Layer3 routing
Switchd plugin supports layer3 routing for IPv4 and IPv6 protocols. ops-switchd learns route/nexthop from ovs-db and pushes down to switchd plugin. Plugin intern calls opennsl API to populate host, longest prefix match (LPM) and ECMP table in ASIC. ECMP hashing currently supports 16-bit CRC-CCITT. By default hashing tuple is source ip, destination ip, source port and destination port. Tuple element can be included/excuded in hash calculation through CLI.

Layer3 functionality is handled in ofproto layer.

### Code details
The most important entry point into the switchd plugin is "bundle_set()" function. Configuration for the entire switch is passed in a structure called 'struct ofproto_bundle_settings'.

It is expected that switchd plugin will maintain a local copy of the switch configuration passed in using the above structure. "bundle_set()" is always called with the entire switch configuration every time. Plugin code should compare it with its local state and derive what has changed since the last function call.

#### Asynchronous notifications
Switchd plugin cannot directly modify the ovs-db. ops-switchd is the only layer which can read/write to the database. Whenever switchd plugin wants to write something to the database, it will increase a counter in the "netdev structure" shared between switchd plugin and ops-switchd layer. Changing the counter also wakes up the ops-switchd layer main thread if it is sleeping. When ops-switchd layer notices the change in the counter value of a netdev device, it will query the entire state of that netdev from the switchd plugin and update the state into ovs-db. Link state changes are updated using this mechanism.

ops-switchd layer collects basic interface statistics once every five seconds by default. User can increase this value to higher than five seconds as needed.

### Buffer Monitoring
OpenSwitch supports monitoring of MMU buffer space consumption (buffer statistics and monitoring) inside the switch hardware. The bufmond Python script is responsible for adding counter details into the ovs-db bufmon table. ops-switchd configures switch hardware based on buffer monitoring  configuration in the ovs-db bufmon table.

Switchd uses bufmon layer API's to configure the switch hardware and for statistics collection from the switch hardware. In switchd the thread "bufmon_stats_thread" is responsible for collecting statistics periodically from the switch hardware, and it will also monitor for threshold crossed trigger notifications from the switch hardware. The same thread will notify the switchd main thread to push counter statistics into the database.

## References
[OpenvSwitch Porting Guide](http://git.openvswitch.org/cgi-bin/gitweb.cgi?p=openvswitch;a=blob;f=PORTING)
[Broadcom OpenNSL](https://github.com/Broadcom-Switch/OpenNSL)
