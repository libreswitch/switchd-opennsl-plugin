# High Level Design of ops-switchd-opennsl-plugin

## Contents

   * [Overview](#overview)
   * [Terminology](#terminology)
    * [In OVSDB](#in-ovsdb)
    * [In ops-switchd](#in-ops-switchd)
    * [In switchd-opennsl-plugin](#in-switchd-opennsl-plugin)
       * [In netdev layer](#in-netdev-layer)
       * [In ofproto layer](#in-ofproto-layer)
       * [In bufmon layer](#in-bufmon-layer)
       * [In OpenNSL API code](#in-opennsl-api-code)
   * [Design](#design)
     * [Physical interface configuration](#physical-interface-configuration)
       * [Trunk/LAG configuration](#trunklag-configuration)
       * [Layer2 switching](#layer2-switching)
     * [Layer3 routing](#layer3-routing)
     * [Code details](#code-details)
       * [Asynchronous notifications](#asynchronous-notifications)
     * [Buffer monitoring](#buffer-monitoring)
     * [L3 loopback interface](#l3-loopback-interface)
     * [L3 subinterface](#l3-subinterface)
   * [References](#references)

## Overview
*OpenSwitch* is a database driven network operating system (NOS) for Open Compute Project (OCP) compliant switch hardware. The *OpenSwitch* switch driver plugin, ops-switchd-opennsl-plugin, is for Broadcom switch ASICs.

The following diagram depicts high level relations between various daemons in the OpenSwitch software:

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
               |         OVSDB          |
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
In the above diagram, "ops-switchd + switchd-opennsl-plugin + opennsl SDK" is called switch driver in this document. Various daemons (management + L2 + L3) read the user configuration from the OVSDB, and generate the hardware configuration into the OVSDB. Switch driver reads this configuration and configures the switch ASIC.

In *OpenSwitch* software the "switch driver" architecture is based on the "Open vSwitch" architecture. In the above diagram, ops-switchd is a generic hardware independent layer, derived from the "Open vSwitch/ops-switchd" code.

"Switchd-opennsl-plugin" is a dynamically loadable plugin library. It uses open APIs published in OpenNSL SDK (open source SDK for Broadcom switch ASICs).

This plugin is divided into three layers:
  1. netdev layer
  2. ofproto layer
  3. bufmon layer

The OpenNSL SDK is provided by Broadcom, and is a maintained binary version of their switch development software.

## Terminology
Across the switch driver, different layers uses different terminologies.

### In OVSDB
Layer 3 router is called "vrf".
Layer 2 switch is called "bridge".
Logical layer 2 switch port, trunk/LAG, layer 3 routable port, layer 3 routable VLAN interface are all identified as "port".
Layer 1 physical interface is called "interface".

### In ops-switchd
The ops-switchd uses the same naming convention as the OVSDB.

### In switchd-opennsl-plugin
#### In netdev layer
The primary scope of the netdev layer is layer 1 device configuration. It calls the ASIC ports "interfaces".
#### In ofproto layer
Layer 3 router is called "vrf".
Layer 2 switch is called "bridge".
Logical layer 2 switch port, trunk/LAG, layer 3 routable port, layer 3 routable VLAN interface are identified as "bundle".
Layer 1 physical interface is called "port".
#### In bufmon layer
The bufmon layer provides an API to configure the switch hardware, based on the buffer monitoring counter's configuration residing in the database, and counter statistics collected from the switch hardware.

#### In OpenNSL API code
Layer 1 physical interface and layer 2 logical switch port are called "port".
Trunk/LAG is called "trunk".
Layer 3 routable port and layer3 routable VLAN interface are called "L3 interface".

## Design
The switchd plugin is responsible for configuring the switch ASIC based on the configuration passed down by ops-switchd. The configuration passed down by ops-switchd is hardware independent. The switchd plugin configures the switch ASIC using a hardware dependent API based on this configuration.

At a high level the OpenNSL switch plugin functionality can be divided into the following categories:
1. Physical interface configuration.
   * Layer 1 interface configuration
        * KNET Linux virtual Ethernet interfaces
   * Trunk configuration
2. Layer2 switching
3. Layer3 routing
4. Advanced statistics

### Physical interface configuration
In *OpenSwitch* software the "ops-intfd" daemon is responsible for physical interface configuration. It derives the hardware configuration based on the user configuration (Interface:user_config), transceiver data, and other interface related information. The switch plugin configures the switch ASIC, and other peripheral devices like PHYs and MACs, per the given hardware configuration.

The switchd plugin also creates one Linux virtual Ethernet interface per physical interface present in the ASIC. Protocol BPDUs received in the switch ASIC are readable via these Ethernet interfaces for Layer 2 & Layer 3 daemon consumption. These daemons also write the protocol BPDUs into these virtual Ethernet devices. These frames should be transmitted out of the switch ASIC interfaces. The opennsl-plugin achieves this functionality by creating virtual Ethernet devices called "KNET interfaces".

These two functionalities are in the netdev layer of the opennsl-plugin.

#### Trunk/LAG configuration
OpenSwitch supports both static and dynamic link aggregation. One or more physical switch ASIC interfaces can be grouped to create a trunk. Currently a maximum of eight interfaces can be grouped as one trunk.
Based on the user configuration, the "ops-lacpd" daemon updates the Interface:hw_bond_config column in the database. The switchd plugin configures trunks in the hardware based on this information
Trunk functionality is handled in the ofproto layer of the opennsl-plugin.

#### Layer2 switching
In OpenSwitch, port VLAN information is stored in three important fields:
* Port:tag
* Port:trunks
* Port:vlan_mode

The vlan_mode field has four possible values:
1. VLAN_ACCESS: The port carries packets on exactly one VLAN specified in Port:tag.  Only untagged packets are accepted on ingress, and all packets are transmitted untagged.
2. VLAN_TRUNK: The port carries packets on one or more VLANs specified in Port:trunks. If Port:trunks is empty, then it can carry all VLANS defined in the system.  All packets transmitted and received are tagged.
3. VLAN_NATIVE_TAGGED: The port resembles a trunk port, with the exception that all untagged packets ingressing the switch go to the native VLAN specified by Port:tag.  All packets egressing the switch are tagged, including packets egressing the native VLAN.
4. VLAN_NATIVE_UNTAGGED: The port resembles a native-tagged port, with the exception that packets egressing the native VLAN are untagged.

This functionality is handled in the ofproto layer.

### Layer3 routing
The switchd plugin supports layer3 routing for IPv4 and IPv6 protocols. The ops-switchd daemon learns route/nexthop from the OVSDB and pushes it down to the switchd plugin. Plugin intern calls the opennsl API to populate the host, the longest prefix match (LPM), and the ECMP table in the ASIC. ECMP hashing currently supports 16-bit CRC-CCITT. By default hashing tuple is source ip, destination ip, source port, and destination port. Tuple element can be included/excuded in the hash calculation through CLI.

Layer3 functionality is handled in the ofproto layer.

### Code details
The most important entry point into the switchd plugin is the "bundle_set()" function. Configuration for the entire switch is passed in a structure called 'struct ofproto_bundle_settings'.

It is expected that the switchd plugin maintains a local copy of the switch configuration that was passed using the above structure. The "bundle_set()" function is always called with the entire switch configuration. The plugin code compares the switch configuration with its local state, and derives what has changed since the last function call.

#### Asynchronous notifications
The switchd plugin cannot directly modify the OVSDB. The ops-switchd layer is the only layer which can read/write to the database. Whenever the switchd plugin writes something to the database, it increases a counter in the "netdev structure" shared between the switchd plugin and the ops-switchd layer. Changing the counter also wakes up the ops-switchd layer's main thread if it is sleeping. When the ops-switchd layer notices a change in the counter value of a netdev device, it queries the entire state of that netdev from the switchd plugin, and updates the state in the OVSDB. Link state changes are updated using this mechanism.

The ops-switchd layer collects basic interface statistics once every five seconds by default. This value can be increased as needed.

### Buffer monitoring
OpenSwitch supports monitoring MMU buffer space consumption (buffer statistics and monitoring) inside the switch hardware. The bufmond Python script is responsible for adding counter details into the OVSDB bufmon table. The ops-switchd daemon configures switch hardware based on the buffer monitoring configuration in the OVSDB bufmon table.

The switchd plugin uses the bufmon layer APIs to configure the switch hardware, and for statistics collection from the switch hardware. In switchd the thread "bufmon_stats_thread" is responsible for periodically collecting statistics from the switch hardware, and it also monitors for threshold crossed trigger notifications from the switch hardware. The same thread notifies the switchd main thread to push counter statistics into the database.

### L3 loopback interface
The netdev class "l3loopback" is registered to handle L3 loopback interfaces. This class has a minimal set of APIs (alloc/construct/distruct/dealloc) registered to handle creation and deletion of L3 loopback interfaces. No other configurations are done in the ASIC via netdev for loopback interfaces.

Via ofproto, only IP address configurations are allowed for loopback interfaces. When a loopback interface is deleted, the corresponding IP addresses are removed from the ASIC.

### L3 subinterface
The netdev class "subinterface" is registered to handle L3 subinterfaces. This class has APIs to handle basic netdev operations (alloc/construct/distruct/dealloc), and an API set_config() to handle a subinterface 802.1q VLAN tag, a MAC address, and parent hardware port ID configurations.

Following are the actions done on subinterface creation:
- Create a VLAN if it does not already exist.
- Create the L3 interface using the VRF, VLAN ID, MAC, and parent hardware port properties. If the VLAN ID is not configured, the L3 interface cannot be created.
- Create a KNET filter to retain the VLAN tag.
- Create an Field Processor(FP) rule on the parent port to drop packets that have a destination MAC not matching MyStationTCAM; to avoid switching on the subinterface VLAN ID.
- Update the parent interface in the trunk bitmap and the subinterface bitmap for the VLAN.
- Configure the IP addresses.

Following are the actions done on subinterface deletion:
- Delete the L3 interface created for the subinterface using the netdev `distruct` operation.
- Delete the VLAN, if it has not been created by the user. In this case, "not been created by the user" means VLANS created for L2.
- Clear just the parent port bit from the trunk and the subinterface bitmap, if the VLAN already exists.

Following are the actions done on subinterface vlan config change:
- Delete the old subinterface and then create a new subinterface with the new VLAN, if the VLAN of a subinterface is changed.
- Add just the parent port bit to the trunk and the subinterface bitmap, if the new VLAN already exists.
- Create a new VLAN and update the trunk and the subinterface bitmap with a parent port bit, if the VLAN does not exist.

If a VLAN is deleted without deleting the subinterface, the VLAN is not deleted from the ASIC, and the parent port bit is left set in the trunk bitmap and subinterface bitmap.


## References
[OpenvSwitch Porting Guide](http://git.openvswitch.org/cgi-bin/gitweb.cgi?p=openvswitch;a=blob;f=PORTING)
[Broadcom OpenNSL](https://github.com/Broadcom-Switch/OpenNSL)
