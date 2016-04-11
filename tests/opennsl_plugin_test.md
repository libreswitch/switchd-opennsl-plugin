# opennsl Plugin Test Cases

## Contents
- [Test loopback creation and deletion](#test-loopback-creation-and-deletion)
- [ECMP resilient test cases](#ecmp-resilient-test-cases)
- [Test L3 LAG creation and deletion](#test-l3-lag-creation-and-deletion)
- [Test OSPF field processor entries](#test-ospf-field-processor-entries)

## Test loopback creation and deletion
### Objective
Verify creating a loopback interface, and assigning an IP address to it. Also verify deleting the loopback interface.
### Requirements
 - RTL setup with physical switch

### Setup
#### Topology Diagram
```
[switch1] <==> [host1]
```
### Description
1. Create port 1 on switch1.
2. Assign the IP address 10.0.10.1 to port 1.
3. Get the UUID of the port 1.
4. Using the ovsdb-client command:
 - Create a loopback interface lo:1 of type loopback.
 - Create a port lo:1 and assign the interface lo:1 to it.
 - Assign the port lo:1 to vrf_default along with port 1.
5. Assign the IP address 2.2.2.1 to port lo:1.
6. Configure host1 eth1 with IP address 10.0.10.2 and default gateway 10.0.10.1.
7. Ping 2.2.2.1 from host1.
8. Using ovsdb-client, delete port lo:1.
9. Ping 2.2.2.1 from host1.

### Test Result Criteria
#### Test Pass Criteria
The first ping passes and the second ping fails.
#### Test Fail Criteria
The first ping fails and the second ping passes.

## ECMP resilient test cases
### Objective
The ECMP resiliency is toggled and all the l3 ecmp egress objects must reflect the appropriate state.

### Requirements
 - RTL setup with physical switch

### Setup
#### Topology Diagram
```
[switch1] <==> [switch2]
```

### Description
1. Configure three interfaces with IP addresses between switch1 and switch2.
2. Configure static routes with three different nexthops ie the 3 links between switch1 and switch2.
3. Check for the 'ovs-appctl' command to see if ECMP resiliency is set.
4. Disable the ECMP resiliency, and check the ovs-appctl command to see if ecmp resiliency is unset.

### Test Result Criteria
#### Test Pass Criteria
   If ECMP resiliency is enabled for all l3ecmp objects in default state.
   if ECMP resiliency is disabled when disabled through configuration.
   Dynamic Size is 512 when resiliency is enabled and 0 when disabled.
   All l3 ecmp egress objects should adhere to the above criteria.

#### Test Fail Criteria
   When resiliency flag in the l3 ecmp egress object is false when enabled, or set to true when disabled.

## Test L3 LAG creation and deletion
### Objective
Verify LAG L3 interface add/deletes members, add/deletes knet filters and creates LAG in the hardware.

### Requirements
 - RTL setup with physical switch

### Setup
#### Topology Diagram
```
[switch1] <==> [switch2]
```

### Description
1. Enable two interfaces between switch1 and switch2.
2. Configure L3 LAG and add these interfaces as members.
3. Using 'ovs-appctl' test if:
    a. internal vlan is created.
    b. if the internal vlan has the members in its bitmap.
    c. if the lag has the members in its bitmap.
4. Shutdown interface 1, and repeat test in step 3.
5. Shutdown interface 2, and repeat test in step 3.
6. Enable both interfaces.
7. Remove interface 1 from LAG, and repeat test in step 3.
8. Remove interface 2 from LAG, and repeat test in step 3.

### Test Result Criteria
#### Test Pass Criteria
   Internal VLAN should be created with members in the bitmap.
   LAG should be created with members in the bitmap.
   When both interfaces are 'shutdown' the lag should exist but the bitmap should be all zeros.
   When both interfaces are 'shutdown' the VLAN should be deleted.
   When both interfaces are removed from the lag, LAG should be destroyed.
   When both interfaces are removed from LAG the VLAN should be deleted.

#### Test Fail Criteria
   Internal VLAN does not exists with members in the bitmap after LAG creation.
   LAG not created with members in the bitmap.
   When both interfaces are 'shutdown' the lag does not exist or the bitmap show non-zero.
   When both interfaces are 'shutdown' the VLAN does not get deleted.
   When both interfaces are removed from the lag, LAG exists.
   When both interfaces are removed from LAG the VLAN does not get deleted.

## Test OSPF field processor entries
### Objective
This test checks for the two OSPF field processor entries programmed in the ASIC.
### Requirements
A physical switch is required for this test.

### Setup
#### Topology diagram
```ditaa
+---------------+
|               |
|    Switch     |
|               |
+---------------+
```
### Description
1. Use the `ovs-appctl` command for retrieving the existing field processor (FP) entries in the ASIC.
    ```
    ovs-appctl plugin/debug fp
    ```

2. Check for the FP entry that forwards OSPF "All Routers" traffic to the CPU. The entry has the following qualifiers:
    - Destination MAC address - 01:00:5E:00:00:05
    - Destination IP address -  224.0.0.5
    - Protocol Type - 0x59
3. Check for the FP entry that forwards OSPF "Designated Routers" traffic to the CPU. The entry has the following qualifiers:
    - Destination MAC address - 01:00:5E:00:00:06
    - Destination IP address -  224.0.0.6
    - Protocol Type - 0x59

### Test result criteria
#### Test pass criteria
The two OSPF field processor entries are present in the ASIC.
#### Test fail criteria
None of the OSPF field processor entries are present in the ASIC.
