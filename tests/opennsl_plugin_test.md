# opennsl Plugin Test Cases

## Contents
- [Test loopback creation and deletion](#test-loopback-creation-and-deletion)
	- [Objective](#objective)
	- [Requirements](#requirements)
	- [Setup](#setup)
		- [Topology Diagram](#topology-diagram)
	- [Description](#description)
	- [Test Result Criteria](#test-result-criteria)
		- [Test Pass Criteria](#test-pass-criteria)
		- [Test Fail Criteria](#test-fail-criteria)
- [ECMP resilient test cases](#ecmp-resilient-test-cases)
        - [Objective](#objective-1)
        - [Requirements](#requirements-1)
        - [Setup](#setup-1)
                - [Topology Diagram](#topology-diagram-1)
        - [Description](#description-1)
        - [Test Result Criteria](#test-result-criteria-1)
                - [Test Pass Criteria](#test-pass-criteria-1)
                - [Test Fail Criteria](#test-fail-criteria-1)

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
