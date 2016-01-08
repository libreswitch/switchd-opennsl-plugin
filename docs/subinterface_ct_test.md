
# Subinterface Test Cases

## Contents

- [Create subinterface and check vlan creation.]
- [Check knet filter creation for subinterface, bridge_normal, l3 interface and bpdu.]
- [Check vlan deletion when subinterface is disabled.]
- [Check if vlan bitmaps update when parent interface link changes.]
- [Change the vlan associated to the subinterface 1.10.]
- [Check all operation when user creates a vlan and adds subinterface to that vlan.]
- [Check vlan deletion when subinterface is deleted.]


## Create subinterface and check vlan creation
### Objective
   check ovs-appctl to see if any vlan is created. Also check if the parent interface is in the bitmap of trunk and subinterface bitmap.
### Requirements
   Enabling interface 1 on switch.
   Configuring ipv4 address 10.0.10.1 on interface 1.
   Enable host 1 interface eth1.
   Create subinterface interface 1.10 using uuid of interface 1 for vlan 10.
   Configuring ipv4 address 2.2.2.1 on subinterface.
   Check l3 ports bitmap for Vlan 10.
### Test Result Criteria
#### Test Pass Criteria
   subinterface & vlan 10 should be created.
   Parent interface is in the bitmap of trunk and subinterface bitmap.
#### Test Fail Criteria
   Vlan 10 does not exists, parent interface not part of the bitmap for trunk and subinterface.

## Check knet filter creation for subinterface, bridge_normal, l3 interface and bpdu.
### Objective
   Subinterface knet filter should be created while creating subinterface to redirect traffic from inport to corresponding kernel outport.
   Bridge normal knet filter is already created.
   l3 interface knet filter is already created.
   bpdu knet filter is already created.
### Requirements
   Subinterface is created.
### Test Result Criteria
#### Test Pass Criteria
   Subinterface knet filter is created.
   bridge_normal knet filter is created.
   l3 interface knet filter is created.
   bpdu knet filter is created.
#### Test Fail Criteria
   Knet filter does not exist for subinterface.

## Check vlan deletion when subinterface is disabled.
### Objective
    Subinterface should delete the vlan if it was not created by user
### Requirements
    Disable the subinterface 1.10.
### Test Result Criteria
#### Test Pass Criteria
    Check Vlan 10 is deleted.
#### Test Fail Criteria
    Vlan 10 is not deleted.

## Check if vlan bitmaps update when parent interface link changes.
### Objective
    Vlan bitmaps should get reset to zero when parent interface goes down.
### Requirements
    Disable parent interface 1.
### Test Result Criteria
#### Test Pass Criteria
    Trunk and subinterface bitmap will show all zeros in their respective bitmaps.
#### Test Fail Criteria
    Trunk and subinterface bitmap shows parent interface in its bitmap.

## Change the vlan associated to the subinterface 1.10
### Objective
   The old vlan is delted (if not created by user) and the new vlan is created with the bitmap.
### Requirements
   Run ovs command to set vlan 30 for subinterface 1.10
### Test Result Criteria
#### Test Pass Criteria
   Verify vlan 10 has been deleted and vlan 30 created with bit map of parent interface using appctl.
#### Test Fail Criteria
   Vlan 10 is not deleted, vlan 30 is not created.

## Check all operation when user creates a vlan and adds subinterface to that vlan.
### Objective
   Check bitmap for all l2 and l3 ports associated with the vlan.
   Check if subinterface goes down l2 ports remain the vlan bitmap.
   Check if vlan is deleted by user, vlan continues to exist internally as subinterface is part of it.
### Requirements
   Create vlan 20.
   Associate interface 2 to vlan 20.
   Associate interface 3 to vlan 20.
   Create subinterface 1.20 and associate it to vlan 20.
### Test Result Criteria
#### Test Pass Criteria
   Check bitmap for all l2 and l3 ports.
   After subinterface goes down on l2 ports should be in the bitmaps.
   After user deletes the vlan, vlan should exist.
#### Test Fail Criteria
   Vlan exists and bitmaps contains the parent interface.

## Check vlan deletion when subinterface is deleted
### Objective
   Delete subinterface port and interface in ovsdb and verify the vlan gets deleted
### Requirements
   Delete subinterface using ovs command.
   Check vlan 20 using appctl.
### Test Result Criteria
#### Test Pass Criteria
   Verify Vlan 20 is deleted using appctl.
#### Test Fail Criteria
   Vlan 20 not deleted.

