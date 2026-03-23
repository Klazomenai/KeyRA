// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {KeyRAAccessControl} from "../src/AccessList.sol";

contract KeyRAAccessControlTest is Test {
    KeyRAAccessControl public acl;
    address public admin;
    address public user1;
    address public user2;

    // Re-declare events for testing
    event AdminAdded(address indexed account, address indexed addedBy);
    event AdminRemoved(address indexed account, address indexed removedBy);
    event AccessGranted(address indexed account, address indexed grantedBy);
    event AccessRevoked(address indexed account, address indexed revokedBy);

    function setUp() public {
        admin = address(this);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        acl = new KeyRAAccessControl(admin);
    }

    // Constructor tests

    function test_constructor_setsInitialAdmin() public view {
        assertTrue(acl.isAdmin(admin));
        assertEq(acl.adminCount(), 1);
    }

    function test_constructor_emitsAdminAdded() public {
        vm.expectEmit(true, true, false, false);
        emit AdminAdded(user1, address(0));
        new KeyRAAccessControl(user1);
    }

    // Admin management tests

    function test_addAdmin_success() public {
        acl.addAdmin(user1);
        assertTrue(acl.isAdmin(user1));
        assertEq(acl.adminCount(), 2);
    }

    function test_addAdmin_emitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit AdminAdded(user1, admin);
        acl.addAdmin(user1);
    }

    function test_addAdmin_revertsIfNotAdmin() public {
        vm.prank(user1);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.addAdmin(user2);
    }

    function test_addAdmin_revertsIfAlreadyAdmin() public {
        acl.addAdmin(user1);
        vm.expectRevert(KeyRAAccessControl.AlreadyAdmin.selector);
        acl.addAdmin(user1);
    }

    function test_removeAdmin_success() public {
        acl.addAdmin(user1);
        acl.removeAdmin(user1);
        assertFalse(acl.isAdmin(user1));
        assertEq(acl.adminCount(), 1);
    }

    function test_removeAdmin_emitsEvent() public {
        acl.addAdmin(user1);
        vm.expectEmit(true, true, false, false);
        emit AdminRemoved(user1, admin);
        acl.removeAdmin(user1);
    }

    function test_removeAdmin_revertsIfNotAdmin() public {
        vm.prank(user1);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.removeAdmin(admin);
    }

    function test_removeAdmin_revertsIfNotAnAdmin() public {
        vm.expectRevert(KeyRAAccessControl.NotAnAdmin.selector);
        acl.removeAdmin(user1);
    }

    function test_removeAdmin_revertsIfLastAdmin() public {
        vm.expectRevert(KeyRAAccessControl.CannotRemoveLastAdmin.selector);
        acl.removeAdmin(admin);
    }

    // Access management tests

    function test_grantAccess_success() public {
        acl.grantAccess(user1);
        assertTrue(acl.hasAccess(user1));
    }

    function test_grantAccess_emitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit AccessGranted(user1, admin);
        acl.grantAccess(user1);
    }

    function test_grantAccess_revertsIfNotAdmin() public {
        vm.prank(user1);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.grantAccess(user2);
    }

    function test_grantAccess_revertsIfAlreadyHasAccess() public {
        acl.grantAccess(user1);
        vm.expectRevert(KeyRAAccessControl.AlreadyHasAccess.selector);
        acl.grantAccess(user1);
    }

    function test_revokeAccess_success() public {
        acl.grantAccess(user1);
        acl.revokeAccess(user1);
        assertFalse(acl.hasAccess(user1));
    }

    function test_revokeAccess_emitsEvent() public {
        acl.grantAccess(user1);
        vm.expectEmit(true, true, false, false);
        emit AccessRevoked(user1, admin);
        acl.revokeAccess(user1);
    }

    function test_revokeAccess_revertsIfNotAdmin() public {
        acl.grantAccess(user1);
        vm.prank(user1);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.revokeAccess(user1);
    }

    function test_revokeAccess_revertsIfNoAccess() public {
        vm.expectRevert(KeyRAAccessControl.NoAccess.selector);
        acl.revokeAccess(user1);
    }

    // View function tests

    function test_hasAccess_returnsFalseByDefault() public view {
        assertFalse(acl.hasAccess(user1));
    }

    function test_isAdmin_returnsFalseByDefault() public view {
        assertFalse(acl.isAdmin(user1));
    }

    // Multi-admin scenario tests

    function test_multipleAdmins_canGrantAccess() public {
        acl.addAdmin(user1);

        vm.prank(user1);
        acl.grantAccess(user2);

        assertTrue(acl.hasAccess(user2));
    }

    function test_multipleAdmins_canRevokeAccess() public {
        acl.addAdmin(user1);
        acl.grantAccess(user2);

        vm.prank(user1);
        acl.revokeAccess(user2);

        assertFalse(acl.hasAccess(user2));
    }

    function test_adminCanRemoveOtherAdmin() public {
        acl.addAdmin(user1);

        vm.prank(user1);
        acl.removeAdmin(admin);

        assertFalse(acl.isAdmin(admin));
        assertTrue(acl.isAdmin(user1));
        assertEq(acl.adminCount(), 1);
    }

    // Zero-address validation tests

    function test_constructor_revertsOnZeroAddress() public {
        vm.expectRevert(KeyRAAccessControl.ZeroAddress.selector);
        new KeyRAAccessControl(address(0));
    }

    function test_addAdmin_revertsOnZeroAddress() public {
        vm.expectRevert(KeyRAAccessControl.ZeroAddress.selector);
        acl.addAdmin(address(0));
    }

    function test_grantAccess_revertsOnZeroAddress() public {
        vm.expectRevert(KeyRAAccessControl.ZeroAddress.selector);
        acl.grantAccess(address(0));
    }

    // Self-referential operation tests

    function test_removeAdmin_selfRemoval() public {
        acl.addAdmin(user1);
        // admin removes themselves — should succeed since adminCount > 1
        acl.removeAdmin(admin);
        assertFalse(acl.isAdmin(admin));
        assertEq(acl.adminCount(), 1);
    }

    function test_grantAccess_toAdmin() public {
        // admin and access are orthogonal — admin can grant access to themselves
        acl.grantAccess(admin);
        assertTrue(acl.hasAccess(admin));
        assertTrue(acl.isAdmin(admin));
    }

    function test_revokeAccess_fromAdmin() public {
        acl.grantAccess(admin);
        acl.revokeAccess(admin);
        assertFalse(acl.hasAccess(admin));
        assertTrue(acl.isAdmin(admin)); // admin role unaffected
    }

    // State transition cycle tests

    function test_grantAccess_afterRevoke_succeeds() public {
        acl.grantAccess(user1);
        acl.revokeAccess(user1);
        assertFalse(acl.hasAccess(user1));

        // Re-grant should succeed
        acl.grantAccess(user1);
        assertTrue(acl.hasAccess(user1));
    }

    function test_addAdmin_afterRemoval_succeeds() public {
        acl.addAdmin(user1);
        acl.removeAdmin(user1);
        assertFalse(acl.isAdmin(user1));

        // Re-add should succeed
        acl.addAdmin(user1);
        assertTrue(acl.isAdmin(user1));
        assertEq(acl.adminCount(), 2);
    }

    function test_removeAdmin_doesNotRevokeAccess() public {
        acl.addAdmin(user1);
        acl.grantAccess(user1);

        acl.removeAdmin(user1);

        assertFalse(acl.isAdmin(user1));
        assertTrue(acl.hasAccess(user1)); // access and admin are independent
    }

    // Removed admin cannot act tests

    function test_removedAdmin_cannotGrantAccess() public {
        acl.addAdmin(user1);
        acl.removeAdmin(user1);

        vm.prank(user1);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.grantAccess(user2);
    }

    function test_removedAdmin_cannotAddAdmin() public {
        acl.addAdmin(user1);
        acl.removeAdmin(user1);

        vm.prank(user1);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.addAdmin(user2);
    }

    // Multi-admin complex scenario tests

    function test_removeAdmin_threeAdmins_canRemoveTwo() public {
        address user3 = makeAddr("user3");
        acl.addAdmin(user1);
        acl.addAdmin(user3);
        assertEq(acl.adminCount(), 3);

        acl.removeAdmin(user1);
        acl.removeAdmin(user3);
        assertEq(acl.adminCount(), 1);

        // Last admin cannot be removed
        vm.expectRevert(KeyRAAccessControl.CannotRemoveLastAdmin.selector);
        acl.removeAdmin(admin);
    }

    function test_newAdmin_removesOriginalAdmin() public {
        acl.addAdmin(user1);

        // user1 removes the original admin who added them
        vm.prank(user1);
        acl.removeAdmin(admin);

        assertFalse(acl.isAdmin(admin));
        assertEq(acl.adminCount(), 1);

        // user1 is now the sole admin and cannot remove themselves
        vm.prank(user1);
        vm.expectRevert(KeyRAAccessControl.CannotRemoveLastAdmin.selector);
        acl.removeAdmin(user1);
    }

    function test_adminA_grants_adminB_revokes_sameUser() public {
        acl.addAdmin(user1);

        // admin grants access to user2
        acl.grantAccess(user2);

        // user1 (different admin) revokes user2's access
        vm.prank(user1);
        acl.revokeAccess(user2);

        assertFalse(acl.hasAccess(user2));
    }

    // View function dedicated tests

    function test_adminCount_afterMultipleAddRemove() public {
        assertEq(acl.adminCount(), 1);
        acl.addAdmin(user1);
        assertEq(acl.adminCount(), 2);
        acl.addAdmin(user2);
        assertEq(acl.adminCount(), 3);
        acl.removeAdmin(user1);
        assertEq(acl.adminCount(), 2);
        acl.removeAdmin(user2);
        assertEq(acl.adminCount(), 1);
    }

    // Full lifecycle integration test

    function test_fullLifecycle() public {
        // 1. Initial admin grants access to user1
        acl.grantAccess(user1);
        assertTrue(acl.hasAccess(user1));

        // 2. Initial admin adds user1 as admin
        acl.addAdmin(user1);

        // 3. user1 (now admin) grants access to user2
        vm.prank(user1);
        acl.grantAccess(user2);
        assertTrue(acl.hasAccess(user2));

        // 4. user1 revokes user2's access
        vm.prank(user1);
        acl.revokeAccess(user2);
        assertFalse(acl.hasAccess(user2));

        // 5. Original admin removes user1 as admin
        acl.removeAdmin(user1);

        // 6. user1 still has access but cannot admin
        assertTrue(acl.hasAccess(user1));
        vm.prank(user1);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.grantAccess(user2);
    }

    // Fuzz tests — access control enforcement

    function testFuzz_grantAccess_revertsIfNotAdmin(address caller) public {
        vm.assume(caller != admin);
        vm.assume(caller != address(0));
        vm.prank(caller);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.grantAccess(user1);
    }

    function testFuzz_addAdmin_revertsIfNotAdmin(address caller) public {
        vm.assume(caller != admin);
        vm.assume(caller != address(0));
        vm.prank(caller);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.addAdmin(user1);
    }

    function testFuzz_removeAdmin_revertsIfNotAdmin(address caller) public {
        vm.assume(caller != admin);
        vm.assume(caller != address(0));
        vm.prank(caller);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.removeAdmin(admin);
    }

    function testFuzz_revokeAccess_revertsIfNotAdmin(address caller) public {
        acl.grantAccess(user1);
        vm.assume(caller != admin);
        vm.assume(caller != address(0));
        vm.prank(caller);
        vm.expectRevert(KeyRAAccessControl.NotAdmin.selector);
        acl.revokeAccess(user1);
    }

    function testFuzz_grantAccess_thenHasAccess(address account) public {
        vm.assume(account != address(0));
        vm.assume(!acl.hasAccess(account));
        acl.grantAccess(account);
        assertTrue(acl.hasAccess(account));
    }

    function testFuzz_addAdmin_thenIsAdmin(address account) public {
        vm.assume(account != admin);
        vm.assume(account != address(0));
        acl.addAdmin(account);
        assertTrue(acl.isAdmin(account));
    }
}
