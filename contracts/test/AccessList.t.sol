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
}
