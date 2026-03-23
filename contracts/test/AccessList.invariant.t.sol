// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {KeyRAAccessControl} from "../src/AccessList.sol";

/// @notice Handler contract that drives invariant testing by calling
/// admin and access management functions with bounded random inputs.
contract KeyRAAccessControlHandler is Test {
    KeyRAAccessControl public acl;
    address public initialAdmin;

    constructor(KeyRAAccessControl _acl, address _initialAdmin) {
        acl = _acl;
        initialAdmin = _initialAdmin;
    }

    function addAdmin(uint256 seed) external {
        address account = _boundAddr(seed);
        if (account == address(0)) return;
        try acl.addAdmin(account) {} catch {}
    }

    function removeAdmin(uint256 seed) external {
        address account = _boundAddr(seed);
        if (account == address(0)) return;
        try acl.removeAdmin(account) {} catch {}
    }

    function grantAccess(uint256 seed) external {
        address account = _boundAddr(seed);
        if (account == address(0)) return;
        try acl.grantAccess(account) {} catch {}
    }

    function revokeAccess(uint256 seed) external {
        address account = _boundAddr(seed);
        if (account == address(0)) return;
        try acl.revokeAccess(account) {} catch {}
    }

    function _boundAddr(uint256 seed) internal pure returns (address) {
        return address(uint160(bound(seed, 1, type(uint160).max)));
    }
}

/// @notice Invariant tests for KeyRAAccessControl.
/// Verifies properties that must hold regardless of operation sequence.
contract KeyRAAccessControlInvariantTest is Test {
    KeyRAAccessControl public acl;
    KeyRAAccessControlHandler public handler;
    address public initialAdmin;

    function setUp() public {
        initialAdmin = address(this);
        acl = new KeyRAAccessControl(initialAdmin);
        handler = new KeyRAAccessControlHandler(acl, initialAdmin);

        // Handler acts as admin so its calls go through onlyAdmin
        acl.addAdmin(address(handler));

        targetContract(address(handler));
    }

    /// @notice Admin count must never reach zero — the contract guard prevents it.
    function invariant_adminCountNeverZero() public view {
        assertGt(acl.adminCount(), 0);
    }

    /// @notice Admin count must always be at least 1.
    function invariant_adminCountMatchesMinimum() public view {
        assertGe(acl.adminCount(), 1);
    }

    /// @notice The initial admin or the handler must remain an admin
    /// (since CannotRemoveLastAdmin prevents removal of the final admin).
    function invariant_atLeastOneKnownAdminExists() public view {
        assertTrue(
            acl.isAdmin(initialAdmin) || acl.isAdmin(address(handler)),
            "Neither initial admin nor handler is admin"
        );
    }
}
