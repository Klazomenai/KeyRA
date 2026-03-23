// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {KeyRAAccessControl} from "../src/AccessList.sol";

/// @notice Handler contract that drives invariant testing by calling
/// admin and access management functions with bounded random inputs.
/// Catches only expected errors — unexpected reverts propagate as failures.
contract KeyRAAccessControlHandler is Test {
    KeyRAAccessControl public acl;

    // Track successful operations for observability
    uint256 public adminsAdded;
    uint256 public adminsRemoved;
    uint256 public accessGranted;
    uint256 public accessRevoked;

    constructor(KeyRAAccessControl _acl) {
        acl = _acl;
    }

    function addAdmin(uint256 seed) external {
        address account = _boundAddr(seed);
        try acl.addAdmin(account) {
            adminsAdded++;
        } catch (bytes memory reason) {
            _expectKnownError(reason);
        }
    }

    function removeAdmin(uint256 seed) external {
        address account = _boundAddr(seed);
        try acl.removeAdmin(account) {
            adminsRemoved++;
        } catch (bytes memory reason) {
            _expectKnownError(reason);
        }
    }

    function grantAccess(uint256 seed) external {
        address account = _boundAddr(seed);
        try acl.grantAccess(account) {
            accessGranted++;
        } catch (bytes memory reason) {
            _expectKnownError(reason);
        }
    }

    function revokeAccess(uint256 seed) external {
        address account = _boundAddr(seed);
        try acl.revokeAccess(account) {
            accessRevoked++;
        } catch (bytes memory reason) {
            _expectKnownError(reason);
        }
    }

    function _boundAddr(uint256 seed) internal pure returns (address) {
        return address(uint160(bound(seed, 1, type(uint160).max)));
    }

    /// @dev Only allow known/expected revert reasons. Unknown reverts fail the test.
    function _expectKnownError(bytes memory reason) internal pure {
        bytes4 selector;
        if (reason.length >= 4) {
            assembly {
                selector := mload(add(reason, 32))
            }
        }

        if (
            selector == KeyRAAccessControl.AlreadyAdmin.selector
                || selector == KeyRAAccessControl.NotAnAdmin.selector
                || selector == KeyRAAccessControl.CannotRemoveLastAdmin.selector
                || selector == KeyRAAccessControl.AlreadyHasAccess.selector
                || selector == KeyRAAccessControl.NoAccess.selector
                || selector == KeyRAAccessControl.ZeroAddress.selector
        ) {
            return; // expected — ignore
        }

        // Unexpected revert — propagate as test failure
        revert(string(reason));
    }
}

/// @notice Invariant tests for KeyRAAccessControl.
/// Verifies properties that must hold regardless of operation sequence.
contract KeyRAAccessControlInvariantTest is Test {
    KeyRAAccessControl public acl;
    KeyRAAccessControlHandler public handler;

    function setUp() public {
        acl = new KeyRAAccessControl(address(this));
        handler = new KeyRAAccessControlHandler(acl);

        // Handler acts as admin so its calls go through onlyAdmin
        acl.addAdmin(address(handler));

        targetContract(address(handler));
    }

    /// @notice Admin count must never reach zero — the contract guard prevents it.
    function invariant_adminCountNeverZero() public view {
        assertGt(acl.adminCount(), 0);
    }

    /// @notice Operations are actually being exercised — not all silently reverting.
    /// Uses a call counter to skip the check on the initial setUp() invocation.
    uint256 private _invariantCalls;

    function invariant_operationsExercised() public {
        _invariantCalls++;
        if (_invariantCalls <= 1) return; // skip initial setUp() check

        uint256 total =
            handler.adminsAdded() + handler.adminsRemoved() + handler.accessGranted()
                + handler.accessRevoked();
        assertGt(total, 0, "No operations succeeded - handler may be misconfigured");
    }
}
