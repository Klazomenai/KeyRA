// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title KeyRAAccessControl
/// @notice Simple access control contract for KeyRA authentication
/// @dev Admins can grant/revoke access. Multiple admins supported.
contract KeyRAAccessControl {
    mapping(address => bool) private _admins;
    mapping(address => bool) private _accessList;
    uint256 private _adminCount;

    event AdminAdded(address indexed account, address indexed addedBy);
    event AdminRemoved(address indexed account, address indexed removedBy);
    event AccessGranted(address indexed account, address indexed grantedBy);
    event AccessRevoked(address indexed account, address indexed revokedBy);

    error NotAdmin();
    error CannotRemoveLastAdmin();
    error AlreadyAdmin();
    error NotAnAdmin();
    error AlreadyHasAccess();
    error NoAccess();

    modifier onlyAdmin() {
        if (!_admins[msg.sender]) revert NotAdmin();
        _;
    }

    /// @notice Initialize with the deployer as the first admin
    /// @param initialAdmin The address to set as the initial admin
    constructor(address initialAdmin) {
        _admins[initialAdmin] = true;
        _adminCount = 1;
        emit AdminAdded(initialAdmin, address(0));
    }

    /// @notice Add a new admin
    /// @param account The address to add as admin
    function addAdmin(address account) external onlyAdmin {
        if (_admins[account]) revert AlreadyAdmin();
        _admins[account] = true;
        _adminCount++;
        emit AdminAdded(account, msg.sender);
    }

    /// @notice Remove an admin (cannot remove the last admin)
    /// @param account The address to remove from admins
    function removeAdmin(address account) external onlyAdmin {
        if (!_admins[account]) revert NotAnAdmin();
        if (_adminCount == 1) revert CannotRemoveLastAdmin();
        _admins[account] = false;
        _adminCount--;
        emit AdminRemoved(account, msg.sender);
    }

    /// @notice Grant access to an address
    /// @param account The address to grant access to
    function grantAccess(address account) external onlyAdmin {
        if (_accessList[account]) revert AlreadyHasAccess();
        _accessList[account] = true;
        emit AccessGranted(account, msg.sender);
    }

    /// @notice Revoke access from an address
    /// @param account The address to revoke access from
    function revokeAccess(address account) external onlyAdmin {
        if (!_accessList[account]) revert NoAccess();
        _accessList[account] = false;
        emit AccessRevoked(account, msg.sender);
    }

    /// @notice Check if an address has access
    /// @param account The address to check
    /// @return True if the address has access
    function hasAccess(address account) external view returns (bool) {
        return _accessList[account];
    }

    /// @notice Check if an address is an admin
    /// @param account The address to check
    /// @return True if the address is an admin
    function isAdmin(address account) external view returns (bool) {
        return _admins[account];
    }

    /// @notice Get the current number of admins
    /// @return The admin count
    function adminCount() external view returns (uint256) {
        return _adminCount;
    }
}
