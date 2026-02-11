// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./DigitalLegacyVaultV2.sol";

contract DigitalLegacyVaultV3 is DigitalLegacyVaultV2 {
    
    // One-time passcode (nonce) management
    mapping(uint256 => uint256) public claimNonces;           // vaultId => current nonce
    
    // Lifetime access (revocable digital passcode)
    mapping(uint256 => mapping(address => bool)) public hasLifetimeAccess;

    // Events for frontend and logging
    event OneTimePasscodeIssued(uint256 indexed vaultId, address indexed beneficiary, uint256 nonce, uint256 expiry);
    event LifetimeAccessGranted(uint256 indexed vaultId, address indexed heir);
    event LifetimeAccessRevoked(uint256 indexed vaultId, address indexed heir);

    /**
     * @notice Issues a one-time passcode after successful claim verification
     * @dev Called after ZKP, oracle, and guardian threshold are met
     */
    function issueOneTimePasscode(uint256 _vaultId, address _beneficiary) 
        external 
        returns (uint256 nonce, uint256 expiry) 
    {
        require(vaults[_vaultId].state == VaultState.Claimed, "Vault not in Claimed state");
        require(msg.sender == _beneficiary || isGuardian(_vaultId, msg.sender), "Unauthorized caller");

        nonce = claimNonces[_vaultId] + 1;
        claimNonces[_vaultId] = nonce;
        expiry = block.timestamp + 48 hours;

        emit OneTimePasscodeIssued(_vaultId, _beneficiary, nonce, expiry);
        return (nonce, expiry);
    }

    /**
     * @notice Consumes the one-time passcode (called by beneficiary)
     */
    function consumeOneTimePasscode(uint256 _vaultId, uint256 _nonce) external {
        require(claimNonces[_vaultId] == _nonce, "Invalid or already used nonce");
        claimNonces[_vaultId] = 0; // Invalidate immediately
        // TODO: Trigger share reconstruction or archive key release here
    }

    /**
     * @notice Grants lifetime digital passcode (revocable access)
     */
    function grantLifetimeAccess(uint256 _vaultId, address _heir) external {
        require(isVaultOwner(_vaultId, msg.sender) || isGuardian(_vaultId, msg.sender), "Not authorized");
        hasLifetimeAccess[_vaultId][_heir] = true;
        emit LifetimeAccessGranted(_vaultId, _heir);
    }

    /**
     * @notice Revokes lifetime access
     */
    function revokeLifetimeAccess(uint256 _vaultId, address _heir) external {
        require(isVaultOwner(_vaultId, msg.sender) || isGuardian(_vaultId, msg.sender), "Not authorized");
        hasLifetimeAccess[_vaultId][_heir] = false;
        emit LifetimeAccessRevoked(_vaultId, _heir);
    }

    /**
     * @notice Check if heir has lifetime access
     */
    function hasAccess(uint256 _vaultId, address _heir) external view returns (bool) {
        return hasLifetimeAccess[_vaultId][_heir];
    }
}
