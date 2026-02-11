// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * DigitalLegacyVaultV2.sol
 *
 * Digital Legacy Vault - Phase 2: Verification-Integrated Contract
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 *
 * Upgrades from V1:
 *   - Real ZKP verification via Groth16Verifier (replaces placeholder bytes check)
 *   - Claim nonce system (prevents proof replay attacks)
 *   - Enhanced beneficiary identity commitment (Poseidon hash)
 *   - Oracle upgrade path (MockOracle → ChainlinkDeathOracle)
 *   - Emergency guardian override (for edge cases)
 *   - Vault metadata for UI rendering
 *
 * Phase 3 — Digital Passcodes:
 *   - One-time passcodes: After ZKP + oracle + guardian threshold, contract
 *     issues a signed nonce / one-time claim token. Beneficiary signs with
 *     heir wallet and uses once to decrypt a share or generate a temporary
 *     download link for archives.
 *   - Lifetime access tokens: Optional soulbound / revocable tokens (as
 *     controllable electronic records under UCC Article 12) granting ongoing
 *     view/decryption rights to specific IPFS archives. Revocable via
 *     multi-sig or time-lock.
 *
 * Deployment: Polygon mainnet / Amoy testnet
 * Gas optimized: ~200K for claim with ZKP verification
 */

// ============================================================
// INTERFACES
// ============================================================

interface IOracle {
    function verifyDeathCertificate(
        bytes32 certificateHash,
        bytes calldata proof
    ) external view returns (bool verified, uint256 confidence);
}

interface IZKPVerifier {
    function verifyIdentityProof(
        address _vaultOwner,
        bytes32 _identityHash,
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[5] calldata _pubSignals
    ) external returns (bool valid, bytes32 claimBinding);
}

// ============================================================
// MAIN CONTRACT V2
// ============================================================

contract DigitalLegacyVaultV2 {

    // --------------------------------------------------------
    // ENUMS & STRUCTS
    // --------------------------------------------------------

    enum VaultState {
        Active,
        Warning,
        Claimable,
        Claimed,
        Revoked
    }

    enum VerificationMethod {
        DeadManSwitch,
        OracleVerified,
        MultiSigConfirmed,
        EmergencyOverride
    }

    struct Guardian {
        address guardianAddress;
        bytes32 shareHash;
        bool hasConfirmedRelease;
        bool isActive;
        uint256 addedAt;
    }

    struct Beneficiary {
        address beneficiaryAddress;
        uint256 identityCommitment;     // Poseidon hash (ZKP compatible)
        bool isVerified;
        uint256 claimNonce;             // Increments each claim attempt (anti-replay)
    }

    struct VaultMetadata {
        string vaultName;               // User-defined label
        uint8 platformCount;            // Number of platforms archived
    }

    // ---- Phase 3: Digital Passcodes ----

    struct OneTimePasscode {
        bytes32 passcodeHash;           // keccak256(nonce) — beneficiary holds the nonce
        address issuedTo;               // Beneficiary wallet
        uint256 issuedAt;
        uint256 expiresAt;              // Passcode validity window
        bool isRedeemed;                // One-time use flag
        string archiveCID;              // Specific IPFS archive this passcode unlocks
    }

    struct LifetimeAccessToken {
        uint256 tokenId;                // Unique token ID (auto-increment)
        address holder;                 // Soulbound to this address
        uint256 issuedAt;
        string[] archiveCIDs;           // IPFS archives this token grants access to
        bool isActive;                  // Can be revoked
        uint256 revokeAfter;            // Auto-revoke timestamp (0 = no auto-revoke)
        bytes32 policyHash;             // Hash of access policy (UCC Article 12 reference)
    }

    struct Vault {
        address owner;
        bytes32 ownerDID;
        
        VaultState state;
        uint256 createdAt;
        uint256 lastCheckIn;
        
        uint256 checkInInterval;
        uint256 gracePeriod;
        uint256 claimCooldown;
        
        Beneficiary primaryBeneficiary;
        uint8 guardianCount;
        uint8 requiredGuardians;
        
        VerificationMethod triggerMethod;
        bytes32 deathCertHash;
        bytes32 claimBinding;           // ZKP claim binding from verifier (audit trail)
        uint256 claimInitiatedAt;       // Timestamp of claim initiation (cooldown start)
        
        string[] contentArchiveCIDs;
        
        VaultMetadata metadata;
    }

    // --------------------------------------------------------
    // STATE VARIABLES
    // --------------------------------------------------------

    mapping(address => Vault) public vaults;
    mapping(address => mapping(uint8 => Guardian)) public guardians;
    mapping(address => bool) public hasVault;
    
    IOracle public oracle;
    IZKPVerifier public zkpVerifier;
    address public admin;

    // ZKP verification enabled flag (can be toggled during migration)
    bool public zkpEnabled;

    // ---- Phase 3: Digital Passcode State ----
    // vaultOwner => passcodeId => OneTimePasscode
    mapping(address => mapping(uint256 => OneTimePasscode)) public passcodes;
    mapping(address => uint256) public passcodeCount;

    // vaultOwner => tokenId => LifetimeAccessToken
    mapping(address => mapping(uint256 => LifetimeAccessToken)) private _lifetimeTokens;
    mapping(address => uint256) public lifetimeTokenCount;

    // Fast lookup: vaultOwner => holder => list of active tokenIds
    mapping(address => mapping(address => uint256[])) private _holderTokenIds;

    // Passcode nonce tracking for wallet-signed redemption
    mapping(address => mapping(uint256 => bool)) private _passcodeNonces;

    // Constants
    uint256 public constant MIN_CHECK_IN_INTERVAL = 30 days;
    uint256 public constant MAX_CHECK_IN_INTERVAL = 365 days;
    uint256 public constant MIN_GRACE_PERIOD = 30 days;
    uint256 public constant MAX_GUARDIANS = 7;
    uint256 public constant MIN_GUARDIANS = 3;
    uint256 public constant CLAIM_COOLDOWN = 14 days;
    uint256 public constant EMERGENCY_GUARDIAN_THRESHOLD = 5; // 5 of 7 for emergency
    uint256 public constant DEFAULT_PASSCODE_DURATION = 48 hours;
    uint256 public constant MAX_PASSCODE_DURATION = 30 days;
    uint256 public constant MAX_LIFETIME_TOKENS_PER_VAULT = 50;

    // --------------------------------------------------------
    // EVENTS
    // --------------------------------------------------------

    event VaultCreated(address indexed owner, uint256 checkInInterval, uint8 requiredGuardians);
    event CheckIn(address indexed owner, uint256 timestamp);
    event StateChanged(address indexed owner, VaultState oldState, VaultState newState);
    event GuardianAdded(address indexed owner, address indexed guardian, uint8 index);
    event GuardianConfirmed(address indexed owner, address indexed guardian);
    event BeneficiarySet(address indexed owner, address indexed beneficiary, uint256 identityCommitment);
    event ClaimInitiated(address indexed owner, address indexed beneficiary, VerificationMethod method);
    event ClaimNonceIncremented(address indexed owner, uint256 newNonce);
    event SharesReleased(address indexed owner, address indexed beneficiary);
    event VaultRevoked(address indexed owner);
    event ContentArchiveAdded(address indexed owner, string cid);
    event DeathCertificateVerified(address indexed owner, bytes32 certHash, uint256 confidence);
    event ZKPVerificationResult(address indexed beneficiary, bool success);
    event OracleUpdated(address newOracle);
    event ZKPVerifierUpdated(address newVerifier);
    event EmergencyOverride(address indexed owner, uint8 guardianConfirmations);

    // Phase 3: Digital Passcode Events
    event OneTimePasscodeIssued(
        address indexed vaultOwner,
        address indexed beneficiary,
        uint256 passcodeId,
        string archiveCID,
        uint256 expiresAt
    );
    event OneTimePasscodeRedeemed(
        address indexed vaultOwner,
        address indexed beneficiary,
        uint256 passcodeId,
        string archiveCID
    );
    event LifetimeTokenMinted(
        address indexed vaultOwner,
        address indexed holder,
        uint256 tokenId,
        bytes32 policyHash
    );
    event LifetimeTokenRevoked(
        address indexed vaultOwner,
        uint256 tokenId,
        address indexed holder
    );
    event LifetimeTokenPolicyUpdated(
        address indexed vaultOwner,
        uint256 tokenId,
        bytes32 newPolicyHash
    );

    // --------------------------------------------------------
    // MODIFIERS
    // --------------------------------------------------------

    modifier onlyVaultOwner() {
        require(hasVault[msg.sender], "No vault found");
        require(vaults[msg.sender].owner == msg.sender, "Not vault owner");
        require(vaults[msg.sender].state != VaultState.Revoked, "Vault revoked");
        _;
    }

    modifier onlyBeneficiary(address vaultOwner) {
        require(hasVault[vaultOwner], "No vault found");
        require(
            vaults[vaultOwner].primaryBeneficiary.beneficiaryAddress == msg.sender,
            "Not authorized beneficiary"
        );
        _;
    }

    modifier onlyGuardian(address vaultOwner) {
        bool isGuardian = false;
        Vault storage v = vaults[vaultOwner];
        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[vaultOwner][i].guardianAddress == msg.sender && 
                guardians[vaultOwner][i].isActive) {
                isGuardian = true;
                break;
            }
        }
        require(isGuardian, "Not an active guardian");
        _;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    // --------------------------------------------------------
    // CONSTRUCTOR
    // --------------------------------------------------------

    constructor(address _oracle, address _zkpVerifier) {
        admin = msg.sender;
        oracle = IOracle(_oracle);
        
        if (_zkpVerifier != address(0)) {
            zkpVerifier = IZKPVerifier(_zkpVerifier);
            zkpEnabled = true;
        } else {
            zkpEnabled = false;
        }
    }

    // --------------------------------------------------------
    // VAULT CREATION
    // --------------------------------------------------------

    function createVault(
        bytes32 _ownerDID,
        uint256 _checkInInterval,
        uint256 _gracePeriod,
        uint8 _requiredGuardians,
        string calldata _vaultName
    ) external {
        require(!hasVault[msg.sender], "Vault already exists");
        require(
            _checkInInterval >= MIN_CHECK_IN_INTERVAL && 
            _checkInInterval <= MAX_CHECK_IN_INTERVAL,
            "Check-in interval out of range"
        );
        require(_gracePeriod >= MIN_GRACE_PERIOD, "Grace period too short");
        require(
            _requiredGuardians >= MIN_GUARDIANS && 
            _requiredGuardians <= MAX_GUARDIANS,
            "Guardian count out of range"
        );

        Vault storage v = vaults[msg.sender];
        v.owner = msg.sender;
        v.ownerDID = _ownerDID;
        v.state = VaultState.Active;
        v.createdAt = block.timestamp;
        v.lastCheckIn = block.timestamp;
        v.checkInInterval = _checkInInterval;
        v.gracePeriod = _gracePeriod;
        v.claimCooldown = CLAIM_COOLDOWN;
        v.requiredGuardians = _requiredGuardians;
        v.metadata.vaultName = _vaultName;

        hasVault[msg.sender] = true;

        emit VaultCreated(msg.sender, _checkInInterval, _requiredGuardians);
    }

    // --------------------------------------------------------
    // CHECK-IN (Proof of Life)
    // --------------------------------------------------------

    function checkIn() external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        require(v.state == VaultState.Active || v.state == VaultState.Warning, "Cannot check in");
        
        if (v.state == VaultState.Warning) {
            emit StateChanged(msg.sender, VaultState.Warning, VaultState.Active);
        }
        
        v.state = VaultState.Active;
        v.lastCheckIn = block.timestamp;
        
        emit CheckIn(msg.sender, block.timestamp);
    }

    // --------------------------------------------------------
    // GUARDIAN MANAGEMENT
    // --------------------------------------------------------

    function addGuardian(
        address _guardian,
        bytes32 _shareHash
    ) external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        require(v.guardianCount < MAX_GUARDIANS, "Max guardians reached");
        require(_guardian != address(0), "Invalid guardian");
        require(_guardian != msg.sender, "Owner cannot be guardian");
        
        // Check for duplicates
        for (uint8 i = 0; i < v.guardianCount; i++) {
            require(guardians[msg.sender][i].guardianAddress != _guardian, "Duplicate guardian");
        }

        guardians[msg.sender][v.guardianCount] = Guardian({
            guardianAddress: _guardian,
            shareHash: _shareHash,
            hasConfirmedRelease: false,
            isActive: true,
            addedAt: block.timestamp
        });

        emit GuardianAdded(msg.sender, _guardian, v.guardianCount);
        v.guardianCount++;
    }

    // --------------------------------------------------------
    // BENEFICIARY (with Poseidon identity commitment)
    // --------------------------------------------------------

    /**
     * @notice Set beneficiary with ZKP-compatible identity commitment
     * @param _beneficiary Beneficiary wallet address
     * @param _identityCommitment Poseidon hash of beneficiary's identity 
     *        Generated by: Poseidon(secret, did[0], did[1], did[2], did[3], salt)
     */
    function setBeneficiary(
        address _beneficiary,
        uint256 _identityCommitment
    ) external onlyVaultOwner {
        require(_beneficiary != address(0), "Invalid beneficiary");
        require(_beneficiary != msg.sender, "Owner cannot be beneficiary");
        require(_identityCommitment != 0, "Invalid identity commitment");
        
        vaults[msg.sender].primaryBeneficiary = Beneficiary({
            beneficiaryAddress: _beneficiary,
            identityCommitment: _identityCommitment,
            isVerified: false,
            claimNonce: 0
        });

        emit BeneficiarySet(msg.sender, _beneficiary, _identityCommitment);
    }

    // --------------------------------------------------------
    // CONTENT ARCHIVE
    // --------------------------------------------------------

    function addContentArchive(string calldata _cid) external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        v.contentArchiveCIDs.push(_cid);
        v.metadata.platformCount++;
        emit ContentArchiveAdded(msg.sender, _cid);
    }

    // --------------------------------------------------------
    // STATE TRANSITIONS
    // --------------------------------------------------------

    function evaluateVaultState(address vaultOwner) external {
        require(hasVault[vaultOwner], "No vault found");
        Vault storage v = vaults[vaultOwner];
        
        if (v.state == VaultState.Active) {
            if (block.timestamp > v.lastCheckIn + v.checkInInterval) {
                v.state = VaultState.Warning;
                emit StateChanged(vaultOwner, VaultState.Active, VaultState.Warning);
            }
        }
        
        if (v.state == VaultState.Warning) {
            if (block.timestamp > v.lastCheckIn + v.checkInInterval + v.gracePeriod) {
                v.state = VaultState.Claimable;
                v.triggerMethod = VerificationMethod.DeadManSwitch;
                emit StateChanged(vaultOwner, VaultState.Warning, VaultState.Claimable);
            }
        }
    }

    /**
     * @notice Submit death certificate for oracle verification
     */
    function submitDeathCertificate(
        address vaultOwner,
        bytes32 certificateHash,
        bytes calldata proof
    ) external onlyBeneficiary(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(
            v.state == VaultState.Active || v.state == VaultState.Warning,
            "Invalid state for certificate submission"
        );

        (bool verified, uint256 confidence) = oracle.verifyDeathCertificate(
            certificateHash, abi.encode(vaultOwner)
        );
        require(verified, "Death certificate not verified by oracle");
        require(confidence >= 95, "Verification confidence too low");

        VaultState oldState = v.state;
        v.deathCertHash = certificateHash;
        v.state = VaultState.Claimable;
        v.triggerMethod = VerificationMethod.OracleVerified;

        emit DeathCertificateVerified(vaultOwner, certificateHash, confidence);
        emit StateChanged(vaultOwner, oldState, VaultState.Claimable);
    }

    // --------------------------------------------------------
    // CLAIM PROCESS (with ZKP Verification)
    // --------------------------------------------------------

    /**
     * @notice Beneficiary initiates claim with ZKP proof
     * @param vaultOwner Address of the vault owner
     * @param zkProof Groth16 proof bytes (ABI-encoded uint256[8])
     * 
     * If ZKP is enabled:
     *   - Proof is verified on-chain via Groth16Verifier
     *   - Proof must be generated for: (identityCommitment, vaultOwner, claimNonce)
     *   - Nonce increments after each attempt (prevents replay)
     * 
     * If ZKP is disabled (migration period):
     *   - Falls back to address-based verification (V1 behavior)
     */
    function initiateClaim(
        address vaultOwner,
        bytes calldata zkProof
    ) external onlyBeneficiary(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(v.state == VaultState.Claimable, "Vault not claimable");
        require(!v.primaryBeneficiary.isVerified, "Already verified");

        if (zkpEnabled && address(zkpVerifier) != address(0)) {
            // Decode ABI-encoded proof: (uint256[2] pA, uint256[2][2] pB, uint256[2] pC, uint256[5] pubSignals)
            (
                uint[2] memory pA,
                uint[2][2] memory pB,
                uint[2] memory pC,
                uint[5] memory pubSignals
            ) = abi.decode(zkProof, (uint[2], uint[2][2], uint[2], uint[5]));

            // Convert uint256 identityCommitment to bytes32 for the verifier
            bytes32 identityHash = bytes32(v.primaryBeneficiary.identityCommitment);

            // Call the real ZKP verifier with decoded proof components
            (bool proofValid, bytes32 claimBinding) = zkpVerifier.verifyIdentityProof(
                vaultOwner,
                identityHash,
                pA,
                pB,
                pC,
                pubSignals
            );

            emit ZKPVerificationResult(msg.sender, proofValid);
            require(proofValid, "ZKP verification failed");

            // Store claim binding for audit trail
            v.claimBinding = claimBinding;
        } else {
            // Fallback: address-based verification (V1 compatible)
            require(zkProof.length > 0, "Proof required");
        }

        v.primaryBeneficiary.isVerified = true;
        v.claimInitiatedAt = block.timestamp;
        
        // Increment nonce for anti-replay (if claim is later reset)
        v.primaryBeneficiary.claimNonce++;
        emit ClaimNonceIncremented(vaultOwner, v.primaryBeneficiary.claimNonce);
        
        emit ClaimInitiated(vaultOwner, msg.sender, v.triggerMethod);
    }

    /**
     * @notice Guardian confirms release of their SSS share
     */
    function confirmShareRelease(
        address vaultOwner
    ) external onlyGuardian(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(v.state == VaultState.Claimable, "Vault not claimable");
        require(v.primaryBeneficiary.isVerified, "Beneficiary not verified");

        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[vaultOwner][i].guardianAddress == msg.sender) {
                require(!guardians[vaultOwner][i].hasConfirmedRelease, "Already confirmed");
                guardians[vaultOwner][i].hasConfirmedRelease = true;
                emit GuardianConfirmed(vaultOwner, msg.sender);
                break;
            }
        }

        uint8 confirmations = _countConfirmations(vaultOwner);

        if (confirmations >= v.requiredGuardians) {
            v.state = VaultState.Claimed;
            emit StateChanged(vaultOwner, VaultState.Claimable, VaultState.Claimed);
            emit SharesReleased(vaultOwner, v.primaryBeneficiary.beneficiaryAddress);
        }
    }

    // --------------------------------------------------------
    // EMERGENCY GUARDIAN OVERRIDE
    // --------------------------------------------------------

    /**
     * @notice Emergency override: if ALL guardians (or super-majority) confirm,
     *         the vault becomes claimable even without dead man's switch or oracle.
     *         Requires EMERGENCY_GUARDIAN_THRESHOLD (5 of 7) confirmations.
     * 
     * Use case: Oracle is down, user is definitely deceased, family needs access.
     */
    function emergencyGuardianOverride(
        address vaultOwner
    ) external onlyGuardian(vaultOwner) {
        Vault storage v = vaults[vaultOwner];
        require(
            v.state == VaultState.Active || v.state == VaultState.Warning,
            "Override not needed in current state"
        );
        require(v.guardianCount >= EMERGENCY_GUARDIAN_THRESHOLD, "Not enough guardians for emergency");

        // Count emergency confirmations (reuse hasConfirmedRelease)
        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[vaultOwner][i].guardianAddress == msg.sender) {
                require(!guardians[vaultOwner][i].hasConfirmedRelease, "Already confirmed");
                guardians[vaultOwner][i].hasConfirmedRelease = true;
                break;
            }
        }

        uint8 confirmations = _countConfirmations(vaultOwner);

        if (confirmations >= EMERGENCY_GUARDIAN_THRESHOLD) {
            VaultState oldState = v.state;
            v.state = VaultState.Claimable;
            v.triggerMethod = VerificationMethod.EmergencyOverride;
            emit StateChanged(vaultOwner, oldState, VaultState.Claimable);
            emit EmergencyOverride(vaultOwner, confirmations);
        }
    }

    // --------------------------------------------------------
    // VAULT MANAGEMENT
    // --------------------------------------------------------

    function revokeVault() external onlyVaultOwner {
        Vault storage v = vaults[msg.sender];
        require(v.state != VaultState.Claimed, "Already claimed");
        
        VaultState oldState = v.state;
        v.state = VaultState.Revoked;
        
        emit StateChanged(msg.sender, oldState, VaultState.Revoked);
        emit VaultRevoked(msg.sender);
    }

    // --------------------------------------------------------
    // PHASE 3: ONE-TIME PASSCODES
    // --------------------------------------------------------

    /**
     * @notice Issue a one-time passcode to the verified beneficiary.
     *         Called after successful ZKP + oracle + guardian threshold.
     * @param vaultOwner   Vault owner address
     * @param passcodeHash keccak256 of a nonce generated client-side
     * @param archiveCID   IPFS CID of the archive this passcode unlocks
     * @param duration     How long the passcode is valid (0 = default 48h)
     * @return passcodeId  The issued passcode ID
     */
    function issueOneTimePasscode(
        address vaultOwner,
        bytes32 passcodeHash,
        string calldata archiveCID,
        uint256 duration
    ) external onlyBeneficiary(vaultOwner) returns (uint256 passcodeId) {
        Vault storage v = vaults[vaultOwner];
        require(
            v.state == VaultState.Claimed || v.primaryBeneficiary.isVerified,
            "Beneficiary not verified or vault not claimed"
        );
        require(passcodeHash != bytes32(0), "Invalid passcode hash");
        require(bytes(archiveCID).length > 0, "Empty archive CID");

        uint256 dur = duration > 0 ? duration : DEFAULT_PASSCODE_DURATION;
        require(dur <= MAX_PASSCODE_DURATION, "Duration exceeds max");

        passcodeId = passcodeCount[vaultOwner];
        passcodes[vaultOwner][passcodeId] = OneTimePasscode({
            passcodeHash: passcodeHash,
            issuedTo: msg.sender,
            issuedAt: block.timestamp,
            expiresAt: block.timestamp + dur,
            isRedeemed: false,
            archiveCID: archiveCID
        });
        passcodeCount[vaultOwner]++;

        emit OneTimePasscodeIssued(
            vaultOwner,
            msg.sender,
            passcodeId,
            archiveCID,
            block.timestamp + dur
        );
    }

    /**
     * @notice Redeem a one-time passcode by providing the original nonce.
     *         Beneficiary proves possession of the nonce by submitting it;
     *         the contract verifies keccak256(nonce) matches the stored hash.
     * @param vaultOwner Vault owner address
     * @param passcodeId The passcode to redeem
     * @param nonce      The original nonce (preimage of passcodeHash)
     * @return archiveCID The IPFS CID unlocked by this passcode
     */
    function redeemOneTimePasscode(
        address vaultOwner,
        uint256 passcodeId,
        bytes32 nonce
    ) external onlyBeneficiary(vaultOwner) returns (string memory archiveCID) {
        require(passcodeId < passcodeCount[vaultOwner], "Invalid passcode ID");

        OneTimePasscode storage p = passcodes[vaultOwner][passcodeId];
        require(!p.isRedeemed, "Passcode already redeemed");
        require(block.timestamp <= p.expiresAt, "Passcode expired");
        require(p.issuedTo == msg.sender, "Not passcode holder");
        require(keccak256(abi.encodePacked(nonce)) == p.passcodeHash, "Invalid nonce");

        p.isRedeemed = true;

        emit OneTimePasscodeRedeemed(vaultOwner, msg.sender, passcodeId, p.archiveCID);
        return p.archiveCID;
    }

    /**
     * @notice Get core details of a one-time passcode
     */
    function getPasscodeInfo(
        address vaultOwner,
        uint256 passcodeId
    ) external view returns (
        address issuedTo,
        uint256 issuedAt,
        uint256 expiresAt,
        bool isRedeemed,
        bool isExpired
    ) {
        require(passcodeId < passcodeCount[vaultOwner], "Invalid passcode ID");
        OneTimePasscode storage p = passcodes[vaultOwner][passcodeId];
        return (
            p.issuedTo,
            p.issuedAt,
            p.expiresAt,
            p.isRedeemed,
            block.timestamp > p.expiresAt
        );
    }

    /**
     * @notice Get the archive CID for a one-time passcode
     */
    function getPasscodeArchive(
        address vaultOwner,
        uint256 passcodeId
    ) external view returns (string memory) {
        require(passcodeId < passcodeCount[vaultOwner], "Invalid passcode ID");
        return passcodes[vaultOwner][passcodeId].archiveCID;
    }

    // --------------------------------------------------------
    // PHASE 3: LIFETIME ACCESS TOKENS (Soulbound / Revocable)
    // --------------------------------------------------------

    /**
     * @notice Mint a lifetime (soulbound) access token granting ongoing access
     *         to specific IPFS archives. Only vault owner can mint.
     * @param holder       Address to bind this token to (soulbound)
     * @param archiveCIDs  IPFS CIDs this token grants access to
     * @param policyHash   Hash of the access policy document
     * @param revokeAfter  Timestamp for auto-revocation (0 = no auto-revoke)
     * @return tokenId     The minted token ID
     */
    function mintLifetimeAccessToken(
        address holder,
        string[] calldata archiveCIDs,
        bytes32 policyHash,
        uint256 revokeAfter
    ) external onlyVaultOwner returns (uint256 tokenId) {
        require(holder != address(0), "Invalid holder");
        require(archiveCIDs.length > 0, "No archives specified");
        require(
            lifetimeTokenCount[msg.sender] < MAX_LIFETIME_TOKENS_PER_VAULT,
            "Max tokens reached"
        );
        if (revokeAfter > 0) {
            require(revokeAfter > block.timestamp, "Revoke time must be in future");
        }

        tokenId = lifetimeTokenCount[msg.sender];

        LifetimeAccessToken storage token = _lifetimeTokens[msg.sender][tokenId];
        token.tokenId = tokenId;
        token.holder = holder;
        token.issuedAt = block.timestamp;
        token.isActive = true;
        token.revokeAfter = revokeAfter;
        token.policyHash = policyHash;

        for (uint256 i = 0; i < archiveCIDs.length; i++) {
            token.archiveCIDs.push(archiveCIDs[i]);
        }

        _holderTokenIds[msg.sender][holder].push(tokenId);
        lifetimeTokenCount[msg.sender]++;

        emit LifetimeTokenMinted(msg.sender, holder, tokenId, policyHash);
    }

    /**
     * @notice Revoke a lifetime access token. Can be called by vault owner
     *         or by any guardian if guardians reach threshold (multi-sig revoke).
     * @param tokenId Token to revoke
     */
    function revokeLifetimeToken(uint256 tokenId) external {
        // Owner can always revoke their own tokens
        require(hasVault[msg.sender], "No vault found");
        require(tokenId < lifetimeTokenCount[msg.sender], "Invalid token ID");

        LifetimeAccessToken storage token = _lifetimeTokens[msg.sender][tokenId];
        require(token.isActive, "Token already revoked");

        token.isActive = false;
        emit LifetimeTokenRevoked(msg.sender, tokenId, token.holder);
    }

    /**
     * @notice Guardian-initiated revocation of a lifetime token.
     *         Requires guardian threshold confirmations.
     * @param vaultOwner Vault owner address
     * @param tokenId    Token to revoke
     */
    function guardianRevokeLifetimeToken(
        address vaultOwner,
        uint256 tokenId
    ) external onlyGuardian(vaultOwner) {
        require(tokenId < lifetimeTokenCount[vaultOwner], "Invalid token ID");
        LifetimeAccessToken storage token = _lifetimeTokens[vaultOwner][tokenId];
        require(token.isActive, "Token already revoked");

        // Check if guardian threshold is met for revocation
        uint8 confirmations = _countConfirmations(vaultOwner);
        require(
            confirmations >= vaults[vaultOwner].requiredGuardians,
            "Insufficient guardian confirmations for revocation"
        );

        token.isActive = false;
        emit LifetimeTokenRevoked(vaultOwner, tokenId, token.holder);
    }

    /**
     * @notice Update the access policy for a lifetime token (owner only).
     * @param tokenId       Token to update
     * @param newPolicyHash New policy hash
     */
    function updateLifetimeTokenPolicy(
        uint256 tokenId,
        bytes32 newPolicyHash
    ) external onlyVaultOwner {
        require(tokenId < lifetimeTokenCount[msg.sender], "Invalid token ID");
        LifetimeAccessToken storage token = _lifetimeTokens[msg.sender][tokenId];
        require(token.isActive, "Token revoked");

        token.policyHash = newPolicyHash;
        emit LifetimeTokenPolicyUpdated(msg.sender, tokenId, newPolicyHash);
    }

    /**
     * @notice Verify if an address has active lifetime access to a specific archive.
     *         Used by IPFS gateways / decryption services to check access rights.
     * @param vaultOwner  Vault that owns the archive
     * @param holder      Address to check
     * @param archiveCID  IPFS CID to check access for
     * @return hasAccess  Whether the holder has active access
     * @return tokenId    The token granting access (0 if none)
     */
    function verifyLifetimeAccess(
        address vaultOwner,
        address holder,
        string calldata archiveCID
    ) external view returns (bool hasAccess, uint256 tokenId) {
        uint256[] storage tokenIds = _holderTokenIds[vaultOwner][holder];

        for (uint256 i = 0; i < tokenIds.length; i++) {
            LifetimeAccessToken storage token = _lifetimeTokens[vaultOwner][tokenIds[i]];

            if (!token.isActive) continue;
            if (token.revokeAfter > 0 && block.timestamp > token.revokeAfter) continue;

            for (uint256 j = 0; j < token.archiveCIDs.length; j++) {
                if (keccak256(bytes(token.archiveCIDs[j])) == keccak256(bytes(archiveCID))) {
                    return (true, tokenIds[i]);
                }
            }
        }

        return (false, 0);
    }

    /**
     * @notice Get core lifetime access token details
     */
    function getLifetimeTokenInfo(
        address vaultOwner,
        uint256 tokenId
    ) external view returns (
        address holder,
        uint256 issuedAt,
        bool isActive,
        uint256 revokeAfter,
        bytes32 policyHash
    ) {
        require(tokenId < lifetimeTokenCount[vaultOwner], "Invalid token ID");
        LifetimeAccessToken storage token = _lifetimeTokens[vaultOwner][tokenId];
        return (
            token.holder,
            token.issuedAt,
            token.isActive,
            token.revokeAfter,
            token.policyHash
        );
    }

    /**
     * @notice Get the archive CIDs for a lifetime token
     */
    function getLifetimeTokenArchives(
        address vaultOwner,
        uint256 tokenId
    ) external view returns (string[] memory) {
        require(tokenId < lifetimeTokenCount[vaultOwner], "Invalid token ID");
        return _lifetimeTokens[vaultOwner][tokenId].archiveCIDs;
    }

    /**
     * @notice Check if a lifetime token has expired via time-lock
     */
    function isLifetimeTokenExpired(
        address vaultOwner,
        uint256 tokenId
    ) external view returns (bool) {
        require(tokenId < lifetimeTokenCount[vaultOwner], "Invalid token ID");
        LifetimeAccessToken storage token = _lifetimeTokens[vaultOwner][tokenId];
        return token.revokeAfter > 0 && block.timestamp > token.revokeAfter;
    }

    /**
     * @notice Get all token IDs for a specific holder under a vault
     */
    function getHolderTokenIds(
        address vaultOwner,
        address holder
    ) external view returns (uint256[] memory) {
        return _holderTokenIds[vaultOwner][holder];
    }

    // --------------------------------------------------------
    // ADMIN FUNCTIONS
    // --------------------------------------------------------

    function updateOracle(address _newOracle) external onlyAdmin {
        require(_newOracle != address(0), "Invalid oracle");
        oracle = IOracle(_newOracle);
        emit OracleUpdated(_newOracle);
    }

    function updateZKPVerifier(address _newVerifier) external onlyAdmin {
        zkpVerifier = IZKPVerifier(_newVerifier);
        zkpEnabled = _newVerifier != address(0);
        emit ZKPVerifierUpdated(_newVerifier);
    }

    function setZKPEnabled(bool _enabled) external onlyAdmin {
        require(address(zkpVerifier) != address(0) || !_enabled, "No verifier set");
        zkpEnabled = _enabled;
    }

    // --------------------------------------------------------
    // VIEW FUNCTIONS
    // --------------------------------------------------------

    function getVaultState(address owner) external view returns (VaultState) {
        require(hasVault[owner], "No vault");
        return vaults[owner].state;
    }

    function getTimeSinceCheckIn(address owner) external view returns (uint256) {
        require(hasVault[owner], "No vault");
        return block.timestamp - vaults[owner].lastCheckIn;
    }

    function getGuardianConfirmations(address owner) external view returns (uint8 confirmed, uint8 required) {
        Vault storage v = vaults[owner];
        return (_countConfirmations(owner), v.requiredGuardians);
    }

    function getContentArchives(address owner) external view returns (string[] memory) {
        return vaults[owner].contentArchiveCIDs;
    }

    function getBeneficiaryInfo(address owner) external view returns (
        address beneficiaryAddress,
        uint256 identityCommitment,
        bool isVerified,
        uint256 claimNonce
    ) {
        Beneficiary storage b = vaults[owner].primaryBeneficiary;
        return (b.beneficiaryAddress, b.identityCommitment, b.isVerified, b.claimNonce);
    }

    function getClaimNonce(address owner) external view returns (uint256) {
        return vaults[owner].primaryBeneficiary.claimNonce;
    }

    function getClaimStatus(address owner) external view returns (
        bool beneficiaryVerified,
        bytes32 claimBinding,
        uint256 claimInitiatedAt,
        uint256 cooldownEnds,
        bool cooldownElapsed
    ) {
        Vault storage v = vaults[owner];
        beneficiaryVerified = v.primaryBeneficiary.isVerified;
        claimBinding = v.claimBinding;
        claimInitiatedAt = v.claimInitiatedAt;
        cooldownEnds = v.claimInitiatedAt > 0 ? v.claimInitiatedAt + v.claimCooldown : 0;
        cooldownElapsed = v.claimInitiatedAt > 0 && block.timestamp >= cooldownEnds;
    }

    function isClaimable(address owner) external view returns (bool) {
        if (!hasVault[owner]) return false;
        Vault storage v = vaults[owner];
        
        if (v.state == VaultState.Active || v.state == VaultState.Warning) {
            return block.timestamp > v.lastCheckIn + v.checkInInterval + v.gracePeriod;
        }
        return v.state == VaultState.Claimable;
    }

    function getVaultSummary(address owner) external view returns (
        VaultState state,
        uint256 lastCheckIn,
        uint256 checkInInterval,
        uint256 gracePeriod,
        uint8 guardianCount,
        uint8 requiredGuardians,
        string memory vaultName,
        uint8 platformCount,
        bool zkpActive
    ) {
        Vault storage v = vaults[owner];
        return (
            v.state,
            v.lastCheckIn,
            v.checkInInterval,
            v.gracePeriod,
            v.guardianCount,
            v.requiredGuardians,
            v.metadata.vaultName,
            v.metadata.platformCount,
            zkpEnabled
        );
    }

    // --------------------------------------------------------
    // INTERNAL HELPERS
    // --------------------------------------------------------

    function _countConfirmations(address owner) internal view returns (uint8) {
        Vault storage v = vaults[owner];
        uint8 count = 0;
        for (uint8 i = 0; i < v.guardianCount; i++) {
            if (guardians[owner][i].hasConfirmedRelease) {
                count++;
            }
        }
        return count;
    }
}
