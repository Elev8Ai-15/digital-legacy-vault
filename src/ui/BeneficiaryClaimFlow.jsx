/**
 * BeneficiaryClaimFlow.jsx — Beneficiary Claim Interface
 * 
 * Digital Legacy Vault - Phase 2: Claim Flow UI
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * 6-step wizard for the beneficiary to claim a deceased user's vault:
 *   Step 1: Connect Wallet & Verify Identity
 *   Step 2: Submit Death Certificate
 *   Step 3: ZKP Identity Proof Generation
 *   Step 4: Initiate On-Chain Claim
 *   Step 5: Guardian Confirmation Tracker
 *   Step 6: Credential Reconstruction
 * 
 * All cryptographic operations run client-side.
 * The platform never sees credentials or private identity data.
 */

import { useState, useEffect, useCallback, useRef } from "react";

// ============================================================
// CONSTANTS
// ============================================================

const STEPS = [
  { id: 1, label: "Connect Wallet", icon: "🔗" },
  { id: 2, label: "Death Certificate", icon: "📜" },
  { id: 3, label: "Identity Proof", icon: "🔐" },
  { id: 4, label: "Initiate Claim", icon: "⚡" },
  { id: 5, label: "Guardian Approvals", icon: "🛡️" },
  { id: 6, label: "Reconstruct", icon: "🔓" },
];

const VAULT_STATES = {
  0: { label: "Active", color: "#27ae60", description: "Owner is checking in regularly" },
  1: { label: "Warning", color: "#f39c12", description: "Check-in missed, grace period active" },
  2: { label: "Claimable", color: "#e74c3c", description: "Ready for beneficiary claim" },
  3: { label: "Claimed", color: "#9b59b6", description: "Shares released to beneficiary" },
  4: { label: "Revoked", color: "#95a5a6", description: "Vault deactivated by owner" },
};

const VERIFICATION_STATUS = {
  idle: { label: "Not Started", color: "#95a5a6" },
  extracting: { label: "Extracting Data...", color: "#3498db" },
  hashing: { label: "Hashing (Privacy Layer)...", color: "#3498db" },
  submitting: { label: "Submitting to Oracle...", color: "#f39c12" },
  pending_oracle: { label: "Awaiting Oracle Verification...", color: "#f39c12" },
  pending_attestation: { label: "Awaiting Attestation...", color: "#f39c12" },
  verified: { label: "Verified ✓", color: "#27ae60" },
  failed: { label: "Verification Failed", color: "#e74c3c" },
};

// ============================================================
// MAIN COMPONENT
// ============================================================

export default function BeneficiaryClaimFlow() {
  // State
  const [currentStep, setCurrentStep] = useState(1);
  const [walletConnected, setWalletConnected] = useState(false);
  const [walletAddress, setWalletAddress] = useState("");
  const [vaultOwnerAddress, setVaultOwnerAddress] = useState("");
  const [vaultState, setVaultState] = useState(null);
  const [vaultInfo, setVaultInfo] = useState(null);
  
  // Death certificate
  const [certForm, setCertForm] = useState({
    decedentFullName: "",
    dateOfDeath: "",
    jurisdiction: "",
    certificateNumber: "",
  });
  const [certStatus, setCertStatus] = useState("idle");
  const [certConfidence, setCertConfidence] = useState(0);
  
  // ZKP
  const [zkpStatus, setZkpStatus] = useState("idle");
  const [zkpProof, setZkpProof] = useState(null);
  const [proofGenTime, setProofGenTime] = useState(null);
  const [identitySecret, setIdentitySecret] = useState("");
  
  // Claim
  const [claimStatus, setClaimStatus] = useState("idle");
  const [claimTxHash, setClaimTxHash] = useState(null);
  
  // Guardians
  const [guardianConfirmations, setGuardianConfirmations] = useState(0);
  const [requiredConfirmations, setRequiredConfirmations] = useState(3);
  const [guardianList, setGuardianList] = useState([]);
  
  // Reconstruction
  const [shares, setShares] = useState([]);
  const [reconstructedCredentials, setReconstructedCredentials] = useState(null);
  
  // Event log
  const [events, setEvents] = useState([]);
  const logRef = useRef(null);

  // ============================================================
  // EVENT LOGGING
  // ============================================================

  const addEvent = useCallback((message, type = "info") => {
    const timestamp = new Date().toLocaleTimeString();
    setEvents((prev) => [...prev, { message, type, timestamp }]);
  }, []);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [events]);

  // ============================================================
  // STEP 1: WALLET CONNECTION (Simulated)
  // ============================================================

  const connectWallet = async () => {
    addEvent("Connecting wallet...", "info");
    await simulateDelay(1000);
    
    const mockAddress = "0x" + Array.from({ length: 40 }, () => 
      "0123456789abcdef"[Math.floor(Math.random() * 16)]
    ).join("");
    
    setWalletAddress(mockAddress);
    setWalletConnected(true);
    addEvent(`Wallet connected: ${mockAddress.slice(0, 6)}...${mockAddress.slice(-4)}`, "success");
  };

  const lookupVault = async () => {
    if (!vaultOwnerAddress) return;
    addEvent(`Looking up vault for ${vaultOwnerAddress.slice(0, 10)}...`, "info");
    await simulateDelay(800);
    
    // Simulated vault data
    setVaultState(2); // Claimable
    setVaultInfo({
      vaultName: "Digital Legacy - Primary",
      lastCheckIn: Date.now() - 180 * 24 * 60 * 60 * 1000, // 180 days ago
      checkInInterval: 90 * 24 * 60 * 60, // 90 days
      gracePeriod: 60 * 24 * 60 * 60, // 60 days
      guardianCount: 5,
      requiredGuardians: 3,
      platformCount: 4,
      triggerMethod: "DeadManSwitch",
      zkpActive: true,
    });
    setRequiredConfirmations(3);
    setGuardianList([
      { address: "0x1a2b...3c4d", label: "Personal Device", confirmed: false },
      { address: "0x5e6f...7g8h", label: "Beneficiary Device", confirmed: false },
      { address: "0x9i0j...1k2l", label: "Attorney (Smith & Associates)", confirmed: false },
      { address: "0x3m4n...5o6p", label: "Cold Storage (Platform)", confirmed: false },
      { address: "0x7q8r...9s0t", label: "Backup Guardian", confirmed: false },
    ]);
    
    addEvent("Vault found: CLAIMABLE state (dead man's switch triggered)", "success");
    addEvent("Dead man's switch: Last check-in was 180 days ago (interval: 90 days + 60 day grace)", "info");
  };

  // ============================================================
  // STEP 2: DEATH CERTIFICATE
  // ============================================================

  const submitCertificate = async () => {
    if (!certForm.decedentFullName || !certForm.dateOfDeath || 
        !certForm.jurisdiction || !certForm.certificateNumber) {
      addEvent("Please fill all certificate fields", "error");
      return;
    }

    setCertStatus("extracting");
    addEvent("Step 2a: Extracting certificate data...", "info");
    await simulateDelay(600);

    setCertStatus("hashing");
    addEvent("Step 2b: Hashing PII (Poseidon hash - privacy layer)...", "info");
    addEvent("  ↳ Name → Poseidon(name) → field element (no plaintext leaves device)", "info");
    addEvent("  ↳ Date → Unix timestamp → field element", "info");
    addEvent("  ↳ Certificate # → Poseidon(certNum) → field element", "info");
    addEvent("  ↳ Salt generated: crypto.getRandomValues(32 bytes)", "info");
    await simulateDelay(1200);

    setCertStatus("submitting");
    addEvent("Step 2c: Submitting hashed data to Chainlink Oracle...", "info");
    addEvent("  ↳ Only hashes transmitted. Zero plaintext PII leaves your device.", "warning");
    await simulateDelay(1500);

    setCertStatus("pending_oracle");
    addEvent("Step 2d: Oracle querying death record databases...", "info");
    addEvent("  ↳ Source 1: Social Security Death Index (SSDI)...", "info");
    await simulateDelay(2000);
    addEvent("  ↳ SSDI: CONFIRMED (confidence: 78%)", "success");
    addEvent("  ↳ Source 2: State Vital Records API...", "info");
    await simulateDelay(1500);
    addEvent("  ↳ State Records: CONFIRMED (confidence: 82%)", "success");

    setCertConfidence(96);
    setCertStatus("verified");
    addEvent("Death certificate VERIFIED (confidence: 96%, 2 sources confirmed)", "success");
    addEvent("Vault state transition: Claimable (oracle-verified)", "success");
  };

  // ============================================================
  // STEP 3: ZKP GENERATION
  // ============================================================

  const generateZKProof = async () => {
    if (!identitySecret) {
      addEvent("Please enter your identity secret", "error");
      return;
    }

    setZkpStatus("generating");
    addEvent("Step 3: Generating Zero-Knowledge Proof...", "info");
    addEvent("  ↳ Circuit: BeneficiaryIdentityProof (Groth16, BN128)", "info");
    addEvent("  ↳ Public inputs:", "info");
    addEvent("    • identityCommitment (on-chain Poseidon hash)", "info");
    addEvent("    • vaultOwner address (anti-replay binding)", "info");
    addEvent("    • claimNonce: 0 (first claim attempt)", "info");
    addEvent("  ↳ Private inputs: (NEVER REVEALED)", "warning");
    addEvent("    • identitySecret (your secret key)", "warning");
    addEvent("    • didComponents[4] (your DID key, split into limbs)", "warning");
    addEvent("    • salt (from setup phase)", "warning");
    await simulateDelay(1000);

    addEvent("  ↳ Computing Poseidon hash of private inputs...", "info");
    await simulateDelay(800);
    addEvent("  ↳ Generating R1CS witness (~5,000 constraints)...", "info");
    await simulateDelay(1200);
    addEvent("  ↳ Computing Groth16 proof (BN128 pairing)...", "info");
    await simulateDelay(2000);

    // Simulated proof
    const mockProof = {
      pi_a: ["0x" + "a".repeat(64), "0x" + "b".repeat(64)],
      pi_b: [["0x" + "c".repeat(64), "0x" + "d".repeat(64)], ["0x" + "e".repeat(64), "0x" + "f".repeat(64)]],
      pi_c: ["0x" + "1".repeat(64), "0x" + "2".repeat(64)],
    };

    setZkpProof(mockProof);
    setProofGenTime("3.2");
    setZkpStatus("verified");

    addEvent("  ↳ Local verification: VALID ✓", "success");
    addEvent(`ZKP generated in 3.2 seconds (256 bytes, ~200K gas to verify on-chain)`, "success");
    addEvent("Your identity is proven WITHOUT revealing any private data.", "success");
  };

  // ============================================================
  // STEP 4: ON-CHAIN CLAIM
  // ============================================================

  const initiateClaim = async () => {
    setClaimStatus("submitting");
    addEvent("Step 4: Submitting claim to DigitalLegacyVaultV2...", "info");
    addEvent("  ↳ Function: initiateClaim(vaultOwner, zkProof)", "info");
    addEvent("  ↳ ZKP proof attached (256 bytes)", "info");
    await simulateDelay(1500);

    addEvent("  ↳ On-chain: ZKPIdentityVerifier.verifyIdentityProof()...", "info");
    addEvent("  ↳ Pairing check: e(-A,B) * e(α,β) * e(IC,γ) * e(C,δ) == 1", "info");
    await simulateDelay(2000);

    const mockTxHash = "0x" + Array.from({ length: 64 }, () => 
      "0123456789abcdef"[Math.floor(Math.random() * 16)]
    ).join("");

    setClaimTxHash(mockTxHash);
    setClaimStatus("confirmed");
    addEvent(`Transaction confirmed: ${mockTxHash.slice(0, 18)}...`, "success");
    addEvent("ZKP verification: PASSED ✓", "success");
    addEvent("Beneficiary verified on-chain. Claim nonce incremented to 1.", "success");
    addEvent("Waiting for guardian confirmations...", "info");
  };

  // ============================================================
  // STEP 5: GUARDIAN CONFIRMATIONS (Simulated)
  // ============================================================

  const simulateGuardianConfirm = async (index) => {
    const guardian = guardianList[index];
    addEvent(`Guardian "${guardian.label}" confirming share release...`, "info");
    await simulateDelay(1500);
    
    const newList = [...guardianList];
    newList[index] = { ...newList[index], confirmed: true };
    setGuardianList(newList);
    
    const newCount = guardianConfirmations + 1;
    setGuardianConfirmations(newCount);
    
    addEvent(`Guardian "${guardian.label}" CONFIRMED ✓ (${newCount}/${requiredConfirmations})`, "success");
    
    if (newCount >= requiredConfirmations) {
      addEvent("THRESHOLD MET! SSS shares released. Vault state → CLAIMED", "success");
      setVaultState(3); // Claimed
    }
  };

  // ============================================================
  // STEP 6: CREDENTIAL RECONSTRUCTION (Simulated)
  // ============================================================

  const reconstructCredentials = async () => {
    addEvent("Step 6: Reconstructing credentials from SSS shares...", "info");
    addEvent("  ↳ Collecting shares from confirmed guardians...", "info");
    await simulateDelay(800);
    
    addEvent("  ↳ Share 1 (Your Device): received", "info");
    addEvent("  ↳ Share 2 (Attorney): received", "info");
    addEvent("  ↳ Share 3 (Cold Storage): received", "info");
    await simulateDelay(1000);
    
    addEvent("  ↳ Lagrange interpolation at x=0 (GF(2^8))...", "info");
    await simulateDelay(1200);
    
    addEvent("  ↳ AES-256-GCM decryption (PBKDF2 600K iterations)...", "info");
    await simulateDelay(1500);
    
    setReconstructedCredentials([
      { platform: "Instagram", username: "user_legacy_123", status: "recovered" },
      { platform: "Facebook", username: "john.doe.legacy", status: "recovered" },
      { platform: "Gmail", username: "johndoe.legacy@gmail.com", status: "recovered" },
      { platform: "TikTok", username: "@legacy_user", status: "recovered" },
    ]);
    
    addEvent("ALL CREDENTIALS RECONSTRUCTED SUCCESSFULLY", "success");
    addEvent("Credentials exist ONLY on your device. The platform never saw them.", "warning");
  };

  // ============================================================
  // RENDER
  // ============================================================

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <h1 style={styles.title}>Digital Legacy Vault</h1>
        <p style={styles.subtitle}>Beneficiary Claim Flow</p>
      </div>

      {/* Step Progress */}
      <div style={styles.stepBar}>
        {STEPS.map((step) => (
          <div
            key={step.id}
            onClick={() => step.id <= getMaxStep() && setCurrentStep(step.id)}
            style={{
              ...styles.stepItem,
              opacity: step.id <= getMaxStep() ? 1 : 0.4,
              cursor: step.id <= getMaxStep() ? "pointer" : "default",
              borderBottom: currentStep === step.id ? "2px solid #6c5ce7" : "2px solid transparent",
            }}
          >
            <span style={styles.stepIcon}>{step.icon}</span>
            <span style={{
              ...styles.stepLabel,
              color: step.id < currentStep ? "#27ae60" : step.id === currentStep ? "#6c5ce7" : "#666",
            }}>
              {step.label}
            </span>
          </div>
        ))}
      </div>

      <div style={styles.content}>
        {/* Left: Step Content */}
        <div style={styles.mainPanel}>
          {currentStep === 1 && renderStep1()}
          {currentStep === 2 && renderStep2()}
          {currentStep === 3 && renderStep3()}
          {currentStep === 4 && renderStep4()}
          {currentStep === 5 && renderStep5()}
          {currentStep === 6 && renderStep6()}
        </div>

        {/* Right: Event Log */}
        <div style={styles.logPanel}>
          <h3 style={styles.logTitle}>On-Chain Event Log</h3>
          <div ref={logRef} style={styles.logContent}>
            {events.length === 0 && (
              <p style={styles.logEmpty}>Events will appear here as you progress through the claim flow...</p>
            )}
            {events.map((evt, i) => (
              <div key={i} style={{
                ...styles.logEntry,
                borderLeft: `3px solid ${evt.type === "success" ? "#27ae60" : evt.type === "error" ? "#e74c3c" : evt.type === "warning" ? "#f39c12" : "#555"}`,
              }}>
                <span style={styles.logTime}>{evt.timestamp}</span>
                <span style={styles.logMsg}>{evt.message}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  // ============================================================
  // STEP RENDERERS
  // ============================================================

  function getMaxStep() {
    if (reconstructedCredentials) return 6;
    if (guardianConfirmations >= requiredConfirmations) return 6;
    if (claimStatus === "confirmed") return 5;
    if (zkpStatus === "verified") return 4;
    if (certStatus === "verified") return 3;
    if (walletConnected && vaultInfo) return 2;
    return 1;
  }

  function renderStep1() {
    return (
      <div style={styles.stepContent}>
        <h2 style={styles.stepTitle}>Step 1: Connect Wallet & Locate Vault</h2>
        
        {!walletConnected ? (
          <div>
            <p style={styles.text}>Connect your wallet to begin the claim process. You must use the wallet address that was registered as the beneficiary.</p>
            <button style={styles.button} onClick={connectWallet}>Connect Wallet (MetaMask)</button>
          </div>
        ) : (
          <div>
            <div style={styles.infoBox}>
              <p style={styles.infoLabel}>Connected Wallet</p>
              <p style={styles.infoValue}>{walletAddress}</p>
            </div>
            
            <div style={styles.inputGroup}>
              <label style={styles.label}>Vault Owner Address</label>
              <input
                style={styles.input}
                placeholder="0x... (address of the deceased)"
                value={vaultOwnerAddress}
                onChange={(e) => setVaultOwnerAddress(e.target.value)}
              />
              <button style={styles.button} onClick={lookupVault}>Lookup Vault</button>
            </div>

            {vaultInfo && (
              <div style={styles.vaultCard}>
                <div style={styles.vaultHeader}>
                  <span style={styles.vaultName}>{vaultInfo.vaultName}</span>
                  <span style={{
                    ...styles.stateBadge,
                    backgroundColor: VAULT_STATES[vaultState]?.color || "#666",
                  }}>
                    {VAULT_STATES[vaultState]?.label}
                  </span>
                </div>
                <div style={styles.vaultGrid}>
                  <div><span style={styles.vaultLabel}>Guardians:</span> {vaultInfo.guardianCount} ({vaultInfo.requiredGuardians} required)</div>
                  <div><span style={styles.vaultLabel}>Platforms:</span> {vaultInfo.platformCount} archived</div>
                  <div><span style={styles.vaultLabel}>Trigger:</span> {vaultInfo.triggerMethod}</div>
                  <div><span style={styles.vaultLabel}>ZKP:</span> {vaultInfo.zkpActive ? "Enabled ✓" : "Disabled"}</div>
                </div>
                <button style={styles.buttonPrimary} onClick={() => setCurrentStep(2)}>
                  Proceed to Death Certificate →
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  function renderStep2() {
    return (
      <div style={styles.stepContent}>
        <h2 style={styles.stepTitle}>Step 2: Death Certificate Verification</h2>
        <p style={styles.text}>Enter the death certificate information. All data is hashed client-side before submission. The platform never sees plaintext PII.</p>
        
        <div style={styles.privacyBanner}>
          🔒 Privacy: All fields are Poseidon-hashed on YOUR device before any data leaves.
        </div>

        <div style={styles.formGrid}>
          <div style={styles.inputGroup}>
            <label style={styles.label}>Decedent's Full Legal Name</label>
            <input style={styles.input} placeholder="As it appears on the certificate"
              value={certForm.decedentFullName}
              onChange={(e) => setCertForm({...certForm, decedentFullName: e.target.value})} />
          </div>
          <div style={styles.inputGroup}>
            <label style={styles.label}>Date of Death</label>
            <input style={styles.input} type="date"
              value={certForm.dateOfDeath}
              onChange={(e) => setCertForm({...certForm, dateOfDeath: e.target.value})} />
          </div>
          <div style={styles.inputGroup}>
            <label style={styles.label}>Jurisdiction (State/Country)</label>
            <input style={styles.input} placeholder="e.g., FL, CA, NY"
              value={certForm.jurisdiction}
              onChange={(e) => setCertForm({...certForm, jurisdiction: e.target.value})} />
          </div>
          <div style={styles.inputGroup}>
            <label style={styles.label}>Certificate Number</label>
            <input style={styles.input} placeholder="Official certificate number"
              value={certForm.certificateNumber}
              onChange={(e) => setCertForm({...certForm, certificateNumber: e.target.value})} />
          </div>
        </div>

        <div style={styles.statusBar}>
          <span style={{ color: VERIFICATION_STATUS[certStatus]?.color }}>
            {VERIFICATION_STATUS[certStatus]?.label}
          </span>
          {certConfidence > 0 && (
            <span style={styles.confidenceBadge}>Confidence: {certConfidence}%</span>
          )}
        </div>

        {certStatus === "idle" && (
          <button style={styles.buttonPrimary} onClick={submitCertificate}>
            Submit for Verification
          </button>
        )}
        {certStatus === "verified" && (
          <button style={styles.buttonPrimary} onClick={() => setCurrentStep(3)}>
            Proceed to ZKP Identity Proof →
          </button>
        )}
      </div>
    );
  }

  function renderStep3() {
    return (
      <div style={styles.stepContent}>
        <h2 style={styles.stepTitle}>Step 3: Zero-Knowledge Identity Proof</h2>
        <p style={styles.text}>Generate a cryptographic proof that your identity matches the on-chain commitment, without revealing any private data.</p>

        <div style={styles.zkpExplainer}>
          <h4 style={styles.zkpTitle}>How This Works:</h4>
          <p style={styles.zkpText}>During vault setup, a Poseidon hash of your identity was stored on-chain. Now you'll prove you know the preimage (your secret + DID) that produces that hash, without revealing the preimage itself. This is called a Zero-Knowledge Proof.</p>
          <p style={styles.zkpText}>The proof is bound to this specific vault owner and claim nonce, preventing replay attacks.</p>
        </div>

        <div style={styles.inputGroup}>
          <label style={styles.label}>Identity Secret (from vault setup)</label>
          <input style={styles.input} type="password" placeholder="Your secret key material"
            value={identitySecret}
            onChange={(e) => setIdentitySecret(e.target.value)} />
          <p style={styles.hint}>This was generated when you were registered as beneficiary. It never leaves your device.</p>
        </div>

        {zkpStatus === "idle" && (
          <button style={styles.buttonPrimary} onClick={generateZKProof}>
            Generate ZK Proof (Groth16)
          </button>
        )}
        {zkpStatus === "generating" && (
          <div style={styles.generating}>
            <div style={styles.spinner} />
            <span>Generating proof... (this takes a few seconds)</span>
          </div>
        )}
        {zkpStatus === "verified" && (
          <div>
            <div style={styles.proofCard}>
              <h4 style={{ color: "#27ae60", margin: "0 0 8px 0" }}>✓ Proof Generated Successfully</h4>
              <p style={{ fontSize: 12, color: "#aaa", margin: 0 }}>Generation time: {proofGenTime}s | Size: 256 bytes | Verification cost: ~200K gas (~$0.004)</p>
              <div style={styles.proofPreview}>
                <code style={{ fontSize: 10, color: "#6c5ce7" }}>
                  π_A: [{zkpProof?.pi_a[0]?.slice(0, 18)}...]<br/>
                  π_B: [[{zkpProof?.pi_b[0][0]?.slice(0, 14)}...]]<br/>
                  π_C: [{zkpProof?.pi_c[0]?.slice(0, 18)}...]
                </code>
              </div>
            </div>
            <button style={styles.buttonPrimary} onClick={() => setCurrentStep(4)}>
              Proceed to On-Chain Claim →
            </button>
          </div>
        )}
      </div>
    );
  }

  function renderStep4() {
    return (
      <div style={styles.stepContent}>
        <h2 style={styles.stepTitle}>Step 4: Initiate On-Chain Claim</h2>
        <p style={styles.text}>Submit your ZKP proof to the DigitalLegacyVaultV2 smart contract. The Groth16 verifier will validate your proof on-chain.</p>

        <div style={styles.txPreview}>
          <h4 style={{ margin: "0 0 8px 0", color: "#6c5ce7" }}>Transaction Preview</h4>
          <div style={styles.txRow}><span>Contract:</span><span>DigitalLegacyVaultV2</span></div>
          <div style={styles.txRow}><span>Function:</span><span>initiateClaim(address, bytes)</span></div>
          <div style={styles.txRow}><span>Vault Owner:</span><span>{vaultOwnerAddress?.slice(0, 10)}...</span></div>
          <div style={styles.txRow}><span>ZKP Proof:</span><span>256 bytes (Groth16)</span></div>
          <div style={styles.txRow}><span>Est. Gas:</span><span>~200,000 (~$0.004 on Polygon)</span></div>
          <div style={styles.txRow}><span>Network:</span><span>Polygon Mainnet</span></div>
        </div>

        {claimStatus === "idle" && (
          <button style={styles.buttonPrimary} onClick={initiateClaim}>
            Submit Claim Transaction
          </button>
        )}
        {claimStatus === "submitting" && (
          <div style={styles.generating}>
            <div style={styles.spinner} />
            <span>Submitting to Polygon...</span>
          </div>
        )}
        {claimStatus === "confirmed" && (
          <div>
            <div style={{ ...styles.proofCard, borderColor: "#27ae60" }}>
              <h4 style={{ color: "#27ae60", margin: "0 0 4px 0" }}>✓ Claim Confirmed On-Chain</h4>
              <p style={{ fontSize: 11, color: "#aaa", margin: 0, wordBreak: "break-all" }}>
                Tx: {claimTxHash}
              </p>
            </div>
            <button style={styles.buttonPrimary} onClick={() => setCurrentStep(5)}>
              Track Guardian Approvals →
            </button>
          </div>
        )}
      </div>
    );
  }

  function renderStep5() {
    return (
      <div style={styles.stepContent}>
        <h2 style={styles.stepTitle}>Step 5: Guardian Share Release</h2>
        <p style={styles.text}>
          Guardians must confirm the release of their SSS shares. {requiredConfirmations} of {guardianList.length} required.
        </p>

        <div style={styles.progressContainer}>
          <div style={styles.progressBar}>
            <div style={{
              ...styles.progressFill,
              width: `${(guardianConfirmations / requiredConfirmations) * 100}%`,
              backgroundColor: guardianConfirmations >= requiredConfirmations ? "#27ae60" : "#6c5ce7",
            }} />
          </div>
          <span style={styles.progressText}>
            {guardianConfirmations} / {requiredConfirmations} confirmations
          </span>
        </div>

        <div style={styles.guardianGrid}>
          {guardianList.map((g, i) => (
            <div key={i} style={{
              ...styles.guardianCard,
              borderColor: g.confirmed ? "#27ae60" : "#333",
            }}>
              <div style={styles.guardianHeader}>
                <span style={styles.guardianLabel}>{g.label}</span>
                <span style={{
                  ...styles.guardianStatus,
                  color: g.confirmed ? "#27ae60" : "#f39c12",
                }}>
                  {g.confirmed ? "✓ Confirmed" : "Pending"}
                </span>
              </div>
              <span style={styles.guardianAddr}>{g.address}</span>
              {!g.confirmed && guardianConfirmations < requiredConfirmations && (
                <button style={styles.buttonSmall} onClick={() => simulateGuardianConfirm(i)}>
                  Simulate Confirmation
                </button>
              )}
            </div>
          ))}
        </div>

        {guardianConfirmations >= requiredConfirmations && (
          <button style={styles.buttonPrimary} onClick={() => setCurrentStep(6)}>
            Reconstruct Credentials →
          </button>
        )}
      </div>
    );
  }

  function renderStep6() {
    return (
      <div style={styles.stepContent}>
        <h2 style={styles.stepTitle}>Step 6: Credential Reconstruction</h2>
        
        {!reconstructedCredentials ? (
          <div>
            <p style={styles.text}>
              All required guardian shares have been released. You can now reconstruct the original credentials using Lagrange interpolation over GF(2^8).
            </p>
            <div style={styles.privacyBanner}>
              🔒 Reconstruction happens entirely on YOUR device. The platform never sees the reconstructed credentials.
            </div>
            <button style={styles.buttonPrimary} onClick={reconstructCredentials}>
              Reconstruct Credentials
            </button>
          </div>
        ) : (
          <div>
            <div style={{ ...styles.proofCard, borderColor: "#27ae60" }}>
              <h4 style={{ color: "#27ae60", margin: "0 0 12px 0" }}>✓ Credentials Recovered Successfully</h4>
              {reconstructedCredentials.map((cred, i) => (
                <div key={i} style={styles.credentialRow}>
                  <span style={styles.credPlatform}>{cred.platform}</span>
                  <span style={styles.credUser}>{cred.username}</span>
                  <span style={{ color: "#27ae60", fontSize: 12 }}>✓ {cred.status}</span>
                </div>
              ))}
            </div>
            <div style={styles.finalNote}>
              <p>These credentials exist only on your device. You can now access the accounts or download the archived content from IPFS.</p>
              <p style={{ color: "#f39c12", fontSize: 12 }}>
                Recommendation: Change passwords immediately after accessing each account to secure them under your control.
              </p>
            </div>
          </div>
        )}
      </div>
    );
  }
}

// ============================================================
// UTILITY
// ============================================================

function simulateDelay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ============================================================
// STYLES
// ============================================================

const styles = {
  container: { fontFamily: "'JetBrains Mono', 'SF Mono', monospace", backgroundColor: "#0a0a0f", color: "#e0e0e0", minHeight: "100vh", padding: 20 },
  header: { textAlign: "center", marginBottom: 20, borderBottom: "1px solid #1a1a2e", paddingBottom: 16 },
  title: { fontSize: 24, margin: 0, background: "linear-gradient(135deg, #6c5ce7, #a29bfe)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" },
  subtitle: { fontSize: 13, color: "#888", margin: "4px 0 0 0" },
  
  stepBar: { display: "flex", justifyContent: "center", gap: 8, marginBottom: 20, flexWrap: "wrap" },
  stepItem: { display: "flex", flexDirection: "column", alignItems: "center", padding: "8px 12px", transition: "all 0.2s" },
  stepIcon: { fontSize: 18, marginBottom: 2 },
  stepLabel: { fontSize: 10, fontWeight: 600 },
  
  content: { display: "flex", gap: 16, maxWidth: 1200, margin: "0 auto" },
  mainPanel: { flex: "1 1 60%", minWidth: 0 },
  logPanel: { flex: "1 1 35%", minWidth: 280, maxWidth: 400 },
  
  stepContent: { backgroundColor: "#12121a", borderRadius: 12, padding: 24, border: "1px solid #1a1a2e" },
  stepTitle: { fontSize: 16, color: "#6c5ce7", margin: "0 0 12px 0" },
  text: { fontSize: 13, color: "#aaa", lineHeight: 1.6, marginBottom: 16 },
  
  inputGroup: { marginBottom: 12 },
  label: { display: "block", fontSize: 11, color: "#888", marginBottom: 4, textTransform: "uppercase", letterSpacing: 1 },
  input: { width: "100%", padding: "10px 12px", backgroundColor: "#1a1a2e", border: "1px solid #2a2a3e", borderRadius: 6, color: "#e0e0e0", fontSize: 13, fontFamily: "inherit", boxSizing: "border-box" },
  hint: { fontSize: 10, color: "#666", marginTop: 4 },
  
  button: { padding: "10px 20px", backgroundColor: "#1a1a2e", border: "1px solid #6c5ce7", borderRadius: 6, color: "#6c5ce7", fontSize: 12, cursor: "pointer", fontFamily: "inherit", marginTop: 8 },
  buttonPrimary: { padding: "12px 24px", background: "linear-gradient(135deg, #6c5ce7, #5a4bd1)", border: "none", borderRadius: 8, color: "#fff", fontSize: 13, cursor: "pointer", fontFamily: "inherit", marginTop: 12, fontWeight: 600 },
  buttonSmall: { padding: "6px 12px", backgroundColor: "transparent", border: "1px solid #444", borderRadius: 4, color: "#aaa", fontSize: 10, cursor: "pointer", fontFamily: "inherit", marginTop: 6 },
  
  infoBox: { backgroundColor: "#1a1a2e", padding: 12, borderRadius: 8, marginBottom: 16, border: "1px solid #2a2a3e" },
  infoLabel: { fontSize: 10, color: "#666", margin: 0, textTransform: "uppercase" },
  infoValue: { fontSize: 12, color: "#6c5ce7", margin: "4px 0 0 0", wordBreak: "break-all" },
  
  vaultCard: { backgroundColor: "#1a1a2e", padding: 16, borderRadius: 10, border: "1px solid #2a2a3e", marginTop: 16 },
  vaultHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 },
  vaultName: { fontSize: 14, fontWeight: 600, color: "#e0e0e0" },
  stateBadge: { padding: "4px 10px", borderRadius: 12, fontSize: 11, fontWeight: 600, color: "#fff" },
  vaultGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, fontSize: 12, color: "#aaa", marginBottom: 12 },
  vaultLabel: { color: "#666" },
  
  formGrid: { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 },
  privacyBanner: { backgroundColor: "#1a2a1a", border: "1px solid #2a4a2a", borderRadius: 8, padding: 12, fontSize: 12, color: "#4caf50", marginBottom: 16 },
  
  statusBar: { display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 12, marginBottom: 12 },
  confidenceBadge: { backgroundColor: "#1a2a1a", color: "#27ae60", padding: "4px 10px", borderRadius: 12, fontSize: 11 },
  
  zkpExplainer: { backgroundColor: "#1a1a2e", padding: 16, borderRadius: 8, marginBottom: 16, borderLeft: "3px solid #6c5ce7" },
  zkpTitle: { margin: "0 0 8px 0", fontSize: 13, color: "#6c5ce7" },
  zkpText: { fontSize: 12, color: "#aaa", margin: "0 0 8px 0", lineHeight: 1.5 },
  
  generating: { display: "flex", alignItems: "center", gap: 12, padding: 16, color: "#6c5ce7" },
  spinner: { width: 20, height: 20, border: "2px solid #333", borderTopColor: "#6c5ce7", borderRadius: "50%", animation: "spin 1s linear infinite" },
  
  proofCard: { backgroundColor: "#0d1a0d", border: "1px solid #1a3a1a", borderRadius: 8, padding: 16, marginBottom: 12 },
  proofPreview: { backgroundColor: "#0a0a0f", padding: 10, borderRadius: 6, marginTop: 8 },
  
  txPreview: { backgroundColor: "#1a1a2e", padding: 16, borderRadius: 8, marginBottom: 16 },
  txRow: { display: "flex", justifyContent: "space-between", fontSize: 12, padding: "4px 0", borderBottom: "1px solid #2a2a3e", color: "#aaa" },
  
  progressContainer: { marginBottom: 16 },
  progressBar: { height: 8, backgroundColor: "#1a1a2e", borderRadius: 4, overflow: "hidden", marginBottom: 6 },
  progressFill: { height: "100%", borderRadius: 4, transition: "width 0.5s ease" },
  progressText: { fontSize: 12, color: "#888" },
  
  guardianGrid: { display: "grid", gap: 10, marginBottom: 16 },
  guardianCard: { backgroundColor: "#1a1a2e", padding: 12, borderRadius: 8, border: "1px solid #333", transition: "border-color 0.3s" },
  guardianHeader: { display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 },
  guardianLabel: { fontSize: 12, fontWeight: 600 },
  guardianStatus: { fontSize: 11 },
  guardianAddr: { fontSize: 10, color: "#555" },
  
  credentialRow: { display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: "1px solid #1a3a1a" },
  credPlatform: { fontSize: 13, fontWeight: 600, color: "#e0e0e0" },
  credUser: { fontSize: 12, color: "#6c5ce7" },
  
  finalNote: { backgroundColor: "#1a1a2e", padding: 16, borderRadius: 8, marginTop: 12, fontSize: 12, color: "#aaa", lineHeight: 1.5 },
  
  logTitle: { fontSize: 13, color: "#6c5ce7", margin: "0 0 8px 0" },
  logContent: { backgroundColor: "#0a0a0f", borderRadius: 8, padding: 12, maxHeight: 600, overflowY: "auto", border: "1px solid #1a1a2e" },
  logEmpty: { fontSize: 11, color: "#444", fontStyle: "italic" },
  logEntry: { padding: "4px 8px", marginBottom: 4, fontSize: 10, lineHeight: 1.4 },
  logTime: { color: "#444", marginRight: 8 },
  logMsg: { color: "#bbb" },
};
