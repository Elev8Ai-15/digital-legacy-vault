"""
verification_routes.py — Phase 2 Verification API Routes

Digital Legacy Vault - Verification Layer
Built by Brad Powell / Elev8.AI Consulting & Integration

These routes handle the off-chain orchestration for:
  1. Death certificate submission and verification tracking
  2. ZKP proof metadata (proof generation happens client-side)
  3. Claim status monitoring
  4. Guardian notification and confirmation tracking
  5. Attestor (attorney/notary) management

SECURITY NOTE:
  - NO credentials or private keys pass through these routes
  - Death certificates are hashed client-side; only hashes stored
  - ZKP proofs are generated client-side and submitted on-chain
  - This API tracks metadata and orchestrates notifications ONLY
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional, List, Dict
from datetime import datetime, timezone
from enum import Enum
import secrets

router = APIRouter(prefix="/api/v2/verification", tags=["verification"])

# ============================================================
# DATA MODELS
# ============================================================

class ClaimPhase(str, Enum):
    IDLE = "idle"
    DEATH_CERT_SUBMITTED = "death_cert_submitted"
    DEATH_CERT_VERIFIED = "death_cert_verified"
    IDENTITY_PROOF_SUBMITTED = "identity_proof_submitted"
    GUARDIAN_CONFIRMATIONS = "guardian_confirmations"
    COOLDOWN = "cooldown"
    SHARES_RELEASED = "shares_released"
    COMPLETE = "complete"
    REJECTED = "rejected"

class DeathCertSubmission(BaseModel):
    vault_owner_address: str
    beneficiary_address: str
    certificate_hash: str = Field(..., description="SHA-256 hash of the death certificate (hashed client-side)")
    certificate_source: str = Field(..., description="Source type: 'county_clerk', 'notary', 'funeral_home', 'attorney'")
    decedent_name_hash: str = Field(..., description="Hash of decedent's legal name")
    date_of_death: str = Field(..., description="ISO date string")
    jurisdiction: str = Field(..., description="US state or jurisdiction code")
    submitter_did_hash: str = Field(..., description="Hash of submitter's DID")

class DeathCertStatus(BaseModel):
    submission_id: str
    vault_owner_address: str
    certificate_hash: str
    status: str  # pending, oracle_submitted, verified, rejected
    confidence: Optional[float] = None
    oracle_request_id: Optional[str] = None
    submitted_at: str
    verified_at: Optional[str] = None
    rejection_reason: Optional[str] = None

class AttestationSubmission(BaseModel):
    vault_owner_address: str
    attestor_did_hash: str
    attestor_type: str = Field(..., description="'attorney', 'notary', 'medical_examiner'")
    attestation_hash: str = Field(..., description="Hash of the signed attestation document")
    verifiable_credential_proof: str = Field(..., description="Serialized VC proof from attestor")

class ZKPProofMetadata(BaseModel):
    vault_owner_address: str
    beneficiary_address: str
    proof_hash: str = Field(..., description="Hash of the ZKP proof (for tracking)")
    nonce: int
    submitted_on_chain: bool = False
    tx_hash: Optional[str] = None

class GuardianConfirmationStatus(BaseModel):
    guardian_address: str
    guardian_alias: Optional[str] = None
    has_confirmed: bool
    confirmed_at: Optional[str] = None
    notification_sent: bool
    notification_sent_at: Optional[str] = None

class ClaimStatus(BaseModel):
    vault_owner_address: str
    beneficiary_address: Optional[str] = None
    phase: ClaimPhase
    death_cert_status: Optional[DeathCertStatus] = None
    attestations: List[Dict] = []
    identity_proof_submitted: bool = False
    guardian_confirmations: List[GuardianConfirmationStatus] = []
    confirmations_received: int = 0
    confirmations_required: int = 0
    cooldown_ends: Optional[str] = None
    shares_released: bool = False
    started_at: Optional[str] = None
    updated_at: Optional[str] = None

class GuardianNotification(BaseModel):
    vault_owner_address: str
    guardian_address: str
    notification_type: str = Field(..., description="'claim_initiated', 'confirmation_requested', 'shares_released'")
    message: Optional[str] = None

# ============================================================
# IN-MEMORY STORAGE (replace with PostgreSQL in production)
# ============================================================

death_cert_submissions: Dict[str, dict] = {}     # submission_id -> data
claim_statuses: Dict[str, dict] = {}              # vault_owner_address -> claim data
attestations: Dict[str, list] = {}                # vault_owner_address -> list of attestations
zkp_proofs: Dict[str, dict] = {}                  # vault_owner_address -> proof metadata
guardian_notifications: Dict[str, list] = {}       # vault_owner_address -> notification log

# ============================================================
# DEATH CERTIFICATE ROUTES
# ============================================================

@router.post("/death-certificate", response_model=DeathCertStatus)
async def submit_death_certificate(
    submission: DeathCertSubmission,
    background_tasks: BackgroundTasks
):
    """
    Submit a death certificate hash for oracle verification.
    
    The actual certificate is NEVER sent to this API.
    Only the hash (computed client-side) is submitted.
    The oracle independently verifies the certificate against
    public death records or notarized sources.
    """
    submission_id = f"dc_{secrets.token_hex(8)}"
    now = datetime.now(timezone.utc).isoformat()

    record = {
        "submission_id": submission_id,
        "vault_owner_address": submission.vault_owner_address,
        "beneficiary_address": submission.beneficiary_address,
        "certificate_hash": submission.certificate_hash,
        "certificate_source": submission.certificate_source,
        "decedent_name_hash": submission.decedent_name_hash,
        "date_of_death": submission.date_of_death,
        "jurisdiction": submission.jurisdiction,
        "submitter_did_hash": submission.submitter_did_hash,
        "status": "pending",
        "confidence": None,
        "oracle_request_id": None,
        "submitted_at": now,
        "verified_at": None,
        "rejection_reason": None,
    }

    death_cert_submissions[submission_id] = record

    # Initialize or update claim status
    if submission.vault_owner_address not in claim_statuses:
        claim_statuses[submission.vault_owner_address] = {
            "vault_owner_address": submission.vault_owner_address,
            "beneficiary_address": submission.beneficiary_address,
            "phase": ClaimPhase.DEATH_CERT_SUBMITTED.value,
            "death_cert_submission_id": submission_id,
            "started_at": now,
            "updated_at": now,
        }
    else:
        claim_statuses[submission.vault_owner_address]["phase"] = ClaimPhase.DEATH_CERT_SUBMITTED.value
        claim_statuses[submission.vault_owner_address]["death_cert_submission_id"] = submission_id
        claim_statuses[submission.vault_owner_address]["updated_at"] = now

    # Background: trigger oracle verification request
    background_tasks.add_task(
        _trigger_oracle_verification,
        submission_id,
        submission.vault_owner_address,
        submission.certificate_hash,
    )

    return DeathCertStatus(
        submission_id=submission_id,
        vault_owner_address=submission.vault_owner_address,
        certificate_hash=submission.certificate_hash,
        status="pending",
        submitted_at=now,
    )


@router.get("/death-certificate/{submission_id}", response_model=DeathCertStatus)
async def get_death_certificate_status(submission_id: str):
    """Get the verification status of a submitted death certificate."""
    if submission_id not in death_cert_submissions:
        raise HTTPException(status_code=404, detail="Submission not found")

    record = death_cert_submissions[submission_id]
    return DeathCertStatus(**{k: record[k] for k in DeathCertStatus.model_fields})


@router.post("/death-certificate/{submission_id}/oracle-callback")
async def oracle_verification_callback(
    submission_id: str,
    verified: bool,
    confidence: float,
    oracle_request_id: str,
    rejection_reason: Optional[str] = None,
):
    """
    Callback endpoint for oracle verification results.
    
    In production, this would be called by a Chainlink Functions
    fulfillment handler or a webhook from the oracle service.
    Access should be restricted to authorized oracle addresses.
    """
    if submission_id not in death_cert_submissions:
        raise HTTPException(status_code=404, detail="Submission not found")

    now = datetime.now(timezone.utc).isoformat()
    record = death_cert_submissions[submission_id]

    record["oracle_request_id"] = oracle_request_id
    record["confidence"] = confidence

    if verified and confidence >= 95.0:
        record["status"] = "verified"
        record["verified_at"] = now

        # Update claim phase
        vault_addr = record["vault_owner_address"]
        if vault_addr in claim_statuses:
            claim_statuses[vault_addr]["phase"] = ClaimPhase.DEATH_CERT_VERIFIED.value
            claim_statuses[vault_addr]["updated_at"] = now
    else:
        record["status"] = "rejected"
        record["rejection_reason"] = rejection_reason or f"Confidence {confidence}% below 95% threshold"

        vault_addr = record["vault_owner_address"]
        if vault_addr in claim_statuses:
            claim_statuses[vault_addr]["phase"] = ClaimPhase.REJECTED.value
            claim_statuses[vault_addr]["updated_at"] = now

    return {"status": record["status"], "confidence": confidence}


# ============================================================
# ATTESTATION ROUTES
# ============================================================

@router.post("/attestation")
async def submit_attestation(attestation: AttestationSubmission):
    """
    Submit an attestation from a verified professional (attorney, notary, etc.).
    
    Attestations serve as supplementary verification alongside
    the oracle death certificate check. An attorney or notary
    issues a Verifiable Credential confirming the death.
    """
    vault_addr = attestation.vault_owner_address
    now = datetime.now(timezone.utc).isoformat()

    record = {
        "attestor_did_hash": attestation.attestor_did_hash,
        "attestor_type": attestation.attestor_type,
        "attestation_hash": attestation.attestation_hash,
        "vc_proof": attestation.verifiable_credential_proof,
        "submitted_at": now,
        "verified": False,  # Verified on-chain via VC check
    }

    if vault_addr not in attestations:
        attestations[vault_addr] = []
    attestations[vault_addr].append(record)

    return {
        "status": "accepted",
        "attestation_count": len(attestations[vault_addr]),
        "submitted_at": now,
    }


@router.get("/attestations/{vault_owner_address}")
async def get_attestations(vault_owner_address: str):
    """Get all attestations for a vault."""
    return {
        "vault_owner_address": vault_owner_address,
        "attestations": attestations.get(vault_owner_address, []),
        "count": len(attestations.get(vault_owner_address, [])),
    }


# ============================================================
# ZKP PROOF ROUTES
# ============================================================

@router.post("/identity-proof")
async def register_identity_proof(proof_meta: ZKPProofMetadata):
    """
    Register that a ZKP identity proof has been generated.
    
    The actual proof is generated CLIENT-SIDE and submitted
    directly to the smart contract. This endpoint only tracks
    the metadata for the claim flow orchestration.
    """
    vault_addr = proof_meta.vault_owner_address
    now = datetime.now(timezone.utc).isoformat()

    zkp_proofs[vault_addr] = {
        "beneficiary_address": proof_meta.beneficiary_address,
        "proof_hash": proof_meta.proof_hash,
        "nonce": proof_meta.nonce,
        "submitted_on_chain": proof_meta.submitted_on_chain,
        "tx_hash": proof_meta.tx_hash,
        "registered_at": now,
    }

    # Update claim phase
    if vault_addr in claim_statuses:
        claim_statuses[vault_addr]["phase"] = ClaimPhase.IDENTITY_PROOF_SUBMITTED.value
        claim_statuses[vault_addr]["updated_at"] = now

    return {"status": "registered", "registered_at": now}


@router.put("/identity-proof/{vault_owner_address}/on-chain")
async def mark_proof_on_chain(
    vault_owner_address: str,
    tx_hash: str,
):
    """Mark that the ZKP proof was successfully submitted on-chain."""
    if vault_owner_address not in zkp_proofs:
        raise HTTPException(status_code=404, detail="No proof registered for this vault")

    zkp_proofs[vault_owner_address]["submitted_on_chain"] = True
    zkp_proofs[vault_owner_address]["tx_hash"] = tx_hash

    return {"status": "updated", "tx_hash": tx_hash}


# ============================================================
# GUARDIAN NOTIFICATION & CONFIRMATION ROUTES
# ============================================================

@router.post("/guardian-notify")
async def notify_guardian(
    notification: GuardianNotification,
    background_tasks: BackgroundTasks,
):
    """
    Send a notification to a guardian about a claim event.
    
    Notification types:
      - claim_initiated: A claim has been started on their vault
      - confirmation_requested: Guardian needs to confirm share release
      - shares_released: All confirmations received, shares released
    """
    vault_addr = notification.vault_owner_address
    now = datetime.now(timezone.utc).isoformat()

    record = {
        "guardian_address": notification.guardian_address,
        "notification_type": notification.notification_type,
        "message": notification.message,
        "sent_at": now,
        "delivered": False,
    }

    if vault_addr not in guardian_notifications:
        guardian_notifications[vault_addr] = []
    guardian_notifications[vault_addr].append(record)

    # Background: send actual notification (email, push, SMS)
    background_tasks.add_task(
        _deliver_guardian_notification,
        vault_addr,
        notification.guardian_address,
        notification.notification_type,
        notification.message,
    )

    return {"status": "queued", "sent_at": now}


@router.post("/guardian-confirm/{vault_owner_address}/{guardian_address}")
async def record_guardian_confirmation(
    vault_owner_address: str,
    guardian_address: str,
    tx_hash: str,
):
    """
    Record that a guardian has confirmed share release on-chain.
    
    This is called after the guardian's on-chain confirmShareRelease()
    transaction is confirmed. Updates the claim status tracker.
    """
    vault_addr = vault_owner_address
    now = datetime.now(timezone.utc).isoformat()

    if vault_addr in claim_statuses:
        if "guardian_confirmations" not in claim_statuses[vault_addr]:
            claim_statuses[vault_addr]["guardian_confirmations"] = {}

        claim_statuses[vault_addr]["guardian_confirmations"][guardian_address] = {
            "confirmed_at": now,
            "tx_hash": tx_hash,
        }
        claim_statuses[vault_addr]["phase"] = ClaimPhase.GUARDIAN_CONFIRMATIONS.value
        claim_statuses[vault_addr]["updated_at"] = now

    return {"status": "recorded", "guardian": guardian_address, "confirmed_at": now}


# ============================================================
# CLAIM STATUS ROUTES
# ============================================================

@router.get("/claim-status/{vault_owner_address}", response_model=ClaimStatus)
async def get_claim_status(vault_owner_address: str):
    """
    Get the full claim status for a vault, aggregating all verification steps.
    
    Returns the current phase, death cert status, attestations,
    identity proof status, guardian confirmations, and cooldown info.
    """
    vault_addr = vault_owner_address

    if vault_addr not in claim_statuses:
        return ClaimStatus(
            vault_owner_address=vault_addr,
            phase=ClaimPhase.IDLE,
        )

    cs = claim_statuses[vault_addr]

    # Build death cert status
    death_cert = None
    if "death_cert_submission_id" in cs:
        sid = cs["death_cert_submission_id"]
        if sid in death_cert_submissions:
            rec = death_cert_submissions[sid]
            death_cert = DeathCertStatus(**{k: rec[k] for k in DeathCertStatus.model_fields})

    # Build guardian confirmation list
    guardian_list = []
    raw_confirmations = cs.get("guardian_confirmations", {})
    for addr, info in raw_confirmations.items():
        guardian_list.append(GuardianConfirmationStatus(
            guardian_address=addr,
            has_confirmed=True,
            confirmed_at=info.get("confirmed_at"),
            notification_sent=True,
            notification_sent_at=info.get("confirmed_at"),
        ))

    # Build attestation list
    vault_attestations = attestations.get(vault_addr, [])

    # Check ZKP proof status
    proof_submitted = vault_addr in zkp_proofs and zkp_proofs[vault_addr].get("submitted_on_chain", False)

    return ClaimStatus(
        vault_owner_address=vault_addr,
        beneficiary_address=cs.get("beneficiary_address"),
        phase=ClaimPhase(cs.get("phase", ClaimPhase.IDLE.value)),
        death_cert_status=death_cert,
        attestations=vault_attestations,
        identity_proof_submitted=proof_submitted,
        guardian_confirmations=guardian_list,
        confirmations_received=len(guardian_list),
        confirmations_required=cs.get("confirmations_required", 3),
        cooldown_ends=cs.get("cooldown_ends"),
        shares_released=cs.get("shares_released", False),
        started_at=cs.get("started_at"),
        updated_at=cs.get("updated_at"),
    )


@router.post("/claim-status/{vault_owner_address}/shares-released")
async def mark_shares_released(
    vault_owner_address: str,
    tx_hash: str,
    background_tasks: BackgroundTasks,
):
    """
    Mark that shares have been released for this vault.
    
    Called after the SharesReleased event is detected on-chain.
    Triggers final notifications to beneficiary and guardians.
    """
    vault_addr = vault_owner_address
    now = datetime.now(timezone.utc).isoformat()

    if vault_addr in claim_statuses:
        claim_statuses[vault_addr]["phase"] = ClaimPhase.SHARES_RELEASED.value
        claim_statuses[vault_addr]["shares_released"] = True
        claim_statuses[vault_addr]["updated_at"] = now
        claim_statuses[vault_addr]["release_tx_hash"] = tx_hash

    # Background: notify all parties
    background_tasks.add_task(
        _notify_shares_released,
        vault_addr,
        tx_hash,
    )

    return {"status": "shares_released", "tx_hash": tx_hash, "at": now}


@router.get("/claim-status/{vault_owner_address}/timeline")
async def get_claim_timeline(vault_owner_address: str):
    """
    Get a chronological timeline of all claim events for a vault.
    Useful for audit trail and UI display.
    """
    vault_addr = vault_owner_address
    timeline = []

    # Death cert events
    for sid, rec in death_cert_submissions.items():
        if rec["vault_owner_address"] == vault_addr:
            timeline.append({
                "event": "death_certificate_submitted",
                "timestamp": rec["submitted_at"],
                "details": {
                    "source": rec["certificate_source"],
                    "jurisdiction": rec["jurisdiction"],
                },
            })
            if rec.get("verified_at"):
                timeline.append({
                    "event": "death_certificate_verified",
                    "timestamp": rec["verified_at"],
                    "details": {"confidence": rec["confidence"]},
                })

    # Attestation events
    for att in attestations.get(vault_addr, []):
        timeline.append({
            "event": "attestation_submitted",
            "timestamp": att["submitted_at"],
            "details": {"type": att["attestor_type"]},
        })

    # ZKP proof events
    if vault_addr in zkp_proofs:
        proof = zkp_proofs[vault_addr]
        timeline.append({
            "event": "identity_proof_registered",
            "timestamp": proof["registered_at"],
            "details": {"on_chain": proof["submitted_on_chain"]},
        })

    # Guardian confirmation events
    if vault_addr in claim_statuses:
        for addr, info in claim_statuses[vault_addr].get("guardian_confirmations", {}).items():
            timeline.append({
                "event": "guardian_confirmed",
                "timestamp": info["confirmed_at"],
                "details": {"guardian": addr[:10] + "..."},
            })

    # Guardian notifications
    for notif in guardian_notifications.get(vault_addr, []):
        timeline.append({
            "event": f"notification_{notif['notification_type']}",
            "timestamp": notif["sent_at"],
            "details": {"guardian": notif["guardian_address"][:10] + "..."},
        })

    # Sort by timestamp
    timeline.sort(key=lambda x: x["timestamp"])

    return {
        "vault_owner_address": vault_addr,
        "timeline": timeline,
        "event_count": len(timeline),
    }


# ============================================================
# BACKGROUND TASKS
# ============================================================

async def _trigger_oracle_verification(
    submission_id: str,
    vault_owner_address: str,
    certificate_hash: str,
):
    """
    Trigger oracle verification of a death certificate.
    
    In production, this would:
      1. Call Chainlink Functions requestVerification() on-chain
      2. Or call a custom oracle API that queries death records
      3. The oracle callback updates the submission status
    
    For MVP, this simulates the oracle request.
    """
    import asyncio
    # Simulate oracle processing delay
    await asyncio.sleep(2)

    # In production: Submit tx to ChainlinkDeathOracle.requestVerification()
    # The oracle's fulfillRequest() callback will call our oracle-callback endpoint
    
    if submission_id in death_cert_submissions:
        death_cert_submissions[submission_id]["status"] = "oracle_submitted"
        death_cert_submissions[submission_id]["oracle_request_id"] = f"req_{secrets.token_hex(8)}"


async def _deliver_guardian_notification(
    vault_owner_address: str,
    guardian_address: str,
    notification_type: str,
    message: Optional[str],
):
    """
    Deliver notification to guardian via their preferred channel.
    
    In production, looks up guardian's contact info and sends via:
      - Email (primary)
      - SMS (backup)
      - Push notification (if app installed)
    """
    import asyncio
    await asyncio.sleep(1)

    # Mark as delivered
    if vault_owner_address in guardian_notifications:
        for notif in guardian_notifications[vault_owner_address]:
            if (notif["guardian_address"] == guardian_address and
                notif["notification_type"] == notification_type):
                notif["delivered"] = True
                break


async def _notify_shares_released(
    vault_owner_address: str,
    tx_hash: str,
):
    """
    Notify all parties that shares have been released.
    
    Sends notifications to:
      - Beneficiary: "Your shares are ready for reconstruction"
      - Guardians: "Share release complete for vault [address]"
    """
    import asyncio
    await asyncio.sleep(1)
    # In production: Send notifications via email/push/SMS
