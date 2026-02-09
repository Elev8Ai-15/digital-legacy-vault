"""
Digital Legacy Vault — Backend Orchestration API
Built by Brad Powell / Elev8.AI Consulting & Integration

This server handles ONLY orchestration and metadata:
  - User registration (DID-based, no passwords stored)
  - Vault status monitoring & notifications
  - Check-in reminders
  - Guardian coordination
  - Content archive metadata (IPFS CIDs)
  - Beneficiary notification pipeline

CRITICAL: This server NEVER stores, handles, or transmits credentials.
All credential encryption and Shamir splitting happens client-side.
The server holds at most 1 SSS share per vault (platform cold storage share).

Run: uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime, timedelta, timezone
from typing import Optional
from enum import Enum
import hashlib
import secrets
import logging

# ============================================================
# APP CONFIGURATION
# ============================================================

app = FastAPI(
    title="Digital Legacy Vault API",
    description="Orchestration API for blockchain-powered digital inheritance",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS — allow frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",      # React dev
        "http://localhost:5173",      # Vite dev
        "https://digitallegacyvault.com",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger = logging.getLogger("digital-legacy-vault")

# ============================================================
# PHASE 2: VERIFICATION ROUTES
# ============================================================

from api.verification_routes import router as verification_router
app.include_router(verification_router)

# ============================================================
# MODELS
# ============================================================

class VaultState(str, Enum):
    ACTIVE = "active"
    WARNING = "warning"
    CLAIMABLE = "claimable"
    CLAIMED = "claimed"
    REVOKED = "revoked"


class RegisterRequest(BaseModel):
    """User registration — DID-based, no email/password on server"""
    did_hash: str = Field(..., description="SHA-256 hash of user's DID")
    wallet_address: str = Field(..., description="Polygon wallet address")
    display_name: Optional[str] = Field(None, description="Optional display name")
    notification_email: Optional[str] = Field(None, description="Optional email for reminders only")
    notification_phone: Optional[str] = Field(None, description="Optional phone for SMS reminders")


class RegisterResponse(BaseModel):
    user_id: str
    did_hash: str
    wallet_address: str
    created_at: datetime
    api_token: str


class VaultRegistration(BaseModel):
    """Register a vault's metadata (after smart contract deployment)"""
    contract_address: str
    chain_id: int = 137  # Polygon mainnet
    check_in_interval_days: int
    grace_period_days: int
    threshold: int
    total_guardians: int


class GuardianInfo(BaseModel):
    """Guardian metadata (no SSS share data — that's client-side only)"""
    guardian_address: str
    guardian_type: str  # device, beneficiary, attorney, cold, backup
    guardian_name: Optional[str] = None
    notification_email: Optional[str] = None


class BeneficiaryInfo(BaseModel):
    """Beneficiary contact info for notification pipeline"""
    beneficiary_address: str
    beneficiary_did_hash: str
    notification_email: Optional[str] = None
    notification_phone: Optional[str] = None


class ContentArchiveEntry(BaseModel):
    """IPFS content archive metadata"""
    cid: str = Field(..., description="IPFS Content Identifier")
    platform: str = Field(..., description="Source platform (e.g., Instagram)")
    content_type: str = Field(..., description="Type: photos, messages, posts, etc.")
    encrypted: bool = True
    size_bytes: Optional[int] = None
    archived_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CheckInRequest(BaseModel):
    """Check-in acknowledgment (actual check-in is on-chain)"""
    tx_hash: str = Field(..., description="On-chain check-in transaction hash")


class ClaimNotification(BaseModel):
    """Notify guardians that a claim has been initiated"""
    vault_owner_address: str
    beneficiary_address: str
    claim_tx_hash: str


class VaultStatus(BaseModel):
    """Full vault status summary"""
    state: VaultState
    last_check_in: Optional[datetime]
    next_check_in_due: Optional[datetime]
    days_until_warning: Optional[int]
    guardian_count: int
    confirmations: int
    threshold: int
    content_archives: int
    contract_address: str
    chain_id: int


class ColdStorageShare(BaseModel):
    """Platform's SSS share (1 of N — useless alone)"""
    encrypted_share: str = Field(..., description="Base64-encoded SSS share")
    share_index: int = Field(..., description="Share number (1-N)")
    vault_owner_hash: str


# ============================================================
# IN-MEMORY STORE (Replace with PostgreSQL in production)
# ============================================================

users_db: dict = {}
vaults_db: dict = {}
guardians_db: dict = {}
archives_db: dict = {}
cold_shares_db: dict = {}


def get_user_id(wallet_address: str) -> Optional[str]:
    for uid, user in users_db.items():
        if user["wallet_address"].lower() == wallet_address.lower():
            return uid
    return None


# ============================================================
# AUTH (Simplified — production would use JWT + DID auth)
# ============================================================

def generate_api_token() -> str:
    return f"dlv_{secrets.token_urlsafe(32)}"


# ============================================================
# ROUTES — REGISTRATION
# ============================================================

@app.post("/api/v1/register", response_model=RegisterResponse)
async def register_user(req: RegisterRequest):
    """
    Register a new user. DID-based — no passwords stored on server.
    The server only stores: DID hash, wallet address, and notification preferences.
    """
    # Check if wallet already registered
    existing = get_user_id(req.wallet_address)
    if existing:
        raise HTTPException(status_code=409, detail="Wallet already registered")

    user_id = f"usr_{secrets.token_hex(12)}"
    api_token = generate_api_token()
    now = datetime.now(timezone.utc)

    users_db[user_id] = {
        "user_id": user_id,
        "did_hash": req.did_hash,
        "wallet_address": req.wallet_address,
        "display_name": req.display_name,
        "notification_email": req.notification_email,
        "notification_phone": req.notification_phone,
        "api_token_hash": hashlib.sha256(api_token.encode()).hexdigest(),
        "created_at": now,
    }

    return RegisterResponse(
        user_id=user_id,
        did_hash=req.did_hash,
        wallet_address=req.wallet_address,
        created_at=now,
        api_token=api_token,
    )


# ============================================================
# ROUTES — VAULT MANAGEMENT
# ============================================================

@app.post("/api/v1/vaults/{user_id}")
async def register_vault(user_id: str, vault: VaultRegistration):
    """Register vault metadata after on-chain deployment"""
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")

    vaults_db[user_id] = {
        **vault.model_dump(),
        "state": VaultState.ACTIVE,
        "last_check_in": datetime.now(timezone.utc),
        "guardians": [],
        "beneficiary": None,
        "created_at": datetime.now(timezone.utc),
    }

    return {"status": "vault_registered", "contract": vault.contract_address}


@app.get("/api/v1/vaults/{user_id}/status", response_model=VaultStatus)
async def get_vault_status(user_id: str):
    """Get comprehensive vault status"""
    if user_id not in vaults_db:
        raise HTTPException(status_code=404, detail="Vault not found")

    vault = vaults_db[user_id]
    last_check_in = vault["last_check_in"]
    interval = timedelta(days=vault["check_in_interval_days"])
    next_due = last_check_in + interval if last_check_in else None
    days_until = (next_due - datetime.now(timezone.utc)).days if next_due else None

    return VaultStatus(
        state=vault["state"],
        last_check_in=last_check_in,
        next_check_in_due=next_due,
        days_until_warning=max(0, days_until) if days_until else None,
        guardian_count=len(vault.get("guardians", [])),
        confirmations=0,
        threshold=vault["threshold"],
        content_archives=len(archives_db.get(user_id, [])),
        contract_address=vault["contract_address"],
        chain_id=vault["chain_id"],
    )


# ============================================================
# ROUTES — CHECK-IN
# ============================================================

@app.post("/api/v1/vaults/{user_id}/check-in")
async def record_check_in(user_id: str, req: CheckInRequest):
    """
    Record a check-in. The actual check-in is on-chain.
    This updates the server-side tracking for notification scheduling.
    """
    if user_id not in vaults_db:
        raise HTTPException(status_code=404, detail="Vault not found")

    vaults_db[user_id]["last_check_in"] = datetime.now(timezone.utc)
    vaults_db[user_id]["state"] = VaultState.ACTIVE

    return {
        "status": "check_in_recorded",
        "tx_hash": req.tx_hash,
        "next_due": datetime.now(timezone.utc) + timedelta(days=vaults_db[user_id]["check_in_interval_days"]),
    }


# ============================================================
# ROUTES — GUARDIANS
# ============================================================

@app.post("/api/v1/vaults/{user_id}/guardians")
async def add_guardian(user_id: str, guardian: GuardianInfo):
    """Register guardian contact info for notification pipeline"""
    if user_id not in vaults_db:
        raise HTTPException(status_code=404, detail="Vault not found")

    if "guardians" not in vaults_db[user_id]:
        vaults_db[user_id]["guardians"] = []

    vaults_db[user_id]["guardians"].append(guardian.model_dump())
    return {"status": "guardian_added", "total": len(vaults_db[user_id]["guardians"])}


@app.post("/api/v1/vaults/{user_id}/beneficiary")
async def set_beneficiary(user_id: str, beneficiary: BeneficiaryInfo):
    """Register beneficiary contact info"""
    if user_id not in vaults_db:
        raise HTTPException(status_code=404, detail="Vault not found")

    vaults_db[user_id]["beneficiary"] = beneficiary.model_dump()
    return {"status": "beneficiary_set"}


# ============================================================
# ROUTES — COLD STORAGE SHARE
# ============================================================

@app.post("/api/v1/vaults/{user_id}/cold-share")
async def store_cold_share(user_id: str, share: ColdStorageShare):
    """
    Store the platform's SSS share (1 of N).
    This share alone reveals ZERO information about the credential.
    Stored encrypted at rest in production.
    """
    if user_id not in vaults_db:
        raise HTTPException(status_code=404, detail="Vault not found")

    cold_shares_db[user_id] = {
        "encrypted_share": share.encrypted_share,
        "share_index": share.share_index,
        "stored_at": datetime.now(timezone.utc).isoformat(),
    }

    return {"status": "cold_share_stored", "share_index": share.share_index}


@app.get("/api/v1/vaults/{user_id}/cold-share")
async def retrieve_cold_share(user_id: str):
    """
    Retrieve cold storage share. In production, this requires:
    1. Vault state == CLAIMABLE or CLAIMED
    2. Beneficiary identity verified via ZKP
    3. Guardian threshold met on-chain
    """
    if user_id not in cold_shares_db:
        raise HTTPException(status_code=404, detail="No cold share found")

    # TODO: Verify on-chain state before releasing
    return cold_shares_db[user_id]


# ============================================================
# ROUTES — CONTENT ARCHIVES
# ============================================================

@app.post("/api/v1/vaults/{user_id}/archives")
async def add_content_archive(user_id: str, entry: ContentArchiveEntry):
    """Register an encrypted content archive stored on IPFS"""
    if user_id not in archives_db:
        archives_db[user_id] = []

    archives_db[user_id].append(entry.model_dump())
    return {"status": "archive_registered", "cid": entry.cid, "total": len(archives_db[user_id])}


@app.get("/api/v1/vaults/{user_id}/archives")
async def list_content_archives(user_id: str):
    """List all content archive entries"""
    return archives_db.get(user_id, [])


# ============================================================
# ROUTES — NOTIFICATIONS (Background Tasks)
# ============================================================

@app.post("/api/v1/vaults/{user_id}/notify-claim")
async def notify_claim_initiated(
    user_id: str,
    notification: ClaimNotification,
    background_tasks: BackgroundTasks,
):
    """
    Trigger notification pipeline when a claim is initiated.
    Notifies all guardians to review and confirm share release.
    """
    if user_id not in vaults_db:
        raise HTTPException(status_code=404, detail="Vault not found")

    vault = vaults_db[user_id]

    # Queue notifications
    background_tasks.add_task(
        _send_guardian_notifications,
        vault.get("guardians", []),
        notification,
    )

    return {"status": "notifications_queued", "guardian_count": len(vault.get("guardians", []))}


async def _send_guardian_notifications(guardians: list, notification: ClaimNotification):
    """Send notifications to all guardians about the claim"""
    for guardian in guardians:
        email = guardian.get("notification_email")
        if email:
            # In production: use SendGrid, SES, etc.
            logger.info(
                f"[NOTIFICATION] Guardian {guardian['guardian_name']} ({email}): "
                f"Claim initiated for vault {notification.vault_owner_address}. "
                f"Please review and confirm share release."
            )


# ============================================================
# ROUTES — HEALTH & INFO
# ============================================================

@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "digital-legacy-vault",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "users": len(users_db),
        "vaults": len(vaults_db),
    }


@app.get("/api/v1/info")
async def platform_info():
    return {
        "name": "Digital Legacy Vault",
        "version": "0.1.0",
        "blockchain": "Polygon",
        "chain_id": 137,
        "encryption": "AES-256-GCM",
        "secret_sharing": "Shamir's Secret Sharing (3-of-5)",
        "identity": "W3C DID:key + Verifiable Credentials",
        "storage": "IPFS / Arweave",
        "credential_storage": "NONE — all client-side",
        "built_by": "Elev8.AI Consulting & Integration",
    }


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():
    logger.info("Digital Legacy Vault API starting...")
    logger.info("SECURITY: This server stores ZERO credentials.")
    logger.info("SECURITY: Maximum 1 SSS share per vault (cold storage).")
    logger.info("SECURITY: Single share reveals zero information.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
