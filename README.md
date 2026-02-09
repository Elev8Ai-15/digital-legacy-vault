# Digital Legacy Vault

**Blockchain-Powered Inheritance Protocol for Your Digital Life**

Built by Brad Powell / [Elev8.AI Consulting & Integration](https://elev8ai.org)

---

## What Is This?

Digital Legacy Vault is a decentralized inheritance protocol that lets users securely pass their digital credentials (social media accounts, email, content libraries) to designated beneficiaries after death — without any central server ever touching the actual credentials.

**The core innovation:** Your credentials are encrypted on your device, split into 5 mathematical shares using Shamir's Secret Sharing, and distributed to guardians. A Polygon smart contract monitors your periodic check-ins. If you stop checking in (dead man's switch) or a verified death certificate is submitted, the contract orchestrates share release to your beneficiary, who reconstructs your credentials on *their* device.

**We never see your passwords. Ever.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      CLIENT DEVICE                          │
│                                                             │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐               │
│  │ AES-256  │──▶│ Shamir   │──▶│ Share    │               │
│  │ Encrypt  │   │ Split    │   │ Distrib  │               │
│  └──────────┘   └──────────┘   └──────────┘               │
│       ▲                              │                      │
│       │                    ┌─────────┼─────────┐            │
│  [credentials]             ▼         ▼         ▼            │
│                         Share 1   Share 2   Share 3...      │
└─────────────────────────────────────────────────────────────┘
                              │         │         │
                    ┌─────────┘    ┌────┘    ┌────┘
                    ▼              ▼         ▼
              ┌──────────┐  ┌──────────┐  ┌──────────┐
              │ Guardian  │  │ Attorney │  │ Cold     │
              │ Device   │  │ Escrow   │  │ Storage  │
              └──────────┘  └──────────┘  └──────────┘

┌─────────────────────────────────────────────────────────────┐
│                    POLYGON BLOCKCHAIN                        │
│                                                             │
│  ┌──────────────────────────────────────────────┐           │
│  │       DigitalLegacyVaultV2.sol               │           │
│  │                                               │           │
│  │  • Dead Man's Switch (check-in timer)        │           │
│  │  • State: Active → Warning → Claimable       │           │
│  │  • Guardian threshold enforcement (3 of 5)   │           │
│  │  • IPFS content archive CID registry         │           │
│  └──────────┬──────────────────┬────────────────┘           │
│             │                  │                             │
│  ┌──────────▼──────────┐  ┌───▼──────────────────────┐     │
│  │ Groth16Verifier.sol │  │ ChainlinkDeathOracle.sol │     │
│  │ + ZKPIdentity       │  │                          │     │
│  │   Verifier.sol      │  │ • Chainlink Functions    │     │
│  │                     │  │ • Multi-source death     │     │
│  │ • On-chain ZKP      │  │   record verification   │     │
│  │ • Poseidon hash     │  │ • 95% confidence gate    │     │
│  │ • Replay protection │  │ • Attestor system        │     │
│  └─────────────────────┘  └──────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   BACKEND (Orchestration Only)               │
│                                                             │
│  • User registration (DID hash, wallet address)             │
│  • Check-in reminders (email/SMS)                           │
│  • Guardian notification pipeline                            │
│  • Death cert verification tracking + claim status API      │
│  • Content archive metadata                                  │
│  • Holds 1 SSS share (cold storage — useless alone)         │
│  • Stores ZERO credentials                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
digital-legacy-vault/
├── contracts/
│   ├── DigitalLegacyVault.sol        # Phase 1 smart contract
│   ├── DigitalLegacyVaultV2.sol      # Phase 2 vault (ZKP + oracle)
│   ├── Groth16Verifier.sol           # On-chain ZKP proof verifier
│   ├── ZKPIdentityVerifier.sol       # Identity proof wrapper
│   ├── ChainlinkDeathOracle.sol      # Chainlink Functions death oracle
│   └── MockOracle.sol                # Test oracle for dev
├── circuits/
│   └── identity_proof.circom         # Circom ZKP circuit (Poseidon hash)
├── scripts/
│   ├── deploy.js                     # Phase 1 deployment script
│   └── deploy-v2.js                  # Phase 2 full stack deployment
├── test/
│   ├── DigitalLegacyVault.test.js    # Phase 1 test suite (30+ tests)
│   └── Phase2Verification.test.js    # Phase 2 test suite (37 tests)
├── src/
│   ├── crypto/
│   │   ├── shamir.js                 # Shamir's Secret Sharing (GF(2^8))
│   │   └── vault-crypto.js           # AES-256-GCM encryption layer
│   ├── blockchain/
│   │   └── vault-client.js           # Ethers.js contract interaction
│   ├── identity/
│   │   └── did-manager.js            # W3C DID & Verifiable Credentials
│   ├── zkp/
│   │   └── proof-generator.js        # Client-side Groth16 proof generation
│   ├── verification/
│   │   ├── claim-flow.js             # Full claim orchestration manager
│   │   ├── death-cert-manager.js     # Death certificate pipeline
│   │   └── chainlink-death-verify.js # Chainlink DON source code
│   └── ui/
│       └── BeneficiaryClaimFlow.jsx  # Beneficiary claim UI (820 lines)
├── api/
│   ├── main.py                       # FastAPI backend (Phase 1 routes)
│   ├── verification_routes.py        # Phase 2 verification API routes
│   └── requirements.txt
├── hardhat.config.js
├── package.json
├── .env.example
└── README.md
```

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Blockchain | Polygon (EVM) | Smart contracts, $0.001 gas |
| Smart Contracts | Solidity 0.8.20 | Inheritance protocol, dead man's switch |
| Secret Sharing | Custom GF(2^8) | Shamir's SSS (3-of-5 threshold) |
| Encryption | AES-256-GCM | Client-side credential encryption |
| Identity | W3C DID:key | Decentralized identity, no usernames |
| Credentials | Verifiable Credentials | Beneficiary identity proof |
| ZKP | Circom + SnarkJS | Zero-knowledge identity verification |
| Oracle | Chainlink Functions | Death certificate verification |
| Storage | IPFS / Arweave (Phase 3) | Encrypted content archives |
| Backend | FastAPI (Python) | Orchestration, notifications |
| Frontend | React + Ethers.js | Client-side app |
| Dev Tools | Hardhat | Compile, test, deploy |

---

## Quick Start

### Prerequisites
- Node.js >= 18
- Python >= 3.10
- MetaMask or compatible wallet

### Smart Contracts

```bash
# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run test suite
npx hardhat test

# Start local node
npx hardhat node

# Deploy locally
npx hardhat run scripts/deploy.js

# Deploy to Polygon Amoy testnet
npx hardhat run scripts/deploy.js --network polygon_amoy
```

### Backend API

```bash
cd api
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# API docs: http://localhost:8000/api/docs
```

### Environment Setup

```bash
cp .env.example .env
# Edit .env with your keys
```

---

## Security Model

### What the platform stores:
- User DID hash (not the DID itself)
- Wallet addresses
- Notification preferences (optional email/phone)
- Content archive IPFS CIDs (encrypted content, not credentials)
- 1 SSS share per vault (mathematically useless alone)

### What the platform NEVER stores:
- Passwords or credentials
- Encryption keys
- Master passwords
- Unencrypted SSS shares
- Full DID documents

### Attack Scenarios

| Attack | Risk | Why |
|--------|------|-----|
| Server breach | **None** | 1 SSS share = zero information (mathematically provable) |
| Rogue employee | **None** | Cannot reconstruct with 1 share, need 3 |
| State-level actor | **None** | Even with server + subpoena, 1 share reveals nothing |
| Beneficiary fraud | **Very Low** | Need: fake death cert + pass ZKP + convince 2+ guardians |
| Guardian collusion | **Low** | Need 3 guardians to collude + beneficiary identity proof |

### Legal Position (US)

- **CFAA**: Platform never accesses credentials = no unauthorized access
- **RUFADAA**: Content archival via authorized APIs legal in 48+ states  
- **Platform ToS**: User splits own credentials on own device; platform is infrastructure
- **Van Buren v. US (2021)**: Narrowed CFAA to unauthorized system access

---

## Smart Contract States

```
Active ──[check-in missed]──▶ Warning ──[grace expired]──▶ Claimable ──[threshold met]──▶ Claimed
  ▲                              │
  └──[check-in received]─────────┘
  
Active ──[death cert verified by oracle]──▶ Claimable ──[threshold met]──▶ Claimed

Any* ──[owner revokes]──▶ Revoked
  (* except Claimed)
```

### Timing Configuration
- Check-in interval: 30-365 days (default: 90)
- Grace period: 30+ days (default: 60)
- Claim cooldown: 14 days
- Total time to trigger: 150 days minimum

---

## Inheritance Flow

1. **User registers** — Creates DID, connects wallet, deploys vault contract
2. **Credentials encrypted** — AES-256-GCM on device, split into 5 Shamir shares
3. **Shares distributed** — Device, beneficiary, attorney, cold storage, backup guardian
4. **Smart contract deployed** — Dead man's switch with configured intervals
5. **Living phase** — User checks in periodically, archives content to IPFS
6. **Trigger** — Check-in lapses past grace period OR verified death certificate
7. **Claim** — Beneficiary submits claim with ZKP identity proof
8. **Guardian confirmation** — 3 of 5 guardians confirm share release on-chain
9. **Reconstruction** — Beneficiary collects shares, reconstructs credentials on their device

---

## Competitive Advantage

The entire blockchain inheritance space ($17.5M+ funded, 364+ companies) focuses exclusively on **crypto asset custody**. Zero competitors are building blockchain-powered inheritance for social media accounts, digital content, or non-crypto assets.

Digital Legacy Vault is the **first** platform in this space.

---

## Roadmap

### Phase 1: Core Protocol ✅
- [x] Smart contract (Solidity)
- [x] Shamir's Secret Sharing
- [x] AES-256-GCM encryption
- [x] DID / Verifiable Credentials
- [x] Blockchain client (ethers.js)
- [x] Backend API (FastAPI)
- [x] Interactive prototype
- [x] Test suite (30+ tests)

### Phase 2: Verification Layer ✅ (Current)
- [x] ZKP identity proof (Circom circuit + Groth16 verifier)
- [x] Chainlink Functions oracle (death certificate verification)
- [x] ZKP Identity Verifier contract (on-chain proof checking)
- [x] DigitalLegacyVaultV2 (upgraded vault with real ZKP + oracle)
- [x] Client-side proof generator (SnarkJS + Poseidon)
- [x] Death certificate verification pipeline
- [x] Claim flow orchestration manager
- [x] Verification API routes (FastAPI)
- [x] Beneficiary claim flow UI (React, 820 lines)
- [x] V2 deployment script (full stack: Verifier → Oracle → VaultV2)
- [x] Phase 2 test suite (37 tests)

### Phase 3: Content Archive (Next)
- [ ] Social media API integrations
- [ ] IPFS/Arweave encrypted storage
- [ ] Content download tools
- [ ] Multi-platform support

### Phase 4: Polish + Legal
- [ ] Full React Native mobile app
- [ ] Attorney partnership portal
- [ ] Terms of service / legal docs
- [ ] SOC 2 preparation
- [ ] Beta testing

### Phase 5: Launch
- [ ] App store submission
- [ ] Marketing site
- [ ] First 50 attorney partnerships
- [ ] Insurance procurement

**Estimated MVP: $50-85K over 22-30 weeks**

---

## License

Proprietary — Elev8.AI Consulting & Integration. All rights reserved.

---

*Built with blockchain. Secured by math. Powered by Elev8.AI.*
