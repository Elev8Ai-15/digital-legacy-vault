/**
 * chainlink-death-verify.js — Chainlink Functions Source Code
 * 
 * Digital Legacy Vault - Phase 2: Oracle Verification Layer
 * Built by Brad Powell / Elev8.AI Consulting & Integration
 * 
 * THIS CODE RUNS ON THE CHAINLINK DECENTRALIZED ORACLE NETWORK (DON).
 * It is NOT a Node.js module - it executes in Chainlink's Deno runtime.
 * 
 * WHAT IT DOES:
 *   Queries multiple death verification sources and returns an aggregated
 *   confidence score to the smart contract.
 * 
 * DATA SOURCES:
 *   1. SSA Death Master File (Social Security Administration)
 *      - Public dataset of deceased individuals
 *      - Accessed via NTIS subscription or approved data provider
 *   
 *   2. State Vital Records (where API available)
 *      - Florida (FL EDRS), California, New York, Texas, etc.
 *      - Varies by state; some have APIs, some require FOIA
 *   
 *   3. Third-party death verification services
 *      - LexisNexis Accurint Death Index
 *      - Experian/TransUnion death indicators
 *      - Genealogy databases (Find a Grave, Legacy.com)
 * 
 * ARGS (from smart contract):
 *   args[0] = decedentName     (full legal name)
 *   args[1] = dateOfDeath      (YYYY-MM-DD)
 *   args[2] = stateOfDeath     (2-letter state code)
 *   args[3] = ssnLast4         (last 4 digits of SSN)
 *   args[4] = certificateHash  (hex string of document hash)
 * 
 * SECRETS (stored in Chainlink DON encrypted storage):
 *   secrets.SSA_API_KEY        - SSA Death Master File API key
 *   secrets.STATE_API_KEY      - State vital records API key
 *   secrets.LEXISNEXIS_KEY     - LexisNexis Accurint API key
 * 
 * RETURNS:
 *   abi.encode(uint8 sourcesConfirmed, bool ssaMatch, bool stateMatch, bool notaryMatch)
 */

// ============================================================
// ARGS & SECRETS
// ============================================================

const decedentName = args[0];
const dateOfDeath = args[1];
const stateOfDeath = args[2];
const ssnLast4 = args[3];
const certificateHash = args[4];

// Track verification results
let sourcesConfirmed = 0;
let ssaMatch = false;
let stateMatch = false;
let thirdPartyMatch = false;


// ============================================================
// SOURCE 1: SSA DEATH MASTER FILE
// ============================================================

/**
 * Query the Social Security Administration Death Master File.
 * 
 * The DMF is distributed by NTIS (National Technical Information Service).
 * Access requires certification under the Bipartisan Budget Act of 2013
 * Section 203, which restricts access to legitimate fraud prevention
 * and verification purposes.
 * 
 * Digital Legacy Vault qualifies as a "legitimate fraud prevention" use case
 * because we are verifying death to prevent fraudulent inheritance claims.
 */
async function checkSSADeathMasterFile() {
    try {
        if (!secrets.SSA_API_KEY) return false;

        // SSA DMF API endpoint (via authorized data provider)
        const response = await Functions.makeHttpRequest({
            url: `https://api.deathrecords.provider.example/v1/verify`,
            method: "POST",
            headers: {
                "Authorization": `Bearer ${secrets.SSA_API_KEY}`,
                "Content-Type": "application/json"
            },
            data: {
                name: decedentName,
                date_of_death: dateOfDeath,
                ssn_last4: ssnLast4,
                state: stateOfDeath
            },
            timeout: 10000
        });

        if (response.error) {
            console.log("SSA API error:", response.error);
            return false;
        }

        // Check for match
        const data = response.data;
        if (data && data.match === true && data.confidence >= 0.9) {
            return true;
        }

        return false;
    } catch (e) {
        console.log("SSA check failed:", e.message);
        return false;
    }
}


// ============================================================
// SOURCE 2: STATE VITAL RECORDS
// ============================================================

/**
 * Query state-level vital records databases.
 * 
 * Availability varies by state. States with electronic death
 * registration systems (EDRS) may offer API access.
 * 
 * Florida uses the FL EDRS managed by the FL Dept of Health.
 * Access requires authorized user status.
 */
async function checkStateVitalRecords() {
    try {
        if (!secrets.STATE_API_KEY) return false;

        // State vital records endpoint (varies by state)
        const stateEndpoints = {
            "FL": "https://api.flhealthcharts.gov/v1/death-records",
            "CA": "https://api.cdph.ca.gov/v1/vital-records/death",
            "NY": "https://api.health.ny.gov/v1/vital-records",
            "TX": "https://api.dshs.texas.gov/v1/vital-statistics/death"
            // Add more states as APIs become available
        };

        const endpoint = stateEndpoints[stateOfDeath.toUpperCase()];
        if (!endpoint) {
            console.log(`No API available for state: ${stateOfDeath}`);
            return false;
        }

        const response = await Functions.makeHttpRequest({
            url: endpoint,
            method: "POST",
            headers: {
                "Authorization": `Bearer ${secrets.STATE_API_KEY}`,
                "Content-Type": "application/json"
            },
            data: {
                decedent_name: decedentName,
                date_of_death: dateOfDeath,
                certificate_hash: certificateHash
            },
            timeout: 10000
        });

        if (response.error) {
            console.log("State API error:", response.error);
            return false;
        }

        const data = response.data;
        if (data && data.record_found === true) {
            return true;
        }

        return false;
    } catch (e) {
        console.log("State check failed:", e.message);
        return false;
    }
}


// ============================================================
// SOURCE 3: THIRD-PARTY VERIFICATION
// ============================================================

/**
 * Query third-party death verification indices.
 * 
 * LexisNexis Accurint Death Index aggregates multiple sources:
 *   - SSA Death Master File
 *   - State death records
 *   - Obituary databases
 *   - Insurance industry death reports
 * 
 * This provides an independent cross-reference beyond direct
 * government sources.
 */
async function checkThirdPartyVerification() {
    try {
        if (!secrets.LEXISNEXIS_KEY) return false;

        const response = await Functions.makeHttpRequest({
            url: `https://api.lexisnexis.com/accurint/v2/death-index/verify`,
            method: "POST",
            headers: {
                "Authorization": `Bearer ${secrets.LEXISNEXIS_KEY}`,
                "Content-Type": "application/json"
            },
            data: {
                full_name: decedentName,
                date_of_death: dateOfDeath,
                ssn_last_four: ssnLast4,
                state_of_death: stateOfDeath
            },
            timeout: 10000
        });

        if (response.error) {
            console.log("Third-party API error:", response.error);
            return false;
        }

        const data = response.data;
        if (data && data.death_confirmed === true) {
            return true;
        }

        return false;
    } catch (e) {
        console.log("Third-party check failed:", e.message);
        return false;
    }
}


// ============================================================
// MAIN EXECUTION
// ============================================================

try {
    // Run all checks in parallel
    const [ssaResult, stateResult, thirdPartyResult] = await Promise.allSettled([
        checkSSADeathMasterFile(),
        checkStateVitalRecords(),
        checkThirdPartyVerification()
    ]);

    // Process results
    ssaMatch = ssaResult.status === "fulfilled" && ssaResult.value === true;
    stateMatch = stateResult.status === "fulfilled" && stateResult.value === true;
    thirdPartyMatch = thirdPartyResult.status === "fulfilled" && thirdPartyResult.value === true;

    // Count confirmed sources
    if (ssaMatch) sourcesConfirmed++;
    if (stateMatch) sourcesConfirmed++;
    if (thirdPartyMatch) sourcesConfirmed++;

    console.log(`Verification complete: ${sourcesConfirmed} sources confirmed`);
    console.log(`  SSA: ${ssaMatch}, State: ${stateMatch}, Third-party: ${thirdPartyMatch}`);

} catch (e) {
    console.log("Verification execution error:", e.message);
    // Return zero confidence on execution error
    sourcesConfirmed = 0;
    ssaMatch = false;
    stateMatch = false;
    thirdPartyMatch = false;
}


// ============================================================
// ENCODE & RETURN
// ============================================================

/**
 * Return ABI-encoded result to smart contract.
 * 
 * Format: abi.encode(uint8, bool, bool, bool)
 * The smart contract decodes this in fulfillRequest()
 */
const abiCoder = new ethers.AbiCoder();
const encoded = abiCoder.encode(
    ["uint8", "bool", "bool", "bool"],
    [sourcesConfirmed, ssaMatch, stateMatch, thirdPartyMatch]
);

return Functions.encodeUint256(
    BigInt("0x" + Buffer.from(encoded).toString("hex"))
);
