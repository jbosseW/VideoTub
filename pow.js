// pow.js — Proof-of-Work challenge system (anti-bot / anti-automation gate).
// No third-party dependencies. Clients must find a nonce where
// SHA256(challenge + nonce) has N leading zero bits before they can upload.

const crypto = require("crypto");

// Leading zero BITS required. ~18 bits ≈ 260K hashes ≈ 1-2s in a browser worker.
const DIFFICULTY = Math.max(8, Number(process.env.POW_DIFFICULTY || 18));
const CHALLENGE_TTL_MS = 5 * 60 * 1000; // 5 minutes to solve
const CLEANUP_INTERVAL_MS = 60 * 1000;

const issuedChallenges = new Map(); // challengeHex -> { createdAt }
const usedChallenges = new Map();   // challengeHex -> usedAt (anti-replay)

setInterval(() => {
  const now = Date.now();
  for (const [ch, data] of issuedChallenges) {
    if (now - data.createdAt > CHALLENGE_TTL_MS) issuedChallenges.delete(ch);
  }
  for (const [ch, ts] of usedChallenges) {
    if (now - ts > CHALLENGE_TTL_MS) usedChallenges.delete(ch);
  }
}, CLEANUP_INTERVAL_MS);

function generateChallenge() {
  const challenge = crypto.randomBytes(16).toString("hex");
  issuedChallenges.set(challenge, { createdAt: Date.now() });
  return { challenge, difficulty: DIFFICULTY };
}

function hasLeadingZeros(hashBuf, difficulty) {
  const fullBytes = Math.floor(difficulty / 8);
  const remainBits = difficulty % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (hashBuf[i] !== 0) return false;
  }
  if (remainBits > 0) {
    const mask = 0xff << (8 - remainBits);
    if ((hashBuf[fullBytes] & mask) !== 0) return false;
  }
  return true;
}

function verify(challenge, nonce) {
  if (!challenge || typeof challenge !== "string") return { valid: false, error: "Missing challenge" };
  if (!nonce || typeof nonce !== "string" || nonce.length > 32) return { valid: false, error: "Bad nonce" };

  const issued = issuedChallenges.get(challenge);
  if (!issued) return { valid: false, error: "Unknown or expired challenge" };
  if (Date.now() - issued.createdAt > CHALLENGE_TTL_MS) {
    issuedChallenges.delete(challenge);
    return { valid: false, error: "Challenge expired" };
  }
  if (usedChallenges.has(challenge)) return { valid: false, error: "Challenge already used" };

  const hash = crypto.createHash("sha256").update(challenge + nonce).digest();
  if (!hasLeadingZeros(hash, DIFFICULTY)) return { valid: false, error: "Invalid solution" };

  usedChallenges.set(challenge, Date.now());
  issuedChallenges.delete(challenge);
  return { valid: true };
}

module.exports = { generateChallenge, verify, DIFFICULTY };
