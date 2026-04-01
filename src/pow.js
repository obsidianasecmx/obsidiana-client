"use strict";

/**
 * Obsidiana Proof of Work — Client-side PoW solver and offer packing.
 *
 * Provides client-side functions for:
 * - Solving PoW challenges (finding nonce that produces leading zero bits)
 * - Unpacking server challenges from base64
 * - Packing client offers with ECDH keys, PoW solution, and signatures
 *
 * The PoW algorithm uses SHA-256: client must find a nonce such that
 * SHA-256(hash + nonce) starts with `difficulty` leading zero bits.
 *
 * @module pow-client
 * @private
 */

/**
 * Solves a Proof of Work challenge.
 *
 * Brute-forces a nonce until SHA-256(hash + nonce) has the required number
 * of leading zero bits. Nonces start from 0 and increment.
 *
 * @param {string} hash - Challenge hash (hex string, 64 chars)
 * @param {number} difficulty - Required leading zero bits (0-8)
 * @returns {Promise<{ nonce: string, attempts: number }>}
 *          Object containing the found nonce (hex string) and attempt count
 *
 * @example
 * const { nonce, attempts } = await solvePOW('a3f8c2d1...', 4);
 * // nonce = "1a2b3c4d", attempts = 12345
 */
async function solvePOW(hash, difficulty) {
  const enc = new TextEncoder();
  const fullChars = Math.floor(difficulty / 4);
  const remainder = difficulty % 4;
  let attempts = 0;

  while (true) {
    const nonce = attempts.toString(16);
    const input = enc.encode(hash + nonce);
    const buf = await crypto.subtle.digest("SHA-256", input);
    const digest = Array.from(new Uint8Array(buf), (b) =>
      b.toString(16).padStart(2, "0"),
    ).join("");

    // Check full zero characters
    let valid = true;
    for (let i = 0; i < fullChars; i++) {
      if (digest[i] !== "0") {
        valid = false;
        break;
      }
    }

    // Check remaining bits (partial character)
    if (valid && remainder > 0) {
      const val = parseInt(digest[fullChars], 16);
      const mask = 0xf >> remainder;
      if (val > mask) valid = false;
    }

    if (valid) return { nonce, attempts };
    attempts++;
  }
}

/**
 * Unpacks a base64-encoded challenge blob from the server.
 *
 * Wire format:
 * ┌──────────────┬──────────────┬──────────────┬──────────────┐
 * │ id (32 bytes)│ difficulty(1)│ ttl (2 bytes)│ hash (64 bytes)│
 * └──────────────┴──────────────┴──────────────┴──────────────┘
 *
 * @param {string} b64 - Base64-encoded challenge blob
 * @returns {{ id: string, hash: string, difficulty: number, ttl: number }}
 *          Decoded challenge object
 *
 * @example
 * const challenge = unpackChallenge(serverChallenge);
 * // { id: "a1b2c3...", hash: "def456...", difficulty: 4, ttl: 30 }
 */
function unpackChallenge(b64) {
  const bin = atob(b64);
  const buf = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  const ID_LEN = 32;
  const HASH_LEN = 64;
  let offset = 0;

  const id = new TextDecoder().decode(buf.slice(offset, offset + ID_LEN));
  offset += ID_LEN;

  const difficulty = buf[offset];
  offset += 1;

  const ttl = (buf[offset] << 8) | buf[offset + 1];
  offset += 2;

  const hash = new TextDecoder().decode(buf.slice(offset, offset + HASH_LEN));

  return { id, hash, difficulty, ttl };
}

/**
 * Packs a client offer into a base64 blob for transmission to the server.
 *
 * Wire format (all length-prefixed):
 * ┌─────────────┬──────────────┬─────────────┬──────────────┬─────────────┬──────────────┬─────────────┬──────────────┐
 * │ ecdhKeyLen  │ ecdhKey      │ signerKeyLen│ signerKey    │ challengeLen│ challengeId  │ nonceLen    │ nonce        │
 * ├─────────────┼──────────────┼─────────────┼──────────────┼─────────────┼──────────────┼─────────────┼──────────────┤
 * │ sigLen      │ clientSig    │ skhLen      │ serverKeyHash│
 * └─────────────┴──────────────┴─────────────┴──────────────┘
 *
 * @param {string} ecdhPublicKey - Base64-encoded ECDH public key (65 bytes)
 * @param {string} signerPublicKey - Base64-encoded client ECDSA public key (65 bytes)
 * @param {string} challengeId - Hex challenge ID (32 chars)
 * @param {string} nonce - PoW nonce solution
 * @param {string} clientSig - Client's ECDSA signature over the challenge
 * @param {string} [serverKeyHash=""] - Hash of server's public key (proof of verification)
 * @returns {string} Base64-encoded offer blob
 *
 * @example
 * const offer = packOffer(
 *   ecdhPublicKey,
 *   signerPublicKey,
 *   challenge.id,
 *   nonce,
 *   clientSig,
 *   serverKeyHash
 * );
 */
function packOffer(
  ecdhPublicKey,
  signerPublicKey,
  challengeId,
  nonce,
  clientSig,
  serverKeyHash = "",
) {
  const ecdh = new TextEncoder().encode(ecdhPublicKey);
  const signer = new TextEncoder().encode(signerPublicKey);
  const cid = new TextEncoder().encode(challengeId);
  const n = new TextEncoder().encode(nonce);
  const sig = new TextEncoder().encode(clientSig);
  const skh = new TextEncoder().encode(serverKeyHash);

  const buf = new Uint8Array(
    2 +
      ecdh.length +
      2 +
      signer.length +
      2 +
      cid.length +
      2 +
      n.length +
      2 +
      sig.length +
      2 +
      skh.length,
  );
  let offset = 0;

  // ecdhPublicKey
  buf[offset] = (ecdh.length >> 8) & 0xff;
  buf[offset + 1] = ecdh.length & 0xff;
  offset += 2;
  buf.set(ecdh, offset);
  offset += ecdh.length;

  // signerPublicKey
  buf[offset] = (signer.length >> 8) & 0xff;
  buf[offset + 1] = signer.length & 0xff;
  offset += 2;
  buf.set(signer, offset);
  offset += signer.length;

  // challengeId
  buf[offset] = (cid.length >> 8) & 0xff;
  buf[offset + 1] = cid.length & 0xff;
  offset += 2;
  buf.set(cid, offset);
  offset += cid.length;

  // nonce
  buf[offset] = (n.length >> 8) & 0xff;
  buf[offset + 1] = n.length & 0xff;
  offset += 2;
  buf.set(n, offset);
  offset += n.length;

  // clientSig
  buf[offset] = (sig.length >> 8) & 0xff;
  buf[offset + 1] = sig.length & 0xff;
  offset += 2;
  buf.set(sig, offset);
  offset += sig.length;

  // serverKeyHash
  buf[offset] = (skh.length >> 8) & 0xff;
  buf[offset + 1] = skh.length & 0xff;
  offset += 2;
  buf.set(skh, offset);

  return btoa(String.fromCharCode(...buf));
}

module.exports = {
  solvePOW,
  unpackChallenge,
  packOffer,
};
