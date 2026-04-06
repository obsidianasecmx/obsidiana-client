"use strict";

/**
 * Obsidiana Proof of Work — Client‑side PoW solver and offer packing.
 *
 * Provides functions for solving PoW challenges (finding nonce that produces
 * required leading zero bits) and packing/unpacking handshake messages.
 *
 * @private
 */

/**
 * Yields control back to the event loop.
 *
 * @returns {Promise<void>}
 * @private
 */
function _yield() {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/**
 * Solves a Proof of Work challenge.
 *
 * Brute‑forces a nonce until SHA‑256(hash + nonce) has the required number
 * of leading zero bits. Batches iterations to avoid blocking the main thread.
 *
 * @param {string} hash - Challenge hash (hex string, 64 chars)
 * @param {number} difficulty - Required leading zero bits (0‑255)
 * @param {number} [batchSize] - Hashes per batch before yielding (auto if omitted)
 * @returns {Promise<{ nonce: string, attempts: number }>}
 */
async function solvePOW(hash, difficulty, batchSize) {
  const enc = new TextEncoder();
  const fullChars = Math.floor(difficulty / 4);
  const remainder = difficulty % 4;

  const BATCH =
    batchSize ?? (difficulty <= 8 ? 2000 : difficulty <= 16 ? 500 : 100);

  let attempts = 0;

  while (true) {
    for (let i = 0; i < BATCH; i++) {
      const nonce = attempts.toString(16);
      const input = enc.encode(hash + nonce);
      const buf = await crypto.subtle.digest("SHA-256", input);
      const digest = Array.from(new Uint8Array(buf), (b) =>
        b.toString(16).padStart(2, "0"),
      ).join("");

      let valid = true;
      for (let j = 0; j < fullChars; j++) {
        if (digest[j] !== "0") {
          valid = false;
          break;
        }
      }

      if (valid && remainder > 0) {
        const val = parseInt(digest[fullChars], 16);
        const mask = 0xf >> remainder;
        if (val > mask) valid = false;
      }

      if (valid) return { nonce, attempts };
      attempts++;
    }

    await _yield();
  }
}

/**
 * Unpacks a base64‑encoded challenge blob from the server.
 *
 * Wire format: id (32 bytes) + difficulty (1) + ttl (2) + hash (64 bytes)
 *
 * @param {string} b64 - Base64‑encoded challenge blob
 * @returns {{ id: string, hash: string, difficulty: number, ttl: number }}
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
 * Wire format: length‑prefixed fields for ECDH key, signer key, challenge ID,
 * nonce, client signature, and server key hash.
 *
 * @param {string} ecdhPublicKey - Base64‑encoded ECDH public key (65 bytes)
 * @param {string} signerPublicKey - Base64‑encoded client ECDSA public key (65 bytes)
 * @param {string} challengeId - Hex challenge ID (32 chars)
 * @param {string} nonce - PoW nonce solution
 * @param {string} clientSig - Client's ECDSA signature over the challenge
 * @param {string} [serverKeyHash=""] - Hash of server's public key
 * @returns {string} Base64‑encoded offer blob
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

  buf[offset] = (ecdh.length >> 8) & 0xff;
  buf[offset + 1] = ecdh.length & 0xff;
  offset += 2;
  buf.set(ecdh, offset);
  offset += ecdh.length;

  buf[offset] = (signer.length >> 8) & 0xff;
  buf[offset + 1] = signer.length & 0xff;
  offset += 2;
  buf.set(signer, offset);
  offset += signer.length;

  buf[offset] = (cid.length >> 8) & 0xff;
  buf[offset + 1] = cid.length & 0xff;
  offset += 2;
  buf.set(cid, offset);
  offset += cid.length;

  buf[offset] = (n.length >> 8) & 0xff;
  buf[offset + 1] = n.length & 0xff;
  offset += 2;
  buf.set(n, offset);
  offset += n.length;

  buf[offset] = (sig.length >> 8) & 0xff;
  buf[offset + 1] = sig.length & 0xff;
  offset += 2;
  buf.set(sig, offset);
  offset += sig.length;

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
