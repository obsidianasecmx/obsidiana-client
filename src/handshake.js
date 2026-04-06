"use strict";

/**
 * Obsidiana Handshake — Full cryptographic handshake over HTTP.
 *
 * Performs the complete Obsidiana handshake sequence:
 * 1. GET /q — receive PoW challenge + server ECDSA signature
 * 2. Verify server identity using ObsidianaECDSA.verify()
 * 3. Solve PoW challenge
 * 4. Generate ephemeral client ECDSA keypair and sign challenge
 * 5. Complete ECDH key exchange
 * 6. Derive AES-GCM-256 session key
 *
 * @module handshake
 * @private
 */

const {
  ObsidianaHandshake,
  ObsidianaECDSA,
  ObsidianaCBOR,
} = require("@obsidianasecmx/obsidiana-protocol");
const { solvePOW, unpackChallenge, packOffer } = require("./pow");

/**
 * Computes SHA-256 hash of a string and returns hex digest.
 *
 * @param {string} str - Input string
 * @returns {Promise<string>} Hex digest (64 chars)
 * @private
 */
async function sha256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Performs the full Obsidiana handshake: PoW → ECDH with mutual authentication.
 *
 * @param {string} baseUrl - Server base URL (e.g., 'https://api.example.com')
 * @param {Function} fetchFn - Fetch implementation (native fetch or polyfill)
 * @param {string} [serverKey=""] - Base64-encoded server identity public key
 * @returns {Promise<{ cipher: object, sessionId: string, sharedSecret: Uint8Array }>}
 *          Handshake result containing AES cipher, session ID, and raw shared secret
 * @throws {Error} If server identity verification fails, PoW fails, or handshake errors
 */
async function doHandshake(baseUrl, fetchFn, serverKey = "") {
  const chRes = await fetchFn(`${baseUrl}/q`, { method: "GET" });
  if (!chRes.ok) throw new Error(`GET /q failed: ${chRes.status}`);

  const chBuf = await chRes.arrayBuffer();
  const chEnvelope = ObsidianaCBOR.decode(new Uint8Array(chBuf));

  const dot = chEnvelope.d.lastIndexOf(".");
  const blob = chEnvelope.d.slice(0, dot);
  const sig = chEnvelope.d.slice(dot + 1);
  const blobBytes = new TextEncoder().encode(blob);

  if (!serverKey) {
    throw new Error(
      "[obsidiana-client] Server identity verification failed. " +
        "Server key not configured. Connection aborted.",
    );
  }

  const isValid = await ObsidianaECDSA.verify(serverKey, blobBytes, sig);
  if (!isValid) {
    throw new Error(
      "[obsidiana-client] Server identity verification failed. " +
        "Possible MITM attack or key mismatch. Connection aborted.",
    );
  }

  const serverKeyHash = await sha256(serverKey);

  const challenge = unpackChallenge(blob);
  const { nonce } = await solvePOW(challenge.hash, challenge.difficulty);

  const signer = new ObsidianaECDSA();
  await signer.generateKeypair();

  const clientSig = await signer.sign(blobBytes);
  const signerPublicKey = await signer.exportPublicKey();

  const hs = new ObsidianaHandshake({ signer });
  await hs.init();
  const ecdhPublicKey = hs.offer().d;

  const offerBlob = packOffer(
    ecdhPublicKey,
    signerPublicKey,
    challenge.id,
    nonce,
    clientSig,
    serverKeyHash,
  );

  const offerWire = ObsidianaCBOR.encode({ d: offerBlob });

  const hsRes = await fetchFn(`${baseUrl}/q`, {
    method: "POST",
    body: offerWire,
    headers: {
      "Content-Type": "application/octet-stream",
    },
  });

  if (!hsRes.ok) throw new Error(`POST /q failed: ${hsRes.status}`);

  const hsBuf = await hsRes.arrayBuffer();
  const hsEnvelope = ObsidianaCBOR.decode(new Uint8Array(hsBuf));
  await hs.complete({ response: hsEnvelope });

  return {
    cipher: hs.cipher,
    sessionId: hs.sessionId,
    sharedSecret: hs.sharedSecret,
  };
}

module.exports = { doHandshake };
