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
 * All cryptographic operations use Web Crypto API and are compatible with
 * Node.js 18+, browsers, and React Native.
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
 * Steps:
 * 1. Fetch challenge from server (GET /q)
 * 2. Verify server identity using ObsidianaECDSA.verify() (prevents MITM)
 * 3. Solve PoW challenge
 * 4. Generate ephemeral client ECDSA keypair
 * 5. Sign challenge with client key (mutual authentication)
 * 6. Send offer with client's ECDH public key, PoW solution, and signatures
 * 7. Complete ECDH handshake and derive AES-GCM-256 session key
 *
 * @param {string} baseUrl - Server base URL (e.g., 'https://api.example.com')
 * @param {Function} fetchFn - Fetch implementation (native fetch or polyfill)
 * @param {string} [serverKey=""] - Base64-encoded server identity public key
 * @returns {Promise<{ cipher: object, sessionId: string, sharedSecret: Uint8Array }>}
 *          Handshake result containing AES cipher, session ID, and raw shared secret
 * @throws {Error} If server identity verification fails, PoW fails, or handshake errors
 */
async function doHandshake(baseUrl, fetchFn, serverKey = "") {
  // ── Step 1: Request PoW challenge from server ─────────────────────────
  const chRes = await fetchFn(`${baseUrl}/q`, { method: "GET" });
  if (!chRes.ok) throw new Error(`GET /q failed: ${chRes.status}`);

  const chBuf = await chRes.arrayBuffer();
  const chEnvelope = ObsidianaCBOR.decode(new Uint8Array(chBuf));

  // Extract blob and signature from response (format: "blob.sig")
  const dot = chEnvelope.d.lastIndexOf(".");
  const blob = chEnvelope.d.slice(0, dot);
  const sig = chEnvelope.d.slice(dot + 1);
  const blobBytes = new TextEncoder().encode(blob);

  // ── Step 2: Verify server identity using ObsidianaECDSA.verify() ───────
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

  // Compute hash of server key as proof of verification
  const serverKeyHash = await sha256(serverKey);

  // ── Step 3: Solve PoW challenge ───────────────────────────────────────
  const challenge = unpackChallenge(blob);
  const { nonce } = await solvePOW(challenge.hash, challenge.difficulty);

  // ── Step 4: Generate client ECDSA keypair for mutual authentication ───
  const signer = new ObsidianaECDSA();
  await signer.generateKeypair();

  // Sign the challenge blob with client's key
  const clientSig = await signer.sign(blobBytes);
  const signerPublicKey = await signer.exportPublicKey();

  // ── Step 5: Generate ephemeral ECDH keypair ───────────────────────────
  const hs = new ObsidianaHandshake({ signer });
  await hs.init();
  const ecdhPublicKey = hs.offer().d;

  // ── Step 6: Build and send offer to server ────────────────────────────
  const offerBlob = packOffer(
    ecdhPublicKey,
    signerPublicKey,
    challenge.id,
    nonce,
    clientSig,
    serverKeyHash, // Proof that client verified the correct server key
  );

  const offerWire = ObsidianaCBOR.encode({ d: offerBlob });

  const hsRes = await fetchFn(`${baseUrl}/q`, {
    method: "POST",
    body: offerWire,
  });

  if (!hsRes.ok) throw new Error(`POST /q failed: ${hsRes.status}`);

  // ── Step 7: Complete ECDH handshake and derive session key ────────────
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
