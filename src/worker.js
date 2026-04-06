"use strict";

/**
 * Obsidiana Worker — Web Worker for encrypted HTTP and WebSocket communication.
 *
 * Runs cryptographic operations in a separate thread (worker_threads in Node.js,
 * Web Worker in browsers) to keep the main thread responsive.
 *
 * @module worker
 * @private
 */

const { ObsidianaCBOR } = require("@obsidianasecmx/obsidiana-protocol");
const { doHandshake } = require("./handshake");

let DoubleRatchet = null;

let isNode = false;
try {
  const _wt = require("worker_threads");
  isNode = _wt.parentPort !== null && _wt.parentPort !== undefined;
  if (!isNode) {
    isNode = true;
  }
} catch {
  isNode = false;
}

/**
 * Retrieves the server's public key from the environment.
 *
 * @returns {string} Base64-encoded server public key (65 bytes)
 * @private
 */
function _getServerKey() {
  if (globalThis.__SERVER_KEY__) {
    const k = globalThis.__SERVER_KEY__;
    delete globalThis.__SERVER_KEY__;
    return k;
  }

  if (isNode) {
    try {
      const fs = require("fs");
      const path = require("path");
      const serverPubPath = path.join(
        process.cwd(),
        ".obsidiana",
        "server.pub",
      );
      if (fs.existsSync(serverPubPath)) {
        return fs.readFileSync(serverPubPath, "utf8").trim();
      }
    } catch (err) {
      console.warn("[worker] Failed to read server public key:", err.message);
    }
  }

  return "";
}

/**
 * Converts a base64 string to Uint8Array.
 *
 * @param {string} str - Base64-encoded string
 * @returns {Uint8Array} Decoded bytes
 * @private
 */
function _fromBase64(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

/**
 * Converts a Uint8Array to base64 string.
 *
 * @param {Uint8Array} buf - Bytes to encode
 * @returns {string} Base64-encoded string
 * @private
 */
function _toBase64(buf) {
  return btoa(String.fromCharCode(...buf));
}

/**
 * Computes SHA-256 hash of a string and returns hex digest.
 *
 * @param {string} str - Input string
 * @returns {Promise<string>} Hex digest (64 chars)
 * @private
 */
async function _sha256(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

let postMessage;
let onMessage;

if (isNode) {
  const { parentPort } = require("worker_threads");
  postMessage = (msg) => parentPort.postMessage(msg);
  onMessage = (fn) => parentPort.on("message", fn);
} else {
  postMessage = (msg) => globalThis.postMessage(msg);
  onMessage = (fn) => globalThis.addEventListener("message", (e) => fn(e.data));
}

let _cipher = null;
let _sessionId = null;
let _baseUrl = null;
let _ratchet = null;
let _wsSockets = {};

onMessage(async (msg) => {
  const { id, type, payload } = msg;

  try {
    switch (type) {
      case "connect": {
        _baseUrl = payload.url;
        const result = await doHandshake(_baseUrl, fetch, _getServerKey());
        _cipher = result.cipher;
        _sessionId = result.sessionId;

        if (DoubleRatchet && result.sharedSecret) {
          _ratchet = await DoubleRatchet.create(result.sharedSecret, 0);
        }

        postMessage({ id, ok: true });
        break;
      }

      case "request": {
        const { method, path, body } = payload;

        let wireData;
        if (_ratchet) {
          const { ciphertext, header } = await _ratchet.encrypt(body ?? {});
          const aadEnvelope = await _cipher.encrypt(
            {},
            { sessionId: _sessionId },
          );
          wireData = ObsidianaCBOR.encode({
            d: aadEnvelope.d,
            ct: _toBase64(ciphertext),
            hdr: _toBase64(header),
          });
        } else {
          const envelope = await _cipher.encrypt(body ?? {}, {
            sessionId: _sessionId,
          });
          wireData = ObsidianaCBOR.encode(envelope);
        }

        let url = `${_baseUrl}${path}`;
        let fetchBody = wireData;

        if (method === "GET" || method === "HEAD") {
          const b64 = _toBase64(wireData)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
          url = `${url}${url.includes("?") ? "&" : "?"}_d=${encodeURIComponent(b64)}`;
          fetchBody = undefined;
        }

        const res = await fetch(url, { method, body: fetchBody });

        if (!res.ok) {
          const err = new Error(`${method} ${path} failed: ${res.status}`);
          err.status = res.status;
          try {
            const errBuf = await res.arrayBuffer();
            if (errBuf.byteLength > 0) {
              const errEnvelope = ObsidianaCBOR.decode(new Uint8Array(errBuf));
              err.body = await _cipher.decrypt(errEnvelope, {
                sessionId: _sessionId,
              });
            }
          } catch {
            /* ignore */
          }
          throw err;
        }

        const resBuf = await res.arrayBuffer();
        const resEnvelope = ObsidianaCBOR.decode(new Uint8Array(resBuf));

        let decrypted;
        if (_ratchet && resEnvelope.ct && resEnvelope.hdr) {
          if (resEnvelope.d) {
            const blob = _fromBase64(resEnvelope.d);
            const aadLen = (blob[12] << 8) | blob[13];
            const aad = JSON.parse(
              new TextDecoder().decode(blob.slice(14, 14 + aadLen)),
            );
            if (Math.abs(Date.now() - aad.ts) > 60_000) {
              throw new Error("Server response timestamp expired");
            }
          }
          const ct = _fromBase64(resEnvelope.ct);
          const hdr = _fromBase64(resEnvelope.hdr);
          decrypted = await _ratchet.decrypt(ct, hdr);
        } else {
          decrypted = await _cipher.decrypt(resEnvelope, {
            sessionId: _sessionId,
          });
        }

        postMessage({ id, ok: true, data: decrypted });
        break;
      }

      case "ws:connect": {
        const { wsUrl } = payload;

        const {
          ObsidianaHandshake,
          ObsidianaECDSA,
        } = require("@obsidianasecmx/obsidiana-protocol");
        const { packOffer, unpackChallenge, solvePOW } = require("./pow");

        const WSClass = isNode ? require("ws") : globalThis.WebSocket;
        const ws = new WSClass(wsUrl);
        ws.binaryType = "arraybuffer";

        let handshakeDone = false;
        let hs = null;
        let wsCipher = null;
        let wsSessionId = null;
        let wsRatchet = null;

        ws.onmessage = async (event) => {
          try {
            const raw = event.data;
            const buf =
              raw instanceof Uint8Array
                ? raw
                : raw?.buffer
                  ? new Uint8Array(
                      raw.buffer,
                      raw.byteOffset,
                      raw.byteLength,
                    ).slice(0)
                  : new Uint8Array(raw);
            const msg = ObsidianaCBOR.decode(buf);

            if (!handshakeDone) {
              if (!hs) {
                const d =
                  typeof msg.d === "string"
                    ? msg.d
                    : new TextDecoder().decode(msg.d);
                const dot = d.lastIndexOf(".");
                const blob = d.slice(0, dot);
                const sig = d.slice(dot + 1);

                const serverKey = _getServerKey();

                if (!serverKey) {
                  throw new Error(
                    "[obsidiana-client] Server identity verification failed. " +
                      "Server key not configured. Connection aborted.",
                  );
                }

                const keyBytes = _fromBase64(serverKey);
                const blobBytes = new TextEncoder().encode(blob);
                const sigBytes = _fromBase64(sig);

                const pubKey = await crypto.subtle.importKey(
                  "raw",
                  keyBytes,
                  { name: "ECDSA", namedCurve: "P-256" },
                  false,
                  ["verify"],
                );

                const valid = await crypto.subtle.verify(
                  { name: "ECDSA", hash: "SHA-256" },
                  pubKey,
                  sigBytes,
                  blobBytes,
                );

                if (!valid) {
                  postMessage({
                    id,
                    ok: false,
                    error:
                      "[obsidiana-client] WS server identity verification failed. Connection aborted.",
                  });
                  ws.close();
                  return;
                }

                const challenge = unpackChallenge(blob);
                const { nonce } = await solvePOW(
                  challenge.hash,
                  challenge.difficulty,
                );

                const signer = new ObsidianaECDSA();
                await signer.generateKeypair();

                const clientSig = await signer.sign(blobBytes);
                const signerPublicKey = await signer.exportPublicKey();

                hs = new ObsidianaHandshake({ signer });
                await hs.init();

                const ecdhPublicKey = hs.offer().d;

                const serverKeyHash = await _sha256(serverKey);

                const offerBlob = packOffer(
                  ecdhPublicKey,
                  signerPublicKey,
                  challenge.id,
                  nonce,
                  clientSig,
                  serverKeyHash,
                );

                ws.send(ObsidianaCBOR.encode({ d: offerBlob }));
              } else {
                await hs.complete({ response: msg });
                wsCipher = hs.cipher;
                wsSessionId = hs.sessionId;
                handshakeDone = true;

                if (DoubleRatchet && hs.sharedSecret) {
                  wsRatchet = await DoubleRatchet.create(hs.sharedSecret, 0);
                }

                postMessage({ type: "ws:ready", wsUrl });

                ws.onmessage = async (event) => {
                  try {
                    const raw = event.data;
                    const buf =
                      raw instanceof Uint8Array
                        ? raw
                        : raw?.buffer
                          ? new Uint8Array(
                              raw.buffer,
                              raw.byteOffset,
                              raw.byteLength,
                            ).slice(0)
                          : new Uint8Array(raw);
                    const env = ObsidianaCBOR.decode(buf);

                    let data;
                    if (wsRatchet && env.ct && env.hdr) {
                      if (env.d) {
                        const blob = _fromBase64(env.d);
                        const aadLen = (blob[12] << 8) | blob[13];
                        const aad = JSON.parse(
                          new TextDecoder().decode(blob.slice(14, 14 + aadLen)),
                        );
                        if (Math.abs(Date.now() - aad.ts) > 60_000) {
                          throw new Error("Server response timestamp expired");
                        }
                      }
                      const ct = _fromBase64(env.ct);
                      const hdr = _fromBase64(env.hdr);
                      data = await wsRatchet.decrypt(ct, hdr);
                    } else {
                      data = await wsCipher.decrypt(env, {
                        sessionId: wsSessionId,
                      });
                    }

                    postMessage({ type: "ws:message", wsUrl, data });
                  } catch (err) {
                    postMessage({
                      type: "ws:error",
                      wsUrl,
                      error: err.message || "decrypt failed",
                    });
                  }
                };
              }
              return;
            }
          } catch (err) {
            console.error("[worker] WS onmessage error:", err);
            postMessage({ id, ok: false, error: err.message });
          }
        };

        ws.onopen = () => {
          console.log("[worker] WS connection opened");
        };

        ws.onclose = () => {
          console.log("[worker] WS connection closed");
          postMessage({ type: "ws:close", wsUrl });
        };

        ws.onerror = (e) => {
          console.error("[worker] WS error:", e.message || e);
          postMessage({
            type: "ws:error",
            wsUrl,
            error: e.message ?? "ws error",
          });
        };

        postMessage({ id, ok: true });
        console.log("[worker] WS connect initiated for:", wsUrl);

        _wsSockets[wsUrl] = {
          ws,
          getCipher: () => wsCipher,
          getSessionId: () => wsSessionId,
          getRatchet: () => wsRatchet,
        };
        break;
      }

      case "ws:send": {
        const { wsUrl, data } = payload;
        const entry = _wsSockets?.[wsUrl];
        if (!entry) throw new Error(`No WS connection for ${wsUrl}`);

        let wire;
        if (entry.getRatchet?.()) {
          const { ciphertext, header } = await entry.getRatchet().encrypt(data);
          const aadEnvelope = await entry
            .getCipher()
            .encrypt({}, { sessionId: entry.getSessionId() });
          wire = ObsidianaCBOR.encode({
            d: aadEnvelope.d,
            ct: _toBase64(ciphertext),
            hdr: _toBase64(header),
          });
        } else {
          const envelope = await entry
            .getCipher()
            .encrypt(data, { sessionId: entry.getSessionId() });
          wire = ObsidianaCBOR.encode(envelope);
        }

        entry.ws.send(wire);
        postMessage({ id, ok: true });
        break;
      }

      case "ws:close": {
        const { wsUrl } = payload;
        _wsSockets?.[wsUrl]?.ws.close();
        postMessage({ id, ok: true });
        break;
      }

      default:
        postMessage({ id, ok: false, error: `Unknown message type: ${type}` });
    }
  } catch (err) {
    console.error("[worker] Unhandled error:", err);
    postMessage({
      id,
      ok: false,
      error: err.message,
      status: err.status,
      body: err.body,
    });
  }
});
