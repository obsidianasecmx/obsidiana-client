"use strict";

/**
 * Obsidiana Worker Inline — React Native compatible worker shim.
 *
 * En React Native no existen worker_threads ni Web Workers con Blob URLs,
 * así que este módulo expone la misma lógica del worker como un objeto
 * que puede ser invocado directamente en el hilo principal.
 *
 * El WorkerBridge detecta React Native y usa este shim en vez de
 * intentar lanzar un worker real.
 *
 * @module worker-inline
 * @private
 */

const {
  ObsidianaCBOR,
  ObsidianaHandshake,
  ObsidianaECDSA,
} = require("@obsidianasecmx/obsidiana-protocol");
const { doHandshake } = require("./handshake");
const { solvePOW, unpackChallenge, packOffer } = require("./pow");

// Lazy-loaded ratchet
let DoubleRatchet = null;

// Estado de sesión (mismo que en worker.js)
let _cipher = null;
let _sessionId = null;
let _baseUrl = null;
let _ratchet = null;
let _wsSockets = {};

/**
 * Lee la server key desde globalThis.__SERVER_KEY__ o vacío.
 * @returns {string}
 * @private
 */
function _getServerKey() {
  if (globalThis.__SERVER_KEY__) {
    const k = globalThis.__SERVER_KEY__;
    delete globalThis.__SERVER_KEY__;
    return k;
  }
  return "";
}

/**
 * @param {string} str
 * @returns {Uint8Array}
 * @private
 */
function _fromBase64(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}

/**
 * @param {Uint8Array} buf
 * @returns {string}
 * @private
 */
function _toBase64(buf) {
  return btoa(String.fromCharCode(...buf));
}

/**
 * @param {string} str
 * @returns {Promise<string>}
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

/**
 * Crea el objeto InlineWorker que simula la interfaz de un Web Worker.
 *
 * El bridge llama a `worker.postMessage(msg)` y el worker responde
 * llamando a `worker.onmessage({ data: ... })`.
 *
 * @returns {{ postMessage: Function, onmessage: Function|null, terminate: Function }}
 */
function createInlineWorker() {
  let _onmessage = null;
  let _terminated = false;

  /**
   * Despacha una respuesta hacia el bridge (simula postMessage del worker).
   * @param {object} msg
   */
  function postBack(msg) {
    if (_terminated) return;
    if (_onmessage) _onmessage({ data: msg });
  }

  /**
   * Maneja un mensaje entrante (misma lógica que onMessage en worker.js).
   * @param {object} msg
   */
  async function handleMessage(msg) {
    if (_terminated) return;
    const { id, type, payload } = msg;

    try {
      switch (type) {
        // ── connect ──────────────────────────────────────────────────────
        case "connect": {
          _baseUrl = payload.url;
          const result = await doHandshake(_baseUrl, fetch, _getServerKey());
          _cipher = result.cipher;
          _sessionId = result.sessionId;

          if (DoubleRatchet && result.sharedSecret) {
            _ratchet = await DoubleRatchet.create(result.sharedSecret, 0);
          }

          postBack({ id, ok: true });
          break;
        }

        // ── request ───────────────────────────────────────────────────────
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
                const errEnvelope = ObsidianaCBOR.decode(
                  new Uint8Array(errBuf),
                );
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

          postBack({ id, ok: true, data: decrypted });
          break;
        }

        // ── ws:connect ────────────────────────────────────────────────────
        case "ws:connect": {
          const { wsUrl } = payload;

          let hs = null;
          let wsCipher = null;
          let wsSessionId = null;
          let wsRatchet = null;
          let handshakeDone = false;

          // React Native soporta WebSocket nativo
          const ws = new WebSocket(wsUrl);
          ws.binaryType = "arraybuffer";

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
                  // Step 1: challenge + verify
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
                      "[obsidiana-client] Server identity verification failed. Server key not configured.",
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
                    postBack({
                      id,
                      ok: false,
                      error:
                        "[obsidiana-client] WS server identity verification failed.",
                    });
                    ws.close();
                    return;
                  }

                  // Step 2: PoW
                  const challenge = unpackChallenge(blob);
                  const { nonce } = await solvePOW(
                    challenge.hash,
                    challenge.difficulty,
                  );

                  // Step 3: ECDSA keypair
                  const signer = new ObsidianaECDSA();
                  await signer.generateKeypair();
                  const clientSig = await signer.sign(blobBytes);
                  const signerPublicKey = await signer.exportPublicKey();

                  // Step 4: ECDH
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
                  // Step 6: complete handshake
                  await hs.complete({ response: msg });
                  wsCipher = hs.cipher;
                  wsSessionId = hs.sessionId;
                  handshakeDone = true;

                  if (DoubleRatchet && hs.sharedSecret) {
                    wsRatchet = await DoubleRatchet.create(hs.sharedSecret, 0);
                  }

                  // Notificar ws:ready SIN id (event-style)
                  postBack({ type: "ws:ready", wsUrl });

                  // Registrar handler para mensajes posteriores
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
                            new TextDecoder().decode(
                              blob.slice(14, 14 + aadLen),
                            ),
                          );
                          if (Math.abs(Date.now() - aad.ts) > 60_000) {
                            throw new Error(
                              "Server response timestamp expired",
                            );
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

                      postBack({ type: "ws:message", wsUrl, data });
                    } catch (err) {
                      postBack({
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
              console.error("[worker-inline] WS onmessage error:", err);
              postBack({ id, ok: false, error: err.message });
            }
          };

          ws.onopen = () => console.log("[worker-inline] WS opened");
          ws.onclose = () => {
            console.log("[worker-inline] WS closed");
            postBack({ type: "ws:close", wsUrl });
          };
          ws.onerror = (e) => {
            console.error("[worker-inline] WS error:", e.message || e);
            postBack({
              type: "ws:error",
              wsUrl,
              error: e.message ?? "ws error",
            });
          };

          postBack({ id, ok: true });

          _wsSockets[wsUrl] = {
            ws,
            getCipher: () => wsCipher,
            getSessionId: () => wsSessionId,
            getRatchet: () => wsRatchet,
          };
          break;
        }

        // ── ws:send ───────────────────────────────────────────────────────
        case "ws:send": {
          const { wsUrl, data } = payload;
          const entry = _wsSockets?.[wsUrl];
          if (!entry) throw new Error(`No WS connection for ${wsUrl}`);

          let wire;
          if (entry.getRatchet?.()) {
            const { ciphertext, header } = await entry
              .getRatchet()
              .encrypt(data);
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
          postBack({ id, ok: true });
          break;
        }

        // ── ws:close ──────────────────────────────────────────────────────
        case "ws:close": {
          const { wsUrl } = payload;
          _wsSockets?.[wsUrl]?.ws.close();
          postBack({ id, ok: true });
          break;
        }

        default:
          postBack({ id, ok: false, error: `Unknown message type: ${type}` });
      }
    } catch (err) {
      console.error("[worker-inline] Unhandled error:", err);
      postBack({
        id,
        ok: false,
        error: err.message,
        status: err.status,
        body: err.body,
      });
    }
  }

  return {
    /** Simula worker.postMessage() — recibe mensajes del bridge */
    postMessage(msg) {
      // Ejecutar async sin bloquear
      handleMessage(msg).catch((err) => {
        postBack({ id: msg.id, ok: false, error: err.message });
      });
    },

    /** El bridge asigna su handler aquí */
    set onmessage(fn) {
      _onmessage = fn;
    },
    get onmessage() {
      return _onmessage;
    },

    /** Simula worker.terminate() */
    terminate() {
      _terminated = true;
      _onmessage = null;
      // Cerrar cualquier WS abierto
      for (const entry of Object.values(_wsSockets)) {
        try {
          entry.ws.close();
        } catch {
          /* ignore */
        }
      }
      _wsSockets = {};
    },
  };
}

module.exports = { createInlineWorker };
