# Obsidiana Client

A zero-runtime-dependency browser and Node.js client for [obsidiana-server](https://github.com/obsidianasecmx/obsidiana-server). Provides transparent end-to-end encryption for HTTP requests and WebSocket connections — all cryptographic operations run in a **Web Worker** (or `worker_threads` in Node.js) to keep the main thread completely unblocked.

**Compatible with modern browsers, Node.js 18+, and React Native.**

---

## Table of Contents

- [How it works](#how-it-works)
- [Installation](#installation)
- [Server Key](#server-key)
- [HTTP Client](#http-client)
  - [Quick start](#quick-start)
  - [All HTTP methods](#all-http-methods)
  - [Error handling](#error-handling)
- [WebSocket Client](#websocket-client)
  - [Quick start](#quick-start-1)
  - [Events](#events)
- [Build system](#build-system)
  - [Outputs](#outputs)
  - [Build options](#build-options)
  - [Key obfuscation](#key-obfuscation)
- [Browser usage](#browser-usage)
- [Node.js usage](#nodejs-usage)
- [Architecture](#architecture)
- [API Reference](#api-reference)

---

## How it works

Every connection goes through a full cryptographic handshake before any application data is exchanged. This happens automatically inside the worker — your code just calls `connect()`.

```
Worker thread                               Server
─────────────                               ──────
GET /q  ──────────────────────────────────► Issue PoW challenge
        ◄─────────────────── { blob, sig }


Verify server signature (ECDSA P-256)
  └─ aborts if key mismatch or invalid


Solve PoW: SHA-256(hash + nonce) with N leading zero bits
Generate ephemeral ECDSA keypair, sign challenge
Generate ephemeral ECDH P-256 keypair


POST /q ──── { ecdhKey, signerKey, challengeId,  ──►  Verify PoW + client sig
               nonce, clientSig, serverKeyHash }       Complete ECDH
        ◄──────────────── { response }                 Derive AES-GCM-256 key


                ◄──── Encrypted channel ────►


HTTP:  encrypt(body) → CBOR → fetch → CBOR → decrypt(response)
WS:    encrypt(msg)  → send  →  recv → decrypt(msg) → emit("message")
```

The server key is embedded into the bundle at build time and protected with multi-XOR obfuscation. The key slot name changes on every build. No plaintext key string exists anywhere in the distributed bundle.

---

## Installation

```bash
npm install @obsidianasecmx/obsidiana-client
```

> **Zero runtime dependencies.** `esbuild` and `javascript-obfuscator` are
> build-only tools used to generate the obfuscated bundle — they are
> never loaded at runtime.

---

## Server Key

The client **must** know the server's ECDSA public key to verify its identity during the handshake. Without it, `connect()` throws immediately — this is intentional.

In development (Node.js), the client automatically reads `.obsidiana/server.pub` from the current working directory. In production, the key must be embedded at build time.

The server's public key is generated on first boot and stored at `.obsidiana/server.pub`. Copy its contents when configuring your client bundle:

```bash
cat .obsidiana/server.pub
# BKvf3...== (88-char base64 string)
```

If `obsidiana-client` and `obsidiana-server` are installed as sibling packages, the server automatically rebuilds the client bundle with the correct key embedded on every `app.listen()`.

---

## HTTP Client

### Quick start

```js
const { createClient } = require("@obsidianasecmx/obsidiana-client");

const client = createClient({ url: "https://api.example.com" });

// Performs PoW + ECDH handshake — resolves when ready
await client.connect();

// All requests are transparently encrypted
const user = await client.get("/api/users/42");
const created = await client.post("/api/users", { name: "Alice" });
const updated = await client.patch("/api/users/42", { active: true });
await client.delete("/api/users/42");

// Clean up when done
client.destroy();
```

### All HTTP methods

```js
// GET — encrypted body sent as query param (?_d=...)
const data = await client.get("/api/products");

// POST
const order = await client.post("/api/orders", {
  productId: "abc",
  quantity: 2,
});

// PUT
const doc = await client.put("/api/documents/1", {
  title: "Updated title",
  content: "...",
});

// PATCH
const patched = await client.patch("/api/users/5", { role: "admin" });

// DELETE — body is optional
await client.delete("/api/sessions/xyz");
await client.delete("/api/posts/1", { reason: "spam" });
```

> **GET requests** are a special case: the encrypted payload is Base64url-encoded and sent as the `_d` query parameter instead of a body, since browsers don't allow bodies on GET requests.

### Error handling

If the server returns a non-2xx status, the client throws an `Error` with additional properties:

```js
try {
  const data = await client.post("/api/login", {
    user: "alice",
    pass: "wrong",
  });
} catch (err) {
  console.log(err.message); // "POST /api/login failed: 401"
  console.log(err.status); // 401
  console.log(err.body); // decrypted error body from server (if any)
}
```

---

## WebSocket Client

### Quick start

```js
const { createWSClient } = require("@obsidianasecmx/obsidiana-client");

const ws = createWSClient({ url: "wss://api.example.com/live" });

// Performs PoW + ECDH handshake over the WebSocket
await ws.connect();

// Receive decrypted messages
ws.on("message", (data) => {
  console.log("Received:", data); // plain JS object, already decrypted
});

// Send encrypted message
await ws.send({ event: "subscribe", topic: "notifications" });

// Clean up
ws.close();
```

### Events

```js
ws.on("open", () => console.log("Handshake complete, ready"));
ws.on("message", (data) => console.log("Decrypted message:", data));
ws.on("close", () => console.log("Connection closed"));
ws.on("error", (err) => console.error("Error:", err));

// Remove a specific handler
ws.off("message", myHandler);
```

---

## Build system

The build script bundles the client for browser distribution, injects the server's public key, and applies heavy obfuscation to the worker code.

```bash
# Build with server key from environment variable
OBSIDIAN_SERVER_KEY="$(cat .obsidiana/server.pub)" node build.js

# Or call buildClient() programmatically
const { buildClient } = require("@obsidianasecmx/obsidiana-client/build");

await buildClient({
  serverKey: fs.readFileSync(".obsidiana/server.pub", "utf8").trim(),
  outDir: "./public/js",
  obfuscate: true,
});
```

### Outputs

Three bundle formats are generated:

| File                      | Format                | Use case                                |
| ------------------------- | --------------------- | --------------------------------------- |
| `obsidiana-client.js`     | ESM (obfuscated)      | Modern bundlers (Vite, Webpack, Rollup) |
| `obsidiana-client.umd.js` | UMD/IIFE (obfuscated) | `<script>` tag, legacy environments     |
| `obsidiana-client.min.js` | ESM (minified only)   | When you handle obfuscation yourself    |

### Build options

```js
await buildClient({
  // Server's ECDSA public key (base64). Required for production.
  // Falls back to OBSIDIAN_SERVER_KEY env var.
  serverKey: "BKvf3...",

  // Output directory for bundles (default: ./dist)
  outDir: "./public/js",

  // Additional directory to copy completed bundles to
  copyTo: "../server/.obsidiana",

  // Apply javascript-obfuscator to final bundles (default: true)
  // Disable only for debugging
  obfuscate: true,
});
```

### Key obfuscation

The server key never appears as a plaintext string in the distributed bundle. The build system applies **multi-XOR splitting**:

1. The key bytes are XORed with **3 independent random masks**, producing 3 encrypted parts.
2. Each part and mask is individually **Base64-encoded and fragmented** into random-sized string chunks (2–7 chars each).
3. The reconstruction function is injected inside the worker IIFE and runs at startup, then all fragments and the reconstructed key are **immediately nulled** after first use.
4. The **variable name** holding the key slot is randomly generated on every build (`_0xa3f8c2d1`, etc.) — static analysis cannot rely on a stable identifier.
5. The entire worker is then processed with `javascript-obfuscator` with **control flow flattening** (75%), **dead code injection** (40%), and a fully scrambled string array.

This does not prevent a determined attacker from extracting the key with a debugger — the key must be present in memory at runtime. The goal is to make automated static extraction impractical.

---

## Browser usage

### ESM (with a bundler)

```js
import { createClient, createWSClient } from "./obsidiana-client.js";

const client = createClient({ url: "https://api.example.com" });
await client.connect();
const data = await client.get("/api/hello");
```

### UMD (script tag)

```html
<script src="/js/obsidiana-client.umd.js"></script>
<script>
  const { createClient } = ObsidianaClient;

  (async () => {
    const client = createClient({ url: "https://api.example.com" });
    await client.connect();
    const data = await client.get("/api/hello");
    console.log(data);
  })();
</script>
```

### React example

```jsx
import { createClient } from "./obsidiana-client.js";
import { useState, useEffect, useRef } from "react";

function useObsidiana(url) {
  const clientRef = useRef(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const client = createClient({ url });
    clientRef.current = client;
    client.connect().then(() => setReady(true));
    return () => client.destroy();
  }, [url]);

  return { client: clientRef.current, ready };
}

function App() {
  const { client, ready } = useObsidiana("https://api.example.com");

  const handleClick = async () => {
    if (!ready) return;
    const data = await client.post("/api/data", { hello: "world" });
    console.log(data);
  };

  return (
    <button onClick={handleClick} disabled={!ready}>
      Send
    </button>
  );
}
```

### WebSocket in React

```jsx
import { createWSClient } from "./obsidiana-client.js";
import { useEffect, useRef } from "react";

function useLiveConnection(url) {
  const wsRef = useRef(null);

  useEffect(() => {
    const ws = createWSClient({ url });
    wsRef.current = ws;

    ws.connect().then(() => {
      ws.on("message", (data) => {
        console.log("Live update:", data);
      });
    });

    return () => ws.close();
  }, [url]);

  return wsRef;
}
```

---

## Node.js usage

In Node.js the worker runs as a `worker_threads.Worker` using the source files directly — no bundle needed. The server key is automatically read from `.obsidiana/server.pub` in your working directory.

```js
const {
  createClient,
  createWSClient,
} = require("@obsidianasecmx/obsidiana-client");

// HTTP
const client = createClient({ url: "http://localhost:3000" });
await client.connect();

const result = await client.post("/api/process", { input: "data" });
console.log(result);

client.destroy();

// WebSocket
const ws = createWSClient({ url: "ws://localhost:3000/live" });
await ws.connect();

ws.on("message", (data) => console.log("Live:", data));
await ws.send({ subscribe: "events" });

// Close after 10 seconds
setTimeout(() => ws.close(), 10000);
```

---

## Architecture

```
Main thread
    │
    ├── ObsidianaClient         ← HTTP client (thin wrapper)
    │       └── WorkerBridge    ← Promise-based postMessage bridge
    │
    └── ObsidianaWSClient       ← WebSocket client (thin wrapper)
            └── WorkerBridge    ← same bridge, event forwarding


Worker thread  (worker.js — isolated, obfuscated in browser bundles)
    │
    ├── doHandshake()           ← GET /q → verify sig → solve PoW → POST /q → ECDH
    │       ├── solvePOW()      ← brute-force nonce via SHA-256
    │       ├── packOffer()     ← binary pack: ecdhKey + signerKey + nonce + sigs
    │       └── unpackChallenge()
    │
    ├── "connect"    → doHandshake → store cipher + sessionId
    ├── "request"    → cipher.encrypt(body) → fetch → cipher.decrypt(response)
    ├── "ws:connect" → open WebSocket → doHandshake over WS frames
    ├── "ws:send"    → cipher.encrypt(data) → ws.send(CBOR)
    └── "ws:close"   → ws.close()


WorkerBridge message protocol:
    send  → { id, type, payload }
    recv  → { id, ok, data }       (response)
          → { type, ... }          (event, no id — forwarded to handlers)
```

### Worker isolation

All secrets (session key, session ID, shared secret) live **exclusively in the worker thread**. The main thread never has access to any cryptographic material — it only sends plaintext in and receives plaintext out. This means a compromised main thread context (e.g., an XSS payload) cannot extract the session key by inspecting JavaScript variables.

### Session lifecycle

```
connect()    → handshake → cipher stored in worker
request()    → worker encrypts with stored cipher → fetch → worker decrypts
destroy()    → worker.terminate() → cipher gone from memory
```

Sessions are ephemeral. If the worker is terminated and a new one started, `connect()` must be called again to establish a new session.

---

## API Reference

### `createClient(options)`

```
createClient(options)  →  ObsidianaClient

options.url           string   — Base URL of the server (required)
```

### `ObsidianaClient`

```
.connect()                    → Promise<this>
.get(path)                    → Promise<any>
.post(path, body?)            → Promise<any>
.put(path, body?)             → Promise<any>
.patch(path, body?)           → Promise<any>
.delete(path, body?)          → Promise<any>
.destroy()                    → void
```

Errors thrown by request methods have:

```
err.message   string   — "METHOD /path failed: STATUS"
err.status    number   — HTTP status code
err.body      any      — decrypted error body from server (if any)
```

### `createWSClient(options)`

```
createWSClient(options)  →  ObsidianaWSClient

options.url     string   — WebSocket URL (required)
```

### `ObsidianaWSClient`

```
.connect()                    → Promise<this>  (resolves after handshake)
.send(data)                   → Promise<void>
.on(event, fn)                → this
.off(event, fn)               → void
.close()                      → void

Events:
  "open"     ()        — handshake complete, connection ready
  "message"  (data)    — decrypted message received
  "close"    ()        — connection closed
  "error"    (err)     — error occurred
```

### `buildClient(options)` (build.js)

```
buildClient(options)  →  Promise<void>

options.serverKey?    string   — base64 server public key
                                 (default: OBSIDIAN_SERVER_KEY env var)
options.outDir?       string   — output directory (default: ./dist)
options.copyTo?       string   — additional copy destination
options.obfuscate?    boolean  — apply obfuscator (default: true)
```

---

## License

See [LICENSE](./LICENSE).
