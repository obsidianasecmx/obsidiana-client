# Obsidiana Client

A zero-runtime-dependency browser and Node.js client for [obsidiana-server](https://github.com/obsidianasecmx/obsidiana-server). Provides transparent end-to-end encryption for HTTP requests and WebSocket connections — all cryptographic operations run in a **Web Worker** (or `worker_threads` in Node.js) to keep the main thread completely unblocked.

**Compatible with modern browsers, Node.js ≥ 18, React, and React Native.**

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
  - [Output bundles](#output-bundles)
  - [Usage by target](#usage-by-target)
  - [Build options](#build-options)
  - [Key obfuscation](#key-obfuscation)
- [Architecture](#architecture)
- [API Reference](#api-reference)

---

## How it works

Every connection goes through a full cryptographic handshake before any application data is exchanged. This happens automatically inside the worker — your code just calls `connect()`.

```
Worker thread                               Server
─────────────                               ──────
GET /q  ──────────────────────────────────► Issue PoW challenge
        ◄─────────────────── CBOR({ d: blob + "." + sig })

Verify server ECDSA signature over challenge blob
  └─ throws immediately if key missing or signature invalid

Solve PoW: SHA-256(hash + nonce) with N leading zero bits
Generate ephemeral ECDSA keypair, sign challenge blob
Generate ephemeral ECDH P-256 keypair

POST /q ──── CBOR({ d: binary offer }) ───► Verify PoW + client sig + server key hash
             offer = ecdhKey | signerKey    Complete ECDH
                   | challengeId | nonce    Derive AES-GCM-256 key
                   | clientSig | serverKeyHash

        ◄──── CBOR(ECDH response) ─────────  Session established

                ◄──── Encrypted channel ────►

HTTP:  cipher.encrypt(body) → CBOR → fetch → CBOR → cipher.decrypt(response)
WS:    cipher.encrypt(msg)  → send  →  recv → cipher.decrypt(msg) → emit("message")
```

The server key is embedded into the bundle at build time and protected with multi-XOR obfuscation. No plaintext key string exists anywhere in the distributed bundle.

---

## Installation

```bash
npm install @obsidianasecmx/obsidiana-client
```

> `esbuild` and `javascript-obfuscator` are build-only dependencies used to generate the distributed bundles — they are never loaded at runtime.

---

## Server Key

The client **must** know the server's ECDSA public key to verify its identity during the handshake. Without it, `connect()` throws immediately — this is intentional and prevents MITM attacks.

The server's public key is generated once on first boot and stored at `.obsidiana/server.pub`:

```bash
cat .obsidiana/server.pub
# BKvf3...== (88-char base64 string)
```

**In Node.js (development):** the worker automatically reads `.obsidiana/server.pub` from the current working directory. No extra configuration is needed.

**In browsers and React Native (production):** the key must be embedded at build time via `buildClient({ serverKey: "..." })`. If `obsidiana-server` and `obsidiana-client` are sibling packages, the server automatically rebuilds the client bundles with the correct key embedded on every `app.listen()`.

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

// Terminate the worker when done
client.destroy();
```

### All HTTP methods

```js
// GET — encrypted body is Base64url-encoded and sent as ?_d=...
const data = await client.get("/api/products");

// POST
const order = await client.post("/api/orders", {
  productId: "abc",
  quantity: 2,
});

// PUT
const doc = await client.put("/api/documents/1", {
  title: "Updated",
  content: "...",
});

// PATCH
const patched = await client.patch("/api/users/5", { role: "admin" });

// DELETE — body is optional
await client.delete("/api/sessions/xyz");
await client.delete("/api/posts/1", { reason: "spam" });
```

> **GET and HEAD requests** are a special case: the encrypted CBOR payload is Base64url-encoded and appended as the `_d` query parameter (e.g., `/api/products?_d=...`) since browsers don't allow request bodies on GET requests.

### Error handling

Non-2xx responses throw an `Error` with extra properties:

```js
try {
  await client.post("/api/login", { user: "alice", pass: "wrong" });
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

// Performs PoW + ECDH handshake over WebSocket frames — resolves when ready
await ws.connect();

// Receive decrypted messages
ws.on("message", (data) => {
  console.log("Received:", data); // plain JS object, already decrypted
});

// Send an encrypted message
await ws.send({ event: "subscribe", topic: "notifications" });

// Close connection and terminate worker
ws.close();
```

### Events

```js
ws.on("open", () => console.log("Handshake complete, ready"));
ws.on("message", (data) => console.log("Decrypted message:", data));
ws.on("close", () => console.log("Connection closed"));
ws.on("error", (err) => console.error("Error:", err.message));

// Remove a specific handler
ws.off("message", myHandler);
```

The `"open"` event fires only after the full PoW + ECDH handshake completes. `connect()` resolves at the same time. If the handshake doesn't complete within 30 seconds, `connect()` rejects with a timeout error.

---

## Build system

The build script (`build.js`) produces four bundles — one for each target environment. It bundles the client with esbuild, injects the obfuscated worker code inline into the bridge, embeds the server public key with multi-XOR protection, and optionally applies a second pass of obfuscation to the final bundles.

```bash
# Run directly with the key from the environment
OBSIDIAN_SERVER_KEY="$(cat .obsidiana/server.pub)" node build.js

# Or call programmatically
const { buildClient } = require("@obsidianasecmx/obsidiana-client/build");

await buildClient({
  serverKey: fs.readFileSync(".obsidiana/server.pub", "utf8").trim(),
  outDir: "./public/js",
  obfuscate: true,
});
```

### Output bundles

Every build produces four files:

| File                       | Format                                | Target                            | Obfuscated                       |
| -------------------------- | ------------------------------------- | --------------------------------- | -------------------------------- |
| `obsidiana-client.js`      | ESM                                   | React / React Native              | ✅ (worker heavy + bundle light) |
| `obsidiana-client.min.js`  | ESM minified                          | React / React Native (production) | minify only                      |
| `obsidiana-client.umd.js`  | IIFE / UMD — global `ObsidianaClient` | Browser `<script>` tag            | ✅ (worker heavy + bundle light) |
| `obsidiana-client.node.js` | CommonJS                              | Node.js server-to-server          | ✅ (worker heavy + bundle light) |

All four bundles have the server public key baked in. They are written to `outDir` (default `./dist`) and optionally copied to `copyTo` (the server uses `copyTo: ".obsidiana/"` when auto-building).

### Usage by target

**React / React Native** — import the ES module build. The worker runs as an inline shim (`worker-inline.js`) on React Native since Blob URLs are not available, and as a real `Worker` with a Blob URL on web.

```jsx
import ObsidianaClient from "./obsidiana-client.js";
// or the minified build for production:
// import ObsidianaClient from './obsidiana-client.min.js'

const { createClient, createWSClient } = ObsidianaClient;

// HTTP
const client = createClient({ url: "https://api.example.com" });
await client.connect();
const data = await client.get("/api/hello");

// WebSocket
const ws = createWSClient({ url: "wss://api.example.com/live" });
await ws.connect();
ws.on("message", (data) => console.log(data));
```

**Browser via `<script>` tag** — use the UMD bundle. It exposes a global `ObsidianaClient` object.

```html
<script src="/js/obsidiana-client.umd.js"></script>
<script>
  const { createClient, createWSClient } = ObsidianaClient;

  (async () => {
    const client = createClient({ url: "https://api.example.com" });
    await client.connect();
    const data = await client.get("/api/hello");
    console.log(data);
  })();
</script>
```

**Node.js** — use the CommonJS bundle for server-to-server encrypted communication. The worker runs as a `worker_threads.Worker` and the server key is read from `.obsidiana/server.pub` automatically if not embedded at build time.

```js
const { createClient, createWSClient } = require("./obsidiana-client.node.js");
// or from the package directly (uses source files + auto-reads .obsidiana/server.pub)
const {
  createClient,
  createWSClient,
} = require("@obsidianasecmx/obsidiana-client");

const client = createClient({ url: "http://localhost:3000" });
await client.connect();
const result = await client.post("/api/process", { input: "data" });
client.destroy();
```

#### React example

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

#### WebSocket in React

```jsx
import { createWSClient } from "./obsidiana-client.js";
import { useEffect, useRef } from "react";

function useLiveConnection(url) {
  const wsRef = useRef(null);

  useEffect(() => {
    const ws = createWSClient({ url });
    wsRef.current = ws;
    ws.connect().then(() => {
      ws.on("message", (data) => console.log("Live update:", data));
    });
    return () => ws.close();
  }, [url]);

  return wsRef;
}
```

### Build options

```js
await buildClient({
  // Server's ECDSA public key (base64). Required for production.
  // Falls back to OBSIDIAN_SERVER_KEY environment variable.
  serverKey: "BKvf3...",

  // Output directory for the four bundles (default: ./dist)
  outDir: "./public/js",

  // Additional directory to copy all four bundles after building
  copyTo: "../server/.obsidiana",

  // Apply javascript-obfuscator to final bundles (default: true)
  // Set to false only for debugging — never ship with obfuscate: false
  obfuscate: true,
});
```

### Key obfuscation

The server key never appears as a plaintext string in any distributed bundle. The build system applies **multi-XOR splitting** in two stages:

**Stage 1 — Worker (heavy obfuscation):**

1. The key bytes are XORed with **3 independent random byte masks**, producing 3 encrypted parts and 3 masks (6 values total).
2. Each value is Base64-encoded and **fragmented** into random-sized string chunks (2–7 chars each), making static string search impossible.
3. A self-executing reconstruction function is injected inside the worker IIFE. It XORs all 6 values together, writes the result to `globalThis.__SERVER_KEY__`, then **nulls every variable** including the key slot.
4. The **key slot variable name** is randomly generated on every build (`_0xa3f8c2d1`, etc.) — no stable identifier to target with static analysis.
5. The entire worker code is then processed by `javascript-obfuscator` with:
   - Control flow flattening (75% threshold)
   - Dead code injection (40% threshold)
   - All strings moved to a shuffled, rotated, Base64-encoded string array
   - Hexadecimal identifier renaming
   - Object key transformation

**Stage 2 — Final bundle (light obfuscation):**

The outer bundle (which contains the obfuscated worker code as a string literal) gets a second, lighter pass: string array encoding, hexadecimal identifiers, and simplification. The `.min.js` build skips this second pass — it is minified only, so you can apply your own obfuscator if needed.

> This does not prevent a determined attacker from extracting the key with a debugger — the key must be present in memory at runtime. The goal is to make **automated static extraction impractical**.

---

## Architecture

```
Main thread
    │
    ├── ObsidianaClient         ← HTTP client API (thin wrapper)
    │       └── WorkerBridge    ← Promise-based postMessage bridge (id-tagged messages)
    │
    └── ObsidianaWSClient       ← WebSocket client API (thin wrapper)
            └── WorkerBridge    ← same bridge; event messages forwarded by type


Worker thread  (isolated, obfuscated in browser/RN bundles)
    │
    ├─ Browser / React:     Web Worker via Blob URL
    ├─ React Native:        worker-inline.js shim (same logic, same thread)
    └─ Node.js:             worker_threads.Worker
    │
    ├── doHandshake()           ← GET /q → verify sig → solve PoW → POST /q → ECDH
    │       ├── unpackChallenge() ← decode server challenge blob
    │       ├── solvePOW()        ← brute-force nonce, yields every BATCH hashes
    │       └── packOffer()       ← encode: ecdhKey|signerKey|cid|nonce|clientSig|serverKeyHash
    │
    ├── "connect"     → doHandshake → store cipher + sessionId (+ optional ratchet)
    ├── "request"     → cipher.encrypt(body) → fetch → cipher.decrypt(response)
    │                   GET/HEAD: body sent as ?_d=<base64url>
    ├── "ws:connect"  → open WebSocket → full PoW + ECDH handshake over WS frames
    ├── "ws:send"     → cipher.encrypt(data) → ws.send(CBOR bytes)
    └── "ws:close"    → ws.close()


WorkerBridge message protocol:
    Request  → { id, type, payload }
    Response → { id, ok, data }         (resolved/rejected by pending promise)
    Event    → { type, wsUrl, ... }     (no id — routed to registered handlers)
```

### Worker isolation

All secrets live **exclusively inside the worker thread** — the session key, session ID, and shared secret never cross back to the main thread. The main thread sends plaintext in and receives plaintext out. This means a compromised main thread context (e.g., an XSS payload) cannot extract the session key by inspecting JavaScript variables.

### Session lifecycle

```
createClient()   → creates WorkerBridge (no worker yet)
connect()        → starts worker → handshake → cipher stored in worker memory
request()        → bridge sends { id, type: "request", payload }
                   worker encrypts → fetch → decrypts → bridge resolves promise
destroy()        → worker.terminate() → all secrets gone from memory
```

Sessions are ephemeral. If `destroy()` is called and a new client is created, `connect()` must be called again to establish a fresh session with a new ECDH keypair.

---

## API Reference

### `createClient(options)`

```
createClient(options)  →  ObsidianaClient

options.url   string   — Base URL of the server, no trailing slash (required)
```

### `ObsidianaClient`

```
.connect()              → Promise<this>   — runs full handshake, resolves when ready
.get(path, body?)       → Promise<any>    — encrypted GET (body sent as ?_d=...)
.post(path, body?)      → Promise<any>
.put(path, body?)       → Promise<any>
.patch(path, body?)     → Promise<any>
.delete(path, body?)    → Promise<any>
.destroy()              → void            — terminates worker, clears all secrets
```

Errors thrown by request methods carry:

```
err.message   string   — "METHOD /path failed: STATUS"
err.status    number   — HTTP status code
err.body      any      — decrypted error body from server (if present)
```

### `createWSClient(options)`

```
createWSClient(options)  →  ObsidianaWSClient

options.url   string   — WebSocket URL, e.g. "wss://api.example.com/chat" (required)
```

### `ObsidianaWSClient`

```
.connect()              → Promise<this>   — resolves after handshake (30s timeout)
.send(data)             → Promise<void>   — encrypts and sends; requires connect() first
.on(event, fn)          → this
.off(event, fn)         → void
.close()                → void            — sends ws:close, terminates worker after 200ms

Events:
  "open"     ()      — handshake complete, ready to send/receive
  "message"  (data)  — decrypted incoming message
  "close"    ()      — connection closed
  "error"    (err)   — Error object
```

### `buildClient(options)` — `build.js`

```
buildClient(options)  →  Promise<void>

options.serverKey?   string    — base64 server public key
                                 (default: OBSIDIAN_SERVER_KEY env var)
options.outDir?      string    — output directory for bundles (default: ./dist)
options.copyTo?      string    — additional copy destination (e.g., ".obsidiana/")
options.obfuscate?   boolean   — apply javascript-obfuscator (default: true)
```

Outputs:

```
obsidiana-client.js       ESM, obfuscated        — React / React Native
obsidiana-client.min.js   ESM, minified only     — React / React Native (production)
obsidiana-client.umd.js   IIFE, obfuscated       — Browser <script> tag
obsidiana-client.node.js  CommonJS, obfuscated   — Node.js
```

---

## License

See [LICENSE](./LICENSE).
