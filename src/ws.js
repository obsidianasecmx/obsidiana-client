"use strict";

/**
 * Obsidiana WebSocket Client — Encrypted WebSocket client with automatic handshake.
 *
 * Provides a WebSocket client that automatically handles the Obsidiana handshake
 * and encrypts all messages using AES-GCM-256. The client runs cryptographic
 * operations in a Web Worker (or worker_thread) to keep the main thread responsive.
 *
 * All messages sent via `send()` are automatically encrypted. Received messages
 * are decrypted and emitted as `message` events. The handshake includes:
 * - PoW challenge solving
 * - Server identity verification (ECDSA)
 * - ECDH key exchange
 * - AES-GCM-256 session key derivation
 *
 * @module ws-client
 * @public
 *
 * @example
 * const { createWSClient } = require('@obsidianasecmx/obsidiana-server');
 *
 * const ws = createWSClient({ url: 'wss://api.example.com/live' });
 * await ws.connect();
 *
 * ws.on('message', (data) => {
 *   console.log('Received:', data);
 * });
 *
 * await ws.send({ event: 'ping' });
 * ws.close();
 */

const { WorkerBridge } = require("./bridge");

/**
 * Encrypted WebSocket client with automatic handshake and message encryption.
 *
 * @example
 * const ws = new ObsidianaWSClient({ url: 'wss://api.example.com/live' });
 * await ws.connect();
 *
 * ws.on('message', (data) => console.log(data));
 * ws.send({ hello: 'world' });
 * ws.close();
 */
class ObsidianaWSClient {
  /**
   * Creates a new Obsidiana WebSocket client.
   *
   * @param {object} options - Client configuration
   * @param {string} options.url - WebSocket URL (e.g., 'wss://api.example.com/live')
   * @throws {Error} If `url` is not provided
   */
  constructor(options = {}) {
    if (!options.url)
      throw new Error("[obsidiana-client/ws] options.url is required");

    /** @private {string} WebSocket URL */
    this._url = options.url;

    /** @private {WorkerBridge} Bridge to the crypto worker */
    this._bridge = new WorkerBridge();

    /** @private {Map<string, Function[]>} Event handlers */
    this._handlers = new Map();

    /** @private {boolean} Whether the handshake is complete */
    this._ready = false;
  }

  /**
   * Connects to the server and performs the full Obsidiana handshake.
   *
   * Steps:
   * 1. Initializes the Web Worker
   * 2. Sends connection request with WebSocket URL
   * 3. Worker handles PoW, server verification, and ECDH handshake
   * 4. Session key derived and stored in worker
   *
   * The promise resolves when the handshake completes successfully.
   * If handshake takes longer than 30 seconds, the promise rejects.
   *
   * @returns {Promise<this>} Current instance for method chaining
   * @throws {Error} If handshake times out or verification fails
   */
  async connect() {
    await this._bridge.init();

    // Forward messages from worker
    this._bridge.on("ws:message", (msg) => {
      if (msg.wsUrl !== this._url) return;
      this._emit("message", msg.data);
    });

    this._bridge.on("ws:ready", (msg) => {
      if (msg.wsUrl !== this._url) return;
      this._ready = true;
      this._emit("open");
    });

    this._bridge.on("ws:close", (msg) => {
      if (msg.wsUrl !== this._url) return;
      this._ready = false;
      this._emit("close");
    });

    this._bridge.on("ws:error", (msg) => {
      if (msg.wsUrl !== this._url) return;
      this._emit("error", new Error(msg.error));
    });

    await this._bridge.send("ws:connect", { wsUrl: this._url });

    // Wait for handshake to complete
    return new Promise((resolve, reject) => {
      const onOpen = () => {
        // Remove the handler to avoid memory leaks
        const handlers = this._handlers.get("open");
        if (handlers) {
          const idx = handlers.indexOf(onOpen);
          if (idx !== -1) handlers.splice(idx, 1);
        }
        resolve(this);
      };

      this.on("open", onOpen);

      // Handshake timeout (30 seconds)
      const timeout = setTimeout(() => {
        const handlers = this._handlers.get("open");
        if (handlers) {
          const idx = handlers.indexOf(onOpen);
          if (idx !== -1) handlers.splice(idx, 1);
        }
        reject(new Error("WebSocket handshake timeout after 30 seconds"));
      }, 30000);

      // Store original resolve to clear timeout
      const originalResolve = resolve;
      resolve = (value) => {
        clearTimeout(timeout);
        originalResolve(value);
      };
    });
  }

  /**
   * Sends an encrypted message over the WebSocket.
   *
   * The data is automatically encrypted with AES-GCM-256 using the session key
   * established during handshake. The method returns a Promise that resolves
   * when the message has been sent (not when acknowledged by the server).
   *
   * @param {any} data - JSON-serializable data to encrypt and send
   * @returns {Promise<void>} Resolves when message is sent
   * @throws {Error} If client is not connected
   */
  send(data) {
    this._assertConnected();
    return this._bridge.send("ws:send", { wsUrl: this._url, data });
  }

  /**
   * Registers an event handler.
   *
   * Supported events:
   * - `open` — emitted when the handshake completes and the connection is ready
   * - `message` — emitted when a decrypted message is received
   * - `close` — emitted when the connection is closed
   * - `error` — emitted when an error occurs
   *
   * @param {string} event - Event name
   * @param {Function} fn - Callback function
   * @returns {this} Current instance for method chaining
   */
  on(event, fn) {
    if (!this._handlers.has(event)) this._handlers.set(event, []);
    this._handlers.get(event).push(fn);
    return this;
  }

  /**
   * Removes an event handler.
   *
   * @param {string} event - Event name
   * @param {Function} fn - Callback function to remove
   */
  off(event, fn) {
    if (!this._handlers.has(event)) return;
    const fns = this._handlers.get(event);
    const index = fns.indexOf(fn);
    if (index !== -1) fns.splice(index, 1);
  }

  /**
   * Closes the WebSocket connection and terminates the worker.
   *
   * If the connection is open, it sends a close frame before terminating.
   * The worker is terminated 200ms after the close frame to allow for
   * any final messages to be processed.
   */
  close() {
    if (this._ready) {
      this._bridge
        .send("ws:close", { wsUrl: this._url })
        .catch(() => {})
        .finally(() => {
          setTimeout(() => this._bridge.terminate(), 200);
        });
    } else {
      this._bridge.terminate();
    }
    this._ready = false;
  }

  /**
   * Emits an event to all registered handlers.
   *
   * @param {string} event - Event name
   * @param {...any} args - Arguments to pass to handlers
   * @private
   */
  _emit(event, ...args) {
    const fns = this._handlers.get(event) ?? [];
    for (const fn of fns) fn(...args);
  }

  /**
   * Asserts that the client is connected.
   *
   * @throws {Error} If `connect()` has not been called or handshake failed
   * @private
   */
  _assertConnected() {
    if (!this._ready) {
      throw new Error(
        "[obsidiana-client/ws] Not connected. Call connect() first.",
      );
    }
  }
}

module.exports = { ObsidianaWSClient };
