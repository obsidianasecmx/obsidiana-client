"use strict";

/**
 * Obsidiana WebSocket Client — Encrypted WebSocket client with automatic handshake.
 *
 * Provides a WebSocket client that automatically handles the Obsidiana handshake
 * and encrypts all messages using AES‑GCM‑256. Cryptographic operations run in
 * a Web Worker (or worker_thread) to keep the main thread responsive.
 *
 * @public
 */

const { WorkerBridge } = require("./bridge");

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

    /** @private {string} */
    this._url = options.url;
    /** @private {WorkerBridge} */
    this._bridge = new WorkerBridge();
    /** @private {Map<string, Function[]>} */
    this._handlers = new Map();
    /** @private {boolean} */
    this._ready = false;
  }

  /**
   * Connects to the server and performs the full Obsidiana handshake.
   *
   * @returns {Promise<this>} Current instance for chaining
   * @throws {Error} If handshake times out (30 seconds) or verification fails
   */
  async connect() {
    await this._bridge.init();

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

    return new Promise((resolve, reject) => {
      const onOpen = () => {
        const handlers = this._handlers.get("open");
        if (handlers) {
          const idx = handlers.indexOf(onOpen);
          if (idx !== -1) handlers.splice(idx, 1);
        }
        resolve(this);
      };

      this.on("open", onOpen);

      const timeout = setTimeout(() => {
        const handlers = this._handlers.get("open");
        if (handlers) {
          const idx = handlers.indexOf(onOpen);
          if (idx !== -1) handlers.splice(idx, 1);
        }
        reject(new Error("WebSocket handshake timeout after 30 seconds"));
      }, 30000);

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
   * @param {any} data - JSON‑serializable data to encrypt and send
   * @returns {Promise<void>}
   * @throws {Error} If client is not connected
   */
  send(data) {
    this._assertConnected();
    return this._bridge.send("ws:send", { wsUrl: this._url, data });
  }

  /**
   * Registers an event handler.
   *
   * @param {string} event - Event name ("open", "message", "close", "error")
   * @param {Function} fn - Callback function
   * @returns {this}
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
   * @param {...any} args - Arguments to pass
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
