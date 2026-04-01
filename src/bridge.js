"use strict";

/**
 * Obsidiana Worker Bridge — Web Worker abstraction for Node.js and browsers.
 *
 * Provides a unified interface for spawning and communicating with Web Workers
 * across Node.js (using `worker_threads`) and browser environments.
 *
 * The bridge handles:
 * - Automatic environment detection (Node.js vs browser)
 * - Promise-based messaging with request/response correlation
 * - Event-based communication for server-initiated messages
 * - Clean worker termination
 *
 * @module worker-bridge
 * @private
 */

/**
 * Bridge class that abstracts Web Worker communication.
 *
 * Messages sent via `send()` return a Promise that resolves when the worker
 * responds with a matching `id`. Workers can also emit events (without an `id`)
 * that are handled by registered event listeners.
 *
 * @example
 * const bridge = new WorkerBridge();
 * await bridge.init();
 *
 * // Promise-based request/response
 * const result = await bridge.send('encrypt', { data: 'hello' });
 *
 * // Event-based communication
 * bridge.on('message', (msg) => console.log('Worker said:', msg));
 */
class WorkerBridge {
  constructor() {
    /** @private {Worker | null} */
    this._worker = null;
    /** @private {Map<number, { resolve: Function, reject: Function }>} */
    this._pending = new Map();
    /** @private {Map<string, Function[]>} */
    this._handlers = new Map();
    /** @private {number} */
    this._msgId = 0;
  }

  /**
   * Initializes the worker based on the runtime environment.
   *
   * In Node.js, uses `worker_threads.Worker` with the worker file.
   * In browsers, creates a Blob URL from the worker code and spawns a Worker.
   *
   * @returns {Promise<void>} Resolves when the worker is ready
   */
  init() {
    return new Promise((resolve, reject) => {
      const isNode = typeof process !== "undefined" && process.versions?.node;

      if (isNode) {
        // Node.js environment — use worker_threads
        const { Worker } = require("worker_threads");
        const path = require("path");
        this._worker = new Worker(path.join(__dirname, "worker.js"));
        this._worker.on("message", (msg) => this._onMessage(msg));
        this._worker.on("error", reject);
        this._worker.on("online", resolve);
      } else {
        // Browser environment — create Worker from Blob
        const workerCode = this._getWorkerCode();
        const blob = new Blob([workerCode], { type: "application/javascript" });
        const url = URL.createObjectURL(blob);
        this._worker = new Worker(url);
        URL.revokeObjectURL(url);
        this._worker.onmessage = (e) => this._onMessage(e.data);
        this._worker.onerror = reject;
        resolve();
      }
    });
  }

  /**
   * Returns the worker source code.
   *
   * This method is overridden by the build system to inject the actual
   * worker code. The default implementation returns an empty string.
   *
   * @returns {string} Worker source code
   * @private
   */
  _getWorkerCode() {
    return "";
  }

  /**
   * Sends a message to the worker and returns a Promise for the response.
   *
   * @param {string} type - Message type (e.g., 'encrypt', 'decrypt')
   * @param {object} [payload={}] - Message payload
   * @returns {Promise<any>} Resolves with worker's response
   */
  send(type, payload = {}) {
    return new Promise((resolve, reject) => {
      const id = ++this._msgId;
      this._pending.set(id, { resolve, reject });
      this._worker.postMessage({ id, type, payload });
    });
  }

  /**
   * Registers an event handler for worker messages without an id.
   *
   * @param {string} event - Event name (e.g., 'message', 'error')
   * @param {Function} fn - Callback function (msg) => void
   */
  on(event, fn) {
    if (!this._handlers.has(event)) this._handlers.set(event, []);
    this._handlers.get(event).push(fn);
  }

  /**
   * Terminates the worker and cleans up resources.
   */
  terminate() {
    this._worker?.terminate?.();
    this._worker = null;
  }

  /**
   * Handles incoming messages from the worker.
   *
   * Messages with an `id` are treated as responses to pending requests.
   * Messages without an `id` are treated as events and dispatched to handlers.
   *
   * @param {object} msg - Message from worker
   * @private
   */
  _onMessage(msg) {
    // Event-style message (no id) — dispatch to handlers
    if (!msg.id) {
      const fns = this._handlers.get(msg.type) ?? [];
      for (const fn of fns) fn(msg);
      return;
    }

    // Special case: WebSocket ready notification
    if (msg.type === "ws:ready") {
      const entry = this._pending.get(msg.id);
      if (entry) {
        this._pending.delete(msg.id);
        entry.resolve(msg);
      }
      return;
    }

    // Regular response to a pending request
    const entry = this._pending.get(msg.id);
    if (!entry) return;
    this._pending.delete(msg.id);

    if (msg.ok) {
      entry.resolve(msg.data ?? msg);
    } else {
      const err = new Error(msg.error ?? "Worker error");
      err.status = msg.status;
      err.body = msg.body;
      entry.reject(err);
    }
  }
}

module.exports = { WorkerBridge };
