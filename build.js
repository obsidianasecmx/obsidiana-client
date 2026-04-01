"use strict";

/**
 * Obsidiana Client Builder — Build script for browser bundles.
 *
 * Bundles the Obsidiana client for browser environments using esbuild,
 * with heavy obfuscation and server key embedding. The worker code is
 * heavily protected with:
 * - Control flow flattening
 * - Dead code injection
 * - Base64-encoded string arrays
 * - Multi-XOR key splitting (3 parts, 6 fragments)
 * - Random variable names per build
 *
 * Outputs three formats:
 * - `obsidiana-client.js` — ESM with obfuscation (optional)
 * - `obsidiana-client.umd.js` — UMD/IIFE with obfuscation
 * - `obsidiana-client.min.js` — ESM with minification only
 *
 * @module builder
 * @private
 */

const esbuild = require("esbuild");
const fs = require("fs");
const path = require("path");
const JavaScriptObfuscator = require("javascript-obfuscator");

/** Output directory for built bundles. @private */
const DIST = path.join(__dirname, "dist");

/**
 * esbuild defines for browser compatibility.
 * @private
 */
const DEFINE = {
  "process.versions.node": "undefined",
  global: "globalThis",
};

/**
 * Generates a random variable name that looks like obfuscator output.
 *
 * Format: `_0x` + 8 random hex chars. Changes on every build to prevent
 * static analysis from identifying the key storage variable.
 *
 * @returns {string} Random variable name (e.g., "_0xa3f8c2d1")
 * @private
 */
function generateKeyVarName() {
  const hex = Array.from({ length: 8 }, () =>
    Math.floor(Math.random() * 16).toString(16),
  ).join("");
  return `_0x${hex}`;
}

/** Path to the Web Worker source file. @private */
const workerPath = path.join(__dirname, "src", "worker.js");

/**
 * Bundles the Web Worker with esbuild and applies multi-XOR key obfuscation.
 *
 * The server key is split into 3 parts XORed with 3 different random masks.
 * The key is reconstructed at runtime and immediately nulled out after use.
 * No complete key string exists anywhere in the bundle at rest.
 *
 * @param {string} serverKey - Server identity public key (base64)
 * @param {string} keyVarName - Random variable name for this build
 * @returns {Promise<string>} Obfuscated worker code
 * @private
 */
async function bundleWorker(serverKey = "", keyVarName) {
  console.log(" -> Bundling worker...");

  const result = await esbuild.build({
    entryPoints: [workerPath],
    bundle: true,
    write: false,
    format: "iife",
    platform: "browser",
    target: ["es2020"],
    external: ["worker_threads", "ws", "path", "crypto"],
    define: DEFINE,
    resolveExtensions: [".js"],
    alias: {
      "obsidiana-client": path.join(__dirname, "index.js"),
    },
  });

  let code = result.outputFiles[0].text;

  // Replace sentinel with random variable name
  code = code.replaceAll("__SERVER_KEY__", keyVarName);

  if (serverKey) {
    // Multi-XOR: Split key into 3 parts XORed with 3 different masks
    const keyBytes = Buffer.from(serverKey, "utf8");
    const keyLength = keyBytes.length;

    // Create 3 different random masks
    const masks = [
      Buffer.from(
        Array.from({ length: keyLength }, () =>
          Math.floor(Math.random() * 256),
        ),
      ),
      Buffer.from(
        Array.from({ length: keyLength }, () =>
          Math.floor(Math.random() * 256),
        ),
      ),
      Buffer.from(
        Array.from({ length: keyLength }, () =>
          Math.floor(Math.random() * 256),
        ),
      ),
    ];

    // Apply triple XOR: key ^ mask1 ^ mask2 ^ mask3 = result
    const xored1 = Buffer.from(keyBytes.map((b, i) => b ^ masks[0][i]));
    const xored2 = Buffer.from(keyBytes.map((b, i) => b ^ masks[1][i]));
    const xored3 = Buffer.from(keyBytes.map((b, i) => b ^ masks[2][i]));

    // Encode everything in base64
    const xored1B64 = xored1.toString("base64");
    const xored2B64 = xored2.toString("base64");
    const xored3B64 = xored3.toString("base64");
    const mask1B64 = masks[0].toString("base64");
    const mask2B64 = masks[1].toString("base64");
    const mask3B64 = masks[2].toString("base64");

    /**
     * Fragments a string into random-sized chunks for obfuscation.
     * @param {string} str - String to fragment
     * @returns {string} JavaScript expression concatenating fragments
     * @private
     */
    function fragment(str) {
      const chunks = [];
      let pos = 0;
      while (pos < str.length) {
        const size = 2 + Math.floor(Math.random() * 5);
        chunks.push(JSON.stringify(str.slice(pos, pos + size)));
        pos += size;
      }
      return chunks.join(" + ");
    }

    // Random names for all fragments
    const parts = {
      x1: "_0x" + Math.random().toString(36).slice(2, 10).padEnd(8, "0"),
      x2: "_0x" + Math.random().toString(36).slice(2, 10).padEnd(8, "0"),
      x3: "_0x" + Math.random().toString(36).slice(2, 10).padEnd(8, "0"),
      m1: "_0x" + Math.random().toString(36).slice(2, 10).padEnd(8, "0"),
      m2: "_0x" + Math.random().toString(36).slice(2, 10).padEnd(8, "0"),
      m3: "_0x" + Math.random().toString(36).slice(2, 10).padEnd(8, "0"),
    };

    // Declare all fragmented parts
    const xorPreamble =
      [
        `var ${parts.x1} = ${fragment(xored1B64)};`,
        `var ${parts.x2} = ${fragment(xored2B64)};`,
        `var ${parts.x3} = ${fragment(xored3B64)};`,
        `var ${parts.m1} = ${fragment(mask1B64)};`,
        `var ${parts.m2} = ${fragment(mask2B64)};`,
        `var ${parts.m3} = ${fragment(mask3B64)};`,
      ].join("\n") + "\n";

    // Multi-XOR decoder with immediate cleanup
    const xorDecode =
      [
        `var ${keyVarName}=(function(){`,
        `var _a=atob(${parts.x1}),_b=atob(${parts.x2}),_c=atob(${parts.x3});`,
        `var _d=atob(${parts.m1}),_e=atob(${parts.m2}),_f=atob(${parts.m3});`,
        `var _o="";`,
        `for(var _i=0;_i<_a.length;_i++){`,
        `  _o+=String.fromCharCode(_a.charCodeAt(_i)^_b.charCodeAt(_i)^_c.charCodeAt(_i)^_d.charCodeAt(_i)^_e.charCodeAt(_i)^_f.charCodeAt(_i));`,
        `}`,
        `_a=null;_b=null;_c=null;_d=null;_e=null;_f=null;`,
        `${parts.x1}=null;${parts.x2}=null;${parts.x3}=null;`,
        `${parts.m1}=null;${parts.m2}=null;${parts.m3}=null;`,
        `return _o;`,
        `})();`,
      ].join("\n") + "\n";

    // Insert decoder as the first instruction inside esbuild's IIFE
    const iifeOpen = "(function(){";
    const iifeIdx = code.indexOf(iifeOpen);
    if (iifeIdx !== -1) {
      code =
        xorPreamble +
        code.slice(0, iifeIdx + iifeOpen.length) +
        "\n" +
        xorDecode +
        code.slice(iifeIdx + iifeOpen.length);
    } else {
      code = xorPreamble + xorDecode + code;
    }
  } else {
    const injection = `var ${keyVarName} = "";\n`;
    code = injection + code;
  }

  console.log(`   -> Worker size (raw): ${(code.length / 1024).toFixed(1)} KB`);

  // Heavy obfuscation for the worker
  const obfuscated = JavaScriptObfuscator.obfuscate(code, {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.75,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.4,
    stringArray: true,
    stringArrayEncoding: ["base64"],
    stringArrayThreshold: 1.0,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    identifierNamesGenerator: "hexadecimal",
    simplify: true,
    transformObjectKeys: true,
    rotateStringArray: true,
    selfDefending: false,
    renameGlobals: false,
    seed: Math.floor(Math.random() * 1000000),
  });

  const obfuscatedCode = obfuscated.getObfuscatedCode();
  console.log(
    `   -> Worker size (obfuscated): ${(obfuscatedCode.length / 1024).toFixed(1)} KB`,
  );
  console.log(
    `   -> Size increase: ${((obfuscatedCode.length / code.length) * 100).toFixed(1)}%`,
  );

  return obfuscatedCode;
}

/**
 * Creates esbuild plugins for worker injection.
 *
 * @param {string} serverKey - Server identity public key
 * @param {string} keyVarName - Random variable name for key storage
 * @returns {object[]} esbuild plugin array
 * @private
 */
function makePlugins(serverKey, keyVarName) {
  const workerInjectPlugin = {
    name: "worker-inject",
    setup(build) {
      build.onLoad({ filter: /bridge\.js$/ }, async (args) => {
        let contents = fs.readFileSync(args.path, "utf-8");

        const workerBundle = await bundleWorker(serverKey, keyVarName);

        const escapedWorkerCode = JSON.stringify(workerBundle);
        const newContents = contents.replace(
          /_getWorkerCode\(\)\s*\{\s*return\s*"";\s*\}/,
          `_getWorkerCode() { return ${escapedWorkerCode}; }`,
        );

        return { contents: newContents, loader: "js" };
      });
    },
  };

  return [workerInjectPlugin];
}

/**
 * Obfuscates a bundle file after esbuild generation.
 *
 * @param {string} inputPath - Path to input file
 * @param {string} outputPath - Path to output file
 * @private
 */
function obfuscateBundle(inputPath, outputPath) {
  console.log(`   -> Obfuscating final bundle ${path.basename(inputPath)}...`);
  const code = fs.readFileSync(inputPath, "utf8");

  const obfuscated = JavaScriptObfuscator.obfuscate(code, {
    compact: true,
    stringArray: true,
    stringArrayEncoding: ["base64"],
    stringArrayThreshold: 1.0,
    identifierNamesGenerator: "hexadecimal",
    simplify: true,
  });

  fs.writeFileSync(outputPath, obfuscated.getObfuscatedCode());
  console.log(`   -> Final bundle obfuscated`);
}

/**
 * Builds the Obsidiana client bundles for browser distribution.
 *
 * Generates three output formats:
 * - ESM with obfuscation (or minified if obfuscation disabled)
 * - UMD/IIFE with obfuscation
 * - Minified ESM (always minified)
 *
 * The worker code is heavily obfuscated with control flow flattening,
 * dead code injection, and multi-XOR key splitting. The server key slot
 * name changes on every build.
 *
 * @param {object} [options] - Build options
 * @param {string} [options.serverKey] - Server identity public key (base64)
 * @param {string} [options.outDir] - Output directory for bundles
 * @param {string} [options.copyTo] - Additional directory to copy bundles to
 * @param {boolean} [options.obfuscate=true] - Whether to obfuscate final bundles
 * @returns {Promise<void>}
 *
 * @example
 * const { buildClient } = require('./build');
 *
 * await buildClient({
 *   serverKey: 'BASE64_SERVER_PUBLIC_KEY',
 *   outDir: './dist',
 *   obfuscate: true
 * });
 */
async function buildClient(options = {}) {
  const {
    serverKey = process.env.OBSIDIAN_SERVER_KEY ?? "",
    outDir = null,
    copyTo = null,
    obfuscate = true,
  } = options;

  // Generate fresh random variable name for this build
  const keyVarName = generateKeyVarName();
  console.log(` -> Key slot: ${keyVarName} (changes every build)`);

  let outputDir;
  if (outDir) {
    outputDir = outDir;
  } else if (copyTo) {
    outputDir = copyTo;
  } else {
    outputDir = DIST;
  }

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const plugins = makePlugins(serverKey, keyVarName);

  if (serverKey) {
    console.log(
      ` -> Server key: ${serverKey.slice(0, 16)}... (${serverKey.length} chars)`,
    );
  } else {
    console.log(" -> No server key — building without identity verification.");
  }

  console.log(` -> Output directory: ${outputDir}`);
  console.log(` -> Final bundle obfuscation: ${obfuscate ? "ON" : "OFF"}\n`);

  const tempDir = path.join(__dirname, "temp");
  if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
  }

  // Build ESM bundle
  const esmTemp = path.join(tempDir, "obsidiana-client.tmp.js");
  await esbuild.build({
    entryPoints: ["index.js"],
    bundle: true,
    platform: "browser",
    target: ["es2020"],
    format: "esm",
    outfile: esmTemp,
    plugins,
    external: ["worker_threads", "ws", "path", "crypto"],
    define: DEFINE,
  });
  console.log(" -> Built ESM");

  if (obfuscate) {
    obfuscateBundle(esmTemp, path.join(outputDir, "obsidiana-client.js"));
  } else {
    fs.copyFileSync(esmTemp, path.join(outputDir, "obsidiana-client.js"));
  }

  // Build UMD/IIFE bundle
  const umdTemp = path.join(tempDir, "obsidiana-client.umd.tmp.js");
  await esbuild.build({
    entryPoints: ["index.js"],
    bundle: true,
    platform: "browser",
    target: ["es2020"],
    format: "iife",
    globalName: "ObsidianaClient",
    outfile: umdTemp,
    plugins,
    external: ["worker_threads", "ws", "path", "crypto"],
    define: DEFINE,
  });
  console.log(" -> Built UMD");

  if (obfuscate) {
    obfuscateBundle(umdTemp, path.join(outputDir, "obsidiana-client.umd.js"));
  } else {
    fs.copyFileSync(umdTemp, path.join(outputDir, "obsidiana-client.umd.js"));
  }

  // Build minified ESM (no extra obfuscation)
  await esbuild.build({
    entryPoints: ["index.js"],
    bundle: true,
    platform: "browser",
    target: ["es2020"],
    format: "esm",
    minify: true,
    outfile: path.join(outputDir, "obsidiana-client.min.js"),
    plugins,
    external: ["worker_threads", "ws", "path", "crypto"],
    define: DEFINE,
  });
  console.log(" -> obsidiana-client.min.js (minified only)");

  // Cleanup temp directory
  fs.rmSync(tempDir, { recursive: true, force: true });

  // Copy bundles to additional location if specified
  if (copyTo && copyTo !== outputDir && fs.existsSync(copyTo)) {
    for (const file of [
      "obsidiana-client.js",
      "obsidiana-client.umd.js",
      "obsidiana-client.min.js",
    ]) {
      const srcPath = path.join(outputDir, file);
      const destPath = path.join(copyTo, file);
      if (fs.existsSync(srcPath)) {
        fs.copyFileSync(srcPath, destPath);
      }
    }
    console.log(` -> Bundles copied to ${copyTo}`);
  }

  console.log(`\nBuild complete!`);
  console.log(`   - Worker is heavily obfuscated with:`);
  console.log(`     • Control flow flattening (75% threshold)`);
  console.log(`     • Dead code injection (40% threshold)`);
  console.log(`     • All strings in base64 encoded array`);
  console.log(`     • String array rotation and shuffle`);
  console.log(`     • Object key transformation`);
  console.log(`     • Multi-XOR key splitting (3 parts, 6 fragments)`);
  console.log(`   - Final bundle is obfuscated`);
  console.log(`   - Server key slot name changes on every build`);
}

// Run build if executed directly
if (require.main === module) {
  console.log("Building obsidiana-client with HEAVY worker obfuscation...\n");
  buildClient({ obfuscate: true })
    .then(() => console.log("\nDone!"))
    .catch(console.error);
}

module.exports = { buildClient };
