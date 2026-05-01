#!/usr/bin/env node
// postinstall: download the GitHub release binary matching the host
// platform/arch into `bin/wallfacer-bin`, so the CLI shim in
// `bin/wallfacer.js` can `execFileSync` it.
//
// Skips silently when WALLFACER_SKIP_INSTALL=1 — useful for CI that
// vendors the binary itself, or for `npm pack` validation.

const fs = require("fs");
const path = require("path");
const { promisify } = require("util");
const { pipeline } = require("stream");
const https = require("https");
const zlib = require("zlib");
const { execFileSync } = require("child_process");

const pipe = promisify(pipeline);

const PKG = require(path.join(__dirname, "..", "package.json"));
const VERSION = process.env.WALLFACER_VERSION || `v${PKG.version}`;
const REPO = "lacausecrypto/mcp-wallfacer";
const BIN_DIR = path.join(__dirname, "..", "bin");

function targetTriple() {
  const { platform, arch } = process;
  const map = {
    "linux:x64": "x86_64-unknown-linux-gnu",
    "linux:arm64": "aarch64-unknown-linux-gnu",
    "darwin:x64": "x86_64-apple-darwin",
    "darwin:arm64": "aarch64-apple-darwin",
    "win32:x64": "x86_64-pc-windows-msvc",
  };
  const key = `${platform}:${arch}`;
  const triple = map[key];
  if (!triple) {
    throw new Error(
      `unsupported platform/arch \`${key}\`. Supported: ${Object.keys(map).join(", ")}.\n` +
        `Build from source instead: \`cargo install mcp-wallfacer\`.`
    );
  }
  return triple;
}

function archiveExtension(triple) {
  return triple.includes("windows") ? "zip" : "tar.gz";
}

function archiveName(triple) {
  return `wallfacer-${triple}.${archiveExtension(triple)}`;
}

function binaryName(triple) {
  return triple.includes("windows") ? "wallfacer.exe" : "wallfacer";
}

function get(url, max = 8) {
  return new Promise((resolve, reject) => {
    if (max <= 0) return reject(new Error("too many redirects"));
    https
      .get(url, { headers: { "User-Agent": "mcp-wallfacer-installer" } }, (res) => {
        if (
          res.statusCode &&
          res.statusCode >= 300 &&
          res.statusCode < 400 &&
          res.headers.location
        ) {
          res.resume();
          return resolve(get(res.headers.location, max - 1));
        }
        if (res.statusCode !== 200) {
          res.resume();
          return reject(
            new Error(`HTTP ${res.statusCode} for ${url}: ${res.statusMessage}`)
          );
        }
        resolve(res);
      })
      .on("error", reject);
  });
}

async function download(url, dest) {
  const res = await get(url);
  await pipe(res, fs.createWriteStream(dest));
}

function extractTarGz(archivePath, destDir) {
  // We rely on the platform `tar` (GNU on Linux, BSD on macOS, both
  // handle gzip transparently). Avoiding a JS tar dep keeps the
  // postinstall snappy and works inside Alpine / minimal images.
  execFileSync("tar", ["-xzf", archivePath, "-C", destDir], {
    stdio: "inherit",
  });
}

function extractZip(archivePath, destDir) {
  // Windows: PowerShell ships everywhere we care about.
  if (process.platform === "win32") {
    execFileSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-Command",
        `Expand-Archive -Force -Path "${archivePath}" -DestinationPath "${destDir}"`,
      ],
      { stdio: "inherit" }
    );
  } else {
    execFileSync("unzip", ["-o", archivePath, "-d", destDir], {
      stdio: "inherit",
    });
  }
}

async function main() {
  if (process.env.WALLFACER_SKIP_INSTALL === "1") {
    console.error(
      "[mcp-wallfacer] WALLFACER_SKIP_INSTALL=1 — skipping binary download."
    );
    return;
  }

  const triple = targetTriple();
  const archive = archiveName(triple);
  const binary = binaryName(triple);
  const url = `https://github.com/${REPO}/releases/download/${VERSION}/${archive}`;

  fs.mkdirSync(BIN_DIR, { recursive: true });
  const archivePath = path.join(BIN_DIR, archive);
  const binaryPath = path.join(BIN_DIR, binary);

  console.error(`[mcp-wallfacer] downloading ${archive} from ${url}`);
  await download(url, archivePath);

  console.error(`[mcp-wallfacer] extracting`);
  if (archive.endsWith(".zip")) {
    extractZip(archivePath, BIN_DIR);
  } else {
    extractTarGz(archivePath, BIN_DIR);
  }
  fs.unlinkSync(archivePath);

  if (!fs.existsSync(binaryPath)) {
    throw new Error(`expected ${binary} after extraction; not found in ${BIN_DIR}`);
  }
  if (process.platform !== "win32") {
    fs.chmodSync(binaryPath, 0o755);
  }
  console.error(`[mcp-wallfacer] installed ${binary} (${VERSION})`);
}

main().catch((err) => {
  console.error(`[mcp-wallfacer] install failed: ${err.message}`);
  console.error(
    `[mcp-wallfacer] you can build from source instead: \`cargo install mcp-wallfacer\`.`
  );
  process.exit(1);
});
