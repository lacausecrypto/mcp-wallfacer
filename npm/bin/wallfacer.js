#!/usr/bin/env node
// Tiny shim: locates the platform binary downloaded by
// `scripts/install.js` and forwards argv + stdio. Exits with the
// child's exit code so CI uses it as a drop-in replacement for the
// Cargo-built binary.

const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");

const BIN_DIR = path.join(__dirname);
const candidates =
  process.platform === "win32"
    ? ["wallfacer.exe"]
    : ["wallfacer"];

let binary = null;
for (const name of candidates) {
  const candidate = path.join(BIN_DIR, name);
  if (fs.existsSync(candidate)) {
    binary = candidate;
    break;
  }
}

if (!binary) {
  console.error(
    `[mcp-wallfacer] binary not found in ${BIN_DIR}. Run \`npm rebuild mcp-wallfacer\` ` +
      `to retrigger the postinstall download, or set WALLFACER_SKIP_INSTALL=0 if you opted out.`
  );
  process.exit(1);
}

// Pass through stdio so wallfacer's stdout (table / JSON / SARIF)
// reaches the parent process unchanged.
const child = spawn(binary, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: false,
});
child.on("exit", (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code === null ? 1 : code);
  }
});
child.on("error", (err) => {
  console.error(`[mcp-wallfacer] failed to spawn binary: ${err.message}`);
  process.exit(1);
});
