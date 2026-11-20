import { spawn } from "node:child_process";
const size = Number(process.argv[2]);
const p = spawn("node", ["server.mjs"], { stdio: ["pipe", "pipe", "inherit"] });
let out = ""; p.stdout.on("data", (d) => { out += d; });
const send = (m) => p.stdin.write(JSON.stringify(m) + "\n");
send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "d", version: "0" } } });
send({ jsonrpc: "2.0", method: "notifications/initialized" });
send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "echo", arguments: { text: "x".repeat(size) } } });
setTimeout(() => send({ jsonrpc: "2.0", id: 3, method: "ping" }), 1500);
setTimeout(() => {
  const ids = out.split("\n").filter(Boolean).map((l) => { const m = JSON.parse(l); return `id=${m.id} ${m.error ? "ERROR " + m.error.message : (m.result?.content?.[0]?.text ?? "ok")}`; });
  console.log(`payload=${size} responses: ${ids.join(" | ") || "(none)"} | alive=${p.exitCode === null}`);
  p.kill();
}, 3500);
