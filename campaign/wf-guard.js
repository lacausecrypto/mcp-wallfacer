#!/usr/bin/env node
// Runs the MCP server as a child; kills it when our stdin closes (the docker
// client went away) or after WF_MAX_SECS, so no orphan container survives.
const { spawn } = require("child_process");
const [cmd, ...args] = process.argv.slice(2);
const child = spawn(cmd, args, { stdio: ["pipe", "inherit", "inherit"] });
const die = (code) => { try { child.kill("SIGKILL"); } catch {} process.exit(code); };
process.stdin.pipe(child.stdin);
process.stdin.on("end", () => setTimeout(() => die(0), 500));
child.stdin.on("error", () => {});
child.on("exit", (c, s) => process.exit(c ?? (s ? 137 : 1)));
setTimeout(() => die(124), Number(process.env.WF_MAX_SECS || 900) * 1000).unref();
