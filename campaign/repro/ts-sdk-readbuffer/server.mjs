import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
const s = new McpServer({ name: "repro", version: "0.0.0" });
s.tool("echo", { text: z.string() }, async ({ text }) => ({ content: [{ type: "text", text: `len=${text.length}` }] }));
const t = new StdioServerTransport();
t.onerror = (e) => process.stderr.write(`[server onerror] ${e.message}\n`);
process.on("exit", (c) => process.stderr.write(`[server exit] code=${c}\n`));
await s.connect(t);
