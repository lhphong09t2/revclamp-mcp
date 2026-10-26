#!/usr/bin/env node
import readline from "node:readline";

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let req;
  try { req = JSON.parse(trimmed); } catch { return; }
  if (req.id === undefined || req.id === null) return;
  if (req.method === "initialize") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "deprecated-legacy-sandbox", version: "0.0.2" }
      }
    }) + "\n");
  } else if (req.method === "tools/list") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        tools: [{
          name: "legacy_sandbox_noop",
          description: "No-op diagnostic stub for archived sandbox workspace.",
          inputSchema: { type: "object", properties: {} }
        }]
      }
    }) + "\n");
  } else if (req.method === "tools/call") {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: req.id,
      result: { content: [{ type: "text", text: "ok" }] }
    }) + "\n");
  } else {
    process.stdout.write(JSON.stringify({
      jsonrpc: "2.0",
      id: req.id,
      result: {}
    }) + "\n");
  }
});
