#!/usr/bin/env node
import readline from "node:readline";

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let req;
  try { req = JSON.parse(trimmed); } catch { return; }
  if (req.id === undefined || req.id === null) return;
  let result = {};
  if (req.method === "initialize") {
    result = {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {}, prompts: {}, resources: {} },
      serverInfo: { name: "deprecated-legacy-sandbox", version: "1.0.1" }
    };
  } else if (req.method === "tools/list") {
    result = {
      tools: [{
        name: "legacy_sandbox_noop",
        description: "No-op diagnostic stub for archived sandbox workspace.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false }
      }]
    };
  } else if (req.method === "prompts/list") {
    result = { prompts: [] };
  } else if (req.method === "resources/list") {
    result = { resources: [] };
  } else if (req.method === "resources/templates/list") {
    result = { resourceTemplates: [] };
  } else if (req.method === "tools/call") {
    result = { content: [{ type: "text", text: "ok" }] };
  }
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: req.id, result }) + "\n");
});
