#!/usr/bin/env node

/**
 * RevClamp Enterprise — Model Context Protocol (MCP) stdio Bridge & CLI Client
 *
 * Thin, zero-dependency JSON-RPC 2.0 client bridging local MCP hosts (Claude Desktop,
 * Cursor, Windsurf, Cline) and terminal workflows to https://api.revclamp.com/api/mcp.
 *
 * Security & Resource Invariants:
 *   - Strict HTTPS origin allowlist (https://api.revclamp.com, https://revclamp.com)
 *   - Hard 10,000ms request deadline (AbortSignal.timeout(10000))
 *   - Hard 32,768-byte request/response payload cap
 */

import { fileURLToPath } from "node:url";

export const DEFAULT_MCP_ENDPOINT = "https://api.revclamp.com/api/mcp";
export const ALLOWED_MCP_ORIGINS = Object.freeze(
  new Set(["https://api.revclamp.com", "https://revclamp.com"])
);
export const MAX_PAYLOAD_BYTES = 32_768;
export const REQUEST_TIMEOUT_MS = 10_000;

/**
 * Validates that the target MCP endpoint uses an admitted HTTPS origin and path.
 *
 * @param {string} rawUrl
 * @returns {string}
 */
export function resolveValidatedMcpEndpoint(rawUrl = DEFAULT_MCP_ENDPOINT) {
  const trimmed = String(rawUrl || DEFAULT_MCP_ENDPOINT).trim();
  let parsed;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error("INVALID_MCP_ENDPOINT_URL");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("UNSAFE_MCP_ENDPOINT_PROTOCOL");
  }
  if (parsed.username || parsed.password) {
    throw new Error("UNSAFE_MCP_ENDPOINT_CREDENTIALS");
  }
  if (!ALLOWED_MCP_ORIGINS.has(parsed.origin)) {
    throw new Error(`UNTRUSTED_MCP_ENDPOINT_ORIGIN:${parsed.origin}`);
  }
  if (parsed.pathname !== "/api/mcp") {
    throw new Error("INVALID_MCP_ENDPOINT_PATH");
  }
  return parsed.toString();
}

/**
 * Reads an HTTP response body stream up to maxBytes, aborting immediately if exceeded.
 *
 * @param {Response|object} res
 * @param {number} [maxBytes]
 * @returns {Promise<string>}
 */
async function readBoundedResponseText(res, maxBytes = MAX_PAYLOAD_BYTES) {
  const contentLength = Number(
    res.headers?.get?.("content-length") ?? res.headers?.["content-length"]
  );
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    try {
      await res.body?.cancel?.();
    } catch {}
    throw new Error("UPSTREAM_RESPONSE_TOO_LARGE");
  }

  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    const chunks = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const buf = Buffer.isBuffer(value)
          ? value
          : typeof value === "string"
            ? Buffer.from(value, "utf8")
            : Buffer.from(value);
        totalBytes += buf.length;
        if (totalBytes > maxBytes) {
          try {
            await reader.cancel();
          } catch {}
          throw new Error("UPSTREAM_RESPONSE_TOO_LARGE");
        }
        chunks.push(buf);
      }
    } finally {
      try {
        reader.releaseLock?.();
      } catch {}
    }
    return Buffer.concat(chunks, totalBytes).toString("utf8");
  }

  if (res.body && typeof res.body[Symbol.asyncIterator] === "function") {
    const chunks = [];
    let totalBytes = 0;
    for await (const chunk of res.body) {
      const buf = Buffer.isBuffer(chunk)
        ? chunk
        : typeof chunk === "string"
          ? Buffer.from(chunk, "utf8")
          : Buffer.from(chunk);
      totalBytes += buf.length;
      if (totalBytes > maxBytes) {
        try {
          res.body.destroy?.();
        } catch {}
        throw new Error("UPSTREAM_RESPONSE_TOO_LARGE");
      }
      chunks.push(buf);
    }
    return Buffer.concat(chunks, totalBytes).toString("utf8");
  }

  const rawText = await res.text();
  if (Buffer.byteLength(rawText, "utf8") > maxBytes) {
    throw new Error("UPSTREAM_RESPONSE_TOO_LARGE");
  }
  return rawText;
}

/**
 * Forwards a single JSON-RPC 2.0 request object to the remote RevClamp MCP server.
 *
 * @param {object} rpcRequest
 * @param {object} [options]
 * @returns {Promise<object|null>}
 */
export async function forwardMcpJsonRpc(
  rpcRequest,
  {
    endpointUrl = process.env.REVCLAMP_MCP_URL || DEFAULT_MCP_ENDPOINT,
    apiKey = process.env.REVCLAMP_API_KEY || "",
    timeoutMs = REQUEST_TIMEOUT_MS,
    fetchImpl = globalThis.fetch,
  } = {}
) {
  if (!rpcRequest || typeof rpcRequest !== "object" || Array.isArray(rpcRequest)) {
    return {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32600, message: "Invalid JSON-RPC request object" },
    };
  }

  const isNotification = !Object.prototype.hasOwnProperty.call(rpcRequest, "id");
  if (
    rpcRequest.jsonrpc !== "2.0" ||
    typeof rpcRequest.method !== "string" ||
    rpcRequest.method.trim().length === 0
  ) {
    if (isNotification) {
      return null;
    }
    return {
      jsonrpc: "2.0",
      id: rpcRequest.id ?? null,
      error: { code: -32600, message: "Invalid JSON-RPC 2.0 request envelope" },
    };
  }

  if (rpcRequest.method === "notifications/initialized" && isNotification) {
    return null;
  }

  try {
    const validatedEndpoint = resolveValidatedMcpEndpoint(endpointUrl);
    const serialized = JSON.stringify(rpcRequest);
    if (Buffer.byteLength(serialized, "utf8") > MAX_PAYLOAD_BYTES) {
      if (isNotification) {
        return null;
      }
      return {
        jsonrpc: "2.0",
        id: rpcRequest.id ?? null,
        error: { code: -32600, message: "JSON-RPC request exceeds 32,768-byte limit" },
      };
    }

    const boundedTimeoutMs = Math.min(10_000, Math.max(100, Number(timeoutMs) || REQUEST_TIMEOUT_MS));
    const headers = {
      "content-type": "application/json",
      accept: "application/json",
    };
    const cleanKey = String(apiKey || "").trim();
    if (cleanKey) {
      headers.authorization = `Bearer ${cleanKey}`;
    }

    const res = await fetchImpl(validatedEndpoint, {
      method: "POST",
      headers,
      body: serialized,
      redirect: "error",
      signal: AbortSignal.timeout(boundedTimeoutMs),
    });

    if (res.status === 204 || isNotification) {
      try {
        await res.body?.cancel?.();
      } catch {}
      return null;
    }

    const httpOk = typeof res.ok === "boolean" ? res.ok : res.status >= 200 && res.status < 300;
    const rawText = await readBoundedResponseText(res, MAX_PAYLOAD_BYTES);

    let parsed;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      if (!httpOk) {
        return {
          jsonrpc: "2.0",
          id: rpcRequest.id ?? null,
          error: { code: -32603, message: `Upstream HTTP ${res.status}` },
        };
      }
      return {
        jsonrpc: "2.0",
        id: rpcRequest.id ?? null,
        error: { code: -32603, message: "Invalid JSON from upstream MCP endpoint" },
      };
    }

    const isPlainObj = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed);
    const hasResultProp = isPlainObj && Object.prototype.hasOwnProperty.call(parsed, "result");
    const hasErrorProp = isPlainObj && Object.prototype.hasOwnProperty.call(parsed, "error");
    const isValidErrorObj =
      hasErrorProp &&
      parsed.error !== null &&
      typeof parsed.error === "object" &&
      !Array.isArray(parsed.error) &&
      Number.isInteger(parsed.error.code) &&
      typeof parsed.error.message === "string" &&
      parsed.error.message.trim().length > 0;
    const isValidEnvelope =
      isPlainObj &&
      parsed.jsonrpc === "2.0" &&
      parsed.id === rpcRequest.id &&
      ((hasResultProp && !hasErrorProp) || (!hasResultProp && isValidErrorObj));

    if (!isValidEnvelope) {
      if (!httpOk) {
        return {
          jsonrpc: "2.0",
          id: rpcRequest.id ?? null,
          error: { code: -32603, message: `Upstream HTTP ${res.status}` },
        };
      }
      return {
        jsonrpc: "2.0",
        id: rpcRequest.id ?? null,
        error: { code: -32603, message: "Malformed JSON-RPC 2.0 response envelope from upstream" },
      };
    }

    if (!httpOk && !isValidErrorObj) {
      return {
        jsonrpc: "2.0",
        id: rpcRequest.id ?? null,
        error: { code: -32603, message: `Upstream HTTP ${res.status}` },
      };
    }

    return parsed;
  } catch (err) {
    if (isNotification) {
      return null;
    }
    if (err instanceof Error && err.message === "UPSTREAM_RESPONSE_TOO_LARGE") {
      return {
        jsonrpc: "2.0",
        id: rpcRequest.id ?? null,
        error: { code: -32603, message: "Upstream MCP response exceeded 32,768-byte ceiling" },
      };
    }
    return {
      jsonrpc: "2.0",
      id: rpcRequest.id ?? null,
      error: {
        code: -32603,
        message: `MCP transport error: ${err instanceof Error ? err.message : "UNKNOWN_ERROR"}`,
      },
    };
  }
}

/**
 * Starts the newline-delimited JSON-RPC 2.0 stdio loop for MCP desktop clients,
 * enforcing a hard 32,768-byte line buffer ceiling before parsing.
 */
export function startMcpStdioServer(options = {}) {
  const inputStream = options.inputStream || process.stdin;
  const outputStream = options.outputStream || process.stdout;
  let lineBuffer = Buffer.alloc(0);
  let discardingOversizedLine = false;
  let queue = Promise.resolve();

  const emitOversizedError = () => {
    outputStream.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: { code: -32600, message: "Payload exceeds 32,768 bytes" },
      })}\n`
    );
  };

  const processCompleteLine = async (rawLineBuffer) => {
    const trimmed = rawLineBuffer.toString("utf8").trim();
    if (!trimmed) return;
    if (Buffer.byteLength(trimmed, "utf8") > MAX_PAYLOAD_BYTES) {
      emitOversizedError();
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      outputStream.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        })}\n`
      );
      return;
    }
    const response = await forwardMcpJsonRpc(parsed, options);
    if (response !== null && response !== undefined) {
      outputStream.write(`${JSON.stringify(response)}\n`);
    }
  };

  inputStream.on("data", (chunk) => {
    let remaining = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), "utf8");
    while (remaining.length > 0) {
      const nlIdx = remaining.indexOf(0x0a);
      if (nlIdx === -1) {
        if (!discardingOversizedLine) {
          if (lineBuffer.length + remaining.length > MAX_PAYLOAD_BYTES) {
            discardingOversizedLine = true;
            lineBuffer = Buffer.alloc(0);
          } else {
            lineBuffer =
              lineBuffer.length === 0 ? remaining : Buffer.concat([lineBuffer, remaining]);
          }
        }
        break;
      }

      const rawSegment = remaining.subarray(0, nlIdx);
      const segment =
        rawSegment.length > 0 && rawSegment[rawSegment.length - 1] === 0x0d
          ? rawSegment.subarray(0, rawSegment.length - 1)
          : rawSegment;
      remaining = remaining.subarray(nlIdx + 1);

      if (discardingOversizedLine) {
        discardingOversizedLine = false;
        lineBuffer = Buffer.alloc(0);
        queue = queue.then(() => emitOversizedError());
      } else if (lineBuffer.length + segment.length > MAX_PAYLOAD_BYTES) {
        lineBuffer = Buffer.alloc(0);
        queue = queue.then(() => emitOversizedError());
      } else {
        const fullLine =
          lineBuffer.length === 0 ? segment : Buffer.concat([lineBuffer, segment]);
        lineBuffer = Buffer.alloc(0);
        queue = queue.then(() => processCompleteLine(fullLine));
      }
    }
  });

  inputStream.on("end", () => {
    if (discardingOversizedLine) {
      discardingOversizedLine = false;
      lineBuffer = Buffer.alloc(0);
      queue = queue.then(() => emitOversizedError());
    } else if (lineBuffer.length > 0) {
      const fullLine = lineBuffer;
      lineBuffer = Buffer.alloc(0);
      queue = queue.then(() => processCompleteLine(fullLine));
    }
  });
}

function printHelp() {
  console.log(
    [
      "RevClamp Enterprise MCP Server & CLI (https://revclamp.com)",
      "",
      "Usage:",
      "  revclamp-mcp                                         Start MCP stdio server (for Claude Desktop / Cursor)",
      "  revclamp-mcp --list-tools                            List all 5 exposed RevClamp MCP tools",
      "  revclamp-mcp --check-vat <VAT_ID> [sellerCC] [mode]  Validate an EU or XI VAT identifier via MCP (default mode: LIVE)",
      "  revclamp-mcp --call <tool_name> '<json_args>'        Invoke any RevClamp MCP tool directly",
      "",
      "Environment Variables:",
      "  REVCLAMP_API_KEY   Optional workspace key (rg_live_...). Omit for Stateless Sandbox mode.",
      "  REVCLAMP_MCP_URL   Optional override (must be https://api.revclamp.com/api/mcp or https://revclamp.com/api/mcp).",
    ].join("\n")
  );
}

export async function runCli(argv = process.argv.slice(2), options = {}) {
  if (argv.includes("--help") || argv.includes("-h")) {
    printHelp();
    return 0;
  }

  if (argv.includes("--list-tools")) {
    const res = await forwardMcpJsonRpc(
      { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} },
      options
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  const vatIdx = argv.indexOf("--check-vat");
  if (vatIdx !== -1) {
    const positional = [];
    let flagMode = "";
    for (let i = vatIdx + 1; i < argv.length; i += 1) {
      const token = String(argv[i] || "").trim();
      if (token.startsWith("--mode=")) {
        flagMode = token.slice("--mode=".length).trim().toUpperCase();
      } else if (!token.startsWith("-")) {
        positional.push(token);
      }
    }
    const buyerVatId = String(positional[0] || "").trim();
    const sellerCountry = String(positional[1] || "DE")
      .trim()
      .toUpperCase();
    const viesMode = String(flagMode || positional[2] || "LIVE")
      .trim()
      .toUpperCase();
    if (!buyerVatId) {
      console.error("Error: --check-vat requires a <VAT_ID> argument (e.g. DE123456789)");
      return 1;
    }
    const res = await forwardMcpJsonRpc(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "revclamp_validate_eu_vat_vies",
          arguments: { sellerCountry, buyerVatId, viesMode },
        },
      },
      options
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  const callIdx = argv.indexOf("--call");
  if (callIdx !== -1) {
    const toolName = String(argv[callIdx + 1] || "").trim();
    const rawArgs = String(argv[callIdx + 2] || "{}");
    if (!toolName) {
      console.error("Error: --call requires <tool_name> and optional '<json_args>'");
      return 1;
    }
    let parsedArgs;
    try {
      parsedArgs = JSON.parse(rawArgs);
    } catch (err) {
      console.error(`Error: invalid JSON arguments: ${err.message}`);
      return 1;
    }
    const res = await forwardMcpJsonRpc(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: toolName, arguments: parsedArgs },
      },
      options
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  startMcpStdioServer(options);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  runCli().then((code) => {
    if (process.argv.slice(2).length > 0) {
      process.exit(code);
    }
  });
}
