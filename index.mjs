#!/usr/bin/env node

/**
 * RevClamp Enterprise — Standalone Open-Source MCP Server, CLI & Optional Cloud Bridge
 *
 * Self-contained, zero-dependency JSON-RPC 2.0 Model Context Protocol (MCP) Server
 * implementing 9 deterministic B2B FinOps, Stripe 2025-03-31.basil, Visa CE 3.0,
 * EU/XI VIES VAT, Shopify Plus B2B Net-15/30/60, and Webhook Security tools locally
 * in-process (local_engine.mjs), with optional hosted workspace sync over HTTPS
 * when REVCLAMP_API_KEY is configured.
 *
 * Security & Resource Invariants:
 *   - 100% local in-process execution by default (zero network or API key required)
 *   - Strict HTTPS origin allowlist (https://api.revclamp.com, https://revclamp.com)
 *   - Hard 10,000ms request deadline (AbortSignal.timeout(10000))
 *   - Hard 32,768-byte request/response payload cap
 */

import { fileURLToPath } from "node:url";
import {
  LOCAL_MCP_TOOLS,
  MCP_PROTOCOL_VERSION,
  normalizeMcpToolArgs,
  executeLocalMcpTool,
  executeLocalMcpJsonRpc,
} from "./local_engine.mjs";

export {
  LOCAL_MCP_TOOLS,
  MCP_PROTOCOL_VERSION,
  normalizeMcpToolArgs,
  executeLocalMcpTool,
  executeLocalMcpJsonRpc,
};

export const PACKAGE_VERSION = "1.20.8";
export const DEFAULT_MCP_ENDPOINT = "https://api.revclamp.com/api/mcp";
export const ALLOWED_MCP_ORIGINS = Object.freeze(
  new Set(["https://api.revclamp.com", "https://revclamp.com"])
);
export const MAX_PAYLOAD_BYTES = 32_768;
export const MAX_STDIO_LINE_BYTES = MAX_PAYLOAD_BYTES;
export const REQUEST_TIMEOUT_MS = 10_000;

const LIVE_SECRET_GUARD_RE =
  /(?:[sr]k_live_[A-Za-z0-9_-]{4,}|whsec_live_[A-Za-z0-9_-]{4,}|whsec_(?!test_|synth_|sandbox_|demo_|sample_|mock_|example_|fake_|dummy_)[A-Za-z0-9_-]{10,}|shpss_live_[A-Za-z0-9_-]{4,}|shpss_[0-9a-fA-F]{16,}|shp(?:at|ua|ca|pa)_[A-Za-z0-9_-]{8,}|lsq_[A-Za-z0-9_-]{4,}|r[gc]_live_[A-Za-z0-9_-]{4,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i;

export function toSafeRpcId(rawId) {
  if (typeof rawId === "number" && Number.isFinite(rawId)) {
    return rawId;
  }
  if (
    typeof rawId === "string" &&
    rawId.length <= 128 &&
    !/[\x00-\x1f\x7f]/.test(rawId)
  ) {
    return rawId;
  }
  return null;
}

export function scanMcpClientPayloadForSecrets(node, depth = 0) {
  if (depth > 8) {
    return { ok: false, reason: "MCP_ARGUMENT_DEPTH_EXCEEDED" };
  }
  if (node === null || node === undefined) {
    return { ok: true };
  }
  if (typeof node === "string") {
    if (LIVE_SECRET_GUARD_RE.test(node)) {
      return { ok: false, reason: "LIVE_SECRET_FORBIDDEN_IN_SANDBOX" };
    }
    return { ok: true };
  }
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      const sub = scanMcpClientPayloadForSecrets(node[i], depth + 1);
      if (!sub.ok) return sub;
    }
    return { ok: true };
  }
  if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (LIVE_SECRET_GUARD_RE.test(k)) {
        return { ok: false, reason: "LIVE_SECRET_FORBIDDEN_IN_SANDBOX" };
      }
      const sub = scanMcpClientPayloadForSecrets(v, depth + 1);
      if (!sub.ok) return sub;
    }
    return { ok: true };
  }
  return { ok: true };
}

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
    endpointUrl,
    endpoint,
    apiUrl,
    apiKey = process.env.REVCLAMP_API_KEY || "",
    timeoutMs = REQUEST_TIMEOUT_MS,
    fetchImpl,
    mode = process.env.REVCLAMP_MCP_MODE || "",
  } = {}
) {
  const effectiveFetch = fetchImpl || globalThis.fetch;
  const hasExplicitRemote =
    Boolean(fetchImpl) ||
    Boolean(endpointUrl) ||
    Boolean(endpoint) ||
    Boolean(apiUrl) ||
    Boolean(String(apiKey || "").trim()) ||
    Boolean(process.env.REVCLAMP_MCP_URL) ||
    String(mode || "").toLowerCase() === "remote";
  const resolvedEndpointUrl =
    endpointUrl ||
    endpoint ||
    apiUrl ||
    process.env.REVCLAMP_MCP_URL ||
    DEFAULT_MCP_ENDPOINT;

  if (!rpcRequest || typeof rpcRequest !== "object" || Array.isArray(rpcRequest)) {
    return {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32600, message: "Invalid JSON-RPC request object" },
    };
  }

  const isNotification =
    !Object.prototype.hasOwnProperty.call(rpcRequest, "id") || rpcRequest.id === undefined;
  const safeId = toSafeRpcId(rpcRequest.id);
  const methodStr = typeof rpcRequest.method === "string" ? rpcRequest.method.trim() : "";

  if (
    rpcRequest.jsonrpc !== "2.0" ||
    methodStr.length === 0 ||
    (!isNotification && (safeId === null || methodStr.startsWith("notifications/"))) ||
    (isNotification && !methodStr.startsWith("notifications/"))
  ) {
    if (isNotification && methodStr.startsWith("notifications/")) {
      return null;
    }
    if (isNotification && rpcRequest.jsonrpc !== "2.0") {
      return null;
    }
    return {
      jsonrpc: "2.0",
      id: safeId,
      error: { code: -32600, message: "Invalid JSON-RPC 2.0 request envelope" },
    };
  }

  if (methodStr === "notifications/initialized" && isNotification) {
    return null;
  }

  if (
    rpcRequest.params !== undefined &&
    (rpcRequest.params === null ||
      typeof rpcRequest.params !== "object" ||
      Array.isArray(rpcRequest.params))
  ) {
    if (isNotification) {
      return null;
    }
    return {
      jsonrpc: "2.0",
      id: safeId,
      error: { code: -32602, message: "Invalid params: params must be a JSON object" },
    };
  }

  if (rpcRequest.params !== undefined) {
    if (
      methodStr === "tools/call" &&
      rpcRequest.params.arguments !== undefined &&
      (rpcRequest.params.arguments === null ||
        typeof rpcRequest.params.arguments !== "object" ||
        Array.isArray(rpcRequest.params.arguments))
    ) {
      if (isNotification) {
        return null;
      }
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: { code: -32602, message: "Invalid params: tool arguments must be a JSON object" },
      };
    }
    const secretScan = scanMcpClientPayloadForSecrets(rpcRequest.params);
    if (!secretScan.ok) {
      if (isNotification) {
        return null;
      }
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: {
          code: -32602,
          message: `Invalid params: ${secretScan.reason}`,
          data: { error: secretScan.reason, reason: secretScan.reason },
        },
      };
    }
    if (methodStr === "tools/call" && rpcRequest.params.arguments !== undefined) {
      const normRes = normalizeMcpToolArgs(
        String(rpcRequest.params?.name || "").trim(),
        rpcRequest.params.arguments
      );
      if (!normRes.ok) {
        if (isNotification) {
          return null;
        }
        return {
          jsonrpc: "2.0",
          id: safeId,
          error: {
            code: -32602,
            message: normRes.message,
            data: {
              error: normRes.error,
              reason: normRes.error,
              ...(normRes.canonicalKey ? { canonicalKey: normRes.canonicalKey } : {}),
            },
          },
        };
      }
      rpcRequest = {
        ...rpcRequest,
        params: {
          ...rpcRequest.params,
          arguments: normRes.args,
        },
      };
    }
  }

  try {
    const validatedEndpoint = resolveValidatedMcpEndpoint(resolvedEndpointUrl);
    const serialized = JSON.stringify(rpcRequest);
    if (Buffer.byteLength(serialized, "utf8") > MAX_PAYLOAD_BYTES) {
      if (isNotification) {
        return null;
      }
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: { code: -32600, message: "JSON-RPC request exceeds 32,768-byte limit" },
      };
    }

    const rawViesMode = String(rpcRequest?.params?.arguments?.viesMode || "")
      .trim()
      .toUpperCase();
    const isLocalOnlyViesCall =
      methodStr === "tools/call" &&
      rpcRequest?.params?.name === "revclamp_validate_eu_vat_vies" &&
      (rawViesMode === "FORMAT_ONLY" || rpcRequest?.params?.arguments?.demo === true);

    if (
      String(mode || "").toLowerCase() === "local" ||
      !hasExplicitRemote ||
      isLocalOnlyViesCall
    ) {
      if (isNotification) return null;
      return executeLocalMcpJsonRpc({ ...rpcRequest, id: safeId }, PACKAGE_VERSION);
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

    const res = await effectiveFetch(validatedEndpoint, {
      method: "POST",
      headers,
      body: serialized,
      redirect: "error",
      signal: AbortSignal.timeout(boundedTimeoutMs),
    });

    if (res.status === 204 || res.status === 202 || isNotification) {
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
          id: safeId,
          error: { code: -32603, message: `Upstream HTTP ${res.status}` },
        };
      }
      return {
        jsonrpc: "2.0",
        id: safeId,
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
    const idMatchesOrUpstreamNullError =
      parsed.id === safeId || (!hasResultProp && isValidErrorObj && parsed.id === null);
    const isValidEnvelope =
      isPlainObj &&
      parsed.jsonrpc === "2.0" &&
      idMatchesOrUpstreamNullError &&
      ((hasResultProp && !hasErrorProp) || (!hasResultProp && isValidErrorObj));

    if (!isValidEnvelope) {
      if (!httpOk) {
        return {
          jsonrpc: "2.0",
          id: safeId,
          error: { code: -32603, message: `Upstream HTTP ${res.status}` },
        };
      }
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: { code: -32603, message: "Malformed JSON-RPC 2.0 response envelope from upstream" },
      };
    }

    if (!httpOk && !isValidErrorObj) {
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: { code: -32603, message: `Upstream HTTP ${res.status}` },
      };
    }

    if (!hasResultProp && isValidErrorObj && parsed.id === null && safeId !== null) {
      return { ...parsed, id: safeId };
    }

    return parsed;
  } catch (err) {
    if (isNotification) {
      return null;
    }
    if (err instanceof Error && err.message === "UPSTREAM_RESPONSE_TOO_LARGE") {
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: { code: -32603, message: "Upstream MCP response exceeded 32,768-byte ceiling" },
      };
    }
    return {
      jsonrpc: "2.0",
      id: safeId,
      error: {
        code: -32603,
        message: `MCP transport error: ${err instanceof Error ? err.message : "UNKNOWN_ERROR"}`,
      },
    };
  }
}

export const handleMcpJsonRpc = forwardMcpJsonRpc;

export const forwardJsonRpcMessage = forwardMcpJsonRpc;

/**
 * Starts the newline-delimited JSON-RPC 2.0 stdio loop for MCP desktop clients,
 * enforcing a hard 32,768-byte line buffer ceiling before parsing.
 */
export function startMcpStdioServer(options = {}) {
  const inputStream = options.inputStream || options.input || process.stdin;
  const outputStream = options.outputStream || options.output || process.stdout;
  const maxPendingQueue =
    Number.isInteger(options.maxPendingQueue) && options.maxPendingQueue > 0
      ? options.maxPendingQueue
      : 64;
  let lineBuffer = Buffer.alloc(0);
  let discardingOversizedLine = false;
  let outputClosed = false;
  let drainingOutput = false;
  let inputPausedForQueue = false;
  let pendingQueueCount = 0;
  let queue = Promise.resolve();

  const closeTransport = () => {
    outputClosed = true;
    try {
      inputStream.pause?.();
    } catch {}
    try {
      if (typeof outputStream.destroy === "function" && outputStream !== process.stdout) {
        outputStream.destroy();
      } else if (typeof outputStream.end === "function" && outputStream !== process.stdout) {
        outputStream.end();
      }
    } catch {}
  };

  outputStream.on?.("error", () => {
    closeTransport();
  });
  inputStream.on?.("error", () => {
    closeTransport();
  });

  const safeWrite = async (payloadStr) => {
    if (outputClosed || outputStream.destroyed || outputStream.writableEnded) {
      return;
    }
    try {
      const canContinue = outputStream.write(payloadStr);
      if (canContinue === false && typeof outputStream.once === "function") {
        drainingOutput = true;
        try {
          inputStream.pause?.();
        } catch {}
        const drained = await new Promise((resolve) => {
          const onDrain = () => {
            clearTimeout(timer);
            resolve(true);
          };
          const timer = setTimeout(() => {
            outputStream.off?.("drain", onDrain);
            outputStream.removeListener?.("drain", onDrain);
            resolve(false);
          }, 2000);
          timer.unref?.();
          outputStream.once("drain", onDrain);
        });
        drainingOutput = false;
        if (!drained) {
          closeTransport();
          return;
        }
        if (!outputClosed && !inputPausedForQueue) {
          try {
            inputStream.resume?.();
          } catch {}
        }
      }
    } catch {
      closeTransport();
    }
  };

  const emitOversizedError = () =>
    safeWrite(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: null,
        error: {
          code: -32600,
          message: `Payload line exceeds ${MAX_PAYLOAD_BYTES.toLocaleString("en-US")} bytes (${MAX_PAYLOAD_BYTES} byte limit)`,
        },
      })}\n`
    );

  const processCompleteLine = async (rawLineBuffer) => {
    if (outputClosed || outputStream.destroyed || outputStream.writableEnded) return;
    const trimmed = rawLineBuffer.toString("utf8").trim();
    if (!trimmed) return;
    if (Buffer.byteLength(trimmed, "utf8") > MAX_PAYLOAD_BYTES) {
      await emitOversizedError();
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      await safeWrite(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        })}\n`
      );
      return;
    }
    let serializedResponse = null;
    try {
      const response = await forwardMcpJsonRpc(parsed, options);
      if (response !== null && response !== undefined) {
        serializedResponse = `${JSON.stringify(response)}\n`;
      }
    } catch {
      if (
        parsed &&
        typeof parsed === "object" &&
        !Array.isArray(parsed) &&
        Object.prototype.hasOwnProperty.call(parsed, "id") &&
        parsed.id !== undefined
      ) {
        await safeWrite(
          `${JSON.stringify({
            jsonrpc: "2.0",
            id: toSafeRpcId(parsed.id),
            error: { code: -32603, message: "Internal JSON-RPC transport error" },
          })}\n`
        );
      }
      return;
    }
    if (serializedResponse !== null) {
      await safeWrite(serializedResponse);
    }
  };

  const emitQueueOverflowError = async (rawLineBuffer) => {
    if (outputClosed || outputStream.destroyed || outputStream.writableEnded) return;
    let reqId = null;
    if (rawLineBuffer) {
      try {
        const parsed = JSON.parse(rawLineBuffer.toString("utf8").trim());
        if (
          parsed &&
          typeof parsed === "object" &&
          !Array.isArray(parsed) &&
          (!Object.prototype.hasOwnProperty.call(parsed, "id") || parsed.id === undefined)
        ) {
          return;
        }
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
          reqId = toSafeRpcId(parsed.id);
        }
      } catch {}
    }
    await safeWrite(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: reqId,
        error: { code: -32000, message: "MCP stdio queue capacity exceeded" },
      })}\n`
    );
  };

  const enqueueTask = (taskFn, overflowFallbackFn = null) => {
    if (outputClosed) return;
    if (pendingQueueCount >= maxPendingQueue) {
      inputPausedForQueue = true;
      try {
        inputStream.pause?.();
      } catch {}
      if (overflowFallbackFn) {
        queue = queue.then(() => overflowFallbackFn()).catch(() => {});
      }
      return;
    }
    pendingQueueCount += 1;
    if (pendingQueueCount >= maxPendingQueue) {
      inputPausedForQueue = true;
      try {
        inputStream.pause?.();
      } catch {}
    }
    queue = queue
      .then(() => taskFn())
      .catch(() => {})
      .finally(() => {
        pendingQueueCount = Math.max(0, pendingQueueCount - 1);
        if (inputPausedForQueue && pendingQueueCount < maxPendingQueue && !outputClosed && !drainingOutput) {
          inputPausedForQueue = false;
          try {
            inputStream.resume?.();
          } catch {}
        }
      });
  };

  inputStream.on("data", (chunk) => {
    if (outputClosed) return;
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
        enqueueTask(
          () => emitOversizedError(),
          () => emitOversizedError()
        );
      } else if (lineBuffer.length + segment.length > MAX_PAYLOAD_BYTES) {
        lineBuffer = Buffer.alloc(0);
        enqueueTask(
          () => emitOversizedError(),
          () => emitOversizedError()
        );
      } else {
        const fullLine =
          lineBuffer.length === 0 ? segment : Buffer.concat([lineBuffer, segment]);
        lineBuffer = Buffer.alloc(0);
        enqueueTask(
          () => processCompleteLine(fullLine),
          () => emitQueueOverflowError(fullLine)
        );
      }
    }
  });

  inputStream.on("end", () => {
    if (outputClosed) return;
    if (discardingOversizedLine) {
      discardingOversizedLine = false;
      lineBuffer = Buffer.alloc(0);
      enqueueTask(
        () => emitOversizedError(),
        () => emitOversizedError()
      );
    } else if (lineBuffer.length > 0) {
      const fullLine = lineBuffer;
      lineBuffer = Buffer.alloc(0);
      enqueueTask(
        () => processCompleteLine(fullLine),
        () => emitQueueOverflowError(fullLine)
      );
    }
  });
}

export const createStdioMcpBridge = startMcpStdioServer;

function printHelp() {
  console.log(
    [
      "RevClamp Enterprise MCP Server & CLI (https://revclamp.com)",
      "",
      "Usage:",
      "  revclamp-mcp                                         Start MCP stdio server (for Claude Desktop / Cursor)",
      "  revclamp-mcp --version | -v                          Print package version",
      "  revclamp-mcp --list-tools                            List all 9 exposed RevClamp MCP tools",
      "  revclamp-mcp --check-vat <VAT_ID> [sellerCC] [mode]  Validate an EU or XI VAT identifier via MCP (default mode: FORMAT_ONLY locally, LIVE with REVCLAMP_API_KEY)",
      "  revclamp-mcp --calc-roi [disputeUsd] [bleedUsd] [ratePct] [events]  Calculate 0% take-rate ROI & plan fit",
      "  revclamp-mcp --sim-replay [presetKey] [windowSec]    Simulate webhook replay & out-of-order state machine",
      "  revclamp-mcp --lint-evidence [preset]                Lint Stripe dispute evidence UTF-16 & CE 3.0 completeness",
      "  revclamp-mcp --verify-webhook [provider] [rawPayload] [signatureHeader]  Verify webhook HMAC via REVCLAMP_WEBHOOK_SECRET env var",
      "  revclamp-mcp --call <tool_name> '<json_args>'        Invoke any RevClamp MCP tool directly",
      "",
      "Environment Variables:",
      "  REVCLAMP_API_KEY         Optional workspace key (rg_live_...). Omit for Stateless Sandbox mode.",
      "  REVCLAMP_MCP_URL         Optional override (must be https://api.revclamp.com/api/mcp or https://revclamp.com/api/mcp).",
      "  REVCLAMP_WEBHOOK_SECRET  Synthetic/test webhook secret used by --verify-webhook (never pass secrets in CLI argv).",
    ].join("\n")
  );
}

const KNOWN_CLI_FLAGS = new Set([
  "--help",
  "-h",
  "--version",
  "-v",
  "--self-test",
  "--list-tools",
  "--check-vat",
  "--calc-roi",
  "--sim-replay",
  "--lint-evidence",
  "--verify-webhook",
  "--call",
  "--stdio",
  "--url",
  "--endpoint",
]);

export async function runCli(argv = process.argv.slice(2), options = {}) {
  const effectiveOptions = { ...options };
  const cleanedArgv = [];
  for (let i = 0; i < argv.length; i += 1) {
    const token = String(argv[i] ?? "");
    if (token === "--secret" || token.startsWith("--secret=")) {
      console.error(
        "Error: passing webhook secrets via CLI flags (--secret) is forbidden; set REVCLAMP_WEBHOOK_SECRET in the environment."
      );
      return 1;
    }
    if (token === "--url" || token === "--endpoint") {
      const nextVal = String(argv[i + 1] ?? "").trim();
      if (!nextVal || nextVal.startsWith("-")) {
        console.error(`Error: ${token} requires a valid endpoint URL argument`);
        return 1;
      }
      effectiveOptions.endpointUrl = nextVal;
      i += 1;
      continue;
    }
    if (token.startsWith("--url=")) {
      effectiveOptions.endpointUrl = token.slice("--url=".length).trim();
      continue;
    }
    if (token.startsWith("--endpoint=")) {
      effectiveOptions.endpointUrl = token.slice("--endpoint=".length).trim();
      continue;
    }
    if (
      token.startsWith("-") &&
      !KNOWN_CLI_FLAGS.has(token) &&
      !token.startsWith("--mode=") &&
      !/^-\d/.test(token)
    ) {
      console.error(`Error: unknown CLI flag '${token}'`);
      return 1;
    }
    cleanedArgv.push(token);
  }

  if (cleanedArgv.includes("--help") || cleanedArgv.includes("-h")) {
    printHelp();
    return 0;
  }

  if (cleanedArgv.includes("--version") || cleanedArgv.includes("-v")) {
    console.log(PACKAGE_VERSION);
    return 0;
  }

  if (cleanedArgv.includes("--self-test")) {
    const validated = resolveValidatedMcpEndpoint(
      effectiveOptions.endpointUrl ||
        effectiveOptions.endpoint ||
        effectiveOptions.apiUrl ||
        DEFAULT_MCP_ENDPOINT
    );
    const smokeAudit = executeLocalMcpTool("revclamp_audit_revenue_leakage", { demo: true });
    const toolsCount = Array.isArray(LOCAL_MCP_TOOLS) ? LOCAL_MCP_TOOLS.length : 0;
    const localEngineVerified =
      Boolean(smokeAudit && smokeAudit.ok === true && smokeAudit.ghostEventsDetected > 0) &&
      toolsCount === 9;
    console.log(
      JSON.stringify({
        ok: localEngineVerified,
        version: PACKAGE_VERSION,
        toolsCount,
        localEngineVerified,
        endpoint: validated,
      })
    );
    return localEngineVerified ? 0 : 1;
  }

  if (cleanedArgv.includes("--list-tools")) {
    const res = await forwardMcpJsonRpc(
      { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} },
      effectiveOptions
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  const vatIdx = cleanedArgv.indexOf("--check-vat");
  if (vatIdx !== -1) {
    const positional = [];
    let flagMode = "";
    for (let i = vatIdx + 1; i < cleanedArgv.length; i += 1) {
      const token = String(cleanedArgv[i] || "").trim();
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
    const effectiveMode = String(
      effectiveOptions.mode || process.env.REVCLAMP_MCP_MODE || ""
    ).toLowerCase();
    const cliHasExplicitRemote =
      effectiveMode !== "local" &&
      (Boolean(effectiveOptions.fetchImpl) ||
        Boolean(effectiveOptions.endpointUrl) ||
        Boolean(effectiveOptions.endpoint) ||
        Boolean(effectiveOptions.apiUrl) ||
        Boolean(String(effectiveOptions.apiKey || process.env.REVCLAMP_API_KEY || "").trim()) ||
        Boolean(process.env.REVCLAMP_MCP_URL) ||
        effectiveMode === "remote");
    const defaultViesMode = cliHasExplicitRemote ? "LIVE" : "FORMAT_ONLY";
    const viesMode = String(flagMode || positional[2] || defaultViesMode)
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
      effectiveOptions
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  const roiIdx = cleanedArgv.indexOf("--calc-roi");
  if (roiIdx !== -1) {
    const positional = [];
    for (let i = roiIdx + 1; i < cleanedArgv.length; i += 1) {
      const token = String(cleanedArgv[i] ?? "").trim();
      if (token.startsWith("--")) break;
      positional.push(token);
    }
    if (positional.length > 4) {
      console.error(
        "Error: --calc-roi accepts at most 4 arguments: [disputeUsd] [bleedUsd] [ratePct] [events]"
      );
      return 1;
    }
    const parseCliDecimal = (rawStr, defVal, minV, maxV, intOnly = false) => {
      if (rawStr === undefined) return { ok: true, value: defVal };
      const pattern = intOnly ? /^\d+$/ : /^\d+(?:\.\d{1,2})?$/;
      if (!pattern.test(rawStr)) return { ok: false };
      const val = Number(rawStr);
      if (!Number.isFinite(val) || val < minV || val > maxV) return { ok: false };
      if (intOnly && !Number.isInteger(val)) return { ok: false };
      return { ok: true, value: val };
    };
    const pDispute = parseCliDecimal(positional[0], 10_000, 0, 10_000_000, false);
    const pBleed = parseCliDecimal(positional[1], 600, 0, 10_000_000, false);
    const pRate = parseCliDecimal(positional[2], 25, 1, 50, false);
    const pEvents = parseCliDecimal(positional[3], 250_000, 0, 50_000_000, true);
    if (!pDispute.ok || !pBleed.ok || !pRate.ok || !pEvents.ok) {
      console.error("Error: invalid --calc-roi numeric arguments");
      return 1;
    }
    const res = await forwardMcpJsonRpc(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "revclamp_calculate_roi_and_plan_fit",
          arguments: {
            monthlyWonDisputeUsd: pDispute.value,
            monthlyGhostBleedUsd: pBleed.value,
            contingencyTakeRatePercent: pRate.value,
            monthlyUsageEvents: pEvents.value,
          },
        },
      },
      effectiveOptions
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  const simReplayIdx = cleanedArgv.indexOf("--sim-replay");
  if (simReplayIdx !== -1) {
    const positional = [];
    for (let i = simReplayIdx + 1; i < cleanedArgv.length; i += 1) {
      const token = String(cleanedArgv[i] ?? "").trim();
      if (token.startsWith("--")) break;
      positional.push(token);
    }
    if (positional.length > 2) {
      console.error(
        "Error: --sim-replay accepts at most 2 arguments: [presetKey] [idempotencyWindowSec]"
      );
      return 1;
    }
    const allowedPresets = new Set([
      "out_of_order_stale_update_after_cancel",
      "duplicate_event_id_replay_72h",
      "valid_monotonic_upgrade_sequence",
      "expired_72h_window_stale_event",
    ]);
    const presetKey = positional[0] || "out_of_order_stale_update_after_cancel";
    if (!allowedPresets.has(presetKey)) {
      console.error(`Error: invalid --sim-replay preset '${presetKey}'`);
      return 1;
    }
    const replayArgs = { scenarioPreset: presetKey };
    if (positional[1] !== undefined) {
      if (!/^\d+$/.test(positional[1])) {
        console.error("Error: invalid --sim-replay idempotencyWindowSec argument");
        return 1;
      }
      const winSec = Number(positional[1]);
      if (!Number.isInteger(winSec) || winSec < 60 || winSec > 2_592_000) {
        console.error("Error: invalid --sim-replay idempotencyWindowSec argument");
        return 1;
      }
      replayArgs.idempotencyWindowSec = winSec;
    }
    const res = await forwardMcpJsonRpc(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "revclamp_simulate_webhook_replay",
          arguments: replayArgs,
        },
      },
      effectiveOptions
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  const lintEvidenceIdx = cleanedArgv.indexOf("--lint-evidence");
  if (lintEvidenceIdx !== -1) {
    const positional = cleanedArgv
      .slice(lintEvidenceIdx + 1)
      .map((t) => String(t ?? "").trim());
    if (positional.length > 1) {
      console.error(
        "Error: --lint-evidence accepts at most 1 argument: [preset]"
      );
      return 1;
    }
    const allowedPresets = new Set([
      "valid_ce3_non_destructive",
      "utf16_overflow_19k",
      "missing_device_and_overwrite_risk",
    ]);
    const preset = positional[0] || "valid_ce3_non_destructive";
    if (!allowedPresets.has(preset)) {
      console.error(`Error: invalid --lint-evidence preset '${preset}'`);
      return 1;
    }
    const res = await forwardMcpJsonRpc(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "revclamp_lint_dispute_evidence",
          arguments: { preset },
        },
      },
      effectiveOptions
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  const verifyWebhookIdx = cleanedArgv.indexOf("--verify-webhook");
  if (verifyWebhookIdx !== -1) {
    const positional = [];
    for (let i = verifyWebhookIdx + 1; i < cleanedArgv.length; i += 1) {
      const token = String(cleanedArgv[i] ?? "").trim();
      if (token.startsWith("--")) break;
      positional.push(token);
    }
    for (const argVal of positional) {
      if (
        LIVE_SECRET_GUARD_RE.test(argVal) ||
        /^whsec_/i.test(argVal) ||
        /^shpss_/i.test(argVal) ||
        /^sk_(?:live|test)_/i.test(argVal)
      ) {
        console.error(
          "Error: passing webhook secrets in CLI arguments is forbidden; provide the secret via the REVCLAMP_WEBHOOK_SECRET environment variable."
        );
        return 1;
      }
    }
    if (positional.length > 3) {
      console.error(
        "Error: --verify-webhook accepts at most 3 arguments: [provider] [rawPayload] [signatureHeader] (secret must be set via REVCLAMP_WEBHOOK_SECRET)"
      );
      return 1;
    }
    const secret = String(
      effectiveOptions.webhookSecret || process.env.REVCLAMP_WEBHOOK_SECRET || ""
    ).trim();
    if (!secret) {
      console.error(
        "Error: --verify-webhook requires the REVCLAMP_WEBHOOK_SECRET environment variable."
      );
      return 1;
    }
    if (LIVE_SECRET_GUARD_RE.test(secret)) {
      console.error(
        "Error: live webhook secrets are forbidden; use a synthetic/test secret in REVCLAMP_WEBHOOK_SECRET."
      );
      return 1;
    }
    const provider = String(positional[0] || "stripe")
      .trim()
      .toLowerCase();
    if (!["stripe", "shopify", "revclamp"].includes(provider)) {
      console.error(
        `Error: invalid --verify-webhook provider '${provider}' (expected stripe, shopify, or revclamp)`
      );
      return 1;
    }
    const rawPayload =
      positional[1] !== undefined && positional[1] !== ""
        ? positional[1]
        : '{"id":"evt_cli_sandbox_01","type":"customer.subscription.updated"}';
    const webhookArgs = { provider, secret, rawPayload };
    if (positional[2] !== undefined && positional[2] !== "") {
      webhookArgs.signatureHeader = positional[2];
    }
    const res = await forwardMcpJsonRpc(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "revclamp_verify_webhook_signature",
          arguments: webhookArgs,
        },
      },
      effectiveOptions
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  const callIdx = cleanedArgv.indexOf("--call");
  if (callIdx !== -1) {
    if (cleanedArgv.length > callIdx + 3) {
      console.error("Error: --call accepts at most 2 arguments: <tool_name> ['<json_args>']");
      return 1;
    }
    const toolName = String(cleanedArgv[callIdx + 1] || "").trim();
    const rawArgs = String(cleanedArgv[callIdx + 2] || "{}");
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
    if (!parsedArgs || typeof parsedArgs !== "object" || Array.isArray(parsedArgs)) {
      console.error("Error: --call JSON arguments must be a JSON object");
      return 1;
    }
    const res = await forwardMcpJsonRpc(
      {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: toolName, arguments: parsedArgs },
      },
      effectiveOptions
    );
    console.log(JSON.stringify(res, null, 2));
    return !res || res.error || res.result?.isError === true ? 1 : 0;
  }

  if (
    cleanedArgv.length === 0 ||
    (cleanedArgv.length === 1 && cleanedArgv[0] === "--stdio")
  ) {
    if (options && typeof options === "object") {
      options._stdioServerStarted = true;
    }
    startMcpStdioServer(effectiveOptions);
    return 0;
  }

  console.error(`Error: unrecognized CLI arguments: ${cleanedArgv.join(" ")}`);
  return 1;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const cliLaunchState = {};
  runCli(process.argv.slice(2), cliLaunchState).then((code) => {
    if (!cliLaunchState._stdioServerStarted) {
      process.exit(code);
    }
  });
}
