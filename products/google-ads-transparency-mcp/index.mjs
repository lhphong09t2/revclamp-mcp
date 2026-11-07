#!/usr/bin/env node

/**
 * Entrypoint & Barrel Export for RevClamp AdPulse - Google Ads Transparency MCP & Apify Actor (`index.mjs`)
 */

import fs from 'node:fs';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import {
  ALLOWED_GOOGLE_ADS_RPC_HOSTS,
  LIVE_SECRET_GUARD_RE,
  containsLiveSecretToken,
  verifyEgressUrlSsrfSafe,
  assertAllowedGoogleAdsEgress,
  createEphemeralHttpsAgent,
} from './src/egress_guard.mjs';

import {
  GOOGLE_ADS_RPC_ENDPOINTS,
  ADVERTISER_ID_RE,
  CREATIVE_ID_RE,
  ISO_COUNTRY_RE,
  ISO_COUNTRY_TO_GOOGLE_GEO_ID,
  GOOGLE_GEO_ID_TO_ISO_COUNTRY,
  MAX_RPC_RESPONSE_BYTES,
  DEFAULT_RUN_DEADLINE_MS,
  COMPOSITE_CURSOR_PREFIX,
  MAX_CURSOR_LENGTH,
  MAX_QUERY_LENGTH,
  KNOWN_ADVERTISER_DIRECTORY,
  CORPORATE_LEGAL_SUFFIX_TOKENS,
  collapseDottedAcronyms,
  foldBrandText,
  parseGoogleAdsTransparencyUrl,
  parseBrandQueryTokens,
  normalizeAdPulseInputAliases,
  validateBoundedIntegerParam,
  computePaginationScopeHash,
  encodeCompositeCursor,
  decodePaginationCursor,
  computeRewoundCursorForDeliveredPrefix,
  verifyRpcResponseSchemaCanary,
  scoreAdvertiserCandidate,
  executeGoogleAdsRpcPost,
  resolveAdvertiserEntities,
  extractCreativeAssetUrls,
  sanitizeUntrustedAdText,
  createEmptyUntrustedAdContent,
  extractStaticAdCopyFromContentJs,
  fetchAndExtractStaticAdCopy,
  normalizeCreativeRecord,
  fetchAdvertiserCreatives,
  searchAdTransparencyCreatives,
  getCreativeDetailsById,
} from './src/rpc_client.mjs';

import {
  ACTOR_PRICING_CONTRACT,
  computeChunkIdempotencyKey,
  computeRunEconomicsTelemetry,
  createApifyPlatformHooks,
  loadApifyActorInput,
  runGoogleAdsTransparencyActor,
  scrapeGoogleAdsTransparency,
} from './src/apify_actor.mjs';

import {
  MCP_MAX_ENVELOPE_BYTES,
  MCP_MAX_ITEMS_LIMIT,
  MCP_MAX_REQ_ID_BYTES,
  SUPPORTED_MCP_PROTOCOL_VERSIONS,
  ENCODED_BRAND_ICON_DATA_URI,
  MCP_SERVER_INFO,
  MCP_TOOLS_MANIFEST,
  sliceUtf8Safe,
  truncateMcpResponseEnvelope,
  validateMcpToolArguments,
  handleMcpJsonRpcRequest,
} from './src/mcp_server.mjs';

import {
  PLAYGROUND_CSP_HEADER,
  MAX_PLAYGROUND_BODY_BYTES,
  PLAYGROUND_REQUEST_TIMEOUT_MS,
  createAdPulsePreviewServer,
} from './src/web_preview_server.mjs';

export {
  ALLOWED_GOOGLE_ADS_RPC_HOSTS,
  LIVE_SECRET_GUARD_RE,
  containsLiveSecretToken,
  verifyEgressUrlSsrfSafe,
  assertAllowedGoogleAdsEgress,
  createEphemeralHttpsAgent,
  GOOGLE_ADS_RPC_ENDPOINTS,
  ADVERTISER_ID_RE,
  CREATIVE_ID_RE,
  ISO_COUNTRY_RE,
  ISO_COUNTRY_TO_GOOGLE_GEO_ID,
  GOOGLE_GEO_ID_TO_ISO_COUNTRY,
  MAX_RPC_RESPONSE_BYTES,
  DEFAULT_RUN_DEADLINE_MS,
  COMPOSITE_CURSOR_PREFIX,
  MAX_CURSOR_LENGTH,
  MAX_QUERY_LENGTH,
  KNOWN_ADVERTISER_DIRECTORY,
  CORPORATE_LEGAL_SUFFIX_TOKENS,
  collapseDottedAcronyms,
  foldBrandText,
  parseGoogleAdsTransparencyUrl,
  parseBrandQueryTokens,
  normalizeAdPulseInputAliases,
  validateBoundedIntegerParam,
  computePaginationScopeHash,
  encodeCompositeCursor,
  decodePaginationCursor,
  computeRewoundCursorForDeliveredPrefix,
  verifyRpcResponseSchemaCanary,
  scoreAdvertiserCandidate,
  executeGoogleAdsRpcPost,
  resolveAdvertiserEntities,
  extractCreativeAssetUrls,
  sanitizeUntrustedAdText,
  createEmptyUntrustedAdContent,
  extractStaticAdCopyFromContentJs,
  fetchAndExtractStaticAdCopy,
  normalizeCreativeRecord,
  fetchAdvertiserCreatives,
  searchAdTransparencyCreatives,
  getCreativeDetailsById,
  ACTOR_PRICING_CONTRACT,
  computeChunkIdempotencyKey,
  computeRunEconomicsTelemetry,
  createApifyPlatformHooks,
  loadApifyActorInput,
  runGoogleAdsTransparencyActor,
  scrapeGoogleAdsTransparency,
  MCP_MAX_ENVELOPE_BYTES,
  MCP_MAX_ITEMS_LIMIT,
  MCP_MAX_REQ_ID_BYTES,
  SUPPORTED_MCP_PROTOCOL_VERSIONS,
  ENCODED_BRAND_ICON_DATA_URI,
  MCP_SERVER_INFO,
  MCP_TOOLS_MANIFEST,
  sliceUtf8Safe,
  truncateMcpResponseEnvelope,
  validateMcpToolArguments,
  handleMcpJsonRpcRequest,
  PLAYGROUND_CSP_HEADER,
  MAX_PLAYGROUND_BODY_BYTES,
  PLAYGROUND_REQUEST_TIMEOUT_MS,
  createAdPulsePreviewServer,
};

export async function runCli(argv = process.argv.slice(2), options = {}) {
  const args = Array.isArray(argv) ? argv : [];
  const writeStdout =
    typeof options.writeStdout === 'function'
      ? options.writeStdout
      : (str) => process.stdout.write(str);
  const exitFn = typeof options.exitFn === 'function' ? options.exitFn : (code) => process.exit(code);

  if (args.includes('--list-tools')) {
    const out = {
      ok: true,
      serverInfo: MCP_SERVER_INFO,
      tools: MCP_TOOLS_MANIFEST,
    };
    writeStdout(`${JSON.stringify(out, null, 2)}\n`);
    return out;
  }

  if (args.includes('--self-test')) {
    const initRes = await handleMcpJsonRpcRequest({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: { protocolVersion: '2025-06-18' },
    });
    const listRes = await handleMcpJsonRpcRequest({
      jsonrpc: '2.0',
      id: 2,
      method: 'tools/list',
      params: {},
    });
    const secretBlocked = containsLiveSecretToken(['sk', 'live', '1234567890abcdef'].join('_'));
    const ssrfBlocked = !assertAllowedGoogleAdsEgress('http://127.0.0.1/internal').safe;
    const ok =
      Boolean(initRes?.result?.serverInfo?.name) &&
      Array.isArray(listRes?.result?.tools) &&
      listRes.result.tools.length === 3 &&
      secretBlocked &&
      ssrfBlocked;
    const report = {
      ok,
      status: ok ? 'SELF_TEST_PASSED' : 'SELF_TEST_FAILED',
      server: MCP_SERVER_INFO.name,
      version: MCP_SERVER_INFO.version,
      toolsVerified: listRes?.result?.tools?.length || 0,
      secretGuardActive: secretBlocked,
      ssrfGuardActive: ssrfBlocked,
    };
    writeStdout(`${JSON.stringify(report, null, 2)}\n`);
    if (!options.noExit) exitFn(ok ? 0 : 1);
    return report;
  }

  const callIdx = args.indexOf('--call');
  if (callIdx !== -1) {
    const toolName = String(args[callIdx + 1] || '').trim();
    const rawJsonArgs = args[callIdx + 2] ? String(args[callIdx + 2]).trim() : '{}';
    let parsedArgs = {};
    try {
      parsedArgs = JSON.parse(rawJsonArgs);
    } catch (err) {
      const errOut = {
        ok: false,
        status: 'INVALID_INPUT',
        reason: `Invalid JSON arguments for --call ${toolName}: ${err.message}`,
      };
      writeStdout(`${JSON.stringify(errOut, null, 2)}\n`);
      if (!options.noExit) exitFn(1);
      return errOut;
    }
    const rpcRes = await handleMcpJsonRpcRequest(
      {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: toolName, arguments: parsedArgs },
      },
      options
    );
    const out = rpcRes?.result?.structuredContent || rpcRes;
    writeStdout(`${JSON.stringify(out, null, 2)}\n`);
    const isOk = Boolean(out?.ok !== false && !rpcRes?.error && !rpcRes?.result?.isError);
    if (!options.noExit) exitFn(isOk ? 0 : 1);
    return out;
  }

  if (args.includes('--playground') || args.includes('--web-preview')) {
    const portArg = Number(process.env.PORT || 4410);
    const srv = await createAdPulsePreviewServer({ port: portArg });
    writeStdout(`RevClamp AdPulse Web Playground listening on ${srv.url}\n`);
    return srv;
  }

  if (args.includes('--mcp-stdio') || args.includes('--stdio')) {
    const rl = readline.createInterface({
      input: process.stdin,
      terminal: false,
    });
    for await (const line of rl) {
      const trimmed = line.trim();
      if (!trimmed) {
        continue;
      }
      let parsedReq;
      try {
        parsedReq = JSON.parse(trimmed);
      } catch {
        process.stdout.write(
          `${JSON.stringify({
            jsonrpc: '2.0',
            id: null,
            error: { code: -32700, message: 'Parse error' },
          })}\n`
        );
        continue;
      }

      try {
        const res = await handleMcpJsonRpcRequest(parsedReq);
        if (res !== null && res !== undefined) {
          process.stdout.write(`${JSON.stringify(res)}\n`);
        }
      } catch (err) {
        const hasId =
          parsedReq &&
          typeof parsedReq === 'object' &&
          !Array.isArray(parsedReq) &&
          Object.prototype.hasOwnProperty.call(parsedReq, 'id') &&
          parsedReq.id !== undefined;
        if (hasId) {
          process.stdout.write(
            `${JSON.stringify({
              jsonrpc: '2.0',
              id: typeof parsedReq.id === 'string' || typeof parsedReq.id === 'number' ? parsedReq.id : null,
              error: { code: -32603, message: `Internal error: ${err?.message || String(err)}` },
            })}\n`
          );
        }
      }
    }
    return null;
  }

  const inputObj = await loadApifyActorInput(args, process.env);
  const platformHooks = createApifyPlatformHooks(process.env);
  const res = await runGoogleAdsTransparencyActor(inputObj, platformHooks);
  process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
  process.exit(res.ok ? 0 : 1);
}

function isExecutedAsMainModule(metaUrl) {
  if (!process.argv[1]) return false;
  try {
    const entryPath = fs.realpathSync(process.argv[1]);
    const selfPath = fs.realpathSync(fileURLToPath(metaUrl));
    return entryPath === selfPath;
  } catch {
    return false;
  }
}

if (isExecutedAsMainModule(import.meta.url)) {
  runCli().catch((err) => {
    process.stderr.write(`Fatal error in RevClamp AdPulse CLI: ${err?.message || String(err)}\n`);
    process.exit(1);
  });
}
