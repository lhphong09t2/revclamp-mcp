#!/usr/bin/env node

/**
 * Entrypoint & Barrel Export for RevClamp TalentPulse - Unified 5-in-1 B2B ATS Job & Hiring Signal Feed (`index.mjs`)
 */

import fs from 'node:fs';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import {
  ALLOWED_ATS_API_HOSTS,
  WORKDAY_CXS_HOST_RE,
  isAllowedAtsApiHost,
  verifyEgressUrlSsrfSafe,
  assertAllowedAtsEgress,
  createEphemeralHttpsAgent,
} from './src/egress_guard.mjs';

import {
  SUPPORTED_ATS_PROVIDERS,
  CANONICAL_JOB_ID_RE,
  JOB_ID_RE,
  ISO_COUNTRY_RE,
  MAX_ATS_RESPONSE_BYTES,
  MAX_RPC_RESPONSE_BYTES,
  DEFAULT_RUN_DEADLINE_MS,
  COMPOSITE_CURSOR_PREFIX,
  MAX_CURSOR_LENGTH,
  MAX_QUERY_LENGTH,
  MAX_EXCERPT_CHARS,
  MAX_TECH_KEYWORDS,
  KNOWN_COMPANY_ATS_DIRECTORY,
  CURATED_COMPANY_ATS_DIRECTORY,
  validateBoundedIntegerParam,
  computePaginationScopeHash,
  encodeCompositeCursor,
  decodePaginationCursor,
  computeRewoundCursorForDeliveredPrefix,
  parseAtsTargetFromInput,
  parseCareerBoardUrl,
  verifyAtsResponseSchemaCanary,
  executeAtsJsonRequest,
  executeAtsHttpJsonRequest,
  sanitizeUntrustedJobText,
  decodeHtmlEntitiesAndStripTags,
  buildUntrustedJobContent,
  sanitizeUntrustedJobExcerpt,
  extractTechStackKeywords,
  extractJobCompensation,
  inferCountryIso2,
  inferWorkplaceType,
  classifyWorkplaceType,
  inferSeniorityLevel,
  classifySeniorityLevel,
  normalizePostedTimestamp,
  normalizeAtsJobRecord,
  resolveCompanyAtsBoard,
  resolveAtsBoardTarget,
  fetchUnifiedAtsJobPostings,
  searchAtsJobPostings,
  getAtsJobPostingDetail,
} from './src/ats_client.mjs';

import {
  ACTOR_PRICING_CONTRACT,
  computeChunkIdempotencyKey,
  computeRunEconomicsTelemetry,
  createApifyPlatformHooks,
  loadApifyActorInput,
  runUnifiedAtsJobsActor,
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
  createTalentPulsePreviewServer,
} from './src/web_preview_server.mjs';

export {
  ALLOWED_ATS_API_HOSTS,
  WORKDAY_CXS_HOST_RE,
  isAllowedAtsApiHost,
  verifyEgressUrlSsrfSafe,
  assertAllowedAtsEgress,
  createEphemeralHttpsAgent,
  SUPPORTED_ATS_PROVIDERS,
  CANONICAL_JOB_ID_RE,
  JOB_ID_RE,
  ISO_COUNTRY_RE,
  MAX_ATS_RESPONSE_BYTES,
  MAX_RPC_RESPONSE_BYTES,
  DEFAULT_RUN_DEADLINE_MS,
  COMPOSITE_CURSOR_PREFIX,
  MAX_CURSOR_LENGTH,
  MAX_QUERY_LENGTH,
  MAX_EXCERPT_CHARS,
  MAX_TECH_KEYWORDS,
  KNOWN_COMPANY_ATS_DIRECTORY,
  CURATED_COMPANY_ATS_DIRECTORY,
  validateBoundedIntegerParam,
  computePaginationScopeHash,
  encodeCompositeCursor,
  decodePaginationCursor,
  computeRewoundCursorForDeliveredPrefix,
  parseAtsTargetFromInput,
  parseCareerBoardUrl,
  verifyAtsResponseSchemaCanary,
  executeAtsJsonRequest,
  executeAtsHttpJsonRequest,
  sanitizeUntrustedJobText,
  decodeHtmlEntitiesAndStripTags,
  buildUntrustedJobContent,
  sanitizeUntrustedJobExcerpt,
  extractTechStackKeywords,
  extractJobCompensation,
  inferCountryIso2,
  inferWorkplaceType,
  classifyWorkplaceType,
  inferSeniorityLevel,
  classifySeniorityLevel,
  normalizePostedTimestamp,
  normalizeAtsJobRecord,
  resolveCompanyAtsBoard,
  resolveAtsBoardTarget,
  fetchUnifiedAtsJobPostings,
  searchAtsJobPostings,
  getAtsJobPostingDetail,
  ACTOR_PRICING_CONTRACT,
  computeChunkIdempotencyKey,
  computeRunEconomicsTelemetry,
  createApifyPlatformHooks,
  loadApifyActorInput,
  runUnifiedAtsJobsActor,
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
  createTalentPulsePreviewServer,
};

export async function runCli(argv = process.argv.slice(2)) {
  const args = Array.isArray(argv) ? argv : [];
  if (args.includes('--playground') || args.includes('--web-preview')) {
    const portArg = Number(process.env.PORT || 4411);
    const srv = await createTalentPulsePreviewServer({ port: portArg });
    process.stdout.write(`RevClamp TalentPulse Web Playground listening on ${srv.url}\n`);
    return srv;
  }

  if (args.includes('--mcp-stdio')) {
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
              id:
                typeof parsedReq.id === 'string' || typeof parsedReq.id === 'number'
                  ? parsedReq.id
                  : null,
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
  const res = await runUnifiedAtsJobsActor(inputObj, platformHooks);
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
    process.stderr.write(
      `Fatal error in RevClamp TalentPulse CLI: ${err?.message || String(err)}\n`
    );
    process.exit(1);
  });
}
