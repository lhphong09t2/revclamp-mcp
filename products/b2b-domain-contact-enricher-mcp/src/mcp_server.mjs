/**
 * Model Context Protocol (MCP) JSON-RPC 2.0 Server (src/mcp_server.mjs)
 *
 * Exposes three deterministic B2B tools sharing the ContactPulse engine:
 *   - `resolve_b2b_domain_contacts`
 *   - `inspect_domain_dns_and_security_txt`
 *   - `verify_email_deliverability_posture`
 * Enforces a strict `30,000`-byte UTF-8 envelope ceiling (`sliceUtf8Safe`) with automatic
 * `rcd1_` pagination cursor rewind when items are popped.
 */

import fs from 'node:fs';
import {
  SUPPORTED_CONTACT_ROLES,
  validateBoundedIntegerParam,
  normalizeContactPulseInputAliases,
  resolveB2bDomainContactsBatch,
  enrichSingleB2bDomain,
  verifyEmailDeliverabilityPosture,
  computeRewoundCursorForDeliveredPrefix,
} from './contact_client.mjs';
import {
  sliceUtf8Safe,
  truncateUtf8Safe,
  containsLiveSecretToken,
} from './egress_guard.mjs';

const PKG_VERSION = JSON.parse(
  fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version;

export { sliceUtf8Safe, truncateUtf8Safe };

export const MCP_MAX_ENVELOPE_BYTES = 30000;
export const MCP_MAX_ITEMS_LIMIT = 25;
export const MCP_MAX_REQ_ID_BYTES = 256;

export const SUPPORTED_MCP_PROTOCOL_VERSIONS = Object.freeze([
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
]);

const RAW_BRAND_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180 180" width="180" height="180" role="img" aria-labelledby="rc-cp-title"><title id="rc-cp-title">RevClamp ContactPulse</title><rect width="180" height="180" fill="#070B14"/><path d="M90 18L154 42V88C154 128 127 150 90 162C53 150 26 128 26 88V42Z" fill="#0F1D3A" stroke="#38BDF8" stroke-width="5.5" stroke-linejoin="round"/><circle cx="90" cy="86" r="34" fill="#0B1326" stroke="#38BDF8" stroke-width="3.6"/><ellipse cx="90" cy="86" rx="16" ry="34" fill="none" stroke="#38BDF8" stroke-width="2.6"/><line x1="56" y1="86" x2="124" y2="86" stroke="#38BDF8" stroke-width="2.6"/><circle cx="118" cy="112" r="16" fill="#0D1F1C" stroke="#10B981" stroke-width="3.4"/><path d="M111 112L116 117L126 107" fill="none" stroke="#10B981" stroke-width="3.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

export const ENCODED_BRAND_ICON_DATA_URI = `data:image/svg+xml;utf8,${encodeURIComponent(RAW_BRAND_ICON_SVG)}`;

export const MCP_SERVER_INFO = Object.freeze({
  name: 'b2b-domain-contact-enricher-mcp',
  title: 'RevClamp ContactPulse - B2B Domain Contact, RFC 9116 & Deliverability Enricher',
  version: PKG_VERSION,
  description:
    'Deterministic B2B domain contact, RFC 9116 /.well-known/security.txt, Schema.org ContactPoint, and DNS-over-HTTPS MX/SPF/DMARC deliverability enricher. Independent B2B intelligence tool by RevClamp.',
  websiteUrl: 'https://revclamp.com',
  icons: [
    {
      src: ENCODED_BRAND_ICON_DATA_URI,
      mimeType: 'image/svg+xml',
      sizes: ['any'],
    },
    {
      src: 'https://raw.githubusercontent.com/lhphong09t2/revclamp-mcp/main/products/b2b-domain-contact-enricher-mcp/assets/icon-180.png',
      mimeType: 'image/png',
      sizes: ['180x180'],
    },
    {
      src: 'https://raw.githubusercontent.com/lhphong09t2/revclamp-mcp/main/products/b2b-domain-contact-enricher-mcp/assets/icon-32.png',
      mimeType: 'image/png',
      sizes: ['32x32'],
    },
  ],
});

const READ_ONLY_TOOL_ANNOTATIONS = Object.freeze({
  readOnlyHint: true,
  idempotentHint: true,
  destructiveHint: false,
  openWorldHint: true,
});

export const MCP_TOOLS_MANIFEST = Object.freeze([
  {
    name: 'resolve_b2b_domain_contacts',
    title: 'Resolve B2B Domain Role Contacts & Deliverability Posture',
    description:
      'Enriches 1 to 25 B2B domains (e.g. "stripe.com, linear.app, cloudflare.com") with role-classified emails (SECURITY, PRIVACY_DPO, BILLING_FINANCE, LEGAL, SUPPORT, SALES, PRESS, GENERAL), RFC 9116 /.well-known/security.txt disclosures, verified social links, and DNS-over-HTTPS MX/SPF/DMARC deliverability grades.',
    annotations: READ_ONLY_TOOL_ANNOTATIONS,
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          title: 'Target B2B Domain(s) or URL',
          type: 'string',
          maxLength: 1024,
          description:
            'Single domain or comma/space-separated B2B domains (e.g. "stripe.com, linear.app, cloudflare.com").',
        },
        domain: {
          title: 'Target B2B Domain (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query (single B2B domain, e.g. "stripe.com").',
        },
        domains: {
          title: 'Target B2B Domains Array or CSV (Alias)',
          type: ['array', 'string'],
          items: { type: 'string' },
          description: 'Alias for query (array of B2B domains or comma-separated string).',
        },
        url: {
          title: 'Target B2B URL (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query (B2B website URL, e.g. "https://stripe.com").',
        },
        company: {
          title: 'Target Company Name or Domain (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query (company name or domain, e.g. "Stripe" or "stripe.com").',
        },
        roleFilter: {
          title: 'Contact Role Filter (Optional)',
          type: 'string',
          enum: ['ANY', ...SUPPORTED_CONTACT_ROLES],
          default: 'ANY',
          description: 'Filter extracted contacts by functional B2B department role.',
        },
        includeDnsPosture: {
          title: 'Include DNS MX / SPF / DMARC Posture',
          type: 'boolean',
          default: true,
          description: 'Whether to include MX gateway, SPF, and DMARC deliverability posture.',
        },
        includeSecurityTxt: {
          title: 'Include RFC 9116 security.txt Inspection',
          type: 'boolean',
          default: true,
          description: 'Whether to include RFC 9116 /.well-known/security.txt disclosures.',
        },
        limit: {
          title: 'Max Domain Profiles per Call',
          type: 'integer',
          minimum: 1,
          maximum: 25,
          default: 5,
          description: 'Maximum number of enriched B2B domain profiles to return (1 to 25).',
        },
        maxResults: {
          title: 'Max Domain Profiles per Call (Alias)',
          type: 'integer',
          minimum: 1,
          maximum: 25,
          deprecated: true,
          description: 'Alias for limit (1 to 25).',
        },
        max_results: {
          title: 'Max Domain Profiles per Call (Snake-Case Alias)',
          type: 'integer',
          minimum: 1,
          maximum: 25,
          deprecated: true,
          description: 'Alias for limit (1 to 25).',
        },
        useSampleFixtures: {
          title: 'Use Deterministic Sample Fixtures (Optional)',
          type: 'boolean',
          default: false,
          description: 'When true, prefer deterministic offline sample fixtures for curated domains.',
        },
        pageToken: {
          title: 'Pagination Cursor Token (Optional)',
          type: 'string',
          maxLength: 2048,
          description: 'Opaque deterministic continuation cursor (rcd1_...) returned by a previous call.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'inspect_domain_dns_and_security_txt',
    title: 'Inspect Domain DNS MX/SPF/DMARC & RFC 9116 security.txt',
    description:
      'Performs a focused RFC 9116 /.well-known/security.txt compliance audit and DNS-over-HTTPS MX, SPF (v=spf1), and DMARC (_dmarc) deliverability posture inspection for a single B2B domain.',
    annotations: READ_ONLY_TOOL_ANNOTATIONS,
    inputSchema: {
      type: 'object',
      properties: {
        domain: {
          title: 'Target B2B Domain',
          type: 'string',
          maxLength: 256,
          description: 'Target B2B domain (e.g. "stripe.com", "cloudflare.com", "linear.app").',
        },
        query: {
          title: 'Target B2B Domain (Alias)',
          type: 'string',
          maxLength: 256,
          description: 'Alias for domain.',
        },
        domains: {
          title: 'Target B2B Domain Array or CSV (Alias)',
          type: ['array', 'string'],
          items: { type: 'string' },
          description: 'Alias for domain.',
        },
        company: {
          title: 'Target Company Name or Domain (Alias)',
          type: 'string',
          maxLength: 256,
          description: 'Alias for domain (e.g. "Stripe" or "stripe.com").',
        },
        url: {
          title: 'Target B2B URL (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for domain (e.g. "https://stripe.com").',
        },
        useSampleFixtures: {
          title: 'Use Deterministic Sample Fixtures (Optional)',
          type: 'boolean',
          default: false,
          description: 'When true, prefer deterministic offline sample fixtures for curated domains.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'verify_email_deliverability_posture',
    title: 'Verify B2B Email Deliverability Posture & Role Classification',
    description:
      'Evaluates a B2B email address or domain against MX gateway availability, SPF qualifier strictness (-all vs ~all), DMARC enforcement policy (p=reject / quarantine / none), false-positive tracker/asset filtering, and 8-role functional classification.',
    annotations: READ_ONLY_TOOL_ANNOTATIONS,
    inputSchema: {
      type: 'object',
      properties: {
        email: {
          title: 'Target B2B Email or Domain',
          type: 'string',
          maxLength: 320,
          description: 'B2B email address (e.g. "security@stripe.com") or domain ("stripe.com").',
        },
        domain: {
          title: 'Target B2B Domain (Optional)',
          type: 'string',
          maxLength: 256,
          description: 'Optional domain when email is omitted.',
        },
        domains: {
          title: 'Target B2B Domain Array or CSV (Alias)',
          type: ['array', 'string'],
          items: { type: 'string' },
          description: 'Alias for domain.',
        },
        company: {
          title: 'Target Company Name or Domain (Alias)',
          type: 'string',
          maxLength: 256,
          description: 'Alias for domain.',
        },
        query: {
          title: 'Target Email or Domain (Alias)',
          type: 'string',
          maxLength: 320,
          description: 'Alias for email/domain.',
        },
        url: {
          title: 'Target B2B URL (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for domain.',
        },
        useSampleFixtures: {
          title: 'Use Deterministic Sample Fixtures (Optional)',
          type: 'boolean',
          default: false,
          description: 'When true, prefer deterministic offline sample fixtures for curated domains.',
        },
      },
      additionalProperties: false,
    },
  },
]);

export function truncateMcpResponseEnvelope(
  requestId,
  structuredPayload,
  maxBytes = MCP_MAX_ENVELOPE_BYTES
) {
  const buildEnvelope = (payload) => {
    const jsonText = JSON.stringify(payload);
    return {
      jsonrpc: '2.0',
      id: requestId,
      result: {
        content: [{ type: 'text', text: jsonText }],
        structuredContent: payload,
        isError: payload?.ok === false,
      },
    };
  };

  const working = JSON.parse(JSON.stringify(structuredPayload));
  const cursorResumeContext = working.cursorResumeContext || null;
  delete working.cursorResumeContext;

  let env = buildEnvelope(working);
  if (Buffer.byteLength(JSON.stringify(env), 'utf8') <= maxBytes) {
    return env;
  }

  // Tier 1: Pop tail items and rewind nextPageToken so zero items are lost
  if (Array.isArray(working.items) && working.items.length > 1) {
    const originalItemCount = working.items.length;
    const originalNextToken = working.pagination?.nextPageToken || null;
    while (
      working.items.length > 1 &&
      Buffer.byteLength(JSON.stringify(buildEnvelope(working)), 'utf8') > maxBytes
    ) {
      working.items.pop();
    }
    if (working.items.length < originalItemCount) {
      working.truncatedForMcpByteCeiling = true;
      working.omittedItemCount = originalItemCount - working.items.length;
    }
    if (working.pagination && cursorResumeContext) {
      working.pagination.nextPageToken = computeRewoundCursorForDeliveredPrefix(
        cursorResumeContext,
        working.items.length,
        originalNextToken
      );
      working.pagination.hasMore = Boolean(working.pagination.nextPageToken);
      working.pagination.paginationStatus = 'TRUNCATED_HAS_MORE_MID_PAGE';
    }
    working.reason = `Enriched and delivered ${working.items.length} B2B domain contact profile(s) (truncated to fit 30000-byte MCP envelope; resume via nextPageToken).`;
  }

  env = buildEnvelope(working);
  if (Buffer.byteLength(JSON.stringify(env), 'utf8') <= maxBytes) {
    return env;
  }

  // Tier 2: Prune oversized single-item contacts or UTF-8 safe string truncation on reason/text fallback
  working.truncatedForMcpByteCeiling = true;
  if (Array.isArray(working.items) && working.items.length === 1 && Array.isArray(working.items[0]?.contacts)) {
    while (
      working.items[0].contacts.length > 1 &&
      Buffer.byteLength(JSON.stringify(buildEnvelope(working)), 'utf8') > maxBytes
    ) {
      working.items[0].contacts.pop();
    }
  }
  if (typeof working.reason === 'string') {
    working.reason = sliceUtf8Safe(working.reason, 240);
  }
  return buildEnvelope(working);
}

export function validateMcpToolArguments(toolName, rawArgs) {
  if (rawArgs !== undefined && (typeof rawArgs !== 'object' || rawArgs === null || Array.isArray(rawArgs))) {
    return { ok: false, errorCode: 'INVALID_INPUT', reason: 'Tool arguments must be a JSON object' };
  }
  const args = { ...(rawArgs || {}) };
  const serialized = JSON.stringify(args);
  if (containsLiveSecretToken(serialized)) {
    return { ok: false, errorCode: 'INVALID_INPUT', reason: 'Arguments rejected by Zero-Trust live secret guard' };
  }
  const manifest = MCP_TOOLS_MANIFEST.find((t) => t.name === toolName);
  if (!manifest) {
    return { ok: false, errorCode: 'INVALID_INPUT', reason: `Unknown MCP tool '${toolName}'` };
  }
  const allowedProps = new Set(Object.keys(manifest.inputSchema.properties || {}));
  for (const key of Object.keys(args)) {
    if (!allowedProps.has(key)) {
      return { ok: false, errorCode: 'INVALID_INPUT', reason: `Unknown argument '${key}' for tool '${toolName}'` };
    }
  }

  for (const strKey of ['query', 'domain', 'company', 'url', 'email', 'roleFilter', 'pageToken']) {
    if (args[strKey] !== undefined && typeof args[strKey] !== 'string') {
      return {
        ok: false,
        errorCode: 'INVALID_INPUT',
        reason: `Parameter '${strKey}' must be a string`,
      };
    }
  }
  if (
    args.domains !== undefined &&
    typeof args.domains !== 'string' &&
    !Array.isArray(args.domains)
  ) {
    return {
      ok: false,
      errorCode: 'INVALID_INPUT',
      reason: "Parameter 'domains' must be an array of strings or a comma-separated string",
    };
  }
  for (const boolKey of ['includeDnsPosture', 'includeSecurityTxt', 'useSampleFixtures']) {
    if (args[boolKey] !== undefined && typeof args[boolKey] !== 'boolean') {
      return {
        ok: false,
        errorCode: 'INVALID_INPUT',
        reason: `Parameter '${boolKey}' must be a boolean`,
      };
    }
  }

  const aliasNorm = normalizeContactPulseInputAliases(
    args,
    toolName === 'verify_email_deliverability_posture' ? 'verify' : 'batch'
  );
  if (!aliasNorm.ok) {
    return {
      ok: false,
      errorCode: aliasNorm.errorCode || 'INVALID_INPUT',
      reason: aliasNorm.reason,
    };
  }
  Object.assign(args, aliasNorm.normalized);

  if (toolName === 'resolve_b2b_domain_contacts') {
    if (args.limit !== undefined || args.maxResults !== undefined || args.max_results !== undefined) {
      const limCheck = validateBoundedIntegerParam(
        args.limit ?? args.maxResults ?? args.max_results,
        5,
        1,
        MCP_MAX_ITEMS_LIMIT,
        'limit'
      );
      if (!limCheck.ok) {
        return { ok: false, errorCode: 'INVALID_INPUT', reason: limCheck.reason };
      }
      args.limit = limCheck.value;
    }
    const hasQuery = typeof args.query === 'string' && args.query.trim().length > 0;
    const hasDomains = Array.isArray(args.domains) && args.domains.length > 0;
    if (!hasQuery && !hasDomains) {
      return {
        ok: false,
        errorCode: 'INVALID_INPUT',
        reason: "Missing required target domain parameter ('query', 'domain', 'domains', 'company', or 'url')",
      };
    }
  } else if (toolName === 'inspect_domain_dns_and_security_txt') {
    const hasDomain = typeof args.domain === 'string' && args.domain.trim().length > 0;
    if (!hasDomain) {
      return {
        ok: false,
        errorCode: 'INVALID_INPUT',
        reason: "Missing required target domain parameter ('domain', 'query', 'company', or 'url')",
      };
    }
  } else if (toolName === 'verify_email_deliverability_posture') {
    const hasEmail = typeof args.email === 'string' && args.email.trim().length > 0;
    const hasDomain = typeof args.domain === 'string' && args.domain.trim().length > 0;
    const hasQuery = typeof args.query === 'string' && args.query.trim().length > 0;
    if (!hasEmail && !hasDomain && !hasQuery) {
      return {
        ok: false,
        errorCode: 'INVALID_INPUT',
        reason: "Missing required parameter ('email', 'domain', 'query', 'company', or 'url')",
      };
    }
  }
  return { ok: true, args };
}

export async function handleMcpJsonRpcRequest(req, options = {}) {
  if (!req || typeof req !== 'object' || Array.isArray(req) || req.jsonrpc !== '2.0') {
    return {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Invalid JSON-RPC 2.0 request envelope' },
    };
  }

  const hasId = Object.prototype.hasOwnProperty.call(req, 'id') && req.id !== undefined;
  const reqId = hasId ? req.id : null;
  if (hasId && reqId !== null && typeof reqId !== 'string' && typeof reqId !== 'number') {
    return {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Invalid request id type' },
    };
  }
  if (typeof reqId === 'string' && Buffer.byteLength(reqId, 'utf8') > MCP_MAX_REQ_ID_BYTES) {
    return {
      jsonrpc: '2.0',
      id: null,
      error: { code: -32600, message: 'Request id exceeds maximum byte length' },
    };
  }

  const method = String(req.method || '');
  if (!hasId || method.startsWith('notifications/')) {
    return null;
  }

  if (method === 'ping') {
    return { jsonrpc: '2.0', id: reqId, result: {} };
  }

  if (method === 'initialize') {
    const clientVer = String(req.params?.protocolVersion || '2025-06-18');
    const negotiated = SUPPORTED_MCP_PROTOCOL_VERSIONS.includes(clientVer)
      ? clientVer
      : SUPPORTED_MCP_PROTOCOL_VERSIONS[0];
    return {
      jsonrpc: '2.0',
      id: reqId,
      result: {
        protocolVersion: negotiated,
        capabilities: {
          tools: { listChanged: false },
        },
        serverInfo: MCP_SERVER_INFO,
      },
    };
  }

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0',
      id: reqId,
      result: {
        tools: MCP_TOOLS_MANIFEST,
      },
    };
  }

  if (method === 'tools/call') {
    const toolName = String(req.params?.name || '').trim();
    const val = validateMcpToolArguments(toolName, req.params?.arguments);
    if (!val.ok) {
      return truncateMcpResponseEnvelope(reqId, {
        ok: false,
        status: 'INVALID_INPUT',
        errorCode: val.errorCode || 'INVALID_INPUT',
        reason: val.reason,
      });
    }

    const args = val.args;
    if (toolName === 'resolve_b2b_domain_contacts') {
      const batchRes = await resolveB2bDomainContactsBatch(args, options);
      return truncateMcpResponseEnvelope(reqId, batchRes);
    }

    if (toolName === 'inspect_domain_dns_and_security_txt') {
      const target = String(args.domain || args.query || args.company || args.url || '').trim();
      const singleRes = await enrichSingleB2bDomain(target, {
        includeDnsPosture: true,
        includeSecurityTxt: true,
        fetchImpl: options?.fetchImpl || globalThis.fetch,
        dnsLookup: options?.dnsLookup,
        nowMs: options?.nowMs || Date.now(),
        preferCurated: options?.preferCurated === true || args?.useSampleFixtures === true,
      });
      if (!singleRes.ok) {
        return truncateMcpResponseEnvelope(reqId, singleRes);
      }
      return truncateMcpResponseEnvelope(reqId, {
        ok: true,
        status: singleRes.profile.emptyResult ? 'EMPTY_RESULT' : 'SUCCEEDED',
        domain: singleRes.profile.domain,
        organizationName: singleRes.profile.organizationName,
        dataSource: singleRes.profile.dataSource,
        emptyResult: singleRes.profile.emptyResult,
        billable: singleRes.profile.billable,
        emailGatewayProvider: singleRes.profile.emailGatewayProvider,
        deliverabilityGrade: singleRes.profile.deliverabilityGrade,
        dmarcPolicy: singleRes.profile.dmarcPolicy,
        spfAllMechanism: singleRes.profile.spfAllMechanism,
        securityTxtStatus: singleRes.profile.securityTxtStatus,
        dnsPosture: singleRes.profile.dnsPosture,
        securityTxt: singleRes.profile.securityTxt,
      });
    }

    if (toolName === 'verify_email_deliverability_posture') {
      const postureRes = await verifyEmailDeliverabilityPosture(args, options);
      return truncateMcpResponseEnvelope(reqId, postureRes);
    }

    return truncateMcpResponseEnvelope(reqId, {
      ok: false,
      status: 'INVALID_INPUT',
      reason: `Unsupported tool '${toolName}'`,
    });
  }

  return {
    jsonrpc: '2.0',
    id: reqId,
    error: { code: -32601, message: `Method not found: ${method}` },
  };
}
