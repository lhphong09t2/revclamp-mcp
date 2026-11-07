/**
 * Model Context Protocol (MCP) JSON-RPC 2.0 Server (src/mcp_server.mjs)
 *
 * Exposes three deterministic tools sharing the 5-in-1 Unified ATS Job & Hiring Signal engine:
 *   - `search_ats_job_postings`: Resolves a company slug or career URL across Greenhouse, Workday CXS,
 *     Ashby, Lever, and SmartRecruiters and extracts normalized job postings (`limit <= 25`,
 *     `pageToken` continuation, full JSON-RPC UTF-8 envelope `<= 30,000` bytes with 4-tier
 *     surrogate-safe degradation and automatic mid-page cursor rewind).
 *   - `resolve_company_ats_board`: Resolves a company slug or career page URL into its canonical
 *     ATS provider (`GREENHOUSE`, `WORKDAY`, `ASHBY`, `LEVER`, `SMARTRECRUITERS`) and public API metadata.
 *   - `get_ats_job_posting_detail`: Fetches detailed metadata for a single normalized job posting
 *     by `jobId` (`PROVIDER:companySlug:rawJobId`) or `{ query, jobId }`, including Workday CXS
 *     and SmartRecruiters detail enrichment, compensation breakdown, and `techStackKeywords`.
 */

import fs from 'node:fs';
import {
  resolveAtsBoardTarget,
  getAtsJobPostingDetail,
  normalizeTalentPulseInputAliases,
  SUPPORTED_ATS_PROVIDERS,
  JOB_ID_RE,
  MAX_QUERY_LENGTH,
  DEFAULT_RUN_DEADLINE_MS,
  decodePaginationCursor,
  validateBoundedIntegerParam,
  computeRewoundCursorForDeliveredPrefix,
} from './ats_client.mjs';
import { runUnifiedAtsJobsActor } from './apify_actor.mjs';

const PKG_VERSION = JSON.parse(
  fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version;

export const MCP_MAX_ENVELOPE_BYTES = 30000;
export const MCP_MAX_ITEMS_LIMIT = 25;
export const MCP_MAX_REQ_ID_BYTES = 256;

export const SUPPORTED_MCP_PROTOCOL_VERSIONS = Object.freeze([
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
]);

const RAW_BRAND_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img" aria-labelledby="rc-title"><title id="rc-title">RevClamp TalentPulse</title><defs><linearGradient id="rc-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#111C38"/><stop offset="100%" stop-color="#090E1D"/></linearGradient><linearGradient id="rc-edge" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#06B6D4"/><stop offset="100%" stop-color="#10B981"/></linearGradient></defs><rect width="64" height="64" fill="#0B1020"/><path d="M32 10L50 16.5V31C50 42.5 42.5 49.5 32 54C21.5 49.5 14 42.5 14 31V16.5Z" fill="url(#rc-fill)" stroke="url(#rc-edge)" stroke-width="2.4" stroke-linejoin="round"/><path d="M32 12.8L47.4 18.4V30.8C47.4 40.4 41 46.7 32 50.8C23 46.7 16.6 40.4 16.6 30.8V18.4Z" fill="none" stroke="#F59E0B" stroke-opacity="0.45" stroke-width="0.9" stroke-linejoin="round"/><path d="M28 24.2V21.8C28 20.8 28.8 20 29.8 20H34.2C35.2 20 36 20.8 36 21.8V24.2" fill="none" stroke="#F8FAFC" stroke-width="1.8" stroke-linecap="round"/><rect x="21.5" y="24.2" width="21" height="14.6" rx="2.8" fill="#0B1020" stroke="#F8FAFC" stroke-width="1.8"/><path d="M24.2 31.6H27.4L29.2 28L32 34.8L34.2 29.8L35.8 31.6H39.8" fill="none" stroke="#10B981" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/><circle cx="32" cy="16.4" r="1.5" fill="#F59E0B"/><circle cx="20.4" cy="19.7" r="1.5" fill="#06B6D4"/><circle cx="43.6" cy="19.7" r="1.5" fill="#06B6D4"/><circle cx="25" cy="42.2" r="1.5" fill="#10B981"/><circle cx="39" cy="42.2" r="1.5" fill="#10B981"/></svg>`;

export const ENCODED_BRAND_ICON_DATA_URI = `data:image/svg+xml;utf8,${encodeURIComponent(RAW_BRAND_ICON_SVG)}`;

export const MCP_SERVER_INFO = Object.freeze({
  name: 'unified-ats-jobs-mcp',
  title: 'RevClamp TalentPulse - Unified 5-in-1 B2B ATS Job & Hiring Signal Feed',
  version: PKG_VERSION,
  description:
    'Extract normalized B2B job postings, compensation ranges, workplace classification (REMOTE/HYBRID/ONSITE), and tech-stack hiring signals across Greenhouse, Workday CXS, Ashby, Lever, and SmartRecruiters. Independent hiring intelligence tool by RevClamp; not affiliated with any ATS vendor.',
  websiteUrl: 'https://revclamp.com',
  icons: [
    {
      src: ENCODED_BRAND_ICON_DATA_URI,
      mimeType: 'image/svg+xml',
      sizes: ['any'],
    },
    {
      src: 'https://raw.githubusercontent.com/lhphong09t2/revclamp-mcp/main/products/unified-ats-jobs-mcp/assets/icon-180.png',
      mimeType: 'image/png',
      sizes: ['180x180'],
    },
    {
      src: 'https://raw.githubusercontent.com/lhphong09t2/revclamp-mcp/main/products/unified-ats-jobs-mcp/assets/icon-32.png',
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
    name: 'search_ats_job_postings',
    title: 'Search Unified 5-in-1 B2B ATS Job Postings',
    description:
      'Resolves a company slug (e.g. "linear", "stripe", "nvidia", "zoox", "BoschGroup") or career board URL across Greenhouse, Workday CXS, Ashby, Lever, and SmartRecruiters and returns normalized job postings with compensation ranges, workplaceType (REMOTE/HYBRID/ONSITE), seniorityLevel, techStackKeywords, and prompt-injection sanitized excerpts.',
    annotations: READ_ONLY_TOOL_ANNOTATIONS,
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          title: 'Company Slug, Brand Name, or Career URL',
          type: 'string',
          maxLength: 512,
          description:
            'Company slug (e.g. "linear", "stripe", "nvidia", "zoox", "BoschGroup") or direct career board URL.',
        },
        company: {
          title: 'Company Name or Slug (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query (company name or slug, e.g. "stripe", "linear").',
        },
        domain: {
          title: 'Company Domain (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query (company domain, e.g. "stripe.com", "linear.app").',
        },
        url: {
          title: 'Career Board URL (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query / careerUrl (direct career board URL).',
        },
        provider: {
          title: 'ATS Provider Override (Optional)',
          type: 'string',
          enum: ['AUTO', ...SUPPORTED_ATS_PROVIDERS],
          default: 'AUTO',
          description:
            'Optional explicit ATS provider override (AUTO, GREENHOUSE, WORKDAY, ASHBY, LEVER, SMARTRECRUITERS).',
        },
        companySlug: {
          title: 'Explicit Company Slug (Optional)',
          type: 'string',
          maxLength: 128,
          description: 'Optional explicit ATS board slug when paired with provider.',
        },
        careerUrl: {
          title: 'Direct Career Board URL (Optional)',
          type: 'string',
          maxLength: 512,
          description: 'Optional direct HTTPS URL to a supported ATS career board.',
        },
        workdayTenant: {
          title: 'Workday Tenant Identifier (Optional)',
          type: 'string',
          maxLength: 128,
          description: 'Optional Workday tenant identifier when provider is WORKDAY.',
        },
        workdaySite: {
          title: 'Workday Career Site Identifier (Optional)',
          type: 'string',
          maxLength: 128,
          description: 'Optional Workday career site path segment (e.g. NVIDIAExternalCareerSite).',
        },
        wdInstance: {
          title: 'Workday Instance Subdomain (Optional)',
          type: 'string',
          enum: ['wd1', 'wd2', 'wd3', 'wd4', 'wd5'],
          description: 'Optional Workday CXS cluster subdomain (wd1..wd5).',
        },
        searchKeyword: {
          title: 'Role or Tech Keyword Filter (Optional)',
          type: 'string',
          maxLength: 128,
          description:
            'Case-insensitive keyword filter across job title, department, location, and techStackKeywords.',
        },
        workplaceType: {
          title: 'Workplace Type Filter (Optional)',
          type: 'string',
          enum: ['ANY', 'REMOTE', 'HYBRID', 'ONSITE'],
          default: 'ANY',
          description: 'Optional workplace classification filter.',
        },
        departmentKeyword: {
          title: 'Department Filter (Optional)',
          type: 'string',
          maxLength: 128,
          description: 'Optional case-insensitive substring filter on department name.',
        },
        countryCode: {
          title: 'Country Filter (Optional)',
          type: 'string',
          maxLength: 16,
          description: 'Optional 2-letter ISO 3166-1 alpha-2 country code filter (e.g. "US", "DE", "GB", or "ALL").',
        },
        country: {
          title: 'Country Filter (Alias)',
          type: 'string',
          maxLength: 16,
          description: 'Alias for countryCode (2-letter ISO country code, e.g. "US", "DE", "GB").',
        },
        region: {
          title: 'Region / Country Filter (Alias)',
          type: 'string',
          maxLength: 16,
          description: 'Alias for countryCode (2-letter ISO country code, e.g. "US", "DE", "GB").',
        },
        limit: {
          title: 'Max Job Postings per Call',
          type: 'integer',
          minimum: 1,
          maximum: 25,
          default: 10,
          description: 'Maximum number of normalized job postings to return in one call (1 to 25).',
        },
        maxResults: {
          title: 'Max Job Postings per Call (Alias)',
          type: 'integer',
          minimum: 1,
          maximum: 25,
          deprecated: true,
          description: 'Alias for limit (1 to 25).',
        },
        max_results: {
          title: 'Max Job Postings per Call (Snake-Case Alias)',
          type: 'integer',
          minimum: 1,
          maximum: 25,
          deprecated: true,
          description: 'Snake_case alias for limit (1 to 25).',
        },
        pageToken: {
          title: 'Pagination Cursor Token (Optional)',
          type: 'string',
          maxLength: 2048,
          description:
            'Optional opaque deterministic continuation cursor (rtp1_...) returned by a previous call.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'resolve_company_ats_board',
    title: 'Resolve Company ATS Board & Provider',
    description:
      'Resolves a company slug, brand name, or career page URL into its canonical ATS provider (GREENHOUSE, WORKDAY, ASHBY, LEVER, SMARTRECRUITERS), normalized companySlug, and public API endpoint metadata without fetching the full job list.',
    annotations: READ_ONLY_TOOL_ANNOTATIONS,
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          title: 'Company Slug, Brand Name, or Career URL',
          type: 'string',
          maxLength: 512,
          description:
            'Company slug or career URL to resolve (e.g. "linear", "stripe", "nvidia", "zoox", "BoschGroup").',
        },
        company: {
          title: 'Company Name or Slug (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query (company name or slug, e.g. "stripe", "linear").',
        },
        domain: {
          title: 'Company Domain (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query (company domain, e.g. "stripe.com", "linear.app").',
        },
        url: {
          title: 'Career Board URL (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query / careerUrl (direct career board URL).',
        },
        provider: {
          title: 'ATS Provider Override (Optional)',
          type: 'string',
          enum: ['AUTO', ...SUPPORTED_ATS_PROVIDERS],
          default: 'AUTO',
          description: 'Optional explicit ATS provider hint.',
        },
        companySlug: {
          title: 'Explicit Company Slug (Optional)',
          type: 'string',
          maxLength: 128,
          description: 'Optional explicit ATS board slug.',
        },
        careerUrl: {
          title: 'Direct Career Board URL (Optional)',
          type: 'string',
          maxLength: 512,
          description: 'Optional direct HTTPS URL to a supported ATS career board.',
        },
        workdayTenant: {
          title: 'Workday Tenant Identifier (Optional)',
          type: 'string',
          maxLength: 128,
          description: 'Optional Workday tenant identifier when provider is WORKDAY.',
        },
        workdaySite: {
          title: 'Workday Career Site Identifier (Optional)',
          type: 'string',
          maxLength: 128,
          description: 'Optional Workday career site path segment.',
        },
        wdInstance: {
          title: 'Workday Instance Subdomain (Optional)',
          type: 'string',
          enum: ['wd1', 'wd2', 'wd3', 'wd4', 'wd5'],
          description: 'Optional Workday CXS cluster subdomain (wd1..wd5).',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'get_ats_job_posting_detail',
    title: 'Get Normalized ATS Job Posting Detail',
    description:
      'Fetches detailed metadata for a single ATS job posting by canonical jobId (e.g. "ASHBY:linear:403ef663..." or "SMARTRECRUITERS:BoschGroup:744000159859639"), including Workday CXS or SmartRecruiters detail enrichment, compensation breakdown, and techStackKeywords.',
    annotations: READ_ONLY_TOOL_ANNOTATIONS,
    inputSchema: {
      type: 'object',
      properties: {
        jobId: {
          title: 'Canonical Job ID or Raw Job ID',
          type: 'string',
          maxLength: 256,
          description:
            'Canonical jobId (PROVIDER:companySlug:rawJobId) or raw job identifier when paired with query/provider.',
        },
        query: {
          title: 'Company Slug or Career URL (Optional)',
          type: 'string',
          maxLength: 512,
          description:
            'Optional company slug or career URL when jobId is passed as a raw provider ID.',
        },
        company: {
          title: 'Company Name or Slug (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query / companySlug.',
        },
        domain: {
          title: 'Company Domain (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query (company domain, e.g. "stripe.com").',
        },
        url: {
          title: 'Career Board URL (Alias)',
          type: 'string',
          maxLength: 512,
          description: 'Alias for query / careerUrl.',
        },
        careerUrl: {
          title: 'Direct Career Board URL (Optional)',
          type: 'string',
          maxLength: 512,
          description: 'Optional direct HTTPS URL to a supported ATS career board.',
        },
        provider: {
          title: 'ATS Provider (Optional)',
          type: 'string',
          enum: ['AUTO', ...SUPPORTED_ATS_PROVIDERS],
          default: 'AUTO',
          description: 'Optional ATS provider override.',
        },
        companySlug: {
          title: 'Company Slug (Optional)',
          type: 'string',
          maxLength: 128,
          description: 'Optional explicit company slug.',
        },
      },
      required: ['jobId'],
      additionalProperties: false,
    },
  },
]);

/**
 * Slices a UTF-16 string to fit within `maxUtf8Bytes` without splitting surrogate pairs
 * or multi-byte UTF-8 sequences.
 *
 * @param {string} rawStr
 * @param {number} maxUtf8Bytes
 * @returns {string}
 */
export function sliceUtf8Safe(rawStr, maxUtf8Bytes) {
  const s = String(rawStr ?? '');
  if (!s || maxUtf8Bytes <= 0) return '';
  if (Buffer.byteLength(s, 'utf8') <= maxUtf8Bytes) return s;

  let out = '';
  let usedBytes = 0;
  for (const codePointChar of s) {
    const charBytes = Buffer.byteLength(codePointChar, 'utf8');
    if (usedBytes + charBytes > maxUtf8Bytes) {
      break;
    }
    out += codePointChar;
    usedBytes += charBytes;
  }
  return out;
}

/**
 * Enforces the 30,000-byte UTF-8 MCP payload ceiling (`<= 32,768` bytes) across the
 * **entire serialized JSON-RPC 2.0 response envelope** via a 4-tier deterministic
 * degradation pipeline. When items are popped (`omittedCount > 0`), rewinds
 * `pagination.nextPageToken` via `cursorResumeContext`.
 *
 * @param {object} payload
 * @param {number} [maxBytes=30000]
 * @param {{reqId?: string|number|null, isError?: boolean, cursorResumeContext?: object|null}} [envelopeContext]
 * @param {boolean} [isErrorArg=false]
 * @returns {object}
 */
export function truncateMcpResponseEnvelope(
  payload,
  maxBytes = MCP_MAX_ENVELOPE_BYTES,
  envelopeContext = {},
  isErrorArg = false
) {
  const parsedMaxBytes =
    maxBytes !== undefined && maxBytes !== null && Number.isFinite(Number(maxBytes))
      ? Number(maxBytes)
      : MCP_MAX_ENVELOPE_BYTES;
  const safeMaxBytes = Math.min(32768, Math.max(2048, parsedMaxBytes));
  const isContextObj =
    envelopeContext !== null &&
    typeof envelopeContext === 'object' &&
    !Array.isArray(envelopeContext);
  const reqId = isContextObj
    ? envelopeContext.reqId !== undefined
      ? envelopeContext.reqId
      : 999999
    : envelopeContext !== undefined
      ? envelopeContext
      : 999999;
  const isError = isContextObj ? Boolean(envelopeContext.isError) : Boolean(isErrorArg);

  const rawClone = JSON.parse(JSON.stringify(payload ?? {}));
  const cursorResumeContext =
    (isContextObj && envelopeContext.cursorResumeContext) ||
    rawClone.pagination?.cursorResumeContext ||
    null;
  if (rawClone.pagination && typeof rawClone.pagination === 'object') {
    delete rawClone.pagination.cursorResumeContext;
  }

  const originalItemCount = Array.isArray(rawClone.items) ? rawClone.items.length : 0;
  const originalNextPageToken = rawClone.pagination?.nextPageToken || null;

  const buildOrderedPayload = (cand, tier, omittedCount) => {
    const truncated = tier > 0;
    const returnedCount = Array.isArray(cand.items)
      ? cand.items.length
      : cand.boardTarget
        ? 1
        : 0;

    if (cand.pagination && typeof cand.pagination === 'object') {
      delete cand.pagination.cursorResumeContext;
      if ((omittedCount > 0 || tier >= 4) && cursorResumeContext) {
        const rewoundToken = computeRewoundCursorForDeliveredPrefix(
          cursorResumeContext,
          returnedCount,
          originalNextPageToken
        );
        cand.pagination.nextPageToken = rewoundToken;
        cand.pagination.hasMore = Boolean(rewoundToken);
        cand.pagination.paginationStatus = rewoundToken
          ? 'TRUNCATED_HAS_MORE_MID_PAGE'
          : 'TRUNCATED_AT_BYTE_CEILING';
      } else {
        cand.pagination.hasMore = Boolean(cand.pagination.nextPageToken);
      }
      if (cand.deliveredCount !== undefined && Array.isArray(cand.items)) {
        cand.deliveredCount = cand.items.length;
      }
    }

    const summary = truncated
      ? `Truncated response to fit ${safeMaxBytes}-byte MCP ceiling (tier ${tier}, returned ${returnedCount}, omitted ${omittedCount} item(s)).`
      : `OK (${returnedCount} item(s) within ${safeMaxBytes}-byte MCP budget).`;

    return {
      summary,
      truncatedForMcpByteCeiling: truncated,
      truncationTier: tier,
      omittedItemCount: omittedCount,
      ...cand,
    };
  };

  const measureFullRpcBytes = (structuredObj) => {
    const textStr = JSON.stringify(structuredObj);
    const fullRpcEnvelope = {
      jsonrpc: '2.0',
      id: reqId,
      result: {
        isError,
        content: [{ type: 'text', text: textStr }],
        structuredContent: structuredObj,
      },
    };
    return Buffer.byteLength(JSON.stringify(fullRpcEnvelope), 'utf8');
  };

  // Tier 0: Fits untouched
  const tier0Obj = buildOrderedPayload(rawClone, 0, 0);
  if (measureFullRpcBytes(tier0Obj) <= safeMaxBytes) {
    return tier0Obj;
  }

  // Tier 1: Pop tail items down to >= 1 while preserving full item fidelity
  const work = JSON.parse(JSON.stringify(rawClone));
  while (Array.isArray(work.items) && work.items.length > 1) {
    const omitted = Math.max(0, originalItemCount - work.items.length);
    const candidate = buildOrderedPayload(work, 1, omitted);
    if (measureFullRpcBytes(candidate) <= safeMaxBytes) {
      return candidate;
    }
    work.items.pop();
  }

  {
    const omitted = Math.max(
      0,
      originalItemCount - (Array.isArray(work.items) ? work.items.length : 0)
    );
    const candidate = buildOrderedPayload(work, 1, omitted);
    if (measureFullRpcBytes(candidate) <= safeMaxBytes) {
      return candidate;
    }
  }

  // Tier 2: Trim untrustedJobContent excerpt to 120 bytes and cap techStackKeywords to 5
  if (Array.isArray(work.items)) {
    for (const item of work.items) {
      if (Array.isArray(item.techStackKeywords) && item.techStackKeywords.length > 5) {
        item.techStackKeywords = item.techStackKeywords.slice(0, 5);
      }
      if (item.untrustedJobContent && typeof item.untrustedJobContent === 'object') {
        item.untrustedJobContent.plainTextExcerpt = sliceUtf8Safe(
          item.untrustedJobContent.plainTextExcerpt,
          120
        );
      }
      if (typeof item.title === 'string') {
        item.title = sliceUtf8Safe(item.title, 120);
      }
      if (typeof item.locationRaw === 'string') {
        item.locationRaw = sliceUtf8Safe(item.locationRaw, 80);
      }
    }
  }
  if (work.detail && typeof work.detail === 'object') {
    if (work.detail.untrustedJobContent && typeof work.detail.untrustedJobContent === 'object') {
      work.detail.untrustedJobContent.plainTextExcerpt = sliceUtf8Safe(
        work.detail.untrustedJobContent.plainTextExcerpt,
        120
      );
    }
  }

  {
    const omitted = Math.max(
      0,
      originalItemCount - (Array.isArray(work.items) ? work.items.length : 0)
    );
    const candidate = buildOrderedPayload(work, 2, omitted);
    if (measureFullRpcBytes(candidate) <= safeMaxBytes) {
      return candidate;
    }
  }

  // Tier 3: Single compact stub item
  if (Array.isArray(work.items) && work.items.length > 0) {
    const first = work.items[0];
    work.items = [
      {
        jobId: first.jobId,
        atsProvider: first.atsProvider,
        companySlug: first.companySlug,
        companyName: sliceUtf8Safe(first.companyName || first.companySlug, 64),
        title: sliceUtf8Safe(first.title || 'Role', 80),
        workplaceType: first.workplaceType || 'UNKNOWN',
        applyUrl: first.applyUrl || null,
      },
    ];
  }
  if (work.detail && typeof work.detail === 'object') {
    work.detail = {
      jobId: work.detail.jobId,
      atsProvider: work.detail.atsProvider,
      companySlug: work.detail.companySlug,
      title: sliceUtf8Safe(work.detail.title || 'Role', 80),
      workplaceType: work.detail.workplaceType || 'UNKNOWN',
      applyUrl: work.detail.applyUrl || null,
    };
  }

  {
    const omitted = Math.max(
      0,
      originalItemCount - (Array.isArray(work.items) ? work.items.length : 0)
    );
    const candidate = buildOrderedPayload(work, 3, omitted);
    if (measureFullRpcBytes(candidate) <= safeMaxBytes) {
      return candidate;
    }
  }

  // Tier 4: Metadata compaction (guaranteed <= safeMaxBytes)
  if (Array.isArray(work.items)) {
    work.items = [];
  }
  if (work.detail && typeof work.detail === 'object') {
    work.detail = {
      jobId: sliceUtf8Safe(work.detail.jobId, 64),
      atsProvider: sliceUtf8Safe(work.detail.atsProvider, 24),
      title: sliceUtf8Safe(work.detail.title || 'Role', 48),
    };
  }
  if (typeof work.reason === 'string') {
    work.reason = sliceUtf8Safe(work.reason, 160);
  }

  const tier4Candidate = buildOrderedPayload(work, 4, originalItemCount);
  if (measureFullRpcBytes(tier4Candidate) <= safeMaxBytes) {
    return tier4Candidate;
  }

  const emergencyWithPagination = buildOrderedPayload(
    {
      ok: Boolean(work.ok),
      status: sliceUtf8Safe(work.status || 'OK', 32),
      items: [],
      ...(rawClone.pagination
        ? {
            pagination: {
              nextPageToken: originalNextPageToken,
              hasMore: Boolean(originalNextPageToken),
              paginationStatus: 'TRUNCATED_AT_BYTE_CEILING',
            },
          }
        : {}),
    },
    4,
    originalItemCount
  );
  if (measureFullRpcBytes(emergencyWithPagination) <= safeMaxBytes) {
    return emergencyWithPagination;
  }

  const emergencyNoToken = {
    summary: `Truncated response to fit ${safeMaxBytes}-byte MCP ceiling (tier 4, returned 0, omitted ${originalItemCount} item(s)).`,
    truncatedForMcpByteCeiling: true,
    truncationTier: 4,
    omittedItemCount: originalItemCount,
    ok: Boolean(work.ok),
    status: sliceUtf8Safe(work.status || 'OK', 32),
    items: [],
    ...(rawClone.pagination
      ? {
          pagination: {
            nextPageToken: null,
            hasMore: false,
            paginationStatus: 'TRUNCATED_AT_BYTE_CEILING',
          },
        }
      : {}),
  };
  if (measureFullRpcBytes(emergencyNoToken) <= safeMaxBytes) {
    return emergencyNoToken;
  }

  const ultraMinimalWithPagination = {
    ok: Boolean(work.ok),
    status: sliceUtf8Safe(work.status || 'OK', 16),
    truncatedForMcpByteCeiling: true,
    truncationTier: 4,
    omittedItemCount: originalItemCount,
    items: [],
    ...(rawClone.pagination
      ? {
          pagination: {
            nextPageToken: null,
            hasMore: false,
          },
        }
      : {}),
  };
  if (measureFullRpcBytes(ultraMinimalWithPagination) <= safeMaxBytes) {
    return ultraMinimalWithPagination;
  }

  return {
    ok: Boolean(work.ok),
    truncatedForMcpByteCeiling: true,
    truncationTier: 4,
    items: [],
  };
}

/**
 * Validates `reqId` per JSON-RPC 2.0 and enforces `<= 256` UTF-8 byte ceiling.
 *
 * @param {unknown} rawId
 * @returns {{valid: boolean, id: string|number|null}}
 */
function validateJsonRpcRequestId(rawId) {
  if (rawId === null) {
    return { valid: true, id: null };
  }
  if (typeof rawId === 'string') {
    if (
      /[\u0000-\u001F\u007F]/.test(rawId) ||
      Buffer.byteLength(rawId, 'utf8') > MCP_MAX_REQ_ID_BYTES ||
      Buffer.byteLength(JSON.stringify(rawId), 'utf8') > MCP_MAX_REQ_ID_BYTES + 2
    ) {
      return { valid: false, id: null };
    }
    return { valid: true, id: rawId };
  }
  if (typeof rawId === 'number' && Number.isFinite(rawId)) {
    const strLen = Buffer.byteLength(String(rawId), 'utf8');
    if (strLen > MCP_MAX_REQ_ID_BYTES) {
      return { valid: false, id: null };
    }
    return { valid: true, id: rawId };
  }
  return { valid: false, id: null };
}

const SEARCH_ALLOWED_ARG_KEYS = new Set([
  'query',
  'company',
  'domain',
  'url',
  'provider',
  'atsProvider',
  'companySlug',
  'careerUrl',
  'workdayTenant',
  'workdaySite',
  'wdInstance',
  'searchKeyword',
  'workplaceType',
  'workplaceTypeFilter',
  'countryCode',
  'country',
  'region',
  'departmentKeyword',
  'limit',
  'maxResults',
  'max_results',
  'pageToken',
]);

const RESOLVE_ALLOWED_ARG_KEYS = new Set([
  'query',
  'company',
  'domain',
  'url',
  'provider',
  'atsProvider',
  'companySlug',
  'careerUrl',
  'workdayTenant',
  'workdaySite',
  'wdInstance',
]);

const DETAIL_ALLOWED_ARG_KEYS = new Set([
  'jobId',
  'upstreamJobId',
  'externalPath',
  'query',
  'company',
  'domain',
  'url',
  'provider',
  'atsProvider',
  'companySlug',
  'careerUrl',
  'workdayTenant',
  'workdaySite',
  'wdInstance',
]);

/**
 * Validates MCP tool arguments strictly before invoking engine functions (`-32602 Invalid params`).
 *
 * @param {string} toolName
 * @param {unknown} rawArgs
 * @returns {{ok: boolean, args?: object, message?: string}}
 */
export function validateMcpToolArguments(toolName, rawArgs) {
  if (rawArgs !== undefined && (!rawArgs || typeof rawArgs !== 'object' || Array.isArray(rawArgs))) {
    return { ok: false, message: 'Tool arguments must be a JSON object' };
  }
  const args = { ...(rawArgs || {}) };
  const allowedSet =
    toolName === 'search_ats_job_postings'
      ? SEARCH_ALLOWED_ARG_KEYS
      : toolName === 'resolve_company_ats_board'
        ? RESOLVE_ALLOWED_ARG_KEYS
        : DETAIL_ALLOWED_ARG_KEYS;

  for (const key of Object.keys(args)) {
    if (!allowedSet.has(key)) {
      return {
        ok: false,
        message: `Unknown argument '${sliceUtf8Safe(key, 48)}' for tool '${toolName}'`,
      };
    }
  }

  for (const aliasKey of ['company', 'domain', 'url']) {
    if (args[aliasKey] !== undefined && typeof args[aliasKey] !== 'string') {
      return { ok: false, message: `Invalid ${aliasKey}: expected a string` };
    }
  }
  const aliasRes = normalizeTalentPulseInputAliases(args);
  if (!aliasRes.ok) {
    return {
      ok: false,
      errorCode: aliasRes.errorCode,
      message: `${aliasRes.errorCode}: ${aliasRes.reason}`,
    };
  }
  Object.assign(args, aliasRes.args);

  if (args.provider !== undefined && args.provider !== null && args.provider !== '') {
    const normProv = String(args.provider).trim().toUpperCase();
    if (normProv !== 'AUTO' && !SUPPORTED_ATS_PROVIDERS.includes(normProv)) {
      return {
        ok: false,
        message: `Invalid provider: expected AUTO, GREENHOUSE, WORKDAY, ASHBY, LEVER, or SMARTRECRUITERS`,
      };
    }
  }

  if (toolName === 'get_ats_job_posting_detail') {
    if (typeof args.jobId !== 'string' || !args.jobId.trim()) {
      return {
        ok: false,
        message: 'Missing or invalid required parameter: jobId (non-empty string)',
      };
    }
    const trimmedId = args.jobId.trim();
    if (trimmedId.length > 256) {
      return {
        ok: false,
        message: 'Invalid jobId: exceeds maximum length of 256 characters',
      };
    }
    const isComposite = JOB_ID_RE.test(trimmedId);
    const hasBoardHint =
      (typeof args.query === 'string' && args.query.trim().length > 0) ||
      (typeof args.companySlug === 'string' && args.companySlug.trim().length > 0) ||
      (typeof args.careerUrl === 'string' && args.careerUrl.trim().length > 0);
    if (!isComposite && !hasBoardHint) {
      return {
        ok: false,
        message:
          'Invalid jobId: must be canonical PROVIDER:companySlug:rawJobId format (e.g. ASHBY:linear:403ef663...) or accompanied by query/companySlug',
      };
    }
    return { ok: true, args };
  }

  if (toolName === 'resolve_company_ats_board') {
    const hasQuery = typeof args.query === 'string' && args.query.trim().length > 0;
    const hasSlug = typeof args.companySlug === 'string' && args.companySlug.trim().length > 0;
    const hasUrl = typeof args.careerUrl === 'string' && args.careerUrl.trim().length > 0;
    if (!hasQuery && !hasSlug && !hasUrl) {
      return {
        ok: false,
        message: 'Missing or invalid required parameter: query (non-empty string)',
      };
    }
    if (hasQuery && args.query.trim().length > MAX_QUERY_LENGTH) {
      return {
        ok: false,
        message: `Invalid query: exceeds maximum length of ${MAX_QUERY_LENGTH} characters`,
      };
    }
    return { ok: true, args };
  }

  // search_ats_job_postings
  const hasQuery = typeof args.query === 'string' && args.query.trim().length > 0;
  const hasSlug = typeof args.companySlug === 'string' && args.companySlug.trim().length > 0;
  const hasUrl = typeof args.careerUrl === 'string' && args.careerUrl.trim().length > 0;
  const hasToken = typeof args.pageToken === 'string' && args.pageToken.trim().length > 0;

  if (args.query !== undefined && typeof args.query !== 'string') {
    return { ok: false, message: 'Invalid query: expected a string' };
  }
  if (hasQuery && args.query.trim().length > MAX_QUERY_LENGTH) {
    return {
      ok: false,
      message: `Invalid query: exceeds maximum length of ${MAX_QUERY_LENGTH} characters`,
    };
  }
  if (!hasQuery && !hasSlug && !hasUrl && !hasToken) {
    return {
      ok: false,
      message: 'Either query (company slug / brand / URL), companySlug, careerUrl, or pageToken is required',
    };
  }

  if (args.workplaceType !== undefined && args.workplaceType !== null && args.workplaceType !== '') {
    if (
      typeof args.workplaceType !== 'string' ||
      !['ANY', 'ALL', 'REMOTE', 'HYBRID', 'ONSITE'].includes(args.workplaceType.trim().toUpperCase())
    ) {
      return {
        ok: false,
        message: 'Invalid workplaceType: expected ANY, REMOTE, HYBRID, or ONSITE',
      };
    }
  }

  if (args.limit !== undefined) {
    const check = validateBoundedIntegerParam(
      args.limit,
      'limit',
      1,
      MCP_MAX_ITEMS_LIMIT,
      10,
      false
    );
    if (!check.ok) {
      return { ok: false, message: check.reason };
    }
  }

  if (args.maxResults !== undefined) {
    const check = validateBoundedIntegerParam(
      args.maxResults,
      'maxResults',
      1,
      MCP_MAX_ITEMS_LIMIT,
      10,
      false
    );
    if (!check.ok) {
      return { ok: false, message: check.reason };
    }
  }

  if (args.pageToken !== undefined && args.pageToken !== null && args.pageToken !== '') {
    const cursorCheck = decodePaginationCursor(args.pageToken);
    if (!cursorCheck.ok) {
      return { ok: false, message: cursorCheck.reason };
    }
  }

  return { ok: true, args };
}

/**
 * Handles a single JSON-RPC 2.0 MCP request (`initialize`, `ping`, `tools/list`, `tools/call`).
 *
 * @param {object} request
 * @param {object} [options]
 * @returns {Promise<object|null>}
 */
export async function handleMcpJsonRpcRequest(request, options = {}) {
  if (
    !request ||
    typeof request !== 'object' ||
    Array.isArray(request) ||
    request.jsonrpc !== '2.0' ||
    typeof request.method !== 'string' ||
    !request.method.trim()
  ) {
    return {
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32600,
        message: 'Invalid JSON-RPC 2.0 request',
      },
    };
  }

  const hasIdProperty =
    Object.prototype.hasOwnProperty.call(request, 'id') && request.id !== undefined;

  if (hasIdProperty) {
    const idCheck = validateJsonRpcRequestId(request.id);
    if (!idCheck.valid) {
      return {
        jsonrpc: '2.0',
        id: null,
        error: {
          code: -32600,
          message: `Invalid JSON-RPC 2.0 request id (must be string, finite number, or null <= ${MCP_MAX_REQ_ID_BYTES} bytes)`,
        },
      };
    }
  }

  if (!hasIdProperty) {
    return null;
  }

  const reqId = request.id;
  const method = request.method.trim();

  if (method === 'ping') {
    return {
      jsonrpc: '2.0',
      id: reqId,
      result: {},
    };
  }

  if (method === 'initialize') {
    const clientVersion = String(request.params?.protocolVersion ?? '').trim();
    const negotiatedVersion = SUPPORTED_MCP_PROTOCOL_VERSIONS.includes(clientVersion)
      ? clientVersion
      : clientVersion
        ? SUPPORTED_MCP_PROTOCOL_VERSIONS[0]
        : '2024-11-05';

    return {
      jsonrpc: '2.0',
      id: reqId,
      result: {
        protocolVersion: negotiatedVersion,
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
    if (!request.params || typeof request.params !== 'object' || Array.isArray(request.params)) {
      return {
        jsonrpc: '2.0',
        id: reqId,
        error: {
          code: -32602,
          message: 'Invalid params: expected an object with tool name and arguments',
        },
      };
    }

    const rawToolName = String(request.params.name ?? '');
    const safeReflectedToolName = sliceUtf8Safe(rawToolName, 64);

    if (
      rawToolName !== 'search_ats_job_postings' &&
      rawToolName !== 'resolve_company_ats_board' &&
      rawToolName !== 'get_ats_job_posting_detail'
    ) {
      return {
        jsonrpc: '2.0',
        id: reqId,
        error: {
          code: -32601,
          message: `Unknown MCP tool '${safeReflectedToolName}'`,
        },
      };
    }

    const argValidation = validateMcpToolArguments(rawToolName, request.params.arguments);
    if (!argValidation.ok) {
      return {
        jsonrpc: '2.0',
        id: reqId,
        error: {
          code: -32602,
          message: `Invalid params: ${argValidation.message}`,
          ...(argValidation.errorCode
            ? {
                errorCode: argValidation.errorCode,
                data: { errorCode: argValidation.errorCode, status: 'INVALID_INPUT' },
              }
            : {}),
        },
      };
    }

    const args = argValidation.args;
    const maxBytes = options.maxPayloadBytes || MCP_MAX_ENVELOPE_BYTES;
    const deadlineAtMs = Date.now() + (Number(options.deadlineMs) || DEFAULT_RUN_DEADLINE_MS);

    try {
      if (rawToolName === 'get_ats_job_posting_detail') {
        const res = await getAtsJobPostingDetail({
          jobId: args.jobId,
          query: args.query,
          provider: args.provider,
          companySlug: args.companySlug,
          careerUrl: args.careerUrl,
          fetchImpl: options.fetchImpl,
          timeoutMs: options.timeoutMs,
          maxRetries: options.maxRetries,
          deadlineAtMs,
        });

        const isError = !res.ok;
        const detailRecord = res.detail || null;
        const structured = truncateMcpResponseEnvelope(
          {
            ok: res.ok,
            status: res.status,
            reason: res.reason,
            boardTarget: res.boardTarget || null,
            detail: detailRecord,
            items: detailRecord ? [detailRecord] : [],
          },
          maxBytes,
          { reqId, isError }
        );

        return {
          jsonrpc: '2.0',
          id: reqId,
          result: {
            isError,
            content: [{ type: 'text', text: JSON.stringify(structured) }],
            structuredContent: structured,
          },
        };
      }

      if (rawToolName === 'resolve_company_ats_board') {
        const res = await resolveAtsBoardTarget({
          query: args.query,
          provider: args.provider,
          companySlug: args.companySlug,
          careerUrl: args.careerUrl,
          workdayTenant: args.workdayTenant,
          workdaySite: args.workdaySite,
          wdInstance: args.wdInstance,
          fetchImpl: options.fetchImpl,
          timeoutMs: options.timeoutMs,
          maxRetries: options.maxRetries,
          deadlineAtMs,
        });

        const isError = !res.ok;
        const structured = truncateMcpResponseEnvelope(
          {
            ok: res.ok,
            status: res.status,
            reason: res.reason,
            boardTarget: res.target || null,
          },
          maxBytes,
          { reqId, isError }
        );

        return {
          jsonrpc: '2.0',
          id: reqId,
          result: {
            isError,
            content: [{ type: 'text', text: JSON.stringify(structured) }],
            structuredContent: structured,
          },
        };
      }

      // search_ats_job_postings
      const requestedLimit = Number(args.limit ?? args.maxResults ?? args.max_results ?? 10);
      const clampedLimit = Math.min(MCP_MAX_ITEMS_LIMIT, Math.max(1, requestedLimit));

      const actorRes = await runUnifiedAtsJobsActor(
        {
          query: args.query,
          company: args.company,
          domain: args.domain,
          url: args.url,
          provider: args.provider ?? args.atsProvider,
          companySlug: args.companySlug,
          careerUrl: args.careerUrl,
          workdayTenant: args.workdayTenant,
          workdaySite: args.workdaySite,
          wdInstance: args.wdInstance,
          searchKeyword: args.searchKeyword,
          workplaceType: args.workplaceType ?? args.workplaceTypeFilter ?? 'ANY',
          countryCode: args.countryCode,
          departmentKeyword: args.departmentKeyword,
          maxResults: clampedLimit,
          pageToken: args.pageToken,
          timeoutMs: options.timeoutMs,
          maxRetries: options.maxRetries,
        },
        {
          fetchImpl: options.fetchImpl,
        }
      );

      const isError = !actorRes.ok;
      const cursorResumeContext =
        actorRes.cursorResumeContext || actorRes.pagination?.cursorResumeContext || null;
      const cleanPagination = actorRes.pagination ? { ...actorRes.pagination } : undefined;
      if (cleanPagination) {
        delete cleanPagination.cursorResumeContext;
      }

      const structured = truncateMcpResponseEnvelope(
        {
          ok: actorRes.ok,
          status: actorRes.status,
          reason: actorRes.reason,
          billingMode: actorRes.billingMode,
          boardTarget: actorRes.boardTarget,
          extractedCount: actorRes.extractedCount,
          deliveredCount: actorRes.deliveredCount,
          billableCount: actorRes.billableCount,
          chargedEventCount: actorRes.chargedEventCount,
          pagination: cleanPagination,
          ...(Array.isArray(actorRes.warnings) && actorRes.warnings.length > 0
            ? { warnings: actorRes.warnings }
            : {}),
          items: actorRes.items,
          telemetry: actorRes.telemetry,
        },
        maxBytes,
        { reqId, isError, cursorResumeContext }
      );

      return {
        jsonrpc: '2.0',
        id: reqId,
        result: {
          isError,
          content: [{ type: 'text', text: JSON.stringify(structured) }],
          structuredContent: structured,
        },
      };
    } catch (internalErr) {
      return {
        jsonrpc: '2.0',
        id: reqId,
        error: {
          code: -32603,
          message: `Internal error: ${sliceUtf8Safe(internalErr?.message || String(internalErr), 200)}`,
        },
      };
    }
  }

  return {
    jsonrpc: '2.0',
    id: reqId,
    error: {
      code: -32601,
      message: `Unsupported JSON-RPC method '${sliceUtf8Safe(method, 64)}'`,
    },
  };
}
