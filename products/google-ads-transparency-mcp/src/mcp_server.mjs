/**
 * Model Context Protocol (MCP) JSON-RPC 2.0 Server (src/mcp_server.mjs)
 *
 * Exposes three deterministic tools sharing the Google Ads Transparency RPC engine:
 *   - `search_google_ads_transparency`: Disambiguates advertiser entities and extracts
 *     normalized ad creatives (`limit <= 25`, `pageToken` continuation, full JSON-RPC
 *     UTF-8 envelope `<= 30,000` bytes with 4-tier surrogate-safe degradation and
 *     automatic mid-page cursor rewind when items are popped for byte ceiling).
 *   - `resolve_google_ads_advertiser`: Resolves a brand name or domain into ranked
 *     verified `AR...` legal entities and ad-volume buckets (`includeSubsidiaries: true`).
 *   - `get_google_ads_creative_detail`: Fetches detailed metadata (`LookupService/GetCreativeById`)
 *     for a specific `(advertiserId, creativeId)` pair, including regional presence and legal name.
 */

import {
  resolveAdvertiserEntities,
  getCreativeDetailsById,
  ADVERTISER_ID_RE,
  CREATIVE_ID_RE,
  ISO_COUNTRY_RE,
  MAX_QUERY_LENGTH,
  DEFAULT_RUN_DEADLINE_MS,
  decodePaginationCursor,
  validateBoundedIntegerParam,
  computeRewoundCursorForDeliveredPrefix,
} from './rpc_client.mjs';
import { runGoogleAdsTransparencyActor } from './apify_actor.mjs';

export const MCP_MAX_ENVELOPE_BYTES = 30000;
export const MCP_MAX_ITEMS_LIMIT = 25;
export const MCP_MAX_REQ_ID_BYTES = 256;

export const SUPPORTED_MCP_PROTOCOL_VERSIONS = Object.freeze([
  '2025-06-18',
  '2025-03-26',
  '2024-11-05',
]);

const RAW_BRAND_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img" aria-labelledby="rc-title"><title id="rc-title">RevClamp AdPulse</title><defs><linearGradient id="rc-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#111C38"/><stop offset="100%" stop-color="#090E1D"/></linearGradient><linearGradient id="rc-edge" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#10B981"/><stop offset="100%" stop-color="#06B6D4"/></linearGradient></defs><rect width="64" height="64" fill="#0B1020"/><path d="M32 10L50 16.5V31C50 42.5 42.5 49.5 32 54C21.5 49.5 14 42.5 14 31V16.5Z" fill="url(#rc-fill)" stroke="url(#rc-edge)" stroke-width="2.4" stroke-linejoin="round"/><path d="M32 12.8L47.4 18.4V30.8C47.4 40.4 41 46.7 32 50.8C23 46.7 16.6 40.4 16.6 30.8V18.4Z" fill="none" stroke="#F59E0B" stroke-opacity="0.45" stroke-width="0.9" stroke-linejoin="round"/><line x1="35.8" y1="34.4" x2="40.6" y2="39.2" stroke="#F59E0B" stroke-width="3.2" stroke-linecap="round"/><circle cx="29.4" cy="28" r="9.4" fill="#0B1020"/><path d="M29.4 19.6V36.4M21 28H37.8" stroke="#06B6D4" stroke-opacity="0.35" stroke-width="1"/><circle cx="29.4" cy="28" r="4.8" fill="none" stroke="#06B6D4" stroke-opacity="0.5" stroke-width="1"/><path d="M29.4 28V19.6A8.4 8.4 0 0 1 36.67 23.8Z" fill="#10B981" fill-opacity="0.38"/><line x1="29.4" y1="28" x2="29.4" y2="19.6" stroke="#10B981" stroke-width="1.4" stroke-linecap="round"/><circle cx="32.2" cy="23.4" r="2" fill="#F59E0B"/><circle cx="25.5" cy="31.3" r="3.5" fill="#10B981"/><path d="M23.9 31.4L25.1 32.6L27.3 30.1" fill="none" stroke="#0B1020" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/><circle cx="29.4" cy="28" r="9.4" fill="none" stroke="#F8FAFC" stroke-width="2"/></svg>`;

export const ENCODED_BRAND_ICON_DATA_URI = `data:image/svg+xml;utf8,${encodeURIComponent(RAW_BRAND_ICON_SVG)}`;

export const MCP_SERVER_INFO = Object.freeze({
  name: 'google-ads-transparency-mcp',
  title: 'RevClamp AdPulse - Google Ads Transparency Scraper & MCP',
  version: '1.0.8',
  description:
    'Find verified Google Ads advertiser entities and extract active or historical ad creatives (Text, Image, Video), preview links, and run dates. Independent intelligence tool by RevClamp; not affiliated with or endorsed by Google LLC.',
  // Forward-compatible MCP Registry & Glama metadata extensions (ignored by older stdio clients)
  websiteUrl: 'https://revclamp.com',
  icons: [
    {
      src: ENCODED_BRAND_ICON_DATA_URI,
      mimeType: 'image/svg+xml',
      sizes: ['any'],
    },
    {
      src: 'https://raw.githubusercontent.com/lhphong09t2/revclamp-mcp/main/products/google-ads-transparency-mcp/assets/icon-180.png',
      mimeType: 'image/png',
      sizes: ['180x180'],
    },
    {
      src: 'https://raw.githubusercontent.com/lhphong09t2/revclamp-mcp/main/products/google-ads-transparency-mcp/assets/icon-32.png',
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
    name: 'search_google_ads_transparency',
    title: 'Search Google Ads Transparency Creatives',
    description:
      'Resolves a brand name or domain (e.g. "nike.com", "Stripe", "shopify.com") or explicit advertiserId (AR...) into verified Google Ads Transparency legal entities and extracts active and historical ad creatives (Text, Image, Video), preview URLs, and first/last seen timestamps. Requires either query or advertiserId.',
    annotations: READ_ONLY_TOOL_ANNOTATIONS,
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          title: 'Brand Name or Domain',
          type: 'string',
          maxLength: 512,
          description: 'Brand name or domain to search (e.g. "nike.com", "Stripe", "Booking.com").',
        },
        advertiserId: {
          title: 'Advertiser ID (Optional)',
          type: 'string',
          description:
            'Optional canonical Google Ads Transparency Advertiser ID (e.g. "AR16735076323512287233").',
        },
        countryCode: {
          title: 'Country Filter (Optional)',
          type: 'string',
          description: 'Optional 2-letter ISO country code filter (e.g. "US").',
        },
        formatFilter: {
          title: 'Ad Format',
          type: 'string',
          enum: ['ALL', 'TEXT', 'IMAGE', 'VIDEO'],
          default: 'ALL',
          description: 'Optional creative format filter.',
        },
        includeSubsidiaries: {
          title: 'Include Regional Subsidiaries',
          type: 'boolean',
          default: true,
          description: 'Include up to 3 verified regional subsidiaries matching the brand.',
        },
        includeCreativeDetails: {
          title: 'Include Creative Region & Legal Details',
          type: 'boolean',
          default: false,
          description:
            'When true, enriches up to 5 returned creatives with GetCreativeById regional presence and legal entity details.',
        },
        maxEntities: {
          title: 'Max Advertiser Entities',
          type: 'integer',
          minimum: 1,
          maximum: 3,
          default: 3,
          description: 'Maximum number of verified advertiser entities to query (1 to 3).',
        },
        limit: {
          title: 'Max Creatives per Call',
          type: 'integer',
          minimum: 1,
          maximum: 25,
          default: 15,
          description: 'Maximum number of creatives to return in a single MCP tool call (1 to 25).',
        },
        maxResults: {
          title: 'Max Creatives per Call (Legacy Alias)',
          type: 'integer',
          minimum: 1,
          maximum: 25,
          deprecated: true,
          description: 'Deprecated alias for limit (1 to 25).',
        },
        pageToken: {
          title: 'Next-Page Cursor Token (Optional)',
          type: 'string',
          maxLength: 2048,
          description:
            'Optional opaque continuation cursor (upstream token or composite rcp1_ token, max 2048 chars) returned by a previous call.',
        },
      },
      additionalProperties: false,
    },
  },
  {
    name: 'resolve_google_ads_advertiser',
    title: 'Resolve Google Ads Advertiser Entities',
    description:
      'Disambiguates a brand name or domain into ranked verified Google Ads Transparency advertiser entities (AR...), regional codes, and verified ad-volume buckets without fetching individual creatives.',
    annotations: READ_ONLY_TOOL_ANNOTATIONS,
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          title: 'Brand Name or Domain',
          type: 'string',
          maxLength: 512,
          description: 'Brand name or domain to resolve (e.g. "nike.com", "Stripe", "Apple").',
        },
        countryCode: {
          title: 'Preferred Country (Optional)',
          type: 'string',
          description: 'Optional 2-letter ISO country code preference (e.g. "US").',
        },
        includeSubsidiaries: {
          title: 'Include Regional Subsidiaries',
          type: 'boolean',
          default: true,
          description: 'When true, returns up to 3 verified regional legal entities.',
        },
        maxEntities: {
          title: 'Max Advertiser Entities',
          type: 'integer',
          minimum: 1,
          maximum: 3,
          default: 3,
          description: 'Maximum number of verified regional legal entities to select (1 to 3).',
        },
      },
      required: ['query'],
      additionalProperties: false,
    },
  },
  {
    name: 'get_google_ads_creative_detail',
    title: 'Get Google Ads Creative Detail',
    description:
      'Fetches detailed metadata for a single verified Google Ads Transparency creative (AR... + CR...), including regional presence (Geo Target Criterion IDs mapped to ISO countries), advertiser legal name, and preview assets.',
    annotations: READ_ONLY_TOOL_ANNOTATIONS,
    inputSchema: {
      type: 'object',
      properties: {
        advertiserId: {
          title: 'Advertiser ID',
          type: 'string',
          description:
            'Canonical Google Ads Transparency Advertiser ID (e.g. "AR16735076323512287233").',
        },
        creativeId: {
          title: 'Creative ID',
          type: 'string',
          description:
            'Canonical Google Ads Transparency Creative ID (e.g. "CR02320987639562076161").',
        },
      },
      required: ['advertiserId', 'creativeId'],
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
 * **entire serialized JSON-RPC 2.0 response envelope** (including `reqId`, `isError`,
 * duplicated `content[0].text` + `structuredContent`, and JSON escaping) via a 4-tier
 * deterministic degradation pipeline. When items are popped (`omittedCount > 0`),
 * rewinds `pagination.nextPageToken` via `cursorResumeContext` so the caller can
 * resume from the first omitted item without data loss.
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
  const originalPaginationStatus = rawClone.pagination?.paginationStatus || 'EXHAUSTED';

  const buildOrderedPayload = (cand, tier, omittedCount) => {
    const truncated = tier > 0;
    const returnedCount = Array.isArray(cand.items)
      ? cand.items.length
      : Array.isArray(cand.selectedEntities)
        ? cand.selectedEntities.length
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

  // Tier 1: Trim candidate lists, cap archiveImageUrls to 2 per item, and pop tail items down to >= 1
  const work = JSON.parse(JSON.stringify(rawClone));
  if (Array.isArray(work.allCandidates) && work.allCandidates.length > 3) {
    work.allCandidates = work.allCandidates.slice(0, 3);
  }
  if (Array.isArray(work.items)) {
    for (const item of work.items) {
      if (Array.isArray(item.archiveImageUrls) && item.archiveImageUrls.length > 2) {
        item.archiveImageUrls = item.archiveImageUrls.slice(0, 2);
      }
      item.previewUrlOmitted = false;
    }
  }

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

  // Tier 2: Omit previewUrl cleanly (previewUrl: null, previewUrlOmitted: true), clear archiveImageUrls, and trim heavy ad copy fields
  if (Array.isArray(work.items)) {
    for (const item of work.items) {
      if (item.previewUrl) {
        item.previewUrl = null;
        item.previewUrlOmitted = true;
      }
      item.archiveImageUrls = [];
      if (item.rawDetailSummary) {
        delete item.rawDetailSummary;
      }
      if (item.creativeDetail) {
        delete item.creativeDetail;
      }
      if (item.untrustedAdContent && typeof item.untrustedAdContent === 'object') {
        delete item.untrustedAdContent.headline;
        delete item.untrustedAdContent.bodyText;
        delete item.untrustedAdContent.landingPageUrl;
        item.untrustedAdContent.omittedFields = ['headline', 'bodyText', 'landingPageUrl'];
      }
      if (typeof item.advertiserName === 'string') {
        item.advertiserName = sliceUtf8Safe(item.advertiserName, 120);
      }
      if (typeof item.advertiserLegalName === 'string') {
        item.advertiserLegalName = sliceUtf8Safe(item.advertiserLegalName, 120);
      }
    }
  }
  if (work.detail && typeof work.detail === 'object') {
    if (work.detail.previewUrl) {
      work.detail.previewUrl = null;
      work.detail.previewUrlOmitted = true;
    }
    work.detail.archiveImageUrls = [];
    if (typeof work.detail.advertiserLegalName === 'string') {
      work.detail.advertiserLegalName = sliceUtf8Safe(work.detail.advertiserLegalName, 120);
    }
    if (Array.isArray(work.detail.regionalPresence) && work.detail.regionalPresence.length > 5) {
      work.detail.regionalPresence = work.detail.regionalPresence.slice(0, 5);
    }
  }
  if (Array.isArray(work.allCandidates)) {
    work.allCandidates = work.allCandidates.slice(0, 1);
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

  // Tier 3: Single compact stub item & single selectedEntity
  if (Array.isArray(work.items) && work.items.length > 0) {
    const first = work.items[0];
    work.items = [
      {
        advertiserId: first.advertiserId,
        advertiserName: sliceUtf8Safe(
          first.advertiserName || first.advertiserLegalName || first.advertiserId,
          64
        ),
        country: first.country || 'ALL',
        creativeId: first.creativeId,
        format: first.format || 'UNKNOWN',
        previewUrl: null,
        previewUrlOmitted: true,
        archiveImageUrls: [],
        transparencyUrl: first.transparencyUrl,
      },
    ];
  }
  if (work.detail && typeof work.detail === 'object') {
    work.detail = {
      advertiserId: work.detail.advertiserId,
      creativeId: work.detail.creativeId,
      advertiserLegalName: sliceUtf8Safe(
        work.detail.advertiserLegalName || work.detail.advertiserId,
        64
      ),
      format: work.detail.format || 'UNKNOWN',
      variationCount: work.detail.variationCount ?? 1,
      regionalPresence: Array.isArray(work.detail.regionalPresence)
        ? work.detail.regionalPresence.slice(0, 3)
        : [],
    };
  }
  if (Array.isArray(work.selectedEntities) && work.selectedEntities.length > 1) {
    work.selectedEntities = work.selectedEntities.slice(0, 1);
  }
  delete work.allCandidates;
  delete work.queryMeta;

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
      advertiserId: sliceUtf8Safe(work.detail.advertiserId, 32),
      creativeId: sliceUtf8Safe(work.detail.creativeId, 32),
      advertiserLegalName: sliceUtf8Safe(
        work.detail.advertiserLegalName || work.detail.advertiserId,
        48
      ),
      format: sliceUtf8Safe(work.detail.format || 'UNKNOWN', 16),
    };
  }
  if (Array.isArray(work.selectedEntities)) {
    work.selectedEntities = work.selectedEntities.slice(0, 1).map((e) => ({
      advertiserId: e.advertiserId,
      advertiserName: sliceUtf8Safe(e.advertiserName || e.advertiserId, 48),
      regionCode: e.regionCode || 'ALL',
    }));
  }
  if (work.primaryEntity && typeof work.primaryEntity === 'object') {
    work.primaryEntity = {
      advertiserId: work.primaryEntity.advertiserId,
      advertiserName: sliceUtf8Safe(
        work.primaryEntity.advertiserName || work.primaryEntity.advertiserId,
        48
      ),
      regionCode: work.primaryEntity.regionCode || 'ALL',
    };
  }
  if (typeof work.reason === 'string') {
    work.reason = sliceUtf8Safe(work.reason, 160);
  }

  const tier4Candidate = buildOrderedPayload(work, 4, originalItemCount);
  if (measureFullRpcBytes(tier4Candidate) <= safeMaxBytes) {
    return tier4Candidate;
  }

  // Emergency minimal stub if oversized top-level custom properties remain
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
  'advertiserId',
  'countryCode',
  'formatFilter',
  'includeSubsidiaries',
  'includeCreativeDetails',
  'includeAdCopy',
  'maxEntities',
  'limit',
  'maxResults',
  'maxPages',
  'pageToken',
]);

const RESOLVE_ALLOWED_ARG_KEYS = new Set([
  'query',
  'countryCode',
  'includeSubsidiaries',
  'maxEntities',
]);

const DETAIL_ALLOWED_ARG_KEYS = new Set(['advertiserId', 'creativeId', 'includeAdCopy']);

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
  const args = rawArgs || {};
  const allowedSet =
    toolName === 'search_google_ads_transparency'
      ? SEARCH_ALLOWED_ARG_KEYS
      : toolName === 'resolve_google_ads_advertiser'
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

  if (toolName === 'get_google_ads_creative_detail') {
    if (
      typeof args.advertiserId !== 'string' ||
      !ADVERTISER_ID_RE.test(args.advertiserId.trim())
    ) {
      return {
        ok: false,
        message: 'Invalid advertiserId: expected canonical AR... format (e.g. AR16735076323512287233)',
      };
    }
    if (typeof args.creativeId !== 'string' || !CREATIVE_ID_RE.test(args.creativeId.trim())) {
      return {
        ok: false,
        message: 'Invalid creativeId: expected canonical CR... format (e.g. CR02320987639562076161)',
      };
    }
    if (args.includeAdCopy !== undefined && typeof args.includeAdCopy !== 'boolean') {
      return {
        ok: false,
        message: 'Invalid includeAdCopy: expected a boolean',
      };
    }
    return { ok: true, args };
  }

  if (args.countryCode !== undefined && args.countryCode !== null && args.countryCode !== '') {
    if (
      typeof args.countryCode !== 'string' ||
      !ISO_COUNTRY_RE.test(args.countryCode.trim().toUpperCase())
    ) {
      return {
        ok: false,
        message: 'Invalid countryCode: expected a 2-letter ISO 3166-1 alpha-2 country code',
      };
    }
  }

  if (args.includeSubsidiaries !== undefined && typeof args.includeSubsidiaries !== 'boolean') {
    return {
      ok: false,
      message: 'Invalid includeSubsidiaries: expected a boolean',
    };
  }

  if (
    args.includeCreativeDetails !== undefined &&
    typeof args.includeCreativeDetails !== 'boolean'
  ) {
    return {
      ok: false,
      message: 'Invalid includeCreativeDetails: expected a boolean',
    };
  }

  if (args.includeAdCopy !== undefined && typeof args.includeAdCopy !== 'boolean') {
    return {
      ok: false,
      message: 'Invalid includeAdCopy: expected a boolean',
    };
  }

  if (args.maxPages !== undefined) {
    const check = validateBoundedIntegerParam(args.maxPages, 'maxPages', 1, 5, 5, false);
    if (!check.ok) {
      return { ok: false, message: check.reason };
    }
  }

  if (args.maxEntities !== undefined) {
    const check = validateBoundedIntegerParam(args.maxEntities, 'maxEntities', 1, 3, 3, false);
    if (!check.ok) {
      return { ok: false, message: check.reason };
    }
  }

  if (toolName === 'resolve_google_ads_advertiser') {
    if (typeof args.query !== 'string' || !args.query.trim()) {
      return {
        ok: false,
        message: 'Missing or invalid required parameter: query (non-empty string)',
      };
    }
    if (args.query.trim().length > MAX_QUERY_LENGTH) {
      return {
        ok: false,
        message: `Invalid query: exceeds maximum length of ${MAX_QUERY_LENGTH} characters`,
      };
    }
    return { ok: true, args };
  }

  // search_google_ads_transparency
  const hasQuery = typeof args.query === 'string' && args.query.trim().length > 0;
  const hasAdvId = typeof args.advertiserId === 'string' && args.advertiserId.trim().length > 0;

  if (args.query !== undefined && typeof args.query !== 'string') {
    return { ok: false, message: 'Invalid query: expected a string' };
  }
  if (hasQuery && args.query.trim().length > MAX_QUERY_LENGTH) {
    return {
      ok: false,
      message: `Invalid query: exceeds maximum length of ${MAX_QUERY_LENGTH} characters`,
    };
  }
  if (args.advertiserId !== undefined && typeof args.advertiserId !== 'string') {
    return { ok: false, message: 'Invalid advertiserId: expected a string' };
  }
  if (!hasQuery && !hasAdvId) {
    return {
      ok: false,
      message: 'Either query (brand/domain) or advertiserId (AR...) is required',
    };
  }
  if (hasAdvId && !ADVERTISER_ID_RE.test(args.advertiserId.trim())) {
    return {
      ok: false,
      message: 'Invalid advertiserId: expected canonical AR... format (e.g. AR16735076323512287233)',
    };
  }

  if (args.formatFilter !== undefined) {
    if (
      typeof args.formatFilter !== 'string' ||
      !['ALL', 'TEXT', 'IMAGE', 'VIDEO'].includes(args.formatFilter.trim().toUpperCase())
    ) {
      return {
        ok: false,
        message: 'Invalid formatFilter: expected ALL, TEXT, IMAGE, or VIDEO',
      };
    }
  }

  if (args.limit !== undefined) {
    const check = validateBoundedIntegerParam(
      args.limit,
      'limit',
      1,
      MCP_MAX_ITEMS_LIMIT,
      15,
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
      15,
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
 * Enforces JSON-RPC 2.0 structure validation prior to notification suppression and separates
 * error codes `-32600`, `-32601`, `-32602`, and `-32603`.
 *
 * @param {object} request
 * @param {object} [options]
 * @returns {Promise<object|null>}
 */
export async function handleMcpJsonRpcRequest(request, options = {}) {
  // Step 1: Validate base JSON-RPC 2.0 request envelope BEFORE notification check
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

  // Step 2: JSON-RPC 2.0 notifications (no `id` member) must NEVER emit a response object
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
      rawToolName !== 'search_google_ads_transparency' &&
      rawToolName !== 'resolve_google_ads_advertiser' &&
      rawToolName !== 'get_google_ads_creative_detail'
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
        },
      };
    }

    const args = argValidation.args;
    const maxBytes = options.maxPayloadBytes || MCP_MAX_ENVELOPE_BYTES;
    const deadlineAtMs = Date.now() + (Number(options.deadlineMs) || DEFAULT_RUN_DEADLINE_MS);

    try {
      if (rawToolName === 'get_google_ads_creative_detail') {
        const res = await getCreativeDetailsById({
          advertiserId: args.advertiserId,
          creativeId: args.creativeId,
          includeAdCopy: args.includeAdCopy === true,
          fetchImpl: options.fetchImpl,
          timeoutMs: options.timeoutMs,
          maxRetries: options.maxRetries,
          deadlineAtMs,
        });

        const isError = !res.ok;
        const detailRecord = res.detail || res.creative || null;
        const structured = truncateMcpResponseEnvelope(
          {
            ok: res.ok,
            status: res.status,
            reason: res.reason,
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

      if (rawToolName === 'resolve_google_ads_advertiser') {
        const res = await resolveAdvertiserEntities({
          query: args.query,
          countryCode: args.countryCode,
          includeSubsidiaries: args.includeSubsidiaries !== false,
          maxEntities: args.maxEntities ?? 3,
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
            queryMeta: res.queryMeta,
            primaryEntity: res.primaryEntity,
            selectedEntities: res.selectedEntities,
            allCandidates: res.allCandidates.slice(0, 10),
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

      // search_google_ads_transparency
      const requestedLimit = Number(args.limit ?? args.maxResults ?? 15);
      const clampedLimit = Math.min(MCP_MAX_ITEMS_LIMIT, Math.max(1, requestedLimit));

      const actorRes = await runGoogleAdsTransparencyActor(
        {
          query: args.query,
          advertiserId: args.advertiserId,
          countryCode: args.countryCode,
          formatFilter: args.formatFilter || 'ALL',
          includeSubsidiaries: args.includeSubsidiaries !== false,
          includeCreativeDetails: args.includeCreativeDetails === true,
          includeAdCopy: args.includeAdCopy === true,
          maxEntities: args.maxEntities ?? 3,
          maxResults: clampedLimit,
          maxPages: args.maxPages,
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
          selectedEntities: actorRes.selectedEntities,
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
