/**
 * Apify Pay-per-Event Execution, Native Platform Adapter & Crash-Safe Billing State Machine (src/apify_actor.mjs)
 *
 * Enforces deterministic Pay-per-Event billing and delivery invariants:
 *   1. Explicit Accounting Separation: Tracks `extractedCount`, `deliveredCount`,
 *      `billableCount` (simulated unit-economics count), and confirmed `chargedEventCount`
 *      (`0` in local/MCP unbilled mode; strictly validated integer in Apify billing mode).
 *   2. Native Zero-Dependency Apify Platform Adapter (`createApifyPlatformHooks` & `loadApifyActorInput`):
 *      Wires Apify Key-Value Store (`INPUT` & `ADPULSE_BILLING_CHECKPOINT`), Dataset (`pushData`),
 *      and Pay-per-Event Charging (`POST /v2/actor-runs/:runId/charge` with `Idempotency-Key`)
 *      when running on Apify (`APIFY_IS_AT_HOME=1` / `APIFY_TOKEN` + `APIFY_ACTOR_RUN_ID`) or local storage.
 *   3. Crash-Safe KVS Checkpoint State Machine (`inFlightIds` -> `chargedIds` -> `deliveredIds`
 *      or `unknownOutcomeIds`), deterministic prefix delivery when `eventChargeLimitReached` returns
 *      partial `chargedCount`, cursor rewind on mid-stream halt/limit, and honest zero-event telemetry.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  normalizeAdPulseInputAliases,
  resolveAdvertiserEntities,
  fetchAdvertiserCreatives,
  getCreativeDetailsById,
  createEmptyUntrustedAdContent,
  computeRewoundCursorForDeliveredPrefix,
  verifyEgressUrlSsrfSafe,
  CREATIVE_ID_RE,
  ADVERTISER_ID_RE,
  DEFAULT_RUN_DEADLINE_MS,
} from './rpc_client.mjs';

export const ACTOR_PRICING_CONTRACT = Object.freeze({
  eventName: 'ad-creative-scraped',
  actorStartFeeUsdc: 0.001,
  priceUsdc: 0.0012,
  costCeilingUsdc: 0.0001,
  platformFeeRate: 0.2,
  netPriceUsdc: 0.00096,
  minMarginMultiplier: 2.5,
  computeRatePerGbHourUsdc: 0.3,
  maxMemoryMb: 256,
  maxTimeoutSec: 25,
  chunkSize: 25,
  checkpointKey: 'ADPULSE_BILLING_CHECKPOINT',
});

/**
 * Computes content-addressed batch idempotency key (`sha256(runId + '\x1f' + sortedChunkIds)`).
 *
 * @param {string} runId
 * @param {string[]} creativeIds
 * @returns {string}
 */
export function computeChunkIdempotencyKey(runId, creativeIds) {
  const safeRunId = String(runId || 'default_run');
  const sortedIds = [...creativeIds].map((id) => String(id)).sort();
  return crypto
    .createHash('sha256')
    .update(`${safeRunId}\x1f${sortedIds.join('\x1f')}`, 'utf8')
    .digest('hex');
}

/**
 * Computes unit-economics and margin telemetry for a single Actor/MCP execution run.
 * Uses Apify's standard `$0.30 / GB-hour` compute rate (`0.25 GB` at `256MB`).
 * When `billableCount === 0`, returns `economicsStatus: 'NO_BILLABLE_EVENTS'` with
 * `withinCostCeiling: false` and `marginPositive: false`.
 *
 * @param {object} params
 * @param {number} params.billableCount
 * @param {number} [params.chargedEventCount=0]
 * @param {number} params.durationMs
 * @param {number} [params.memoryMb=256]
 * @param {number} [params.requestCount=1]
 * @returns {object}
 */
export function computeRunEconomicsTelemetry({
  billableCount = 0,
  chargedEventCount = 0,
  durationMs = 100,
  memoryMb =
    Number(process.env.ACTOR_MEMORY_MBYTES || process.env.APIFY_MEMORY_MBYTES) ||
    ACTOR_PRICING_CONTRACT.maxMemoryMb,
  requestCount = 1,
  unitPriceUsdc = ACTOR_PRICING_CONTRACT.priceUsdc,
  actorStartFeeUsdc = ACTOR_PRICING_CONTRACT.actorStartFeeUsdc,
  pricingDeterministic,
} = {}) {
  const safeCount = Math.max(0, Math.floor(Number(billableCount) || 0));
  const safeChargedCount = Math.max(0, Math.floor(Number(chargedEventCount) || 0));
  const safeDurationMs = Math.max(1, Number(durationMs) || 1);
  const safeMemoryMb = Math.min(1024, Math.max(64, Number(memoryMb) || 256));
  const safeRequests = Math.max(1, Math.floor(Number(requestCount) || 1));
  const unitPriceUnresolved = unitPriceUsdc === null;
  const startFeeUnresolved = actorStartFeeUsdc === null;
  const isPricingUnresolved =
    pricingDeterministic === false || unitPriceUnresolved || startFeeUnresolved;
  const resolvedUnitPriceUsdc = unitPriceUnresolved
    ? null
    : Number.isFinite(Number(unitPriceUsdc)) && Number(unitPriceUsdc) > 0
      ? Number(unitPriceUsdc)
      : ACTOR_PRICING_CONTRACT.priceUsdc;
  const resolvedNetPriceUsdc =
    resolvedUnitPriceUsdc === null
      ? null
      : Number((resolvedUnitPriceUsdc * (1 - ACTOR_PRICING_CONTRACT.platformFeeRate)).toFixed(6));
  const resolvedStartFeeUsdc = startFeeUnresolved
    ? null
    : Number.isFinite(Number(actorStartFeeUsdc)) && Number(actorStartFeeUsdc) >= 0
      ? Number(actorStartFeeUsdc)
      : ACTOR_PRICING_CONTRACT.actorStartFeeUsdc;

  // Apify compute rate: $0.30 per GB-hour; 256MB = 0.25 GB -> $0.075/hour -> $0.00002083/sec
  const computeHours = safeDurationMs / 3600000;
  const computeCostUsdc =
    (safeMemoryMb / 1024) * computeHours * ACTOR_PRICING_CONTRACT.computeRatePerGbHourUsdc;
  const networkOverheadUsdc = safeRequests * 0.0000002;
  const totalRunCostUsdc = Number((computeCostUsdc + networkOverheadUsdc).toFixed(8));

  const configuredFloorMultiplier =
    isPricingUnresolved || resolvedNetPriceUsdc === null
      ? null
      : Number((resolvedNetPriceUsdc / ACTOR_PRICING_CONTRACT.costCeilingUsdc).toFixed(2));

  if (safeCount === 0) {
    return {
      economicsStatus: 'NO_BILLABLE_EVENTS',
      pricingDeterministic: !isPricingUnresolved,
      billableCount: 0,
      chargedEventCount: safeChargedCount,
      durationMs: safeDurationMs,
      memoryMb: safeMemoryMb,
      requestCount: safeRequests,
      unitPriceUsdc: resolvedUnitPriceUsdc,
      actorStartFeeUsdc: resolvedStartFeeUsdc,
      totalRunCostUsdc,
      actualCostPerEventUsdc: 0,
      costCeilingUsdc: ACTOR_PRICING_CONTRACT.costCeilingUsdc,
      withinCostCeiling: false,
      grossRevenueUsdc: 0,
      netRevenueUsdc: 0,
      configuredFloorMultiplier,
      effectiveMarginMultiplier: 0,
      marginPositive: false,
    };
  }

  const actualCostPerEventUsdc = Number((totalRunCostUsdc / safeCount).toFixed(8));
  const withinCostCeiling = actualCostPerEventUsdc <= ACTOR_PRICING_CONTRACT.costCeilingUsdc;

  if (isPricingUnresolved) {
    return {
      economicsStatus: 'UNRESOLVED_TIER_PRICING',
      pricingDeterministic: false,
      billableCount: safeCount,
      chargedEventCount: safeChargedCount,
      durationMs: safeDurationMs,
      memoryMb: safeMemoryMb,
      requestCount: safeRequests,
      unitPriceUsdc: resolvedUnitPriceUsdc,
      actorStartFeeUsdc: resolvedStartFeeUsdc,
      totalRunCostUsdc,
      actualCostPerEventUsdc,
      costCeilingUsdc: ACTOR_PRICING_CONTRACT.costCeilingUsdc,
      withinCostCeiling,
      grossRevenueUsdc: null,
      netRevenueUsdc: null,
      configuredFloorMultiplier: null,
      effectiveMarginMultiplier: null,
      marginPositive: false,
    };
  }

  const grossRevenueUsdc = Number((safeCount * resolvedUnitPriceUsdc).toFixed(6));
  const netRevenueUsdc = Number((safeCount * resolvedNetPriceUsdc).toFixed(6));
  const effectiveMarginMultiplier =
    actualCostPerEventUsdc > 0
      ? Number((resolvedNetPriceUsdc / actualCostPerEventUsdc).toFixed(2))
      : configuredFloorMultiplier;

  const marginPositive =
    withinCostCeiling &&
    configuredFloorMultiplier >= ACTOR_PRICING_CONTRACT.minMarginMultiplier;

  return {
    economicsStatus: marginPositive ? 'PROFITABLE' : 'COST_CEILING_EXCEEDED',
    pricingDeterministic: true,
    billableCount: safeCount,
    chargedEventCount: safeChargedCount,
    durationMs: safeDurationMs,
    memoryMb: safeMemoryMb,
    requestCount: safeRequests,
    unitPriceUsdc: resolvedUnitPriceUsdc,
    actorStartFeeUsdc: resolvedStartFeeUsdc,
    totalRunCostUsdc,
    actualCostPerEventUsdc,
    costCeilingUsdc: ACTOR_PRICING_CONTRACT.costCeilingUsdc,
    withinCostCeiling,
    grossRevenueUsdc,
    netRevenueUsdc,
    configuredFloorMultiplier,
    effectiveMarginMultiplier,
    marginPositive,
  };
}

/**
 * Validates that an Apify API base URL is safe (`https://api.apify.com` by default).
 * When `rawApiBaseUrl` is an internal HTTP endpoint on Apify Cloud and a valid HTTPS
 * `fallbackPublicBaseUrl` (`APIFY_API_PUBLIC_BASE_URL`) is provided, uses the HTTPS public URL.
 *
 * @param {string} [rawApiBaseUrl]
 * @param {string} [fallbackPublicBaseUrl]
 * @returns {string}
 */
function resolveSafeApifyApiBaseUrl(rawApiBaseUrl, fallbackPublicBaseUrl = undefined) {
  const candidate = String(rawApiBaseUrl || fallbackPublicBaseUrl || 'https://api.apify.com')
    .trim()
    .replace(/\/+$/, '');
  const ssrf = verifyEgressUrlSsrfSafe(candidate);
  if (!ssrf.safe) {
    if (fallbackPublicBaseUrl) {
      const publicCandidate = String(fallbackPublicBaseUrl).trim().replace(/\/+$/, '');
      const publicSsrf = verifyEgressUrlSsrfSafe(publicCandidate);
      if (publicSsrf.safe) {
        return publicCandidate;
      }
    }
    throw new Error(`Invalid or unsafe APIFY_API_BASE_URL '${candidate}': ${ssrf.reason}`);
  }
  return candidate;
}

/**
 * Loads Actor input JSON from CLI `--input-json`, `APIFY_INPUT_PATH`, local Apify storage
 * (`$ACTOR_STORAGE_DIR` / `$APIFY_LOCAL_STORAGE_DIR/key_value_stores/default/INPUT.json`),
 * or Apify Platform KVS REST API.
 *
 * @param {string[]} [cliArgs=[]]
 * @param {object} [env=process.env]
 * @param {Function} [fetchImpl=globalThis.fetch]
 * @returns {Promise<object>}
 */
export async function loadApifyActorInput(
  cliArgs = [],
  env = process.env,
  fetchImpl = globalThis.fetch
) {
  const inputIdx = Array.isArray(cliArgs) ? cliArgs.indexOf('--input-json') : -1;
  if (inputIdx !== -1 && cliArgs[inputIdx + 1]) {
    const raw = fs.readFileSync(cliArgs[inputIdx + 1], 'utf8');
    return JSON.parse(raw);
  }

  const isAtHome = env?.APIFY_IS_AT_HOME === '1' || env?.APIFY_IS_AT_HOME === 'true';
  const applyAtHomeSchemaDefaults = (parsedInput) => {
    if (!parsedInput || typeof parsedInput !== 'object' || Array.isArray(parsedInput)) {
      return parsedInput;
    }
    const next = { ...parsedInput };
    const hasNonEmptyAlias = (keys) =>
      keys.some((k) => next[k] !== undefined && next[k] !== null && String(next[k]).trim() !== '');
    if (
      next.query === 'Stripe' &&
      hasNonEmptyAlias(['domain', 'brand', 'company', 'advertiser', 'url', 'advertiserId', 'creativeId'])
    ) {
      delete next.query;
    }
    if ((next.maxResults === 40 || next.maxResults === 5) && hasNonEmptyAlias(['limit', 'max_results'])) {
      delete next.maxResults;
    }
    if (
      (next.pageToken === undefined || next.pageToken === null || String(next.pageToken).trim() === '') &&
      typeof next.cursor === 'string' &&
      next.cursor.trim() !== ''
    ) {
      next.pageToken = next.cursor;
    }
    if (
      isAtHome &&
      !Object.prototype.hasOwnProperty.call(next, 'query') &&
      !Object.prototype.hasOwnProperty.call(next, 'domain') &&
      !Object.prototype.hasOwnProperty.call(next, 'brand') &&
      !Object.prototype.hasOwnProperty.call(next, 'company') &&
      !Object.prototype.hasOwnProperty.call(next, 'advertiser') &&
      !Object.prototype.hasOwnProperty.call(next, 'url') &&
      !Object.prototype.hasOwnProperty.call(next, 'advertiserId') &&
      !Object.prototype.hasOwnProperty.call(next, 'creativeId') &&
      !hasNonEmptyAlias(['pageToken', 'cursor'])
    ) {
      return { query: 'Stripe', ...next };
    }
    return next;
  };

  if (env?.APIFY_INPUT_PATH && fs.existsSync(env.APIFY_INPUT_PATH)) {
    const raw = fs.readFileSync(env.APIFY_INPUT_PATH, 'utf8');
    return applyAtHomeSchemaDefaults(raw && raw.trim() ? JSON.parse(raw) : {});
  }

  const localStorageDir =
    env?.ACTOR_STORAGE_DIR || env?.APIFY_LOCAL_STORAGE_DIR || env?.CRAWLEE_STORAGE_DIR;
  if (localStorageDir) {
    const kvsId =
      env?.ACTOR_DEFAULT_KEY_VALUE_STORE_ID ||
      env?.APIFY_DEFAULT_KEY_VALUE_STORE_ID ||
      'default';
    const inputKey = env?.ACTOR_INPUT_KEY || env?.APIFY_INPUT_KEY || 'INPUT';
    for (const candidateName of [`${inputKey}.json`, inputKey]) {
      const localInputPath = path.join(
        localStorageDir,
        'key_value_stores',
        kvsId,
        candidateName
      );
      if (fs.existsSync(localInputPath)) {
        const raw = fs.readFileSync(localInputPath, 'utf8');
        return applyAtHomeSchemaDefaults(raw && raw.trim() ? JSON.parse(raw) : {});
      }
    }
  }

  const kvsId =
    env?.ACTOR_DEFAULT_KEY_VALUE_STORE_ID || env?.APIFY_DEFAULT_KEY_VALUE_STORE_ID;
  const token = env?.APIFY_TOKEN;
  if (kvsId && token && typeof fetchImpl === 'function') {
    const apiBase = resolveSafeApifyApiBaseUrl(
      env?.APIFY_API_BASE_URL,
      env?.APIFY_API_PUBLIC_BASE_URL
    );
    const inputKey = encodeURIComponent(
      env?.ACTOR_INPUT_KEY || env?.APIFY_INPUT_KEY || 'INPUT'
    );
    const url = `${apiBase}/v2/key-value-stores/${encodeURIComponent(kvsId)}/records/${inputKey}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    try {
      const res = await fetchImpl(url, {
        method: 'GET',
        headers: {
          authorization: `Bearer ${token}`,
          accept: 'application/json',
        },
        signal: controller.signal,
      });
      if (res.status === 200) {
        const text = await res.text();
        const parsed = text && text.trim() ? JSON.parse(text) : {};
        return applyAtHomeSchemaDefaults(parsed);
      }
      if (res.status === 204 || res.status === 404) {
        return applyAtHomeSchemaDefaults({});
      }
      return {};
    } finally {
      clearTimeout(timer);
    }
  }

  return applyAtHomeSchemaDefaults({});
}

/**
 * Creates native zero-dependency Apify Platform runtime hooks (`runId`, `isAtHome`,
 * `loadCheckpoint`, `saveCheckpoint`, `listDeliveredIds`, `pushData`, `chargeEvent`, `saveOutput`)
 * when Apify environment variables (`ACTOR_*` primary, `APIFY_*` fallback) or local
 * storage directories are configured. Returns `{}` in pure local CLI/MCP mode.
 *
 * @param {object} [env=process.env]
 * @param {Function} [fetchImpl=globalThis.fetch]
 * @returns {object}
 */
export function createApifyPlatformHooks(env = process.env, fetchImpl = globalThis.fetch) {
  const rawRunId = env?.ACTOR_RUN_ID || env?.APIFY_ACTOR_RUN_ID;
  const runId = rawRunId ? String(rawRunId).trim() : undefined;
  const token = env?.APIFY_TOKEN ? String(env.APIFY_TOKEN).trim() : undefined;
  const rawDatasetId = env?.ACTOR_DEFAULT_DATASET_ID || env?.APIFY_DEFAULT_DATASET_ID;
  const datasetId = rawDatasetId ? String(rawDatasetId).trim() : undefined;
  const rawKvsId =
    env?.ACTOR_DEFAULT_KEY_VALUE_STORE_ID || env?.APIFY_DEFAULT_KEY_VALUE_STORE_ID;
  const kvsId = rawKvsId ? String(rawKvsId).trim() : undefined;
  const localStorageDir =
    env?.ACTOR_STORAGE_DIR || env?.APIFY_LOCAL_STORAGE_DIR || env?.CRAWLEE_STORAGE_DIR;
  const isAtHome = env?.APIFY_IS_AT_HOME === '1' || env?.APIFY_IS_AT_HOME === 'true';

  const hasCloudApi = Boolean((isAtHome || runId) && token && typeof fetchImpl === 'function');
  if (!hasCloudApi && !localStorageDir) {
    if (isAtHome) {
      return { isAtHome: true, ...(runId ? { runId } : {}) };
    }
    return runId ? { runId } : {};
  }

  const hooks = {};
  if (runId) {
    hooks.runId = runId;
  }
  if (isAtHome || hasCloudApi) {
    hooks.isAtHome = true;
  }

  if (hasCloudApi) {
    const apiBase = resolveSafeApifyApiBaseUrl(
      env?.APIFY_API_BASE_URL,
      env?.APIFY_API_PUBLIC_BASE_URL
    );
    let pricingInfoChargeEvents = null;
    let resolvedUserTier = String(
      env?.APIFY_USER_PLAN_TIER || env?.APIFY_PRICING_TIER || ''
    )
      .trim()
      .toUpperCase();
    const rawPricingInfoEnv = env?.APIFY_ACTOR_PRICING_INFO || env?.ACTOR_PRICING_INFO;
    if (rawPricingInfoEnv) {
      try {
        const parsedPricing = JSON.parse(String(rawPricingInfoEnv));
        const eventsObj = parsedPricing?.pricingPerEvent?.actorChargeEvents;
        if (eventsObj && typeof eventsObj === 'object') {
          pricingInfoChargeEvents = eventsObj;
        }
        const parsedTier = String(parsedPricing?.userTier || parsedPricing?.tier || '').trim();
        if (parsedTier) {
          resolvedUserTier = parsedTier.toUpperCase();
        }
      } catch {
        pricingInfoChargeEvents = null;
      }
    }
    const rawMaxChargeStr =
      env?.ACTOR_MAX_TOTAL_CHARGE_USD !== undefined && env?.ACTOR_MAX_TOTAL_CHARGE_USD !== null
        ? String(env.ACTOR_MAX_TOTAL_CHARGE_USD).trim()
        : '';
    const maxTotalChargeUsdRaw = rawMaxChargeStr !== '' ? Number(rawMaxChargeStr) : NaN;
    const hasMaxChargeUsd = Number.isFinite(maxTotalChargeUsdRaw) && maxTotalChargeUsdRaw >= 0;
    const isPayingFlag = String(env?.APIFY_USER_IS_PAYING ?? '')
      .trim()
      .toLowerCase();
    const isExplicitlyFreeUser = isPayingFlag === '0' || isPayingFlag === 'false';
    const isExplicitlyPayingUser = isPayingFlag === '1' || isPayingFlag === 'true';
    const resolveTieredEventPriceInfo = (eventObj, { allowZero = false } = {}) => {
      if (!eventObj || typeof eventObj !== 'object') {
        return { priceUsd: NaN, deterministic: true };
      }
      const isValidPrice = (n) => Number.isFinite(n) && (allowZero ? n >= 0 : n > 0);
      const flat = Number(eventObj.eventPriceUsd);
      if (isValidPrice(flat)) {
        return { priceUsd: flat, deterministic: true };
      }
      const tiered = eventObj.eventTieredPricingUsd;
      if (!tiered || typeof tiered !== 'object' || Array.isArray(tiered)) {
        return { priceUsd: NaN, deterministic: true };
      }
      if (resolvedUserTier && tiered[resolvedUserTier]) {
        const explicitPrice = Number(tiered[resolvedUserTier]?.tieredEventPriceUsd);
        if (isValidPrice(explicitPrice)) {
          return { priceUsd: explicitPrice, deterministic: true };
        }
      }
      if (isExplicitlyFreeUser) {
        const freePrice = Number(tiered.FREE?.tieredEventPriceUsd);
        if (isValidPrice(freePrice)) {
          return { priceUsd: freePrice, deterministic: true };
        }
      }
      const candidatePrices = Object.entries(tiered)
        .filter(([k]) => (isExplicitlyPayingUser ? k !== 'FREE' : true))
        .map(([, v]) => Number(v?.tieredEventPriceUsd))
        .filter(isValidPrice);
      const distinctPrices = Array.from(new Set(candidatePrices));
      if (distinctPrices.length === 1) {
        return { priceUsd: distinctPrices[0], deterministic: true };
      }
      return {
        priceUsd: NaN,
        deterministic: false,
      };
    };
    let userTierProbeDone = false;
    const ensureUserTierResolved = async () => {
      if (userTierProbeDone || resolvedUserTier || isExplicitlyFreeUser || !token || typeof fetchImpl !== 'function') {
        return resolvedUserTier;
      }
      userTierProbeDone = true;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 1500);
      try {
        const res = await fetchImpl(`${apiBase}/v2/users/me`, {
          method: 'GET',
          headers: {
            authorization: `Bearer ${token}`,
            accept: 'application/json',
          },
          signal: controller.signal,
        });
        if (res && res.status >= 200 && res.status < 300) {
          let body = null;
          if (typeof res.json === 'function') {
            body = await res.json();
          } else if (typeof res.text === 'function') {
            const txt = await res.text();
            body = txt && txt.trim() ? JSON.parse(txt) : null;
          }
          const fetchedTier = String(
            body?.data?.plan?.tier ||
              body?.data?.userTier ||
              body?.plan?.tier ||
              ''
          )
            .trim()
            .toUpperCase();
          if (fetchedTier) {
            resolvedUserTier = fetchedTier;
          }
        }
      } catch {
        // Leave resolvedUserTier empty on network/mock failure
      } finally {
        clearTimeout(timer);
      }
      if (resolvedUserTier) {
        const refreshedStart = computeStartFeeState();
        hooks.actorStartFeeUsdc = refreshedStart.feeUsd;
        const primaryInfo = resolveTieredEventPriceInfo(
          pricingInfoChargeEvents?.[ACTOR_PRICING_CONTRACT.eventName],
          { allowZero: false }
        );
        if (Number.isFinite(primaryInfo.priceUsd) && primaryInfo.priceUsd > 0) {
          hooks.unitPriceUsdc = primaryInfo.priceUsd;
        }
        hooks.pricingDeterministic = refreshedStart.deterministic && primaryInfo.deterministic;
      }
      return resolvedUserTier;
    };
    hooks.resolveUserTier = ensureUserTierResolved;
    const includeStartFeeFlag = String(env?.ACTOR_INCLUDE_START_FEE ?? '1')
      .trim()
      .toLowerCase();
    const includeStartFee = includeStartFeeFlag !== '0' && includeStartFeeFlag !== 'false';
    const computeStartFeeState = () => {
      const hasExplicitEnvStart =
        env?.ACTOR_START_FEE_USD !== undefined &&
        env?.ACTOR_START_FEE_USD !== null &&
        String(env.ACTOR_START_FEE_USD).trim() !== '';
      if (hasExplicitEnvStart) {
        const val = Number(env.ACTOR_START_FEE_USD);
        const valid = Number.isFinite(val) && val >= 0;
        const feeUsd = valid ? val : ACTOR_PRICING_CONTRACT.actorStartFeeUsdc;
        return {
          feeUsd: includeStartFee ? feeUsd : 0,
          micros: includeStartFee ? Math.round(feeUsd * 1_000_000) : 0,
          deterministic: true,
        };
      }
      const startInfo = resolveTieredEventPriceInfo(
        pricingInfoChargeEvents?.['apify-actor-start'],
        { allowZero: true }
      );
      if (!startInfo.deterministic) {
        return {
          feeUsd: includeStartFee ? null : 0,
          micros: 0,
          deterministic: !includeStartFee,
        };
      }
      const feeUsd =
        Number.isFinite(startInfo.priceUsd) && startInfo.priceUsd >= 0
          ? startInfo.priceUsd
          : ACTOR_PRICING_CONTRACT.actorStartFeeUsdc;
      return {
        feeUsd: includeStartFee ? feeUsd : 0,
        micros: includeStartFee ? Math.round(feeUsd * 1_000_000) : 0,
        deterministic: true,
      };
    };
    const initialStartState = computeStartFeeState();
    const maxBudgetMicros = hasMaxChargeUsd ? Math.round(maxTotalChargeUsdRaw * 1_000_000) : 0;
    let cumulativeChargedInAdapter = 0;
    let adapterChargeLimitLatched = false;
    hooks.actorStartFeeUsdc = initialStartState.feeUsd;
    hooks.pricingDeterministic = initialStartState.deterministic;

    if (kvsId) {
      const checkpointRecordUrl = `${apiBase}/v2/key-value-stores/${encodeURIComponent(kvsId)}/records/${ACTOR_PRICING_CONTRACT.checkpointKey}`;
      const outputRecordUrl = `${apiBase}/v2/key-value-stores/${encodeURIComponent(kvsId)}/records/OUTPUT`;

      hooks.loadCheckpoint = async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 1500);
        try {
          const res = await fetchImpl(checkpointRecordUrl, {
            method: 'GET',
            headers: {
              authorization: `Bearer ${token}`,
              accept: 'application/json',
            },
            signal: controller.signal,
          });
          if (res.status === 404 || res.status === 204) {
            return null;
          }
          if (res.status >= 200 && res.status < 300) {
            const text = await res.text();
            const loaded = text && text.trim() ? JSON.parse(text) : null;
            if (
              loaded &&
              Array.isArray(loaded.chargedIds) &&
              (!loaded.runId || !runId || String(loaded.runId) === String(runId))
            ) {
              cumulativeChargedInAdapter = loaded.chargedIds.length;
            }
            return loaded;
          }
          throw new Error(`Apify KVS loadCheckpoint failed with HTTP ${res.status}`);
        } finally {
          clearTimeout(timer);
        }
      };

      hooks.saveCheckpoint = async (snapshot) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 1500);
        try {
          const res = await fetchImpl(checkpointRecordUrl, {
            method: 'PUT',
            headers: {
              authorization: `Bearer ${token}`,
              'content-type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify(snapshot),
            signal: controller.signal,
          });
          if (res.status < 200 || res.status >= 300) {
            throw new Error(`Apify KVS saveCheckpoint HTTP ${res.status}`);
          }
        } finally {
          clearTimeout(timer);
        }
      };

      hooks.saveOutput = async (outputRecord) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 1500);
        try {
          const res = await fetchImpl(outputRecordUrl, {
            method: 'PUT',
            headers: {
              authorization: `Bearer ${token}`,
              'content-type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify(outputRecord),
            signal: controller.signal,
          });
          if (res.status < 200 || res.status >= 300) {
            throw new Error(`Apify KVS saveOutput HTTP ${res.status}`);
          }
        } finally {
          clearTimeout(timer);
        }
      };
    }

    if (datasetId) {
      const datasetItemsUrl = `${apiBase}/v2/datasets/${encodeURIComponent(datasetId)}/items`;
      hooks.listDeliveredIds = async () => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 1500);
        try {
          const res = await fetchImpl(`${datasetItemsUrl}?fields=creativeId&clean=1`, {
            method: 'GET',
            headers: {
              authorization: `Bearer ${token}`,
              accept: 'application/json',
            },
            signal: controller.signal,
          });
          if (res.status >= 200 && res.status < 300) {
            const text = await res.text();
            const parsed = text && text.trim() ? JSON.parse(text) : [];
            const arr = Array.isArray(parsed)
              ? parsed
              : Array.isArray(parsed?.data?.items)
                ? parsed.data.items
                : [];
            return arr
              .map((row) => (typeof row?.creativeId === 'string' ? row.creativeId : null))
              .filter(Boolean);
          }
          throw new Error(`Apify Dataset listDeliveredIds failed with HTTP ${res.status}`);
        } finally {
          clearTimeout(timer);
        }
      };

      hooks.pushData = async (items) => {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 1500);
        try {
          const res = await fetchImpl(datasetItemsUrl, {
            method: 'POST',
            headers: {
              authorization: `Bearer ${token}`,
              'content-type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify(items),
            signal: controller.signal,
          });
          if (res.status < 200 || res.status >= 300) {
            throw new Error(`Apify Dataset pushData HTTP ${res.status}`);
          }
        } finally {
          clearTimeout(timer);
        }
      };
    }

    if (runId) {
      const chargeUrl = `${apiBase}/v2/actor-runs/${encodeURIComponent(runId)}/charge`;
      const allowUnbilledAtHome = env?.ADPULSE_ALLOW_UNBILLED_AT_HOME === '1';
      let unbilledOwnerTestLatched = false;
      let latchedPlatformEventName = null;
      const resolvePlatformEventAndPrice = (rawEventName) => {
        const candidate = String(rawEventName || ACTOR_PRICING_CONTRACT.eventName);
        const effectiveName =
          latchedPlatformEventName ||
          (() => {
            if (pricingInfoChargeEvents) {
              if (Object.prototype.hasOwnProperty.call(pricingInfoChargeEvents, candidate)) {
                return candidate;
              }
              if (
                candidate === 'ad-creative-scraped' ||
                candidate === 'ad_transparency_creative_retrieved'
              ) {
                if (
                  Object.prototype.hasOwnProperty.call(
                    pricingInfoChargeEvents,
                    'ad_transparency_creative_retrieved'
                  )
                ) {
                  return 'ad_transparency_creative_retrieved';
                }
                if (
                  Object.prototype.hasOwnProperty.call(
                    pricingInfoChargeEvents,
                    'ad-creative-scraped'
                  )
                ) {
                  return 'ad-creative-scraped';
                }
              }
            }
            return candidate;
          })();
        const evInfo = resolveTieredEventPriceInfo(
          pricingInfoChargeEvents?.[effectiveName],
          { allowZero: false }
        );
        const unitPriceUsdc = !evInfo.deterministic
          ? null
          : Number.isFinite(evInfo.priceUsd) && evInfo.priceUsd > 0
            ? evInfo.priceUsd
            : ACTOR_PRICING_CONTRACT.priceUsdc;
        return {
          eventName: effectiveName,
          unitPriceUsdc,
          deterministic: evInfo.deterministic,
        };
      };
      const initialPrimaryPrice = resolvePlatformEventAndPrice(
        ACTOR_PRICING_CONTRACT.eventName
      );
      hooks.unitPriceUsdc = initialPrimaryPrice.unitPriceUsdc;
      hooks.pricingDeterministic =
        initialStartState.deterministic && initialPrimaryPrice.deterministic;
      hooks.chargeEvent = async (receipt) => {
        const requestedCount = Math.max(0, Number(receipt?.count) || 0);
        let {
          eventName: primaryEventName,
          unitPriceUsdc: resolvedUnitPriceUsdc,
          deterministic: eventPriceDeterministic,
        } = resolvePlatformEventAndPrice(receipt?.eventName);
        let startState = computeStartFeeState();
        if ((!eventPriceDeterministic || !startState.deterministic) && !userTierProbeDone) {
          await ensureUserTierResolved();
          ({
            eventName: primaryEventName,
            unitPriceUsdc: resolvedUnitPriceUsdc,
            deterministic: eventPriceDeterministic,
          } = resolvePlatformEventAndPrice(receipt?.eventName));
          startState = computeStartFeeState();
        }
        hooks.unitPriceUsdc = resolvedUnitPriceUsdc;
        hooks.actorStartFeeUsdc = startState.feeUsd;
        hooks.pricingDeterministic = eventPriceDeterministic && startState.deterministic;
        if (unbilledOwnerTestLatched) {
          return {
            chargedCount: 0,
            eventChargeLimitReached: false,
            unbilledOwnerTestBypass: true,
            chargedCreativeIds: [],
            eventName: primaryEventName,
            unitPriceUsdc: resolvedUnitPriceUsdc,
            pricingDeterministic: hooks.pricingDeterministic,
          };
        }
        if (adapterChargeLimitLatched) {
          return {
            chargedCount: 0,
            eventChargeLimitReached: true,
            chargedCreativeIds: [],
            eventName: primaryEventName,
            unitPriceUsdc: resolvedUnitPriceUsdc,
            pricingDeterministic: hooks.pricingDeterministic,
          };
        }
        const unitPriceMicros =
          resolvedUnitPriceUsdc === null ? NaN : Math.round(resolvedUnitPriceUsdc * 1_000_000);
        if (eventPriceDeterministic && (!Number.isFinite(unitPriceMicros) || unitPriceMicros < 1)) {
          throw new Error(
            `Invalid unitPriceUsdc (${String(resolvedUnitPriceUsdc)}): unitPriceMicros must be >= 1`
          );
        }
        const canEnforceLocalBudgetCap =
          hasMaxChargeUsd && eventPriceDeterministic && startState.deterministic;
        const maxPayableEvents = canEnforceLocalBudgetCap
          ? Math.floor(Math.max(0, maxBudgetMicros - startState.micros) / unitPriceMicros)
          : Infinity;
        const remainingAllowance = Number.isFinite(maxPayableEvents)
          ? Math.max(0, maxPayableEvents - cumulativeChargedInAdapter)
          : requestedCount;
        const countToCharge = Math.min(requestedCount, remainingAllowance);
        const limitReached =
          Number.isFinite(maxPayableEvents) &&
          cumulativeChargedInAdapter + countToCharge >= maxPayableEvents &&
          countToCharge < requestedCount;

        if (countToCharge === 0) {
          return {
            chargedCount: 0,
            eventChargeLimitReached: Number.isFinite(maxPayableEvents),
            chargedCreativeIds: [],
            eventName: primaryEventName,
            unitPriceUsdc: resolvedUnitPriceUsdc,
          };
        }

        const chargeIdempotencyVerified =
          env?.APIFY_CHARGE_IDEMPOTENCY_SUPPORTED === '1' ||
          env?.APIFY_CHARGE_IDEMPOTENCY_SUPPORTED === 'true';
        const maxChargeAttempts = chargeIdempotencyVerified ? 2 : 1;
        const perAttemptTimeoutMs = 900;
        const canStartChargePost = () =>
          !Number.isFinite(receipt?.deadlineAtMs) ||
          Date.now() + perAttemptTimeoutMs + 300 < receipt.deadlineAtMs;

        const postChargeRequestWithIdempotentRetry = async (
          eventNameToPost,
          idempotencyKeyToPost
        ) => {
          let lastPostErr = null;
          for (let attempt = 1; attempt <= maxChargeAttempts; attempt += 1) {
            if (attempt > 1 && !canStartChargePost()) {
              break;
            }
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), perAttemptTimeoutMs);
            try {
              const res = await fetchImpl(chargeUrl, {
                method: 'POST',
                headers: {
                  authorization: `Bearer ${token}`,
                  'content-type': 'application/json; charset=utf-8',
                  'idempotency-key': idempotencyKeyToPost,
                },
                body: JSON.stringify({
                  eventName: eventNameToPost,
                  count: countToCharge,
                }),
                signal: controller.signal,
              });
              if (
                attempt < maxChargeAttempts &&
                (res.status === 429 || res.status >= 500) &&
                canStartChargePost()
              ) {
                try {
                  await res.body?.cancel?.();
                } catch {
                  // Ignore body cancel failure on retry
                }
                await new Promise((r) => setTimeout(r, 150));
                continue;
              }
              const bodyText =
                typeof res?.text === 'function'
                  ? await Promise.race([
                      res.text(),
                      new Promise((_, reject) => {
                        if (controller.signal.aborted) {
                          reject(new Error('AbortError: charge response body timed out'));
                          return;
                        }
                        controller.signal.addEventListener(
                          'abort',
                          () => reject(new Error('AbortError: charge response body timed out')),
                          { once: true }
                        );
                      }),
                    ])
                  : '';
              return { status: res.status, bodyText };
            } catch (err) {
              lastPostErr = err;
              if (attempt < maxChargeAttempts && canStartChargePost()) {
                await new Promise((r) => setTimeout(r, 150));
                continue;
              }
              throw err;
            } finally {
              clearTimeout(timer);
            }
          }
          throw lastPostErr || new Error('Charge POST exceeded run deadline');
        };

        try {
          let effectiveEventName = primaryEventName;
          let effectiveIdempotencyKey = receipt.idempotencyKey;
          let res = await postChargeRequestWithIdempotentRetry(
            primaryEventName,
            receipt.idempotencyKey
          );
          if (
            res.status === 404 &&
            !pricingInfoChargeEvents &&
            !latchedPlatformEventName &&
            (primaryEventName === 'ad-creative-scraped' ||
              primaryEventName === 'ad_transparency_creative_retrieved')
          ) {
            const aliasEventName =
              primaryEventName === 'ad-creative-scraped'
                ? 'ad_transparency_creative_retrieved'
                : 'ad-creative-scraped';
            const aliasIdempotencyKey = `${receipt.idempotencyKey}-${aliasEventName}`;
            const fallbackRes = await postChargeRequestWithIdempotentRetry(
              aliasEventName,
              aliasIdempotencyKey
            );
            if (fallbackRes.status !== 404) {
              res = fallbackRes;
              effectiveEventName = aliasEventName;
              effectiveIdempotencyKey = aliasIdempotencyKey;
              if (
                (fallbackRes.status >= 200 && fallbackRes.status < 300) ||
                fallbackRes.status === 402
              ) {
                latchedPlatformEventName = aliasEventName;
              }
            }
          }
          if (res.status === 402) {
            // Platform enforced spending ceiling (HTTP 402 Payment Required): latch so no further charge POSTs occur
            adapterChargeLimitLatched = true;
            return {
              chargedCount: 0,
              eventChargeLimitReached: true,
              chargedCreativeIds: [],
              eventName: effectiveEventName,
              unitPriceUsdc: resolvedUnitPriceUsdc,
              idempotencyKey: effectiveIdempotencyKey,
            };
          }
          if (allowUnbilledAtHome && (res.status === 405 || res.status === 403)) {
            let isUnmonetizedNotAllowed = res.status === 405;
            if (res.status === 403) {
              try {
                const errText = res.bodyText || '';
                const errJson = errText && errText.trim() ? JSON.parse(errText) : null;
                isUnmonetizedNotAllowed = errJson?.error?.type === 'operation-not-allowed';
              } catch {
                isUnmonetizedNotAllowed = false;
              }
            }
            if (isUnmonetizedNotAllowed) {
              unbilledOwnerTestLatched = true;
              return {
                chargedCount: 0,
                eventChargeLimitReached: false,
                unbilledOwnerTestBypass: true,
                chargedCreativeIds: [],
                eventName: effectiveEventName,
                unitPriceUsdc: resolvedUnitPriceUsdc,
                idempotencyKey: effectiveIdempotencyKey,
              };
            }
          }
          if (res.status < 200 || res.status >= 300) {
            let errSuffix = '';
            try {
              const errText = res.bodyText || '';
              if (errText && errText.trim()) {
                const errJson = JSON.parse(errText);
                const errType = errJson?.error?.type;
                if (typeof errType === 'string' && /^[A-Za-z0-9_.:-]{1,64}$/.test(errType)) {
                  errSuffix = ` (${errType})`;
                }
              }
            } catch {
              errSuffix = '';
            }
            throw new Error(`Apify Pay-per-Event charge HTTP ${res.status}${errSuffix}`);
          }
          const rawText = res.bodyText || '';
          const parsed = rawText && rawText.trim() ? JSON.parse(rawText) : {};
          const dataObj = parsed?.data && typeof parsed.data === 'object' ? parsed.data : parsed;
          // Apify REST `POST /v2/actor-runs/{runId}/charge` returns HTTP 201 Created with `{}` on success.
          // Only fallback to `countToCharge` when `chargedCount` is genuinely omitted; if present but invalid, throw fail-closed.
          const hasExplicitChargedCount =
            Boolean(dataObj) &&
            typeof dataObj === 'object' &&
            Object.prototype.hasOwnProperty.call(dataObj, 'chargedCount') &&
            dataObj.chargedCount !== undefined;
          if (
            hasExplicitChargedCount &&
            (!Number.isInteger(dataObj.chargedCount) ||
              dataObj.chargedCount < 0 ||
              dataObj.chargedCount > countToCharge)
          ) {
            throw new Error(
              `Apify Pay-per-Event charge response contained invalid chargedCount: ${String(dataObj.chargedCount)}`
            );
          }
          const resolvedChargedCount = hasExplicitChargedCount
            ? dataObj.chargedCount
            : countToCharge;
          cumulativeChargedInAdapter += resolvedChargedCount;
          const resolvedLimitReached =
            Boolean(dataObj?.eventChargeLimitReached) ||
            limitReached ||
            (Number.isFinite(maxPayableEvents) && cumulativeChargedInAdapter >= maxPayableEvents);
          let subsetIds;
          if (Array.isArray(dataObj?.chargedCreativeIds)) {
            const reqIds = Array.isArray(receipt?.creativeIds) ? receipt.creativeIds : null;
            const uniqueValidIds = new Set(
              dataObj.chargedCreativeIds.filter(
                (id) => typeof id === 'string' && (!reqIds || reqIds.includes(id))
              )
            );
            if (
              dataObj.chargedCreativeIds.length !== resolvedChargedCount ||
              uniqueValidIds.size !== resolvedChargedCount
            ) {
              throw new Error(
                'Apify Pay-per-Event charge response contained invalid chargedCreativeIds'
              );
            }
            subsetIds = Array.from(uniqueValidIds);
          } else if (Array.isArray(receipt?.creativeIds)) {
            subsetIds = receipt.creativeIds.slice(0, resolvedChargedCount);
          }
          return {
            chargedCount: resolvedChargedCount,
            eventChargeLimitReached: resolvedLimitReached,
            eventName: effectiveEventName,
            unitPriceUsdc: resolvedUnitPriceUsdc,
            idempotencyKey: effectiveIdempotencyKey,
            ...(subsetIds ? { chargedCreativeIds: subsetIds } : {}),
          };
        } finally {
          // Per-attempt timeout timers are cleared inside postChargeRequestWithIdempotentRetry
        }
      };
    }

    return hooks;
  }

  // Local Apify storage directory mode (`APIFY_LOCAL_STORAGE_DIR`)
  const storeName = kvsId || 'default';
  const dsName = datasetId || 'default';
  const kvsDir = path.join(localStorageDir, 'key_value_stores', storeName);
  const dsDir = path.join(localStorageDir, 'datasets', dsName);
  const checkpointPath = path.join(kvsDir, `${ACTOR_PRICING_CONTRACT.checkpointKey}.json`);
  const outputPath = path.join(kvsDir, 'OUTPUT.json');

  hooks.loadCheckpoint = async () => {
    if (!fs.existsSync(checkpointPath)) return null;
    return JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
  };

  hooks.saveCheckpoint = async (snapshot) => {
    fs.mkdirSync(kvsDir, { recursive: true });
    fs.writeFileSync(checkpointPath, JSON.stringify(snapshot, null, 2), 'utf8');
  };

  hooks.saveOutput = async (outputRecord) => {
    fs.mkdirSync(kvsDir, { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(outputRecord, null, 2), 'utf8');
  };

  hooks.listDeliveredIds = async () => {
    if (!fs.existsSync(dsDir)) return [];
    const existingFiles = fs.readdirSync(dsDir).filter((f) => f.endsWith('.json'));
    const ids = [];
    for (const file of existingFiles) {
      try {
        const parsed = JSON.parse(fs.readFileSync(path.join(dsDir, file), 'utf8'));
        if (typeof parsed?.creativeId === 'string') {
          ids.push(parsed.creativeId);
        }
      } catch {
        // Ignore unreadable partial files
      }
    }
    return ids;
  };

  hooks.pushData = async (items) => {
    fs.mkdirSync(dsDir, { recursive: true });
    const existingSeqs = fs
      .readdirSync(dsDir)
      .map((f) => {
        const m = /^(\d+)\.json$/.exec(f);
        return m ? Number(m[1]) : 0;
      })
      .filter((n) => Number.isInteger(n) && n > 0);
    let nextSeq = existingSeqs.length > 0 ? Math.max(...existingSeqs) + 1 : 1;
    const list = Array.isArray(items) ? items : [items];
    for (const item of list) {
      const fileName = `${String(nextSeq++).padStart(9, '0')}.json`;
      fs.writeFileSync(path.join(dsDir, fileName), JSON.stringify(item, null, 2), 'utf8');
    }
  };

  return hooks;
}

/**
 * Normalizes a persisted KVS billing checkpoint object.
 * If the checkpoint belongs to a different `runId`, discards stale state and starts fresh.
 *
 * @param {unknown} rawState
 * @param {string} runId
 * @returns {object}
 */
function normalizeBillingCheckpointState(rawState, runId) {
  const s = rawState && typeof rawState === 'object' && !Array.isArray(rawState) ? rawState : {};
  if (s.runId && String(s.runId).trim() !== String(runId).trim()) {
    return {
      runId: String(runId || 'default_run'),
      chargedIds: [],
      deliveredIds: [],
      inFlightIds: [],
      inFlightIdempotencyKey: null,
      unknownOutcomeIds: [],
      stagedItemsById: {},
    };
  }

  const toUniqueIdArray = (arr) =>
    Array.isArray(arr)
      ? Array.from(new Set(arr.map((x) => String(x || '').trim()).filter((x) => CREATIVE_ID_RE.test(x))))
      : [];

  const stagedItemsById = {};
  if (s.stagedItemsById && typeof s.stagedItemsById === 'object' && !Array.isArray(s.stagedItemsById)) {
    for (const [k, v] of Object.entries(s.stagedItemsById)) {
      if (CREATIVE_ID_RE.test(k) && v && typeof v === 'object') {
        stagedItemsById[k] = v;
      }
    }
  }

  return {
    runId: String(s.runId || runId || 'default_run'),
    chargedIds: toUniqueIdArray(s.chargedIds),
    deliveredIds: toUniqueIdArray(s.deliveredIds),
    inFlightIds: toUniqueIdArray(s.inFlightIds),
    inFlightIdempotencyKey:
      typeof s.inFlightIdempotencyKey === 'string' && s.inFlightIdempotencyKey.trim()
        ? s.inFlightIdempotencyKey.trim()
        : null,
    unknownOutcomeIds: toUniqueIdArray(s.unknownOutcomeIds),
    stagedItemsById,
  };
}

/**
 * Executes the end-to-end Google Ads Transparency Actor workflow with crash-safe billing
 * checkpointing, strict `ChargeResult` validation, deterministic partial-limit prefix delivery,
 * mid-stream cursor rewind, and fail-closed zero-charge protection.
 *
 * @param {object} input
 * @param {object} [hooks]
 * @param {Function} [hooks.pushData]
 * @param {Function} [hooks.chargeEvent]
 * @param {Function} [hooks.loadCheckpoint]
 * @param {Function} [hooks.saveCheckpoint]
 * @param {Function} [hooks.fetchImpl]
 * @param {Function} [hooks.nowMs]
 * @param {string} [hooks.runId]
 * @returns {Promise<object>}
 */
export async function runGoogleAdsTransparencyActor(input = {}, hooks = {}) {
  const nowMs = typeof hooks.nowMs === 'function' ? hooks.nowMs : () => Date.now();
  const startedAtMs = nowMs();
  // Authoritative runId precedence: hooks.runId -> ACTOR_RUN_ID -> APIFY_ACTOR_RUN_ID -> input.runId -> 'default_run'
  const runId = String(
    hooks.runId ||
      process.env.ACTOR_RUN_ID ||
      process.env.APIFY_ACTOR_RUN_ID ||
      input?.runId ||
      'default_run'
  );
  const hasChargeHook = typeof hooks.chargeEvent === 'function';
  let billingMode =
    hasChargeHook || hooks.isAtHome === true ? 'APIFY_PAY_PER_EVENT' : 'LOCAL_UNBILLED';

  const maxRunDurationMs = Math.min(
    DEFAULT_RUN_DEADLINE_MS,
    Math.max(1000, Number(input?.maxRunDurationMs) || DEFAULT_RUN_DEADLINE_MS)
  );
  const deadlineAtMs = startedAtMs + maxRunDurationMs;
  const billingReserveMs =
    maxRunDurationMs >= 6000 ? 2500 : Math.min(1000, Math.floor(maxRunDurationMs * 0.25));
  const rpcDeadlineAtMs = hasChargeHook
    ? Math.max(startedAtMs + 500, deadlineAtMs - billingReserveMs)
    : deadlineAtMs;
  const step4ReserveMs = hasChargeHook
    ? Math.min(2100, Math.floor(billingReserveMs * 0.85))
    : 0;

  const finalizeActorReturn = async (finalResult) => {
    if (typeof hooks.saveOutput === 'function' && nowMs() < deadlineAtMs) {
      try {
        await hooks.saveOutput({
          ok: finalResult.ok,
          status: finalResult.status,
          ...(finalResult.errorCode ? { errorCode: finalResult.errorCode } : {}),
          reason: finalResult.reason || null,
          billingMode: finalResult.billingMode,
          extractedCount: finalResult.extractedCount,
          deliveredCount: finalResult.deliveredCount,
          billableCount: finalResult.billableCount,
          chargedEventCount: finalResult.chargedEventCount,
          pagination: finalResult.pagination,
          ...(Array.isArray(finalResult.warnings) && finalResult.warnings.length > 0
            ? { warnings: finalResult.warnings }
            : {}),
          queryMeta: finalResult.queryMeta,
          selectedEntities: finalResult.selectedEntities,
          telemetry: finalResult.telemetry,
        });
      } catch {
        // Non-fatal KVS summary write
      }
    }
    return finalResult;
  };

  const pushDataWithRetry = async (itemsToPush) => {
    if (
      typeof hooks.pushData !== 'function' ||
      !Array.isArray(itemsToPush) ||
      itemsToPush.length === 0
    ) {
      return { ok: true };
    }
    let pendingItems = [...itemsToPush];
    let lastErr = null;
    for (let attempt = 1; attempt <= 2; attempt += 1) {
      try {
        await hooks.pushData(pendingItems);
        return { ok: true };
      } catch (err) {
        lastErr = err;
        if (attempt < 2) {
          if (nowMs() + 1500 >= deadlineAtMs || typeof hooks.listDeliveredIds !== 'function') {
            return { ok: false, error: lastErr };
          }
          try {
            const committedIds = new Set(await hooks.listDeliveredIds());
            pendingItems = pendingItems.filter((it) => !committedIds.has(it.creativeId));
            if (pendingItems.length === 0) {
              return { ok: true };
            }
          } catch (reconcileErr) {
            return { ok: false, error: reconcileErr || lastErr };
          }
        }
      }
    }
    return { ok: false, error: lastErr };
  };

  // Step 0.0: Fail-Closed At-Home Cloud Hook Completeness Gate
  // In Apify Cloud (`hooks.isAtHome === true`), require all 4 platform hooks (`chargeEvent`,
  // `pushData`, `loadCheckpoint`, `saveCheckpoint`) before any RPC fetch or billing occurs.
  if (
    hooks.isAtHome === true &&
    (typeof hooks.chargeEvent !== 'function' ||
      typeof hooks.pushData !== 'function' ||
      typeof hooks.loadCheckpoint !== 'function' ||
      typeof hooks.saveCheckpoint !== 'function')
  ) {
    const durationMs = Math.max(1, nowMs() - startedAtMs);
    return finalizeActorReturn({
      ok: false,
      status: 'PARTIAL_BILLING_HALT',
      reason:
        'Incomplete Apify Cloud runtime hooks (missing chargeEvent, pushData, loadCheckpoint, or saveCheckpoint in at-home mode)',
      billingMode,
      queryMeta: null,
      selectedEntities: [],
      items: [],
      extractedCount: 0,
      deliveredCount: 0,
      billableCount: 0,
      chargedEventCount: 0,
      unknownOutcomeIds: [],
      chargeReceipts: [],
      pagination: {
        nextPageToken: input?.pageToken || null,
        paginationStatus: 'PARTIAL_BILLING_HALT',
        paginationIncompleteReason: 'CLOUD_HOOKS_INCOMPLETE',
      },
      telemetry: computeRunEconomicsTelemetry({
        billableCount: 0,
        chargedEventCount: 0,
        durationMs,
        requestCount: 1,
      }),
    });
  }

  // Step 0: Load & Reconcile Crash-Safe Billing Checkpoint (fail-closed if loadCheckpoint throws)
  let rawLoadedCheckpoint = null;
  if (typeof hooks.loadCheckpoint === 'function') {
    try {
      rawLoadedCheckpoint = await hooks.loadCheckpoint();
    } catch (cpErr) {
      const durationMs = Math.max(1, nowMs() - startedAtMs);
      return finalizeActorReturn({
        ok: false,
        status: 'PARTIAL_BILLING_HALT',
        reason: `Failed to load billing checkpoint fail-closed: ${cpErr?.message || String(cpErr)}`,
        billingMode,
        queryMeta: null,
        selectedEntities: [],
        items: [],
        extractedCount: 0,
        deliveredCount: 0,
        billableCount: 0,
        chargedEventCount: 0,
        unknownOutcomeIds: [],
        chargeReceipts: [],
        pagination: {
          nextPageToken: input?.pageToken || null,
          paginationStatus: 'PARTIAL_BILLING_HALT',
          paginationIncompleteReason: 'CHECKPOINT_LOAD_FAILED',
        },
        telemetry: computeRunEconomicsTelemetry({
          billableCount: 0,
          chargedEventCount: 0,
          durationMs,
          requestCount: 1,
        }),
      });
    }
  }
  const checkpoint = normalizeBillingCheckpointState(rawLoadedCheckpoint, runId);

  const chargedSet = new Set(checkpoint.chargedIds);
  const deliveredSet = new Set(checkpoint.deliveredIds);
  const unknownOutcomeSet = new Set(checkpoint.unknownOutcomeIds);
  let inFlightSet = new Set(checkpoint.inFlightIds);
  let inFlightIdempotencyKey = checkpoint.inFlightIdempotencyKey || null;
  const stagedItemsById = { ...checkpoint.stagedItemsById };

  const persistCheckpoint = async () => {
    const snapshot = {
      runId,
      chargedIds: Array.from(chargedSet),
      deliveredIds: Array.from(deliveredSet),
      inFlightIds: Array.from(inFlightSet),
      inFlightIdempotencyKey: inFlightSet.size > 0 ? inFlightIdempotencyKey : null,
      unknownOutcomeIds: Array.from(unknownOutcomeSet),
      stagedItemsById,
    };
    if (typeof hooks.saveCheckpoint === 'function') {
      await hooks.saveCheckpoint(snapshot);
    }
    return snapshot;
  };

  const reconciledItems = [];
  let deliveredCount = deliveredSet.size;

  // Step 0a: Reconcile any already-paid items (`chargedIds \ deliveredIds`) without re-charging.
  // First check `hooks.listDeliveredIds()` if available so items already committed to dataset before a lost ACK
  // are marked delivered without duplicate dataset POSTs. Fail closed if dataset listing throws.
  const paidUndeliveredIds = Array.from(chargedSet).filter((id) => !deliveredSet.has(id));
  if (paidUndeliveredIds.length > 0) {
    let alreadyInDatasetSet = new Set();
    if (typeof hooks.listDeliveredIds === 'function') {
      try {
        const existingDsIds = await hooks.listDeliveredIds();
        if (Array.isArray(existingDsIds)) {
          alreadyInDatasetSet = new Set(existingDsIds);
        }
      } catch (dsListErr) {
        const durationMs = Math.max(1, nowMs() - startedAtMs);
        return finalizeActorReturn({
          ok: false,
          status: 'PARTIAL_BILLING_HALT',
          reason: `Failed to verify delivered dataset IDs during reconciliation: ${dsListErr?.message || String(dsListErr)}`,
          billingMode,
          queryMeta: null,
          selectedEntities: [],
          items: [],
          extractedCount: 0,
          deliveredCount,
          billableCount: 0,
          chargedEventCount: chargedSet.size,
          unknownOutcomeIds: Array.from(unknownOutcomeSet),
          chargeReceipts: [],
          pagination: {
            nextPageToken: input?.pageToken || null,
            paginationStatus: 'PARTIAL_BILLING_HALT',
            paginationIncompleteReason: 'DATASET_RECONCILIATION_FAILED',
          },
          telemetry: computeRunEconomicsTelemetry({
            billableCount: 0,
            chargedEventCount: chargedSet.size,
            durationMs,
            requestCount: 1,
          }),
        });
      }
    }

    const deliverablePairs = [];
    for (const id of paidUndeliveredIds) {
      const staged = stagedItemsById[id];
      if (alreadyInDatasetSet.has(id)) {
        deliveredSet.add(id);
        if (staged && typeof staged === 'object' && staged.creativeId === id) {
          reconciledItems.push(staged);
        }
        delete stagedItemsById[id];
      } else if (staged && typeof staged === 'object' && staged.creativeId === id) {
        deliverablePairs.push({ id, item: staged });
      } else {
        unknownOutcomeSet.add(id);
      }
    }

    if (deliverablePairs.length > 0) {
      const itemsToDeliver = deliverablePairs.map((p) => p.item);
      const pushRes = await pushDataWithRetry(itemsToDeliver);
      if (!pushRes.ok) {
        await persistCheckpoint();
        const durationMs = Math.max(1, nowMs() - startedAtMs);
        return finalizeActorReturn({
          ok: false,
          status: 'PARTIAL_BILLING_HALT',
          reason: `Dataset pushData failed during reconciliation: ${pushRes.error?.message || String(pushRes.error)}`,
          billingMode,
          queryMeta: null,
          selectedEntities: [],
          items: reconciledItems,
          extractedCount: 0,
          deliveredCount,
          billableCount: reconciledItems.length,
          chargedEventCount: chargedSet.size,
          unknownOutcomeIds: Array.from(unknownOutcomeSet),
          chargeReceipts: [],
          pagination: {
            nextPageToken: input?.pageToken || null,
            paginationStatus: 'PARTIAL_BILLING_HALT',
            paginationIncompleteReason: 'DATASET_PUSH_FAILED',
          },
          telemetry: computeRunEconomicsTelemetry({
            billableCount: reconciledItems.length,
            chargedEventCount: chargedSet.size,
            durationMs,
            requestCount: 1,
          }),
        });
      }
      for (const { id, item } of deliverablePairs) {
        deliveredSet.add(id);
        delete stagedItemsById[id];
        reconciledItems.push(item);
      }
    }
    deliveredCount = deliveredSet.size;
    await persistCheckpoint();
  }

  // Step 0b: Reconcile leftover `inFlightIds` via stored `inFlightIdempotencyKey` when available; otherwise transition to `unknownOutcomeIds`
  if (inFlightSet.size > 0) {
    const inFlightArr = Array.from(inFlightSet);
    const canReplayInFlight =
      hooks.idempotentChargeRetryEnabled === true &&
      Boolean(inFlightIdempotencyKey) &&
      typeof hooks.chargeEvent === 'function' &&
      inFlightArr.every((id) => stagedItemsById[id] && stagedItemsById[id].creativeId === id);

    let reconciledInFlight = false;
    if (canReplayInFlight) {
      try {
        const replayRes = await hooks.chargeEvent({
          idempotencyKey: inFlightIdempotencyKey,
          eventName: ACTOR_PRICING_CONTRACT.eventName,
          count: inFlightArr.length,
          unitPriceUsdc: ACTOR_PRICING_CONTRACT.priceUsdc,
          chunkAmountUsdc: Number(
            (inFlightArr.length * ACTOR_PRICING_CONTRACT.priceUsdc).toFixed(6)
          ),
          creativeIds: inFlightArr,
          deadlineAtMs,
        });
        if (replayRes && replayRes.chargedCount === inFlightArr.length) {
          for (const id of inFlightArr) {
            chargedSet.add(id);
          }
          inFlightSet = new Set();
          inFlightIdempotencyKey = null;
          await persistCheckpoint();

          let alreadyInDatasetSet = new Set();
          if (typeof hooks.listDeliveredIds === 'function') {
            try {
              const existingDsIds = await hooks.listDeliveredIds();
              if (Array.isArray(existingDsIds)) {
                alreadyInDatasetSet = new Set(existingDsIds);
              }
            } catch (dsListErr) {
              const durationMs = Math.max(1, nowMs() - startedAtMs);
              return finalizeActorReturn({
                ok: false,
                status: 'PARTIAL_BILLING_HALT',
                reason: `Failed to verify delivered dataset IDs during in-flight replay reconciliation: ${dsListErr?.message || String(dsListErr)}`,
                billingMode,
                queryMeta: null,
                selectedEntities: [],
                items: reconciledItems,
                extractedCount: 0,
                deliveredCount,
                billableCount: reconciledItems.length,
                chargedEventCount: chargedSet.size,
                unknownOutcomeIds: Array.from(unknownOutcomeSet),
                chargeReceipts: [],
                pagination: {
                  nextPageToken: input?.pageToken || null,
                  paginationStatus: 'PARTIAL_BILLING_HALT',
                  paginationIncompleteReason: 'DATASET_RECONCILIATION_FAILED',
                },
                telemetry: computeRunEconomicsTelemetry({
                  billableCount: reconciledItems.length,
                  chargedEventCount: chargedSet.size,
                  durationMs,
                  requestCount: 1,
                }),
              });
            }
          }

          const itemsToDeliver = [];
          for (const id of inFlightArr) {
            const staged = stagedItemsById[id];
            if (alreadyInDatasetSet.has(id)) {
              deliveredSet.add(id);
              if (staged) reconciledItems.push(staged);
              delete stagedItemsById[id];
            } else if (staged) {
              itemsToDeliver.push(staged);
            }
          }

          if (itemsToDeliver.length > 0) {
            const pushRes = await pushDataWithRetry(itemsToDeliver);
            if (!pushRes.ok) {
              await persistCheckpoint();
              const durationMs = Math.max(1, nowMs() - startedAtMs);
              return finalizeActorReturn({
                ok: false,
                status: 'PARTIAL_BILLING_HALT',
                reason: `Dataset pushData failed during in-flight replay reconciliation: ${pushRes.error?.message || String(pushRes.error)}`,
                billingMode,
                queryMeta: null,
                selectedEntities: [],
                items: reconciledItems,
                extractedCount: 0,
                deliveredCount: deliveredSet.size,
                billableCount: reconciledItems.length,
                chargedEventCount: chargedSet.size,
                unknownOutcomeIds: Array.from(unknownOutcomeSet),
                chargeReceipts: [],
                pagination: {
                  nextPageToken: input?.pageToken || null,
                  paginationStatus: 'PARTIAL_BILLING_HALT',
                  paginationIncompleteReason: 'DATASET_PUSH_FAILED',
                },
                telemetry: computeRunEconomicsTelemetry({
                  billableCount: reconciledItems.length,
                  chargedEventCount: chargedSet.size,
                  durationMs,
                  requestCount: 1,
                }),
              });
            }
            for (const item of itemsToDeliver) {
              deliveredSet.add(item.creativeId);
              delete stagedItemsById[item.creativeId];
              reconciledItems.push(item);
            }
          }
          deliveredCount = deliveredSet.size;
          await persistCheckpoint();
          reconciledInFlight = true;
        }
      } catch {
        reconciledInFlight = false;
      }
    }

    if (!reconciledInFlight) {
      for (const id of inFlightArr) {
        if (!chargedSet.has(id) && !deliveredSet.has(id)) {
          unknownOutcomeSet.add(id);
        }
      }
      inFlightSet = new Set();
      inFlightIdempotencyKey = null;
      await persistCheckpoint();
    }
  }

  if (unknownOutcomeSet.size > 0 && input?.strictBillingResume !== false) {
    const durationMs = Math.max(1, nowMs() - startedAtMs);
    return finalizeActorReturn({
      ok: false,
      status: 'PARTIAL_BILLING_HALT',
      reason: `Halted due to ${unknownOutcomeSet.size} unreconciled creative(s) in UNKNOWN_CHARGE_OUTCOME state`,
      billingMode,
      queryMeta: null,
      selectedEntities: [],
      items: reconciledItems,
      extractedCount: 0,
      deliveredCount,
      billableCount: reconciledItems.length,
      chargedEventCount: chargedSet.size,
      unknownOutcomeIds: Array.from(unknownOutcomeSet),
      chargeReceipts: [],
      pagination: {
        nextPageToken: input?.pageToken || null,
        paginationStatus: 'PARTIAL_BILLING_HALT',
        paginationIncompleteReason: 'UNKNOWN_CHARGE_OUTCOME',
      },
      telemetry: computeRunEconomicsTelemetry({
        billableCount: reconciledItems.length,
        chargedEventCount: chargedSet.size,
        durationMs,
        requestCount: 1,
      }),
    });
  }

  const sleepFn =
    typeof hooks.sleepFn === 'function'
      ? hooks.sleepFn
      : typeof input?.sleepFn === 'function'
        ? input.sleepFn
        : undefined;
  const randomFn =
    typeof hooks.randomFn === 'function'
      ? hooks.randomFn
      : typeof input?.randomFn === 'function'
        ? input.randomFn
        : undefined;

  const aliasNorm = normalizeAdPulseInputAliases(input || {});
  if (!aliasNorm.ok) {
    const durationMs = Math.max(1, nowMs() - startedAtMs);
    return finalizeActorReturn({
      ok: false,
      status: aliasNorm.status || 'INVALID_INPUT',
      ...(aliasNorm.errorCode ? { errorCode: aliasNorm.errorCode } : {}),
      reason: aliasNorm.reason,
      billingMode,
      queryMeta: null,
      selectedEntities: [],
      items: reconciledItems,
      extractedCount: 0,
      deliveredCount,
      billableCount: reconciledItems.length,
      chargedEventCount: hasChargeHook ? chargedSet.size : 0,
      unknownOutcomeIds: Array.from(unknownOutcomeSet),
      chargeReceipts: [],
      pagination: {
        nextPageToken: input?.pageToken || null,
        paginationStatus: 'INVALID_INPUT',
        paginationIncompleteReason: aliasNorm.reason || null,
      },
      telemetry: computeRunEconomicsTelemetry({
        billableCount: reconciledItems.length,
        chargedEventCount: hasChargeHook ? chargedSet.size : 0,
        durationMs,
        requestCount: 0,
      }),
    });
  }
  input = aliasNorm.normalized;

  // Step 1: Resolve Advertiser Entities
  const entityRes = await resolveAdvertiserEntities({
    query: input?.query,
    domain: input?.domain,
    brand: input?.brand,
    company: input?.company,
    advertiser: input?.advertiser,
    url: input?.url,
    advertiserId: input?.advertiserId,
    advertiserName: input?.advertiserName,
    countryCode: input?.countryCode,
    country: input?.country,
    region: input?.region,
    includeSubsidiaries: input?.includeSubsidiaries,
    maxEntities: input?.maxEntities,
    fetchImpl: hooks.fetchImpl,
    nowFn: nowMs,
    sleepFn,
    randomFn,
    timeoutMs: input?.timeoutMs,
    maxRetries: input?.maxRetries,
    deadlineAtMs: rpcDeadlineAtMs,
  });

  if (!entityRes.ok) {
    const durationMs = Math.max(1, nowMs() - startedAtMs);
    const isPreChargeDeadline =
      hasChargeHook &&
      nowMs() >= rpcDeadlineAtMs &&
      /deadline exceeded/i.test(String(entityRes.reason || ''));
    return finalizeActorReturn({
      ok: false,
      status: isPreChargeDeadline ? 'DEADLINE_EXCEEDED_BEFORE_CHARGE' : entityRes.status,
      ...(entityRes.errorCode ? { errorCode: entityRes.errorCode } : {}),
      reason: entityRes.reason,
      billingMode,
      queryMeta: entityRes.queryMeta,
      selectedEntities: [],
      items: reconciledItems,
      extractedCount: 0,
      deliveredCount,
      billableCount: reconciledItems.length,
      chargedEventCount: hasChargeHook ? chargedSet.size : 0,
      unknownOutcomeIds: Array.from(unknownOutcomeSet),
      chargeReceipts: [],
      pagination: {
        nextPageToken: input?.pageToken || null,
        paginationStatus: isPreChargeDeadline ? 'DEADLINE_EXCEEDED_HAS_MORE' : entityRes.status,
        paginationIncompleteReason: isPreChargeDeadline
          ? 'DEADLINE_EXCEEDED_BEFORE_CHARGE'
          : entityRes.reason || null,
      },
      telemetry: computeRunEconomicsTelemetry({
        billableCount: reconciledItems.length,
        chargedEventCount: hasChargeHook ? chargedSet.size : 0,
        durationMs,
        requestCount: Math.max(1, entityRes.rpcAttempts),
      }),
    });
  }

  if (entityRes.status === 'EMPTY_RESULT' || entityRes.selectedEntities.length === 0) {
    const durationMs = Math.max(1, nowMs() - startedAtMs);
    return finalizeActorReturn({
      ok: true,
      status: 'EMPTY_RESULT',
      billingMode,
      queryMeta: entityRes.queryMeta,
      selectedEntities: [],
      items: reconciledItems,
      extractedCount: 0,
      deliveredCount,
      billableCount: reconciledItems.length,
      chargedEventCount: hasChargeHook ? chargedSet.size : 0,
      unknownOutcomeIds: Array.from(unknownOutcomeSet),
      chargeReceipts: [],
      pagination: {
        nextPageToken: null,
        paginationStatus: 'EXHAUSTED',
        paginationIncompleteReason: null,
      },
      telemetry: computeRunEconomicsTelemetry({
        billableCount: reconciledItems.length,
        chargedEventCount: hasChargeHook ? chargedSet.size : 0,
        durationMs,
        requestCount: Math.max(1, entityRes.rpcAttempts),
      }),
    });
  }

  // Step 2: Fetch Creatives across selected verified advertiser entities
  const advertiserIds = entityRes.selectedEntities.map((e) => e.advertiserId);
  const creativesRes = await fetchAdvertiserCreatives({
    advertiserIds,
    entities: entityRes.selectedEntities,
    maxResults: input?.maxResults,
    limit: input?.limit,
    max_results: input?.max_results,
    maxPages: input?.maxPages,
    pageSize: input?.pageSize,
    pageToken: input?.pageToken,
    countryCode: input?.countryCode,
    country: input?.country,
    region: input?.region,
    formatFilter: input?.formatFilter,
    fetchImpl: hooks.fetchImpl,
    nowFn: nowMs,
    sleepFn,
    randomFn,
    timeoutMs: input?.timeoutMs,
    maxRetries: input?.maxRetries,
    deadlineAtMs: rpcDeadlineAtMs,
  });

  let totalRpcRequests = entityRes.rpcAttempts + creativesRes.rpcAttempts;

  if (!creativesRes.ok) {
    const durationMs = Math.max(1, nowMs() - startedAtMs);
    const isPreChargeDeadline =
      hasChargeHook &&
      nowMs() >= rpcDeadlineAtMs &&
      /deadline exceeded/i.test(String(creativesRes.reason || ''));
    return finalizeActorReturn({
      ok: false,
      status: isPreChargeDeadline ? 'DEADLINE_EXCEEDED_BEFORE_CHARGE' : creativesRes.status,
      ...(creativesRes.errorCode ? { errorCode: creativesRes.errorCode } : {}),
      reason: creativesRes.reason,
      billingMode,
      queryMeta: entityRes.queryMeta,
      selectedEntities: entityRes.selectedEntities,
      items: reconciledItems,
      extractedCount: 0,
      deliveredCount,
      billableCount: reconciledItems.length,
      chargedEventCount: hasChargeHook ? chargedSet.size : 0,
      unknownOutcomeIds: Array.from(unknownOutcomeSet),
      chargeReceipts: [],
      pagination: {
        nextPageToken: input?.pageToken || null,
        paginationStatus: isPreChargeDeadline
          ? 'DEADLINE_EXCEEDED_HAS_MORE'
          : creativesRes.paginationStatus || creativesRes.status,
        paginationIncompleteReason: isPreChargeDeadline
          ? 'DEADLINE_EXCEEDED_BEFORE_CHARGE'
          : creativesRes.paginationIncompleteReason || creativesRes.reason || null,
      },
      telemetry: computeRunEconomicsTelemetry({
        billableCount: reconciledItems.length,
        chargedEventCount: hasChargeHook ? chargedSet.size : 0,
        durationMs,
        requestCount: Math.max(1, totalRpcRequests),
      }),
    });
  }

  const maxResultsCap = Math.min(200, Math.max(1, Number(input?.maxResults) || 40));

  // Step 3: Strict Deduplication & Validation Gate before emitting Pay-per-Event charges
  const uniqueExtractedItems = [];
  const seenInRunIds = new Set();

  for (const item of creativesRes.creatives) {
    if (
      !item ||
      !ADVERTISER_ID_RE.test(String(item.advertiserId || '')) ||
      !CREATIVE_ID_RE.test(String(item.creativeId || ''))
    ) {
      const durationMs = Math.max(1, nowMs() - startedAtMs);
      return finalizeActorReturn({
        ok: false,
        status: 'SCHEMA_DRIFT_HALT',
        reason: 'Normalized creative record failed AR.../CR... identifier gate prior to billing',
        billingMode,
        queryMeta: entityRes.queryMeta,
        selectedEntities: entityRes.selectedEntities,
        items: reconciledItems,
        extractedCount: 0,
        deliveredCount,
        billableCount: reconciledItems.length,
        chargedEventCount: hasChargeHook ? chargedSet.size : 0,
        unknownOutcomeIds: Array.from(unknownOutcomeSet),
        chargeReceipts: [],
        pagination: {
          nextPageToken: null,
          paginationStatus: 'SCHEMA_DRIFT_HALT',
          paginationIncompleteReason: 'INVALID_CREATIVE_IDENTIFIER',
        },
        telemetry: computeRunEconomicsTelemetry({
          billableCount: reconciledItems.length,
          chargedEventCount: hasChargeHook ? chargedSet.size : 0,
          durationMs,
          requestCount: Math.max(1, totalRpcRequests),
        }),
      });
    }

    if (!seenInRunIds.has(item.creativeId)) {
      seenInRunIds.add(item.creativeId);
      uniqueExtractedItems.push(item);
      if (uniqueExtractedItems.length >= maxResultsCap) {
        break;
      }
    }
  }

  // Optional Step 3b: Enrich up to 10 creatives (default 5) via LookupService/GetCreativeById when includeCreativeDetails === true
  if (input?.includeCreativeDetails === true && uniqueExtractedItems.length > 0) {
    const requestedEnrichCap = Number(input?.maxEnrichItems ?? 5);
    const enrichCap = Math.min(
      10,
      Math.max(1, Number.isFinite(requestedEnrichCap) ? Math.floor(requestedEnrichCap) : 5),
      uniqueExtractedItems.length
    );
    let rateLimitedInEnrich = false;
    for (let i = 0; i < enrichCap; i += 1) {
      const targetItem = uniqueExtractedItems[i];
      if (rateLimitedInEnrich) {
        targetItem.untrustedAdContent = createEmptyUntrustedAdContent(
          'NOT_ATTEMPTED_RATE_LIMITED'
        );
        continue;
      }
      if (nowMs() >= rpcDeadlineAtMs) {
        targetItem.untrustedAdContent = createEmptyUntrustedAdContent(
          'NOT_ATTEMPTED_DEADLINE'
        );
        continue;
      }
      const detailRes = await getCreativeDetailsById({
        advertiserId: targetItem.advertiserId,
        creativeId: targetItem.creativeId,
        includeAdCopy: Boolean(input?.includeAdCopy),
        fallbackPreviewUrl: targetItem.previewUrl,
        fetchImpl: hooks.fetchImpl,
        nowFn: nowMs,
        sleepFn,
        randomFn,
        timeoutMs: input?.timeoutMs,
        maxRetries: input?.maxRetries !== undefined ? input.maxRetries : 1,
        deadlineAtMs: rpcDeadlineAtMs,
      });
      totalRpcRequests += detailRes.rpcAttempts;
      if (detailRes.status === 'UPSTREAM_RATE_LIMITED') {
        rateLimitedInEnrich = true;
        targetItem.untrustedAdContent = createEmptyUntrustedAdContent(
          'NOT_ATTEMPTED_RATE_LIMITED'
        );
        continue;
      }
      if (detailRes.ok && detailRes.detail) {
        targetItem.creativeDetail = detailRes.detail;
        if (detailRes.detail.untrustedAdContent) {
          targetItem.untrustedAdContent = detailRes.detail.untrustedAdContent;
          if (
            detailRes.detail.untrustedAdContent.extractionStatus === 'UPSTREAM_RATE_LIMITED' ||
            detailRes.detail.untrustedAdContent.contentJsFetchStatus === 'UPSTREAM_RATE_LIMITED'
          ) {
            rateLimitedInEnrich = true;
          }
        }
      } else if (detailRes.ok && detailRes.untrustedAdContent) {
        targetItem.untrustedAdContent = detailRes.untrustedAdContent;
        if (
          detailRes.untrustedAdContent.extractionStatus === 'UPSTREAM_RATE_LIMITED' ||
          detailRes.untrustedAdContent.contentJsFetchStatus === 'UPSTREAM_RATE_LIMITED'
        ) {
          rateLimitedInEnrich = true;
        }
      }
    }
  }

  const extractedCount = uniqueExtractedItems.length;

  // Filter out items already charged, delivered, or marked unknown in prior checkpoint
  const newBillableCandidates = uniqueExtractedItems.filter(
    (item) =>
      !chargedSet.has(item.creativeId) &&
      !deliveredSet.has(item.creativeId) &&
      !unknownOutcomeSet.has(item.creativeId)
  );

  if (newBillableCandidates.length === 0 && reconciledItems.length === 0) {
    const durationMs = Math.max(1, nowMs() - startedAtMs);
    return finalizeActorReturn({
      ok: true,
      status: 'EMPTY_RESULT',
      billingMode,
      queryMeta: entityRes.queryMeta,
      selectedEntities: entityRes.selectedEntities,
      items: [],
      extractedCount,
      deliveredCount,
      billableCount: 0,
      chargedEventCount: hasChargeHook ? chargedSet.size : 0,
      unknownOutcomeIds: Array.from(unknownOutcomeSet),
      chargeReceipts: [],
      pagination: {
        offset: creativesRes.offset ?? 0,
        nextPageToken: creativesRes.nextPageToken,
        nextCursor: creativesRes.nextPageToken,
        paginationStatus: creativesRes.paginationStatus,
        paginationIncompleteReason: creativesRes.paginationIncompleteReason,
        pagesFetched: creativesRes.pagesFetched,
      },
      cursorResumeContext: creativesRes.cursorResumeContext,
      telemetry: computeRunEconomicsTelemetry({
        billableCount: 0,
        chargedEventCount: hasChargeHook ? chargedSet.size : 0,
        durationMs,
        requestCount: Math.max(1, totalRpcRequests),
        unitPriceUsdc:
          hooks && 'unitPriceUsdc' in hooks ? hooks.unitPriceUsdc : ACTOR_PRICING_CONTRACT.priceUsdc,
        actorStartFeeUsdc: hooks?.actorStartFeeUsdc,
        pricingDeterministic: hooks?.pricingDeterministic,
      }),
    });
  }

  // Step 4: Chunked Dataset Push (25 items/chunk) & Crash-Safe Event Charging
  const chunkSize = ACTOR_PRICING_CONTRACT.chunkSize;
  const chargeReceipts = [];
  const newlyDeliveredItems = [];
  let chargedEventCount = hasChargeHook ? chargedSet.size : 0;
  let finalStatus = 'OK';
  let finalOk = true;
  let haltReason = undefined;
  const runtimeWarnings = Array.isArray(creativesRes.warnings) ? [...creativesRes.warnings] : [];
  const persistCheckpointPostCharge = async () => {
    try {
      await persistCheckpoint();
    } catch (cpErr) {
      runtimeWarnings.push(
        `Post-charge checkpoint write warning: ${cpErr?.message || String(cpErr)}`
      );
    }
  };

  let lastResolvedUnitPriceUsdc =
    hooks && 'unitPriceUsdc' in hooks ? hooks.unitPriceUsdc : ACTOR_PRICING_CONTRACT.priceUsdc;
  for (let offset = 0; offset < newBillableCandidates.length; offset += chunkSize) {
    const effectiveChunkDeadlineMs = hasChargeHook
      ? deadlineAtMs - step4ReserveMs
      : deadlineAtMs;
    if (nowMs() >= effectiveChunkDeadlineMs) {
      finalOk = newlyDeliveredItems.length > 0 || reconciledItems.length > 0;
      finalStatus = 'DEADLINE_EXCEEDED_BEFORE_CHARGE';
      haltReason = 'Run deadline reserve reached prior to charging next chunk; halted cleanly before billing';
      break;
    }

    const unchargedChunk = newBillableCandidates
      .slice(offset, offset + chunkSize)
      .filter(
        (c) =>
          !chargedSet.has(c.creativeId) &&
          !deliveredSet.has(c.creativeId) &&
          !unknownOutcomeSet.has(c.creativeId)
      );

    if (unchargedChunk.length === 0) {
      continue;
    }

    const chunkIds = unchargedChunk.map((c) => c.creativeId);
    const idempotencyKey = computeChunkIdempotencyKey(runId, chunkIds);

    if (!hasChargeHook) {
      // Local / MCP unbilled execution mode: deliver items with chargedEventCount = 0
      const pushRes = await pushDataWithRetry(unchargedChunk);
      if (!pushRes.ok) {
        await persistCheckpointPostCharge();
        finalOk = false;
        finalStatus = 'PARTIAL_BILLING_HALT';
        haltReason = `Dataset pushData failed in local mode: ${pushRes.error?.message || String(pushRes.error)}`;
        break;
      }
      for (const c of unchargedChunk) {
        deliveredSet.add(c.creativeId);
        delete stagedItemsById[c.creativeId];
        newlyDeliveredItems.push(c);
      }
      deliveredCount = deliveredSet.size;
      await persistCheckpointPostCharge();
      continue;
    }

    // Step 4.1: Persist inFlightIds, inFlightIdempotencyKey, and stagedItemsById BEFORE invoking chargeEvent
    inFlightSet = new Set(chunkIds);
    inFlightIdempotencyKey = idempotencyKey;
    for (const c of unchargedChunk) {
      stagedItemsById[c.creativeId] = c;
    }
    try {
      await persistCheckpoint();
    } catch (preCpErr) {
      inFlightSet = new Set();
      inFlightIdempotencyKey = null;
      finalOk = false;
      finalStatus = 'PARTIAL_BILLING_HALT';
      haltReason = `Pre-charge checkpoint write failed before billing: ${preCpErr?.message || String(preCpErr)}`;
      break;
    }

    if (nowMs() >= effectiveChunkDeadlineMs) {
      inFlightSet = new Set();
      inFlightIdempotencyKey = null;
      await persistCheckpointPostCharge();
      finalOk = newlyDeliveredItems.length > 0 || reconciledItems.length > 0;
      finalStatus = 'DEADLINE_EXCEEDED_BEFORE_CHARGE';
      haltReason =
        'Run deadline reserve reached immediately after pre-charge checkpoint write; cleared inFlightIds and halted before billing';
      break;
    }

    const receipt = {
      idempotencyKey,
      eventName: ACTOR_PRICING_CONTRACT.eventName,
      count: unchargedChunk.length,
      unitPriceUsdc: ACTOR_PRICING_CONTRACT.priceUsdc,
      chunkAmountUsdc: Number(
        (unchargedChunk.length * ACTOR_PRICING_CONTRACT.priceUsdc).toFixed(6)
      ),
      creativeIds: chunkIds,
      deadlineAtMs,
    };

    let chargeResult;
    try {
      chargeResult = await hooks.chargeEvent(receipt);
    } catch (chargeErr) {
      for (const id of chunkIds) {
        unknownOutcomeSet.add(id);
      }
      inFlightSet = new Set();
      inFlightIdempotencyKey = null;
      await persistCheckpointPostCharge();
      finalOk = false;
      finalStatus = 'PARTIAL_BILLING_HALT';
      haltReason = `chargeEvent threw error: ${chargeErr?.message || String(chargeErr)}`;
      break;
    }

    // Step 4.2: Strict ChargeResult validation (never fallback to ?? unchargedChunk.length)
    const chargedCount = chargeResult?.chargedCount;
    const eventChargeLimitReached = Boolean(chargeResult?.eventChargeLimitReached);
    const resolvedReceiptEventName =
      typeof chargeResult?.eventName === 'string' && chargeResult.eventName
        ? chargeResult.eventName
        : receipt.eventName;
    const resolvedReceiptUnitPriceUsdc =
      chargeResult && 'unitPriceUsdc' in chargeResult && chargeResult.unitPriceUsdc === null
        ? null
        : Number.isFinite(Number(chargeResult?.unitPriceUsdc)) && Number(chargeResult.unitPriceUsdc) > 0
          ? Number(chargeResult.unitPriceUsdc)
          : receipt.unitPriceUsdc;
    lastResolvedUnitPriceUsdc = resolvedReceiptUnitPriceUsdc;
    const resolvedReceiptIdempotencyKey =
      typeof chargeResult?.idempotencyKey === 'string' && chargeResult.idempotencyKey
        ? chargeResult.idempotencyKey
        : receipt.idempotencyKey;
    const buildFinalReceipt = (actualChargedCount, extra = {}) => ({
      ...receipt,
      idempotencyKey: resolvedReceiptIdempotencyKey,
      eventName: resolvedReceiptEventName,
      unitPriceUsdc: resolvedReceiptUnitPriceUsdc,
      chunkAmountUsdc:
        resolvedReceiptUnitPriceUsdc === null
          ? null
          : Number((actualChargedCount * resolvedReceiptUnitPriceUsdc).toFixed(6)),
      chargedCount: actualChargedCount,
      ...extra,
    });

    if (
      !chargeResult ||
      typeof chargeResult !== 'object' ||
      !Number.isInteger(chargedCount) ||
      chargedCount < 0 ||
      chargedCount > unchargedChunk.length
    ) {
      for (const id of chunkIds) {
        unknownOutcomeSet.add(id);
      }
      inFlightSet = new Set();
      await persistCheckpointPostCharge();
      finalOk = false;
      finalStatus = 'PARTIAL_BILLING_HALT';
      haltReason =
        'chargeEvent returned invalid or missing integer chargedCount (transitioned chunk to UNKNOWN_CHARGE_OUTCOME)';
      break;
    }

    // Step 4.3: Branch on validated chargedCount
    if (chargedCount === unchargedChunk.length) {
      // Full chunk charged: persist chargedIds immediately BEFORE pushData (best-effort so KVS glitch never blocks delivery)
      for (const id of chunkIds) {
        chargedSet.add(id);
      }
      inFlightSet = new Set();
      chargedEventCount = chargedSet.size;
      await persistCheckpointPostCharge();

      const pushRes = await pushDataWithRetry(unchargedChunk);
      if (!pushRes.ok) {
        chargeReceipts.push(buildFinalReceipt(chargedCount, { eventChargeLimitReached }));
        finalOk = false;
        finalStatus = 'PARTIAL_BILLING_HALT';
        haltReason = `Dataset pushData failed after charge (paid items preserved in KVS checkpoint stagedItemsById): ${pushRes.error?.message || String(pushRes.error)}`;
        break;
      }
      for (const c of unchargedChunk) {
        deliveredSet.add(c.creativeId);
        delete stagedItemsById[c.creativeId];
        newlyDeliveredItems.push(c);
      }
      deliveredCount = deliveredSet.size;
      await persistCheckpointPostCharge();

      chargeReceipts.push(buildFinalReceipt(chargedCount, { eventChargeLimitReached }));

      if (eventChargeLimitReached) {
        finalStatus = 'CHARGE_LIMIT_REACHED';
        break;
      }
    } else if (chargedCount === 0) {
      inFlightSet = new Set();
      if (chargeResult?.unbilledOwnerTestBypass === true) {
        billingMode = 'UNBILLED_OWNER_TEST';
        await persistCheckpointPostCharge();
        const pushRes = await pushDataWithRetry(unchargedChunk);
        if (!pushRes.ok) {
          finalOk = false;
          finalStatus = 'PARTIAL_BILLING_HALT';
          haltReason = `Dataset pushData failed in UNBILLED_OWNER_TEST mode: ${pushRes.error?.message || String(pushRes.error)}`;
          break;
        }
        for (const c of unchargedChunk) {
          deliveredSet.add(c.creativeId);
          delete stagedItemsById[c.creativeId];
          newlyDeliveredItems.push(c);
        }
        deliveredCount = deliveredSet.size;
        await persistCheckpointPostCharge();
        chargeReceipts.push(
          buildFinalReceipt(0, {
            eventChargeLimitReached: false,
            unbilledOwnerTestBypass: true,
          })
        );
        continue;
      }
      await persistCheckpointPostCharge();
      chargeReceipts.push(buildFinalReceipt(0, { eventChargeLimitReached }));
      if (eventChargeLimitReached) {
        finalOk = true;
        finalStatus = 'CHARGE_LIMIT_REACHED';
      } else {
        finalOk = false;
        finalStatus = 'PARTIAL_BILLING_HALT';
        haltReason = 'chargeEvent returned chargedCount = 0 without eventChargeLimitReached';
      }
      break;
    } else {
      // Partial chunk charge (0 < chargedCount < unchargedChunk.length)
      const hasExplicitIdsArray = Array.isArray(chargeResult.chargedCreativeIds);
      const explicitChargedIds = hasExplicitIdsArray
        ? Array.from(
            new Set(chargeResult.chargedCreativeIds.filter((id) => chunkIds.includes(id)))
          )
        : null;
      const isValidExplicitChargedIds = Boolean(
        explicitChargedIds &&
          explicitChargedIds.length === chargedCount &&
          chargeResult.chargedCreativeIds.length === chargedCount
      );

      if (isValidExplicitChargedIds) {
        for (const id of explicitChargedIds) {
          chargedSet.add(id);
        }
        inFlightSet = new Set();
        chargedEventCount = chargedSet.size;
        await persistCheckpointPostCharge();

        const paidSubset = unchargedChunk.filter((c) => explicitChargedIds.includes(c.creativeId));
        const pushRes = await pushDataWithRetry(paidSubset);
        if (!pushRes.ok) {
          chargeReceipts.push(
            buildFinalReceipt(chargedCount, {
              chargedCreativeIds: explicitChargedIds,
              eventChargeLimitReached,
            })
          );
          finalOk = false;
          finalStatus = 'PARTIAL_BILLING_HALT';
          haltReason = `Dataset pushData failed after partial charge (paid items preserved in KVS checkpoint stagedItemsById): ${pushRes.error?.message || String(pushRes.error)}`;
          break;
        }
        for (const c of paidSubset) {
          deliveredSet.add(c.creativeId);
          delete stagedItemsById[c.creativeId];
          newlyDeliveredItems.push(c);
        }
        deliveredCount = deliveredSet.size;
        await persistCheckpointPostCharge();

        chargeReceipts.push(
          buildFinalReceipt(chargedCount, {
            chargedCreativeIds: explicitChargedIds,
            eventChargeLimitReached,
          })
        );

        finalOk = eventChargeLimitReached;
        finalStatus = eventChargeLimitReached ? 'CHARGE_LIMIT_REACHED' : 'PARTIAL_BILLING_HALT';
        if (!eventChargeLimitReached) {
          haltReason = `Partial chunk charge (${chargedCount}/${unchargedChunk.length}) without charge limit flag`;
        }
        break;
      } else if (!hasExplicitIdsArray && eventChargeLimitReached) {
        // Standard Apify SDK ChargeResult when hitting user's max charge ceiling:
        // Attribute charge deterministically to the ordered prefix `unchargedChunk.slice(0, chargedCount)`
        // so the customer receives every item they paid for, and leave the remaining tail uncharged.
        const paidPrefix = unchargedChunk.slice(0, chargedCount);
        const paidPrefixIds = paidPrefix.map((c) => c.creativeId);
        for (const id of paidPrefixIds) {
          chargedSet.add(id);
        }
        inFlightSet = new Set();
        chargedEventCount = chargedSet.size;
        await persistCheckpointPostCharge();

        const pushRes = await pushDataWithRetry(paidPrefix);
        if (!pushRes.ok) {
          chargeReceipts.push(
            buildFinalReceipt(chargedCount, {
              chargedCreativeIds: paidPrefixIds,
              eventChargeLimitReached: true,
            })
          );
          finalOk = false;
          finalStatus = 'PARTIAL_BILLING_HALT';
          haltReason = `Dataset pushData failed after charge limit prefix (paid items preserved in KVS checkpoint stagedItemsById): ${pushRes.error?.message || String(pushRes.error)}`;
          break;
        }
        for (const c of paidPrefix) {
          deliveredSet.add(c.creativeId);
          delete stagedItemsById[c.creativeId];
          newlyDeliveredItems.push(c);
        }
        deliveredCount = deliveredSet.size;
        await persistCheckpointPostCharge();

        chargeReceipts.push(
          buildFinalReceipt(chargedCount, {
            chargedCreativeIds: paidPrefixIds,
            eventChargeLimitReached: true,
          })
        );

        finalOk = true;
        finalStatus = 'CHARGE_LIMIT_REACHED';
        break;
      } else {
        // Unexpected partial count without eventChargeLimitReached and without explicit IDs ->
        // move chunk to unknownOutcomeIds and halt fail-closed
        for (const id of chunkIds) {
          unknownOutcomeSet.add(id);
        }
        inFlightSet = new Set();
        chargedEventCount = chargedSet.size + chargedCount;
        await persistCheckpointPostCharge();

        chargeReceipts.push(
          buildFinalReceipt(chargedCount, {
            eventChargeLimitReached: false,
          })
        );

        finalOk = false;
        finalStatus = 'PARTIAL_BILLING_HALT';
        haltReason = `Ambiguous partial chunk charge (${chargedCount}/${unchargedChunk.length}) without chargedCreativeIds attribution or eventChargeLimitReached`;
        break;
      }
    }
  }

  // Step 5: Rewind pagination cursor if billing halted or reached charge limit before delivering all extracted items
  let effectiveNextPageToken = creativesRes.nextPageToken;
  let effectivePaginationStatus = creativesRes.paginationStatus;
  let effectiveIncompleteReason = creativesRes.paginationIncompleteReason;
  const undeliveredCount = Math.max(0, newBillableCandidates.length - newlyDeliveredItems.length);

  if (undeliveredCount > 0) {
    const firstUndeliveredItem = newBillableCandidates.find((c) => !deliveredSet.has(c.creativeId));
    const firstUndeliveredExtractedIdx = Array.isArray(creativesRes.creatives)
      ? creativesRes.creatives.findIndex((c) => c.creativeId === firstUndeliveredItem?.creativeId)
      : -1;
    const effectiveDeliveredPrefixLen =
      firstUndeliveredExtractedIdx >= 0 ? firstUndeliveredExtractedIdx : newlyDeliveredItems.length;
    effectiveNextPageToken = computeRewoundCursorForDeliveredPrefix(
      creativesRes.cursorResumeContext,
      effectiveDeliveredPrefixLen,
      creativesRes.nextPageToken
    );
    effectivePaginationStatus =
      finalStatus === 'CHARGE_LIMIT_REACHED'
        ? 'CHARGE_LIMIT_REACHED_HAS_MORE'
        : finalStatus === 'DEADLINE_EXCEEDED_BEFORE_CHARGE'
          ? 'DEADLINE_EXCEEDED_HAS_MORE'
          : 'PARTIAL_BILLING_HALT';
    effectiveIncompleteReason = finalStatus;
  } else if (finalStatus === 'CHARGE_LIMIT_REACHED' && effectiveNextPageToken) {
    effectivePaginationStatus = 'CHARGE_LIMIT_REACHED_HAS_MORE';
    effectiveIncompleteReason = finalStatus;
  }

  const paginationMeta = {
    offset: creativesRes.offset ?? 0,
    nextPageToken: effectiveNextPageToken,
    nextCursor: effectiveNextPageToken,
    paginationStatus: effectivePaginationStatus,
    paginationIncompleteReason: effectiveIncompleteReason,
    pagesFetched: creativesRes.pagesFetched,
    ...(runtimeWarnings.length > 0 ? { warnings: runtimeWarnings } : {}),
    ...(undeliveredCount > 0 ? { undeliveredCount } : {}),
  };

  // Merge reconciled items + newly delivered items with strict creativeId deduplication
  const allOutputItems = [];
  const outputSeenIds = new Set();
  for (const item of [...reconciledItems, ...newlyDeliveredItems]) {
    if (item?.creativeId && !outputSeenIds.has(item.creativeId)) {
      outputSeenIds.add(item.creativeId);
      allOutputItems.push(item);
    }
  }

  const simulatedBillableCount = hasChargeHook ? chargedEventCount : allOutputItems.length;
  const durationMs = Math.max(1, nowMs() - startedAtMs);
  const telemetry = computeRunEconomicsTelemetry({
    billableCount: simulatedBillableCount,
    chargedEventCount,
    durationMs,
    requestCount: Math.max(1, totalRpcRequests),
    unitPriceUsdc: lastResolvedUnitPriceUsdc,
    actorStartFeeUsdc: hooks?.actorStartFeeUsdc,
  });

  return finalizeActorReturn({
    ok: finalOk,
    status: finalStatus,
    reason: haltReason,
    billingMode,
    queryMeta: entityRes.queryMeta,
    selectedEntities: entityRes.selectedEntities,
    items: allOutputItems,
    extractedCount,
    deliveredCount,
    billableCount: simulatedBillableCount,
    chargedEventCount,
    unknownOutcomeIds: Array.from(unknownOutcomeSet),
    chargeReceipts,
    pagination: paginationMeta,
    ...(runtimeWarnings.length > 0 ? { warnings: runtimeWarnings } : {}),
    cursorResumeContext: creativesRes.cursorResumeContext,
    telemetry,
  });
}

export const scrapeGoogleAdsTransparency = runGoogleAdsTransparencyActor;

