/**
 * Apify Pay-per-Event Execution, Native Platform Adapter & Crash-Safe Billing State Machine (src/apify_actor.mjs)
 *
 * Enforces deterministic Pay-per-Event billing and fail-closed KVS OUTPUT diagnostic persistence
 * for RevClamp ContactPulse (`@revclamp/b2b-domain-contact-enricher-mcp`).
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  DEFAULT_RUN_DEADLINE_MS,
  normalizeContactPulseInputAliases,
  resolveB2bDomainContactsBatch,
  computeRewoundCursorForDeliveredPrefix,
} from './contact_client.mjs';
import { verifyEgressUrlSsrfSafe } from './egress_guard.mjs';

export const ACTOR_PRICING_CONTRACT = Object.freeze({
  eventName: 'domain-contact-profile-enriched',
  actorStartFeeUsdc: 0.001,
  priceUsdc: 0.002,
  costCeilingUsdc: 0.00015,
  platformFeeRate: 0.2,
  netPriceUsdc: 0.0016,
  minMarginMultiplier: 2.5,
  computeRatePerGbHourUsdc: 0.3,
  maxMemoryMb: 256,
  maxTimeoutSec: 25,
  chunkSize: 25,
  checkpointKey: 'CONTACTPULSE_BILLING_CHECKPOINT',
});

export function computeChunkIdempotencyKey(runId, profileIds = []) {
  const safeRunId = String(runId || 'default_run');
  const sortedIds = [...profileIds].map((id) => String(id)).sort();
  return crypto
    .createHash('sha256')
    .update(`${safeRunId}\x1f${sortedIds.join('\x1f')}`, 'utf8')
    .digest('hex');
}

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
    withinCostCeiling && configuredFloorMultiplier >= ACTOR_PRICING_CONTRACT.minMarginMultiplier;

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

function resolveSafeApifyApiBaseUrl(rawApiBaseUrl, fallbackPublicBaseUrl = undefined) {
  const candidate = String(rawApiBaseUrl || fallbackPublicBaseUrl || 'https://api.apify.com')
    .trim()
    .replace(/\/+$/, '');
  const ssrf = verifyEgressUrlSsrfSafe(candidate);
  if (!ssrf.safe) {
    if (fallbackPublicBaseUrl) {
      const publicCandidate = String(fallbackPublicBaseUrl).trim().replace(/\/+$/, '');
      const publicSsrf = verifyEgressUrlSsrfSafe(publicCandidate);
      if (publicSsrf.safe) return publicCandidate;
    }
    throw new Error(`Invalid or unsafe APIFY_API_BASE_URL '${candidate}': ${ssrf.reason}`);
  }
  return candidate;
}

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
  const DEFAULT_SCHEMA_QUERY =
    'stripe.com, linear.app, cloudflare.com, shopify.com';
  const LEGACY_SCHEMA_QUERY =
    'stripe.com, linear.app, cloudflare.com, shopify.com, github.com';
  const applyAtHomeSchemaDefaults = (parsedInput) => {
    if (!parsedInput || typeof parsedInput !== 'object' || Array.isArray(parsedInput)) {
      return parsedInput;
    }
    const next = { ...parsedInput };
    const hasNonEmptyAlias = (keys) =>
      keys.some((k) => {
        const v = next[k];
        if (v === undefined || v === null) return false;
        if (Array.isArray(v)) return v.length > 0;
        return String(v).trim() !== '';
      });
    if (
      (next.query === DEFAULT_SCHEMA_QUERY || next.query === LEGACY_SCHEMA_QUERY) &&
      hasNonEmptyAlias(['domains', 'domain', 'company', 'url'])
    ) {
      delete next.query;
    }
    if (
      (next.maxResults === 4 || next.maxResults === 5) &&
      hasNonEmptyAlias(['limit', 'max_results'])
    ) {
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
      !Object.prototype.hasOwnProperty.call(next, 'domains') &&
      !Object.prototype.hasOwnProperty.call(next, 'domain') &&
      !Object.prototype.hasOwnProperty.call(next, 'company') &&
      !Object.prototype.hasOwnProperty.call(next, 'url') &&
      !hasNonEmptyAlias(['pageToken', 'cursor'])
    ) {
      const hasExplicitLimit =
        Object.prototype.hasOwnProperty.call(next, 'maxResults') ||
        Object.prototype.hasOwnProperty.call(next, 'limit') ||
        Object.prototype.hasOwnProperty.call(next, 'max_results');
      return {
        query: DEFAULT_SCHEMA_QUERY,
        ...(!hasExplicitLimit ? { maxResults: 4 } : {}),
        ...next,
      };
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
      return applyAtHomeSchemaDefaults({});
    } finally {
      clearTimeout(timer);
    }
  }

  return applyAtHomeSchemaDefaults({});
}

export function createApifyPlatformHooks(env = process.env, fetchImpl = globalThis.fetch) {
  const runId = String(env?.ACTOR_RUN_ID || env?.APIFY_ACTOR_RUN_ID || 'local_run');
  const kvsId = env?.ACTOR_DEFAULT_KEY_VALUE_STORE_ID || env?.APIFY_DEFAULT_KEY_VALUE_STORE_ID;
  const datasetId = env?.ACTOR_DEFAULT_DATASET_ID || env?.APIFY_DEFAULT_DATASET_ID;
  const token = env?.APIFY_TOKEN;
  const isAtHome =
    (env?.APIFY_IS_AT_HOME === '1' || env?.APIFY_IS_AT_HOME === 'true') &&
    Boolean(token && runId && datasetId);
  const localStorageDir =
    env?.ACTOR_STORAGE_DIR || env?.APIFY_LOCAL_STORAGE_DIR || env?.CRAWLEE_STORAGE_DIR;

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
  const rawIncludeStartFee = String(env?.ACTOR_INCLUDE_START_FEE ?? '')
    .trim()
    .toLowerCase();
  const includeStartFee =
    rawIncludeStartFee === '' ? true : rawIncludeStartFee !== '0' && rawIncludeStartFee !== 'false';
  const rawStartFeeUsd =
    env?.ACTOR_START_FEE_USD !== undefined && env?.ACTOR_START_FEE_USD !== null
      ? String(env.ACTOR_START_FEE_USD).trim()
      : '';
  const explicitStartFeeUsd = rawStartFeeUsd !== '' ? Number(rawStartFeeUsd) : NaN;
  const rawIdempotencyFlag = String(env?.APIFY_CHARGE_IDEMPOTENCY_SUPPORTED ?? '')
    .trim()
    .toLowerCase();
  const idempotentChargeRetryEnabled =
    rawIdempotencyFlag === ''
      ? true
      : rawIdempotencyFlag === '1' || rawIdempotencyFlag === 'true';
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
    const apiBase = resolveSafeApifyApiBaseUrl(
      env?.APIFY_API_BASE_URL,
      env?.APIFY_API_PUBLIC_BASE_URL
    );
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
    if (resolvedUserTier && hooksObj) {
      const refreshed = computeCurrentPricingState();
      hooksObj.unitPriceUsdc = refreshed.unitPriceUsdc;
      hooksObj.actorStartFeeUsdc = refreshed.actorStartFeeUsdc;
      hooksObj.pricingDeterministic = refreshed.deterministic;
    }
    return resolvedUserTier;
  };
  const computeCurrentPricingState = () => {
    const startInfo = resolveTieredEventPriceInfo(
      pricingInfoChargeEvents?.['apify-actor-start'],
      { allowZero: true }
    );
    const resolvedBaseStartFee = !startInfo.deterministic
      ? null
      : Number.isFinite(explicitStartFeeUsd) && explicitStartFeeUsd >= 0
        ? explicitStartFeeUsd
        : Number.isFinite(startInfo.priceUsd) && startInfo.priceUsd >= 0
          ? startInfo.priceUsd
          : ACTOR_PRICING_CONTRACT.actorStartFeeUsdc;
    const actorStartFeeUsdc =
      resolvedBaseStartFee === null ? (includeStartFee ? null : 0) : includeStartFee ? resolvedBaseStartFee : 0;
    const primaryInfo = resolveTieredEventPriceInfo(
      pricingInfoChargeEvents?.[ACTOR_PRICING_CONTRACT.eventName],
      { allowZero: false }
    );
    const unitPriceUsdc = !primaryInfo.deterministic
      ? null
      : Number.isFinite(primaryInfo.priceUsd) && primaryInfo.priceUsd > 0
        ? primaryInfo.priceUsd
        : ACTOR_PRICING_CONTRACT.priceUsdc;
    return {
      actorStartFeeUsdc,
      unitPriceUsdc,
      deterministic: (startInfo.deterministic || !includeStartFee) && primaryInfo.deterministic,
    };
  };
  const initialPricingState = computeCurrentPricingState();
  const maxBudgetMicros = hasMaxChargeUsd ? Math.round(maxTotalChargeUsdRaw * 1_000_000) : 0;
  let cumulativeChargedInAdapter = 0;
  let adapterChargeLimitLatched = false;

  const memStore = new Map();
  const memDataset = [];

  const putKvsRecord = async (key, value) => {
    const jsonBody = JSON.stringify(value, null, 2);
    if (kvsId && token && typeof fetchImpl === 'function') {
      const apiBase = resolveSafeApifyApiBaseUrl(
        env?.APIFY_API_BASE_URL,
        env?.APIFY_API_PUBLIC_BASE_URL
      );
      const url = `${apiBase}/v2/key-value-stores/${encodeURIComponent(kvsId)}/records/${encodeURIComponent(key)}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4500);
      try {
        const res = await fetchImpl(url, {
          method: 'PUT',
          headers: {
            authorization: `Bearer ${token}`,
            'content-type': 'application/json; charset=utf-8',
          },
          body: jsonBody,
          signal: controller.signal,
        });
        if (!res.ok) {
          throw new Error(`Apify KVS PUT '${key}' failed with HTTP ${res.status}`);
        }
      } finally {
        clearTimeout(timer);
      }
    }
    if (localStorageDir) {
      const storeFolder = path.join(
        localStorageDir,
        'key_value_stores',
        kvsId || 'default'
      );
      fs.mkdirSync(storeFolder, { recursive: true });
      fs.writeFileSync(path.join(storeFolder, `${key}.json`), jsonBody, 'utf8');
    }
    memStore.set(key, value);
  };

  const getKvsRecord = async (key) => {
    if (memStore.has(key)) return memStore.get(key);
    if (localStorageDir) {
      const localPath = path.join(
        localStorageDir,
        'key_value_stores',
        kvsId || 'default',
        `${key}.json`
      );
      if (fs.existsSync(localPath)) {
        return JSON.parse(fs.readFileSync(localPath, 'utf8'));
      }
    }
    if (kvsId && token && typeof fetchImpl === 'function') {
      const apiBase = resolveSafeApifyApiBaseUrl(
        env?.APIFY_API_BASE_URL,
        env?.APIFY_API_PUBLIC_BASE_URL
      );
      const url = `${apiBase}/v2/key-value-stores/${encodeURIComponent(kvsId)}/records/${encodeURIComponent(key)}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 3500);
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
          return await res.json();
        }
      } catch {
        return null;
      } finally {
        clearTimeout(timer);
      }
    }
    return null;
  };

  const hooksObj = {
    runId,
    isAtHome,
    hasMaxChargeUsd,
    maxTotalChargeUsd: hasMaxChargeUsd ? maxTotalChargeUsdRaw : null,
    includeStartFee,
    unitPriceUsdc: initialPricingState.unitPriceUsdc,
    actorStartFeeUsdc: initialPricingState.actorStartFeeUsdc,
    pricingDeterministic: initialPricingState.deterministic,
    resolveUserTier: ensureUserTierResolved,
    async loadCheckpoint() {
      const loaded = (await getKvsRecord(ACTOR_PRICING_CONTRACT.checkpointKey)) || {
        chargedIds: [],
        deliveredIds: [],
      };
      if (
        loaded &&
        Array.isArray(loaded.chargedIds) &&
        (!loaded.runId || !runId || String(loaded.runId) === String(runId))
      ) {
        cumulativeChargedInAdapter = loaded.chargedIds.length;
      }
      return loaded;
    },
    async saveCheckpoint(state) {
      await putKvsRecord(ACTOR_PRICING_CONTRACT.checkpointKey, state);
    },
    async listDeliveredIds() {
      if (memDataset.length > 0) {
        return memDataset
          .map((row) => (typeof row?.profileId === 'string' ? row.profileId : null))
          .filter(Boolean);
      }
      if (localStorageDir) {
        const dsFolder = path.join(localStorageDir, 'datasets', datasetId || 'default');
        if (fs.existsSync(dsFolder)) {
          const ids = [];
          for (const file of fs.readdirSync(dsFolder).filter((f) => f.endsWith('.json'))) {
            try {
              const parsed = JSON.parse(fs.readFileSync(path.join(dsFolder, file), 'utf8'));
              if (typeof parsed?.profileId === 'string') ids.push(parsed.profileId);
            } catch {
              // Ignore unreadable partial files
            }
          }
          if (ids.length > 0) return ids;
        }
      }
      if (datasetId && token && typeof fetchImpl === 'function') {
        const apiBase = resolveSafeApifyApiBaseUrl(
          env?.APIFY_API_BASE_URL,
          env?.APIFY_API_PUBLIC_BASE_URL
        );
        const url = `${apiBase}/v2/datasets/${encodeURIComponent(datasetId)}/items?fields=profileId&clean=1`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 2500);
        try {
          const res = await fetchImpl(url, {
            method: 'GET',
            headers: {
              authorization: `Bearer ${token}`,
              accept: 'application/json',
            },
            signal: controller.signal,
          });
          if (res && res.status >= 200 && res.status < 300) {
            const text = typeof res.text === 'function' ? await res.text() : '';
            const parsed =
              text && text.trim()
                ? JSON.parse(text)
                : typeof res.json === 'function'
                  ? await res.json()
                  : [];
            const arr = Array.isArray(parsed)
              ? parsed
              : Array.isArray(parsed?.data?.items)
                ? parsed.data.items
                : [];
            return arr
              .map((row) => (typeof row?.profileId === 'string' ? row.profileId : null))
              .filter(Boolean);
          }
        } catch {
          return [];
        } finally {
          clearTimeout(timer);
        }
      }
      return [];
    },
    async pushData(items = []) {
      const batch = Array.isArray(items) ? items : [items];
      if (batch.length === 0) return { pushedCount: 0 };
      if (datasetId && token && typeof fetchImpl === 'function') {
        const apiBase = resolveSafeApifyApiBaseUrl(
          env?.APIFY_API_BASE_URL,
          env?.APIFY_API_PUBLIC_BASE_URL
        );
        const url = `${apiBase}/v2/datasets/${encodeURIComponent(datasetId)}/items`;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        try {
          const res = await fetchImpl(url, {
            method: 'POST',
            headers: {
              authorization: `Bearer ${token}`,
              'content-type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify(batch),
            signal: controller.signal,
          });
          if (!res.ok) {
            throw new Error(`Dataset pushData failed with HTTP ${res.status}`);
          }
        } finally {
          clearTimeout(timer);
        }
      }
      memDataset.push(...batch);
      if (localStorageDir) {
        const dsFolder = path.join(
          localStorageDir,
          'datasets',
          datasetId || 'default'
        );
        fs.mkdirSync(dsFolder, { recursive: true });
        for (const [idx, item] of batch.entries()) {
          const fname = `${String(memDataset.length - batch.length + idx + 1).padStart(9, '0')}.json`;
          fs.writeFileSync(path.join(dsFolder, fname), JSON.stringify(item, null, 2), 'utf8');
        }
      }
      return { pushedCount: batch.length };
    },
    async chargeEvent({ eventName, count, idempotencyKey }) {
      let currentPricing = computeCurrentPricingState();
      if (!currentPricing.deterministic && !userTierProbeDone) {
        await ensureUserTierResolved();
        currentPricing = computeCurrentPricingState();
      }
      hooksObj.unitPriceUsdc = currentPricing.unitPriceUsdc;
      hooksObj.actorStartFeeUsdc = currentPricing.actorStartFeeUsdc;
      hooksObj.pricingDeterministic = currentPricing.deterministic;
      const requested = Math.max(0, Math.floor(Number(count) || 0));
      if (requested === 0 || !isAtHome) {
        return {
          chargedCount: 0,
          eventChargeLimitReached: false,
          unitPriceUsdc: currentPricing.unitPriceUsdc,
          pricingDeterministic: hooksObj.pricingDeterministic,
        };
      }
      if (adapterChargeLimitLatched) {
        return {
          chargedCount: 0,
          eventChargeLimitReached: true,
          unitPriceUsdc: currentPricing.unitPriceUsdc,
          pricingDeterministic: hooksObj.pricingDeterministic,
        };
      }
      const unitPriceMicros =
        currentPricing.unitPriceUsdc === null
          ? NaN
          : Math.round(currentPricing.unitPriceUsdc * 1_000_000);
      const startFeeMicros =
        currentPricing.actorStartFeeUsdc === null
          ? NaN
          : Math.round(currentPricing.actorStartFeeUsdc * 1_000_000);
      const canEnforceLocalBudgetCap =
        hasMaxChargeUsd &&
        currentPricing.deterministic &&
        Number.isInteger(unitPriceMicros) &&
        unitPriceMicros >= 1 &&
        Number.isInteger(startFeeMicros) &&
        startFeeMicros >= 0;
      const maxPayableEvents = canEnforceLocalBudgetCap
        ? Math.floor(Math.max(0, maxBudgetMicros - startFeeMicros) / unitPriceMicros)
        : Infinity;
      const remainingAllowance = Number.isFinite(maxPayableEvents)
        ? Math.max(0, maxPayableEvents - cumulativeChargedInAdapter)
        : requested;
      const countToCharge = Math.min(requested, remainingAllowance);
      const localCapReached =
        Number.isFinite(maxPayableEvents) &&
        cumulativeChargedInAdapter + countToCharge >= maxPayableEvents &&
        countToCharge < requested;
      if (countToCharge === 0) {
        adapterChargeLimitLatched = Number.isFinite(maxPayableEvents);
        return {
          chargedCount: 0,
          eventChargeLimitReached: Number.isFinite(maxPayableEvents),
          unitPriceUsdc: currentPricing.unitPriceUsdc,
          pricingDeterministic: hooksObj.pricingDeterministic,
        };
      }

      const apiBase = resolveSafeApifyApiBaseUrl(
        env?.APIFY_API_BASE_URL,
        env?.APIFY_API_PUBLIC_BASE_URL
      );
      const url = `${apiBase}/v2/actor-runs/${encodeURIComponent(runId)}/charge`;
      const safeIdemKey = String(idempotencyKey || `${runId}_${Date.now()}`);
      const maxAttempts = idempotentChargeRetryEnabled ? 3 : 1;
      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 5000);
        try {
          const res = await fetchImpl(url, {
            method: 'POST',
            headers: {
              authorization: `Bearer ${token}`,
              'content-type': 'application/json; charset=utf-8',
              'idempotency-key': safeIdemKey,
            },
            body: JSON.stringify({ eventName, count: countToCharge }),
            signal: controller.signal,
          });
          if (res.status === 402) {
            adapterChargeLimitLatched = true;
            return {
              chargedCount: 0,
              eventChargeLimitReached: true,
              unitPriceUsdc: currentPricing.unitPriceUsdc,
              pricingDeterministic: hooksObj.pricingDeterministic,
            };
          }
          if (
            attempt < maxAttempts &&
            (res.status === 429 || res.status === 502 || res.status === 503 || res.status === 504)
          ) {
            await new Promise((resolve) => setTimeout(resolve, attempt * 150));
            continue;
          }
          if (!res.ok) {
            throw new Error(`Apify charge API returned HTTP ${res.status}`);
          }
          let body = null;
          try {
            body = await res.json();
          } catch {
            body = null;
          }
          const rawCharged = body?.data?.chargedCount ?? body?.chargedCount;
          const chargedCount =
            typeof rawCharged === 'number' && Number.isInteger(rawCharged) && rawCharged >= 0
              ? Math.min(countToCharge, rawCharged)
              : countToCharge;
          cumulativeChargedInAdapter += chargedCount;
          const limitReached = Boolean(
            body?.data?.eventChargeLimitReached ||
              body?.eventChargeLimitReached ||
              localCapReached ||
              (Number.isFinite(maxPayableEvents) && cumulativeChargedInAdapter >= maxPayableEvents)
          );
          if (limitReached) {
            adapterChargeLimitLatched = true;
          }
          return {
            chargedCount,
            eventChargeLimitReached: limitReached,
            unitPriceUsdc: currentPricing.unitPriceUsdc,
            pricingDeterministic: hooksObj.pricingDeterministic,
          };
        } finally {
          clearTimeout(timer);
        }
      }
      throw new Error(`Apify charge API rate limit exhausted after ${maxAttempts} attempt(s)`);
    },
    async saveOutput(outputRecord) {
      await putKvsRecord('OUTPUT', outputRecord);
    },
  };
  Object.defineProperty(hooksObj, 'idempotentChargeRetryEnabled', {
    enumerable: true,
    configurable: true,
    get: () => idempotentChargeRetryEnabled !== false,
  });
  return hooksObj;
}

/**
 * Computes the maximum number of new billable domains affordable under `ACTOR_MAX_TOTAL_CHARGE_USD`
 * using integer micro-USD arithmetic (`Math.round(usd * 1_000_000)`).
 *
 * @param {object} hooks
 * @param {number} [alreadyChargedCount=0]
 * @returns {number}
 */
export function resolveMaxBillableDomainsForBudget(hooks, alreadyChargedCount = 0) {
  if (!hooks || !hooks.isAtHome || !hooks.hasMaxChargeUsd) {
    return Infinity;
  }
  if (
    hooks.pricingDeterministic === false ||
    hooks.unitPriceUsdc === null ||
    hooks.actorStartFeeUsdc === null
  ) {
    return Infinity;
  }
  const maxUsd = Number(hooks.maxTotalChargeUsd);
  if (!Number.isFinite(maxUsd) || maxUsd < 0) {
    return Infinity;
  }
  const unitUsd =
    Number.isFinite(Number(hooks.unitPriceUsdc)) && Number(hooks.unitPriceUsdc) > 0
      ? Number(hooks.unitPriceUsdc)
      : ACTOR_PRICING_CONTRACT.priceUsdc;
  const startFeeUsd =
    hooks.includeStartFee === false
      ? 0
      : Number.isFinite(Number(hooks.actorStartFeeUsdc)) && Number(hooks.actorStartFeeUsdc) >= 0
        ? Number(hooks.actorStartFeeUsdc)
        : ACTOR_PRICING_CONTRACT.actorStartFeeUsdc;

  const maxMicros = Math.round(maxUsd * 1_000_000);
  const startMicros = Math.round(startFeeUsd * 1_000_000);
  const unitMicros = Math.max(1, Math.round(unitUsd * 1_000_000));
  const totalPayable = Math.floor(Math.max(0, maxMicros - startMicros) / unitMicros);
  const priorCharged = Math.max(0, Math.floor(Number(alreadyChargedCount) || 0));
  return Math.max(0, totalPayable - priorCharged);
}

function normalizeBillingCheckpointState(rawState, runId) {
  const s = rawState && typeof rawState === 'object' && !Array.isArray(rawState) ? rawState : {};
  if (s.runId && runId && String(s.runId).trim() !== String(runId).trim()) {
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
  const toCleanStringList = (arr) =>
    Array.isArray(arr)
      ? Array.from(new Set(arr.filter((v) => typeof v === 'string' && v.trim())))
      : [];
  const rawStaged =
    s.stagedItemsById && typeof s.stagedItemsById === 'object' && !Array.isArray(s.stagedItemsById)
      ? s.stagedItemsById
      : {};
  const stagedItemsById = {};
  for (const [k, v] of Object.entries(rawStaged)) {
    if (k && v && typeof v === 'object') {
      stagedItemsById[k] = v;
    }
  }
  return {
    runId: String(runId || s.runId || 'default_run'),
    chargedIds: toCleanStringList(s.chargedIds),
    deliveredIds: toCleanStringList(s.deliveredIds),
    inFlightIds: toCleanStringList(s.inFlightIds),
    inFlightIdempotencyKey:
      typeof s.inFlightIdempotencyKey === 'string' && s.inFlightIdempotencyKey.trim()
        ? s.inFlightIdempotencyKey.trim()
        : null,
    unknownOutcomeIds: toCleanStringList(s.unknownOutcomeIds),
    stagedItemsById,
  };
}

export async function runDomainContactEnricherActor(input = {}, options = {}) {
  const startedAtMs = Date.now();
  const hooks =
    options?.platformHooks || createApifyPlatformHooks(options?.env || process.env, options?.fetchImpl);
  const billingMode = hooks.isAtHome ? 'APIFY_PAY_PER_EVENT' : 'LOCAL_UNBILLED';
  const billingReserveMs = hooks.isAtHome ? 2500 : 0;
  const deadlineAtMs =
    Number.isFinite(Number(options?.deadlineAtMs)) && Number(options.deadlineAtMs) > 0
      ? Number(options.deadlineAtMs)
      : startedAtMs + Math.max(2000, DEFAULT_RUN_DEADLINE_MS - billingReserveMs);

  const rawCheckpoint =
    hooks.isAtHome && typeof hooks.loadCheckpoint === 'function'
      ? await hooks.loadCheckpoint()
      : null;
  const checkpoint = normalizeBillingCheckpointState(rawCheckpoint, hooks.runId);
  const alreadyCharged = new Set(checkpoint.chargedIds);
  const alreadyDelivered = new Set(checkpoint.deliveredIds);
  let inFlightSet = new Set(checkpoint.inFlightIds);
  let inFlightIdempotencyKey = checkpoint.inFlightIdempotencyKey;
  const unknownOutcomeSet = new Set(checkpoint.unknownOutcomeIds);
  const stagedItemsById = { ...checkpoint.stagedItemsById };

  const persistCheckpoint = async () => {
    if (!hooks.isAtHome || typeof hooks.saveCheckpoint !== 'function') return;
    await hooks.saveCheckpoint({
      runId: String(hooks.runId || 'default_run'),
      chargedIds: Array.from(alreadyCharged),
      deliveredIds: Array.from(alreadyDelivered),
      inFlightIds: Array.from(inFlightSet),
      inFlightIdempotencyKey,
      unknownOutcomeIds: Array.from(unknownOutcomeSet),
      stagedItemsById,
      updatedAtIso: new Date().toISOString(),
    });
  };

  let reconciledDeliveredItems = [];
  let chargeLimitReached = false;
  let partialBillingFailure = false;
  let haltErrorCode = null;
  let haltStatusOverride = null;
  let haltReasonOverride = null;

  if (hooks.isAtHome) {
    let existingDatasetIds = new Set();
    if (typeof hooks.listDeliveredIds === 'function') {
      try {
        const listed = await hooks.listDeliveredIds();
        if (Array.isArray(listed)) {
          existingDatasetIds = new Set(listed.filter((v) => typeof v === 'string'));
        }
      } catch {
        existingDatasetIds = new Set();
      }
    }

    // Step 0a: Deliver any already-charged items not yet marked delivered
    const pendingChargedUndelivered = Array.from(alreadyCharged).filter(
      (id) => !alreadyDelivered.has(id) && stagedItemsById[id]
    );
    if (pendingChargedUndelivered.length > 0) {
      const toReplayPush = pendingChargedUndelivered
        .filter((id) => !existingDatasetIds.has(id))
        .map((id) => stagedItemsById[id]);
      if (toReplayPush.length > 0) {
        await hooks.pushData(toReplayPush);
      }
      for (const id of pendingChargedUndelivered) {
        alreadyDelivered.add(id);
        reconciledDeliveredItems.push(stagedItemsById[id]);
        delete stagedItemsById[id];
      }
      await persistCheckpoint();
    }

    // Step 0b: Reconcile any pre-crash IN_FLIGHT chunk via deterministic Idempotency-Key replay
    if (inFlightSet.size > 0) {
      const inFlightIdsList = Array.from(inFlightSet);
      const canReplayIdempotently =
        hooks.idempotentChargeRetryEnabled === true &&
        Boolean(inFlightIdempotencyKey) &&
        typeof hooks.chargeEvent === 'function';
      if (!canReplayIdempotently) {
        for (const id of inFlightIdsList) {
          unknownOutcomeSet.add(id);
        }
        inFlightSet = new Set();
        inFlightIdempotencyKey = null;
        await persistCheckpoint();
        partialBillingFailure = true;
        haltStatusOverride = 'PARTIAL_BILLING_HALT';
        haltErrorCode = 'PARTIAL_BILLING_HALT';
        haltReasonOverride =
          'Cannot replay in-flight Pay-per-Event charge without idempotent charge retry support';
      } else {
        try {
          const replayRes = await hooks.chargeEvent({
            eventName: ACTOR_PRICING_CONTRACT.eventName,
            count: inFlightIdsList.length,
            idempotencyKey: inFlightIdempotencyKey,
          });
          const replayChargedCount = Math.max(
            0,
            Math.min(inFlightIdsList.length, Number(replayRes?.chargedCount) || 0)
          );
          const replayChargedIds = inFlightIdsList.slice(0, replayChargedCount);
          for (const id of replayChargedIds) {
            alreadyCharged.add(id);
          }
          if (replayRes?.eventChargeLimitReached) {
            chargeLimitReached = true;
          } else if (replayChargedCount < inFlightIdsList.length) {
            partialBillingFailure = true;
            haltStatusOverride = 'PARTIAL_BILLING_HALT';
            haltErrorCode = 'PARTIAL_BILLING_HALT';
            haltReasonOverride = `Ambiguous partial charge replay (${replayChargedCount}/${inFlightIdsList.length})`;
            for (const id of inFlightIdsList.slice(replayChargedCount)) {
              unknownOutcomeSet.add(id);
            }
          }
          inFlightSet = new Set();
          inFlightIdempotencyKey = null;
          await persistCheckpoint();

          const toPushReplayed = replayChargedIds
            .filter((id) => !alreadyDelivered.has(id) && stagedItemsById[id])
            .filter((id) => !existingDatasetIds.has(id))
            .map((id) => stagedItemsById[id]);
          if (toPushReplayed.length > 0) {
            await hooks.pushData(toPushReplayed);
          }
          for (const id of replayChargedIds) {
            if (stagedItemsById[id]) {
              alreadyDelivered.add(id);
              reconciledDeliveredItems.push(stagedItemsById[id]);
              delete stagedItemsById[id];
            }
          }
          await persistCheckpoint();
        } catch (replayErr) {
          for (const id of inFlightIdsList) {
            unknownOutcomeSet.add(id);
          }
          inFlightSet = new Set();
          inFlightIdempotencyKey = null;
          await persistCheckpoint();
          partialBillingFailure = true;
          haltStatusOverride = 'UNKNOWN_CHARGE_OUTCOME';
          haltErrorCode = 'CHARGE_API_ERROR';
          haltReasonOverride = `In-flight charge replay failed: ${replayErr?.message || replayErr}`;
        }
      }
    }

    if (!partialBillingFailure && unknownOutcomeSet.size > 0) {
      partialBillingFailure = true;
      haltStatusOverride = 'PARTIAL_BILLING_HALT';
      haltErrorCode = 'PARTIAL_BILLING_HALT';
      haltReasonOverride =
        'Unreconciled unknown charge outcome from prior container attempt; halting fail-closed';
    }
  }

  if (partialBillingFailure && haltStatusOverride) {
    const durationMs = Math.max(1, Date.now() - startedAtMs);
    const chargedCountSoFar = hooks.isAtHome ? alreadyCharged.size : 0;
    const telemetry = computeRunEconomicsTelemetry({
      billableCount: reconciledDeliveredItems.length,
      chargedEventCount: chargedCountSoFar,
      durationMs,
      requestCount: 1,
      unitPriceUsdc: hooks.unitPriceUsdc,
      actorStartFeeUsdc: hooks.actorStartFeeUsdc,
      pricingDeterministic: hooks.pricingDeterministic,
    });
    const haltPayload = {
      ok: false,
      status: haltStatusOverride,
      errorCode: haltErrorCode || 'PARTIAL_BILLING_HALT',
      reason: haltReasonOverride || 'Billing reconciliation halted fail-closed',
      billingMode,
      extractedCount: reconciledDeliveredItems.length,
      deliveredCount: reconciledDeliveredItems.length,
      billableCount: reconciledDeliveredItems.length,
      chargedEventCount: chargedCountSoFar,
      items: reconciledDeliveredItems,
      pagination: {
        offset: 0,
        limit: 5,
        totalDomainsCount: reconciledDeliveredItems.length,
        hasMore: true,
        nextPageToken: null,
        nextCursor: null,
        paginationStatus: haltStatusOverride,
      },
      telemetry,
    };
    await hooks.saveOutput(haltPayload);
    return haltPayload;
  }

  // Upfront micro-USD budget pre-cap before crawling upstream domains
  let maxDomainsToProcess = undefined;
  if (hooks.isAtHome && hooks.hasMaxChargeUsd) {
    if (hooks.pricingDeterministic === false && typeof hooks.resolveUserTier === 'function') {
      await hooks.resolveUserTier();
    }
    const maxAffordableNewDomains = resolveMaxBillableDomainsForBudget(hooks, alreadyCharged.size);
    if (Number.isFinite(maxAffordableNewDomains)) {
      maxDomainsToProcess = Math.max(0, maxAffordableNewDomains);
      if (maxDomainsToProcess === 0) {
        chargeLimitReached = true;
      }
    }
  }

  const batchRes = await resolveB2bDomainContactsBatch(input, {
    ...options,
    deadlineAtMs,
    ...(maxDomainsToProcess !== undefined ? { maxDomainsToProcess } : {}),
  });
  if (!batchRes.ok) {
    const durationMs = Math.max(1, Date.now() - startedAtMs);
    const chargedCountOnInvalid = hooks.isAtHome ? alreadyCharged.size : 0;
    const telemetry = computeRunEconomicsTelemetry({
      billableCount: 0,
      chargedEventCount: chargedCountOnInvalid,
      durationMs,
      requestCount: 1,
      unitPriceUsdc: hooks.unitPriceUsdc,
      actorStartFeeUsdc: hooks.actorStartFeeUsdc,
      pricingDeterministic: hooks.pricingDeterministic,
    });
    const failPayload = {
      ok: false,
      status: batchRes.status || 'INVALID_INPUT',
      errorCode: batchRes.errorCode || 'INVALID_INPUT',
      reason: batchRes.reason || 'Invalid domain enrichment input',
      billingMode,
      extractedCount: 0,
      deliveredCount: 0,
      billableCount: 0,
      chargedEventCount: chargedCountOnInvalid,
      items: [],
      pagination: {
        offset: 0,
        limit: 5,
        totalDomainsCount: 0,
        hasMore: false,
        nextPageToken: null,
        nextCursor: null,
        paginationStatus: 'ERROR',
      },
      telemetry,
    };
    await hooks.saveOutput(failPayload);
    return failPayload;
  }

  const extractedItems = Array.isArray(batchRes.items) ? batchRes.items : [];
  let deliveredItems = [];

  const isItemBillable = (item) => {
    if (!item || item.emptyResult === true) return false;
    if (item.dataSource === 'SAMPLE_FIXTURE_DIRECTORY') {
      return options?.allowSampleBillingInTest === true;
    }
    return item.billable !== false;
  };

  if (!hooks.isAtHome) {
    deliveredItems = extractedItems;
    if (deliveredItems.length > 0) {
      await hooks.pushData(deliveredItems);
    }
  } else if (extractedItems.length > 0) {
    const billableExtracted = extractedItems.filter(isItemBillable);
    const unchargedBillableItems = billableExtracted.filter(
      (item) => !alreadyCharged.has(item.profileId)
    );
    const chunkSize = Math.max(1, Number(ACTOR_PRICING_CONTRACT.chunkSize) || 25);

    for (let offset = 0; offset < unchargedBillableItems.length; offset += chunkSize) {
      const chunk = unchargedBillableItems.slice(offset, offset + chunkSize);
      const chunkIds = chunk.map((item) => item.profileId);
      const idempotencyKey = computeChunkIdempotencyKey(hooks.runId, chunkIds);

      // Phase 1 (PENDING -> IN_FLIGHT): Persist staged items & inFlightIds BEFORE calling chargeEvent
      for (const item of chunk) {
        stagedItemsById[item.profileId] = item;
      }
      inFlightSet = new Set(chunkIds);
      inFlightIdempotencyKey = idempotencyKey;
      await persistCheckpoint();

      let chargeRes;
      try {
        chargeRes = await hooks.chargeEvent({
          eventName: ACTOR_PRICING_CONTRACT.eventName,
          count: chunk.length,
          idempotencyKey,
        });
      } catch (chargeErr) {
        for (const id of chunkIds) {
          unknownOutcomeSet.add(id);
        }
        inFlightSet = new Set();
        inFlightIdempotencyKey = null;
        await persistCheckpoint();

        const firstUnchargedIdx = extractedItems.findIndex(
          (item) => isItemBillable(item) && !alreadyCharged.has(item.profileId)
        );
        const deliveredPrefix =
          firstUnchargedIdx === -1 ? extractedItems : extractedItems.slice(0, firstUnchargedIdx);
        const durationMs = Math.max(1, Date.now() - startedAtMs);
        const telemetry = computeRunEconomicsTelemetry({
          billableCount: deliveredPrefix.filter(isItemBillable).length,
          chargedEventCount: alreadyCharged.size,
          durationMs,
          requestCount: Math.max(1, extractedItems.length),
          unitPriceUsdc: hooks.unitPriceUsdc,
          actorStartFeeUsdc: hooks.actorStartFeeUsdc,
          pricingDeterministic: hooks.pricingDeterministic,
        });
        const unknownChargePayload = {
          ok: false,
          status: 'UNKNOWN_CHARGE_OUTCOME',
          errorCode: 'CHARGE_API_ERROR',
          reason: `Apify chargeEvent failed before dataset delivery: ${chargeErr?.message || chargeErr}`,
          billingMode,
          extractedCount: extractedItems.length,
          deliveredCount: deliveredPrefix.length,
          billableCount: deliveredPrefix.filter(isItemBillable).length,
          chargedEventCount: alreadyCharged.size,
          items: deliveredPrefix,
          pagination: (() => {
            const rewound = computeRewoundCursorForDeliveredPrefix(
              batchRes.cursorResumeContext,
              deliveredPrefix.length,
              batchRes.pagination.nextPageToken
            );
            return {
              ...batchRes.pagination,
              nextPageToken: rewound,
              nextCursor: rewound,
              hasMore: true,
              paginationStatus: 'UNKNOWN_CHARGE_OUTCOME',
            };
          })(),
          telemetry,
        };
        await hooks.saveOutput(unknownChargePayload);
        return unknownChargePayload;
      }

      // Phase 2 (IN_FLIGHT -> CHARGED): Record charged subset and clear inFlightIds before pushData
      const chunkChargedCount = Math.max(
        0,
        Math.min(chunk.length, Number(chargeRes?.chargedCount) || 0)
      );
      const newlyChargedSlice = chunk.slice(0, chunkChargedCount);
      for (const item of newlyChargedSlice) {
        alreadyCharged.add(item.profileId);
      }
      for (const item of chunk.slice(chunkChargedCount)) {
        if (!alreadyCharged.has(item.profileId)) {
          delete stagedItemsById[item.profileId];
        }
      }
      inFlightSet = new Set();
      inFlightIdempotencyKey = null;
      await persistCheckpoint();

      if (chargeRes?.eventChargeLimitReached) {
        chargeLimitReached = true;
        break;
      }
      if (chunkChargedCount < chunk.length) {
        partialBillingFailure = true;
        for (const item of chunk.slice(chunkChargedCount)) {
          unknownOutcomeSet.add(item.profileId);
        }
        await persistCheckpoint();
        break;
      }
    }

    // Phase 3 (CHARGED -> DELIVERED): Push charged prefix to Dataset and purge stagedItemsById
    const firstUnchargedBillableIdx = extractedItems.findIndex(
      (item) => isItemBillable(item) && !alreadyCharged.has(item.profileId)
    );
    deliveredItems =
      firstUnchargedBillableIdx === -1
        ? extractedItems
        : extractedItems.slice(0, firstUnchargedBillableIdx);
    const toPush = deliveredItems.filter((item) => !alreadyDelivered.has(item.profileId));
    if (toPush.length > 0) {
      await hooks.pushData(toPush);
      for (const item of toPush) {
        alreadyDelivered.add(item.profileId);
        delete stagedItemsById[item.profileId];
      }
    }
    for (const id of alreadyDelivered) {
      delete stagedItemsById[id];
    }
    await persistCheckpoint();
  }

  const finalPagination = { ...batchRes.pagination };
  if (
    (deliveredItems.length < extractedItems.length ||
      (chargeLimitReached && extractedItems.length === 0 && finalPagination.hasMore)) &&
    batchRes.cursorResumeContext
  ) {
    finalPagination.nextPageToken = computeRewoundCursorForDeliveredPrefix(
      batchRes.cursorResumeContext,
      deliveredItems.length,
      batchRes.pagination.nextPageToken
    );
    finalPagination.nextCursor = finalPagination.nextPageToken;
    finalPagination.hasMore = Boolean(finalPagination.nextPageToken);
    finalPagination.paginationStatus =
      deliveredItems.length === 0 ? 'PARTIAL_CHARGE_LIMIT_HALTED' : 'PARTIAL_CHARGE_LIMIT_REWOUND';
  }

  const chargedEventCount = hooks.isAtHome ? alreadyCharged.size : 0;
  const durationMs = Math.max(1, Date.now() - startedAtMs);
  const billableCount = deliveredItems.filter(isItemBillable).length;
  const telemetry = computeRunEconomicsTelemetry({
    billableCount,
    chargedEventCount,
    durationMs,
    requestCount: Math.max(1, extractedItems.length),
    unitPriceUsdc: hooks.unitPriceUsdc,
    actorStartFeeUsdc: hooks.actorStartFeeUsdc,
    pricingDeterministic: hooks.pricingDeterministic,
  });

  const status = partialBillingFailure
    ? 'PARTIAL_BILLING_HALT'
    : chargeLimitReached
      ? 'CHARGE_LIMIT_REACHED'
      : billableCount > 0 || deliveredItems.some((i) => !i.emptyResult)
        ? 'SUCCEEDED'
        : 'EMPTY_RESULT';
  const ok = !partialBillingFailure;
  const errorCode = partialBillingFailure ? 'PARTIAL_BILLING_HALT' : null;
  const reason =
    chargeLimitReached && extractedItems.length === 0
      ? 'Actor maximum total charge budget reached before domain crawl; resume via nextPageToken.'
      : batchRes.reason;

  const resultPayload = {
    ok,
    status,
    ...(errorCode ? { errorCode } : {}),
    reason,
    billingMode,
    extractedCount: extractedItems.length,
    deliveredCount: deliveredItems.length,
    billableCount,
    chargedEventCount,
    items: deliveredItems,
    pagination: finalPagination,
    telemetry,
  };

  await hooks.saveOutput({
    ok,
    status,
    ...(errorCode ? { errorCode } : {}),
    reason,
    billingMode,
    extractedCount: extractedItems.length,
    deliveredCount: deliveredItems.length,
    billableCount,
    chargedEventCount,
    pagination: finalPagination,
    telemetry,
  });

  return resultPayload;
}
