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
} = {}) {
  const safeCount = Math.max(0, Math.floor(Number(billableCount) || 0));
  const safeChargedCount = Math.max(0, Math.floor(Number(chargedEventCount) || 0));
  const safeDurationMs = Math.max(1, Number(durationMs) || 1);
  const safeMemoryMb = Math.min(1024, Math.max(64, Number(memoryMb) || 256));
  const safeRequests = Math.max(1, Math.floor(Number(requestCount) || 1));
  const resolvedUnitPriceUsdc =
    Number.isFinite(Number(unitPriceUsdc)) && Number(unitPriceUsdc) > 0
      ? Number(unitPriceUsdc)
      : ACTOR_PRICING_CONTRACT.priceUsdc;
  const resolvedNetPriceUsdc = Number(
    (resolvedUnitPriceUsdc * (1 - ACTOR_PRICING_CONTRACT.platformFeeRate)).toFixed(6)
  );
  const resolvedStartFeeUsdc =
    Number.isFinite(Number(actorStartFeeUsdc)) && Number(actorStartFeeUsdc) >= 0
      ? Number(actorStartFeeUsdc)
      : ACTOR_PRICING_CONTRACT.actorStartFeeUsdc;

  const computeHours = safeDurationMs / 3600000;
  const computeCostUsdc =
    (safeMemoryMb / 1024) * computeHours * ACTOR_PRICING_CONTRACT.computeRatePerGbHourUsdc;
  const networkOverheadUsdc = safeRequests * 0.0000002;
  const totalRunCostUsdc = Number((computeCostUsdc + networkOverheadUsdc).toFixed(8));
  const configuredFloorMultiplier = Number(
    (resolvedNetPriceUsdc / ACTOR_PRICING_CONTRACT.costCeilingUsdc).toFixed(2)
  );

  if (safeCount === 0) {
    return {
      economicsStatus: 'NO_BILLABLE_EVENTS',
      billableCount: 0,
      chargedEventCount: safeChargedCount,
      durationMs: safeDurationMs,
      memoryMb: safeMemoryMb,
      requestCount: safeRequests,
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
  const grossRevenueUsdc = Number((safeCount * resolvedUnitPriceUsdc).toFixed(6));
  const netRevenueUsdc = Number((safeCount * resolvedNetPriceUsdc).toFixed(6));
  const effectiveMarginMultiplier =
    actualCostPerEventUsdc > 0
      ? Number((resolvedNetPriceUsdc / actualCostPerEventUsdc).toFixed(2))
      : configuredFloorMultiplier;
  const withinCostCeiling = actualCostPerEventUsdc <= ACTOR_PRICING_CONTRACT.costCeilingUsdc;
  const marginPositive =
    withinCostCeiling && configuredFloorMultiplier >= ACTOR_PRICING_CONTRACT.minMarginMultiplier;

  return {
    economicsStatus: marginPositive ? 'PROFITABLE' : 'COST_CEILING_EXCEEDED',
    billableCount: safeCount,
    chargedEventCount: safeChargedCount,
    durationMs: safeDurationMs,
    memoryMb: safeMemoryMb,
    requestCount: safeRequests,
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
  const applyAtHomeSchemaDefaults = (parsedInput) => {
    if (
      isAtHome &&
      parsedInput &&
      typeof parsedInput === 'object' &&
      !Array.isArray(parsedInput) &&
      !Object.prototype.hasOwnProperty.call(parsedInput, 'query') &&
      !Object.prototype.hasOwnProperty.call(parsedInput, 'domains') &&
      !Object.prototype.hasOwnProperty.call(parsedInput, 'domain') &&
      !Object.prototype.hasOwnProperty.call(parsedInput, 'pageToken')
    ) {
      return {
        query: 'stripe.com, linear.app, cloudflare.com, shopify.com, github.com',
        maxResults: 5,
        ...parsedInput,
      };
    }
    return parsedInput;
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

  return {
    runId,
    isAtHome,
    async loadCheckpoint() {
      return (await getKvsRecord(ACTOR_PRICING_CONTRACT.checkpointKey)) || {
        chargedIds: [],
        deliveredIds: [],
      };
    },
    async saveCheckpoint(state) {
      await putKvsRecord(ACTOR_PRICING_CONTRACT.checkpointKey, state);
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
      const requested = Math.max(0, Math.floor(Number(count) || 0));
      if (requested === 0 || !isAtHome) {
        return { chargedCount: 0, eventChargeLimitReached: false };
      }
      const apiBase = resolveSafeApifyApiBaseUrl(
        env?.APIFY_API_BASE_URL,
        env?.APIFY_API_PUBLIC_BASE_URL
      );
      const url = `${apiBase}/v2/actor-runs/${encodeURIComponent(runId)}/charge`;
      const safeIdemKey = String(idempotencyKey || `${runId}_${Date.now()}`);
      const maxAttempts = 3;
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
            body: JSON.stringify({ eventName, count: requested }),
            signal: controller.signal,
          });
          if (res.status === 402) {
            return { chargedCount: 0, eventChargeLimitReached: true };
          }
          if (res.status === 429 && attempt < maxAttempts) {
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
              ? Math.min(requested, rawCharged)
              : requested;
          const limitReached = Boolean(
            body?.data?.eventChargeLimitReached || body?.eventChargeLimitReached
          );
          return { chargedCount, eventChargeLimitReached: limitReached };
        } finally {
          clearTimeout(timer);
        }
      }
      throw new Error('Apify charge API rate limit exhausted after 3 attempts');
    },
    async saveOutput(outputRecord) {
      await putKvsRecord('OUTPUT', outputRecord);
    },
  };
}

export async function runDomainContactEnricherActor(input = {}, options = {}) {
  const startedAtMs = Date.now();
  const hooks = options?.platformHooks || createApifyPlatformHooks(options?.env || process.env, options?.fetchImpl);
  const billingMode = hooks.isAtHome ? 'APIFY_PAY_PER_EVENT' : 'LOCAL_UNBILLED';
  const billingReserveMs = hooks.isAtHome ? 2500 : 0;
  const deadlineAtMs =
    Number.isFinite(Number(options?.deadlineAtMs)) && Number(options.deadlineAtMs) > 0
      ? Number(options.deadlineAtMs)
      : startedAtMs + Math.max(2000, DEFAULT_RUN_DEADLINE_MS - billingReserveMs);

  const batchRes = await resolveB2bDomainContactsBatch(input, {
    ...options,
    deadlineAtMs,
  });
  if (!batchRes.ok) {
    const durationMs = Math.max(1, Date.now() - startedAtMs);
    const telemetry = computeRunEconomicsTelemetry({
      billableCount: 0,
      chargedEventCount: 0,
      durationMs,
      requestCount: 1,
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
      chargedEventCount: 0,
      items: [],
      pagination: {
        offset: 0,
        limit: 5,
        totalDomainsCount: 0,
        hasMore: false,
        nextPageToken: null,
        paginationStatus: 'ERROR',
      },
      telemetry,
    };
    await hooks.saveOutput(failPayload);
    return failPayload;
  }

  const extractedItems = Array.isArray(batchRes.items) ? batchRes.items : [];
  const checkpoint = await hooks.loadCheckpoint();
  const alreadyDelivered = new Set(Array.isArray(checkpoint?.deliveredIds) ? checkpoint.deliveredIds : []);
  const alreadyCharged = new Set(Array.isArray(checkpoint?.chargedIds) ? checkpoint.chargedIds : []);

  let deliveredItems = [];
  let chargedEventCount = 0;
  let chargeLimitReached = false;
  let partialBillingFailure = false;

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
    const unchargedBillableItems = billableExtracted.filter((item) => !alreadyCharged.has(item.profileId));
    if (unchargedBillableItems.length > 0) {
      const idempotencyKey = computeChunkIdempotencyKey(
        hooks.runId,
        unchargedBillableItems.map((i) => i.profileId)
      );
      let chargeRes;
      try {
        chargeRes = await hooks.chargeEvent({
          eventName: ACTOR_PRICING_CONTRACT.eventName,
          count: unchargedBillableItems.length,
          idempotencyKey,
        });
      } catch (chargeErr) {
        const durationMs = Math.max(1, Date.now() - startedAtMs);
        const telemetry = computeRunEconomicsTelemetry({
          billableCount: 0,
          chargedEventCount: 0,
          durationMs,
          requestCount: Math.max(1, extractedItems.length),
        });
        const unknownChargePayload = {
          ok: false,
          status: 'UNKNOWN_CHARGE_OUTCOME',
          errorCode: 'CHARGE_API_ERROR',
          reason: `Apify chargeEvent failed before dataset delivery: ${chargeErr?.message || chargeErr}`,
          billingMode,
          extractedCount: extractedItems.length,
          deliveredCount: 0,
          billableCount: 0,
          chargedEventCount: 0,
          items: [],
          pagination: {
            ...batchRes.pagination,
            nextPageToken: computeRewoundCursorForDeliveredPrefix(
              batchRes.cursorResumeContext,
              0,
              batchRes.pagination.nextPageToken
            ),
            hasMore: true,
            paginationStatus: 'UNKNOWN_CHARGE_OUTCOME',
          },
          telemetry,
        };
        await hooks.saveOutput(unknownChargePayload);
        return unknownChargePayload;
      }
      chargedEventCount = chargeRes.chargedCount;
      const newlyChargedSlice = unchargedBillableItems.slice(0, chargedEventCount);
      for (const item of newlyChargedSlice) {
        alreadyCharged.add(item.profileId);
      }
      if (chargeRes.eventChargeLimitReached) {
        chargeLimitReached = true;
      } else if (chargedEventCount < unchargedBillableItems.length) {
        partialBillingFailure = true;
      }
      // Persist chargedIds immediately before pushData so dataset failures cannot cause double-billing on retry
      await hooks.saveCheckpoint({
        chargedIds: Array.from(alreadyCharged),
        deliveredIds: Array.from(alreadyDelivered),
      });
    }

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
      }
    }
    await hooks.saveCheckpoint({
      chargedIds: Array.from(alreadyCharged),
      deliveredIds: Array.from(alreadyDelivered),
    });
  }

  const finalPagination = { ...batchRes.pagination };
  if (deliveredItems.length < extractedItems.length && batchRes.cursorResumeContext) {
    finalPagination.nextPageToken = computeRewoundCursorForDeliveredPrefix(
      batchRes.cursorResumeContext,
      deliveredItems.length,
      batchRes.pagination.nextPageToken
    );
    finalPagination.hasMore = Boolean(finalPagination.nextPageToken);
    finalPagination.paginationStatus =
      deliveredItems.length === 0 ? 'PARTIAL_CHARGE_LIMIT_HALTED' : 'PARTIAL_CHARGE_LIMIT_REWOUND';
  }

  const durationMs = Math.max(1, Date.now() - startedAtMs);
  const billableCount = deliveredItems.filter(isItemBillable).length;
  const telemetry = computeRunEconomicsTelemetry({
    billableCount,
    chargedEventCount,
    durationMs,
    requestCount: Math.max(1, extractedItems.length),
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

  const resultPayload = {
    ok,
    status,
    ...(errorCode ? { errorCode } : {}),
    reason: batchRes.reason,
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
    reason: batchRes.reason,
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
