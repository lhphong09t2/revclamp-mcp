/**
 * RevClamp Enterprise — Standalone Open-Source Local MCP Server Engine
 *
 * Self-contained, zero-dependency Node.js implementation of all 9 deterministic
 * B2B FinOps, Stripe 2025-03-31.basil, Visa CE 3.0, EU/XI VIES VAT format,
 * Shopify Plus B2B Net-15/30/60, Webhook HMAC-SHA256, 72h Replay FSM, and
 * 0% Take-Rate ROI tools.
 *
 * Open-Core Execution Boundary:
 *   - Local Mode (Default, MIT, Zero Network / Zero API Key): Executes deterministic
 *     cryptographic, accounting, state-machine, and format verification strictly on
 *     caller-supplied payloads. Never fabricates live consultation IDs or card-network
 *     dispute evidence unless `demo: true` is explicitly passed (`sample: true`).
 *   - Cloud Workspace Mode (`REVCLAMP_API_KEY` on https://api.revclamp.com/api/mcp):
 *     Unlocks the 90-day SQLite WAL usage ledger, 24/7 autonomous Stripe dispute &
 *     entitlement webhook outbox, and live European Commission VIES consultation IDs.
 */

import crypto from "node:crypto";
import { isDeepStrictEqual } from "node:util";

export const MCP_PROTOCOL_VERSION = "2024-11-05";
export const SUPPORTED_MCP_PROTOCOL_VERSIONS = Object.freeze([
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
]);

const LOCAL_LIVE_SECRET_GUARD_RE =
  /(?:[sr]k_live_[A-Za-z0-9_-]{4,}|whsec_live_[A-Za-z0-9_-]{4,}|whsec_(?!test_|synth_|sandbox_|demo_|sample_|mock_|example_|fake_|dummy_)[A-Za-z0-9_-]{10,}|shpss_live_[A-Za-z0-9_-]{4,}|shpss_[0-9a-fA-F]{16,}|shp(?:at|ua|ca|pa)_[A-Za-z0-9_-]{8,}|lsq_[A-Za-z0-9_-]{4,}|r[gc]_live_[A-Za-z0-9_-]{4,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/i;

const LOCAL_MCP_TOOL_ARG_ALIAS_GROUPS = Object.freeze({
  revclamp_verify_webhook_signature: Object.freeze([
    Object.freeze({ canonical: "provider", aliases: Object.freeze(["webhookProvider"]) }),
    Object.freeze({ canonical: "rawPayload", aliases: Object.freeze(["payload", "body"]) }),
    Object.freeze({
      canonical: "signatureHeader",
      aliases: Object.freeze(["signature", "header", "stripeSignature", "shopifyHmac"]),
    }),
    Object.freeze({
      canonical: "secret",
      aliases: Object.freeze(["webhookSecret", "signingSecret"]),
    }),
    Object.freeze({ canonical: "timestampSec", aliases: Object.freeze(["timestamp"]) }),
    Object.freeze({
      canonical: "toleranceSec",
      aliases: Object.freeze(["toleranceSeconds", "tolerance"]),
    }),
  ]),
  revclamp_simulate_webhook_replay: Object.freeze([
    Object.freeze({ canonical: "scenarioPreset", aliases: Object.freeze(["preset"]) }),
    Object.freeze({
      canonical: "events",
      aliases: Object.freeze(["webhookEvents", "eventSequence"]),
    }),
    Object.freeze({
      canonical: "idempotencyWindowSec",
      aliases: Object.freeze(["windowSec", "dedupWindowSec"]),
    }),
  ]),
});

export function normalizeMcpToolArgs(toolName, rawArgs) {
  if (rawArgs === null || typeof rawArgs !== "object" || Array.isArray(rawArgs)) {
    return {
      ok: false,
      error: "INVALID_ARGUMENTS_OBJECT",
      message: "Invalid params: arguments must be a JSON object",
    };
  }
  const normalized = { ...rawArgs };
  const groups = Object.hasOwn(LOCAL_MCP_TOOL_ARG_ALIAS_GROUPS, toolName)
    ? LOCAL_MCP_TOOL_ARG_ALIAS_GROUPS[toolName]
    : null;
  if (!groups) {
    return { ok: true, args: normalized };
  }
  for (const group of groups) {
    const allKeys = [group.canonical, ...group.aliases];
    const presentKeys = allKeys.filter(
      (k) => Object.hasOwn(rawArgs, k) && rawArgs[k] !== undefined
    );
    if (presentKeys.length > 1) {
      const firstKey = presentKeys[0];
      const firstVal = rawArgs[firstKey];
      for (let i = 1; i < presentKeys.length; i += 1) {
        const otherKey = presentKeys[i];
        const otherVal = rawArgs[otherKey];
        if (!Object.is(firstVal, otherVal) && !isDeepStrictEqual(firstVal, otherVal)) {
          return {
            ok: false,
            error: "CONFLICTING_PARAMETER_ALIASES",
            canonicalKey: group.canonical,
            conflictKey: otherKey,
            message: `Invalid params: conflicting parameter aliases for '${group.canonical}' ('${firstKey}' vs '${otherKey}')`,
          };
        }
      }
    }
    if (presentKeys.length >= 1) {
      normalized[group.canonical] = rawArgs[presentKeys[0]];
      for (const aliasKey of group.aliases) {
        delete normalized[aliasKey];
      }
    }
  }
  return { ok: true, args: normalized };
}

export function scanLocalMcpPayloadForSecrets(node, depth = 0) {
  if (depth > 8) {
    return { ok: false, reason: "MCP_ARGUMENT_DEPTH_EXCEEDED" };
  }
  if (node === null || node === undefined) {
    return { ok: true };
  }
  if (typeof node === "string") {
    if (LOCAL_LIVE_SECRET_GUARD_RE.test(node)) {
      return { ok: false, reason: "LIVE_SECRET_FORBIDDEN_IN_SANDBOX" };
    }
    return { ok: true };
  }
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i += 1) {
      const sub = scanLocalMcpPayloadForSecrets(node[i], depth + 1);
      if (!sub.ok) return sub;
    }
    return { ok: true };
  }
  if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (LOCAL_LIVE_SECRET_GUARD_RE.test(k)) {
        return { ok: false, reason: "LIVE_SECRET_FORBIDDEN_IN_SANDBOX" };
      }
      const sub = scanLocalMcpPayloadForSecrets(v, depth + 1);
      if (!sub.ok) return sub;
    }
    return { ok: true };
  }
  return { ok: true };
}

export const LOCAL_MCP_RESOURCES = Object.freeze([
  Object.freeze({
    uri: "revclamp://docs/open-core-capabilities",
    name: "RevClamp Open-Core vs Hosted Cloud Capabilities",
    description:
      "Reference summary of the 9 local deterministic MCP tools vs. hosted REVCLAMP_API_KEY capabilities (90-day SQLite WAL ledger, 24/7 Stripe webhook outbox, and live EU VIES consultation IDs).",
    mimeType: "application/json",
  }),
]);

export const LOCAL_MCP_PROMPTS = Object.freeze([
  Object.freeze({
    name: "audit_stripe_and_vat_compliance",
    description:
      "Guided workflow for auditing Stripe 2025-03-31.basil ghost usage, Visa CE 3.0 dispute evidence, and EU/XI B2B VAT IDs.",
    arguments: [
      {
        name: "sellerCountry",
        description: "Two-letter EU/XI seller country code (e.g. DE, FR, NL, XI).",
        required: false,
      },
    ],
  }),
]);

export const TIER_EVENT_CAPS = Object.freeze({
  free: 5_000,
  starter_19: 100_000,
  growth_59: 1_000_000,
  scale_199: 5_000_000,
});

const PLAN_CATALOG = Object.freeze([
  Object.freeze({ tier: "free", name: "Free Sandbox", priceUsd: 0, monthlyCap: 5_000 }),
  Object.freeze({ tier: "starter_19", name: "Starter", priceUsd: 19, monthlyCap: 100_000 }),
  Object.freeze({ tier: "growth_59", name: "Growth", priceUsd: 59, monthlyCap: 1_000_000 }),
  Object.freeze({ tier: "scale_199", name: "Scale", priceUsd: 199, monthlyCap: 5_000_000 }),
]);

const EU_VIES_FORMAT_RULES = Object.freeze({
  AT: /^ATU\d{8}$/,
  BE: /^BE[01]\d{9}$/,
  BG: /^BG\d{9,10}$/,
  CY: /^CY\d{8}[A-Z]$/,
  CZ: /^CZ\d{8,10}$/,
  DE: /^DE\d{9}$/,
  DK: /^DK\d{8}$/,
  EE: /^EE\d{9}$/,
  EL: /^EL\d{9}$/,
  ES: /^ES[A-Z0-9]\d{7}[A-Z0-9]$/,
  FI: /^FI\d{8}$/,
  FR: /^FR[A-HJ-NP-Z0-9]{2}\d{9}$/,
  HR: /^HR\d{11}$/,
  HU: /^HU\d{8}$/,
  IE: /^IE(?:\d{7}[A-W][A-I]?|\d[A-Z+*]\d{5}[A-W])$/,
  IT: /^IT\d{11}$/,
  LT: /^LT(?:\d{9}|\d{12})$/,
  LU: /^LU\d{8}$/,
  LV: /^LV\d{11}$/,
  MT: /^MT\d{8}$/,
  NL: /^NL\d{9}B\d{2}$/,
  PL: /^PL\d{10}$/,
  PT: /^PT\d{9}$/,
  RO: /^RO[1-9]\d{1,9}$/,
  SE: /^SE\d{12}$/,
  SI: /^SI\d{8}$/,
  SK: /^SK\d{10}$/,
  XI: /^XI(?:\d{9}|\d{12}|(?:GD|HA)\d{3})$/,
});

const REVCLAMP_START_MARKER = "--- BEGIN REVCLAMP CE3 EVIDENCE ---";
const REVCLAMP_END_MARKER = "--- END REVCLAMP CE3 EVIDENCE ---";
const REVCLAMP_BRACKET_START_MARKER = "[RevClamp Verified Product Usage Log]";
const REVCLAMP_BRACKET_END_MARKER = "[/RevClamp Verified Product Usage Log]";
const PRODUCTION_EMPTY_BLOCK_WRAPPER_CHARS =
  REVCLAMP_BRACKET_START_MARKER.length + 1 + REVCLAMP_BRACKET_END_MARKER.length;
const MAX_ACCESS_ACTIVITY_LOG_CHARS = 18_000;
const CE3_MIN_WINDOW_SEC = 120 * 86_400;
const CE3_MAX_WINDOW_SEC = 365 * 86_400;

export const LOCAL_MCP_TOOLS = Object.freeze([
  {
    name: "revclamp_audit_revenue_leakage",
    description:
      "Runs a deterministic 90-day B2B revenue leakage and Visa CE 3.0 readiness audit across caller-supplied Stripe subscriptions (2025-03-31.basil item-level periods), usage events, and disputes.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        customers: {
          type: "array",
          description: "Array of Stripe customer objects with subscriptions ({ id, subscriptions: { data, has_more } }).",
        },
        usageEvents: {
          type: "array",
          description: "Array of metered API/SaaS usage events ({ customer_id, event_name, occurred_at }).",
        },
        disputes: {
          type: "array",
          description: "Optional array of Stripe dispute objects.",
        },
        dunningGracePeriodDays: {
          type: "integer",
          minimum: 0,
          maximum: 14,
          default: 3,
        },
        costPerEventCents: {
          type: "integer",
          minimum: 1,
          maximum: 100000,
          default: 142,
        },
        demo: {
          type: "boolean",
          description: "Set true only to generate a labeled sample preview when customers/usageEvents are omitted.",
          default: false,
        },
      },
    },
  },
  {
    name: "revclamp_evaluate_ghost_usage",
    description:
      "Evaluates whether a metered API/SaaS usage event belongs to an entitled customer or represents post-cancellation / post-grace ghost usage under Stripe 2025-03-31.basil.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["subscriptions"],
      properties: {
        customerId: {
          type: "string",
          description:
            "Optional Stripe customer identifier to evaluate (e.g. 'cus_9s6XKzkNRiz8i3', max 64 chars).",
        },
        subscriptions: {
          description:
            "Stripe subscriptions list envelope ({ data: [...], has_more: false }) or raw array of subscription objects.",
        },
        usageEvent: {
          type: "object",
          description: "Optional metered usage event with customer_id, event_name, occurred_at (or occurred_at_sec).",
        },
        subscriptionsHasMore: {
          type: "boolean",
          description:
            "Pagination completeness flag (must be false when passing a raw subscriptions array).",
        },
        dunningGracePeriodDays: {
          type: "integer",
          minimum: 0,
          maximum: 14,
          default: 3,
        },
        usageTimestampSec: {
          type: "integer",
          minimum: 1,
          description: "Optional Unix epoch timestamp in integer seconds when the usage event occurred.",
        },
        occurredAtSec: {
          type: "integer",
          minimum: 1,
          description: "Optional alias for usageTimestampSec.",
        },
        demo: {
          type: "boolean",
          default: false,
        },
      },
    },
  },
  {
    name: "revclamp_stage_stripe_dispute_ce3",
    description:
      "Evaluates Visa Compelling Evidence 3.0 (CE 3.0) 120d-365d historical footprint overlap (IP / device_id) and builds a non-destructive access_activity_log draft (<= 18,000 UTF-16 code units, submit: false).",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        disputeId: { type: "string" },
        customerId: { type: "string" },
        disputeReason: {
          type: "string",
          enum: [
            "fraudulent",
            "unrecognized",
            "subscription_canceled",
            "product_unacceptable",
            "general",
          ],
          default: "fraudulent",
        },
        existingAccessActivityLog: { type: "string" },
        existingUncategorizedText: { type: "string" },
        disputedTransaction: { type: "object" },
        priorTransactions: { type: "array" },
        usageEvents: { type: "array" },
        demo: {
          type: "boolean",
          description: "Set true only to generate a labeled sample preview when usageEvents is omitted.",
          default: false,
        },
      },
    },
  },
  {
    name: "revclamp_validate_eu_vat_vies",
    description:
      "Normalizes 27 EU member states + Northern Ireland (XI) B2B VAT IDs (auto-converting Greece GR -> EL) and checks cross-border reverse-charge format eligibility locally (or simulates VIES states when demo: true).",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["buyerVatId"],
      properties: {
        sellerCountry: { type: "string", default: "DE" },
        buyerVatId: { type: "string" },
        viesMode: {
          type: "string",
          enum: [
            "FORMAT_ONLY",
            "VALID",
            "INVALID",
            "MS_UNAVAILABLE",
            "GLOBAL_MAX_CONCURRENT_REQ",
            "LIVE",
          ],
          default: "FORMAT_ONLY",
        },
        consultationNumber: { type: "string" },
        demo: {
          type: "boolean",
          description: "Required when using simulated viesMode values (VALID, INVALID, MS_UNAVAILABLE, GLOBAL_MAX_CONCURRENT_REQ) in local mode.",
          default: false,
        },
      },
    },
  },
  {
    name: "revclamp_reconcile_b2b_net_terms",
    description:
      "Reconciles Shopify Plus B2B Net-15/30/60 wholesale invoices, upfront deposits, credit notes, and rounding tolerances using integer EUR-cent double-entry accounting.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      required: ["paidAmountCents"],
      properties: {
        orderId: { type: "string" },
        totalOrderCents: { type: "integer", minimum: 1 },
        orderTotalCents: { type: "integer", minimum: 1 },
        paidAmountCents: { type: "integer", minimum: 0 },
        creditNoteCents: { type: "integer", minimum: 0, default: 0 },
        creditNotesCents: { type: "integer", minimum: 0, default: 0 },
        requiredDepositCents: { type: "integer", minimum: 0 },
        requiredDepositPercent: { type: "integer", minimum: 0, maximum: 100, default: 30 },
        paymentTermsDays: { type: "integer", enum: [15, 30, 60], default: 30 },
        daysElapsedSinceInvoice: { type: "integer", minimum: 0, maximum: 3650, default: 0 },
        toleranceCents: { type: "integer", minimum: 0, maximum: 500, default: 0 },
        demo: { type: "boolean", default: false },
      },
    },
  },
  {
    name: "revclamp_verify_webhook_signature",
    description:
      "Generates and verifies raw-UTF8 HMAC-SHA256 webhook signatures for Stripe (Stripe-Signature t=,v1=), Shopify (X-Shopify-Hmac-Sha256 base64), and RevClamp (X-RevClamp-Signature) with 300s timestamp replay protection.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        provider: { type: "string", enum: ["stripe", "shopify", "revclamp"] },
        secret: { type: "string" },
        secrets: {
          type: "array",
          maxItems: 5,
          items: { type: "string" },
        },
        rawPayload: { type: "string" },
        signatureHeader: { type: "string" },
        timestampSec: { type: "integer", minimum: 1, maximum: 9999999999 },
        toleranceSec: { type: "integer", minimum: 1, maximum: 3600, default: 300 },
        demo: { type: "boolean" },
      },
    },
  },
  {
    name: "revclamp_calculate_roi_and_plan_fit",
    description:
      "Calculates monthly and annual B2B margin savings in integer USD cents comparing 0% take-rate flat pricing against 25%-30% chargeback contingency agencies and recommends the optimal tier.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        monthlyWonDisputeUsd: { type: "number", minimum: 0, maximum: 10000000, default: 10000 },
        monthlyGhostBleedUsd: { type: "number", minimum: 0, maximum: 10000000, default: 600 },
        contingencyTakeRatePercent: { type: "number", minimum: 1, maximum: 50, default: 25 },
        monthlyUsageEvents: { type: "integer", minimum: 0, maximum: 50000000, default: 250000 },
      },
    },
  },
  {
    name: "revclamp_simulate_webhook_replay",
    description:
      "Simulates out-of-order and duplicate subscription lifecycle webhooks against a 72-hour deduplication Set and monotonic createdSec watermark vs. a naive arrival-order handler.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        scenarioPreset: {
          type: "string",
          enum: [
            "out_of_order_stale_update_after_cancel",
            "duplicate_event_id_replay_72h",
            "valid_monotonic_upgrade_sequence",
            "expired_72h_window_stale_event",
            "custom",
          ],
          default: "out_of_order_stale_update_after_cancel",
        },
        nowSec: {
          type: "integer",
          minimum: 946684800,
          maximum: 4102444800,
        },
        idempotencyWindowSec: {
          type: "integer",
          minimum: 60,
          maximum: 2592000,
          default: 259200,
        },
        events: {
          type: "array",
          items: {
            type: "object",
            properties: {
              eventId: { type: "string" },
              eventType: { type: "string" },
              createdSec: { type: "integer" },
              subscriptionStatus: { type: "string" },
              tier: { type: "string" },
              currentPeriodEndSec: { type: "integer" },
              id: { type: "string" },
              type: { type: "string" },
              created: { type: "integer" },
              status: { type: "string" },
              target_status: { type: "string" },
              arrivedAtSec: { type: "integer" },
              arrived_at_sec: { type: "integer" },
            },
            additionalProperties: false,
          },
        },
        demo: { type: "boolean" },
      },
    },
  },
  {
    name: "revclamp_lint_dispute_evidence",
    description:
      "Lints Stripe dispute evidence[access_activity_log] payloads against the 18,000 UTF-16 code unit ceiling, non-destructive RevClamp CE 3.0 block markers, merchant note preservation, 17,922/17,920-char fixed wrapper capacity threshold (SKIP_POST_PRESERVE_DRAFT), and Visa CE 3.0 two-identifier overlap.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        preset: {
          type: "string",
          enum: [
            "valid_ce3_non_destructive",
            "utf16_overflow_19k",
            "missing_device_and_overwrite_risk",
            "custom",
            "ce3_24k_truncation_trap",
            "ce3_clean_compacted_14k",
            "ce3_missing_device_binding_19k",
          ],
          default: "valid_ce3_non_destructive",
          description:
            "Scenario preset to evaluate when custom evidenceLogText / accessActivityLog is omitted (default: 'valid_ce3_non_destructive').",
        },
        existingMerchantNotes: {
          type: "string",
          maxLength: 30000,
          description:
            "Existing human AE/support notes inside evidence[access_activity_log] that must be preserved.",
        },
        evidenceLogText: {
          type: "string",
          maxLength: 30000,
          description:
            "Merged or candidate Stripe dispute evidence[access_activity_log] payload evaluated against the 18,000 UTF-16 code unit ceiling and non-destructive delimiter markers.",
        },
        accessActivityLog: {
          type: "string",
          maxLength: 30000,
          description:
            "Alias for evidenceLogText representing Stripe dispute evidence[access_activity_log] payload.",
        },
        priorMatchedCount: {
          type: "integer",
          minimum: 0,
          maximum: 100,
          description:
            "Number of prior undisputed Stripe charges (120d-365d old) with matching customer_id and IP/device fingerprint (Visa CE 3.0 requires >= 2).",
        },
        hasIpMatch: {
          type: "boolean",
          description:
            "Whether the disputed charge IPv4/IPv6 address matches the historical undisputed charges.",
        },
        hasDeviceMatch: {
          type: "boolean",
          description:
            "Whether the disputed charge device_id fingerprint matches the historical undisputed charges.",
        },
        disputedTransaction: {
          type: "object",
          description:
            "Optional disputed Stripe charge/transaction metadata evaluated against priorTransactions for Visa CE 3.0 qualification.",
        },
        priorTransactions: {
          type: "array",
          description:
            "Optional historical undisputed Stripe charges (120d-365d prior) evaluated for Visa CE 3.0 two-identifier overlap.",
        },
        demo: {
          type: "boolean",
          description:
            "Set true to lint a sample preset fixture when evidenceLogText / accessActivityLog is omitted.",
          default: false,
        },
      },
    },
  },
]);

export function validateArgsAgainstSchema(schema, args) {
  if (!schema || typeof schema !== "object") return { ok: true };
  if (args === null || typeof args !== "object" || Array.isArray(args)) {
    return { ok: false, message: "Tool arguments must be a JSON object." };
  }
  const props = schema.properties || {};
  if (schema.additionalProperties === false) {
    for (const key of Object.keys(args)) {
      if (!Object.prototype.hasOwnProperty.call(props, key)) {
        return { ok: false, message: `Unknown argument '${key}' is not allowed.` };
      }
    }
  }
  if (Array.isArray(schema.required)) {
    for (const reqKey of schema.required) {
      if (args[reqKey] === undefined || args[reqKey] === null || args[reqKey] === "") {
        return { ok: false, message: `Missing required argument '${reqKey}'.` };
      }
    }
  }
  for (const [key, val] of Object.entries(args)) {
    if (val === undefined) continue;
    const propSchema = props[key];
    if (!propSchema) continue;
    if (propSchema.type === "integer") {
      if (typeof val !== "number" || !Number.isSafeInteger(val)) {
        return { ok: false, message: `Argument '${key}' must be a safe integer.` };
      }
      if (propSchema.minimum !== undefined && val < propSchema.minimum) {
        return { ok: false, message: `Argument '${key}' must be >= ${propSchema.minimum}.` };
      }
      if (propSchema.maximum !== undefined && val > propSchema.maximum) {
        return { ok: false, message: `Argument '${key}' must be <= ${propSchema.maximum}.` };
      }
    } else if (propSchema.type === "number") {
      if (typeof val !== "number" || !Number.isFinite(val)) {
        return { ok: false, message: `Argument '${key}' must be a finite number.` };
      }
      if (propSchema.minimum !== undefined && val < propSchema.minimum) {
        return { ok: false, message: `Argument '${key}' must be >= ${propSchema.minimum}.` };
      }
      if (propSchema.maximum !== undefined && val > propSchema.maximum) {
        return { ok: false, message: `Argument '${key}' must be <= ${propSchema.maximum}.` };
      }
    } else if (propSchema.type === "string") {
      if (typeof val !== "string") {
        return { ok: false, message: `Argument '${key}' must be a string.` };
      }
      if (propSchema.maxLength !== undefined && val.length > propSchema.maxLength) {
        return {
          ok: false,
          message: `Argument '${key}' exceeds maximum length of ${propSchema.maxLength}.`,
        };
      }
    } else if (propSchema.type === "boolean") {
      if (typeof val !== "boolean") {
        return { ok: false, message: `Argument '${key}' must be a boolean.` };
      }
    } else if (propSchema.type === "array") {
      if (!Array.isArray(val)) {
        return { ok: false, message: `Argument '${key}' must be an array.` };
      }
    } else if (propSchema.type === "object") {
      if (val === null || typeof val !== "object" || Array.isArray(val)) {
        return { ok: false, message: `Argument '${key}' must be a JSON object.` };
      }
    }
    if (Array.isArray(propSchema.enum) && !propSchema.enum.includes(val)) {
      return {
        ok: false,
        message: `Argument '${key}' must be one of: ${propSchema.enum.join(", ")}.`,
      };
    }
  }
  return { ok: true };
}

function normalizeCountryCode(raw) {
  const clean = String(raw || "")
    .trim()
    .toUpperCase();
  return clean === "GR" ? "EL" : clean;
}

function normalizeVatId(rawVat) {
  const compact = String(rawVat || "")
    .toUpperCase()
    .replace(/[\s.\-/:]+/g, "");
  if (compact.length < 4) {
    return { validFormat: false, memberState: "", vatNumber: "", fullVatId: compact };
  }
  const rawPrefix = compact.slice(0, 2);
  const memberState = rawPrefix === "GR" ? "EL" : rawPrefix;
  const vatNumber = compact.slice(2);
  const fullVatId = `${memberState}${vatNumber}`;
  const rule = EU_VIES_FORMAT_RULES[memberState];
  const validFormat = Boolean(rule && rule.test(fullVatId));
  return { validFormat, memberState, vatNumber, fullVatId };
}

function sanitizeLogToken(raw, maxLen = 96) {
  if (raw === null || raw === undefined) return "";
  const cleaned = String(raw)
    .replace(/[\r\n\t|]+/g, " ")
    .replace(/-{3}\s*(?:BEGIN|END)\s+REVCLAMP\s+CE3\s+EVIDENCE\s*-{3}/gi, "[REDACTED_MARKER]")
    .replace(/\[/g, "(")
    .replace(/\]/g, ")")
    .trim();
  if (cleaned.length <= maxLen) return cleaned;
  let sliced = cleaned.slice(0, maxLen);
  const lastCode = sliced.charCodeAt(sliced.length - 1);
  if (lastCode >= 0xd800 && lastCode <= 0xdbff) {
    sliced = sliced.slice(0, -1);
  }
  return sliced;
}

function stripExistingRevClampBlock(rawNotes) {
  if (typeof rawNotes !== "string" || !rawNotes) {
    return { ok: true, hadBlock: false, prefix: "", suffix: "", text: "" };
  }
  const hasCanonical =
    rawNotes.includes(REVCLAMP_START_MARKER) || rawNotes.includes(REVCLAMP_END_MARKER);
  const hasBracket =
    rawNotes.includes(REVCLAMP_BRACKET_START_MARKER) ||
    rawNotes.includes(REVCLAMP_BRACKET_END_MARKER);
  if (!hasCanonical && !hasBracket) {
    return { ok: true, hadBlock: false, prefix: rawNotes, suffix: "", text: rawNotes.trim() };
  }
  if (hasCanonical && hasBracket) {
    return { ok: false, hadBlock: true, prefix: rawNotes, suffix: "", text: rawNotes.trim() };
  }
  const activeStart = hasCanonical ? REVCLAMP_START_MARKER : REVCLAMP_BRACKET_START_MARKER;
  const activeEnd = hasCanonical ? REVCLAMP_END_MARKER : REVCLAMP_BRACKET_END_MARKER;
  let cursor = 0;
  const prefixSegments = [];
  let trailingSegment = "";
  while (cursor < rawNotes.length) {
    const startIdx = rawNotes.indexOf(activeStart, cursor);
    if (startIdx === -1) {
      if (rawNotes.indexOf(activeEnd, cursor) !== -1) {
        return { ok: false, hadBlock: true, prefix: rawNotes, suffix: "", text: rawNotes.trim() };
      }
      trailingSegment = rawNotes.slice(cursor);
      break;
    }
    if (rawNotes.slice(cursor, startIdx).includes(activeEnd)) {
      return { ok: false, hadBlock: true, prefix: rawNotes, suffix: "", text: rawNotes.trim() };
    }
    const contentStart = startIdx + activeStart.length;
    const endIdx = rawNotes.indexOf(activeEnd, contentStart);
    if (endIdx === -1) {
      return { ok: false, hadBlock: true, prefix: rawNotes, suffix: "", text: rawNotes.trim() };
    }
    const nextStartIdx = rawNotes.indexOf(activeStart, contentStart);
    if (nextStartIdx !== -1 && nextStartIdx < endIdx) {
      return { ok: false, hadBlock: true, prefix: rawNotes, suffix: "", text: rawNotes.trim() };
    }
    const beforeSegment = rawNotes.slice(cursor, startIdx).replace(/\n{1,2}$/, "");
    if (beforeSegment.length > 0) {
      prefixSegments.push(beforeSegment);
    }
    cursor = endIdx + activeEnd.length;
    if (rawNotes.slice(cursor, cursor + 2) === "\n\n") {
      cursor += 2;
    } else if (rawNotes[cursor] === "\n") {
      cursor += 1;
    }
  }
  const prefix = prefixSegments.join("\n");
  const suffix = trailingSegment;
  const keptTrimmed = [prefix.trim(), suffix.trim()].filter(Boolean);
  return {
    ok: true,
    hadBlock: true,
    prefix,
    suffix,
    text: keptTrimmed.join("\n\n").trim(),
  };
}

function isValidUnixSec(val) {
  return Number.isSafeInteger(val) && val >= 1_000_000_000 && val <= 10_000_000_000;
}

function parseEventTimestampSec(ev) {
  for (const numCandidate of [
    ev?.occurred_at_sec,
    ev?.occurredAtSec,
    ev?.timestampSec,
    ev?.usageTimestampSec,
    ev?.occurred_at,
    ev?.created,
  ]) {
    if (isValidUnixSec(numCandidate)) {
      return numCandidate;
    }
  }
  for (const strCandidate of [ev?.occurred_at, ev?.created]) {
    if (typeof strCandidate === "string" && strCandidate.trim()) {
      const ms = Date.parse(strCandidate.trim());
      if (!Number.isFinite(ms)) return null;
      const s = Math.floor(ms / 1000);
      return isValidUnixSec(s) ? s : null;
    }
  }
  return null;
}

function extractSubPeriodEndSec(sub) {
  if (sub?.items?.has_more === true) return null;
  const candidates = [];
  if (isValidUnixSec(sub?.current_period_end)) {
    candidates.push(sub.current_period_end);
  }
  if (Array.isArray(sub?.items?.data)) {
    for (const item of sub.items.data) {
      if (isValidUnixSec(item?.current_period_end)) {
        candidates.push(item.current_period_end);
      }
    }
  }
  if (candidates.length === 0) return null;
  if (isValidUnixSec(sub?.ended_at)) {
    candidates.push(sub.ended_at);
  }
  return Math.max(...candidates);
}

function extractPastDueAnchorSec(sub) {
  if (sub?.items?.has_more === true) return 0;
  if (isValidUnixSec(sub?.latest_invoice_failed_at)) return sub.latest_invoice_failed_at;
  if (isValidUnixSec(sub?.latest_invoice?.created)) return sub.latest_invoice.created;
  if (isValidUnixSec(sub?.current_period_start)) return sub.current_period_start;
  if (Array.isArray(sub?.items?.data)) {
    const starts = sub.items.data
      .map((item) => item?.current_period_start)
      .filter((v) => isValidUnixSec(v));
    if (starts.length > 0) return Math.max(...starts);
  }
  return 0;
}

function extractTerminalStatusAnchorSec(sub, graceSec = 0) {
  if (sub?.items?.has_more === true) return 0;
  if (sub?.status === "unpaid") {
    const pastDueAnchor = extractPastDueAnchorSec(sub);
    if (pastDueAnchor > 0) {
      const explicitTransition = isValidUnixSec(sub?.status_transitioned_at)
        ? sub.status_transitioned_at
        : 0;
      return Math.max(explicitTransition, pastDueAnchor + graceSec);
    }
  }
  const candidates = [
    sub?.status_transitioned_at,
    sub?.pause_collection?.started_at,
    sub?.trial_end,
    sub?.ended_at,
  ].filter((v) => isValidUnixSec(v));
  const transitionAnchor = candidates.length > 0 ? Math.max(...candidates) : 0;
  if (sub?.status === "paused") {
    const periodEndAnchor = extractSubPeriodEndSec(sub) || 0;
    return Math.max(transitionAnchor, periodEndAnchor);
  }
  return transitionAnchor;
}

const ENTITLED_SUB_STATUSES = new Set(["active", "trialing", "incomplete"]);
const DELINQUENT_OR_TERMINAL_SUB_STATUSES = new Set([
  "canceled",
  "past_due",
  "unpaid",
  "incomplete_expired",
  "paused",
]);

function normalizeEmailToken(raw) {
  if (typeof raw !== "string") return "";
  return raw.trim().toLowerCase();
}

function extractCanonicalCustomerId(obj) {
  if (!obj || typeof obj !== "object") return "";
  const raw =
    obj.customer_id ||
    obj.stripe_customer_id ||
    (typeof obj.customer === "string" ? obj.customer : obj.customer?.id) ||
    "";
  return typeof raw === "string" ? raw.trim() : "";
}

function evaluateLocalGhostUsage(subscriptionsEnv, usageEvent, dunningGracePeriodDays = 3) {
  const subsEnv = subscriptionsEnv && typeof subscriptionsEnv === "object" ? subscriptionsEnv : {};
  const subs = Array.isArray(subsEnv.data) ? subsEnv.data : null;
  if (!subs || subsEnv.has_more !== false) {
    return {
      ok: true,
      executionMode: "local_open_source_engine",
      isGhostUsage: false,
      decision: "HOLD_INCOMPLETE_PAGINATION",
      reason: "INCOMPLETE_PAGINATION_SNAPSHOT",
    };
  }
  const ev = usageEvent && typeof usageEvent === "object" ? usageEvent : {};
  const occurredAtSec = parseEventTimestampSec(ev);
  if (occurredAtSec === null) {
    return {
      ok: true,
      executionMode: "local_open_source_engine",
      isGhostUsage: false,
      decision: "HOLD_INVALID_EVENT_TIMESTAMP",
      reason: "MISSING_OR_INVALID_EVENT_TIMESTAMP",
    };
  }
  const evCustomerId = extractCanonicalCustomerId(ev);
  const evEmail = normalizeEmailToken(ev.email || ev.customer_email);
  if (!evCustomerId && !evEmail) {
    return {
      ok: true,
      executionMode: "local_open_source_engine",
      isGhostUsage: false,
      decision: "HOLD_CUSTOMER_MISMATCH",
      reason: "MISSING_EVENT_CUSTOMER_ID",
    };
  }
  if (subs.length === 0) {
    return {
      ok: true,
      executionMode: "local_open_source_engine",
      isGhostUsage: false,
      decision: "HOLD_NO_SUBSCRIPTIONS",
      reason: "NO_SUBSCRIPTIONS_IN_SNAPSHOT",
    };
  }

  for (const sub of subs) {
    if (!sub || typeof sub !== "object" || typeof sub.status !== "string") {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        isGhostUsage: false,
        decision: "HOLD_INSUFFICIENT_PERIOD_DATA",
        reason: "MALFORMED_SUBSCRIPTION_OBJECT",
      };
    }
    const subCus = extractCanonicalCustomerId(sub);
    const subEmail = normalizeEmailToken(sub.customer_email || sub.email || sub.customer?.email);
    if (evCustomerId && subCus && subCus !== evCustomerId) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        isGhostUsage: false,
        decision: "HOLD_CUSTOMER_MISMATCH",
        reason: "UNMATCHED_CUSTOMER_ID",
      };
    }
    if (evEmail && subEmail && subEmail !== evEmail) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        isGhostUsage: false,
        decision: "HOLD_CUSTOMER_MISMATCH",
        reason: "UNMATCHED_CUSTOMER_EMAIL",
      };
    }
    if (!subCus && !subEmail) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        isGhostUsage: false,
        decision: "HOLD_CUSTOMER_MISMATCH",
        reason: "UNMATCHED_CUSTOMER_ID",
      };
    }
    const st = sub.status.trim();
    if (ENTITLED_SUB_STATUSES.has(st)) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        isGhostUsage: false,
        decision: "ALLOW_ENTITLED",
        reason: "ACTIVE_SUBSCRIPTION_PRESENT",
      };
    }
    if (sub.items?.has_more === true) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        isGhostUsage: false,
        decision: "HOLD_INCOMPLETE_PAGINATION",
        reason: "INCOMPLETE_PAGINATION_SNAPSHOT",
      };
    }
    if (!DELINQUENT_OR_TERMINAL_SUB_STATUSES.has(st)) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        isGhostUsage: false,
        decision: "HOLD_UNSUPPORTED_SUBSCRIPTION_STATUS",
        reason: "UNSUPPORTED_SUBSCRIPTION_STATUS",
      };
    }
  }

  const parsedGraceDays = Number(dunningGracePeriodDays);
  const clampedGraceDays = Number.isFinite(parsedGraceDays)
    ? Math.min(14, Math.max(0, Math.floor(parsedGraceDays)))
    : 3;
  const graceSec = clampedGraceDays * 86_400;
  let maxEntitledUntilSec = 0;

  for (const sub of subs) {
    const st = sub.status.trim();
    if (st === "canceled") {
      const pEnd = extractSubPeriodEndSec(sub);
      if (pEnd === null) {
        return {
          ok: true,
          executionMode: "local_open_source_engine",
          isGhostUsage: false,
          decision: "HOLD_INSUFFICIENT_PERIOD_DATA",
          reason: "INSUFFICIENT_CANCELED_PERIOD_DATA",
        };
      }
      const entitledUntil = pEnd + 3600;
      maxEntitledUntilSec = Math.max(maxEntitledUntilSec, entitledUntil);
      if (occurredAtSec <= entitledUntil) {
        return {
          ok: true,
          executionMode: "local_open_source_engine",
          isGhostUsage: false,
          decision: "HOLD_REVOKE_UNTIL_WINDOW_EXPIRES",
          reason: "WITHIN_PAID_THROUGH_OR_GRACE_WINDOW",
          entitledUntilSec: entitledUntil,
          occurredAtSec,
        };
      }
      continue;
    }

    if (st === "past_due") {
      const failedAtSec = extractPastDueAnchorSec(sub);
      if (failedAtSec <= 0) {
        return {
          ok: true,
          executionMode: "local_open_source_engine",
          isGhostUsage: false,
          decision: "HOLD_INSUFFICIENT_PERIOD_DATA",
          reason: "INSUFFICIENT_PAST_DUE_TIMESTAMP_DATA",
        };
      }
      const entitledUntil = failedAtSec + graceSec;
      maxEntitledUntilSec = Math.max(maxEntitledUntilSec, entitledUntil);
      if (occurredAtSec <= entitledUntil) {
        return {
          ok: true,
          executionMode: "local_open_source_engine",
          isGhostUsage: false,
          decision: "HOLD_REVOKE_UNTIL_WINDOW_EXPIRES",
          reason: "WITHIN_PAID_THROUGH_OR_GRACE_WINDOW",
          entitledUntilSec: entitledUntil,
          occurredAtSec,
        };
      }
      continue;
    }

    const transitionSec = extractTerminalStatusAnchorSec(sub, graceSec);
    if (transitionSec <= 0) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        isGhostUsage: false,
        decision: "HOLD_INSUFFICIENT_PERIOD_DATA",
        reason: "INSUFFICIENT_STATUS_TRANSITION_DATA",
      };
    }
    const entitledUntil = transitionSec + 3600;
    maxEntitledUntilSec = Math.max(maxEntitledUntilSec, entitledUntil);
    if (occurredAtSec <= entitledUntil) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        isGhostUsage: false,
        decision: "HOLD_REVOKE_UNTIL_WINDOW_EXPIRES",
        reason: "BEFORE_OR_WITHIN_STATUS_TRANSITION_BUFFER",
        entitledUntilSec: entitledUntil,
        occurredAtSec,
      };
    }
  }

  return {
    ok: true,
    executionMode: "local_open_source_engine",
    isGhostUsage: true,
    decision: "DISPATCH_SIGNED_REVOKE_WEBHOOK",
    reason: "CRITICAL_GHOST_LEAK",
    entitledUntilSec: maxEntitledUntilSec,
    occurredAtSec,
  };
}

function parseStrictIpv4Octets(str) {
  const parts = String(str || "").trim().split(".");
  if (parts.length !== 4) return null;
  const octets = [];
  for (const p of parts) {
    if (!/^(?:0|[1-9]\d{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets;
}

function normalizeIpForCe3Correlation(ip) {
  if (typeof ip !== "string") return null;
  const clean = ip.trim().replace(/^\[|\]$/g, "").replace(/%[^\s%\]]+$/, "").trim().toLowerCase();
  if (!clean) return null;
  const directV4 = parseStrictIpv4Octets(clean);
  if (directV4) return `ipv4:${directV4.join(".")}`;
  if (!clean.includes(":")) return null;
  let hexCandidate = clean;
  if (clean.includes(".")) {
    const lastColonIdx = clean.lastIndexOf(":");
    if (lastColonIdx === -1) return null;
    const v4Octets = parseStrictIpv4Octets(clean.slice(lastColonIdx + 1));
    if (!v4Octets) return null;
    const w6 = (((v4Octets[0] << 8) | v4Octets[1]) >>> 0).toString(16);
    const w7 = (((v4Octets[2] << 8) | v4Octets[3]) >>> 0).toString(16);
    hexCandidate = `${clean.slice(0, lastColonIdx + 1)}${w6}:${w7}`;
  }
  const doubleColonParts = hexCandidate.split("::");
  if (doubleColonParts.length > 2) return null;
  let groups = [];
  if (doubleColonParts.length === 1) {
    groups = hexCandidate.split(":");
    if (groups.length !== 8) return null;
  } else {
    const left = doubleColonParts[0] ? doubleColonParts[0].split(":") : [];
    const right = doubleColonParts[1] ? doubleColonParts[1].split(":") : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...new Array(missing).fill("0"), ...right];
  }
  if (groups.length !== 8) return null;
  const words = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    const val = Number.parseInt(g, 16);
    if (!Number.isInteger(val) || val < 0 || val > 0xffff) return null;
    words.push(val);
  }
  if (
    words[0] === 0 &&
    words[1] === 0 &&
    words[2] === 0 &&
    words[3] === 0 &&
    words[4] === 0 &&
    words[5] === 0xffff
  ) {
    return `ipv4:${(words[6] >> 8) & 0xff}.${words[6] & 0xff}.${(words[7] >> 8) & 0xff}.${words[7] & 0xff}`;
  }
  return `ipv6_64:${words.slice(0, 4).map((w) => w.toString(16).padStart(4, "0")).join(":")}`;
}

function extractNormalizedCe3Identifiers(tx) {
  if (!tx || typeof tx !== "object") {
    return {
      user_id: null,
      email: null,
      ip_subnet: null,
      device_id: null,
      shipping_address: null,
    };
  }
  const rawUserId =
    tx.user_id ||
    tx.customer_id ||
    tx.stripe_customer_id ||
    (typeof tx.customer === "string" ? tx.customer : tx.customer?.id) ||
    tx.metadata?.user_id ||
    "";
  const userId = sanitizeLogToken(rawUserId, 96);
  const rawEmail =
    tx.email ||
    tx.billing_details?.email ||
    tx.receipt_email ||
    tx.customer?.email ||
    tx.metadata?.email ||
    "";
  const email = sanitizeLogToken(String(rawEmail || "").toLowerCase(), 96);
  const rawIp =
    tx.ip_address ||
    tx.ip ||
    tx.client_ip ||
    tx.metadata?.ip_address ||
    (typeof tx.ip_subnet === "string" ? tx.ip_subnet.replace(/\/\d{1,3}$/, "") : "") ||
    "";
  const ipSubnet = normalizeIpForCe3Correlation(typeof rawIp === "string" ? rawIp : "");
  const rawDevice =
    tx.device_id ||
    tx.device_fingerprint ||
    tx.metadata?.device_id ||
    tx.metadata?.device_fingerprint ||
    "";
  const deviceId = sanitizeLogToken(rawDevice, 96);
  let shippingAddr = "";
  if (typeof tx.shipping_address === "string") {
    shippingAddr = tx.shipping_address
      .split("|")
      .map((v) => sanitizeLogToken(v.trim(), 96))
      .filter(Boolean)
      .join("|")
      .toLowerCase();
  } else {
    const addr =
      tx.shipping?.address && typeof tx.shipping.address === "object"
        ? tx.shipping.address
        : tx.shipping_address && typeof tx.shipping_address === "object"
          ? tx.shipping_address
          : null;
    if (addr) {
      shippingAddr = [
        addr.line1,
        addr.line2,
        addr.city,
        addr.state,
        addr.postal_code,
        addr.country,
      ]
        .map((v) => sanitizeLogToken(String(v || "").trim(), 96))
        .filter(Boolean)
        .join("|")
        .toLowerCase();
    }
  }
  return {
    user_id: userId || null,
    email: email || null,
    ip_subnet: ipSubnet || null,
    device_id: deviceId || null,
    shipping_address: shippingAddr || null,
  };
}

function extractPaymentCredential(tx) {
  if (!tx || typeof tx !== "object") return "";
  const raw =
    tx.card_fingerprint ||
    tx.payment_method_fingerprint ||
    tx.payment_method ||
    tx.payment_method_details?.card?.fingerprint ||
    tx.card?.fingerprint ||
    "";
  return sanitizeLogToken(raw, 96);
}

function evaluateLocalVisaCe3Qualification(disputeReason, disputedTransaction, priorTransactions) {
  const reason = String(disputeReason || "fraudulent").trim().toLowerCase();
  if (reason !== "fraudulent") {
    return {
      qualified: false,
      status: "NOT_APPLICABLE_NON_FRAUD_REASON",
      reason: "CE3_REQUIRES_FRAUDULENT_REASON",
      matchedTransactionIds: [],
      sharedIdentifiers: [],
    };
  }
  if (!disputedTransaction || typeof disputedTransaction !== "object") {
    return {
      qualified: false,
      status: "INCOMPLETE_DISPUTED_TRANSACTION",
      reason: "MISSING_DISPUTED_TRANSACTION_METADATA",
      matchedTransactionIds: [],
      sharedIdentifiers: [],
    };
  }
  const dispSec = parseEventTimestampSec(disputedTransaction);
  const dispIds = extractNormalizedCe3Identifiers(disputedTransaction);
  const dispCred = extractPaymentCredential(disputedTransaction);
  if (dispSec === null || (!dispIds.ip_subnet && !dispIds.device_id)) {
    return {
      qualified: false,
      status: "INCOMPLETE_DISPUTED_TRANSACTION",
      reason: "MISSING_DISPUTED_TIMESTAMP_OR_IDENTIFIERS",
      matchedTransactionIds: [],
      sharedIdentifiers: [],
    };
  }
  const IDENTIFIER_KEYS = ["user_id", "email", "ip_subnet", "device_id", "shipping_address"];
  const priors = Array.isArray(priorTransactions) ? priorTransactions.slice(0, 1000) : [];
  const seenIds = new Set();
  const dispId = String(disputedTransaction.id || "").trim();
  const allWindowQualified = [];
  let sawPaymentCredentialMismatch = false;

  for (const tx of priors) {
    if (!tx || typeof tx !== "object") continue;
    const txSec = parseEventTimestampSec(tx);
    if (txSec === null) continue;
    const txId = String(tx.id || `tx_${txSec}`).trim();
    if (!txId || (dispId && txId === dispId) || seenIds.has(txId)) continue;
    seenIds.add(txId);
    if (tx.status !== "succeeded" || tx.disputed === true || tx.refunded === true) continue;
    if (Number(tx.amount_refunded || 0) !== 0) continue;
    const ageSec = dispSec - txSec;
    if (ageSec < CE3_MIN_WINDOW_SEC || ageSec > CE3_MAX_WINDOW_SEC) continue;
    const txCred = extractPaymentCredential(tx);
    if ((dispCred && txCred && dispCred !== txCred) || (dispCred && !txCred) || (!dispCred && txCred)) {
      sawPaymentCredentialMismatch = true;
      continue;
    }
    const priorIds = extractNormalizedCe3Identifiers(tx);
    const matchedFields = [];
    for (const k of IDENTIFIER_KEYS) {
      if (dispIds[k] !== null && priorIds[k] !== null && dispIds[k] === priorIds[k]) {
        matchedFields.push(k);
      }
    }
    if (matchedFields.length >= 2) {
      allWindowQualified.push({
        id: txId,
        occurredAtSec: txSec,
        matchedFields,
        samePaymentMethodVerified: Boolean(dispCred && txCred && dispCred === txCred),
      });
    }
  }

  const windowQualified = allWindowQualified
    .sort((a, b) => {
      const aHasNetOrDev =
        a.matchedFields.includes("ip_subnet") || a.matchedFields.includes("device_id") ? 1 : 0;
      const bHasNetOrDev =
        b.matchedFields.includes("ip_subnet") || b.matchedFields.includes("device_id") ? 1 : 0;
      if (bHasNetOrDev !== aHasNetOrDev) return bHasNetOrDev - aHasNetOrDev;
      return b.occurredAtSec !== a.occurredAtSec
        ? b.occurredAtSec - a.occurredAtSec
        : a.id.localeCompare(b.id);
    })
    .slice(0, 100);

  let bestGroup = null;
  let bestSharedFields = null;
  for (let i = 0; i < windowQualified.length; i += 1) {
    for (let j = i + 1; j < windowQualified.length; j += 1) {
      const commonFields = windowQualified[i].matchedFields.filter((f) =>
        windowQualified[j].matchedFields.includes(f)
      );
      if (commonFields.length < 2) continue;
      if (!commonFields.includes("ip_subnet") && !commonFields.includes("device_id")) continue;
      const matchingGroup = windowQualified.filter((p) =>
        commonFields.every((f) => p.matchedFields.includes(f))
      );
      if (
        matchingGroup.length >= 2 &&
        (!bestSharedFields ||
          commonFields.length > bestSharedFields.length ||
          (commonFields.length === bestSharedFields.length &&
            matchingGroup.length > bestGroup.length))
      ) {
        bestSharedFields = commonFields;
        bestGroup = matchingGroup;
      }
    }
  }

  const qualified = Boolean(bestGroup && bestSharedFields);
  const samePaymentMethodVerified = Boolean(
    qualified && bestGroup.every((p) => p.samePaymentMethodVerified)
  );
  const matchedIds = qualified ? bestGroup.map((q) => q.id) : [];
  return {
    qualified,
    eligible: qualified,
    samePaymentMethodVerified,
    status: !qualified
      ? "INSUFFICIENT_HISTORICAL_OVERLAP"
      : samePaymentMethodVerified
        ? "QUALIFIED_VISA_CE3_SAFE_HARBOR"
        : "QUALIFIED_CE3_IDENTIFIER_OVERLAP_VERIFY_SAME_CARD",
    reason: qualified
      ? "TWO_PRIOR_CHARGES_120D_365D_WITH_CONSISTENT_TWO_FIELD_OVERLAP"
      : sawPaymentCredentialMismatch
        ? "PAYMENT_CREDENTIAL_MISMATCH_OR_MISSING_ON_PRIOR_CHARGES"
        : "REQUIRES_2_UNDISPUTED_CHARGES_120D_TO_365D_WITH_CONSISTENT_TWO_FIELD_OVERLAP",
    matchedTransactionIds: matchedIds,
    matchedPriorTransactionIds: matchedIds,
    sharedIdentifiers: qualified ? bestSharedFields : [],
    ...(qualified && !samePaymentMethodVerified
      ? { limitations: ["SAME_PAYMENT_METHOD_NOT_PROVIDED_IN_LOCAL_PAYLOAD"] }
      : {}),
  };
}

export function executeLocalMcpTool(toolName, rawArgs = {}) {
  const inputArgs =
    rawArgs === undefined
      ? {}
      : rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs)
        ? rawArgs
        : null;
  if (!inputArgs) {
    const err = new Error("Invalid params: arguments must be a JSON object");
    err.code = -32602;
    err.reason = "INVALID_ARGUMENTS_OBJECT";
    throw err;
  }
  const secretScan = scanLocalMcpPayloadForSecrets(inputArgs);
  if (!secretScan.ok) {
    const err = new Error(`Invalid params: ${secretScan.reason}`);
    err.code = -32602;
    err.reason = secretScan.reason;
    throw err;
  }
  const normalizedRes = normalizeMcpToolArgs(toolName, inputArgs);
  if (!normalizedRes.ok) {
    const err = new Error(normalizedRes.message);
    err.code = -32602;
    err.reason = normalizedRes.error;
    throw err;
  }
  const args = normalizedRes.args;

  if (toolName === "revclamp_calculate_roi_and_plan_fit") {
    const monthlyWonDisputeUsd = Number(args.monthlyWonDisputeUsd ?? 10_000);
    const monthlyGhostBleedUsd = Number(args.monthlyGhostBleedUsd ?? 600);
    const contingencyTakeRatePercent = Number(Number(args.contingencyTakeRatePercent ?? 25).toFixed(2));
    const monthlyUsageEvents = Number(args.monthlyUsageEvents ?? 250_000);

    const monthlyWonDisputeCents = Math.round(monthlyWonDisputeUsd * 100);
    const monthlyGhostBleedCents = Math.round(monthlyGhostBleedUsd * 100);
    const legacyTakeRateCommissionCents = Math.round(
      (monthlyWonDisputeCents * contingencyTakeRatePercent) / 100
    );

    let recommendedTier = "scale_199";
    if (monthlyUsageEvents <= TIER_EVENT_CAPS.starter_19) {
      recommendedTier = "starter_19";
    } else if (monthlyUsageEvents <= TIER_EVENT_CAPS.growth_59) {
      recommendedTier = "growth_59";
    }
    const recommendedPlan =
      PLAN_CATALOG.find((p) => p.tier === recommendedTier) || PLAN_CATALOG[2];
    const withinScaleCap = monthlyUsageEvents <= TIER_EVENT_CAPS.scale_199;

    const revclampMonthlyPlanCents = recommendedPlan.priceUsd * 100;
    const monthlyGrossValueProtectedCents =
      legacyTakeRateCommissionCents + monthlyGhostBleedCents;
    const monthlyNetMarginSavedCents = Math.max(
      0,
      monthlyGrossValueProtectedCents - revclampMonthlyPlanCents
    );
    const annualNetMarginSavedCents = monthlyNetMarginSavedCents * 12;
    const roiMultiple =
      revclampMonthlyPlanCents > 0
        ? Number((monthlyGrossValueProtectedCents / revclampMonthlyPlanCents).toFixed(2))
        : 0;

    const planComparison = PLAN_CATALOG.filter((p) => p.tier !== "free").map((p) => {
      const planCents = p.priceUsd * 100;
      const netMonthlyCents = Math.max(0, monthlyGrossValueProtectedCents - planCents);
      return {
        tier: p.tier,
        name: p.name,
        priceUsd: p.priceUsd,
        monthlyCap: p.monthlyCap,
        fitsUsageVolume: monthlyUsageEvents <= p.monthlyCap,
        annualPlanCostUsd: p.priceUsd * 12,
        annualNetSavingsUsd: Number(((netMonthlyCents * 12) / 100).toFixed(2)),
      };
    });

    return {
      ok: true,
      executionMode: "local_open_source_engine",
      monthlyWonDisputeCents,
      monthlyWonDisputeUsd: Number((monthlyWonDisputeCents / 100).toFixed(2)),
      monthlyGhostBleedCents,
      monthlyGhostBleedUsd: Number((monthlyGhostBleedCents / 100).toFixed(2)),
      contingencyTakeRatePercent,
      monthlyUsageEvents,
      legacyTakeRateCommissionCents,
      legacyTakeRateCommissionUsd: Number((legacyTakeRateCommissionCents / 100).toFixed(2)),
      recommendedTier: recommendedPlan.tier,
      recommendedPlanName: recommendedPlan.name,
      recommendedPlanPriceUsd: recommendedPlan.priceUsd,
      recommendedPlanMonthlyCap: recommendedPlan.monthlyCap,
      withinScaleCap,
      revclampMonthlyPlanCents,
      revclampMonthlyPlanUsd: recommendedPlan.priceUsd,
      monthlyGrossValueProtectedCents,
      monthlyGrossValueProtectedUsd: Number((monthlyGrossValueProtectedCents / 100).toFixed(2)),
      monthlyNetMarginSavedCents,
      monthlyNetMarginSavedUsd: Number((monthlyNetMarginSavedCents / 100).toFixed(2)),
      annualNetMarginSavedCents,
      annualNetMarginSavedUsd: Number((annualNetMarginSavedCents / 100).toFixed(2)),
      roiMultiple,
      zeroTakeRateGuaranteed: true,
      planComparison,
    };
  }

  if (toolName === "revclamp_simulate_webhook_replay") {
    const hasExplicitEvents = args.events !== undefined && args.events !== null;
    const preset = String(
      args.scenarioPreset ||
        (hasExplicitEvents ? "custom" : "out_of_order_stale_update_after_cancel")
    );
    const windowSec = Number(args.idempotencyWindowSec ?? 259_200);
    const defaultNowByPreset = {
      out_of_order_stale_update_after_cancel: 1_760_001_200,
      duplicate_event_id_replay_72h: 1_760_002_500,
      valid_monotonic_upgrade_sequence: 1_760_001_500,
      expired_72h_window_stale_event: 1_760_500_000,
    };
    const effectiveNowSec = Number.isInteger(args.nowSec)
      ? args.nowSec
      : defaultNowByPreset[preset] || Math.floor(Date.now() / 1000);
    const defaultPresets = {
      out_of_order_stale_update_after_cancel: [
        { id: "evt_01_active", status: "active", createdSec: 1760000100, arrivedAtSec: 1760000101 },
        { id: "evt_02_cancel", status: "canceled", createdSec: 1760000500, arrivedAtSec: 1760000501 },
        { id: "evt_03_stale_active", status: "active", createdSec: 1760000200, arrivedAtSec: 1760000510 },
      ],
      duplicate_event_id_replay_72h: [
        { id: "evt_dup_01", status: "canceled", createdSec: 1760000500, arrivedAtSec: 1760000501 },
        { id: "evt_dup_01", status: "canceled", createdSec: 1760000500, arrivedAtSec: 1760000600 },
      ],
      valid_monotonic_upgrade_sequence: [
        { id: "evt_up_01", status: "trialing", createdSec: 1760000100, arrivedAtSec: 1760000101 },
        { id: "evt_up_02", status: "active", createdSec: 1760000300, arrivedAtSec: 1760000301 },
      ],
      expired_72h_window_stale_event: [
        { id: "evt_exp_01", status: "canceled", createdSec: 1760000100, arrivedAtSec: 1760000101 },
        { id: "evt_exp_01", status: "active", createdSec: 1760000050, arrivedAtSec: 1760300000 },
      ],
    };

    if (preset === "custom" && (!Array.isArray(args.events) || args.events.length === 0)) {
      const err = new Error(
        "INVALID_REPLAY_EVENTS_SEQUENCE: Custom scenarioPreset requires a non-empty events array (1..10 items)."
      );
      err.code = -32602;
      throw err;
    }

    if (Array.isArray(args.events)) {
      if (args.events.length < 1 || args.events.length > 10) {
        const err = new Error(
          "INVALID_REPLAY_EVENTS_SEQUENCE: events must contain between 1 and 10 webhook transition objects."
        );
        err.code = -32602;
        throw err;
      }
      const allowedEventKeys = new Set([
        "eventId",
        "eventType",
        "createdSec",
        "subscriptionStatus",
        "tier",
        "currentPeriodEndSec",
        "id",
        "type",
        "created",
        "status",
        "target_status",
        "arrivedAtSec",
        "arrived_at_sec",
      ]);
      const allowedSubStatuses = new Set([
        "active",
        "trialing",
        "past_due",
        "paused",
        "canceled",
        "cancelled",
        "unpaid",
        "cancel_at_period_end",
        "expired",
      ]);
      const allowedTiers = new Set(["free", "starter_19", "growth_59", "scale_199"]);
      for (let idx = 0; idx < args.events.length; idx += 1) {
        const item = args.events[idx];
        if (!item || typeof item !== "object" || Array.isArray(item)) {
          const err = new Error("Each item in 'events' must be a JSON object.");
          err.code = -32602;
          throw err;
        }
        for (const ek of Object.keys(item)) {
          if (!allowedEventKeys.has(ek)) {
            const err = new Error(
              `INVALID_REPLAY_EVENTS_SEQUENCE: Unknown field '${ek}' on event at index ${idx}.`
            );
            err.code = -32602;
            throw err;
          }
        }
        const definedStatuses = [item.subscriptionStatus, item.status, item.target_status]
          .filter((v) => v !== undefined)
          .map((v) => String(v).trim().toLowerCase());
        const hasStatusConflict =
          definedStatuses.length > 1 && new Set(definedStatuses).size > 1;
        const hasArrivedConflict =
          item.arrivedAtSec !== undefined &&
          item.arrived_at_sec !== undefined &&
          Number(item.arrivedAtSec) !== Number(item.arrived_at_sec);
        if (
          (item.eventId !== undefined &&
            item.id !== undefined &&
            String(item.eventId).trim() !== String(item.id).trim()) ||
          (item.eventType !== undefined &&
            item.type !== undefined &&
            String(item.eventType).trim() !== String(item.type).trim()) ||
          (item.createdSec !== undefined &&
            item.created !== undefined &&
            Number(item.createdSec) !== Number(item.created)) ||
          hasStatusConflict ||
          hasArrivedConflict
        ) {
          const err = new Error(
            `CONFLICTING_REPLAY_EVENT_ALIASES: Event at index ${idx} specifies conflicting canonical and alias fields.`
          );
          err.code = -32602;
          throw err;
        }
        const resolvedIdInput = item.eventId !== undefined ? item.eventId : item.id;
        const rawId = typeof resolvedIdInput === "string" ? resolvedIdInput.trim() : "";
        if (!rawId || !/^[A-Za-z0-9_.:-]{1,96}$/.test(rawId)) {
          const err = new Error(
            `INVALID_REPLAY_EVENTS_SEQUENCE: Event at index ${idx} has an invalid eventId/id.`
          );
          err.code = -32602;
          throw err;
        }
        const resolvedTypeInput =
          item.eventType !== undefined
            ? item.eventType
            : item.type !== undefined
              ? item.type
              : "customer.subscription.updated";
        const rawType = typeof resolvedTypeInput === "string" ? resolvedTypeInput.trim() : "";
        if (!rawType || !/^[A-Za-z0-9_.-]{1,96}$/.test(rawType)) {
          const err = new Error(
            `INVALID_REPLAY_EVENTS_SEQUENCE: Event at index ${idx} has an invalid eventType/type.`
          );
          err.code = -32602;
          throw err;
        }
        const resolvedCreatedInput = item.createdSec !== undefined ? item.createdSec : item.created;
        const parsedCreated = Number(resolvedCreatedInput);
        if (
          typeof resolvedCreatedInput === "boolean" ||
          resolvedCreatedInput === null ||
          resolvedCreatedInput === undefined ||
          resolvedCreatedInput === "" ||
          Array.isArray(resolvedCreatedInput) ||
          !Number.isInteger(parsedCreated) ||
          parsedCreated < 946_684_800 ||
          parsedCreated > effectiveNowSec + 400 * 86_400
        ) {
          const err = new Error(
            `INVALID_REPLAY_EVENTS_SEQUENCE: Event at index ${idx} has an invalid createdSec/created timestamp.`
          );
          err.code = -32602;
          throw err;
        }
        const resolvedStatusInput =
          item.subscriptionStatus !== undefined
            ? item.subscriptionStatus
            : item.status !== undefined
              ? item.status
              : item.target_status;
        const rawStatus =
          typeof resolvedStatusInput === "string" ? resolvedStatusInput.trim().toLowerCase() : "";
        if (!allowedSubStatuses.has(rawStatus)) {
          const err = new Error(
            `INVALID_REPLAY_EVENTS_SEQUENCE: Event at index ${idx} has an invalid subscriptionStatus/status.`
          );
          err.code = -32602;
          throw err;
        }
        const resolvedArrivedInput =
          item.arrivedAtSec !== undefined ? item.arrivedAtSec : item.arrived_at_sec;
        if (resolvedArrivedInput !== undefined && resolvedArrivedInput !== null) {
          const parsedArr = Number(resolvedArrivedInput);
          if (
            typeof resolvedArrivedInput === "boolean" ||
            resolvedArrivedInput === "" ||
            Array.isArray(resolvedArrivedInput) ||
            !Number.isInteger(parsedArr) ||
            parsedArr < 946_684_800 ||
            parsedArr > effectiveNowSec + 400 * 86_400
          ) {
            const err = new Error(
              `INVALID_REPLAY_EVENTS_SEQUENCE: Event at index ${idx} has an invalid arrivedAtSec timestamp.`
            );
            err.code = -32602;
            throw err;
          }
        }
        if (item.tier !== undefined && item.tier !== null) {
          const rawTier = typeof item.tier === "string" ? item.tier.trim().toLowerCase() : "";
          if (!allowedTiers.has(rawTier)) {
            const err = new Error(
              `INVALID_REPLAY_EVENTS_SEQUENCE: Event at index ${idx} has an invalid tier.`
            );
            err.code = -32602;
            throw err;
          }
        }
        if (item.currentPeriodEndSec !== undefined && item.currentPeriodEndSec !== null) {
          const parsedPe = Number(item.currentPeriodEndSec);
          if (
            typeof item.currentPeriodEndSec === "boolean" ||
            item.currentPeriodEndSec === "" ||
            Array.isArray(item.currentPeriodEndSec) ||
            !Number.isInteger(parsedPe) ||
            parsedPe < 946_684_800 ||
            parsedPe > effectiveNowSec + 5 * 366 * 86_400
          ) {
            const err = new Error(
              `INVALID_REPLAY_EVENTS_SEQUENCE: Event at index ${idx} has an invalid currentPeriodEndSec.`
            );
            err.code = -32602;
            throw err;
          }
        }
      }
    }

    const events =
      Array.isArray(args.events) && args.events.length > 0
        ? args.events
        : defaultPresets[preset] || defaultPresets.out_of_order_stale_update_after_cancel;

    const seenIds = new Map();
    let watermarkCreatedSec = 0;
    let finalStatus = "unknown";
    let naiveFinalStatus = "unknown";
    const trace = [];

    for (const ev of events) {
      const evId = String((ev.eventId !== undefined ? ev.eventId : ev.id) || "");
      const createdSec = Number((ev.createdSec !== undefined ? ev.createdSec : ev.created) || 0);
      const resolvedArrivedVal =
        ev.arrivedAtSec !== undefined ? ev.arrivedAtSec : ev.arrived_at_sec;
      const hasArrivedAt = resolvedArrivedVal !== undefined && resolvedArrivedVal !== null;
      const evalClockSec = hasArrivedAt ? Number(resolvedArrivedVal) : effectiveNowSec;
      const rawStatusVal = String(
        (ev.subscriptionStatus !== undefined
          ? ev.subscriptionStatus
          : ev.status !== undefined
            ? ev.status
            : ev.target_status) || ""
      );
      const normStatusVal = rawStatusVal === "cancelled" ? "canceled" : rawStatusVal;
      naiveFinalStatus = normStatusVal || naiveFinalStatus;

      if (hasArrivedAt) {
        for (const [k, seenAt] of seenIds.entries()) {
          if (evalClockSec - seenAt > windowSec) {
            seenIds.delete(k);
          }
        }
      } else if (evalClockSec - createdSec > windowSec) {
        trace.push({ id: evId, decision: "EXPIRED_OUTSIDE_72H_DEDUP_WINDOW", statusAfter: finalStatus });
        continue;
      }

      if (seenIds.has(evId)) {
        trace.push({ id: evId, decision: "IGNORED_DUPLICATE_72H", statusAfter: finalStatus });
        continue;
      }
      seenIds.set(evId, evalClockSec);

      if (createdSec < watermarkCreatedSec) {
        trace.push({ id: evId, decision: "IGNORED_STALE_OUT_OF_ORDER", statusAfter: finalStatus });
        continue;
      }

      watermarkCreatedSec = createdSec;
      finalStatus = normStatusVal || finalStatus;
      trace.push({ id: evId, decision: "APPLIED_MONOTONIC", statusAfter: finalStatus });
    }

    return {
      ok: true,
      executionMode: "local_open_source_engine",
      scenarioPreset: preset,
      idempotencyWindowSec: windowSec,
      finalStatus,
      naiveFinalStatus,
      preventedStateCorruption:
        finalStatus !== naiveFinalStatus || trace.some((t) => t.decision !== "APPLIED_MONOTONIC"),
      trace,
    };
  }

  if (toolName === "revclamp_lint_dispute_evidence") {
    const lintToolSpec = LOCAL_MCP_TOOLS.find((t) => t.name === "revclamp_lint_dispute_evidence");
    if (lintToolSpec) {
      const schemaCheck = validateArgsAgainstSchema(lintToolSpec.inputSchema, args);
      if (!schemaCheck.ok) {
        const err = new Error(`Invalid params: ${schemaCheck.message}`);
        err.code = -32602;
        err.reason = "INVALID_DISPUTE_EVIDENCE_LINT_PARAMETERS";
        throw err;
      }
    }
    const hasEvidenceLogText =
      typeof args.evidenceLogText === "string" && args.evidenceLogText.trim().length > 0;
    const hasAccessActivityLog =
      typeof args.accessActivityLog === "string" && args.accessActivityLog.trim().length > 0;
    if (
      hasEvidenceLogText &&
      hasAccessActivityLog &&
      args.evidenceLogText.trim() !== args.accessActivityLog.trim()
    ) {
      const err = new Error(
        "CONFLICTING_EVIDENCE_LOG_ALIASES: evidenceLogText and accessActivityLog must match when both are provided"
      );
      err.code = -32602;
      err.reason = "CONFLICTING_EVIDENCE_LOG_ALIASES";
      throw err;
    }

    const hasExplicitLogString =
      typeof args.evidenceLogText === "string" || typeof args.accessActivityLog === "string";
    const resolvedLogInput = hasEvidenceLogText
      ? args.evidenceLogText
      : hasAccessActivityLog
        ? args.accessActivityLog
        : typeof args.evidenceLogText === "string"
          ? args.evidenceLogText
          : typeof args.accessActivityLog === "string"
            ? args.accessActivityLog
            : undefined;
    const rawCallerLog =
      typeof resolvedLogInput === "string"
        ? resolvedLogInput
        : typeof args.existingMerchantNotes === "string" &&
            args.existingMerchantNotes.trim().length > 0
          ? args.existingMerchantNotes
          : "";
    const hasCallerLog = rawCallerLog.length > 0 || hasExplicitLogString;
    const hasExplicitPreset =
      typeof args.preset === "string" &&
      args.preset.trim().length > 0 &&
      args.preset.trim() !== "custom";
    const hasSummaryArgs =
      args.priorMatchedCount !== undefined ||
      args.hasIpMatch !== undefined ||
      args.hasDeviceMatch !== undefined;
    const hasTransactionArgs =
      (args.disputedTransaction !== undefined && args.disputedTransaction !== null) ||
      (args.priorTransactions !== undefined && args.priorTransactions !== null);
    const hasCustomInputFields =
      args.evidenceLogText !== undefined ||
      args.accessActivityLog !== undefined ||
      args.existingMerchantNotes !== undefined ||
      args.priorMatchedCount !== undefined ||
      args.hasIpMatch !== undefined ||
      args.hasDeviceMatch !== undefined ||
      args.disputedTransaction !== undefined ||
      args.priorTransactions !== undefined;
    const preset =
      typeof args.preset === "string" && args.preset.trim()
        ? args.preset.trim()
        : hasCustomInputFields
          ? "custom"
          : "valid_ce3_non_destructive";
    const isDemo =
      args.demo === true ||
      (!hasCallerLog &&
        (preset !== "custom" || hasExplicitPreset || hasSummaryArgs || hasTransactionArgs));
    if (!hasCallerLog && !isDemo) {
      const err = new Error(
        "MISSING_ACCESS_ACTIVITY_LOG: Provide accessActivityLog / evidenceLogText to lint a real dispute payload, or specify preset / demo: true to lint a sample fixture."
      );
      err.code = -32602;
      err.reason = "MISSING_ACCESS_ACTIVITY_LOG";
      throw err;
    }

    const ce3Qualification = hasTransactionArgs
      ? evaluateLocalVisaCe3Qualification(
          "fraudulent",
          args.disputedTransaction,
          args.priorTransactions
        )
      : null;

    if (ce3Qualification && hasSummaryArgs) {
      const derived = {
        priorMatchedCount: (ce3Qualification.matchedTransactionIds || []).length,
        hasIpMatch: (ce3Qualification.sharedIdentifiers || []).includes("ip_subnet"),
        hasDeviceMatch: (ce3Qualification.sharedIdentifiers || []).includes("device_id"),
      };
      if (
        (args.priorMatchedCount !== undefined &&
          Number(args.priorMatchedCount) !== derived.priorMatchedCount) ||
        (args.hasIpMatch !== undefined && Boolean(args.hasIpMatch) !== derived.hasIpMatch) ||
        (args.hasDeviceMatch !== undefined &&
          Boolean(args.hasDeviceMatch) !== derived.hasDeviceMatch)
      ) {
        const err = new Error(
          "CONFLICTING_CE3_SUMMARY_AND_TRANSACTIONS: Explicit CE 3.0 summary parameters (priorMatchedCount, hasIpMatch, hasDeviceMatch) conflict with transaction-derived qualification."
        );
        err.code = -32602;
        err.reason = "CONFLICTING_CE3_SUMMARY_AND_TRANSACTIONS";
        throw err;
      }
    }

    const ce3SummarySource = hasTransactionArgs
      ? "transactions"
      : hasSummaryArgs
        ? "explicit"
        : preset !== "custom"
          ? "preset"
          : "log_inferred";
    const normalizedPresetKey =
      preset === "ce3_24k_truncation_trap"
        ? "utf16_overflow_19k"
        : preset === "ce3_missing_device_binding_19k"
          ? "missing_device_and_overwrite_risk"
          : preset === "ce3_clean_compacted_14k"
            ? "valid_ce3_non_destructive"
            : preset;
    const localPresetFixtures = {
      valid_ce3_non_destructive: {
        existingMerchantNotes: "Customer signed annual MSA #2025-884; ticket #9102 resolved.",
        evidenceLogText: [
          "Customer signed annual MSA #2025-884; ticket #9102 resolved.",
          "--- BEGIN REVCLAMP CE3 EVIDENCE ---",
          "Prior Charge 1: py_1Ox99a (2026-03-11, IP 198.51.100.42, Device dev_88a)",
          "Prior Charge 2: py_1P211b (2026-05-19, IP 198.51.100.42, Device dev_88a)",
          "90-Day Verified Usage Events: 412 API calls authenticated via workspace key.",
          "--- END REVCLAMP CE3 EVIDENCE ---",
        ].join("\n"),
      },
      utf16_overflow_19k: {
        existingMerchantNotes: "Finance note: enterprise renewal disputed.",
        evidenceLogText: `Finance note: enterprise renewal disputed.\n--- BEGIN REVCLAMP CE3 EVIDENCE ---\n${"E".repeat(19000)}\n--- END REVCLAMP CE3 EVIDENCE ---`,
      },
      missing_device_and_overwrite_risk: {
        existingMerchantNotes: "VIP customer escalation note from account executive.",
        evidenceLogText: "Raw replacement log that overwrote AE notes without markers.",
      },
    };
    const basePreset =
      normalizedPresetKey !== "custom" ? localPresetFixtures[normalizedPresetKey] : null;
    const existingMerchantNotes =
      typeof args.existingMerchantNotes === "string"
        ? args.existingMerchantNotes
        : basePreset?.existingMerchantNotes ?? "";
    const logText =
      typeof resolvedLogInput === "string"
        ? resolvedLogInput
        : basePreset
          ? basePreset.evidenceLogText ?? ""
          : existingMerchantNotes ||
            localPresetFixtures.valid_ce3_non_destructive.evidenceLogText;

    const inferredHasIp = /\bip(?:=|\s+\d)/i.test(logText);
    const inferredHasDevice = /\bdevice(?:=|\s+[a-z0-9_])/i.test(logText);
    const inferredPriorCount = inferredHasIp || inferredHasDevice ? 2 : 0;
    const isMissingDevicePreset = normalizedPresetKey === "missing_device_and_overwrite_risk";
    const defaultPriorMatchedCount = ce3Qualification
      ? (ce3Qualification.matchedTransactionIds || []).length
      : isMissingDevicePreset
        ? 1
        : normalizedPresetKey !== "custom"
          ? 2
          : inferredPriorCount;
    const defaultHasIpMatch = ce3Qualification
      ? (ce3Qualification.sharedIdentifiers || []).includes("ip_subnet")
      : isMissingDevicePreset
        ? false
        : normalizedPresetKey !== "custom"
          ? true
          : inferredHasIp;
    const defaultHasDeviceMatch = ce3Qualification
      ? (ce3Qualification.sharedIdentifiers || []).includes("device_id")
      : isMissingDevicePreset
        ? false
        : normalizedPresetKey !== "custom"
          ? true
          : inferredHasDevice;

    const priorMatchedCount =
      args.priorMatchedCount !== undefined
        ? Number(args.priorMatchedCount)
        : defaultPriorMatchedCount;
    const hasIpMatch =
      args.hasIpMatch !== undefined ? Boolean(args.hasIpMatch) : defaultHasIpMatch;
    const hasDeviceMatch =
      args.hasDeviceMatch !== undefined ? Boolean(args.hasDeviceMatch) : defaultHasDeviceMatch;
    const ce3RubricPassed =
      priorMatchedCount >= 2 &&
      Boolean(hasIpMatch || hasDeviceMatch) &&
      (!ce3Qualification || ce3Qualification.qualified);

    const hasNetworkOrDevice = Boolean(hasIpMatch || hasDeviceMatch);
    const hasDeviceAndIp = Boolean(hasIpMatch && hasDeviceMatch);
    const strippedNotes = stripExistingRevClampBlock(logText);
    const nonDestructiveMarkersPresent = Boolean(strippedNotes.ok && strippedNotes.hadBlock);
    const malformedExistingMarkers = Boolean(!strippedNotes.ok);
    const warnings = malformedExistingMarkers ? ["MALFORMED_EXISTING_MARKERS"] : [];
    const trimmedExistingNotes = existingMerchantNotes.trim();
    const outsideMarkerText = `${strippedNotes.prefix || ""}\n${strippedNotes.suffix || ""}`;
    const preservesMerchantNotes = Boolean(
      nonDestructiveMarkersPresent &&
        strippedNotes.text.length > 0 &&
        (trimmedExistingNotes === "" || outsideMarkerText.includes(trimmedExistingNotes))
    );

    const extractedNotesLen =
      (strippedNotes.prefix?.length || 0) + (strippedNotes.suffix?.length || 0);
    const fallbackNotes = existingMerchantNotes;
    const capacityPrefix =
      extractedNotesLen > 0 ? strippedNotes.prefix || "" : fallbackNotes;
    const capacitySuffix = extractedNotesLen > 0 ? strippedNotes.suffix || "" : "";
    const preSeparatorUnits = capacityPrefix.length > 0 ? 2 : 0;
    const postSeparatorUnits = capacitySuffix.length > 0 ? 2 : 0;
    const merchantNotesUtf16CodeUnits = capacityPrefix.length + capacitySuffix.length;
    const fixedWrapperUtf16CodeUnits =
      capacityPrefix.length +
      preSeparatorUnits +
      PRODUCTION_EMPTY_BLOCK_WRAPPER_CHARS +
      postSeparatorUnits +
      capacitySuffix.length;
    const merchantLogAtCapacity = Boolean(
      fixedWrapperUtf16CodeUnits >= MAX_ACCESS_ACTIVITY_LOG_CHARS
    );
    const stagingActionWhenAtCapacity = merchantLogAtCapacity
      ? "SKIP_POST_PRESERVE_DRAFT"
      : null;
    if (merchantLogAtCapacity) {
      warnings.push("MERCHANT_LOG_AT_CAPACITY");
    }

    const utf16CodeUnits = logText.length;
    const remainingUtf16Units = Math.max(0, MAX_ACCESS_ACTIVITY_LOG_CHARS - utf16CodeUnits);
    const remainingCodeUnitsTo20k = Math.max(0, 20_000 - utf16CodeUnits);
    const utf8Bytes = Buffer.byteLength(logText, "utf8");
    const within18kCeiling = utf16CodeUnits <= MAX_ACCESS_ACTIVITY_LOG_CHARS;
    const within20kHardCeiling = utf16CodeUnits <= 20_000;
    const exceeds20kHardCeiling = utf16CodeUnits > 20_000;
    let overallVerdict = "PASS_CE3_READY";
    if (!within18kCeiling) {
      overallVerdict = "FAIL_UTF16_OVERFLOW";
    } else if (
      !hasNetworkOrDevice ||
      !ce3RubricPassed ||
      !preservesMerchantNotes ||
      malformedExistingMarkers ||
      merchantLogAtCapacity ||
      (ce3Qualification && !ce3Qualification.qualified)
    ) {
      overallVerdict = "WARN_INCOMPLETE_CE3_OR_OVERWRITE_RISK";
    }
    const verdictClass =
      overallVerdict === "PASS_CE3_READY"
        ? "PASS"
        : overallVerdict.startsWith("FAIL")
          ? "FAIL"
          : "WARN";

    return {
      ok: true,
      executionMode: "local_open_source_engine",
      ...(!hasCallerLog ? { sample: true } : {}),
      preset,
      ce3SummarySource,
      utf16CodeUnits,
      maxAllowedUtf16CodeUnits: MAX_ACCESS_ACTIVITY_LOG_CHARS,
      maxUtf16Ceiling: MAX_ACCESS_ACTIVITY_LOG_CHARS,
      remainingUtf16Units,
      remainingCodeUnitsTo18k: remainingUtf16Units,
      remainingCodeUnitsTo20k,
      within18kCeiling,
      withinCeiling: within18kCeiling,
      within18kSafeBudget: within18kCeiling,
      within20kHardCeiling,
      exceeds20kHardCeiling,
      utf8Bytes,
      hasNetworkOrDevice,
      hasDeviceAndIp,
      nonDestructiveMarkersPresent,
      malformedExistingMarkers,
      warnings,
      preservesMerchantNotes,
      merchantNotesPreserved: preservesMerchantNotes,
      merchantNotesUtf16CodeUnits,
      fixedWrapperUtf16CodeUnits,
      merchantLogAtCapacity,
      stagingActionWhenAtCapacity,
      priorMatchedCount,
      hasIpMatch,
      hasDeviceMatch,
      ce3RubricPassed,
      ...(ce3Qualification ? { ce3Qualification } : {}),
      overallVerdict,
      verdictClass,
    };
  }

  if (toolName === "revclamp_verify_webhook_signature") {
    if (args.demo !== undefined && args.demo !== null && typeof args.demo !== "boolean") {
      const err = new Error("INVALID_DEMO_FLAG: demo must be a boolean.");
      err.code = -32602;
      throw err;
    }
    const provider = String(args.provider || "stripe").trim().toLowerCase();
    if (provider !== "stripe" && provider !== "shopify" && provider !== "revclamp") {
      const err = new Error(
        "INVALID_WEBHOOK_PROVIDER: Supported webhook providers are 'stripe', 'shopify', and 'revclamp'."
      );
      err.code = -32602;
      throw err;
    }
    const defaultPayloadByProvider = {
      stripe:
        '{"id":"evt_basil_sandbox_01","object":"event","api_version":"2025-03-31.basil","type":"customer.subscription.updated","data":{"object":{"id":"sub_basil_01","customer":"cus_basil_ai_team_01","status":"past_due"}}}',
      shopify:
        '{"id":908812,"admin_graphql_api_id":"gid://shopify/Order/908812","financial_status":"partially_paid","currency":"EUR","total_price":"2500.00"}',
      revclamp:
        '{"event":"revclamp.entitlement.revoke","tenantId":"tnt_sandbox_preview","accountId":"acct_sandbox_preview","customerId":"cus_basil_ai_team_01","leakReason":"UNPAID_GHOST_USAGE_CONFIRMED"}',
    };
    const rawSecretsList =
      Array.isArray(args.secrets) && args.secrets.length > 0
        ? args.secrets
        : typeof args.secret === "string" && args.secret.trim().length > 0
          ? args.secret.split(",")
          : ["whsec_test_revclamp_sandbox_secret_2026"];
    if (rawSecretsList.length > 5) {
      const err = new Error(
        "PAYLOAD_OR_SECRET_TOO_LONG: at most 5 rotation secrets may be supplied."
      );
      err.code = -32602;
      throw err;
    }
    const candidateSecrets = [];
    for (const item of rawSecretsList) {
      if (typeof item !== "string") {
        const err = new Error("INVALID_SECRET: each secret must be a string.");
        err.code = -32602;
        throw err;
      }
      const trimmed = item.trim();
      if (!trimmed) continue;
      if (trimmed.length > 256) {
        const err = new Error(
          "PAYLOAD_OR_SECRET_TOO_LONG: secret must be <= 256 chars and rawPayload must be <= 16384 chars."
        );
        err.code = -32602;
        throw err;
      }
      candidateSecrets.push(trimmed);
    }
    if (candidateSecrets.length === 0) {
      candidateSecrets.push("whsec_test_revclamp_sandbox_secret_2026");
    }
    const secret = candidateSecrets[0];
    const rawPayload =
      typeof args.rawPayload === "string" && args.rawPayload.length > 0
        ? args.rawPayload
        : defaultPayloadByProvider[provider];
    if (rawPayload.length > 16_384) {
      const err = new Error(
        "PAYLOAD_OR_SECRET_TOO_LONG: secret must be <= 256 chars and rawPayload must be <= 16384 chars."
      );
      err.code = -32602;
      throw err;
    }
    const wallNowSec = Math.floor(Date.now() / 1000);
    if (args.timestampSec !== undefined) {
      const numTs = Number(args.timestampSec);
      if (
        typeof args.timestampSec === "boolean" ||
        !Number.isInteger(numTs) ||
        numTs < 1 ||
        numTs > 9_999_999_999
      ) {
        const err = new Error(
          "INVALID_TIMESTAMP_SECONDS: timestampSec must be an integer Unix timestamp between 1 and 9999999999."
        );
        err.code = -32602;
        throw err;
      }
    }
    const signingTimestampSec = Number.isInteger(args.timestampSec)
      ? args.timestampSec
      : wallNowSec;
    if (args.toleranceSec !== undefined) {
      const numTol = Number(args.toleranceSec);
      if (
        typeof args.toleranceSec === "boolean" ||
        !Number.isInteger(numTol) ||
        numTol < 1 ||
        numTol > 3_600
      ) {
        const err = new Error(
          "INVALID_TOLERANCE_SECONDS: toleranceSec must be an integer between 1 and 3600 seconds."
        );
        err.code = -32602;
        throw err;
      }
    }
    const toleranceSec = Number(args.toleranceSec ?? 300);
    const hasProvidedHeader =
      typeof args.signatureHeader === "string" && args.signatureHeader.trim().length > 0;

    if (provider === "shopify") {
      const expectedB64 = crypto
        .createHmac("sha256", secret)
        .update(rawPayload, "utf8")
        .digest("base64");
      if (!hasProvidedHeader) {
        return {
          ok: true,
          executionMode: "local_open_source_engine",
          verification: {
            provider: "shopify",
            mode: "generate_only",
            signatureValid: null,
            generatedHeader: expectedB64,
            matchedSecretIndex: null,
            secretsEvaluatedCount: candidateSecrets.length,
          },
        };
      }
      const provided = args.signatureHeader.trim();
      let valid = false;
      let matchedSecretIndex = null;
      for (let sIdx = 0; sIdx < candidateSecrets.length; sIdx += 1) {
        const candB64 = crypto
          .createHmac("sha256", candidateSecrets[sIdx])
          .update(rawPayload, "utf8")
          .digest("base64");
        if (
          Buffer.byteLength(provided) === Buffer.byteLength(candB64) &&
          crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(candB64))
        ) {
          valid = true;
          matchedSecretIndex = sIdx;
          break;
        }
      }
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        verification: {
          provider: "shopify",
          mode: "verify",
          signatureValid: valid,
          generatedHeader: expectedB64,
          matchedSecretIndex,
          secretsEvaluatedCount: candidateSecrets.length,
        },
      };
    }

    const sigHex = crypto
      .createHmac("sha256", secret)
      .update(`${signingTimestampSec}.${rawPayload}`, "utf8")
      .digest("hex");
    const generatedHeader = `t=${signingTimestampSec},v1=${sigHex}`;

    if (!hasProvidedHeader) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        verification: {
          provider,
          mode: "generate_only",
          signatureValid: null,
          generatedHeader,
          timestampSec: signingTimestampSec,
          toleranceSec,
          matchedSecretIndex: null,
          secretsEvaluatedCount: candidateSecrets.length,
        },
      };
    }

    let parsedTs = null;
    const v1Candidates = [];
    const trimmedHeader = args.signatureHeader.trim();
    const isBareHex = /^[0-9a-fA-F]{64}$/.test(trimmedHeader);
    if (isBareHex) {
      parsedTs = signingTimestampSec;
      v1Candidates.push(trimmedHeader.toLowerCase());
    } else {
      for (const part of trimmedHeader.split(",")) {
        const eqIdx = part.indexOf("=");
        if (eqIdx === -1) continue;
        const k = part.slice(0, eqIdx).trim();
        const v = part.slice(eqIdx + 1).trim();
        if (parsedTs === null && k === "t" && /^\d{1,10}$/.test(v)) {
          const numTs = Number(v);
          if (numTs >= 1 && numTs <= 9_999_999_999) {
            parsedTs = numTs;
          }
        } else if (k === "v1" && /^[0-9a-fA-F]{64}$/.test(v)) {
          v1Candidates.push(v.toLowerCase());
        }
      }
    }

    const effectiveTs = parsedTs !== null ? parsedTs : signingTimestampSec;
    const timestampSkewSeconds = Math.abs(wallNowSec - effectiveTs);
    const withinWindow = timestampSkewSeconds <= toleranceSec;
    let signatureValid = false;
    let matchedSecretIndex = null;
    if (parsedTs !== null && v1Candidates.length > 0 && withinWindow) {
      for (let sIdx = 0; sIdx < candidateSecrets.length; sIdx += 1) {
        const expectedForTs = crypto
          .createHmac("sha256", candidateSecrets[sIdx])
          .update(`${parsedTs}.${rawPayload}`, "utf8")
          .digest("hex");
        const expectedBuf = Buffer.from(expectedForTs, "utf8");
        const matched = v1Candidates.some(
          (cand) =>
            cand.length === expectedForTs.length &&
            crypto.timingSafeEqual(Buffer.from(cand, "utf8"), expectedBuf)
        );
        if (matched) {
          signatureValid = true;
          matchedSecretIndex = sIdx;
          break;
        }
      }
    }

    return {
      ok: true,
      executionMode: "local_open_source_engine",
      verification: {
        provider,
        mode: "verify",
        signatureValid,
        generatedHeader,
        timestampSec: effectiveTs,
        timestampSkewSeconds,
        withinReplayWindow: withinWindow,
        toleranceSec,
        matchedSecretIndex,
        secretsEvaluatedCount: candidateSecrets.length,
      },
    };
  }

  if (toolName === "revclamp_validate_eu_vat_vies") {
    if (
      args.consultationNumber !== undefined &&
      (typeof args.consultationNumber !== "string" ||
        args.consultationNumber.trim().length === 0 ||
        args.consultationNumber.trim().length > 64)
    ) {
      const err = new Error(
        "Invalid params: consultationNumber must be a non-empty string up to 64 chars"
      );
      err.code = -32602;
      throw err;
    }
    const sellerCountry = normalizeCountryCode(args.sellerCountry || "DE");
    if (!Object.prototype.hasOwnProperty.call(EU_VIES_FORMAT_RULES, sellerCountry)) {
      const err = new Error(
        `Invalid sellerCountry '${sellerCountry}': must be an EU member state or XI.`
      );
      err.code = -32602;
      throw err;
    }
    const norm = normalizeVatId(args.buyerVatId || "");
    const viesMode = String(args.viesMode || "FORMAT_ONLY").toUpperCase();
    const isDemo = args.demo === true;

    if (viesMode === "LIVE") {
      const err = new Error(
        "LIVE_VIES_REQUIRES_CLOUD_ENDPOINT: Live European Commission VIES consultation requires cloud mode (https://api.revclamp.com/api/mcp with REVCLAMP_API_KEY)."
      );
      err.code = -32602;
      throw err;
    }

    if (viesMode !== "FORMAT_ONLY" && !isDemo) {
      const err = new Error(
        `SIMULATED_VIES_REQUIRES_DEMO_FLAG: viesMode '${viesMode}' is a local simulation preset; set demo: true to simulate VIES gateway states or use FORMAT_ONLY.`
      );
      err.code = -32602;
      throw err;
    }

    if (!norm.validFormat) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        ...(isDemo ? { sample: true } : {}),
        valid: false,
        formatValid: false,
        status: "HOLD_INVALID_VAT",
        reason: "INVALID_EU_VAT_FORMAT",
        sellerCountry,
        normalizedVatId: norm.fullVatId,
        reverseChargeEligible: false,
        zeroRateAllowed: false,
        consultationId: null,
      };
    }

    const crossBorder = sellerCountry !== norm.memberState;

    if (!isDemo || viesMode === "FORMAT_ONLY") {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        valid: null,
        formatValid: true,
        status: "FORMAT_VALID_UNVERIFIED",
        reason: "LOCAL_FORMAT_CHECK_ONLY_NO_LIVE_VIES_CONSULTATION",
        sellerCountry,
        normalizedVatId: norm.fullVatId,
        memberState: norm.memberState,
        crossBorderSupply: crossBorder,
        reverseChargeEligible: false,
        zeroRateAllowed: false,
        consultationId: null,
        limitations: ["NO_LIVE_VIES_CONSULTATION_NUMBER"],
        upgrade: {
          capability: "live_vies_consultation",
          requires: "REVCLAMP_API_KEY",
          url: "https://revclamp.com/pricing",
        },
      };
    }

    if (viesMode === "MS_UNAVAILABLE" || viesMode === "GLOBAL_MAX_CONCURRENT_REQ") {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        sample: true,
        valid: null,
        formatValid: true,
        status: "PENDING_ASYNC_RETRY",
        reason: `VIES_SOFT_FAULT_${viesMode}`,
        sellerCountry,
        normalizedVatId: norm.fullVatId,
        memberState: norm.memberState,
        reverseChargeEligible: false,
        zeroRateAllowed: false,
        consultationId: null,
      };
    }

    if (viesMode === "INVALID") {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        sample: true,
        valid: false,
        formatValid: true,
        status: "HOLD_INVALID_VAT",
        reason: "VIES_DEFINITE_INVALID",
        sellerCountry,
        normalizedVatId: norm.fullVatId,
        memberState: norm.memberState,
        reverseChargeEligible: false,
        zeroRateAllowed: false,
        consultationId: null,
      };
    }

    return {
      ok: true,
      executionMode: "local_open_source_engine",
      sample: true,
      valid: true,
      formatValid: true,
      status: crossBorder ? "VERIFIED_ZERO_RATED" : "DOMESTIC_TAXABLE_SUPPLY",
      reason: crossBorder ? "VALID_CROSS_BORDER_REVERSE_CHARGE" : "SAME_MEMBER_STATE_DOMESTIC",
      sellerCountry,
      normalizedVatId: norm.fullVatId,
      memberState: norm.memberState,
      reverseChargeEligible: crossBorder,
      zeroRateAllowed: crossBorder,
      consultationId: "DEMO_SAMPLE_NOT_FOR_TAX_AUDIT",
    };
  }

  if (toolName === "revclamp_reconcile_b2b_net_terms") {
    if (
      args.orderId !== undefined &&
      (typeof args.orderId !== "string" ||
        args.orderId.trim().length === 0 ||
        args.orderId.trim().length > 64)
    ) {
      const err = new Error("Invalid params: orderId must be a non-empty string (<= 64 chars).");
      err.code = -32602;
      throw err;
    }
    const orderId = args.orderId !== undefined ? args.orderId.trim() : "ord_local_b2b_01";
    if (
      args.totalOrderCents !== undefined &&
      args.orderTotalCents !== undefined &&
      args.totalOrderCents !== args.orderTotalCents
    ) {
      const err = new Error(
        "CONFLICTING_NET_TERMS_ALIASES: totalOrderCents and orderTotalCents must match when both are provided."
      );
      err.code = -32602;
      throw err;
    }
    const orderTotalCents = args.totalOrderCents ?? args.orderTotalCents;
    if (!Number.isSafeInteger(orderTotalCents) || orderTotalCents <= 0) {
      const err = new Error(
        "INVALID_TOTAL_ORDER_CENTS: totalOrderCents / orderTotalCents must be a positive safe integer."
      );
      err.code = -32602;
      throw err;
    }
    const paidAmountCents = args.paidAmountCents;
    if (
      typeof paidAmountCents !== "number" ||
      !Number.isSafeInteger(paidAmountCents) ||
      paidAmountCents < 0
    ) {
      const err = new Error(
        "INVALID_PAID_AMOUNT_CENTS: paidAmountCents must be a non-negative safe integer."
      );
      err.code = -32602;
      throw err;
    }
    if (
      args.creditNoteCents !== undefined &&
      args.creditNotesCents !== undefined &&
      args.creditNoteCents !== args.creditNotesCents
    ) {
      const err = new Error(
        "CONFLICTING_NET_TERMS_ALIASES: creditNoteCents and creditNotesCents must match when both are provided."
      );
      err.code = -32602;
      throw err;
    }
    const creditNotesCents = args.creditNoteCents ?? args.creditNotesCents ?? 0;
    if (
      !Number.isSafeInteger(creditNotesCents) ||
      creditNotesCents < 0 ||
      creditNotesCents > orderTotalCents
    ) {
      const err = new Error(
        "INVALID_CREDIT_NOTE_CENTS: creditNoteCents must be an integer between 0 and totalOrderCents."
      );
      err.code = -32602;
      throw err;
    }
    const requiredDepositPercent = args.requiredDepositPercent ?? 30;
    const paymentTermsDays = args.paymentTermsDays ?? 30;
    const daysElapsed = args.daysElapsedSinceInvoice ?? 0;
    const toleranceCents = args.toleranceCents ?? 0;
    const maxAllowedToleranceCents = Math.min(
      500,
      orderTotalCents > 1
        ? Math.min(orderTotalCents - 1, Math.max(1, Math.floor(orderTotalCents * 0.01)))
        : 0
    );
    if (
      !Number.isSafeInteger(toleranceCents) ||
      toleranceCents < 0 ||
      toleranceCents > maxAllowedToleranceCents
    ) {
      const err = new Error(
        "INVALID_TOLERANCE_CENTS: toleranceCents must be between 0 and min(500, 1% of totalOrderCents)."
      );
      err.code = -32602;
      throw err;
    }

    const effectiveTotalCents = Math.max(0, orderTotalCents - creditNotesCents);
    const hasExplicitDepositCents = args.requiredDepositCents !== undefined;
    const requiredDepositCents = hasExplicitDepositCents
      ? args.requiredDepositCents
      : Math.ceil((effectiveTotalCents * requiredDepositPercent) / 100);
    if (
      !Number.isSafeInteger(requiredDepositCents) ||
      requiredDepositCents < 0 ||
      requiredDepositCents > effectiveTotalCents
    ) {
      const err = new Error(
        "INVALID_REQUIRED_DEPOSIT_CENTS: requiredDepositCents must be an integer between 0 and effectiveTotalCents."
      );
      err.code = -32602;
      throw err;
    }

    const shortfallRawCents = Math.max(0, effectiveTotalCents - paidAmountCents);
    const overpaidCents = Math.max(0, paidAmountCents - effectiveTotalCents);

    let status = "PAID_IN_FULL";
    let state = "FULLY_RECONCILED";
    let orderTag = "b2b_net_terms:paid_in_full";
    let appliedToleranceCents = 0;
    let remainingBalanceCents = 0;

    if (effectiveTotalCents === 0) {
      status = "REFUNDED_OR_CREDITED";
      state = "REFUNDED_OR_CREDITED";
      orderTag = "b2b_net_terms:refunded_or_credited";
      appliedToleranceCents = 0;
      remainingBalanceCents = 0;
    } else if (overpaidCents > 0) {
      status = "OVERPAID_CREDIT_DUE";
      state = "FULLY_RECONCILED";
      orderTag = "b2b_net_terms:overpaid_credit_due";
      appliedToleranceCents = 0;
      remainingBalanceCents = 0;
    } else if (paidAmountCents < requiredDepositCents) {
      status = "PENDING_DEPOSIT";
      state = "PENDING_DEPOSIT";
      orderTag = "b2b_net_terms:awaiting_deposit";
      appliedToleranceCents = 0;
      remainingBalanceCents = shortfallRawCents;
    } else if (shortfallRawCents <= toleranceCents) {
      status = "PAID_IN_FULL";
      state = "FULLY_RECONCILED";
      orderTag = "b2b_net_terms:paid_in_full";
      appliedToleranceCents = shortfallRawCents;
      remainingBalanceCents = 0;
    } else if (daysElapsed > paymentTermsDays) {
      status = "BALANCE_OVERDUE";
      state = "BALANCE_OVERDUE";
      orderTag = "b2b_net_terms:overdue_balance";
      appliedToleranceCents = 0;
      remainingBalanceCents = shortfallRawCents;
    } else {
      status = "DEPOSIT_MET_NET_ACTIVE";
      state = "DEPOSIT_CLEARED_ACTIVE";
      orderTag = "b2b_net_terms:deposit_cleared_active";
      appliedToleranceCents = 0;
      remainingBalanceCents = shortfallRawCents;
    }

    const fulfillmentAllowed =
      status === "PAID_IN_FULL" ||
      status === "DEPOSIT_MET_NET_ACTIVE" ||
      status === "OVERPAID_CREDIT_DUE";
    const fulfillmentHold = !fulfillmentAllowed && status !== "BALANCE_OVERDUE";
    const doubleEntryBalanced =
      paidAmountCents + remainingBalanceCents + appliedToleranceCents - overpaidCents ===
      effectiveTotalCents;

    const reconciliation = {
      orderId,
      state,
      status,
      orderTag,
      fulfillmentAllowed,
      fulfillmentHold,
      releaseHoldAction: fulfillmentAllowed,
      totalOrderCents: orderTotalCents,
      creditNoteCents: creditNotesCents,
      effectiveTotalCents,
      requiredDepositCents,
      effectivePaidCents: paidAmountCents,
      remainingBalanceCents,
      appliedToleranceCents,
      overpaidCents,
      creditDueCents: overpaidCents,
      overpaidWarning: overpaidCents > 0,
      doubleEntryBalanced,
    };

    return {
      ok: true,
      executionMode: "local_open_source_engine",
      orderId,
      state,
      status,
      orderTag,
      fulfillmentAllowed,
      fulfillmentHold,
      effectiveTotalCents,
      requiredDepositCents,
      effectivePaidCents: paidAmountCents,
      remainingBalanceCents,
      appliedToleranceCents,
      overpaidCents,
      doubleEntryBalanced,
      reconciliation,
    };
  }

  if (toolName === "revclamp_evaluate_ghost_usage") {
    if (
      args.customerId !== undefined &&
      (typeof args.customerId !== "string" ||
        args.customerId.trim().length === 0 ||
        args.customerId.trim().length > 64)
    ) {
      const err = new Error("Invalid params: customerId must be a non-empty string (<= 64 chars).");
      err.code = -32602;
      throw err;
    }
    const topCustomerId =
      typeof args.customerId === "string" ? args.customerId.trim() : "";
    const evObj =
      args.usageEvent && typeof args.usageEvent === "object" && !Array.isArray(args.usageEvent)
        ? args.usageEvent
        : null;
    const evCustomerId = evObj ? extractCanonicalCustomerId(evObj) : "";
    const evEmail = evObj ? normalizeEmailToken(evObj.email || evObj.customer_email) : "";
    if (topCustomerId && evCustomerId && topCustomerId !== evCustomerId) {
      const err = new Error(
        "CONFLICTING_GHOST_USAGE_CUSTOMER_ID: customerId and usageEvent customer_id must match when both are provided."
      );
      err.code = -32602;
      throw err;
    }
    const tsCandidates = [];
    if (args.usageTimestampSec !== undefined) tsCandidates.push(Number(args.usageTimestampSec));
    if (args.occurredAtSec !== undefined) tsCandidates.push(Number(args.occurredAtSec));
    if (evObj && evObj.occurred_at_sec !== undefined) tsCandidates.push(Number(evObj.occurred_at_sec));
    if (evObj && evObj.occurredAtSec !== undefined) tsCandidates.push(Number(evObj.occurredAtSec));
    if (evObj && evObj.timestampSec !== undefined) tsCandidates.push(Number(evObj.timestampSec));
    if (evObj && evObj.usageTimestampSec !== undefined) tsCandidates.push(Number(evObj.usageTimestampSec));
    for (const flexKey of ["occurred_at", "created"]) {
      if (evObj && evObj[flexKey] !== undefined) {
        if (typeof evObj[flexKey] === "number") {
          tsCandidates.push(evObj[flexKey]);
        } else if (typeof evObj[flexKey] === "string" && evObj[flexKey].trim().length > 0) {
          const parsedMs = Date.parse(evObj[flexKey].trim());
          if (Number.isFinite(parsedMs) && parsedMs > 0) {
            tsCandidates.push(Math.floor(parsedMs / 1000));
          }
        }
      }
    }
    if (tsCandidates.length > 1 && new Set(tsCandidates).size > 1) {
      const err = new Error(
        "CONFLICTING_GHOST_USAGE_TIMESTAMPS: usageTimestampSec, occurredAtSec, and usageEvent timestamps must match when multiple are provided."
      );
      err.code = -32602;
      throw err;
    }
    if (!evObj && !topCustomerId && args.demo !== true) {
      const err = new Error(
        "Invalid params: provide customerId or usageEvent (with customer_id / email)."
      );
      err.code = -32602;
      throw err;
    }
    const isSubsArray = Array.isArray(args.subscriptions);
    const isSubsObj =
      !isSubsArray &&
      args.subscriptions !== null &&
      typeof args.subscriptions === "object" &&
      Array.isArray(args.subscriptions.data);
    if (!isSubsArray && !isSubsObj) {
      const err = new Error(
        "Invalid params: subscriptions must be an array or Stripe list object { data: [...] }."
      );
      err.code = -32602;
      throw err;
    }
    const rawSubsList = isSubsArray ? args.subscriptions : args.subscriptions.data;
    const isCompletePagination =
      rawSubsList.length <= 50 &&
      args.subscriptions?.has_more !== true &&
      args.subscriptionsHasMore !== true &&
      (args.subscriptions?.has_more === false || args.subscriptionsHasMore === false);
    const normalizedSubsList = rawSubsList.slice(0, 50).map((s) => {
      if (!s || typeof s !== "object" || Array.isArray(s)) return s;
      if (topCustomerId && !extractCanonicalCustomerId(s) && !s.customer_email && !s.email) {
        return { ...s, customer: topCustomerId };
      }
      return s;
    });
    const normalizedSubsEnv = {
      data: normalizedSubsList,
      has_more: isCompletePagination ? false : true,
    };
    const fallbackTsSec =
      args.usageTimestampSec ??
      args.occurredAtSec ??
      (evObj ? undefined : Math.floor(Date.now() / 1000));
    const normalizedUsageEvent = evObj
      ? {
          ...evObj,
          ...(topCustomerId && !evCustomerId ? { customer_id: topCustomerId } : {}),
          ...(fallbackTsSec !== undefined &&
          evObj.occurred_at === undefined &&
          evObj.occurred_at_sec === undefined &&
          evObj.occurredAtSec === undefined &&
          evObj.timestamp === undefined
            ? { occurred_at_sec: fallbackTsSec }
            : {}),
        }
      : {
          customer_id: topCustomerId || (args.demo === true ? "cus_demo_ghost_01" : ""),
          occurred_at_sec: fallbackTsSec,
        };
    const res = evaluateLocalGhostUsage(
      normalizedSubsEnv,
      normalizedUsageEvent,
      args.dunningGracePeriodDays ?? 3
    );
    return {
      ...res,
      isGhostLeak: res.isGhostUsage,
      evaluation: {
        ...res,
        isGhostLeak: res.isGhostUsage,
      },
    };
  }

  if (toolName === "revclamp_stage_stripe_dispute_ce3") {
    if (Object.hasOwn(args, "submit") && args.submit !== false) {
      const err = new Error(
        "Invalid params: 'submit' parameter must be omitted or false; RevClamp enforces non-destructive staging (submit: false)"
      );
      err.code = -32602;
      throw err;
    }
    if (
      args.disputeId !== undefined &&
      (typeof args.disputeId !== "string" ||
        args.disputeId.trim().length === 0 ||
        args.disputeId.trim().length > 64)
    ) {
      const err = new Error("Invalid params: disputeId must be a non-empty string (<= 64 chars)");
      err.code = -32602;
      throw err;
    }
    if (
      args.customerId !== undefined &&
      (typeof args.customerId !== "string" ||
        args.customerId.trim().length === 0 ||
        args.customerId.trim().length > 64)
    ) {
      const err = new Error("Invalid params: customerId must be a non-empty string (<= 64 chars)");
      err.code = -32602;
      throw err;
    }
    if (
      args.existingAccessActivityLog !== undefined &&
      args.existingUncategorizedText !== undefined &&
      String(args.existingAccessActivityLog).trim() !==
        String(args.existingUncategorizedText).trim()
    ) {
      const err = new Error(
        "CONFLICTING_EXISTING_EVIDENCE_TEXT: existingAccessActivityLog and existingUncategorizedText must match when both are provided."
      );
      err.code = -32602;
      throw err;
    }
    const cleanDisputeId = sanitizeLogToken(args.disputeId || "du_mcp_staged_01", 64);
    const cleanCustomerId = sanitizeLogToken(args.customerId || "cus_mcp_enterprise_01", 64);
    const disputeReason = String(args.disputeReason || "fraudulent").trim();
    const isDemo = args.demo === true;
    const rawEvents = Array.isArray(args.usageEvents) ? args.usageEvents : null;

    if ((!rawEvents || rawEvents.length === 0) && !isDemo) {
      const err = new Error(
        "MISSING_USAGE_EVENTS_OR_WORKSPACE_LEDGER: Provide a non-empty usageEvents array for local staging, set demo: true for a labeled sample preview, or configure REVCLAMP_API_KEY to query the 90-day workspace ledger."
      );
      err.code = -32602;
      throw err;
    }

    const eventsToFormat =
      rawEvents && rawEvents.length > 0
        ? rawEvents
        : [
            {
              occurred_at: "2026-06-15T14:22:10Z",
              event_name: "demo.sample.event",
              customer_id: cleanCustomerId,
            },
          ];

    const formattedLines = [];
    for (const ev of eventsToFormat.slice(0, 200)) {
      if (!ev || typeof ev !== "object") continue;
      const evCus = sanitizeLogToken(extractCanonicalCustomerId(ev), 64);
      if (!evCus || evCus !== cleanCustomerId) {
        continue;
      }
      const tsSec = parseEventTimestampSec(ev);
      const eventName = sanitizeLogToken(ev.event_name, 80);
      if (tsSec === null || !eventName) continue;
      const isoTs = new Date(tsSec * 1000).toISOString().replace(".000Z", "Z");
      const parts = [`${isoTs}`, `event=${eventName}`, `actor=${cleanCustomerId}`];
      const cleanIp = sanitizeLogToken(ev.ip_address || ev.ip, 64);
      if (cleanIp) parts.push(`ip=${cleanIp}`);
      const cleanDev = sanitizeLogToken(ev.device_id || ev.device_fingerprint, 80);
      if (cleanDev) parts.push(`device=${cleanDev}`);
      const cleanModel = sanitizeLogToken(ev.model, 80);
      if (cleanModel) parts.push(`model=${cleanModel}`);
      if (typeof ev.tokens === "number" && Number.isSafeInteger(ev.tokens) && ev.tokens >= 0) {
        parts.push(`tokens=${ev.tokens}`);
      }
      formattedLines.push(parts.join(" | "));
    }

    if (formattedLines.length === 0) {
      const err = new Error(
        "NO_VALID_CUSTOMER_USAGE_EVENTS: None of the supplied usageEvents contained a valid timestamp, event_name, and matching customerId."
      );
      err.code = -32602;
      throw err;
    }

    const MAX_LOG_UTF8_BYTES = 26_000;
    const rawExistingLog =
      typeof args.existingAccessActivityLog === "string"
        ? args.existingAccessActivityLog
        : typeof args.existingUncategorizedText === "string"
          ? args.existingUncategorizedText
          : "";
    const strippedNotes = stripExistingRevClampBlock(rawExistingLog);
    if (!strippedNotes.ok) {
      const rawUtf8Bytes = Buffer.byteLength(rawExistingLog, "utf8");
      const boundedMalformedLog =
        rawExistingLog.length <= MAX_ACCESS_ACTIVITY_LOG_CHARS && rawUtf8Bytes <= MAX_LOG_UTF8_BYTES
          ? rawExistingLog
          : `[Omitted malformed existingAccessActivityLog (${rawExistingLog.length} UTF-16 code units, ${rawUtf8Bytes} UTF-8 bytes) exceeding 18,000-char / 26,000-byte ceiling]`;
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        disputeId: cleanDisputeId,
        customerId: cleanCustomerId,
        skipped: true,
        reason: "MALFORMED_EXISTING_REVCLAMP_BLOCK_MARKERS",
        submit: false,
        evidence: {
          access_activity_log: boundedMalformedLog,
        },
      };
    }
    const preservedMerchantNotes = strippedNotes.text;
    const headerLine = isDemo
      ? `[DEMO SAMPLE - NOT FOR DISPUTE SUBMISSION | dispute=${cleanDisputeId} | customer=${cleanCustomerId} | submit=false]`
      : `[RevClamp Verified Product Usage Log | dispute=${cleanDisputeId} | customer=${cleanCustomerId} | submit=false]`;

    const prefix = preservedMerchantNotes ? `${preservedMerchantNotes}\n\n` : "";
    const fixedEnvelopeChars =
      prefix.length +
      REVCLAMP_START_MARKER.length +
      1 +
      headerLine.length +
      1 +
      REVCLAMP_END_MARKER.length;
    const fixedEnvelopeUtf8Bytes = Buffer.byteLength(
      `${prefix}${REVCLAMP_START_MARKER}\n${headerLine}\n${REVCLAMP_END_MARKER}`,
      "utf8"
    );

    if (
      fixedEnvelopeChars > MAX_ACCESS_ACTIVITY_LOG_CHARS ||
      fixedEnvelopeUtf8Bytes > MAX_LOG_UTF8_BYTES
    ) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        disputeId: cleanDisputeId,
        customerId: cleanCustomerId,
        skipped: true,
        reason: "EXISTING_MERCHANT_NOTES_EXCEED_18K_CEILING",
        submit: false,
        evidence: {},
      };
    }

    const packedLines = [];
    let currentChars = fixedEnvelopeChars;
    let currentUtf8Bytes = fixedEnvelopeUtf8Bytes;
    for (const line of formattedLines) {
      const lineUtf8Bytes = 1 + Buffer.byteLength(line, "utf8");
      if (
        currentChars + 1 + line.length > MAX_ACCESS_ACTIVITY_LOG_CHARS ||
        currentUtf8Bytes + lineUtf8Bytes > MAX_LOG_UTF8_BYTES
      ) {
        break;
      }
      packedLines.push(line);
      currentChars += 1 + line.length;
      currentUtf8Bytes += lineUtf8Bytes;
    }

    const block = [
      REVCLAMP_START_MARKER,
      headerLine,
      ...packedLines,
      REVCLAMP_END_MARKER,
    ].join("\n");

    const merged = `${prefix}${block}`;
    const ce3Qualification = evaluateLocalVisaCe3Qualification(
      disputeReason,
      args.disputedTransaction,
      args.priorTransactions
    );

    return {
      ok: true,
      executionMode: "local_open_source_engine",
      ...(isDemo ? { sample: true } : {}),
      disputeId: cleanDisputeId,
      customerId: cleanCustomerId,
      disputeReason,
      ce3Qualification,
      submit: false,
      utf16CodeUnits: merged.length,
      linesIncluded: packedLines.length,
      evidence: {
        access_activity_log: merged,
      },
      limitations: ["LOCAL_DRAFT_ONLY_NOT_STAGED_TO_STRIPE_API"],
      upgrade: {
        capability: "autonomous_stripe_dispute_staging_and_90d_ledger",
        requires: "REVCLAMP_API_KEY",
        url: "https://revclamp.com/pricing",
      },
    };
  }

  if (toolName === "revclamp_audit_revenue_leakage") {
    const isDemo = args.demo === true;
    const hasCallerCustomers = Array.isArray(args.customers) && args.customers.length > 0;
    const hasCallerEvents = Array.isArray(args.usageEvents) && args.usageEvents.length > 0;
    const costPerEventCents = Number(args.costPerEventCents ?? 142);
    const graceDays = Number(args.dunningGracePeriodDays ?? 3);

    if ((!hasCallerCustomers || !hasCallerEvents) && !isDemo) {
      return {
        ok: true,
        executionMode: "local_open_source_engine",
        statelessEphemeralAudit: true,
        customersEvaluated: hasCallerCustomers ? args.customers.length : 0,
        usageEventsEvaluated: hasCallerEvents ? args.usageEvents.length : 0,
        ghostEventsDetected: 0,
        estimatedMonthlyLeakUsd: 0,
        ce3ReadinessStatus: "NO_CALLER_SNAPSHOT_SUPPLIED",
        limitations: ["NO_WORKSPACE_LEDGER_CONNECTED"],
        upgrade: {
          capability: "persistent_90d_usage_ledger_and_live_stripe_backfill",
          requires: "REVCLAMP_API_KEY",
          url: "https://revclamp.com/pricing",
        },
      };
    }

    const customers = hasCallerCustomers
      ? args.customers
      : [
          {
            id: "cus_demo_sample_01",
            subscriptions: {
              has_more: false,
              data: [
                {
                  customer: "cus_demo_sample_01",
                  status: "canceled",
                  current_period_end: 1750000000,
                },
              ],
            },
          },
        ];
    const events = hasCallerEvents
      ? args.usageEvents
      : [
          {
            customer_id: "cus_demo_sample_01",
            event_name: "demo.inference",
            occurred_at_sec: 1760000000,
          },
        ];

    const subMap = new Map();
    const emailToCustomerIds = new Map();
    const customerEmailById = new Map();
    for (const c of customers) {
      if (c && typeof c === "object" && typeof c.id === "string") {
        const cleanCid = c.id.trim();
        const normEmail = normalizeEmailToken(c.email);
        if (normEmail) {
          customerEmailById.set(cleanCid, normEmail);
          if (!emailToCustomerIds.has(normEmail)) {
            emailToCustomerIds.set(normEmail, new Set());
          }
          emailToCustomerIds.get(normEmail).add(cleanCid);
        }
        const rawSubsEnv =
          c.subscriptions && typeof c.subscriptions === "object"
            ? c.subscriptions
            : { data: [], has_more: true };
        const enrichedData = Array.isArray(rawSubsEnv.data)
          ? rawSubsEnv.data.map((s) =>
              s && typeof s === "object" && !s.customer ? { ...s, customer: cleanCid } : s
            )
          : null;
        subMap.set(cleanCid, { ...rawSubsEnv, data: enrichedData });
      }
    }

    let ghostEventsDetected = 0;
    for (const ev of events) {
      if (!ev || typeof ev !== "object") continue;
      let cid = extractCanonicalCustomerId(ev);
      const evEmail = normalizeEmailToken(ev.email || ev.customer_email);
      if (cid) {
        const expectedEmail = customerEmailById.get(cid);
        if (expectedEmail && evEmail && expectedEmail !== evEmail) {
          continue;
        }
      } else if (evEmail) {
        const matchedIds = emailToCustomerIds.get(evEmail);
        if (!matchedIds || matchedIds.size !== 1) {
          continue;
        }
        cid = [...matchedIds][0];
      }
      const subsEnv = subMap.get(cid);
      if (!subsEnv) continue;
      const evalRes = evaluateLocalGhostUsage(
        subsEnv,
        cid && !ev.customer_id ? { ...ev, customer_id: cid } : ev,
        graceDays
      );
      if (evalRes.isGhostUsage) {
        ghostEventsDetected += 1;
      }
    }

    const estimatedMonthlyLeakUsd = Number(
      ((ghostEventsDetected * costPerEventCents) / 100).toFixed(2)
    );

    return {
      ok: true,
      executionMode: "local_open_source_engine",
      ...(isDemo ? { sample: true } : {}),
      statelessEphemeralAudit: true,
      customersEvaluated: customers.length,
      usageEventsEvaluated: events.length,
      ghostEventsDetected,
      estimatedMonthlyLeakUsd,
      ce3ReadinessStatus: "STATELESS_CALLER_SNAPSHOT_EVALUATED",
      limitations: ["STATELESS_CALLER_SNAPSHOT_ONLY_NO_90D_WORKSPACE_LEDGER"],
      upgrade: {
        capability: "persistent_90d_usage_ledger_and_live_stripe_backfill",
        requires: "REVCLAMP_API_KEY",
        url: "https://revclamp.com/pricing",
      },
    };
  }

  const unknownErr = new Error(`Unknown MCP tool: ${String(toolName || "").trim()}`);
  unknownErr.code = -32602;
  throw unknownErr;
}

function toSafeLocalRpcId(rawId) {
  if (rawId === null || rawId === undefined) return null;
  if (typeof rawId === "number" && Number.isFinite(rawId)) return rawId;
  if (typeof rawId === "string" && /^[A-Za-z0-9._:-]{1,128}$/.test(rawId)) return rawId;
  return null;
}

export function executeLocalMcpJsonRpc(rpcRequest, packageVersion = "1.20.9") {
  if (!rpcRequest || typeof rpcRequest !== "object" || Array.isArray(rpcRequest)) {
    return {
      jsonrpc: "2.0",
      id: null,
      error: {
        code: -32600,
        message: "Invalid JSON-RPC 2.0 request envelope",
      },
    };
  }

  const isNotification =
    !Object.prototype.hasOwnProperty.call(rpcRequest, "id") || rpcRequest.id === undefined;
  const safeId = toSafeLocalRpcId(rpcRequest.id);
  const method = String(rpcRequest.method || "").trim();

  if (method === "notifications/initialized" || isNotification) {
    return null;
  }

  if (rpcRequest.jsonrpc !== "2.0" || !method) {
    return {
      jsonrpc: "2.0",
      id: safeId,
      error: {
        code: -32600,
        message: "Invalid JSON-RPC 2.0 request envelope",
      },
    };
  }

  if (rpcRequest.params !== undefined) {
    const secretScan = scanLocalMcpPayloadForSecrets(rpcRequest.params);
    if (!secretScan.ok) {
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
  }

  if (method === "initialize") {
    const requestedVersion = String(rpcRequest?.params?.protocolVersion || "").trim();
    const negotiatedVersion = SUPPORTED_MCP_PROTOCOL_VERSIONS.includes(requestedVersion)
      ? requestedVersion
      : MCP_PROTOCOL_VERSION;
    return {
      jsonrpc: "2.0",
      id: safeId,
      result: {
        protocolVersion: negotiatedVersion,
        capabilities: {
          tools: { listChanged: false },
          resources: { listChanged: false },
          prompts: { listChanged: false },
        },
        serverInfo: {
          name: "revclamp-mcp",
          version: packageVersion,
        },
      },
    };
  }

  if (method === "ping") {
    return {
      jsonrpc: "2.0",
      id: safeId,
      result: { pong: true, mode: "local_open_source_engine" },
    };
  }

  if (method === "resources/list") {
    return {
      jsonrpc: "2.0",
      id: safeId,
      result: {
        resources: LOCAL_MCP_RESOURCES,
      },
    };
  }

  if (method === "resources/read") {
    const uri = String(rpcRequest?.params?.uri || "").trim();
    const found = LOCAL_MCP_RESOURCES.find((r) => r.uri === uri);
    if (!found) {
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: {
          code: -32602,
          message: `Unknown MCP resource URI: ${uri}`,
        },
      };
    }
    return {
      jsonrpc: "2.0",
      id: safeId,
      result: {
        contents: [
          {
            uri: found.uri,
            mimeType: found.mimeType,
            text: JSON.stringify({
              name: "revclamp-mcp",
              version: packageVersion,
              localExecution: "9 deterministic tools in local_engine.mjs (0 network calls by default)",
              cloudCapabilities: [
                "90-day SQLite WAL usage & audit ledger",
                "24/7 autonomous Stripe dispute & entitlement webhook outbox",
                "Live EU Commission VIES SOAP consultation numbers (viesMode: 'LIVE')",
              ],
              tierEventCaps: TIER_EVENT_CAPS,
              pricingUrl: "https://revclamp.com/pricing",
            }),
          },
        ],
      },
    };
  }

  if (method === "prompts/list") {
    return {
      jsonrpc: "2.0",
      id: safeId,
      result: {
        prompts: LOCAL_MCP_PROMPTS,
      },
    };
  }

  if (method === "prompts/get") {
    const promptName = String(rpcRequest?.params?.name || "").trim();
    const found = LOCAL_MCP_PROMPTS.find((p) => p.name === promptName);
    if (!found) {
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: {
          code: -32602,
          message: `Unknown MCP prompt: ${promptName}`,
        },
      };
    }
    const sellerCountry = String(rpcRequest?.params?.arguments?.sellerCountry || "DE")
      .trim()
      .toUpperCase();
    return {
      jsonrpc: "2.0",
      id: safeId,
      result: {
        description: found.description,
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Run a deterministic RevClamp compliance check (sellerCountry=${sellerCountry}) using revclamp_evaluate_ghost_usage, revclamp_lint_dispute_evidence, and revclamp_validate_eu_vat_vies.`,
            },
          },
        ],
      },
    };
  }

  if (method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id: safeId,
      result: {
        tools: LOCAL_MCP_TOOLS,
      },
    };
  }

  if (method === "tools/call") {
    const toolName = String(rpcRequest?.params?.name || "").trim();
    const rawToolArgs =
      rpcRequest?.params?.arguments === undefined ? {} : rpcRequest.params.arguments;
    if (!rawToolArgs || typeof rawToolArgs !== "object" || Array.isArray(rawToolArgs)) {
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: {
          code: -32602,
          message: "Invalid params: arguments must be a JSON object",
        },
      };
    }
    const toolSpec = LOCAL_MCP_TOOLS.find((t) => t.name === toolName);
    if (!toolSpec) {
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: {
          code: -32602,
          message: `Unknown MCP tool: ${toolName}`,
        },
      };
    }

    const normalizedRes = normalizeMcpToolArgs(toolName, rawToolArgs);
    if (!normalizedRes.ok) {
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: {
          code: -32602,
          message: normalizedRes.message,
          data: {
            error: normalizedRes.error,
            reason: normalizedRes.error,
            ...(normalizedRes.canonicalKey ? { canonicalKey: normalizedRes.canonicalKey } : {}),
          },
        },
      };
    }
    const toolArgs = normalizedRes.args;

    const exampleCallMap = {
      revclamp_verify_webhook_signature: {
        provider: "stripe",
        secret: "whsec_test_secret_revclamp_2026",
        rawPayload: '{"id":"evt_test_01","type":"customer.subscription.deleted"}',
        toleranceSec: 300,
        demo: true,
      },
      revclamp_simulate_webhook_replay: {
        scenarioPreset: "out_of_order_stale_update_after_cancel",
        demo: true,
      },
    };

    let effectiveToolArgs = toolArgs;
    if (
      toolName === "revclamp_stage_stripe_dispute_ce3" &&
      toolArgs &&
      typeof toolArgs === "object" &&
      !Array.isArray(toolArgs) &&
      Object.hasOwn(toolArgs, "submit")
    ) {
      if (toolArgs.submit !== false) {
        return {
          jsonrpc: "2.0",
          id: safeId,
          error: {
            code: -32602,
            message:
              "Invalid params: 'submit' parameter must be omitted or false; RevClamp enforces non-destructive staging (submit: false)",
          },
        };
      }
      const { submit: _ignoredSubmit, ...restArgs } = toolArgs;
      effectiveToolArgs = restArgs;
    }

    const schemaCheck = validateArgsAgainstSchema(toolSpec.inputSchema, effectiveToolArgs);
    if (!schemaCheck.ok) {
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: {
          code: -32602,
          message: `Invalid params: ${schemaCheck.message}`,
          ...(exampleCallMap[toolName]
            ? {
                data: {
                  tool: toolName,
                  reason: "SCHEMA_VALIDATION_ERROR",
                  exampleCall: exampleCallMap[toolName],
                },
              }
            : {}),
        },
      };
    }

    try {
      const structuredContent = executeLocalMcpTool(toolName, effectiveToolArgs);
      let responseObj = {
        jsonrpc: "2.0",
        id: safeId,
        result: {
          content: [
            {
              type: "text",
              text: JSON.stringify(structuredContent),
            },
          ],
          structuredContent,
          isError: false,
        },
      };
      let serializedBytes = Buffer.byteLength(JSON.stringify(responseObj), "utf8");
      if (serializedBytes > 32_768) {
        const compactForText =
          structuredContent &&
          typeof structuredContent === "object" &&
          structuredContent.evidence &&
          typeof structuredContent.evidence.access_activity_log === "string"
            ? {
                ...structuredContent,
                evidence: {
                  ...structuredContent.evidence,
                  access_activity_log: `[Omitted in text mirror to respect 32,768-byte cap; full ${structuredContent.evidence.access_activity_log.length} UTF-16 code unit draft is in result.structuredContent.evidence.access_activity_log]`,
                },
              }
            : structuredContent;
        responseObj = {
          jsonrpc: "2.0",
          id: safeId,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify(compactForText),
              },
            ],
            structuredContent,
            isError: false,
          },
        };
        serializedBytes = Buffer.byteLength(JSON.stringify(responseObj), "utf8");
        if (
          serializedBytes > 32_768 &&
          structuredContent &&
          typeof structuredContent === "object" &&
          structuredContent.evidence &&
          typeof structuredContent.evidence.access_activity_log === "string"
        ) {
          const compactBoth = {
            ...structuredContent,
            evidence: {
              ...structuredContent.evidence,
              access_activity_log: `[Omitted to respect 32,768-byte JSON-RPC envelope cap; original draft was ${structuredContent.evidence.access_activity_log.length} UTF-16 code units]`,
            },
          };
          responseObj = {
            jsonrpc: "2.0",
            id: safeId,
            result: {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(compactBoth),
                },
              ],
              structuredContent: compactBoth,
              isError: false,
            },
          };
          serializedBytes = Buffer.byteLength(JSON.stringify(responseObj), "utf8");
        }
      }
      if (serializedBytes > 32_768) {
        return {
          jsonrpc: "2.0",
          id: safeId,
          error: {
            code: -32603,
            message: "Local MCP response exceeded 32,768-byte ceiling",
          },
        };
      }
      return responseObj;
    } catch (err) {
      const errCode = Number.isInteger(err?.code) ? err.code : -32603;
      return {
        jsonrpc: "2.0",
        id: safeId,
        error: {
          code: errCode,
          message: err instanceof Error ? err.message : "Tool execution failed",
          ...(errCode === -32602 && (err?.reason || exampleCallMap[toolName])
            ? {
                data: {
                  tool: toolName,
                  error: err?.reason || "INVALID_TOOL_PARAMS",
                  reason: err?.reason || "INVALID_TOOL_PARAMS",
                  ...(exampleCallMap[toolName] ? { exampleCall: exampleCallMap[toolName] } : {}),
                },
              }
            : {}),
        },
      };
    }
  }

  return {
    jsonrpc: "2.0",
    id: safeId,
    error: {
      code: -32601,
      message: `Method not found: ${method}`,
    },
  };
}
