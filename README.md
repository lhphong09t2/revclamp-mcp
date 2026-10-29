# RevClamp MCP Server & CLI (`revclamp-mcp`)

[![RevClamp Enterprise — B2B Revenue & Compliance Guardrails](https://revclamp.com/assets/revclamp-product-banner.png)](https://revclamp.com)

**`revclamp-mcp`** is a standalone, zero-dependency **Open-Source Model Context Protocol (MCP) Server & CLI** (`index.mjs` + `local_engine.mjs`) implementing **9 deterministic B2B FinOps, Stripe `2025-03-31.basil`, Visa CE 3.0, EU/XI VIES VAT, Shopify Plus B2B Net-15/30/60, and Webhook Security tools** in pure Node.js.

- **100% Local In-Process Execution (Default — Zero Network / Zero API Key Required):** All 9 MCP tools (`initialize`, `tools/list`, and `tools/call`) execute locally in-process inside [`local_engine.mjs`](./local_engine.mjs) using pure Node.js (`node:crypto` HMAC-SHA256 verification, integer-cent double-entry accounting, 72-hour webhook replay state machines, and `18,000` UTF-16 code unit CE 3.0 linting). Zero network calls are ever made unless `REVCLAMP_API_KEY` or `REVCLAMP_MCP_URL` is explicitly configured.
- **Optional Hosted Cloud Workspace Sync (`REVCLAMP_API_KEY`):** When `REVCLAMP_API_KEY` (`rg_live_...`) is configured, `revclamp-mcp` connects to [**RevClamp Enterprise**](https://revclamp.com) (`https://api.revclamp.com/api/mcp`) to unlock the **90-day durable transactional usage & audit ledger**, **24/7 autonomous Stripe dispute & entitlement webhook outbox**, and **real-time EU Commission VIES SOAP gateway consultation numbers**.

## Local Open-Core (`local_engine.mjs`) vs. Hosted Cloud (`REVCLAMP_API_KEY`)

| Capability | Local Open-Core Default (Zero API Key) | Hosted Cloud (`REVCLAMP_API_KEY`) |
| :--- | :--- | :--- |
| **Execution & Network** | 100% in-process (`local_engine.mjs`), zero network calls | HTTPS JSON-RPC to `https://api.revclamp.com/api/mcp` (`redirect: "error"`) |
| **Usage & Audit Storage** | Stateless evaluation of caller-supplied JSON snapshots | **Persistent 90-day durable transactional ledger** + Stripe historical backfill |
| **Dispute & Entitlement Action** | Returns non-destructive `submit: false` draft & `revoke_entitlement` decision | **24/7 autonomous Stripe webhook outbox** (`disputes.update` & signed revoke webhooks) |
| **EU & `XI` B2B VAT (`VIES`)** | Deterministic syntax & `GR -> EL` normalization (`FORMAT_ONLY` default, `valid: null`) | **Live EU Commission VIES SOAP consultation IDs** + circuit-breaker retry queue (`viesMode: "LIVE"` + `REVCLAMP_API_KEY`) |
| **Monthly Event Tiers** | Unlimited local in-process evaluations (0 network cost) | **Free Sandbox** (`5,000` events/mo) · **Starter $19/mo** (`100k`) · **Growth $59/mo** (`1M`) · **Scale $199/mo** (`5M`) |
| **Data Minimization & Privacy** | Nothing ever leaves your machine | Only explicit `tools/call` arguments are sent over TLS after local live-secret scrubbing (blocks `sk_live_`, non-test `whsec_`, and `shpat_` locally before any network request) |

## Open-Source MCP Tools Implemented in `local_engine.mjs` (9)

| Tool Name | Domain | Local In-Process Implementation (`local_engine.mjs`) | Execution Mode |
| :---: | :---: | :---: | :---: |
| `revclamp_audit_revenue_leakage` | Stripe Billing & Usage | Evaluates caller-supplied customer/usage arrays (`demo: true` for synthetic sample) and returns upgrade hooks when no workspace ledger is connected | Local In-Process (or Optional Cloud Key) |
| `revclamp_evaluate_ghost_usage` | Stripe `2025-03-31.basil` | Evaluates multi-subscription customer snapshots (`has_more: false` enforced) and 0–14d dunning grace windows for unpaid API/LLM bleed | Local In-Process (or Optional Cloud Key) |
| `revclamp_stage_stripe_dispute_ce3` | Visa 10.4 / CE 3.0 | Evaluates 120d–365d prior undisputed charges (`ip_subnet`/`device_id` overlap) against caller-supplied `usageEvents` (`demo: true` for sample) and stages a non-destructive `submit: false` draft (`<= 18,000` UTF-16 code units) | Local In-Process (or Optional Cloud Key) |
| `revclamp_validate_eu_vat_vies` | EU & `XI` B2B VAT | Normalizes 27 EU member states + Northern Ireland (`XI`) VAT IDs (`GR -> EL`), checks syntax locally (`FORMAT_ONLY`, `valid: null`), simulates `errorWrappers` (`demo: true`), or queries live EU VIES (`viesMode: "LIVE"` + `REVCLAMP_API_KEY`) | Local In-Process (or Optional Live VIES) |
| `revclamp_reconcile_b2b_net_terms` | B2B Wholesale Net-30 | Reconciles Net-15/30/60 upfront deposits and credit notes using integer EUR-cent double-entry accounting | Local In-Process (or Optional Cloud Key) |
| `revclamp_verify_webhook_signature` | Webhook HMAC-SHA256 | Generates and verifies `Stripe-Signature`, `X-Shopify-Hmac-Sha256`, and `X-RevClamp-Signature` over raw UTF-8 bytes (`node:crypto`) with 300s replay checks | Local In-Process (or Optional Cloud Key) |
| `revclamp_calculate_roi_and_plan_fit` | 0% Take-Rate ROI & Plan Fit | Calculates monthly and annual B2B margin savings in integer USD cents vs. 25%–30% chargeback agencies and recommends the optimal tier | Local In-Process (or Optional Cloud Key) |
| `revclamp_simulate_webhook_replay` | Webhook Replay & FSM | Simulates subscription lifecycle webhooks against a 72h deduplication `Set` and monotonic `createdSec` guard vs. naive arrival-order handlers | Local In-Process (or Optional Cloud Key) |
| `revclamp_lint_dispute_evidence` | Dispute Evidence UTF-16 & CE 3.0 | Lints `evidence[access_activity_log]` payloads against the 18,000 UTF-16 code unit ceiling, non-destructive CE 3.0 markers, and merchant note preservation | Local In-Process (or Optional Cloud Key) |

## Quick Start (Claude Desktop / Cursor / Windsurf)

Add `revclamp-mcp` to your `claude_desktop_config.json` or `.cursor/mcp.json`. By default, `revclamp-mcp` runs **100% locally in-process** with zero network calls and zero API keys required:

```json
{
  "mcpServers": {
    "revclamp": {
      "command": "npx",
      "args": ["-y", "github:lhphong09t2/revclamp-mcp"]
    }
  }
}
```

*(Optional)* To connect to a live workspace on [`https://revclamp.com/dashboard`](https://revclamp.com/dashboard), pass `REVCLAMP_API_KEY` in `env` or use the hosted Streamable HTTP endpoint (`POST https://api.revclamp.com/api/mcp`):

```bash
curl -sS -X POST https://api.revclamp.com/api/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## CLI Usage & `<60s` Local Smoke Check (`--self-test`)

```bash
# Run a <60s local CLI smoke check (verifies all 9 tool schemas & executes a local_engine.mjs sample audit with zero API key)
npx -y github:lhphong09t2/revclamp-mcp#v1.20.11 --self-test

# Provision a free Cloud Workspace (or reuse REVCLAMP_API_KEY) & send a 6-digit login OTP
npx -y revclamp-mcp@1.20.11 --init-workspace you@company.com

# Verify the 6-digit OTP using REVCLAMP_API_KEY from environment
REVCLAMP_API_KEY="rg_live_..." npx -y revclamp-mcp@1.20.11 --verify-otp you@company.com 123456

# List all 9 MCP tools and JSON schemas (runs locally in-process)
node index.mjs --list-tools

# Validate an EU or Northern Ireland (XI) B2B VAT ID (auto-converts Greece GR -> EL)
node index.mjs --check-vat GR123456789 DE

# Calculate 0% take-rate ROI and optimal flat-rate plan fit (runs locally in-process)
node index.mjs --calc-roi 10000 600 25 250000

# Simulate out-of-order webhook replay and 72-hour deduplication state machine (runs locally)
node index.mjs --sim-replay out_of_order_stale_update_after_cancel

# Lint Stripe dispute evidence UTF-16 code units and non-destructive CE 3.0 markers (runs locally)
node index.mjs --lint-evidence valid_ce3_non_destructive

# Verify webhook HMAC-SHA256 using REVCLAMP_WEBHOOK_SECRET from environment (runs locally)
REVCLAMP_WEBHOOK_SECRET="whsec_test_secret_revclamp_sandbox_2026" node index.mjs --verify-webhook stripe

# Invoke Visa CE 3.0 readiness staging locally (pass demo: true for synthetic sample or usageEvents for real logs)
node index.mjs --call revclamp_stage_stripe_dispute_ce3 '{"disputeId":"du_1Qxyz01","customerId":"cus_ent_88","disputeReason":"fraudulent","demo":true}'
```

## Architecture & Engineering Deep-Dives (7 Post-Mortems & 8 Interactive Browser Tools)

### 1. Stripe `2025-03-31.basil` Entitlement Guard & Visa CE 3.0 Two-Tier Routing

![Stripe basil entitlement and CE 3.0 flowchart](https://revclamp.com/assets/stripe-basil-ce3-flowchart.png?v=2)

- **Engineering Post-Mortem #1:** [Stripe's `basil` API broke my grace-period logic, and CE 3.0 turned out to be a routing problem](https://revclamp.com/blog/stripe-basil-ce3-routing)
- **Engineering Post-Mortem #7:** [Visa CE 3.0 `18,000` UTF-16 Code Unit Evidence Truncation & Non-Destructive Staging](https://revclamp.com/blog/visa-ce3-18k-utf16-evidence-truncation-pitfalls)
- **Interactive Tools (No Signup):**
  - [Free Stripe `2025-03-31.basil` Ghost-Usage Auditor](https://revclamp.com/tools/stripe-basil-auditor)
  - [Free Visa CE 3.0 Readiness Checker](https://revclamp.com/tools/stripe-ce3-checker)
  - [Free 18,000 UTF-16 Stripe Dispute Evidence Linter](https://revclamp.com/tools/stripe-dispute-evidence-char-counter)

### 2. EU VIES `HTTP 200 OK` Soft-Failure Circuit Breaker & B2B Net-Terms Reconciliation

![EU VIES circuit breaker flowchart](https://revclamp.com/assets/eu-vies-circuit-breaker-flowchart.png?v=2)

- **Engineering Post-Mortem #2:** [VIES returns `HTTP 200` when it's down, and I charged the wrong VAT because of it](https://revclamp.com/blog/eu-vies-http200-circuit-breaker)
- **Engineering Post-Mortem #3:** [Shopify Plus B2B Net-15/30/60 Integer-Cent Deposit & Credit-Note Reconciliation](https://revclamp.com/blog/shopify-b2b-net-terms-integer-cent-reconciliation)
- **Interactive Tools (No Signup):**
  - [Free 20-ID EU & `XI` VIES VAT Batch Validator](https://revclamp.com/tools/vies-vat-validator)
  - [Free Shopify Plus B2B Net-Terms Deposit & Credit-Note Calculator](https://revclamp.com/tools/b2b-net-terms-calculator)

### 3. Webhook HMAC-SHA256 Raw-Body Security, 72h Replay FSM & 0% Take-Rate ROI

- **Engineering Post-Mortem #4:** [Why Stripe and Shopify Webhook HMAC-SHA256 Verification Fails on Parsed JSON Bodies](https://revclamp.com/blog/stripe-shopify-webhook-hmac-raw-body-pitfalls)
- **Engineering Post-Mortem #5:** [Chargeback Contingency Fees (25%–30%) vs. Flat-Rate 0% Commission Automation](https://revclamp.com/blog/chargeback-contingency-fees-vs-flat-rate-roi)
- **Engineering Post-Mortem #6:** [Webhook Idempotency & Out-of-Order Subscription State Machines](https://revclamp.com/blog/webhook-idempotency-out-of-order-state-machines)
- **Interactive Tools (No Signup):**
  - [Free Stripe, Shopify & RevClamp Webhook HMAC-SHA256 Signature Tester](https://revclamp.com/tools/webhook-signature-tester)
  - [Free B2B Chargeback ROI & Take-Rate Calculator](https://revclamp.com/tools/b2b-chargeback-roi-calculator)
  - [Free 72h Webhook Replay & Out-of-Order State Machine Simulator](https://revclamp.com/tools/webhook-replay-simulator)

## Security & Resource Bounds

- **Local-First Deterministic Execution:** Runs all 9 tools locally in-process inside `local_engine.mjs` with zero external npm dependencies.
- **Strict Origin Pinning (Cloud Mode):** When `REVCLAMP_API_KEY` is provided, only connects to `https://api.revclamp.com/api/mcp` or `https://revclamp.com/api/mcp` over TLS (`redirect: "error"`).
- **Bounded Execution:** Enforces a hard `10,000ms` request timeout (`AbortSignal.timeout`) and a `32,768`-byte request/response payload cap.
- **Full LLM Reference:** [`https://revclamp.com/llms-full.txt`](https://revclamp.com/llms-full.txt)

## License

MIT © [RevClamp Enterprise](https://revclamp.com)
