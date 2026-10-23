# RevClamp MCP Server & CLI (`revclamp-mcp`)

[![RevClamp Enterprise — B2B Revenue & Compliance Guardrails](https://revclamp.com/assets/revclamp-product-banner.png)](https://revclamp.com)

**`revclamp-mcp`** is the official Model Context Protocol (MCP) `stdio` bridge and CLI diagnostic client for [**RevClamp Enterprise**](https://revclamp.com). It connects Claude Desktop, Cursor, Windsurf, Cline, and CI pipelines to RevClamp's Streamable HTTP MCP endpoint (`POST https://api.revclamp.com/api/mcp`) with zero external npm dependencies.

## Exposed MCP Tools (7)

| Tool Name | Domain | Primary Capability | Mode |
| :---: | :---: | :---: | :---: |
| `revclamp_audit_revenue_leakage` | Stripe Billing & Usage | Runs a 90-day B2B revenue leakage and dispute readiness audit across subscriptions, usage events, and disputes | Stateless Sandbox or Workspace Key |
| `revclamp_evaluate_ghost_usage` | Stripe `2025-03-31.basil` | Evaluates multi-subscription customer snapshots (`has_more: false` enforced) and 0–14d dunning grace windows for unpaid API/LLM bleed | Stateless Sandbox or Workspace Key |
| `revclamp_stage_stripe_dispute_ce3` | Visa 10.4 / CE 3.0 | Evaluates 120d–365d prior undisputed charges (`ip_subnet`/`device_id` overlap) and stages a `submit: false` draft (`<= 18,000` UTF-16 code units) | Stateless Sandbox or Workspace Key |
| `revclamp_validate_eu_vat_vies` | EU & `XI` B2B VAT | Normalizes 27 EU member states + Northern Ireland (`XI`) VAT IDs (`GR -> EL`) and evaluates VIES `HTTP 200` `errorWrappers` holds | Stateless Sandbox or Workspace Key |
| `revclamp_reconcile_b2b_net_terms` | B2B Wholesale Net-30 | Reconciles Net-15/30/60 upfront deposits and credit notes using integer EUR-cent accounting | Stateless Sandbox or Workspace Key |
| `revclamp_verify_webhook_signature` | Webhook HMAC-SHA256 | Generates and verifies `Stripe-Signature`, `X-Shopify-Hmac-Sha256`, and `X-RevClamp-Signature` over raw UTF-8 bytes with 300s replay checks | Stateless Sandbox or Workspace Key |
| `revclamp_calculate_roi_and_plan_fit` | 0% Take-Rate ROI & Plan Fit | Calculates monthly and annual B2B margin savings in integer USD cents vs. 25%–30% chargeback agencies and recommends the optimal tier | Stateless Sandbox or Workspace Key |

## Quick Start (Claude Desktop / Cursor / Windsurf)

Add `revclamp-mcp` to your `claude_desktop_config.json` or `.cursor/mcp.json`. Omit `REVCLAMP_API_KEY` to run in **Stateless Sandbox Mode** (zero database writes), or pass your `rg_live_...` workspace key from [`https://revclamp.com/dashboard`](https://revclamp.com/dashboard):

```json
{
  "mcpServers": {
    "revclamp": {
      "command": "npx",
      "args": ["-y", "github:lhphong09t2/revclamp-mcp"],
      "env": {
        "REVCLAMP_API_KEY": "rg_live_YOUR_WORKSPACE_KEY"
      }
    }
  }
}
```

Or connect directly via **Streamable HTTP** (`JSON-RPC 2.0`) without installing a local binary:

```bash
curl -sS -X POST https://api.revclamp.com/api/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

## CLI Usage

```bash
# List all 7 MCP tools and JSON schemas
node index.mjs --list-tools

# Validate an EU or Northern Ireland (XI) B2B VAT ID (auto-converts Greece GR -> EL)
node index.mjs --check-vat GR123456789 DE

# Calculate 0% take-rate ROI and optimal flat-rate plan fit
node index.mjs --calc-roi 10000 600 25 250000

# Invoke Visa CE 3.0 readiness staging in Stateless Sandbox mode
node index.mjs --call revclamp_stage_stripe_dispute_ce3 '{"disputeId":"du_1Qxyz01","customerId":"cus_ent_88","disputeReason":"fraudulent"}'
```

## Architecture & Engineering Deep-Dives

### 1. Stripe `2025-03-31.basil` Entitlement Guard & Visa CE 3.0 Two-Tier Routing

![Stripe basil entitlement and CE 3.0 flowchart](https://revclamp.com/assets/stripe-basil-ce3-flowchart.png?v=2)

- **Engineering Post-Mortem:** [Stripe's `basil` API broke my grace-period logic, and CE 3.0 turned out to be a routing problem](https://revclamp.com/blog/stripe-basil-ce3-routing)
- **Interactive Tool (No Signup):** [Free Visa CE 3.0 Readiness Checker](https://revclamp.com/tools/stripe-ce3-checker)

### 2. EU VIES `HTTP 200 OK` Soft-Failure Circuit Breaker & Reverse-Charge Vault

![EU VIES circuit breaker flowchart](https://revclamp.com/assets/eu-vies-circuit-breaker-flowchart.png?v=2)

- **Engineering Post-Mortem:** [VIES returns `HTTP 200` when it's down, and I charged the wrong VAT because of it](https://revclamp.com/blog/eu-vies-http200-circuit-breaker)
- **Interactive Tool (No Signup):** [Free 20-ID EU & `XI` VIES VAT Batch Validator](https://revclamp.com/tools/vies-vat-validator)

## Security & Resource Bounds

- **Strict Origin Pinning:** Only connects to `https://api.revclamp.com/api/mcp` or `https://revclamp.com/api/mcp` over TLS (`redirect: "error"`). Rejects non-HTTPS protocols, embedded credentials, and untrusted origins.
- **Bounded Execution:** Enforces a hard `10,000ms` request timeout (`AbortSignal.timeout`) and a `32,768`-byte request/response payload cap.
- **Full LLM Reference:** [`https://revclamp.com/llms-full.txt`](https://revclamp.com/llms-full.txt)

## License

MIT © [RevClamp Enterprise](https://revclamp.com)
