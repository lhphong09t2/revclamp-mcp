# RevClamp ContactPulse - B2B Domain Contact, RFC 9116 & Deliverability Enricher (`@revclamp/b2b-domain-contact-enricher-mcp`)

[![RevClamp ContactPulse Banner](https://revclamp.com/assets/revclamp-product-banner.png)](https://revclamp.com)

Deterministic B2B Domain Contact, RFC 9116 `/.well-known/security.txt`, Schema.org `ContactPoint` JSON-LD, de-obfuscated email & social profile extractor, and DNS-over-HTTPS (`MX` / `SPF` / `DMARC`) deliverability posture enricher over **Model Context Protocol (MCP `2025-06-18` `stdio`)** and **Apify Pay-per-Event**.

> **Independent Tool Notice:** RevClamp ContactPulse is an independent B2B intelligence tool developed by RevClamp Engineering. All company domains and trademarks referenced in examples belong to their respective owners.

---

## Key Capabilities

1. **Multi-Surface B2B Role Contact Extraction & De-Obfuscation:**
   - Parses Schema.org `Organization` / `ContactPoint` JSON-LD blocks, `mailto:` anchors, Cloudflare `data-cfemail` hex-encoded strings, and HTML entity / bracketed obfuscations (`[at]`, `(at)`, `&#64;`, `&#x40;`).
   - Automatically prunes false-positive tracker/asset addresses (`*@*.ingest.sentry.io`, `*@sentry.wixpress.com`, `example.com`, image filename collisions like `logo@2x.png`).
   - Classifies every verified contact into canonical B2B functional roles: `SECURITY`, `PRIVACY_DPO`, `BILLING_FINANCE`, `LEGAL`, `SUPPORT`, `SALES`, `PRESS`, and `GENERAL`.
2. **RFC 9116 `/.well-known/security.txt` & `/security.txt` Compliance Parser:**
   - Parses `Contact:`, `Expires:`, `Encryption:`, `Acknowledgments:`, `Policy:`, `Hiring:`, `Canonical:`, and `Preferred-Languages:`.
   - Evaluates expiration timestamps into deterministic statuses (`VALID_ACTIVE`, `EXPIRED`, `MISSING_EXPIRES`, `NOT_FOUND`).
3. **DNS-over-HTTPS (`DoH`) `MX` / `SPF` / `_dmarc` Deliverability Posture:**
   - Resolves `MX`, `TXT` (`v=spf1`), and `_dmarc.<domain>` (`v=DMARC1`) via Cloudflare and Google DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query` & `https://dns.google/resolve`).
   - Fingerprints the enterprise email gateway (`GOOGLE_WORKSPACE`, `MICROSOFT_365`, `PROTONMAIL`, `FASTMAIL`, `PROOFPOINT`, `MIMECAST`, `AMAZONSES`, `CUSTOM_MX`, `NONE`) and computes a deterministic `deliverabilityGrade` (`A+`, `A`, `B`, `C`, `D`, `F`).
4. **Zero-Trust SSRF Port-443 Guard & 30 KB MCP Envelope Ceiling:**
   - Enforces `https:` port `443` only, blocks IPv4/IPv6 literals, `localhost`, `.local`, `.internal`, and cloud metadata hosts, re-validates every `3xx` redirect target (`redirect: "manual"`), and enforces a `30,000`-byte UTF-8 JSON-RPC ceiling with automatic `rcd1_` cursor rewind.

---

## 1. Apify Store Cloud, Clay / n8n & REST API Quick Start

Run **RevClamp ContactPulse** in the cloud on [Apify Store (`revclamp/b2b-domain-contact-enricher-mcp`)](https://apify.com/revclamp/b2b-domain-contact-enricher-mcp) with zero local setup, or trigger it directly from **Clay**, **n8n**, **Make**, or any HTTP pipeline via the Apify REST API:

```bash
curl -s -X POST \
  "https://api.apify.com/v2/acts/revclamp~b2b-domain-contact-enricher-mcp/run-sync-get-dataset-items" \
  -H "Authorization: Bearer $APIFY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "stripe.com, linear.app, cloudflare.com",
    "includeDnsPosture": true,
    "includeSecurityTxt": true,
    "maxResults": 5
  }'
```

### Transparent Pay-per-Event Pricing & Free-Tier Credit Math

- **Event Price:** `$0.0020` per enriched B2B domain profile (`domain-contact-profile-enriched`).
- **What `$1.00` in Free Apify Credits Gets You:** Approximately **`~500` enriched B2B domain profiles** with role-classified organizational contacts (`SECURITY`, `PRIVACY_DPO`, `BILLING_FINANCE`, `LEGAL`, `SUPPORT`, `SALES`, `PRESS`), RFC 9116 `/.well-known/security.txt` audit, and DNS-over-HTTPS `MX`/`SPF`/`DMARC` deliverability grades.
- **Zero-Waste Billing Guarantee:** You pay **`$0.00`** on `EMPTY_RESULT`, `INVALID_INPUT`, or upstream rate limits. Only verified, non-empty B2B domain profiles delivered to your Dataset are billed.

---

## 2. Local AI Agent & MCP Server Quick Start (`stdio` & CLI)

Run directly via `npx` (supports natural parameter aliases `query`, `domain`, `domains`, or `url`):

```bash
# Start MCP JSON-RPC 2.0 server over stdio
npx -y @revclamp/b2b-domain-contact-enricher-mcp --mcp-stdio

# Run built-in self-test
npx -y @revclamp/b2b-domain-contact-enricher-mcp --self-test

# Inspect exposed MCP tools
npx -y @revclamp/b2b-domain-contact-enricher-mcp --list-tools

# Call a tool directly from CLI
npx -y @revclamp/b2b-domain-contact-enricher-mcp --call resolve_b2b_domain_contacts '{"domain":"stripe.com"}'
```

### Claude Desktop / Cursor / Windsurf Configuration

```json
{
  "mcpServers": {
    "revclamp-contactpulse": {
      "command": "npx",
      "args": ["-y", "@revclamp/b2b-domain-contact-enricher-mcp", "--mcp-stdio"]
    }
  }
}
```

---

## Exposed MCP Tools (3)

| Tool Name | Description |
|---|---|
| `resolve_b2b_domain_contacts` | Enriches 1 to 25 B2B domains with role-classified emails (`SECURITY`, `PRIVACY_DPO`, `BILLING_FINANCE`, `LEGAL`, `SUPPORT`, `SALES`, `PRESS`, `GENERAL`), RFC 9116 `security.txt` disclosures, verified social links, and DNS `MX`/`SPF`/`DMARC` deliverability grades. |
| `inspect_domain_dns_and_security_txt` | Performs a focused RFC 9116 `/.well-known/security.txt` and DNS-over-HTTPS (`MX`, `SPF`, `_dmarc`) inspection for a single B2B domain. |
| `verify_email_deliverability_posture` | Evaluates an email address or domain against `MX` gateway availability, `SPF` qualifier strictness (`-all` vs `~all`), `DMARC` policy (`p=reject` / `quarantine` / `none`), and role-account classification. |

---

## Companion Web Playground & Ecosystem Links

- **Interactive Browser Playground:** [https://revclamp.com/tools/b2b-domain-contact-enricher](https://revclamp.com/tools/b2b-domain-contact-enricher)
- **RevClamp MCP Hub:** [https://revclamp.com/mcp#mcp-contactpulse-companion-card](https://revclamp.com/mcp#mcp-contactpulse-companion-card)

---

## Data Processing & B2B Role-Mailbox Policy

- **Role-Based organizational mailboxes only (No Personal Data):** ContactPulse strictly extracts and returns organizational role and functional mailboxes (`SECURITY`, `PRIVACY_DPO`, `BILLING_FINANCE`, `LEGAL`, `SUPPORT`, `SALES`, `PRESS`, and generic functional inboxes such as `info@`, `contact@`, `hello@`, `office@`, `team@`). Personal or named individual email addresses (`firstname.lastname@`) are automatically excluded at extraction time (`PERSONAL_MAILBOX_EXCLUDED_BY_B2B_ROLE_POLICY`).
- **Public Standards Only:** All signals are resolved in real time from public RFC 9116 `/.well-known/security.txt`, public DNS `MX`/`SPF`/`_dmarc` records, and public Schema.org `Organization` / `ContactPoint` metadata. Offline fixture samples (`SAMPLE_FIXTURE_DIRECTORY`) are used only in local self-tests or the preview playground and are never billed.

---

## License

MIT © [RevClamp Enterprise](https://revclamp.com)
