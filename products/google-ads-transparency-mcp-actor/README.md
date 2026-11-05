# RevClamp AdPulse - Google Ads Transparency Scraper & MCP

[![RevClamp AdPulse - Google Ads Transparency Intelligence](https://revclamp.com/assets/revclamp-product-banner.png)](https://revclamp.com)

> **Disclaimer:** Independent intelligence tool by RevClamp; not affiliated with or endorsed by Google LLC.

Find verified Google Ads advertiser entities and extract active or historical ad creatives (Text, Image, Video), preview links, and run dates directly from the Google Ads Transparency Center (`adstransparency.google.com`) with zero browser or residential proxy overhead. Available as both an Apify Pay-per-Event Actor and a Model Context Protocol (MCP) server (`@revclamp/google-ads-transparency-mcp-actor`).

- **Canonical Publisher Website:** [https://revclamp.com](https://revclamp.com)
- **Official MCP Package:** `@revclamp/google-ads-transparency-mcp-actor` (`com.revclamp/google-ads-transparency-mcp-actor`)

## Key Capabilities

1. **Smart Advertiser Entity Matching (`SearchSuggestions`):**
   - Matches internationalized domains (`nike.com`, `stripe.com`, `shopify.co.uk`, `brand.myshopify.com`, `on-running.com`, `bankofamerica.com`, `thenorthface.com`) and multi-token or Unicode brand queries (CJK/Hangul corporate names, `"The Coca-Cola Company"`, `L'Oréal`) to verified Google Ads Transparency legal entities (`AR...`).
   - Prevents substring lookalike mismatches where querying `nike.com` selects `NIKETA'S COMPANY S.R.L.` instead of `Nike, Inc.` (`AR16735076323512287233`), and enforces a strict leading-word identity gate so middle-word lookalikes (`Big Apple Pizza LLC`) or unrelated same-first-word companies (`Nike AI Solutions`) are never admitted as corporate subsidiaries.
   - Supports regional subsidiary inclusion (`includeSubsidiaries: true`, up to 3 verified regional corporate entities such as `Stripe, Inc.` US + `Stripe Payments Europe, Limited` IE).
2. **Paginated Creative & Asset Extraction (`SearchCreatives` & `LookupService/GetCreativeById`):**
   - Maps ISO-2 `countryCode` filters to Google Ads Geo Target Criterion IDs (`US -> 2840`, `GB -> 2826`, `DE -> 2276`, `SG -> 2702`, `VN -> 2704`) and extracts normalized `TEXT`, `IMAGE`, and `VIDEO` ad creatives with decoded `previewUrl`, `archiveImageUrls`, `firstSeenAtIso`, `lastSeenAtIso`, `daysActive`, `timestampsRepaired`, `regionalPresence`, and `transparencyUrl`.
   - Preserves mid-page pagination resume via opaque continuation cursors (`rcp1_...`, `maxLength: 2048`, with query-scope hash `qh`, raw page length `rl`, and anchor `creativeId` `ac`) and automatically rewinds `pagination.nextPageToken` whenever `maxResults`, Apify `CHARGE_LIMIT_REACHED`, `DEADLINE_EXCEEDED_BEFORE_CHARGE`, or the 30,000-byte MCP response ceiling truncates a page. Pass the returned `pagination.nextPageToken` back as `pageToken` in the next Actor input or MCP tool call to resume without duplicate charges or skipped creatives.
3. **Zero-Charge Schema Guard, Rate-Limit Safety & Crash-Safe Apify Billing:**
   - Separates legitimate empty results (`EMPTY_RESULT`) from upstream HTTP errors (`UPSTREAM_ERROR`), rate-limiting/CAPTCHA challenges (`UPSTREAM_RATE_LIMITED`), and protobuf-JSON schema changes (`SCHEMA_DRIFT_HALT`), halting before any Pay-per-Event billing charge is emitted.
   - Integrates natively with Apify Cloud (`ACTOR_RUN_ID`, `ACTOR_DEFAULT_DATASET_ID`, `ACTOR_DEFAULT_KEY_VALUE_STORE_ID`, `ACTOR_MEMORY_MBYTES`, with fallback to `APIFY_*` legacy aliases), writes the run summary and `pagination.nextPageToken` to the default Key-Value Store `OUTPUT` record on every exit path as well as stdout, and tracks `inFlightIds`, `chargedIds`, `deliveredIds`, `unknownOutcomeIds`, and `stagedItemsById` with bounded `pushData` retry so transient failures or same-run resumptions never double-charge or lose staged paid payloads.

## CLI & Verification

```bash
# Run MCP stdio server
npx @revclamp/google-ads-transparency-mcp-actor --mcp-stdio

# Start local interactive web playground on http://127.0.0.1:4410
npm run playground

# Run full unit, golden-corpus, metamorphic, mutation, and CDP E2E test suites
npm test
```

## Terms of Use, Data Provenance & Independent Tool Disclaimer

- **Public Transparency Records Only:** RevClamp AdPulse queries publicly accessible transparency disclosures published on the Google Ads Transparency Center (`adstransparency.google.com`) for research, brand-safety auditing, regulatory compliance, and competitive ad intelligence.
- **No Circumvention or Personal Data:** This tool operates strictly against unauthenticated public transparency endpoints, enforces a strict hostname allowlist (`adstransparency.google.com`, `displayads-formats.googleusercontent.com`, `tpc.googlesyndication.com`), strips cookies and credentials on egress, and halts immediately (`UPSTREAM_RATE_LIMITED`) if upstream rate limits or CAPTCHA challenges (`HTTP 429` / `/sorry/`) are encountered.
- **Trademark & Affiliation Notice:** "Google" and "Google Ads" are trademarks of Google LLC. RevClamp AdPulse is an independent software tool developed by RevClamp and is not affiliated with, sponsored by, or endorsed by Google LLC.

## License

MIT © [RevClamp Enterprise](https://revclamp.com)
