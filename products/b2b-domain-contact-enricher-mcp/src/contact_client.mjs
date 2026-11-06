/**
 * B2B Domain Contact, RFC 9116 security.txt & DNS-over-HTTPS Deliverability Engine (src/contact_client.mjs)
 *
 * Implements:
 *   1. Multi-domain input normalization & SSRF-guarded URL/domain parsing.
 *   2. RFC 9116 `/.well-known/security.txt` parser with expiration validation (`VALID_ACTIVE`, `EXPIRED`, `MISSING_EXPIRES`).
 *   3. DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query` & `https://dns.google/resolve`) MX, SPF (`v=spf1`),
 *      and DMARC (`_dmarc.<domain>`) posture resolver, gateway provider detector, and `deliverabilityGrade` (`A+`..`F`).
 *   4. Schema.org `Organization` / `ContactPoint` JSON-LD, `mailto:`, Cloudflare `data-cfemail` XOR hex, and
 *      entity/bracket de-obfuscation extractor with tracker/asset false-positive pruning and 8-role classification.
 *   5. Query-bound `rcd1_` pagination cursor encoding, validation, and mid-batch prefix rewind.
 */

import crypto from 'node:crypto';
import https from 'node:https';
import {
  verifyEgressUrlSsrfSafe,
  isPrivateOrReservedIp,
  resolveAndVerifyPublicHostname,
  createEphemeralHttpsAgent,
  containsLiveSecretToken,
  sliceUtf8Safe,
} from './egress_guard.mjs';

export const SUPPORTED_CONTACT_ROLES = Object.freeze([
  'SECURITY',
  'PRIVACY_DPO',
  'BILLING_FINANCE',
  'LEGAL',
  'SUPPORT',
  'SALES',
  'PRESS',
  'GENERAL',
]);

export const SUPPORTED_EMAIL_GATEWAYS = Object.freeze([
  'GOOGLE_WORKSPACE',
  'MICROSOFT_365',
  'PROTONMAIL',
  'FASTMAIL',
  'PROOFPOINT',
  'MIMECAST',
  'AMAZONSES',
  'CUSTOM_MX',
  'NONE',
]);

export const PROFILE_ID_RE = /^DOMAIN:[a-z0-9.-]{3,128}$/;
export const COMPOSITE_CURSOR_PREFIX = 'rcd1_';
export const MAX_CURSOR_LENGTH = 2048;
export const MAX_QUERY_LENGTH = 1024;
export const MAX_HTTP_RESPONSE_BYTES = 262144;
export const DEFAULT_RUN_DEADLINE_MS = 23000;

const EMAIL_CANDIDATE_RE =
  /\b([a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]{1,64})@([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)\b/g;

const OBFUSCATED_EMAIL_RE =
  /\b([a-zA-Z0-9._+-]{1,64})\s*(?:\[\s*at\s*\]|\(\s*at\s*\)|&#64;|&#x40;|&commat;)\s*([a-zA-Z0-9-]+(?:\s*(?:\.|(?:\[\s*dot\s*\]|\(\s*dot\s*\)|&#46;|&#x2e;|&period;))\s*[a-zA-Z0-9-]+)+)\b/gi;

const CF_EMAIL_ATTR_RE = /data-cfemail\s*=\s*["']([0-9a-fA-F]{6,256})["']/gi;

const FALSE_POSITIVE_EMAIL_DOMAINS = new Set([
  'sentry.io',
  'ingest.sentry.io',
  'sentry.wixpress.com',
  'sentry-next.wixpress.com',
  'example.com',
  'example.org',
  'example.net',
  'test.com',
  'domain.com',
  'yourdomain.com',
  'company.com',
  'email.com',
  'localhost',
  'w3.org',
  'schema.org',
]);

const FALSE_POSITIVE_ASSET_TLD_RE =
  /\.(?:png|jpg|jpeg|gif|svg|webp|avif|ico|css|js|mjs|cjs|ts|tsx|jsx|woff|woff2|ttf|eot|otf|map|mp4|webm|pdf|zip)$/i;

const NO_REPLY_LOCAL_RE = /^(?:no-?reply|donotreply|do-not-reply|bounce|mailer-daemon|postmaster|Automated)$/i;
const HEX_NOISE_LOCAL_RE = /^[0-9a-f]{24,}$/i;

export const CURATED_B2B_DOMAIN_DIRECTORY = Object.freeze({
  'stripe.com': {
    domain: 'stripe.com',
    organizationName: 'Stripe, Inc.',
    canonicalUrl: 'https://stripe.com',
    industryCategory: 'FINTECH_PAYMENTS_INFRASTRUCTURE',
    headquartersCountryIso2: 'US',
    mxHosts: [
      'aspmx.l.google.com',
      'alt1.aspmx.l.google.com',
      'alt2.aspmx.l.google.com',
    ],
    spfRecord: 'v=spf1 include:_spf.google.com include:spf.mandrillapp.com -all',
    dmarcRecord: 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@stripe.com',
    securityTxtRaw: [
      'Contact: mailto:security@stripe.com',
      'Contact: https://stripe.com/docs/security/vulnerability-disclosure',
      'Expires: 2027-12-31T23:59:59.000Z',
      'Encryption: https://stripe.com/security/pgp-key.txt',
      'Policy: https://stripe.com/docs/security',
      'Acknowledgments: https://stripe.com/docs/security/hall-of-fame',
      'Hiring: https://stripe.com/jobs',
      'Canonical: https://stripe.com/.well-known/security.txt',
    ].join('\n'),
    contacts: [
      { email: 'security@stripe.com', role: 'SECURITY', source: 'RFC9116_SECURITY_TXT', verified: true },
      { email: 'privacy@stripe.com', role: 'PRIVACY_DPO', source: 'LEGAL_PRIVACY_POLICY', verified: true },
      { email: 'support@stripe.com', role: 'SUPPORT', source: 'SCHEMA_CONTACT_POINT', verified: true },
      { email: 'sales@stripe.com', role: 'SALES', source: 'SCHEMA_CONTACT_POINT', verified: true },
      { email: 'press@stripe.com', role: 'PRESS', source: 'NEWSROOM_PAGE', verified: true },
      { email: 'legal@stripe.com', role: 'LEGAL', source: 'TERMS_PAGE', verified: true },
    ],
    socialProfiles: {
      linkedin: 'https://www.linkedin.com/company/stripe',
      github: 'https://github.com/stripe',
      x: 'https://x.com/stripe',
    },
  },
  'linear.app': {
    domain: 'linear.app',
    organizationName: 'Linear Orbit, Inc.',
    canonicalUrl: 'https://linear.app',
    industryCategory: 'B2B_DEVTOOLS_PRODUCT_MANAGEMENT',
    headquartersCountryIso2: 'US',
    mxHosts: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'],
    spfRecord: 'v=spf1 include:_spf.google.com include:amazonses.com -all',
    dmarcRecord: 'v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-reports@linear.app',
    securityTxtRaw: [
      'Contact: mailto:security@linear.app',
      'Expires: 2027-06-30T23:59:59.000Z',
      'Policy: https://linear.app/security',
      'Hiring: https://linear.app/careers',
      'Canonical: https://linear.app/.well-known/security.txt',
    ].join('\n'),
    contacts: [
      { email: 'security@linear.app', role: 'SECURITY', source: 'RFC9116_SECURITY_TXT', verified: true },
      { email: 'privacy@linear.app', role: 'PRIVACY_DPO', source: 'LEGAL_PRIVACY_POLICY', verified: true },
      { email: 'support@linear.app', role: 'SUPPORT', source: 'CONTACT_PAGE', verified: true },
      { email: 'sales@linear.app', role: 'SALES', source: 'CONTACT_PAGE', verified: true },
    ],
    socialProfiles: {
      linkedin: 'https://www.linkedin.com/company/linearapp',
      github: 'https://github.com/linear',
      x: 'https://x.com/linear',
    },
  },
  'cloudflare.com': {
    domain: 'cloudflare.com',
    organizationName: 'Cloudflare, Inc.',
    canonicalUrl: 'https://www.cloudflare.com',
    industryCategory: 'CLOUD_SECURITY_EDGE_NETWORK',
    headquartersCountryIso2: 'US',
    mxHosts: [
      'aspmx.l.google.com',
      'alt1.aspmx.l.google.com',
      'alt2.aspmx.l.google.com',
    ],
    spfRecord: 'v=spf1 include:_spf.google.com include:_spf.salesforce.com -all',
    dmarcRecord: 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@cloudflare.com',
    securityTxtRaw: [
      'Contact: mailto:security@cloudflare.com',
      'Contact: https://hackerone.com/cloudflare',
      'Expires: 2027-10-01T00:00:00.000Z',
      'Policy: https://www.cloudflare.com/disclosure/',
      'Hiring: https://www.cloudflare.com/careers/',
      'Canonical: https://www.cloudflare.com/.well-known/security.txt',
    ].join('\n'),
    contacts: [
      { email: 'security@cloudflare.com', role: 'SECURITY', source: 'RFC9116_SECURITY_TXT', verified: true },
      { email: 'privacyquestions@cloudflare.com', role: 'PRIVACY_DPO', source: 'LEGAL_PRIVACY_POLICY', verified: true },
      { email: 'billing@cloudflare.com', role: 'BILLING_FINANCE', source: 'SCHEMA_CONTACT_POINT', verified: true },
      { email: 'legal@cloudflare.com', role: 'LEGAL', source: 'TERMS_PAGE', verified: true },
      { email: 'press@cloudflare.com', role: 'PRESS', source: 'NEWSROOM_PAGE', verified: true },
    ],
    socialProfiles: {
      linkedin: 'https://www.linkedin.com/company/cloudflare',
      github: 'https://github.com/cloudflare',
      x: 'https://x.com/cloudflare',
    },
  },
  'shopify.com': {
    domain: 'shopify.com',
    organizationName: 'Shopify Inc.',
    canonicalUrl: 'https://www.shopify.com',
    industryCategory: 'ECOMMERCE_B2B_PLATFORM',
    headquartersCountryIso2: 'CA',
    mxHosts: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'],
    spfRecord: 'v=spf1 include:_spf.google.com include:mail.zendesk.com -all',
    dmarcRecord: 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@shopify.com',
    securityTxtRaw: [
      'Contact: mailto:security@shopify.com',
      'Expires: 2027-11-15T00:00:00.000Z',
      'Policy: https://shopify.com/security-response',
      'Acknowledgments: https://hackerone.com/shopify/thanks',
      'Canonical: https://www.shopify.com/.well-known/security.txt',
    ].join('\n'),
    contacts: [
      { email: 'security@shopify.com', role: 'SECURITY', source: 'RFC9116_SECURITY_TXT', verified: true },
      { email: 'privacy@shopify.com', role: 'PRIVACY_DPO', source: 'LEGAL_PRIVACY_POLICY', verified: true },
      { email: 'support@shopify.com', role: 'SUPPORT', source: 'SCHEMA_CONTACT_POINT', verified: true },
      { email: 'press@shopify.com', role: 'PRESS', source: 'NEWSROOM_PAGE', verified: true },
    ],
    socialProfiles: {
      linkedin: 'https://www.linkedin.com/company/shopify',
      github: 'https://github.com/Shopify',
      x: 'https://x.com/Shopify',
    },
  },
  'github.com': {
    domain: 'github.com',
    organizationName: 'GitHub, Inc.',
    canonicalUrl: 'https://github.com',
    industryCategory: 'DEVELOPER_CLOUD_PLATFORM',
    headquartersCountryIso2: 'US',
    mxHosts: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'],
    spfRecord: 'v=spf1 include:_netblocks.google.com include:spf.protection.outlook.com -all',
    dmarcRecord: 'v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@github.com',
    securityTxtRaw: [
      'Contact: https://bounty.github.com/',
      'Contact: mailto:security@github.com',
      'Expires: 2027-09-01T00:00:00.000Z',
      'Policy: https://bounty.github.com/',
      'Hiring: https://github.com/about/careers',
      'Canonical: https://github.com/.well-known/security.txt',
    ].join('\n'),
    contacts: [
      { email: 'security@github.com', role: 'SECURITY', source: 'RFC9116_SECURITY_TXT', verified: true },
      { email: 'dpo@github.com', role: 'PRIVACY_DPO', source: 'LEGAL_PRIVACY_POLICY', verified: true },
      { email: 'support@github.com', role: 'SUPPORT', source: 'CONTACT_PAGE', verified: true },
      { email: 'sales@github.com', role: 'SALES', source: 'CONTACT_PAGE', verified: true },
      { email: 'press@github.com', role: 'PRESS', source: 'NEWSROOM_PAGE', verified: true },
    ],
    socialProfiles: {
      linkedin: 'https://www.linkedin.com/company/github',
      github: 'https://github.com/github',
      x: 'https://x.com/github',
    },
  },
  'datadoghq.com': {
    domain: 'datadoghq.com',
    organizationName: 'Datadog, Inc.',
    canonicalUrl: 'https://www.datadoghq.com',
    industryCategory: 'CLOUD_OBSERVABILITY_SECURITY',
    headquartersCountryIso2: 'US',
    mxHosts: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'],
    spfRecord: 'v=spf1 include:_spf.google.com include:amazonses.com ~all',
    dmarcRecord: 'v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@datadoghq.com',
    securityTxtRaw: [
      'Contact: mailto:security@datadoghq.com',
      'Expires: 2027-08-01T00:00:00.000Z',
      'Policy: https://www.datadoghq.com/security/',
      'Canonical: https://www.datadoghq.com/.well-known/security.txt',
    ].join('\n'),
    contacts: [
      { email: 'security@datadoghq.com', role: 'SECURITY', source: 'RFC9116_SECURITY_TXT', verified: true },
      { email: 'privacy@datadoghq.com', role: 'PRIVACY_DPO', source: 'LEGAL_PRIVACY_POLICY', verified: true },
      { email: 'support@datadoghq.com', role: 'SUPPORT', source: 'CONTACT_PAGE', verified: true },
      { email: 'sales@datadoghq.com', role: 'SALES', source: 'CONTACT_PAGE', verified: true },
      { email: 'press@datadoghq.com', role: 'PRESS', source: 'NEWSROOM_PAGE', verified: true },
    ],
    socialProfiles: {
      linkedin: 'https://www.linkedin.com/company/datadog',
      github: 'https://github.com/DataDog',
      x: 'https://x.com/datadoghq',
    },
  },
  'vercel.com': {
    domain: 'vercel.com',
    organizationName: 'Vercel Inc.',
    canonicalUrl: 'https://vercel.com',
    industryCategory: 'FRONTEND_CLOUD_INFRASTRUCTURE',
    headquartersCountryIso2: 'US',
    mxHosts: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'],
    spfRecord: 'v=spf1 include:_spf.google.com include:amazonses.com -all',
    dmarcRecord: 'v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@vercel.com',
    securityTxtRaw: [
      'Contact: mailto:security@vercel.com',
      'Expires: 2027-12-01T00:00:00.000Z',
      'Policy: https://vercel.com/security',
      'Canonical: https://vercel.com/.well-known/security.txt',
    ].join('\n'),
    contacts: [
      { email: 'security@vercel.com', role: 'SECURITY', source: 'RFC9116_SECURITY_TXT', verified: true },
      { email: 'privacy@vercel.com', role: 'PRIVACY_DPO', source: 'LEGAL_PRIVACY_POLICY', verified: true },
      { email: 'support@vercel.com', role: 'SUPPORT', source: 'CONTACT_PAGE', verified: true },
      { email: 'sales@vercel.com', role: 'SALES', source: 'CONTACT_PAGE', verified: true },
    ],
    socialProfiles: {
      linkedin: 'https://www.linkedin.com/company/vercel',
      github: 'https://github.com/vercel',
      x: 'https://x.com/vercel',
    },
  },
  'supabase.com': {
    domain: 'supabase.com',
    organizationName: 'Supabase, Inc.',
    canonicalUrl: 'https://supabase.com',
    industryCategory: 'OPEN_SOURCE_POSTGRES_BACKEND',
    headquartersCountryIso2: 'US',
    mxHosts: ['aspmx.l.google.com', 'alt1.aspmx.l.google.com'],
    spfRecord: 'v=spf1 include:_spf.google.com ~all',
    dmarcRecord: 'v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@supabase.io',
    securityTxtRaw: [
      'Contact: mailto:security@supabase.io',
      'Expires: 2027-07-01T00:00:00.000Z',
      'Policy: https://supabase.com/security',
      'Canonical: https://supabase.com/.well-known/security.txt',
    ].join('\n'),
    contacts: [
      { email: 'security@supabase.io', role: 'SECURITY', source: 'RFC9116_SECURITY_TXT', verified: true },
      { email: 'privacy@supabase.io', role: 'PRIVACY_DPO', source: 'LEGAL_PRIVACY_POLICY', verified: true },
      { email: 'support@supabase.io', role: 'SUPPORT', source: 'CONTACT_PAGE', verified: true },
    ],
    socialProfiles: {
      linkedin: 'https://www.linkedin.com/company/supabase',
      github: 'https://github.com/supabase',
      x: 'https://x.com/supabase',
    },
  },
});

/**
 * Validates an integer parameter within `[min, max]`.
 */
export function validateBoundedIntegerParam(rawVal, defaultVal, min, max, paramName = 'limit') {
  if (rawVal === undefined || rawVal === null || rawVal === '') {
    return { ok: true, value: defaultVal };
  }
  const num = Number(rawVal);
  if (!Number.isInteger(num) || num < min || num > max) {
    return {
      ok: false,
      reason: `Parameter '${paramName}' must be an integer between ${min} and ${max} (got ${JSON.stringify(rawVal)})`,
    };
  }
  return { ok: true, value: num };
}

/**
 * Normalizes a raw domain or URL string into a canonical registrable/host domain (lowercase, no www.).
 *
 * @param {string} rawInput
 * @returns {{ok: boolean, domain?: string, canonicalUrl?: string, reason?: string}}
 */
export function normalizeTargetB2bDomain(rawInput) {
  const trimmed = String(rawInput ?? '').trim();
  if (!trimmed) {
    return { ok: false, reason: 'Domain or URL is empty' };
  }
  if (containsLiveSecretToken(trimmed)) {
    return { ok: false, reason: 'Input rejected by Zero-Trust live secret guard' };
  }
  let candidateUrl = trimmed;
  if (!/^https?:\/\//i.test(candidateUrl)) {
    if (/^[a-z0-9+.-]+:\/\//i.test(candidateUrl)) {
      return { ok: false, reason: `Unsupported protocol in '${trimmed}' (only https:// or bare domain allowed)` };
    }
    candidateUrl = `https://${candidateUrl}`;
  }
  const ssrf = verifyEgressUrlSsrfSafe(candidateUrl);
  if (!ssrf.safe) {
    return { ok: false, reason: ssrf.reason || `Unsafe domain '${trimmed}'` };
  }
  const cleanHost = ssrf.hostname.replace(/^www\./i, '');
  if (!cleanHost || !cleanHost.includes('.')) {
    return { ok: false, reason: `Invalid public B2B domain '${cleanHost}'` };
  }
  return {
    ok: true,
    domain: cleanHost,
    canonicalUrl: `https://${cleanHost}`,
  };
}

/**
 * Parses a comma/newline/space-separated query string or array of domains into deduplicated normalized domains.
 *
 * @param {string|string[]} rawQuery
 * @returns {{ok: boolean, domains: string[], rejected: Array<{input: string, reason: string}>, reason?: string}}
 */
export function parseDomainBatchInput(rawQuery) {
  const tokens = Array.isArray(rawQuery)
    ? rawQuery.flatMap((item) => String(item ?? '').split(/[\s,;]+/))
    : String(rawQuery ?? '').split(/[\s,;]+/);
  const cleanedTokens = tokens.map((t) => t.trim()).filter(Boolean);
  if (cleanedTokens.length === 0) {
    return { ok: false, domains: [], rejected: [], reason: 'No target B2B domains provided in query' };
  }
  if (cleanedTokens.some((t) => containsLiveSecretToken(t))) {
    return {
      ok: false,
      domains: [],
      rejected: [],
      reason: 'Query rejected by Zero-Trust live secret guard',
    };
  }
  const seen = new Set();
  const domains = [];
  const rejected = [];
  for (const tok of cleanedTokens) {
    const norm = normalizeTargetB2bDomain(tok);
    if (!norm.ok) {
      rejected.push({ input: tok, reason: norm.reason });
      continue;
    }
    if (!seen.has(norm.domain)) {
      seen.add(norm.domain);
      domains.push(norm.domain);
    }
  }
  if (domains.length === 0) {
    return {
      ok: false,
      domains: [],
      rejected,
      reason: rejected[0]?.reason || 'All target domains failed SSRF or domain syntax validation',
    };
  }
  return { ok: true, domains, rejected };
}

/**
 * Decodes Cloudflare `data-cfemail` XOR hex-obfuscated email strings.
 *
 * @param {string} hexStr
 * @returns {string}
 */
export function decodeCloudflareEmail(hexStr) {
  const clean = String(hexStr ?? '').trim();
  if (!/^[0-9a-fA-F]{4,256}$/.test(clean) || clean.length % 2 !== 0) {
    return '';
  }
  const key = parseInt(clean.slice(0, 2), 16);
  let out = '';
  for (let i = 2; i < clean.length; i += 2) {
    const byte = parseInt(clean.slice(i, i + 2), 16) ^ key;
    if (byte < 32 || byte > 126) return '';
    out += String.fromCharCode(byte);
  }
  return out.trim().toLowerCase();
}

/**
 * Classifies a B2B email address and optional context label into one of 8 canonical functional roles.
 *
 * @param {string} email
 * @param {string} [labelHint='']
 * @returns {string}
 */
export function classifyContactEmailRole(email, labelHint = '') {
  const cleanEmail = String(email ?? '').trim().toLowerCase();
  const localPart = (cleanEmail.split('@')[0] || '').replace(/[^a-z0-9._-]/g, '');
  const hint = String(labelHint ?? '').trim().toLowerCase();

  const strippedRoleToken = localPart.replace(
    /[._-](?:team|dept|department|desk|office|group|ops|support|inquiries|enquiries|reports|requests|questions|policy|response|alerts|notices|us|global|eu|uk|apac|amer|emea)$/,
    ''
  );

  const isExactRoleToken = (tok) =>
    /^(?:security|sec|psirt|csirt|soc|vuln|vulnerability|bugbounty|bounty|abuse|cert|infosec|trust|privacy|dpo|dataprotection|data-protection|gdpr|ccpa|privacyquestions|privacypolicy|billing|finance|accounts|accounting|ap|ar|invoicing|invoices|payments|tax|vat|treasury|procurement|legal|compliance|dmca|copyright|trademark|subpoena|lawenforcement|counsel|notices|terms|support|help|helpdesk|care|customerservice|customer-service|customercare|success|customersuccess|service|sales|enterprise|partners|partnerships|bd|bizdev|deals|solutions|commercial|revenue|press|media|pr|communications|comms|news|newsroom|analyst|info|contact|contactus|contact-us|hello|hi|office|team|hq|inquiries|enquiries|enquiry|general|admin|administrator|webmaster|hostmaster|ops|operations|devops|engineering|eng|product|feedback|careers|jobs|hr|recruiting|talent|people|ir|investors|governance|board|founders|executive|exec|leadership|events|marketing|growth|community|api|developers|dev|status|noc|dmarc|dmarc-reports)$/.test(
      tok
    );

  if (!isExactRoleToken(localPart) && !isExactRoleToken(strippedRoleToken)) {
    return 'PERSONAL_EXCLUDED';
  }
  const roleToken = isExactRoleToken(localPart) ? localPart : strippedRoleToken;

  if (
    /^(?:security|sec|psirt|csirt|soc|vuln|vulnerability|bugbounty|bounty|abuse|cert|infosec|trust)$/.test(roleToken) ||
    /\b(?:security|vulnerability|psirt|csirt|bug\s*bounty|abuse)\b/.test(hint)
  ) {
    return 'SECURITY';
  }
  if (
    /^(?:privacy|dpo|dataprotection|data-protection|gdpr|ccpa|privacyquestions|privacypolicy)$/.test(roleToken) ||
    /\b(?:privacy|dpo|data\s*protection|gdpr|ccpa)\b/.test(hint)
  ) {
    return 'PRIVACY_DPO';
  }
  if (
    /^(?:billing|finance|accounts|accounting|ap|ar|invoicing|invoices|payments|tax|vat|treasury|procurement)$/.test(roleToken) ||
    /\b(?:billing|finance|invoic|accounts\s*payable|tax|vat)\b/.test(hint)
  ) {
    return 'BILLING_FINANCE';
  }
  if (
    /^(?:legal|compliance|dmca|copyright|trademark|subpoena|lawenforcement|counsel|notices|terms)$/.test(roleToken) ||
    /\b(?:legal|compliance|dmca|counsel|trademark)\b/.test(hint)
  ) {
    return 'LEGAL';
  }
  if (
    /^(?:support|help|helpdesk|care|customerservice|customer-service|customercare|success|customersuccess|service)$/.test(roleToken) ||
    /\b(?:support|helpdesk|customer\s*service|customer\s*care|technical\s*support)\b/.test(hint)
  ) {
    return 'SUPPORT';
  }
  if (
    /^(?:sales|enterprise|partners|partnerships|bd|bizdev|deals|solutions|commercial|revenue)$/.test(roleToken) ||
    /\b(?:sales|enterprise|partnership|business\s*development)\b/.test(hint)
  ) {
    return 'SALES';
  }
  if (
    /^(?:press|media|pr|communications|comms|news|newsroom|analyst)$/.test(roleToken) ||
    /\b(?:press|media|public\s*relations|newsroom)\b/.test(hint)
  ) {
    return 'PRESS';
  }
  return 'GENERAL';
}

/**
 * Validates whether an extracted email candidate is a genuine B2B role/generic contact address (filtering out
 * personal/individual mailboxes, Sentry/Wix DSNs, image filenames like `logo@2x.png`, noreply addresses, and test placeholders).
 *
 * @param {string} rawEmail
 * @param {string} [labelHint='']
 * @returns {{valid: boolean, email?: string, localPart?: string, domainPart?: string, role?: string, reason?: string}}
 */
export function validateExtractedB2bEmail(rawEmail, labelHint = '') {
  const cleaned = String(rawEmail ?? '')
    .trim()
    .replace(/^mailto:/i, '')
    .split('?')[0]
    .trim()
    .toLowerCase()
    .replace(/^[<([\s'"]+/, '')
    .replace(/[.,;:)>\]'"]+$/, '');
  const parts = cleaned.split('@');
  if (parts.length !== 2) {
    return { valid: false, reason: 'MALFORMED_EMAIL' };
  }
  const [localPart, domainPart] = parts;
  if (!localPart || localPart.length > 64 || !domainPart || domainPart.length > 253) {
    return { valid: false, reason: 'LENGTH_OUT_OF_BOUNDS' };
  }
  if (FALSE_POSITIVE_ASSET_TLD_RE.test(domainPart) || /^\d+x\./i.test(domainPart)) {
    return { valid: false, reason: 'ASSET_FILENAME_COLLISION' };
  }
  if (
    FALSE_POSITIVE_EMAIL_DOMAINS.has(domainPart) ||
    Array.from(FALSE_POSITIVE_EMAIL_DOMAINS).some((d) => domainPart.endsWith(`.${d}`))
  ) {
    return { valid: false, reason: 'TRACKER_OR_PLACEHOLDER_DOMAIN' };
  }
  if (NO_REPLY_LOCAL_RE.test(localPart)) {
    return { valid: false, reason: 'NOREPLY_ADDRESS' };
  }
  if (HEX_NOISE_LOCAL_RE.test(localPart)) {
    return { valid: false, reason: 'HEX_TOKEN_LOCAL_PART' };
  }
  if (!/\.[a-z]{2,63}$/i.test(domainPart)) {
    return { valid: false, reason: 'INVALID_DOMAIN_TLD' };
  }
  const fullEmail = `${localPart}@${domainPart}`;
  const classifiedRole = classifyContactEmailRole(fullEmail, labelHint);
  if (classifiedRole === 'PERSONAL_EXCLUDED') {
    return { valid: false, reason: 'PERSONAL_MAILBOX_EXCLUDED_BY_B2B_ROLE_POLICY' };
  }
  return {
    valid: true,
    email: fullEmail,
    localPart,
    domainPart,
    role: classifiedRole,
  };
}

/**
 * Extracts, de-obfuscates, and classifies B2B contact emails and social links from HTML or plain text.
 *
 * @param {string} rawContent
 * @param {string} [sourceLabel='HTML_PAGE']
 * @returns {{contacts: Array<{email: string, role: string, source: string, verified: boolean}>, socialProfiles: object}}
 */
export function extractContactsFromHtmlOrText(rawContent, sourceLabel = 'HTML_PAGE') {
  const text = String(rawContent ?? '');
  if (!text) {
    return { contacts: [], socialProfiles: {} };
  }

  const byEmail = new Map();
  const addCandidate = (rawEmail, roleHint = '', src = sourceLabel) => {
    const check = validateExtractedB2bEmail(rawEmail);
    if (!check.valid) return;
    const role = classifyContactEmailRole(check.email, roleHint);
    const existing = byEmail.get(check.email);
    if (!existing || (existing.role === 'GENERAL' && role !== 'GENERAL')) {
      byEmail.set(check.email, {
        email: check.email,
        role,
        source: src,
        verified: true,
      });
    }
  };

  // 1. Cloudflare data-cfemail attributes
  for (const m of text.matchAll(CF_EMAIL_ATTR_RE)) {
    const decoded = decodeCloudflareEmail(m[1]);
    if (decoded) addCandidate(decoded, '', 'CLOUDFLARE_CFEMAIL_DECODED');
  }

  // 2. Schema.org JSON-LD ContactPoint blocks
  const scriptBlocks = text.matchAll(
    /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi
  );
  for (const sb of scriptBlocks) {
    try {
      const parsed = JSON.parse(sb[1].trim());
      const nodes = Array.isArray(parsed)
        ? parsed
        : Array.isArray(parsed?.['@graph'])
          ? parsed['@graph']
          : [parsed];
      for (const node of nodes) {
        if (!node || typeof node !== 'object') continue;
        if (typeof node.email === 'string') {
          addCandidate(node.email, node.contactType || node.name || '', 'SCHEMA_CONTACT_POINT');
        }
        const cps = Array.isArray(node.contactPoint)
          ? node.contactPoint
          : node.contactPoint && typeof node.contactPoint === 'object'
            ? [node.contactPoint]
            : [];
        for (const cp of cps) {
          if (cp && typeof cp.email === 'string') {
            addCandidate(cp.email, cp.contactType || cp.name || '', 'SCHEMA_CONTACT_POINT');
          }
        }
      }
    } catch {
      // Ignore malformed JSON-LD blocks
    }
  }

  // 3. De-obfuscate HTML entities & bracketed [at] / (at) patterns
  const entityNormalized = text
    .replace(/&#64;|&#x40;|&commat;/gi, '@')
    .replace(/&#46;|&#x2e;|&period;/gi, '.');

  for (const m of text.matchAll(OBFUSCATED_EMAIL_RE)) {
    const local = m[1];
    const dom = m[2]
      .replace(/\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|&#46;|&#x2e;|&period;)\s*/gi, '.')
      .replace(/\s+/g, '');
    addCandidate(`${local}@${dom}`, '', 'DEOBFUSCATED_TEXT');
  }

  for (const m of entityNormalized.matchAll(EMAIL_CANDIDATE_RE)) {
    addCandidate(`${m[1]}@${m[2]}`, '', sourceLabel);
  }

  // 4. Extract canonical social links (LinkedIn, GitHub, X/Twitter)
  const socialProfiles = {};
  const liMatch = text.match(/https:\/\/(?:www\.)?linkedin\.com\/company\/[a-zA-Z0-9_-]+/i);
  if (liMatch) socialProfiles.linkedin = liMatch[0];
  const ghMatch = text.match(/https:\/\/github\.com\/[a-zA-Z0-9_.-]+/i);
  if (ghMatch && !/\/(?:login|signup|pricing|features|about|security|settings)$/i.test(ghMatch[0])) {
    socialProfiles.github = ghMatch[0];
  }
  const xMatch = text.match(/https:\/\/(?:x\.com|twitter\.com)\/[a-zA-Z0-9_]{2,32}/i);
  if (xMatch && !/\/(?:intent|share|home|explore|search)$/i.test(xMatch[0])) {
    socialProfiles.x = xMatch[0].replace('twitter.com', 'x.com');
  }

  return {
    contacts: Array.from(byEmail.values()),
    socialProfiles,
  };
}

/**
 * Parses an RFC 9116 `/.well-known/security.txt` payload and evaluates its expiration status.
 *
 * @param {string} rawText
 * @param {number} [nowMs=Date.now()]
 * @returns {object}
 */
export function parseRfc9116SecurityTxt(rawText, nowMs = Date.now()) {
  const text = String(rawText ?? '').trim();
  if (!text || /<!doctype\s+html|<html\b/i.test(text)) {
    return {
      found: false,
      status: 'NOT_FOUND',
      contacts: [],
      expiresAtIso: null,
      isExpired: false,
      encryptionUrls: [],
      policyUrls: [],
      acknowledgmentUrls: [],
      hiringUrls: [],
      canonicalUrls: [],
      preferredLanguages: [],
    };
  }

  const contacts = [];
  const encryptionUrls = [];
  const policyUrls = [];
  const acknowledgmentUrls = [];
  const hiringUrls = [];
  const canonicalUrls = [];
  let expiresAtIso = null;
  let preferredLanguages = [];

  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim().replace(/^-\s+/, '');
    if (!line || line.startsWith('#')) continue;
    const colonIdx = line.indexOf(':');
    if (colonIdx <= 0) continue;
    const key = line.slice(0, colonIdx).trim().toLowerCase();
    const val = line.slice(colonIdx + 1).trim();
    if (!val) continue;

    if (key === 'contact') {
      if (/^mailto:/i.test(val) || (!/^https?:\/\//i.test(val) && val.includes('@'))) {
        const check = validateExtractedB2bEmail(val);
        if (check.valid) {
          contacts.push(/^mailto:/i.test(val) ? `mailto:${check.email}` : check.email);
        }
      } else if (/^https:\/\//i.test(val)) {
        contacts.push(val);
      }
    } else if (key === 'expires') {
      const parsedMs = Date.parse(val);
      if (Number.isFinite(parsedMs)) {
        expiresAtIso = new Date(parsedMs).toISOString();
      } else {
        expiresAtIso = val;
      }
    } else if (key === 'encryption') {
      encryptionUrls.push(val);
    } else if (key === 'policy') {
      policyUrls.push(val);
    } else if (key === 'acknowledgments' || key === 'acknowledgements') {
      acknowledgmentUrls.push(val);
    } else if (key === 'hiring') {
      hiringUrls.push(val);
    } else if (key === 'canonical') {
      canonicalUrls.push(val);
    } else if (key === 'preferred-languages') {
      preferredLanguages = val
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    }
  }

  if (contacts.length === 0) {
    return {
      found: false,
      status: 'INVALID_FORMAT',
      contacts: [],
      expiresAtIso,
      isExpired: false,
      encryptionUrls,
      policyUrls,
      acknowledgmentUrls,
      hiringUrls,
      canonicalUrls,
      preferredLanguages,
    };
  }

  const expMs = expiresAtIso ? Date.parse(expiresAtIso) : NaN;
  const isExpired = Number.isFinite(expMs) ? expMs < nowMs : false;
  const status = !expiresAtIso
    ? 'MISSING_EXPIRES'
    : !Number.isFinite(expMs)
      ? 'INVALID_EXPIRES'
      : isExpired
        ? 'EXPIRED'
        : 'VALID_ACTIVE';

  return {
    found: true,
    status,
    contacts,
    expiresAtIso,
    isExpired,
    encryptionUrls,
    policyUrls,
    acknowledgmentUrls,
    hiringUrls,
    canonicalUrls,
    preferredLanguages,
  };
}

/**
 * Fingerprints the email gateway provider from MX hostnames.
 *
 * @param {string[]} mxHosts
 * @returns {string}
 */
export function detectEmailGatewayProvider(mxHosts = []) {
  const hosts = Array.isArray(mxHosts)
    ? mxHosts
        .map((h) => String(h ?? '').trim().toLowerCase().replace(/\.+$/, ''))
        .filter((h) => h && h !== '.' && !/^0\s*\.$/.test(h))
    : [];
  if (hosts.length === 0) return 'NONE';
  const joined = hosts.join(' ');
  if (joined.includes('google.com') || joined.includes('googlemail.com')) {
    return 'GOOGLE_WORKSPACE';
  }
  if (joined.includes('protection.outlook.com') || joined.includes('mail.eo.outlook.com')) {
    return 'MICROSOFT_365';
  }
  if (joined.includes('protonmail.ch') || joined.includes('proton.me')) {
    return 'PROTONMAIL';
  }
  if (joined.includes('messagingengine.com')) {
    return 'FASTMAIL';
  }
  if (joined.includes('pphosted.com')) {
    return 'PROOFPOINT';
  }
  if (joined.includes('mimecast.com')) {
    return 'MIMECAST';
  }
  if (joined.includes('amazonaws.com') || joined.includes('awsapps.com')) {
    return 'AMAZONSES';
  }
  return 'CUSTOM_MX';
}

/**
 * Evaluates DNS MX, SPF (`v=spf1`), and DMARC (`v=DMARC1`) records into a normalized deliverability posture.
 *
 * @param {{mxHosts?: string[], txtRecords?: string[], dmarcTxtRecords?: string[]}} params
 * @returns {object}
 */
export function evaluateDnsDeliverabilityPosture({
  mxHosts = [],
  txtRecords = [],
  dmarcTxtRecords = [],
} = {}) {
  const cleanMx = (Array.isArray(mxHosts) ? mxHosts : [])
    .map((h) =>
      String(h ?? '')
        .trim()
        .replace(/^\d+\s+/, '')
        .replace(/\.+$/, '')
        .toLowerCase()
    )
    .filter((h) => h && h !== '.');

  const emailGatewayProvider = detectEmailGatewayProvider(cleanMx);
  const hasMx = emailGatewayProvider !== 'NONE';

  const spfCandidates = (Array.isArray(txtRecords) ? txtRecords : [])
    .map((r) =>
      String(r ?? '')
        .replace(/"\s+"/g, '')
        .replace(/^"+|"+$/g, '')
        .trim()
    )
    .filter((r) => /^v=spf1\b/i.test(r));

  const spfRecord = spfCandidates[0] || null;
  const spfMultipleRecordsWarning = spfCandidates.length > 1;
  let spfAllMechanism = 'MISSING';
  if (spfRecord) {
    if (/(?:^|\s)-all(?:\s|$)/i.test(spfRecord)) {
      spfAllMechanism = 'HARDFAIL';
    } else if (/(?:^|\s)~all(?:\s|$)/i.test(spfRecord)) {
      spfAllMechanism = 'SOFTFAIL';
    } else if (/(?:^|\s)\?all(?:\s|$)/i.test(spfRecord)) {
      spfAllMechanism = 'NEUTRAL';
    } else if (/(?:^|\s)\+?all(?:\s|$)/i.test(spfRecord)) {
      spfAllMechanism = 'PASS_OPEN';
    } else if (/\bredirect=/i.test(spfRecord)) {
      spfAllMechanism = 'REDIRECT_DELEGATED';
    } else {
      spfAllMechanism = 'NEUTRAL';
    }
  }

  const dmarcCandidates = (Array.isArray(dmarcTxtRecords) ? dmarcTxtRecords : [])
    .map((r) =>
      String(r ?? '')
        .replace(/"\s+"/g, '')
        .replace(/^"+|"+$/g, '')
        .trim()
    )
    .filter((r) => /^v=DMARC1\b/i.test(r));

  const dmarcRecord = dmarcCandidates[0] || null;
  let dmarcPolicy = 'MISSING';
  let dmarcSubdomainPolicy = null;
  let dmarcPct = 100;
  let dmarcRua = null;
  if (dmarcRecord) {
    const pMatch = dmarcRecord.match(/(?:^|;)\s*p\s*=\s*([a-zA-Z]+)/i);
    if (pMatch) {
      const pVal = pMatch[1].toUpperCase();
      if (pVal === 'REJECT' || pVal === 'QUARANTINE' || pVal === 'NONE') {
        dmarcPolicy = pVal;
      }
    }
    const spMatch = dmarcRecord.match(/(?:^|;)\s*sp\s*=\s*([a-zA-Z]+)/i);
    if (spMatch) dmarcSubdomainPolicy = spMatch[1].toUpperCase();
    const pctMatch = dmarcRecord.match(/(?:^|;)\s*pct\s*=\s*(\d+)/i);
    if (pctMatch) dmarcPct = Math.min(100, Math.max(0, Number(pctMatch[1])));
    const ruaMatch = dmarcRecord.match(/(?:^|;)\s*rua\s*=\s*([^;]+)/i);
    if (ruaMatch) dmarcRua = ruaMatch[1].trim();
  }

  let deliverabilityGrade = 'F';
  if (!hasMx) {
    deliverabilityGrade = 'F';
  } else if (
    dmarcPolicy === 'REJECT' &&
    spfAllMechanism === 'HARDFAIL' &&
    !spfMultipleRecordsWarning
  ) {
    deliverabilityGrade = 'A+';
  } else if (
    (dmarcPolicy === 'REJECT' || dmarcPolicy === 'QUARANTINE') &&
    (spfAllMechanism === 'HARDFAIL' ||
      spfAllMechanism === 'SOFTFAIL' ||
      spfAllMechanism === 'REDIRECT_DELEGATED')
  ) {
    deliverabilityGrade = 'A';
  } else if (
    dmarcPolicy === 'NONE' &&
    (spfAllMechanism === 'HARDFAIL' ||
      spfAllMechanism === 'SOFTFAIL' ||
      spfAllMechanism === 'REDIRECT_DELEGATED')
  ) {
    deliverabilityGrade = 'B';
  } else if (
    spfAllMechanism === 'HARDFAIL' ||
    spfAllMechanism === 'SOFTFAIL' ||
    spfAllMechanism === 'REDIRECT_DELEGATED'
  ) {
    deliverabilityGrade = 'C';
  } else {
    deliverabilityGrade = 'D';
  }

  return {
    hasMx,
    mxHosts: cleanMx,
    emailGatewayProvider,
    spfRecord,
    spfAllMechanism,
    spfMultipleRecordsWarning,
    dmarcRecord,
    dmarcPolicy,
    dmarcSubdomainPolicy,
    dmarcPct,
    dmarcRua,
    deliverabilityGrade,
  };
}

/**
 * Computes a deterministic 16-hex scope hash for pagination cursor binding.
 */
export function computePaginationScopeHash({ domains = [], roleFilter = 'ANY' } = {}) {
  const canonical = JSON.stringify({
    domains: [...domains].map((d) => String(d).toLowerCase()),
    roleFilter: String(roleFilter || 'ANY').toUpperCase(),
  });
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex').slice(0, 16);
}

/**
 * Encodes a deterministic `rcd1_` pagination cursor.
 */
export function encodeCompositeCursor({ offset = 0, totalCount = null, scopeHash = '' } = {}) {
  const payload = {
    v: 1,
    offset: Math.max(0, Math.floor(Number(offset) || 0)),
    totalCount: Number.isInteger(totalCount) && totalCount >= 0 ? totalCount : null,
    scopeHash: String(scopeHash || ''),
  };
  const b64 = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `${COMPOSITE_CURSOR_PREFIX}${b64}`;
}

/**
 * Decodes and validates an `rcd1_` pagination cursor against expected `scopeHash`.
 */
export function decodePaginationCursor(rawToken, expectedScopeHash = '') {
  const token = String(rawToken ?? '').trim();
  if (!token) {
    return { ok: true, offset: 0, totalCount: null, scopeHash: expectedScopeHash };
  }
  if (token.length > MAX_CURSOR_LENGTH || !token.startsWith(COMPOSITE_CURSOR_PREFIX)) {
    return { ok: false, reason: 'Malformed pagination cursor prefix or length' };
  }
  try {
    const jsonStr = Buffer.from(token.slice(COMPOSITE_CURSOR_PREFIX.length), 'base64url').toString('utf8');
    const parsed = JSON.parse(jsonStr);
    if (
      !parsed ||
      parsed.v !== 1 ||
      !Number.isInteger(parsed.offset) ||
      parsed.offset < 0
    ) {
      return { ok: false, reason: 'Invalid pagination cursor payload structure' };
    }
    if (expectedScopeHash && parsed.scopeHash && parsed.scopeHash !== expectedScopeHash) {
      return {
        ok: false,
        reason: 'CURSOR_SCOPE_MISMATCH: pageToken was issued for a different domain query or roleFilter',
      };
    }
    return {
      ok: true,
      offset: parsed.offset,
      totalCount: Number.isInteger(parsed.totalCount) ? parsed.totalCount : null,
      scopeHash: parsed.scopeHash || expectedScopeHash,
    };
  } catch (err) {
    return { ok: false, reason: `Malformed pagination cursor encoding: ${err.message}` };
  }
}

/**
 * Rewinds `nextPageToken` when MCP 30 KB byte-ceiling truncation pops tail items from a page.
 */
export function computeRewoundCursorForDeliveredPrefix(
  cursorResumeContext,
  deliveredCount,
  fallbackNextPageToken = null
) {
  if (!cursorResumeContext || typeof cursorResumeContext !== 'object') {
    return fallbackNextPageToken;
  }
  const safeDelivered = Math.max(0, Math.floor(Number(deliveredCount) || 0));
  const startOffset = Math.max(0, Math.floor(Number(cursorResumeContext.startOffset) || 0));
  const totalCount = Number.isInteger(cursorResumeContext.totalCount)
    ? cursorResumeContext.totalCount
    : null;
  const itemOffsets = Array.isArray(cursorResumeContext.itemNextOffsets)
    ? cursorResumeContext.itemNextOffsets
    : null;
  const nextOffset =
    safeDelivered === 0
      ? startOffset
      : itemOffsets && Number.isInteger(itemOffsets[safeDelivered - 1])
        ? itemOffsets[safeDelivered - 1]
        : startOffset + safeDelivered;
  if (totalCount !== null && nextOffset >= totalCount) {
    return null;
  }
  return encodeCompositeCursor({
    offset: nextOffset,
    totalCount,
    scopeHash: cursorResumeContext.scopeHash || '',
  });
}

/**
 * Reads an HTTP response body incrementally up to `maxBytes` UTF-8 bytes and aborts the stream
 * immediately once the ceiling is exceeded so oversized responses cannot exhaust memory.
 */
export async function readResponseTextWithByteCap(res, maxBytes = MAX_HTTP_RESPONSE_BYTES, controller = null) {
  const safeCap = Math.max(256, Number(maxBytes) || MAX_HTTP_RESPONSE_BYTES);
  const body = res?.body;
  if (body && typeof body.getReader === 'function') {
    const reader = body.getReader();
    const chunks = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
        chunks.push(buf);
        totalBytes += buf.length;
        if (totalBytes > safeCap) {
          try {
            await reader.cancel();
          } catch {
            // ignore reader cancel error
          }
          if (controller && typeof controller.abort === 'function') {
            controller.abort();
          }
          break;
        }
      }
    } catch {
      // stream aborted at byte cap
    }
    const merged = Buffer.concat(chunks, Math.min(totalBytes, safeCap + 4));
    return sliceUtf8Safe(merged.toString('utf8'), safeCap);
  }
  if (body && typeof body[Symbol.asyncIterator] === 'function') {
    const chunks = [];
    let totalBytes = 0;
    try {
      for await (const chunk of body) {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        chunks.push(buf);
        totalBytes += buf.length;
        if (totalBytes > safeCap) {
          if (controller && typeof controller.abort === 'function') {
            controller.abort();
          }
          if (typeof body.destroy === 'function') {
            body.destroy();
          }
          break;
        }
      }
    } catch {
      // stream aborted at byte cap
    }
    const merged = Buffer.concat(chunks, Math.min(totalBytes, safeCap + 4));
    return sliceUtf8Safe(merged.toString('utf8'), safeCap);
  }
  const rawText = typeof res?.text === 'function' ? await res.text() : '';
  return sliceUtf8Safe(rawText, safeCap);
}

/**
 * Executes an HTTPS GET using Node's native `https.request` bound to `pinnedAgent`
 * (`agent.options.lookup` pinned to the pre-vetted public IP, with TLS SNI set to `hostname`)
 * so that Node's built-in undici `fetch` never performs an unpinned second DNS lookup (TOCTOU defense).
 */
export function requestPinnedHttpsViaNodeAgent(
  urlStr,
  { agent, headers = {}, signal = null, timeoutMs = 3500 } = {}
) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const req = https.request(
      {
        protocol: 'https:',
        hostname: parsed.hostname,
        servername: parsed.hostname,
        port: 443,
        path: `${parsed.pathname}${parsed.search}`,
        method: 'GET',
        headers,
        agent,
        timeout: timeoutMs,
      },
      (incomingRes) => {
        resolve({
          status: incomingRes.statusCode || 0,
          headers: {
            get(name) {
              const val = incomingRes.headers[String(name || '').toLowerCase()];
              return Array.isArray(val) ? val[0] : val || '';
            },
          },
          body: incomingRes,
          async text() {
            const chunks = [];
            for await (const chunk of incomingRes) {
              chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
            }
            return Buffer.concat(chunks).toString('utf8');
          },
        });
      }
    );
    if (signal) {
      if (signal.aborted) {
        req.destroy(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
        return;
      }
      signal.addEventListener(
        'abort',
        () => {
          req.destroy(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
        },
        { once: true }
      );
    }
    req.on('timeout', () => {
      req.destroy(Object.assign(new Error('Timeout'), { name: 'AbortError' }));
    });
    req.on('error', (err) => reject(err));
    req.end();
  });
}

/**
 * Performs an SSRF-guarded HTTPS GET with DNS A/AAAA public-IP verification,
 * manual redirect re-validation (`maxRedirects <= 3`), and bounded body streaming (`<= MAX_HTTP_RESPONSE_BYTES`).
 */
export async function fetchHttpsTextBounded(
  rawUrl,
  {
    fetchImpl = globalThis.fetch,
    dnsLookup = undefined,
    timeoutMs = 3500,
    maxBytes = MAX_HTTP_RESPONSE_BYTES,
    acceptHeader = 'text/plain, text/html, application/json;q=0.9',
  } = {}
) {
  let currentUrl = rawUrl;
  const maxRedirects = 3;
  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const ssrf = verifyEgressUrlSsrfSafe(currentUrl);
    if (!ssrf.safe) {
      return { ok: false, status: 0, reason: `SSRF_BLOCKED:${ssrf.reason}`, text: '' };
    }
    let pinnedAgent = null;
    if (typeof dnsLookup === 'function' || fetchImpl === globalThis.fetch) {
      const dnsCheck = await resolveAndVerifyPublicHostname(ssrf.hostname, dnsLookup);
      if (!dnsCheck.safe) {
        return { ok: false, status: 0, reason: `SSRF_DNS_BLOCKED:${dnsCheck.reason}`, text: '' };
      }
      pinnedAgent = createEphemeralHttpsAgent(timeoutMs, dnsCheck.addresses?.[0] || null);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.max(250, Math.min(8000, timeoutMs)));
    try {
      const reqHeaders = {
        accept: acceptHeader,
        'user-agent': 'RevClamp-ContactPulse/1.0 (+https://revclamp.com)',
        connection: 'close',
      };
      const res =
        fetchImpl === globalThis.fetch && pinnedAgent
          ? await requestPinnedHttpsViaNodeAgent(ssrf.normalizedUrl, {
              agent: pinnedAgent,
              headers: reqHeaders,
              signal: controller.signal,
              timeoutMs,
            })
          : await fetchImpl(ssrf.normalizedUrl, {
              method: 'GET',
              redirect: 'manual',
              headers: reqHeaders,
              ...(pinnedAgent ? { agent: pinnedAgent } : {}),
              signal: controller.signal,
            });
      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers?.get?.('location') || '';
        res.body?.resume?.();
        res.body?.destroy?.();
        if (!loc || hop === maxRedirects) {
          return { ok: false, status: res.status, reason: 'REDIRECT_LIMIT_OR_MISSING_LOCATION', text: '' };
        }
        currentUrl = new URL(loc, ssrf.normalizedUrl).toString();
        continue;
      }
      if (res.status !== 200) {
        res.body?.resume?.();
        res.body?.destroy?.();
        return { ok: false, status: res.status, reason: `HTTP_${res.status}`, text: '' };
      }
      const boundedText = await readResponseTextWithByteCap(res, maxBytes, controller);
      return {
        ok: true,
        status: 200,
        text: boundedText,
        finalUrl: ssrf.normalizedUrl,
      };
    } catch (err) {
      return {
        ok: false,
        status: 0,
        reason: err?.name === 'AbortError' ? 'TIMEOUT' : `NETWORK_ERROR:${err?.message || err}`,
        text: '',
      };
    } finally {
      clearTimeout(timer);
    }
  }
  return { ok: false, status: 0, reason: 'MAX_REDIRECTS_EXCEEDED', text: '' };
}

/**
 * Resolves DNS records (`MX`, `TXT`) for a domain via Cloudflare DNS-over-HTTPS (`https://cloudflare-dns.com/dns-query`).
 */
export async function queryDohJsonRecords(
  domain,
  recordType = 'TXT',
  { fetchImpl = globalThis.fetch, dnsLookup = undefined, timeoutMs = 2500 } = {}
) {
  const cleanName = String(domain ?? '').trim().toLowerCase().replace(/\.+$/, '');
  if (!cleanName) return [];
  const upperType = String(recordType || 'TXT').trim().toUpperCase();
  const expectedRrType = upperType === 'MX' ? 15 : upperType === 'TXT' ? 16 : null;
  const endpoints = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanName)}&type=${encodeURIComponent(upperType)}`,
    `https://dns.google/resolve?name=${encodeURIComponent(cleanName)}&type=${encodeURIComponent(upperType)}`,
  ];
  for (const url of endpoints) {
    const res = await fetchHttpsTextBounded(url, {
      fetchImpl,
      dnsLookup,
      timeoutMs,
      maxBytes: 65536,
      acceptHeader: 'application/dns-json',
    });
    if (!res.ok || !res.text) continue;
    try {
      const parsed = JSON.parse(res.text);
      const answers = Array.isArray(parsed?.Answer) ? parsed.Answer : [];
      return answers
        .filter((a) => !expectedRrType || !a?.type || Number(a.type) === expectedRrType)
        .map((a) => String(a?.data ?? '').trim())
        .filter(Boolean);
    } catch {
      continue;
    }
  }
  return [];
}

/**
 * Builds a normalized B2B Domain Contact & Deliverability Profile for a single domain.
 */
export async function enrichSingleB2bDomain(
  rawDomain,
  {
    roleFilter = 'ANY',
    includeDnsPosture = true,
    includeSecurityTxt = true,
    fetchImpl = globalThis.fetch,
    dnsLookup = undefined,
    nowMs = Date.now(),
    preferCurated = false,
  } = {}
) {
  const norm = normalizeTargetB2bDomain(rawDomain);
  if (!norm.ok) {
    return { ok: false, status: 'INVALID_INPUT', reason: norm.reason };
  }
  const domain = norm.domain;
  const normalizedRoleFilter = String(roleFilter || 'ANY').trim().toUpperCase();
  const curated = preferCurated === true ? CURATED_B2B_DOMAIN_DIRECTORY[domain] : null;

  if (!curated && (typeof dnsLookup === 'function' || fetchImpl === globalThis.fetch)) {
    const dnsCheck = await resolveAndVerifyPublicHostname(domain, dnsLookup);
    if (!dnsCheck.safe) {
      return {
        ok: false,
        status: 'SSRF_BLOCKED',
        errorCode: 'SSRF_BLOCKED',
        reason: dnsCheck.reason,
      };
    }
  }

  let organizationName =
    curated?.organizationName ||
    domain
      .split('.')[0]
      .replace(/[-_]+/g, ' ')
      .replace(/\b\w/g, (c) => c.toUpperCase());
  let canonicalUrl = curated?.canonicalUrl || `https://${domain}`;
  let mxHosts = curated?.mxHosts ? [...curated.mxHosts] : [];
  let txtRecords = curated?.spfRecord ? [curated.spfRecord] : [];
  let dmarcTxtRecords = curated?.dmarcRecord ? [curated.dmarcRecord] : [];
  let securityTxtRaw = curated?.securityTxtRaw || '';
  let rawContacts = curated?.contacts ? curated.contacts.map((c) => ({ ...c, verified: false })) : [];
  let socialProfiles = curated?.socialProfiles ? { ...curated.socialProfiles } : {};
  let resolutionSource = curated ? 'SAMPLE_FIXTURE_DIRECTORY' : 'LIVE_HTTPS_AND_DOH_PROBE';

  if (!curated && typeof fetchImpl === 'function') {
    if (includeDnsPosture) {
      const [mxAns, txtAns, dmarcAns] = await Promise.all([
        queryDohJsonRecords(domain, 'MX', { fetchImpl, dnsLookup }),
        queryDohJsonRecords(domain, 'TXT', { fetchImpl, dnsLookup }),
        queryDohJsonRecords(`_dmarc.${domain}`, 'TXT', { fetchImpl, dnsLookup }),
      ]);
      mxHosts = mxAns;
      txtRecords = txtAns;
      dmarcTxtRecords = dmarcAns;
    }
    if (includeSecurityTxt) {
      const secRes = await fetchHttpsTextBounded(`https://${domain}/.well-known/security.txt`, {
        fetchImpl,
        dnsLookup,
        timeoutMs: 3000,
      });
      if (secRes.ok && secRes.text) {
        securityTxtRaw = secRes.text;
      }
    }
    const homeRes = await fetchHttpsTextBounded(`https://${domain}`, {
      fetchImpl,
      dnsLookup,
      timeoutMs: 3500,
    });
    if (homeRes.ok && homeRes.text) {
      const extracted = extractContactsFromHtmlOrText(homeRes.text, 'HOMEPAGE_HTML');
      rawContacts.push(...extracted.contacts);
      socialProfiles = { ...socialProfiles, ...extracted.socialProfiles };
      const titleMatch = homeRes.text.match(/<title[^>]*>([^<]{2,80})<\/title>/i);
      if (titleMatch) {
        const cleanTitle = titleMatch[1].split(/[|\-\u2013\u2014]/)[0].trim();
        if (cleanTitle.length >= 2 && cleanTitle.length <= 48) {
          organizationName = cleanTitle;
        }
      }
    }
  }

  const securityTxt = includeSecurityTxt
    ? parseRfc9116SecurityTxt(securityTxtRaw, nowMs)
    : {
        found: false,
        status: 'SKIPPED',
        contacts: [],
        expiresAtIso: null,
        isExpired: false,
        encryptionUrls: [],
        policyUrls: [],
        acknowledgmentUrls: [],
        hiringUrls: [],
        canonicalUrls: [],
        preferredLanguages: [],
      };

  // Merge any mailto: contacts from non-expired security.txt into contacts list (RFC 9116 Section 2.5.3)
  if (securityTxt.isExpired) {
    rawContacts = rawContacts.filter((c) => c.source !== 'RFC9116_SECURITY_TXT');
  } else {
    for (const secContact of securityTxt.contacts) {
      if (/^mailto:/i.test(secContact) || secContact.includes('@')) {
        const check = validateExtractedB2bEmail(secContact);
        if (check.valid && !rawContacts.some((c) => c.email === check.email)) {
          rawContacts.push({
            email: check.email,
            role: 'SECURITY',
            source: 'RFC9116_SECURITY_TXT',
            verified: !curated && securityTxt.status === 'VALID_ACTIVE',
          });
        }
      }
    }
  }

  const filteredContacts =
    normalizedRoleFilter === 'ANY'
      ? rawContacts
      : rawContacts.filter((c) => c.role === normalizedRoleFilter);

  const dnsPosture = includeDnsPosture
    ? evaluateDnsDeliverabilityPosture({
        mxHosts,
        txtRecords,
        dmarcTxtRecords,
      })
    : {
        hasMx: false,
        mxHosts: [],
        emailGatewayProvider: 'NONE',
        spfRecord: null,
        spfAllMechanism: 'SKIPPED',
        spfMultipleRecordsWarning: false,
        dmarcRecord: null,
        dmarcPolicy: 'SKIPPED',
        dmarcSubdomainPolicy: null,
        dmarcPct: 100,
        dmarcRua: null,
        deliverabilityGrade: 'N/A',
      };

  const primaryContact = filteredContacts[0] || rawContacts[0] || null;
  const hasEnrichedSignal =
    filteredContacts.length > 0 ||
    dnsPosture.hasMx ||
    Boolean(dnsPosture.spfRecord) ||
    Boolean(dnsPosture.dmarcRecord) ||
    (securityTxt.found && !securityTxt.isExpired);
  const billable = !curated && hasEnrichedSignal;

  return {
    ok: true,
    profile: {
      profileId: `DOMAIN:${domain}`,
      domain,
      organizationName,
      canonicalUrl,
      resolutionSource,
      dataSource: resolutionSource,
      emptyResult: !hasEnrichedSignal,
      billable,
      primaryEmail: primaryContact?.email || null,
      primaryRole: primaryContact?.role || null,
      contactsCount: filteredContacts.length,
      contacts: filteredContacts,
      emailGatewayProvider: dnsPosture.emailGatewayProvider,
      deliverabilityGrade: dnsPosture.deliverabilityGrade,
      dmarcPolicy: dnsPosture.dmarcPolicy,
      spfAllMechanism: dnsPosture.spfAllMechanism,
      securityTxtStatus: securityTxt.status,
      dnsPosture,
      securityTxt,
      socialProfiles,
    },
  };
}

/**
 * Batch-enriches 1 to 25 B2B domains with deterministic `rcd1_` cursor pagination.
 */
export async function resolveB2bDomainContactsBatch(input = {}, options = {}) {
  const rawQuery = input?.query ?? input?.domains ?? input?.domain ?? 'stripe.com';
  const roleFilter = String(input?.roleFilter || 'ANY').trim().toUpperCase();
  if (roleFilter !== 'ANY' && !SUPPORTED_CONTACT_ROLES.includes(roleFilter)) {
    return {
      ok: false,
      status: 'INVALID_INPUT',
      errorCode: 'INVALID_INPUT',
      reason: `Unsupported roleFilter '${roleFilter}'. Allowed: ANY, ${SUPPORTED_CONTACT_ROLES.join(', ')}`,
      items: [],
    };
  }

  const limitRes = validateBoundedIntegerParam(
    input?.limit ?? input?.maxResults,
    5,
    1,
    25,
    'maxResults'
  );
  if (!limitRes.ok) {
    return {
      ok: false,
      status: 'INVALID_INPUT',
      errorCode: 'INVALID_INPUT',
      reason: limitRes.reason,
      items: [],
    };
  }
  const pageSize = limitRes.value;

  const parsedBatch = parseDomainBatchInput(rawQuery);
  if (!parsedBatch.ok) {
    return {
      ok: false,
      status: 'INVALID_INPUT',
      errorCode: 'INVALID_INPUT',
      reason: parsedBatch.reason,
      items: [],
    };
  }

  const allDomains = parsedBatch.domains;
  const scopeHash = computePaginationScopeHash({ domains: allDomains, roleFilter });
  const cursorRes = decodePaginationCursor(input?.pageToken, scopeHash);
  if (!cursorRes.ok) {
    return {
      ok: false,
      status: 'INVALID_INPUT',
      errorCode: 'INVALID_INPUT',
      reason: cursorRes.reason,
      items: [],
    };
  }

  const startOffset = cursorRes.offset;
  const sliceDomains = allDomains.slice(startOffset, startOffset + pageSize);
  const items = [];
  const itemNextOffsets = [];
  for (let sliceIdx = 0; sliceIdx < sliceDomains.length; sliceIdx += 1) {
    const dom = sliceDomains[sliceIdx];
    const res = await enrichSingleB2bDomain(dom, {
      roleFilter,
      includeDnsPosture: input?.includeDnsPosture !== false,
      includeSecurityTxt: input?.includeSecurityTxt !== false,
      fetchImpl: options?.fetchImpl || globalThis.fetch,
      dnsLookup: options?.dnsLookup,
      nowMs: options?.nowMs || Date.now(),
      preferCurated: options?.preferCurated === true || input?.useSampleFixtures === true,
    });
    if (res.ok && res.profile) {
      items.push(res.profile);
      itemNextOffsets.push(startOffset + sliceIdx + 1);
    }
  }

  const nextOffset = startOffset + sliceDomains.length;
  const hasMore = nextOffset < allDomains.length;
  const nextPageToken = hasMore
    ? encodeCompositeCursor({
        offset: nextOffset,
        totalCount: allDomains.length,
        scopeHash,
      })
    : null;

  const nonEmptyCount = items.filter((item) => !item.emptyResult).length;

  return {
    ok: true,
    status: nonEmptyCount > 0 ? 'SUCCEEDED' : 'EMPTY_RESULT',
    reason:
      nonEmptyCount > 0
        ? `Enriched ${nonEmptyCount} B2B domain contact profile(s).`
        : 'No matching domain contact profiles found for slice.',
    query: Array.isArray(rawQuery) ? rawQuery.join(', ') : String(rawQuery),
    roleFilter,
    items,
    rejectedInputs: parsedBatch.rejected,
    pagination: {
      offset: startOffset,
      limit: pageSize,
      totalDomainsCount: allDomains.length,
      hasMore,
      nextPageToken,
      paginationStatus: hasMore ? 'HAS_MORE' : 'COMPLETE',
    },
    cursorResumeContext: {
      startOffset,
      totalCount: allDomains.length,
      scopeHash,
      itemNextOffsets,
    },
  };
}

/**
 * Evaluates a single email address or domain for deliverability posture and role-account risk.
 */
export async function verifyEmailDeliverabilityPosture(input = {}, options = {}) {
  const rawTarget = String(input?.email ?? input?.domain ?? input?.query ?? '').trim();
  if (!rawTarget) {
    return {
      ok: false,
      status: 'INVALID_INPUT',
      errorCode: 'INVALID_INPUT',
      reason: 'Missing email or domain parameter',
    };
  }
  if (containsLiveSecretToken(rawTarget)) {
    return {
      ok: false,
      status: 'INVALID_INPUT',
      errorCode: 'INVALID_INPUT',
      reason: 'Input rejected by Zero-Trust live secret guard',
    };
  }

  let candidateEmail = null;
  let targetDomain = rawTarget;
  if (rawTarget.includes('@')) {
    const emailCheck = validateExtractedB2bEmail(rawTarget);
    if (!emailCheck.valid) {
      return {
        ok: false,
        status: 'INVALID_INPUT',
        errorCode: 'INVALID_INPUT',
        reason: `Email validation failed (${emailCheck.reason}): '${rawTarget}'`,
      };
    }
    candidateEmail = emailCheck.email;
    targetDomain = emailCheck.domainPart;
  }

  const enriched = await enrichSingleB2bDomain(targetDomain, {
    includeDnsPosture: true,
    includeSecurityTxt: true,
    fetchImpl: options?.fetchImpl || globalThis.fetch,
    dnsLookup: options?.dnsLookup,
    nowMs: options?.nowMs || Date.now(),
    preferCurated: options?.preferCurated === true || input?.useSampleFixtures === true,
  });
  if (!enriched.ok) {
    return enriched;
  }

  const p = enriched.profile;
  const role = candidateEmail ? classifyContactEmailRole(candidateEmail) : p.primaryRole || 'GENERAL';
  const isRoleAccount = Boolean(candidateEmail && role !== 'GENERAL');
  const knownDirectoryMatch = candidateEmail
    ? p.contacts.some((c) => c.email === candidateEmail)
    : false;

  return {
    ok: true,
    status: 'SUCCEEDED',
    domain: p.domain,
    organizationName: p.organizationName,
    evaluatedEmail: candidateEmail,
    classifiedRole: role,
    isRoleAccount,
    knownDirectoryMatch,
    emailGatewayProvider: p.emailGatewayProvider,
    deliverabilityGrade: p.deliverabilityGrade,
    dmarcPolicy: p.dmarcPolicy,
    spfAllMechanism: p.spfAllMechanism,
    securityTxtStatus: p.securityTxtStatus,
    dnsPosture: p.dnsPosture,
  };
}
