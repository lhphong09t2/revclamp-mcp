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
import net from 'node:net';
import {
  SSRF_BLOCKED_HOST_RE,
  LIVE_SECRET_GUARD_RE,
  parseIpv6Hextets,
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

const NO_REPLY_LOCAL_RE = /^(?:no-?reply|donotreply|do-not-reply|bounce|mailer-daemon|automated)$/i;
const HEX_NOISE_LOCAL_RE = /^[0-9a-f]{24,}$/i;

const CORE_B2B_ROLE_SUBTOKENS = new Set([
  'security',
  'sec',
  'psirt',
  'csirt',
  'soc',
  'vuln',
  'vulnerability',
  'bugbounty',
  'bounty',
  'abuse',
  'cert',
  'infosec',
  'trust',
  'disclosure',
  'privacy',
  'dpo',
  'dataprotection',
  'gdpr',
  'ccpa',
  'privacyquestions',
  'privacypolicy',
  'billing',
  'finance',
  'accounts',
  'accounting',
  'payable',
  'receivable',
  'ap',
  'ar',
  'invoicing',
  'invoices',
  'payments',
  'tax',
  'vat',
  'treasury',
  'procurement',
  'legal',
  'compliance',
  'dmca',
  'copyright',
  'trademark',
  'subpoena',
  'lawenforcement',
  'counsel',
  'notices',
  'terms',
  'support',
  'help',
  'helpdesk',
  'care',
  'customerservice',
  'customercare',
  'success',
  'customersuccess',
  'service',
  'sales',
  'enterprise',
  'partners',
  'partnerships',
  'bd',
  'bizdev',
  'deals',
  'solutions',
  'commercial',
  'revenue',
  'press',
  'media',
  'pr',
  'communications',
  'comms',
  'news',
  'newsroom',
  'analyst',
  'relations',
  'info',
  'contact',
  'contactus',
  'hello',
  'hi',
  'office',
  'team',
  'hq',
  'inquiries',
  'enquiries',
  'enquiry',
  'general',
  'admin',
  'administrator',
  'webmaster',
  'hostmaster',
  'postmaster',
  'ops',
  'operations',
  'devops',
  'engineering',
  'eng',
  'product',
  'feedback',
  'careers',
  'jobs',
  'hr',
  'recruiting',
  'talent',
  'people',
  'ir',
  'investors',
  'governance',
  'board',
  'founders',
  'executive',
  'exec',
  'leadership',
  'events',
  'marketing',
  'growth',
  'community',
  'api',
  'developers',
  'dev',
  'status',
  'noc',
  'desk',
  'dept',
  'department',
]);

const B2B_QUALIFIER_SUBTOKENS = new Set([
  'customer',
  'customers',
  'tech',
  'technical',
  'partner',
  'channel',
  'corporate',
  'corp',
  'global',
  'regional',
  'us',
  'eu',
  'uk',
  'apac',
  'emea',
  'amer',
  'b2b',
  'client',
  'clients',
  'vendor',
  'vendors',
  'supplier',
  'suppliers',
  'public',
  'investor',
  'data',
  'protection',
  'bug',
  'group',
  'questions',
  'policy',
  'requests',
  'reports',
  'aggregate',
  'alerts',
  'response',
]);

const DMARC_TELEMETRY_SUBTOKENS = new Set([
  'dmarc',
  'rua',
  'ruf',
  'forensics',
  'spf',
  'tls',
  'rpt',
]);

const RESERVED_GITHUB_NON_PROFILE_PATHS = new Set([
  'login',
  'signup',
  'pricing',
  'features',
  'about',
  'why-github',
  'account',
  'session',
  'join',
  'new',
  'organizations',
  'education',
  'nonprofit',
  'git-guides',
  'customer-terms',
  'trust-center',
  'newsroom',
  'blog',
  'diversity',
  'sustainability',
  'social-impact',
  'security',
  'settings',
  'marketplace',
  'sponsors',
  'orgs',
  'topics',
  'collections',
  'events',
  'trending',
  'readme',
  'customer-stories',
  'enterprise',
  'mobile',
  'copilot',
  'codespaces',
  'notifications',
  'pulls',
  'issues',
  'explore',
  'search',
  'site',
  'platform',
  'solutions',
  'resources',
  'open-source',
  'services',
  'team',
  'contact',
  'premium-support',
  'partners',
  'privacy',
  'press',
  'support',
  'legal',
  'status',
  'terms',
  'docs',
  'careers',
  'investors',
  'customers',
  'spark',
  'models',
  'fluidicon.png',
]);

const RESERVED_X_NON_PROFILE_PATHS = new Set([
  'intent',
  'share',
  'home',
  'explore',
  'search',
  'login',
  'signup',
  'i',
  'settings',
  'privacy',
  'tos',
  'hashtag',
]);

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

const TWO_PART_CCTLD_SUFFIXES = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'nhs.uk',
  'police.uk',
  'plc.uk',
  'ltd.uk',
  'sch.uk',
  'me.uk',
  'net.uk',
  'gouv.fr',
  'asso.fr',
  'gob.es',
  'gob.mx',
  'gob.ar',
  'gob.pe',
  'gob.cl',
  'gov.br',
  'mil.br',
  'edu.br',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'gov.au',
  'asn.au',
  'id.au',
  'co.jp',
  'ne.jp',
  'or.jp',
  'ac.jp',
  'ad.jp',
  'ed.jp',
  'go.jp',
  'gr.jp',
  'lg.jp',
  'kobe.jp',
  'osaka.jp',
  'tokyo.jp',
  'yokohama.jp',
  'nagoya.jp',
  'sapporo.jp',
  'kyoto.jp',
  'fukuoka.jp',
  'kawasaki.jp',
  'saitama.jp',
  'hiroshima.jp',
  'sendai.jp',
  'kitakyushu.jp',
  'chiba.jp',
  'co.nz',
  'org.nz',
  'net.nz',
  'govt.nz',
  'ac.nz',
  'co.in',
  'net.in',
  'org.in',
  'gen.in',
  'firm.in',
  'ind.in',
  'ac.in',
  'edu.in',
  'res.in',
  'gov.in',
  'co.kr',
  'or.kr',
  'ne.kr',
  're.kr',
  'pe.kr',
  'go.kr',
  'ac.kr',
  'co.za',
  'org.za',
  'net.za',
  'gov.za',
  'ac.za',
  'com.br',
  'net.br',
  'org.br',
  'com.sg',
  'edu.sg',
  'org.sg',
  'net.sg',
  'gov.sg',
  'com.mx',
  'org.mx',
  'net.mx',
  'edu.mx',
  'com.hk',
  'org.hk',
  'edu.hk',
  'gov.hk',
  'net.hk',
  'com.tw',
  'org.tw',
  'net.tw',
  'edu.tw',
  'gov.tw',
  'com.cn',
  'net.cn',
  'org.cn',
  'gov.cn',
  'edu.cn',
  'com.tr',
  'org.tr',
  'gov.tr',
  'edu.tr',
  'co.il',
  'org.il',
  'ac.il',
  'gov.il',
  'com.ar',
  'org.ar',
  'com.co',
  'org.co',
  'gov.co',
  'edu.co',
  'com.my',
  'org.my',
  'gov.my',
  'edu.my',
  'com.ph',
  'org.ph',
  'gov.ph',
  'edu.ph',
  'com.vn',
  'org.vn',
  'gov.vn',
  'edu.vn',
  'co.id',
  'or.id',
  'ac.id',
  'go.id',
  'co.th',
  'or.th',
  'ac.th',
  'go.th',
]);

const MULTI_TENANT_HOSTING_SUFFIXES = new Set([
  'github.io',
  'gitlab.io',
  'bitbucket.io',
  'vercel.app',
  'netlify.app',
  'pages.dev',
  'workers.dev',
  'fly.dev',
  'railway.app',
  'onrender.com',
  'herokuapp.com',
  'myshopify.com',
  'appspot.com',
  'web.app',
  'firebaseapp.com',
  'run.app',
  'cloudfunctions.net',
  'azurewebsites.net',
  'amplifyapp.com',
  'webflow.io',
  'framer.website',
  'framer.app',
  'notion.site',
  'substack.com',
  'zendesk.com',
  'freshdesk.com',
  'atlassian.net',
  'force.com',
  'wordpress.com',
  'blogspot.com',
  'ghost.io',
  'surge.sh',
  'deno.dev',
  'replit.app',
  'glitch.me',
  'ngrok-free.app',
  'ngrok.io',
]);

const THREE_PART_MULTI_TENANT_SUFFIXES = new Set([
  'cloudapp.azure.com',
  's3.amazonaws.com',
  'elb.amazonaws.com',
]);

const STRIPPABLE_SUBDOMAIN_LABELS = new Set([
  'www',
  'app',
  'careers',
  'jobs',
  'boards',
  'work',
  'talent',
  'hiring',
  'join',
  'apply',
  'people',
  'about',
  'security',
  'press',
  'news',
  'newsroom',
  'trust',
  'ir',
  'investors',
  'legal',
  'privacy',
  'status',
  'docs',
  'blog',
  'developers',
  'developer',
  'support',
  'help',
  'portal',
  'console',
  'dashboard',
  'team',
  'company',
  'corp',
  'global',
  'intl',
  'eu',
  'us',
  'apac',
  'emea',
  'amer',
  'latam',
  'mail',
  'contact',
  'info',
  'hello',
  'hq',
  'api',
  'auth',
  'login',
  'id',
  'account',
  'accounts',
  'billing',
  'pay',
  'checkout',
  'shop',
  'store',
  'cloud',
  'platform',
  'marketing',
  'events',
  'community',
  'forum',
  'learn',
  'academy',
  'training',
  'partners',
  'partner',
  'affiliates',
  'media',
  'brand',
  'assets',
  'cdn',
  'static',
  'm',
  'mobile',
  'web',
  'go',
  'try',
  'get',
]);

const RFC2606_TEST_PARENT_DOMAINS = new Set([
  'example.org',
  'example.com',
  'example.net',
]);

function isTwoPartCcTldSuffix(lastTwo) {
  const lower = String(lastTwo || '').toLowerCase();
  return (
    TWO_PART_CCTLD_SUFFIXES.has(lower) ||
    /^(?:co|com|org|net|ac|gov|edu|or|ne|go|gob|gouv|nhs|police|plc|ltd|sch|mil)\.[a-z]{2}$/i.test(
      lower
    )
  );
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

  const rawHostProbe = trimmed
    .replace(/^[a-z0-9+.-]+:\/\//i, '')
    .split(/[/?#]/)[0]
    .replace(/:\d+$/, '')
    .replace(/^\[|\]$/g, '')
    .trim();
  if (
    rawHostProbe &&
    (net.isIP(rawHostProbe) !== 0 || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(rawHostProbe))
  ) {
    return {
      ok: false,
      reason: `IP address literal '${rawHostProbe}' is not a valid public B2B domain`,
    };
  }

  let candidateUrl = trimmed;
  if (!candidateUrl.includes('/') && !candidateUrl.includes(':') && (/[\s,]/.test(candidateUrl) || !candidateUrl.includes('.'))) {
    const strippedCorp = candidateUrl
      .replace(/[,()]/g, ' ')
      .replace(
        /\b(?:inc|incorporated|llc|ltd|limited|corp|corporation|co|company|gmbh|plc|ag|sa|srl|bv|nv|pty|opco|holdco|holdings|hq|group|international|global|technologies|technology|tech|labs|software|systems|platforms)\b\.?/gi,
        ' '
      )
      .trim();
    if (strippedCorp && !strippedCorp.includes(' ')) {
      const bareLower = strippedCorp.toLowerCase();
      const matchedCurated = Object.keys(CURATED_B2B_DOMAIN_DIRECTORY).find(
        (dom) => dom.split('.')[0] === bareLower
      );
      if (matchedCurated) {
        candidateUrl = matchedCurated;
      } else if (bareLower.includes('.')) {
        candidateUrl = bareLower;
      }
    }
  }
  if (/^http:\/\//i.test(candidateUrl)) {
    candidateUrl = candidateUrl.replace(/^http:\/\//i, 'https://');
  } else if (!/^https:\/\//i.test(candidateUrl)) {
    if (/^[a-z0-9+.-]+:\/\//i.test(candidateUrl)) {
      return { ok: false, reason: `Unsupported protocol in '${trimmed}' (only https:// or bare domain allowed)` };
    }
    candidateUrl = `https://${candidateUrl}`;
  }
  const ssrf = verifyEgressUrlSsrfSafe(candidateUrl);
  if (!ssrf.safe) {
    return { ok: false, reason: ssrf.reason || `Unsafe domain '${trimmed}'` };
  }

  let cleanHost = ssrf.hostname.toLowerCase().replace(/\.+$/, '');
  if (net.isIP(cleanHost) !== 0) {
    return { ok: false, reason: `IP address literal '${cleanHost}' is not a valid public B2B domain` };
  }
  const initialLabels = cleanHost.split('.').filter(Boolean);
  if (initialLabels.length < 2) {
    return { ok: false, reason: `Invalid public B2B domain '${cleanHost}'` };
  }
  const rawTld = initialLabels[initialLabels.length - 1];
  if (/^\d+$/.test(rawTld) || !/^(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i.test(rawTld)) {
    return { ok: false, reason: `Invalid numeric or non-DNS top-level domain '${rawTld}'` };
  }

  const resolveMinRootLabels = (parts) => {
    if (parts.length >= 3) {
      const tailThree = `${parts[parts.length - 3]}.${parts[parts.length - 2]}.${parts[parts.length - 1]}`.toLowerCase();
      if (THREE_PART_MULTI_TENANT_SUFFIXES.has(tailThree)) {
        return 4;
      }
    }
    if (parts.length >= 2) {
      const tailTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`.toLowerCase();
      if (
        isTwoPartCcTldSuffix(tailTwo) ||
        MULTI_TENANT_HOSTING_SUFFIXES.has(tailTwo) ||
        RFC2606_TEST_PARENT_DOMAINS.has(tailTwo)
      ) {
        return 3;
      }
    }
    return 2;
  };

  while (true) {
    const hostParts = cleanHost.split('.').filter(Boolean);
    const minRootLabels = resolveMinRootLabels(hostParts);
    if (hostParts.length <= minRootLabels) break;
    const headLabel = hostParts[0].toLowerCase();
    if (!STRIPPABLE_SUBDOMAIN_LABELS.has(headLabel)) break;
    cleanHost = hostParts.slice(1).join('.');
  }

  const finalLabels = cleanHost.split('.').filter(Boolean);
  if (
    (finalLabels.length === 2 &&
      (isTwoPartCcTldSuffix(cleanHost) || MULTI_TENANT_HOSTING_SUFFIXES.has(cleanHost))) ||
    (finalLabels.length === 3 && THREE_PART_MULTI_TENANT_SUFFIXES.has(cleanHost))
  ) {
    return { ok: false, reason: `Invalid bare public suffix '${cleanHost}'` };
  }
  if (!cleanHost || finalLabels.length < 2) {
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
  const stripCorpSuffixes = (s) =>
    String(s ?? '').replace(
      /,?\s+\b(?:inc|incorporated|llc|ltd|limited|corp|corporation|co|company|gmbh|plc|ag|sa|srl|bv|nv|pty|opco|holdco|holdings|hq|group)\b\.?/gi,
      ''
    );
  const tokens = Array.isArray(rawQuery)
    ? rawQuery.flatMap((item) => stripCorpSuffixes(item).split(/[\s,;]+/))
    : stripCorpSuffixes(rawQuery).split(/[\s,;]+/);
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

  const subTokens = localPart.split(/[._-]+/).filter(Boolean);
  if (subTokens.length === 0 || subTokens.length > 5) {
    return 'PERSONAL_EXCLUDED';
  }
  const hasDmarcTelemetryToken = subTokens.some((tok) => DMARC_TELEMETRY_SUBTOKENS.has(tok));
  if (hasDmarcTelemetryToken) {
    const allDmarcTokensAllowed = subTokens.every(
      (tok) =>
        CORE_B2B_ROLE_SUBTOKENS.has(tok) ||
        B2B_QUALIFIER_SUBTOKENS.has(tok) ||
        DMARC_TELEMETRY_SUBTOKENS.has(tok)
    );
    return allDmarcTokensAllowed ? 'DMARC_REPORTING' : 'PERSONAL_EXCLUDED';
  }
  const allTokensAllowed = subTokens.every(
    (tok) => CORE_B2B_ROLE_SUBTOKENS.has(tok) || B2B_QUALIFIER_SUBTOKENS.has(tok)
  );
  const hasCoreRoleToken =
    subTokens.some((tok) => CORE_B2B_ROLE_SUBTOKENS.has(tok)) ||
    (subTokens.includes('data') && subTokens.includes('protection'));
  if (!allTokensAllowed || !hasCoreRoleToken) {
    return 'PERSONAL_EXCLUDED';
  }

  const hasSubToken = (re) => subTokens.some((tok) => re.test(tok));

  if (
    hasSubToken(
      /^(?:security|sec|psirt|csirt|soc|vuln|vulnerability|bugbounty|bounty|bug|abuse|cert|infosec|trust|disclosure)$/
    ) ||
    /\b(?:security|vulnerability|psirt|csirt|bug\s*bounty|abuse)\b/.test(hint)
  ) {
    return 'SECURITY';
  }
  if (
    hasSubToken(/^(?:privacy|dpo|dataprotection|gdpr|ccpa|privacyquestions|privacypolicy)$/) ||
    (subTokens.includes('data') && subTokens.includes('protection')) ||
    /\b(?:privacy|dpo|data\s*protection|gdpr|ccpa)\b/.test(hint)
  ) {
    return 'PRIVACY_DPO';
  }
  if (
    hasSubToken(
      /^(?:billing|finance|accounts|accounting|payable|receivable|ap|ar|invoicing|invoices|payments|tax|vat|treasury|procurement)$/
    ) ||
    /\b(?:billing|finance|invoic|accounts\s*payable|tax|vat)\b/.test(hint)
  ) {
    return 'BILLING_FINANCE';
  }
  if (
    hasSubToken(
      /^(?:legal|compliance|dmca|copyright|trademark|subpoena|lawenforcement|counsel|notices|terms)$/
    ) ||
    /\b(?:legal|compliance|dmca|counsel|trademark)\b/.test(hint)
  ) {
    return 'LEGAL';
  }
  if (
    hasSubToken(
      /^(?:support|help|helpdesk|care|customerservice|customercare|success|customersuccess|service)$/
    ) ||
    /\b(?:support|helpdesk|customer\s*service|customer\s*care|technical\s*support)\b/.test(hint)
  ) {
    return 'SUPPORT';
  }
  if (
    hasSubToken(
      /^(?:sales|enterprise|partners|partnerships|bd|bizdev|deals|solutions|commercial|revenue)$/
    ) ||
    /\b(?:sales|enterprise|partnership|business\s*development)\b/.test(hint)
  ) {
    return 'SALES';
  }
  if (
    hasSubToken(/^(?:press|media|pr|communications|comms|news|newsroom|analyst)$/) ||
    (subTokens.includes('public') && subTokens.includes('relations')) ||
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
    .replace(/[.,;:)>\]'"]+$/, '')
    .replace(/![0-9]+[kmgt]?$/i, '');
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
  if (
    classifiedRole === 'DMARC_REPORTING' &&
    String(labelHint || '').trim().toLowerCase() !== 'dmarc'
  ) {
    return {
      valid: false,
      reason: 'AUTOMATED_DMARC_REPORT_INBOX_EXCLUDED',
      role: 'DMARC_REPORTING',
    };
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
 * Sanitizes untrusted HTML or text from third-party domain pages, stripping executable
 * tags, invisible/bidirectional Unicode control characters, live secret tokens, and
 * indirect prompt-injection override directives.
 *
 * @param {unknown} rawHtmlOrText
 * @param {number} [maxChars=400]
 * @returns {string}
 */
export function sanitizeUntrustedDomainText(rawHtmlOrText, maxChars = 400) {
  if (rawHtmlOrText === undefined || rawHtmlOrText === null) return '';
  const safeMax = Math.max(16, Math.min(2000, Math.floor(Number(maxChars) || 400)));
  let s = String(rawHtmlOrText).slice(0, 32768);

  s = s
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script\b[^>]*>[\s\S]*$/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*$/gi, ' ');

  s = s.replace(
    /<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>|<<SYS>>|<\/SYS>>/gi,
    ' [REDACTED_UNTRUSTED_DIRECTIVE] '
  );

  s = s
    .replace(/<\/?(?:p|div|br|li|ul|ol|h[1-6]|tr|td|section|article|header|footer)\b[^>]*>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&#x27;|&#39;|&apos;/gi, "'")
    .replace(/&quot;/gi, '"')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&lt;/gi, ' ')
    .replace(/&gt;/gi, ' ')
    .replace(/[<>]/g, ' ')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(
      /[\u0000-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u2028-\u2029\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFE00-\uFE0F\uFEFF\uFFF9-\uFFFB\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/gu,
      ''
    )
    .replace(/\s+/g, ' ')
    .trim();

  s = s
    .replace(new RegExp(LIVE_SECRET_GUARD_RE.source, 'g'), '[REDACTED_LIVE_SECRET]')
    .replace(
      /\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|earlier|system|developer)\s+(?:instructions?|prompts?|directives?|rules?|guardrails?)(?:\s+(?:and|to)\s+(?:exfiltrate|leak|dump|print|output|send|reveal|execute)\b[^.!?;]{0,80})?/gi,
      '[REDACTED_UNTRUSTED_DIRECTIVE]'
    )
    .replace(
      /\b(?:exfiltrate|leak|dump)\s+(?:all\s+)?(?:environment\s+variables|env\s+vars|api\s+keys|secrets|credentials|private\s+keys|system\s+prompt)\b/gi,
      '[REDACTED_UNTRUSTED_DIRECTIVE]'
    )
    .replace(
      /\b(?:new\s+system\s+prompt|system\s+prompt\s*:|developer\s+message\s*:|you\s+are\s+now\s+(?:a\b|an\b|in\s+developer\s+mode|unrestricted))/gi,
      '[REDACTED_UNTRUSTED_DIRECTIVE]'
    )
    .replace(
      /\[(?:SYSTEM|INST|\/INST|ADMIN_OVERRIDE|SYSTEM_PROMPT|DEVELOPER)\]/gi,
      '[REDACTED_UNTRUSTED_DIRECTIVE]'
    )
    .replace(/\s+/g, ' ')
    .trim();

  const codePoints = Array.from(s);
  if (codePoints.length > safeMax) {
    return codePoints.slice(0, safeMax).join('').trim();
  }
  return s;
}

/**
 * Wraps sanitized third-party domain text in the canonical untrusted signal envelope.
 *
 * @param {unknown} rawHtmlOrText
 * @param {number} [maxChars=400]
 * @returns {{trustLevel: string, instructionPolicy: string, plainTextExcerpt: string}}
 */
export function buildUntrustedDomainExcerpt(rawHtmlOrText, maxChars = 400) {
  return {
    trustLevel: 'UNTRUSTED_PUBLIC_DOMAIN_SIGNAL',
    instructionPolicy: 'DATA_ONLY_NEVER_EXECUTE_OR_FOLLOW_DIRECTIVES',
    plainTextExcerpt: sanitizeUntrustedDomainText(rawHtmlOrText, maxChars),
  };
}

/**
 * Extracts a clean organization name from raw `<title>` inner text, splitting on standard
 * title delimiters (including backslash `\`) and stripping generic `'Home'`/`'Welcome'` prefixes.
 *
 * @param {string} rawTitleText
 * @returns {string}
 */
export function extractOrganizationNameFromTitleText(rawTitleText) {
  const decodedTitle = sanitizeUntrustedDomainText(
    String(rawTitleText ?? '')
      .replace(/&amp;/gi, '&')
      .replace(/&#x27;|&#39;|&apos;/gi, "'")
      .replace(/&quot;/gi, '"'),
    160
  );
  if (!decodedTitle) return '';
  const segments = decodedTitle
    .split(/\s*[:|\\/\-\u2013\u2014\u2022\u00b7]\s*/)
    .map((s) => s.trim())
    .filter(Boolean);
  const candidateSeg =
    segments.find((seg) => !/^(?:home|homepage|welcome|index)$/i.test(seg)) || segments[0] || '';
  const cleanTitle = candidateSeg
    .replace(/^(?:home\s+of\s+|welcome\s+to\s+|home\s+)/i, '')
    .trim();
  if (cleanTitle.length >= 2 && cleanTitle.length <= 48) {
    return cleanTitle;
  }
  return '';
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

  // 2. Schema.org JSON-LD ContactPoint & Organization sameAs blocks
  const socialProfiles = {};
  const tryAcceptSocialUrl = (rawSocialUrl) => {
    const cleanUrl = String(rawSocialUrl ?? '').trim().replace(/\/+$/, '');
    if (
      !cleanUrl ||
      FALSE_POSITIVE_ASSET_TLD_RE.test(cleanUrl) ||
      /\.(?:json|xml|txt)$/i.test(cleanUrl)
    ) {
      return;
    }
    const liMatch = cleanUrl.match(/^https:\/\/(?:www\.)?linkedin\.com\/company\/([a-zA-Z0-9_-]+)$/i);
    if (liMatch && !socialProfiles.linkedin) {
      socialProfiles.linkedin = liMatch[0];
      return;
    }
    const ghMatch = cleanUrl.match(/^https:\/\/github\.com\/([a-zA-Z0-9_.-]+)$/i);
    if (ghMatch && !socialProfiles.github) {
      const slug = ghMatch[1].toLowerCase();
      if (
        !RESERVED_GITHUB_NON_PROFILE_PATHS.has(slug) &&
        !FALSE_POSITIVE_ASSET_TLD_RE.test(slug) &&
        !/\.(?:json|xml|txt)$/i.test(slug)
      ) {
        socialProfiles.github = ghMatch[0];
      }
      return;
    }
    const xMatch = cleanUrl.match(/^https:\/\/(?:x\.com|twitter\.com)\/([a-zA-Z0-9_]{2,32})$/i);
    if (xMatch && !socialProfiles.x) {
      const handle = xMatch[1].toLowerCase();
      if (!RESERVED_X_NON_PROFILE_PATHS.has(handle)) {
        socialProfiles.x = `https://x.com/${xMatch[1]}`;
      }
    }
  };

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
        const sameAsList = Array.isArray(node.sameAs)
          ? node.sameAs
          : typeof node.sameAs === 'string'
            ? [node.sameAs]
            : [];
        for (const sameUrl of sameAsList) {
          tryAcceptSocialUrl(sameUrl);
        }
      }
    } catch {
      // Ignore malformed JSON-LD blocks
    }
  }

  // 3. De-obfuscate HTML entities & bracketed [at] / (at) patterns (replacing non-anchor HTML tags with spaces to prevent cross-tag word concatenation)
  const entityNormalized = text
    .replace(
      /<\/?(?:p|div|span|li|ul|ol|td|tr|th|table|br|hr|h[1-6]|strong|em|b|i|code|pre|section|article|header|footer|main|nav)\b[^<>]*>/gi,
      ' '
    )
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
  for (const liMatch of text.matchAll(/https:\/\/(?:www\.)?linkedin\.com\/company\/[a-zA-Z0-9_-]+\/?(?=["'\s<>)]|$)/gi)) {
    tryAcceptSocialUrl(liMatch[0]);
    if (socialProfiles.linkedin) break;
  }
  for (const ghMatch of text.matchAll(/https:\/\/github\.com\/[a-zA-Z0-9_.-]+\/?(?=["'\s<>)]|$)/gi)) {
    tryAcceptSocialUrl(ghMatch[0]);
    if (socialProfiles.github) break;
  }
  for (const xMatch of text.matchAll(/https:\/\/(?:x\.com|twitter\.com)\/[a-zA-Z0-9_.]{2,32}\/?(?=["'\s<>)]|$)/gi)) {
    tryAcceptSocialUrl(xMatch[0]);
    if (socialProfiles.x) break;
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
  let dmarcRuf = null;
  const dmarcEmails = [];
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
    const rufMatch = dmarcRecord.match(/(?:^|;)\s*ruf\s*=\s*([^;]+)/i);
    if (rufMatch) dmarcRuf = rufMatch[1].trim();

    const seenDmarcEmails = new Set();
    for (const rawList of [dmarcRua, dmarcRuf]) {
      if (!rawList) continue;
      for (const token of rawList.split(',')) {
        const trimmedUri = token.trim();
        if (!/^mailto:/i.test(trimmedUri) && !trimmedUri.includes('@')) continue;
        const validated = validateExtractedB2bEmail(trimmedUri, 'dmarc');
        if (validated.valid && !seenDmarcEmails.has(validated.email)) {
          seenDmarcEmails.add(validated.email);
          dmarcEmails.push(validated.email);
        }
      }
    }
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
    dmarcRuf,
    dmarcEmails,
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
        servername: net.isIP(parsed.hostname) === 0 ? parsed.hostname : undefined,
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
  const rawTimeoutMs = timeoutMs === undefined ? 3500 : Number(timeoutMs);
  if (!Number.isFinite(rawTimeoutMs) || rawTimeoutMs <= 0) {
    return { ok: false, status: 0, reason: 'TIMEOUT', text: '' };
  }
  const totalBudgetMs = Math.max(1, Math.min(8000, rawTimeoutMs));
  const fetchDeadlineAtMs = Date.now() + totalBudgetMs;
  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const dnsBudgetMs = fetchDeadlineAtMs - Date.now();
    if (dnsBudgetMs <= 0) {
      return { ok: false, status: 0, reason: 'TIMEOUT', text: '' };
    }
    const ssrf = verifyEgressUrlSsrfSafe(currentUrl);
    if (!ssrf.safe) {
      return { ok: false, status: 0, reason: `SSRF_BLOCKED:${ssrf.reason}`, text: '' };
    }
    let pinnedAgent = null;
    if (typeof dnsLookup === 'function' || fetchImpl === globalThis.fetch) {
      const dnsCheck = await resolveAndVerifyPublicHostname(
        ssrf.hostname,
        dnsLookup,
        dnsBudgetMs
      );
      if (!dnsCheck.safe) {
        return { ok: false, status: 0, reason: `SSRF_DNS_BLOCKED:${dnsCheck.reason}`, text: '' };
      }
      const postDnsBudgetMs = fetchDeadlineAtMs - Date.now();
      if (postDnsBudgetMs <= 0) {
        return { ok: false, status: 0, reason: 'TIMEOUT', text: '' };
      }
      pinnedAgent = createEphemeralHttpsAgent(postDnsBudgetMs, dnsCheck.addresses?.[0] || null);
    }
    const httpBudgetMs = fetchDeadlineAtMs - Date.now();
    if (httpBudgetMs <= 0) {
      return { ok: false, status: 0, reason: 'TIMEOUT', text: '' };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), httpBudgetMs);
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
              timeoutMs: httpBudgetMs,
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
  const rawTimeoutMs = timeoutMs === undefined ? 2500 : Number(timeoutMs);
  if (!Number.isFinite(rawTimeoutMs) || rawTimeoutMs <= 0) return [];
  const dohDeadlineAtMs = Date.now() + Math.max(1, Math.min(8000, rawTimeoutMs));
  for (const url of endpoints) {
    const remMs = dohDeadlineAtMs - Date.now();
    if (remMs <= 0) break;
    const res = await fetchHttpsTextBounded(url, {
      fetchImpl,
      dnsLookup,
      timeoutMs: remMs,
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

const CONTACT_TARGET_ALIAS_KEYS_BATCH = Object.freeze([
  'query',
  'domain',
  'domains',
  'company',
  'url',
]);
const CONTACT_TARGET_ALIAS_KEYS_VERIFY = Object.freeze([
  'email',
  'domain',
  'domains',
  'query',
  'company',
  'url',
]);
const CONTACT_LIMIT_ALIAS_KEYS = Object.freeze(['limit', 'maxResults', 'max_results']);

function computeCanonicalContactTargetSignature(rawVal) {
  if (Array.isArray(rawVal)) {
    const parsed = parseDomainBatchInput(rawVal);
    if (parsed.ok && parsed.domains.length > 0) {
      return parsed.domains.join(',');
    }
    return rawVal
      .map((x) => String(x ?? '').trim().toLowerCase())
      .filter(Boolean)
      .join(',');
  }
  const str = String(rawVal ?? '').trim();
  if (!str) return '';
  if (str.includes('@') && !str.includes(' ') && !str.includes(',')) {
    const domPart = str.split('@').slice(1).join('@').trim().toLowerCase();
    const normDom = normalizeTargetB2bDomain(domPart);
    return normDom.ok ? normDom.domain : domPart;
  }
  const parsed = parseDomainBatchInput(str);
  if (parsed.ok && parsed.domains.length > 0) {
    return parsed.domains.join(',');
  }
  return str.toLowerCase();
}

/**
 * Normalizes cross-layer parameter aliases (`query`/`domain`/`domains`/`company`/`url`/`email` and
 * `limit`/`maxResults`/`max_results`) across ContactPulse Core Engine, Apify Actor, and MCP Server.
 * Fails closed with `errorCode: 'CONFLICTING_PARAMETER_ALIASES'` when multiple aliases in the same
 * group resolve to different values.
 *
 * @param {unknown} rawInput
 * @param {'batch'|'single'|'verify'} [mode='batch']
 * @returns {{ok: boolean, normalized: object, status?: string, errorCode?: string, reason?: string}}
 */
export function normalizeContactPulseInputAliases(rawInput = {}, mode = 'batch') {
  if (typeof rawInput === 'string') {
    const trimmed = rawInput.trim();
    return {
      ok: true,
      normalized: {
        query: trimmed,
        domain: trimmed,
        ...(trimmed.includes('@') ? { email: trimmed } : {}),
      },
    };
  }
  if (!rawInput || typeof rawInput !== 'object' || Array.isArray(rawInput)) {
    return {
      ok: false,
      normalized: {},
      status: 'INVALID_INPUT',
      errorCode: 'INVALID_INPUT',
      reason: 'Input parameters must be a JSON object',
    };
  }
  const normalized = { ...rawInput };
  const targetKeys =
    mode === 'verify' ? CONTACT_TARGET_ALIAS_KEYS_VERIFY : CONTACT_TARGET_ALIAS_KEYS_BATCH;

  const providedTargets = [];
  for (const key of targetKeys) {
    const val = rawInput[key];
    if (val === undefined || val === null) continue;
    if (key === 'domains') {
      if (typeof val !== 'string' && !Array.isArray(val)) {
        return {
          ok: false,
          normalized,
          status: 'INVALID_INPUT',
          errorCode: 'INVALID_PARAMETER_TYPE',
          reason: `Parameter 'domains' must be a string or array of strings`,
        };
      }
      if (Array.isArray(val)) {
        if (val.some((item) => typeof item !== 'string')) {
          return {
            ok: false,
            normalized,
            status: 'INVALID_INPUT',
            errorCode: 'INVALID_PARAMETER_TYPE',
            reason: `All items in 'domains' array must be strings`,
          };
        }
        const nonEmptyItems = val.map((x) => x.trim()).filter(Boolean);
        if (nonEmptyItems.length > 0) {
          providedTargets.push({
            key,
            val: nonEmptyItems,
            display: nonEmptyItems.join(', '),
            sig: computeCanonicalContactTargetSignature(nonEmptyItems),
          });
        }
      } else {
        const trimmed = val.trim();
        if (trimmed.length > 0) {
          providedTargets.push({
            key,
            val: trimmed,
            display: trimmed,
            sig: computeCanonicalContactTargetSignature(trimmed),
          });
        }
      }
    } else {
      if (typeof val !== 'string') {
        return {
          ok: false,
          normalized,
          status: 'INVALID_INPUT',
          errorCode: 'INVALID_PARAMETER_TYPE',
          reason: `Parameter '${key}' must be a string`,
        };
      }
      const trimmed = val.trim();
      if (trimmed.length > 0) {
        const isSingleEmail =
          trimmed.includes('@') && !trimmed.includes(' ') && !trimmed.includes(',');
        providedTargets.push({
          key,
          val: trimmed,
          display: trimmed,
          sig: computeCanonicalContactTargetSignature(trimmed),
          emailLower: isSingleEmail ? trimmed.toLowerCase() : null,
        });
      }
    }
  }

  if (providedTargets.length > 1) {
    const first = providedTargets[0];
    for (let i = 1; i < providedTargets.length; i += 1) {
      const other = providedTargets[i];
      const emailConflict =
        Boolean(first.emailLower && other.emailLower) &&
        first.emailLower !== other.emailLower;
      if (first.sig !== other.sig || emailConflict) {
        return {
          ok: false,
          normalized,
          status: 'INVALID_INPUT',
          errorCode: 'CONFLICTING_PARAMETER_ALIASES',
          reason: `Conflicting target parameters: '${first.key}' ("${first.display}") and '${other.key}' ("${other.display}") resolve to different targets`,
        };
      }
    }
  }

  if (providedTargets.length > 0) {
    const primaryDisplay = providedTargets[0].display;
    if (typeof normalized.query !== 'string' || !normalized.query.trim()) {
      normalized.query = primaryDisplay;
    }
    if (typeof normalized.domain !== 'string' || !normalized.domain.trim()) {
      normalized.domain = primaryDisplay;
    }
    if (mode === 'verify') {
      const emailTarget = providedTargets.find((t) => t.display.includes('@'));
      if (emailTarget) {
        if (typeof normalized.email !== 'string' || !normalized.email.trim()) {
          normalized.email = emailTarget.display;
        }
        normalized.query = emailTarget.display;
      }
    }
  }

  // Limit / maxResults / max_results alias group
  const providedLimits = [];
  for (const key of CONTACT_LIMIT_ALIAS_KEYS) {
    const val = rawInput[key];
    if (val === undefined || val === null || val === '') continue;
    providedLimits.push({ key, val });
  }

  if (providedLimits.length > 1) {
    const first = providedLimits[0];
    const firstNum = Number(first.val);
    for (let i = 1; i < providedLimits.length; i += 1) {
      const other = providedLimits[i];
      const otherNum = Number(other.val);
      if (
        typeof first.val === 'boolean' ||
        typeof other.val === 'boolean' ||
        !Number.isFinite(firstNum) ||
        !Number.isFinite(otherNum) ||
        firstNum !== otherNum
      ) {
        return {
          ok: false,
          normalized,
          status: 'INVALID_INPUT',
          errorCode: 'CONFLICTING_PARAMETER_ALIASES',
          reason: `Conflicting limit parameters: '${first.key}' (${String(first.val)}) and '${other.key}' (${String(other.val)}) do not match`,
        };
      }
    }
  }

  if (providedLimits.length > 0) {
    const chosenLimit = providedLimits[0].val;
    normalized.limit = chosenLimit;
    normalized.maxResults = chosenLimit;
  }

  // Cursor / pageToken alias group
  const hasPageToken =
    rawInput.pageToken !== undefined &&
    rawInput.pageToken !== null &&
    String(rawInput.pageToken).trim() !== '';
  const hasCursor =
    rawInput.cursor !== undefined &&
    rawInput.cursor !== null &&
    String(rawInput.cursor).trim() !== '';
  if (hasPageToken && hasCursor && String(rawInput.pageToken).trim() !== String(rawInput.cursor).trim()) {
    return {
      ok: false,
      normalized,
      status: 'INVALID_INPUT',
      errorCode: 'CONFLICTING_PARAMETER_ALIASES',
      reason: `Conflicting pagination cursor parameters: 'pageToken' and 'cursor' do not match`,
    };
  }
  if (!hasPageToken && hasCursor) {
    normalized.pageToken = rawInput.cursor;
  }

  return { ok: true, normalized };
}

/**
 * Builds a normalized B2B Domain Contact & Deliverability Profile for a single domain.
 */
export async function enrichSingleB2bDomain(rawDomain, options = {}) {
  let effectiveRawDomain = rawDomain;
  let effectiveOptions = options || {};
  if (rawDomain && typeof rawDomain === 'object' && !Array.isArray(rawDomain)) {
    const aliasNorm = normalizeContactPulseInputAliases(rawDomain, 'single');
    if (!aliasNorm.ok) {
      return {
        ok: false,
        status: 'INVALID_INPUT',
        errorCode: aliasNorm.errorCode || 'INVALID_INPUT',
        reason: aliasNorm.reason,
      };
    }
    const normObj = aliasNorm.normalized;
    effectiveRawDomain =
      normObj.domain ?? normObj.query ?? normObj.company ?? normObj.url ?? '';
    effectiveOptions = {
      ...normObj,
      ...effectiveOptions,
      preferCurated:
        effectiveOptions.preferCurated === true ||
        normObj.preferCurated === true ||
        normObj.useSampleFixtures === true,
    };
  }
  const {
    roleFilter = 'ANY',
    includeDnsPosture = true,
    includeSecurityTxt = true,
    fetchImpl = globalThis.fetch,
    dnsLookup = undefined,
    nowMs = Date.now(),
    deadlineAtMs = undefined,
    preferCurated = false,
  } = effectiveOptions;

  const norm = normalizeTargetB2bDomain(effectiveRawDomain);
  if (!norm.ok) {
    return {
      ok: false,
      status: 'INVALID_INPUT',
      errorCode: 'INVALID_INPUT',
      reason: norm.reason,
    };
  }
  const domain = norm.domain;
  const normalizedRoleList = Array.isArray(roleFilter)
    ? roleFilter
        .map((r) => String(r || '').trim().toUpperCase())
        .filter((r) => r && r !== 'ANY')
    : String(roleFilter || 'ANY').trim().toUpperCase() === 'ANY'
      ? []
      : [String(roleFilter).trim().toUpperCase()];
  const hasActiveRoleFilter = normalizedRoleList.length > 0;
  const curated = preferCurated === true ? CURATED_B2B_DOMAIN_DIRECTORY[domain] : null;

  const numericDeadlineAtMs = Number(deadlineAtMs);
  const getRemainingBudgetMs = (capMs) => {
    if (!Number.isFinite(numericDeadlineAtMs) || numericDeadlineAtMs <= 0) return capMs;
    return Math.min(capMs, Math.max(0, numericDeadlineAtMs - Date.now()));
  };

  if (!curated && (typeof dnsLookup === 'function' || fetchImpl === globalThis.fetch)) {
    const dnsCheck = await resolveAndVerifyPublicHostname(
      domain,
      dnsLookup,
      getRemainingBudgetMs(2500)
    );
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

  const isFirstPartyDomainEmail = (emailStr) => {
    const emailDom = String(emailStr || '').split('@')[1] || '';
    return emailDom === domain || emailDom.endsWith(`.${domain}`);
  };

  if (!curated && typeof fetchImpl === 'function') {
    const [dnsTuple, secWellKnownRes, homeRes] = await Promise.all([
      includeDnsPosture
        ? Promise.all([
            queryDohJsonRecords(domain, 'MX', {
              fetchImpl,
              dnsLookup,
              timeoutMs: getRemainingBudgetMs(2500),
            }),
            queryDohJsonRecords(domain, 'TXT', {
              fetchImpl,
              dnsLookup,
              timeoutMs: getRemainingBudgetMs(2500),
            }),
            queryDohJsonRecords(`_dmarc.${domain}`, 'TXT', {
              fetchImpl,
              dnsLookup,
              timeoutMs: getRemainingBudgetMs(2500),
            }),
          ])
        : Promise.resolve([[], [], []]),
      includeSecurityTxt
        ? fetchHttpsTextBounded(`https://${domain}/.well-known/security.txt`, {
            fetchImpl,
            dnsLookup,
            timeoutMs: getRemainingBudgetMs(3000),
          })
        : Promise.resolve({ ok: false, text: '' }),
      fetchHttpsTextBounded(`https://${domain}`, {
        fetchImpl,
        dnsLookup,
        timeoutMs: getRemainingBudgetMs(3500),
      }),
    ]);

    if (includeDnsPosture) {
      [mxHosts, txtRecords, dmarcTxtRecords] = dnsTuple;
    }
    if (includeSecurityTxt && secWellKnownRes.ok && secWellKnownRes.text) {
      securityTxtRaw = secWellKnownRes.text;
    }
    if (homeRes.ok && homeRes.text) {
      const extracted = extractContactsFromHtmlOrText(homeRes.text, 'HOMEPAGE_HTML');
      for (const c of extracted.contacts) {
        if (isFirstPartyDomainEmail(c.email) && !rawContacts.some((ex) => ex.email === c.email)) {
          rawContacts.push(c);
        }
      }
      socialProfiles = { ...socialProfiles, ...extracted.socialProfiles };
      const titleMatch = homeRes.text.match(/<title[^>]*>([^<]{2,120})<\/title>/i);
      if (titleMatch) {
        const parsedOrgName = extractOrganizationNameFromTitleText(titleMatch[1]);
        if (parsedOrgName) {
          organizationName = parsedOrgName;
        }
      }
    }

    const secParsedInitial = includeSecurityTxt
      ? parseRfc9116SecurityTxt(securityTxtRaw, nowMs)
      : { found: true, contacts: [], isExpired: false };
    const hasInitialSecEmail =
      !secParsedInitial.isExpired &&
      (secParsedInitial.contacts || []).some(
        (u) => (/^mailto:/i.test(u) || u.includes('@')) && validateExtractedB2bEmail(u).valid
      );
    const needsSecFallback = includeSecurityTxt && !secParsedInitial.found;
    const needsHtmlContactFallback = rawContacts.length === 0 && !hasInitialSecEmail;

    if ((needsSecFallback || needsHtmlContactFallback) && getRemainingBudgetMs(2200) >= 800) {
      const fbTimeout = getRemainingBudgetMs(2200);
      const [
        secRootRes,
        secWwwRes,
        contactPageRes,
        privacyPageRes,
        pressPageRes,
        sitePrivacyRes,
      ] = await Promise.all([
        needsSecFallback
          ? fetchHttpsTextBounded(`https://${domain}/security.txt`, {
              fetchImpl,
              dnsLookup,
              timeoutMs: fbTimeout,
            })
          : Promise.resolve({ ok: false, text: '' }),
        needsSecFallback
          ? fetchHttpsTextBounded(`https://www.${domain}/.well-known/security.txt`, {
              fetchImpl,
              dnsLookup,
              timeoutMs: fbTimeout,
            })
          : Promise.resolve({ ok: false, text: '' }),
        needsHtmlContactFallback
          ? fetchHttpsTextBounded(`https://${domain}/contact`, {
              fetchImpl,
              dnsLookup,
              timeoutMs: fbTimeout,
            })
          : Promise.resolve({ ok: false, text: '' }),
        needsHtmlContactFallback
          ? fetchHttpsTextBounded(`https://${domain}/privacy`, {
              fetchImpl,
              dnsLookup,
              timeoutMs: fbTimeout,
            })
          : Promise.resolve({ ok: false, text: '' }),
        needsHtmlContactFallback
          ? fetchHttpsTextBounded(`https://${domain}/press`, {
              fetchImpl,
              dnsLookup,
              timeoutMs: fbTimeout,
            })
          : Promise.resolve({ ok: false, text: '' }),
        needsHtmlContactFallback
          ? fetchHttpsTextBounded(`https://${domain}/site/privacy`, {
              fetchImpl,
              dnsLookup,
              timeoutMs: fbTimeout,
            })
          : Promise.resolve({ ok: false, text: '' }),
      ]);

      if (needsSecFallback) {
        if (secRootRes.ok && secRootRes.text && parseRfc9116SecurityTxt(secRootRes.text, nowMs).found) {
          securityTxtRaw = secRootRes.text;
        } else if (secWwwRes.ok && secWwwRes.text && parseRfc9116SecurityTxt(secWwwRes.text, nowMs).found) {
          securityTxtRaw = secWwwRes.text;
        }
      }

      for (const [pageRes, pageSource] of [
        [contactPageRes, 'CONTACT_PAGE'],
        [privacyPageRes, 'PRIVACY_PAGE'],
        [pressPageRes, 'PRESS_PAGE'],
        [sitePrivacyRes, 'PRIVACY_PAGE'],
      ]) {
        if (pageRes.ok && pageRes.text) {
          const pageExt = extractContactsFromHtmlOrText(pageRes.text, pageSource);
          for (const c of pageExt.contacts) {
            if (isFirstPartyDomainEmail(c.email) && !rawContacts.some((ex) => ex.email === c.email)) {
              rawContacts.push(c);
            }
          }
          socialProfiles = { ...pageExt.socialProfiles, ...socialProfiles };
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
            verified: !curated && !securityTxt.isExpired,
          });
        }
      }
    }
  }

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
        dmarcRuf: null,
        dmarcEmails: [],
        deliverabilityGrade: 'N/A',
      };

  const filteredContacts = hasActiveRoleFilter
    ? rawContacts.filter((c) => normalizedRoleList.includes(c.role))
    : rawContacts;

  const primaryContact = hasActiveRoleFilter
    ? filteredContacts[0] || null
    : filteredContacts[0] || rawContacts[0] || null;
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
      untrustedDomainExcerpt: buildUntrustedDomainExcerpt(organizationName, 240),
    },
  };
}

/**
 * Batch-enriches 1 to 25 B2B domains with deterministic `rcd1_` cursor pagination.
 */
export async function resolveB2bDomainContactsBatch(input = {}, options = {}) {
  const aliasNorm = normalizeContactPulseInputAliases(input, 'batch');
  if (!aliasNorm.ok) {
    return {
      ok: false,
      status: 'INVALID_INPUT',
      errorCode: aliasNorm.errorCode || 'INVALID_INPUT',
      reason: aliasNorm.reason,
      items: [],
    };
  }
  input = aliasNorm.normalized;
  const rawQuery =
    input?.query ?? input?.domains ?? input?.domain ?? input?.company ?? input?.url ?? '';
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
  const hasExplicitDomainCap =
    Number.isInteger(options?.maxDomainsToProcess) && options.maxDomainsToProcess >= 0;
  const effectiveSliceSize = hasExplicitDomainCap
    ? Math.min(pageSize, options.maxDomainsToProcess)
    : pageSize;
  const sliceDomains = allDomains.slice(startOffset, startOffset + effectiveSliceSize);
  const items = [];
  const itemNextOffsets = [];
  const batchStartedAtMs = Date.now();
  const deadlineMs =
    Number.isFinite(Number(options?.deadlineMs)) && Number(options.deadlineMs) > 0
      ? Number(options.deadlineMs)
      : DEFAULT_RUN_DEADLINE_MS;
  const deadlineAtMs =
    Number.isFinite(Number(options?.deadlineAtMs)) && Number(options.deadlineAtMs) > 0
      ? Number(options.deadlineAtMs)
      : batchStartedAtMs + deadlineMs;
  let deadlineReached = false;
  let lastAttemptedOffset = startOffset;

  for (let sliceIdx = 0; sliceIdx < sliceDomains.length; sliceIdx += 1) {
    if (
      sliceIdx > 0 &&
      (Date.now() >= deadlineAtMs || deadlineAtMs - Date.now() < 2500)
    ) {
      deadlineReached = true;
      break;
    }
    const dom = sliceDomains[sliceIdx];
    const res = await enrichSingleB2bDomain(dom, {
      roleFilter,
      includeDnsPosture: input?.includeDnsPosture !== false,
      includeSecurityTxt: input?.includeSecurityTxt !== false,
      fetchImpl: options?.fetchImpl || globalThis.fetch,
      dnsLookup: options?.dnsLookup,
      nowMs: options?.nowMs || Date.now(),
      deadlineAtMs,
      preferCurated: options?.preferCurated === true || input?.useSampleFixtures === true,
    });
    lastAttemptedOffset = startOffset + sliceIdx + 1;
    if (res.ok && res.profile) {
      items.push(res.profile);
      itemNextOffsets.push(startOffset + sliceIdx + 1);
    }
  }

  const nextOffset = deadlineReached ? lastAttemptedOffset : startOffset + sliceDomains.length;
  const hasMore = nextOffset < allDomains.length;
  const nextPageToken = hasMore
    ? encodeCompositeCursor({
        offset: nextOffset,
        totalCount: allDomains.length,
        scopeHash,
      })
    : null;
  const paginationStatus =
    deadlineReached && hasMore ? 'DEADLINE_REACHED_HAS_MORE' : hasMore ? 'HAS_MORE' : 'COMPLETE';

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
      nextCursor: nextPageToken,
      paginationStatus,
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
  const aliasNorm = normalizeContactPulseInputAliases(input, 'verify');
  if (!aliasNorm.ok) {
    return {
      ok: false,
      status: 'INVALID_INPUT',
      errorCode: aliasNorm.errorCode || 'INVALID_INPUT',
      reason: aliasNorm.reason,
    };
  }
  input = aliasNorm.normalized;
  const rawTarget = String(
    input?.email ?? input?.domain ?? input?.query ?? input?.company ?? input?.url ?? ''
  ).trim();
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
