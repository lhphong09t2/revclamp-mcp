/**
 * Self-Contained Outbound SSRF, Host-Pinning, Live-Secret Scrubbing & Ephemeral Socket Guard (src/egress_guard.mjs)
 *
 * Enforces HTTPS-only egress, blocks private/loopback/metadata/IP-literal hosts,
 * pins outbound requests to canonical Google Ads Transparency hosts, blocks accidental
 * live secret tokens in free-text queries, and provides per-attempt ephemeral HTTPS agent creation.
 */

import https from 'node:https';

export const ALLOWED_GOOGLE_ADS_RPC_HOSTS = new Set([
  'adstransparency.google.com',
  'displayads-formats.googleusercontent.com',
  'tpc.googlesyndication.com',
]);

export const LIVE_SECRET_GUARD_RE =
  /\b(sk_live_[0-9a-zA-Z]{10,}|rk_live_[0-9a-zA-Z]{10,}|whsec_[0-9a-zA-Z]{10,}|shpat_[0-9a-fA-F]{10,}|shppa_[0-9a-fA-F]{10,}|ghp_[0-9a-zA-Z]{20,}|github_pat_[0-9a-zA-Z_]{20,}|apify_api_[0-9a-zA-Z]{16,}|rg_live_[0-9a-zA-Z_]{10,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9a-zA-Z-]{10,})\b/;

/**
 * Checks whether a free-text input accidentally contains a live API secret or credential token.
 *
 * @param {string} rawText
 * @returns {boolean}
 */
export function containsLiveSecretToken(rawText) {
  if (!rawText || typeof rawText !== 'string') return false;
  return LIVE_SECRET_GUARD_RE.test(rawText);
}

const SSRF_BLOCKED_HOST_RE =
  /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.arpa|.*\.nip\.io|.*\.sslip\.io|metadata\.google\.internal|\d+\.\d+\.\d+\.\d+|\[.*\])$/i;

/**
 * Validates whether a target URL is safe from SSRF against internal/cloud metadata networks.
 * @param {string} rawUrl
 * @returns {{safe: boolean, hostname?: string, reason?: string}}
 */
export function verifyEgressUrlSsrfSafe(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { safe: false, reason: 'URL is empty or not a string' };
  }
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.protocol !== 'https:') {
      return { safe: false, reason: `Egress protocol must be https: (got ${parsed.protocol})` };
    }
    if (parsed.username || parsed.password) {
      return { safe: false, reason: 'Egress URL must not contain userinfo credentials' };
    }
    if (parsed.port && parsed.port !== '443') {
      return { safe: false, reason: `Egress URL must not use non-standard port ${parsed.port}` };
    }
    const hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
    if (!hostname || !hostname.includes('.') || SSRF_BLOCKED_HOST_RE.test(hostname)) {
      return {
        safe: false,
        hostname,
        reason: `Host ${hostname} is blocked by SSRF private/metadata/IP-literal egress policy`,
      };
    }
    return { safe: true, hostname };
  } catch (err) {
    return { safe: false, reason: `Malformed URL: ${err.message}` };
  }
}

/**
 * Validates that a target URL passes both SSRF checks and strict Google Ads Transparency host pinning.
 * @param {string} rawUrl
 * @returns {{safe: boolean, hostname?: string, reason?: string}}
 */
export function assertAllowedGoogleAdsEgress(rawUrl) {
  const ssrfCheck = verifyEgressUrlSsrfSafe(rawUrl);
  if (!ssrfCheck.safe) {
    return ssrfCheck;
  }
  if (!ALLOWED_GOOGLE_ADS_RPC_HOSTS.has(ssrfCheck.hostname)) {
    return {
      safe: false,
      hostname: ssrfCheck.hostname,
      reason: `Host '${ssrfCheck.hostname}' is not in ALLOWED_GOOGLE_ADS_RPC_HOSTS`,
    };
  }
  return { safe: true, hostname: ssrfCheck.hostname };
}

/**
 * Creates a per-attempt ephemeral `https.Agent({ keepAlive: false })` for custom `https`
 * or test transport harnesses so timed-out or throttled sockets are never pooled.
 *
 * @param {number} [timeoutMs=6000]
 * @returns {https.Agent}
 */
export function createEphemeralHttpsAgent(timeoutMs = 6000) {
  const safeTimeout = Math.max(250, Math.min(23000, Number(timeoutMs) || 6000));
  return new https.Agent({
    keepAlive: false,
    maxSockets: 4,
    timeout: safeTimeout,
  });
}
