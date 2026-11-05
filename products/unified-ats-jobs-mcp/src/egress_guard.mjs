/**
 * Self-Contained Outbound SSRF, Host-Pinning Guard & Ephemeral Socket Isolation (src/egress_guard.mjs)
 *
 * Enforces HTTPS-only egress, blocks private/loopback/link-local/CGNAT/metadata/IP-literal hosts,
 * pins outbound requests strictly to the 5 public ATS API domains (Greenhouse, Workday CXS,
 * Ashby, Lever, SmartRecruiters), and provides per-attempt ephemeral HTTPS agent creation
 * (`keepAlive: false`) so timed-out or rate-limited sockets are destroyed immediately.
 */

import https from 'node:https';

export const ALLOWED_ATS_API_HOSTS = new Set([
  'boards-api.greenhouse.io',
  'api.ashbyhq.com',
  'api.lever.co',
  'api.smartrecruiters.com',
]);

export const WORKDAY_CXS_HOST_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.wd[1-5]\.myworkdayjobs\.com$/i;

const SSRF_BLOCKED_HOST_RE =
  /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.arpa|.*\.nip\.io|.*\.sslip\.io|metadata\.google\.internal|\d+\.\d+\.\d+\.\d+|\[.*\])$/i;

/**
 * Checks whether a hostname matches one of the 5 allowed public ATS API hosts.
 *
 * @param {string} hostname
 * @returns {boolean}
 */
export function isAllowedAtsApiHost(hostname) {
  const clean = String(hostname ?? '')
    .trim()
    .toLowerCase()
    .replace(/\.+$/, '');
  if (!clean) return false;
  return ALLOWED_ATS_API_HOSTS.has(clean) || WORKDAY_CXS_HOST_RE.test(clean);
}

/**
 * Validates whether a target URL is safe from SSRF against internal/cloud metadata networks.
 *
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
 * Validates that a target URL passes both SSRF checks and strict 5-ATS host pinning.
 *
 * @param {string} rawUrl
 * @returns {{safe: boolean, hostname?: string, reason?: string}}
 */
export function assertAllowedAtsEgress(rawUrl) {
  const ssrfCheck = verifyEgressUrlSsrfSafe(rawUrl);
  if (!ssrfCheck.safe) {
    return ssrfCheck;
  }
  if (!isAllowedAtsApiHost(ssrfCheck.hostname)) {
    return {
      safe: false,
      hostname: ssrfCheck.hostname,
      reason: `Host '${ssrfCheck.hostname}' is not in ALLOWED_ATS_API_HOSTS or WORKDAY_CXS_HOST_RE`,
    };
  }
  return { safe: true, hostname: ssrfCheck.hostname };
}

/**
 * Creates a per-attempt ephemeral `https.Agent({ keepAlive: false })` for custom `https`
 * or test transport harnesses (paired with `connection: 'close'` and `AbortController`
 * signal cancellation on native `fetch`) so timed-out or throttled sockets are never pooled.
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
