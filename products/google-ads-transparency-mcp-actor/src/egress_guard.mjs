/**
 * Self-Contained Outbound SSRF & Host-Pinning Guard (src/egress_guard.mjs)
 *
 * Enforces HTTPS-only egress, blocks private/loopback/metadata/IP-literal hosts,
 * and pins outbound requests to canonical Google Ads Transparency hosts.
 */

export const ALLOWED_GOOGLE_ADS_RPC_HOSTS = new Set([
  'adstransparency.google.com',
  'displayads-formats.googleusercontent.com',
  'tpc.googlesyndication.com',
]);

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
