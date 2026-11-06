/**
 * Self-Contained Outbound SSRF Port-443 Guard, UTF-8 Safe Truncation & Ephemeral Socket Isolation (src/egress_guard.mjs)
 *
 * Enforces HTTPS-only port-443 egress, blocks private/loopback/link-local/CGNAT/metadata/IP-literal hosts,
 * provides IP-range validation for DNS-rebinding defense, UTF-8 code-point safe truncation without splitting
 * surrogate pairs, and per-attempt ephemeral HTTPS agent creation (`keepAlive: false`).
 */

import dns from 'node:dns';
import https from 'node:https';
import net from 'node:net';

export const ALLOWED_DOH_HOSTS = new Set(['cloudflare-dns.com', 'dns.google']);

export const LIVE_SECRET_GUARD_RE =
  /\b(sk_live_[0-9a-zA-Z]{10,}|rk_live_[0-9a-zA-Z]{10,}|whsec_[0-9a-zA-Z]{10,}|shpat_[0-9a-fA-F]{10,}|shppa_[0-9a-fA-F]{10,}|ghp_[0-9a-zA-Z]{20,}|github_pat_[0-9a-zA-Z_]{20,}|apify_api_[0-9a-zA-Z]{16,}|rg_live_[0-9a-zA-Z_]{10,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9a-zA-Z-]{10,})\b/;

const SSRF_BLOCKED_HOST_RE =
  /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.arpa|.*\.nip\.io|.*\.sslip\.io|.*\.xip\.io|metadata\.google\.internal|metadata|instance-data|\d+\.\d+\.\d+\.\d+|\[.*\])$/i;

const PUBLIC_DOMAIN_SYNTAX_RE =
  /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;

const PUBLIC_TLD_RE = /\.[a-z]{2,63}$/i;

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

/**
 * Checks whether an IPv4 or IPv6 address belongs to a private, loopback, link-local,
 * CGNAT, documentation, multicast, or cloud metadata range.
 *
 * @param {string} rawIp
 * @returns {boolean}
 */
export function isPrivateOrReservedIp(rawIp) {
  const ip = String(rawIp ?? '').trim().toLowerCase();
  if (!ip) return true;
  const family = net.isIP(ip);
  if (family === 4) {
    const parts = ip.split('.').map((p) => Number(p));
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return true;
    }
    const [a, b, c] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    if (a >= 224) return true;
    return false;
  }
  if (family === 6) {
    if (ip === '::' || ip === '::1') return true;
    if (ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
    if (ip.startsWith('ff') || ip.startsWith('2001:db8:')) return true;
    if (ip.startsWith('::ffff:')) {
      const mapped = ip.slice('::ffff:'.length);
      if (net.isIP(mapped) === 4) return isPrivateOrReservedIp(mapped);
      return true;
    }
    return false;
  }
  return true;
}

/**
 * Validates whether a target URL is safe from SSRF against internal/cloud metadata networks.
 * Enforces HTTPS-only over port 443 and public DNS domain syntax.
 *
 * @param {string} rawUrl
 * @returns {{safe: boolean, hostname?: string, normalizedUrl?: string, reason?: string}}
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
      return { safe: false, reason: `Egress URL must not use non-standard port ${parsed.port} (only 443 allowed)` };
    }
    const hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
    if (
      !hostname ||
      !hostname.includes('.') ||
      SSRF_BLOCKED_HOST_RE.test(hostname) ||
      !PUBLIC_DOMAIN_SYNTAX_RE.test(hostname) ||
      !PUBLIC_TLD_RE.test(hostname) ||
      net.isIP(hostname) !== 0
    ) {
      return {
        safe: false,
        hostname,
        reason: `Host '${hostname}' is blocked by SSRF private/metadata/IP-literal egress policy`,
      };
    }
    return {
      safe: true,
      hostname,
      normalizedUrl: parsed.toString(),
    };
  } catch (err) {
    return { safe: false, reason: `Malformed URL: ${err.message}` };
  }
}

export const assertSafeEgressUrl = verifyEgressUrlSsrfSafe;

/**
 * Slices a UTF-16 string to fit within `maxUtf8Bytes` without splitting surrogate pairs
 * or multi-byte UTF-8 sequences.
 *
 * @param {string} rawStr
 * @param {number} maxUtf8Bytes
 * @returns {string}
 */
export function sliceUtf8Safe(rawStr, maxUtf8Bytes) {
  const s = String(rawStr ?? '');
  if (!s || maxUtf8Bytes <= 0) return '';
  if (Buffer.byteLength(s, 'utf8') <= maxUtf8Bytes) return s;

  let out = '';
  let usedBytes = 0;
  for (const codePointChar of s) {
    const charBytes = Buffer.byteLength(codePointChar, 'utf8');
    if (usedBytes + charBytes > maxUtf8Bytes) {
      break;
    }
    out += codePointChar;
    usedBytes += charBytes;
  }
  return out;
}

export const truncateUtf8Safe = sliceUtf8Safe;

/**
 * Resolves all A/AAAA records for `hostname` and verifies that at least one public IP is returned
 * and zero resolved IPs fall inside private, loopback, link-local, CGNAT, or cloud metadata ranges.
 *
 * @param {string} hostname
 * @param {Function} [lookupFn]
 * @returns {Promise<{safe: boolean, hostname: string, addresses?: Array<{address: string, family: number}>, reason?: string}>}
 */
export async function resolveAndVerifyPublicHostname(
  hostname,
  lookupFn = dns.promises.lookup,
  timeoutMs = 2500
) {
  const cleanHost = String(hostname ?? '').trim().toLowerCase().replace(/\.+$/, '');
  if (!cleanHost || net.isIP(cleanHost) !== 0) {
    return {
      safe: false,
      hostname: cleanHost,
      reason: `Host '${cleanHost}' must be a valid DNS domain name`,
    };
  }
  const rawTimeoutMs = timeoutMs === undefined ? 2500 : Number(timeoutMs);
  if (!Number.isFinite(rawTimeoutMs) || rawTimeoutMs <= 0) {
    return {
      safe: false,
      hostname: cleanHost,
      reason: `DNS lookup budget exhausted (${rawTimeoutMs}ms) for '${cleanHost}'`,
    };
  }
  const boundedTimeoutMs = Math.max(1, Math.min(8000, rawTimeoutMs));
  let timer = null;
  try {
    const rawRecords = await Promise.race([
      lookupFn(cleanHost, { all: true, verbatim: true }),
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          reject(new Error(`DNS lookup timed out after ${boundedTimeoutMs}ms`));
        }, boundedTimeoutMs);
      }),
    ]);
    const records = Array.isArray(rawRecords)
      ? rawRecords
      : rawRecords && typeof rawRecords === 'object' && rawRecords.address
        ? [rawRecords]
        : [];
    if (records.length === 0) {
      return {
        safe: false,
        hostname: cleanHost,
        reason: `DNS lookup returned zero A/AAAA records for '${cleanHost}'`,
      };
    }
    const vetted = [];
    for (const rec of records) {
      const addr = String(rec?.address ?? '').trim();
      const fam = Number(rec?.family) || net.isIP(addr);
      if (!addr || isPrivateOrReservedIp(addr)) {
        return {
          safe: false,
          hostname: cleanHost,
          reason: `DNS rebinding / SSRF blocked: '${cleanHost}' resolved to private/reserved IP '${addr || 'unknown'}'`,
        };
      }
      vetted.push({ address: addr, family: fam === 6 ? 6 : 4 });
    }
    return {
      safe: true,
      hostname: cleanHost,
      addresses: vetted,
    };
  } catch (err) {
    return {
      safe: false,
      hostname: cleanHost,
      reason: `DNS resolution failed for '${cleanHost}': ${err?.message || err}`,
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Creates a per-attempt ephemeral `https.Agent({ keepAlive: false })` so timed-out or
 * rate-limited sockets are never pooled across retries. When `pinnedAddress` is provided,
 * pins the custom `lookup` callback to the vetted public IP to prevent TOCTOU DNS rebinding.
 *
 * @param {number} [timeoutMs=4000]
 * @param {{address?: string, family?: number}} [pinnedAddress]
 * @returns {https.Agent}
 */
export function createEphemeralHttpsAgent(timeoutMs = 4000, pinnedAddress = null) {
  const safeTimeout = Math.max(250, Math.min(23000, Number(timeoutMs) || 4000));
  const agentOpts = {
    keepAlive: false,
    maxSockets: 4,
    timeout: safeTimeout,
  };
  if (
    pinnedAddress &&
    typeof pinnedAddress.address === 'string' &&
    pinnedAddress.address &&
    !isPrivateOrReservedIp(pinnedAddress.address)
  ) {
    const pinnedIp = pinnedAddress.address;
    const pinnedFam = pinnedAddress.family === 6 ? 6 : 4;
    agentOpts.lookup = (_host, opts, cb) => {
      if (typeof opts === 'function') {
        return opts(null, pinnedIp, pinnedFam);
      }
      if (opts && opts.all) {
        return cb(null, [{ address: pinnedIp, family: pinnedFam }]);
      }
      return cb(null, pinnedIp, pinnedFam);
    };
  }
  return new https.Agent(agentOpts);
}
