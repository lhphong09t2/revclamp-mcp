/**
 * Self-Contained Outbound SSRF, Host-Pinning, Live-Secret Scrubbing & Ephemeral Socket Guard (src/egress_guard.mjs)
 *
 * Enforces HTTPS-only egress, blocks private/loopback/metadata/IP-literal hosts,
 * pins outbound requests to canonical Google Ads Transparency hosts, blocks accidental
 * live secret tokens in free-text queries, and provides per-attempt ephemeral HTTPS agent creation.
 */

import dns from 'node:dns';
import https from 'node:https';
import net from 'node:net';
import zlib from 'node:zlib';

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

export const SSRF_BLOCKED_HOST_RE =
  /^(?:localhost|.*\.localhost|.*\.local|.*\.internal|.*\.arpa|.*\.nip\.io|.*\.sslip\.io|.*\.xip\.io|.*\.lan|.*\.corp|.*\.home|.*\.invalid|.*\.test|.*\.example|.*\.onion|.*\.cluster|.*\.svc|.*\.pod|.*\.k8s|.*\.docker|.*\.intranet|metadata\.google\.internal|metadata|instance-data|.*\.amazonaws\.com\.internal|\d+\.\d+\.\d+\.\d+|\[.*\])$/i;

/**
 * Deterministically parses a canonical or uncompressed IPv6 address into 8 16-bit hextets.
 * Returns `null` on invalid syntax, zone identifiers (`%`), or trailing dots.
 *
 * @param {string} rawIpv6
 * @returns {number[]|null}
 */
export function parseIpv6Hextets(rawIpv6) {
  if (typeof rawIpv6 !== 'string') return null;
  let s = rawIpv6.trim().toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) {
    s = s.slice(1, -1);
  }
  if (!s || s.includes('%') || s.endsWith('.') || net.isIP(s) !== 6) {
    return null;
  }

  if (s.includes('.')) {
    const lastColon = s.lastIndexOf(':');
    if (lastColon === -1) return null;
    const ipv4Tail = s.slice(lastColon + 1);
    if (net.isIP(ipv4Tail) !== 4) return null;
    const octets = ipv4Tail.split('.').map((p) => Number(p));
    if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return null;
    }
    const hiHex = (((octets[0] << 8) | octets[1]) >>> 0).toString(16);
    const loHex = (((octets[2] << 8) | octets[3]) >>> 0).toString(16);
    s = `${s.slice(0, lastColon + 1)}${hiHex}:${loHex}`;
  }

  const dblParts = s.split('::');
  if (dblParts.length > 2) return null;

  let groups;
  if (dblParts.length === 2) {
    const left = dblParts[0] ? dblParts[0].split(':') : [];
    const right = dblParts[1] ? dblParts[1].split(':') : [];
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...new Array(missing).fill('0'), ...right];
  } else {
    groups = s.split(':');
    if (groups.length !== 8) return null;
  }

  const hextets = new Array(8);
  for (let i = 0; i < 8; i += 1) {
    const g = groups[i];
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    hextets[i] = parseInt(g, 16);
  }
  return hextets;
}

/**
 * Checks whether an IPv4 or IPv6 address belongs to any RFC 6890 / RFC 4291 /
 * RFC 6052 / RFC 9637 private, loopback, link-local, transition, documentation, or
 * special-purpose range.
 *
 * @param {string} rawIp
 * @returns {boolean}
 */
export function isPrivateOrReservedIp(rawIp) {
  if (typeof rawIp !== 'string') return true;
  let ip = rawIp.trim();
  if (ip.startsWith('[') && ip.endsWith(']')) {
    ip = ip.slice(1, -1);
  }
  if (!ip || ip.includes('%') || ip.endsWith('.')) return true;

  const family = net.isIP(ip);
  if (family === 4) {
    const parts = ip.split('.').map((p) => Number(p));
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
      return true;
    }
    const [a, b, c] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
    if (a === 192 && b === 31 && c === 196) return true;
    if (a === 192 && b === 52 && c === 193) return true;
    if (a === 192 && b === 88 && c === 99) return true;
    if (a === 192 && b === 168) return true;
    if (a === 192 && b === 175 && c === 48) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    if (a >= 224) return true;
    return false;
  }

  if (family === 6) {
    const w = parseIpv6Hextets(ip);
    if (!w) return true;
    const [w0, w1, w2, w3, w4, w5, w6, w7] = w;
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0) return true;
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0xffff) {
      const v4 = `${(w6 >> 8) & 0xff}.${w6 & 0xff}.${(w7 >> 8) & 0xff}.${w7 & 0xff}`;
      return isPrivateOrReservedIp(v4);
    }
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0xffff && w5 === 0) return true;
    if (
      w0 === 0x0064 &&
      w1 === 0xff9b &&
      ((w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0) || w2 === 0x0001)
    ) {
      return true;
    }
    if (w0 === 0x0100 && w1 === 0 && w2 === 0 && w3 === 0) return true;
    if (w0 === 0x2001 && (w1 < 0x0200 || w1 === 0x0db8)) return true;
    if (w0 === 0x2002) return true;
    if (w0 === 0x3fff && (w1 & 0xf000) === 0) return true;
    if (w0 === 0x5f00) return true;
    if ((w0 & 0xfe00) === 0xfc00) return true;
    if ((w0 & 0xffc0) === 0xfe80) return true;
    if ((w0 & 0xffc0) === 0xfec0) return true;
    if ((w0 & 0xff00) === 0xff00) return true;
    return false;
  }

  return true;
}

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
    const rawHost = parsed.hostname.toLowerCase();
    const unbracketed =
      rawHost.startsWith('[') && rawHost.endsWith(']') ? rawHost.slice(1, -1) : rawHost;
    const hostname = rawHost.replace(/\.+$/, '');
    if (
      !hostname ||
      !hostname.includes('.') ||
      net.isIP(unbracketed) !== 0 ||
      net.isIP(hostname) !== 0 ||
      SSRF_BLOCKED_HOST_RE.test(hostname)
    ) {
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
 * Resolves A/AAAA records for `hostname` and verifies every returned IP is globally routable.
 *
 * @param {string} hostname
 * @param {Function} [lookupFn]
 * @param {number} [timeoutMs=2500]
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
 * Creates a per-attempt ephemeral `https.Agent({ keepAlive: false })` with optional
 * DNS-pinned `lookup` callback so timed-out sockets are never pooled and TOCTOU rebinding is blocked.
 *
 * @param {number} [timeoutMs=6000]
 * @param {{address?: string, family?: number}|null} [pinnedAddress=null]
 * @returns {https.Agent}
 */
export function createEphemeralHttpsAgent(timeoutMs = 6000, pinnedAddress = null) {
  const safeTimeout = Math.max(250, Math.min(23000, Number(timeoutMs) || 6000));
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

function wrapNodeStreamAsFetchBody(incomingRes, decodedStream) {
  let streamErr = null;
  let ended = false;
  const bufferedChunks = [];
  let pendingRead = null;

  const settlePending = () => {
    if (!pendingRead) return;
    const current = pendingRead;
    if (streamErr) {
      pendingRead = null;
      current.reject(streamErr);
    } else if (bufferedChunks.length > 0) {
      pendingRead = null;
      current.resolve({ done: false, value: bufferedChunks.shift() });
    } else if (ended) {
      pendingRead = null;
      current.resolve({ done: true, value: undefined });
    }
  };

  decodedStream.on('data', (chunk) => {
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    bufferedChunks.push(buf);
    if (bufferedChunks.length >= 8) {
      decodedStream.pause();
    }
    settlePending();
  });
  decodedStream.on('end', () => {
    ended = true;
    settlePending();
  });
  decodedStream.on('close', () => {
    ended = true;
    settlePending();
  });
  decodedStream.on('error', (err) => {
    streamErr = err;
    settlePending();
  });
  if (decodedStream !== incomingRes) {
    incomingRes.on('error', (err) => {
      if (!streamErr) {
        streamErr = err;
        decodedStream.destroy();
        settlePending();
      }
    });
  }

  const cancel = async () => {
    ended = true;
    bufferedChunks.length = 0;
    try {
      decodedStream.destroy();
    } catch {
      // Ignore stream destroy errors
    }
    try {
      incomingRes.destroy();
    } catch {
      // Ignore socket destroy errors
    }
    settlePending();
  };

  return {
    cancel,
    getReader() {
      return {
        read() {
          if (streamErr) return Promise.reject(streamErr);
          if (bufferedChunks.length > 0) {
            const next = bufferedChunks.shift();
            if (bufferedChunks.length < 4 && !ended) {
              decodedStream.resume();
            }
            return Promise.resolve({ done: false, value: next });
          }
          if (ended) return Promise.resolve({ done: true, value: undefined });
          decodedStream.resume();
          return new Promise((resolve, reject) => {
            pendingRead = { resolve, reject };
          });
        },
        cancel,
        releaseLock() {},
      };
    },
  };
}

/**
 * Executes an HTTPS request over a DNS-pinned `https.Agent` (`createEphemeralHttpsAgent`),
 * returning a `fetch`-compatible streaming response object (`status`, `ok`, `headers`, `body`, `text`).
 *
 * @param {string} urlStr
 * @param {object} [options]
 * @returns {Promise<object>}
 */
export function executePinnedHttpsRequest(urlStr, options = {}) {
  const parsed = new URL(urlStr);
  const method = String(options.method || 'GET').toUpperCase();
  const rawHeaders = { ...(options.headers || {}) };
  const hasAcceptEncoding = Object.keys(rawHeaders).some(
    (k) => k.toLowerCase() === 'accept-encoding'
  );
  if (!hasAcceptEncoding) {
    rawHeaders['accept-encoding'] = 'gzip, deflate, br';
  }
  const bodyBuf =
    options.body !== undefined && options.body !== null
      ? Buffer.isBuffer(options.body)
        ? options.body
        : Buffer.from(String(options.body), 'utf8')
      : null;
  if (bodyBuf) {
    const hasContentLen = Object.keys(rawHeaders).some(
      (k) => k.toLowerCase() === 'content-length'
    );
    if (!hasContentLen) {
      rawHeaders['content-length'] = String(bodyBuf.length);
    }
  }

  const agent =
    options.agent ||
    createEphemeralHttpsAgent(options.timeoutMs || 6000, options.pinnedAddress || null);
  const signal = options.signal || null;

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      const abortErr = new Error('The operation was aborted');
      abortErr.name = 'AbortError';
      agent.destroy();
      reject(abortErr);
      return;
    }

    let settled = false;
    let activeRes = null;

    const req = https.request(
      {
        protocol: 'https:',
        hostname: parsed.hostname,
        port: 443,
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers: rawHeaders,
        agent,
        servername: net.isIP(parsed.hostname) === 0 ? parsed.hostname : undefined,
      },
      (res) => {
        activeRes = res;
        const status = Number(res.statusCode || 0);
        const encoding = String(res.headers['content-encoding'] || '')
          .trim()
          .toLowerCase();
        let decodedStream = res;
        if (status !== 204 && status !== 304 && !(status >= 300 && status < 400)) {
          if (encoding === 'gzip' || encoding === 'x-gzip') {
            decodedStream = res.pipe(zlib.createGunzip());
          } else if (encoding === 'deflate') {
            decodedStream = res.pipe(zlib.createInflate());
          } else if (encoding === 'br') {
            decodedStream = res.pipe(zlib.createBrotliDecompress());
          }
        }

        const body = wrapNodeStreamAsFetchBody(res, decodedStream);
        settled = true;
        resolve({
          status,
          ok: status >= 200 && status < 300,
          headers: {
            get(name) {
              const val = res.headers[String(name ?? '').toLowerCase()];
              return Array.isArray(val) ? val.join(', ') : val !== undefined ? String(val) : null;
            },
          },
          body,
          async text() {
            const reader = body.getReader();
            const chunks = [];
            let total = 0;
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              chunks.push(value);
              total += value.length;
            }
            return Buffer.concat(chunks, total).toString('utf8');
          },
        });
      }
    );

    const onAbort = () => {
      const abortErr = new Error('The operation was aborted');
      abortErr.name = 'AbortError';
      req.destroy(abortErr);
      if (activeRes) {
        activeRes.destroy(abortErr);
      }
      agent.destroy();
      if (!settled) {
        settled = true;
        reject(abortErr);
      }
    };

    if (signal) {
      signal.addEventListener('abort', onAbort, { once: true });
    }

    req.on('close', () => {
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
      agent.destroy();
    });

    req.on('error', (err) => {
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
      agent.destroy();
      if (!settled) {
        settled = true;
        reject(err);
      }
    });

    if (bodyBuf) {
      req.write(bodyBuf);
    }
    req.end();
  });
}
