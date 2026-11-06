/**
 * Hardened Localhost Web Playground Server (src/web_preview_server.mjs)
 *
 * Binds strictly to `127.0.0.1` (default port `4410`), enforces `Host` and exact `Origin`
 * DNS-rebinding/CSRF guards, `Content-Type: application/json`, streaming `64KB`
 * request body ceiling, `25s` request timeout aligned with engine deadline,
 * strict Content-Security-Policy, and `X-Content-Type-Options: nosniff`.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MCP_SERVER_INFO,
  MCP_TOOLS_MANIFEST,
  handleMcpJsonRpcRequest,
} from './mcp_server.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ASSETS_DIR = path.resolve(__dirname, '..', 'assets');

export const PLAYGROUND_CSP_HEADER =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

export const MAX_PLAYGROUND_BODY_BYTES = 65536;
export const PLAYGROUND_REQUEST_TIMEOUT_MS = 25000;

const ALLOWED_HOST_HEADER_RE = /^(127\.0\.0\.1|localhost|\[::1\])(:\d{1,5})?$/i;

const STATIC_ASSET_MAP = Object.freeze({
  '/assets/icon.svg': {
    file: 'icon.svg',
    contentType: 'image/svg+xml; charset=utf-8',
  },
  '/assets/icon-32.png': {
    file: 'icon-32.png',
    contentType: 'image/png',
  },
  '/assets/icon-180.png': {
    file: 'icon-180.png',
    contentType: 'image/png',
  },
  '/assets/playground.css': {
    file: 'playground.css',
    contentType: 'text/css; charset=utf-8',
  },
  '/assets/playground.js': {
    file: 'playground.js',
    contentType: 'application/javascript; charset=utf-8',
  },
});

function buildPlaygroundHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>RevClamp AdPulse - Google Ads Transparency Scraper &amp; MCP</title>
  <link rel="icon" type="image/png" sizes="32x32" href="/assets/icon-32.png">
  <link rel="apple-touch-icon" sizes="180x180" href="/assets/icon-180.png">
  <link rel="stylesheet" href="/assets/playground.css">
  <script src="/assets/playground.js" defer></script>
</head>
<body>
  <header class="site-header">
    <div class="header-inner">
      <div class="brand-group">
        <img class="brand-logo" src="/assets/icon.svg" width="36" height="36" alt="RevClamp AdPulse shield icon">
        <div class="brand-titles">
          <h1 class="brand-title">RevClamp AdPulse - Google Ads Transparency Scraper &amp; MCP</h1>
          <p class="brand-subtitle">Find Verified Advertiser Entities &amp; Extract Active or Historical Google Ads Creatives</p>
        </div>
      </div>
      <div class="header-badges">
        <span class="badge badge-emerald">MCP 2025-06-18 Ready</span>
        <span class="badge badge-cyan">Responses up to 30 KB</span>
      </div>
    </div>
  </header>

  <main class="workbench-main">
    <section class="panel" aria-labelledby="controls-heading">
      <h2 id="controls-heading" class="panel-heading">Search &amp; Tool Controls</h2>
      <div class="form-stack">
        <div class="field-group">
          <label class="field-label" for="tool-select">Tool Action</label>
          <select id="tool-select" class="select-control">
            <option value="search_google_ads_transparency">Search Google Ads Transparency Creatives</option>
            <option value="resolve_google_ads_advertiser">Resolve Google Ads Advertiser Entities</option>
            <option value="get_google_ads_creative_detail">Get Google Ads Creative Detail</option>
          </select>
        </div>

        <div id="dynamic-schema-fields" class="form-stack"></div>

        <label class="checkbox-row" for="toggle-load-previews">
          <input id="toggle-load-previews" class="checkbox-input" type="checkbox">
          <span>Show verified ad preview &amp; archive links</span>
        </label>

        <div class="button-row">
          <button id="btn-run-tool" class="btn btn-primary" type="button">Run Tool</button>
          <button id="btn-load-next-page" class="btn btn-secondary" type="button" hidden>Load next page</button>
        </div>
      </div>
    </section>

    <section class="panel" aria-labelledby="results-heading">
      <div class="panel-heading">
        <h2 id="results-heading" class="panel-heading-title">Results</h2>
        <div class="export-actions-row">
          <button id="btn-copy-json" class="btn btn-secondary" type="button" disabled>Copy JSON</button>
          <button id="btn-download-json" class="btn btn-secondary" type="button" disabled>Download JSON</button>
        </div>
      </div>
      <div id="status-banner" class="status-banner" role="status" aria-live="polite" data-state="idle">
        Ready. Choose a tool action and click Run Tool to inspect public Google Ads Transparency records.
      </div>

      <div class="telemetry-grid">
        <div class="telemetry-card">
          <div class="telemetry-label">Billing Mode</div>
          <div id="telemetry-billing-mode" class="telemetry-value">Local mode - not billed</div>
        </div>
        <div class="telemetry-card">
          <div class="telemetry-label">Extracted Items</div>
          <div id="telemetry-extracted-count" class="telemetry-value">0</div>
        </div>
        <div class="telemetry-card">
          <div class="telemetry-label">Pagination Status</div>
          <div id="telemetry-pagination-status" class="telemetry-value">IDLE</div>
        </div>
        <div class="telemetry-card">
          <div class="telemetry-label">Response Size</div>
          <div id="telemetry-envelope-bytes" class="telemetry-value">0 B</div>
        </div>
      </div>

      <div id="results-cards-container" class="cards-stack"></div>

      <pre id="raw-json-output" class="raw-json-box" aria-label="Raw JSON-RPC Envelope">{}</pre>
    </section>
  </main>

  <footer class="site-footer">
    Independent intelligence tool by RevClamp; not affiliated with or endorsed by Google LLC.
  </footer>
</body>
</html>`;
}

function applySecurityHeaders(res, isApiRoute = false) {
  res.setHeader('Content-Security-Policy', PLAYGROUND_CSP_HEADER);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (isApiRoute) {
    res.setHeader('Cache-Control', 'no-store');
  }
}

function sendJson(res, statusCode, payload) {
  if (res.headersSent || res.writableEnded) {
    return;
  }
  applySecurityHeaders(res, true);
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body, 'utf8'),
  });
  res.end(body);
}

/**
 * Validates that an HTTP `Origin` header matches the exact `http://${hostHeader}` host+port pair.
 *
 * @param {string} originHeader
 * @param {string} hostHeader
 * @returns {boolean}
 */
function isAllowedSamePortOrigin(originHeader, hostHeader) {
  const rawOrigin = String(originHeader ?? '').trim();
  const rawHost = String(hostHeader ?? '').trim().toLowerCase();
  if (!rawOrigin || !rawHost) return false;
  try {
    const parsedOrigin = new URL(rawOrigin);
    if (parsedOrigin.protocol !== 'http:') return false;
    const originHostPort = parsedOrigin.host.toLowerCase();
    return originHostPort === rawHost;
  } catch {
    return false;
  }
}

/**
 * Creates and starts the hardened localhost Web Playground HTTP server.
 *
 * @param {object} [options]
 * @param {number} [options.port=4410]
 * @param {string} [options.host='127.0.0.1']
 * @param {Function} [options.fetchImpl]
 * @param {number} [options.maxBodyBytes=65536]
 * @returns {Promise<{server: http.Server, host: string, port: number, url: string, close: () => Promise<void>}>}
 */
export async function createAdPulsePreviewServer(options = {}) {
  const requestedHost = String(options.host ?? '127.0.0.1').trim();
  if (requestedHost !== '127.0.0.1' && requestedHost !== 'localhost') {
    throw new Error(`Playground server must bind strictly to 127.0.0.1 (got '${requestedHost}')`);
  }

  const requestedPort = options.port !== undefined ? Number(options.port) : 4410;
  const maxBodyBytes =
    Number.isInteger(options.maxBodyBytes) && options.maxBodyBytes > 0
      ? options.maxBodyBytes
      : MAX_PLAYGROUND_BODY_BYTES;

  const server = http.createServer((req, res) => {
    req.setTimeout(PLAYGROUND_REQUEST_TIMEOUT_MS, () => {
      if (!res.headersSent && !res.writableEnded) {
        sendJson(res, 408, { ok: false, error: 'Request timeout' });
      }
      req.destroy();
    });

    const hostHeader = String(req.headers.host ?? '').trim();
    if (!hostHeader || !ALLOWED_HOST_HEADER_RE.test(hostHeader)) {
      sendJson(res, 403, {
        ok: false,
        error: 'Forbidden Host header (DNS rebinding guard)',
      });
      return;
    }

    const rawUrl = String(req.url || '/');
    if (rawUrl.startsWith('//')) {
      sendJson(res, 400, { ok: false, error: 'Malformed request URL' });
      return;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(rawUrl, `http://${hostHeader}`);
    } catch {
      sendJson(res, 400, { ok: false, error: 'Malformed request URL' });
      return;
    }
    const pathname = parsedUrl.pathname;

    if (req.method === 'GET' && pathname === '/') {
      applySecurityHeaders(res, false);
      const html = buildPlaygroundHtml();
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Length': Buffer.byteLength(html, 'utf8'),
      });
      res.end(html);
      return;
    }

    if (req.method === 'GET' && Object.prototype.hasOwnProperty.call(STATIC_ASSET_MAP, pathname)) {
      const assetMeta = STATIC_ASSET_MAP[pathname];
      const filePath = path.join(ASSETS_DIR, assetMeta.file);
      try {
        const buf = fs.readFileSync(filePath);
        applySecurityHeaders(res, false);
        res.writeHead(200, {
          'Content-Type': assetMeta.contentType,
          'Content-Length': buf.length,
        });
        res.end(buf);
      } catch {
        sendJson(res, 404, { ok: false, error: 'Asset not found' });
      }
      return;
    }

    if (req.method === 'GET' && pathname === '/api/schema') {
      sendJson(res, 200, {
        ok: true,
        serverInfo: MCP_SERVER_INFO,
        tools: MCP_TOOLS_MANIFEST,
      });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/mcp') {
      const originHeader = req.headers.origin;
      if (originHeader !== undefined && !isAllowedSamePortOrigin(originHeader, hostHeader)) {
        sendJson(res, 403, {
          ok: false,
          error: 'Forbidden Origin header (cross-origin request blocked)',
        });
        return;
      }

      const contentType = String(req.headers['content-type'] ?? '').trim().toLowerCase();
      if (!contentType.startsWith('application/json')) {
        sendJson(res, 415, {
          ok: false,
          error: 'Unsupported Media Type: Content-Type must be application/json',
        });
        return;
      }

      const chunks = [];
      let totalBytes = 0;
      let abortedForSize = false;

      req.on('data', (chunk) => {
        if (abortedForSize) return;
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        totalBytes += buf.length;
        if (totalBytes > maxBodyBytes) {
          abortedForSize = true;
          sendJson(res, 413, {
            ok: false,
            error: `Payload Too Large: request body exceeds ${maxBodyBytes} byte limit`,
          });
          req.destroy();
          return;
        }
        chunks.push(buf);
      });

      req.on('end', async () => {
        if (abortedForSize || res.headersSent || res.writableEnded) return;
        const rawBody = Buffer.concat(chunks, totalBytes).toString('utf8');
        let parsedBody;
        try {
          parsedBody = JSON.parse(rawBody);
        } catch {
          sendJson(res, 200, {
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32700,
              message: 'Parse error: Invalid JSON was received by the server.',
            },
          });
          return;
        }

        try {
          const rpcResponse = await handleMcpJsonRpcRequest(parsedBody, {
            fetchImpl: options.fetchImpl,
          });
          if (res.headersSent || res.writableEnded) return;
          if (rpcResponse === null) {
            applySecurityHeaders(res, true);
            res.writeHead(204);
            res.end();
            return;
          }
          sendJson(res, 200, rpcResponse);
        } catch (err) {
          sendJson(res, 500, {
            jsonrpc: '2.0',
            id: null,
            error: {
              code: -32603,
              message: err?.message || 'Internal server error',
            },
          });
        }
      });
      return;
    }

    sendJson(res, 404, { ok: false, error: 'Route not found' });
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(requestedPort, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  const addr = server.address();
  const actualPort = typeof addr === 'object' && addr ? addr.port : requestedPort;

  return {
    server,
    host: '127.0.0.1',
    port: actualPort,
    url: `http://127.0.0.1:${actualPort}`,
    close: () =>
      new Promise((resolve) => {
        server.close(() => resolve());
      }),
  };
}

function isExecutedAsMainModule(metaUrl) {
  if (!process.argv[1]) return false;
  try {
    const entryPath = fs.realpathSync(process.argv[1]);
    const selfPath = fs.realpathSync(fileURLToPath(metaUrl));
    return entryPath === selfPath;
  } catch {
    return false;
  }
}

if (isExecutedAsMainModule(import.meta.url)) {
  const portArg = Number(process.env.PORT || 4410);
  createAdPulsePreviewServer({ port: portArg })
    .then((srv) => {
      process.stdout.write(`RevClamp AdPulse Web Playground listening on ${srv.url}\n`);
    })
    .catch((err) => {
      process.stderr.write(`Failed to start Web Playground server: ${err?.message || String(err)}\n`);
      process.exit(1);
    });
}
