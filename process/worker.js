const VERSION = 'ai';

const CONFIG = {
  DEFAULT_PROFILE: 'all',
  CACHE_TTL_SECONDS: 300,
  MAX_THROTTLE_ENTRIES: 20000,
  MAX_DNS_MESSAGE_BYTES: 4096,
  RATE_LIMIT_WINDOW_MS: 60_000,
  RATE_LIMIT_MAX_REQUESTS: 5000,
  UPSTREAM_TIMEOUT_MS: 2000,
  RACE_COUNT: 5,
  SCORE_START: 100,
  SCORE_MIN: 0,
  SCORE_MAX: 100,
  SCORE_SUCCESS_DELTA: 1,
  SCORE_FAILURE_DELTA: 15,
  SCORE_TIMEOUT_DELTA: 10
};

const CONTROLD_DNS_UPSTREAMS = [
  'https://freedns.controld.com/no-ads-dating-drugs-gambling-typo-malware',
  'https://freedns.controld.com/no-ads-dating-gambling-typo-malware',
  'https://freedns.controld.com/no-ads-typo-malware',
  'https://freedns.controld.com/p2',
  ];

const RESOLVER_PROFILES = {
  all: [
    ...CONTROLD_DNS_UPSTREAMS
  ]
};

const APP_STATE = {
  resolversByProfile: buildResolverState(RESOLVER_PROFILES),
  throttle: new Map()
};

function buildResolverState(profiles) {
  const state = {};

  for (const [profile, urls] of Object.entries(profiles)) {
    state[profile] = urls.map((url) => ({
      url,
      score: CONFIG.SCORE_START,
      ok: 0,
      fail: 0,
      timeout: 0,
      lastLatencyMs: null,
      lastError: null
    }));
  }

  return state;
}

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const clientIP = getClientIP(req);

    // Intercept /status to show the JSON health snapshot
    if (url.pathname === '/status') {
      return jsonResponse(getHealthSnapshot(), 200, {
        'cache-control': 'no-store'
      });
    }

    if (checkSpam(clientIP)) {
      return textResponse('Rate limit exceeded', 429, {
        'cache-control': 'no-store'
      });
    }

    // Route ALL other paths to the DNS handler
    return handleDNS(req, url, ctx);
  }
};

async function handleDNS(req, url, ctx) {
  const methodError = validateMethod(req.method);
  if (methodError) return methodError;

  let payload;

  try {
    payload = await readDNSPayload(req, url);
  } catch (err) {
    return textResponse('Not found', err.status || 404, {
      'cache-control': 'no-store'
    });
  }

  if (!payload || payload.byteLength === 0) {
    return textResponse('Not found', 404, { 'cache-control': 'no-store' });
  }

  if (payload.byteLength > CONFIG.MAX_DNS_MESSAGE_BYTES) {
    return textResponse('Not found', 404, { 'cache-control': 'no-store' });
  }

  const parsed = parseDNSQuestion(payload);
  if (!parsed.ok) {
    return textResponse('Not found', 404, { 'cache-control': 'no-store' });
  }

  const profile = pickProfile(url);
  const resolvers = APP_STATE.resolversByProfile[profile] || APP_STATE.resolversByProfile[CONFIG.DEFAULT_PROFILE];
  const cacheKey = await makeCacheKey(profile, parsed.questionKey);
  const hit = await getCache(cacheKey);

  if (hit) {
    const responseBody = patchDNSResponseID(hit.body, parsed.id);
    return dnsResponse(responseBody, {
      'x-cache': 'HIT',
      'x-profile': profile
    });
  }

  const racers = selectRacers(resolvers);

  try {
    const winner = await raceResolvers(racers, payload, parsed.id);

    if (isCacheableDNSResponse(winner.body)) {
      const ttlSeconds = computeCacheTTL(winner.body);
      setCache(cacheKey, normalizeDNSResponseID(winner.body), ttlSeconds, ctx);
    }

    return dnsResponse(winner.body, {
      'x-cache': 'MISS',
      'x-profile': profile,
      'x-winner': sanitizeHeaderValue(winner.url),
      'x-winner-lat': `${winner.latencyMs}ms`
    });
  } catch (err) {
    return textResponse('Global resolving failed', 502, {
      'cache-control': 'no-store',
      'x-profile': profile
    });
  }
}

function validateMethod(method) {
  if (method !== 'GET' && method !== 'POST') {
    return textResponse('Not found', 404, {
      'cache-control': 'no-store'
    });
  }

  return null;
}

async function readDNSPayload(req, url) {
  if (req.method === 'GET') {
    const q = url.searchParams.get('dns');
    if (!q) throw httpError('Not found', 404);
    return decodeBase64Url(q);
  }

  const contentType = req.headers.get('content-type') || '';
  if (!contentType.toLowerCase().includes('application/dns-message')) {
    throw httpError('Not found', 404);
  }

  return new Uint8Array(await req.arrayBuffer());
}

function decodeBase64Url(input) {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) {
    throw httpError('Not found', 404);
  }

  let normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  normalized += '='.repeat((4 - (normalized.length % 4)) % 4);

  try {
    return Uint8Array.from(atob(normalized), (c) => c.charCodeAt(0));
  } catch (_) {
    throw httpError('Not found', 404);
  }
}

function parseDNSQuestion(packet) {
  const bytes = packet instanceof Uint8Array ? packet : new Uint8Array(packet);

  if (bytes.byteLength < 12) {
    return { ok: false, error: 'Not found' };
  }

  const id = (bytes[0] << 8) | bytes[1];
  const flags = (bytes[2] << 8) | bytes[3];
  const qdcount = (bytes[4] << 8) | bytes[5];

  if ((flags & 0x8000) !== 0) {
    return { ok: false, error: 'Not found' };
  }

  if (qdcount !== 1) {
    return { ok: false, error: 'Not found' };
  }

  let offset = 12;
  const labels = [];

  while (offset < bytes.length) {
    const len = bytes[offset++];

    if (len === 0) break;

    if ((len & 0xc0) !== 0) {
      return { ok: false, error: 'Not found' };
    }

    if (len > 63 || offset + len > bytes.length) {
      return { ok: false, error: 'Not found' };
    }

    let label = '';
    for (let i = 0; i < len; i++) {
      const ch = bytes[offset++];
      label += String.fromCharCode(ch).toLowerCase();
    }

    labels.push(label);
  }

  if (offset + 4 > bytes.length) {
    return { ok: false, error: 'Not found' };
  }

  const qtype = (bytes[offset] << 8) | bytes[offset + 1];
  const qclass = (bytes[offset + 2] << 8) | bytes[offset + 3];
  const qname = labels.join('.') || '.';

  return {
    ok: true,
    id,
    qname,
    qtype,
    qclass,
    questionKey: `${qname}|${qtype}|${qclass}`
  };
}

function normalizeDNSResponseID(responseBuffer) {
  const bytes = new Uint8Array(responseBuffer);
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  copy[0] = 0;
  copy[1] = 0;
  return copy.buffer;
}

function patchDNSResponseID(responseBuffer, queryID) {
  const bytes = new Uint8Array(responseBuffer);
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  copy[0] = (queryID >> 8) & 0xff;
  copy[1] = queryID & 0xff;
  return copy.buffer;
}

function isCacheableDNSResponse(responseBuffer) {
  const bytes = new Uint8Array(responseBuffer);

  if (bytes.length < 12) return false;

  const flags = (bytes[2] << 8) | bytes[3];
  const isResponse = (flags & 0x8000) !== 0;
  const rcode = flags & 0x000f;

  if (!isResponse) return false;

  return rcode === 0 || rcode === 3;
}

// --- DNS answer TTL parsing (used to derive an accurate cache TTL) ---

function skipName(bytes, offset) {
  while (offset < bytes.length) {
    const len = bytes[offset];

    if (len === 0) {
      return offset + 1;
    }

    if ((len & 0xc0) === 0xc0) {
      // Compression pointer: 2 bytes total, always terminates the name here.
      if (offset + 1 >= bytes.length) return -1;
      return offset + 2;
    }

    if (len > 63) return -1;

    offset += 1 + len;
  }

  return -1;
}

function extractMinAnswerTTL(responseBuffer) {
  const bytes = new Uint8Array(responseBuffer);

  if (bytes.length < 12) return null;

  const qdcount = (bytes[4] << 8) | bytes[5];
  const ancount = (bytes[6] << 8) | bytes[7];

  if (ancount === 0) return null;

  let offset = 12;

  for (let i = 0; i < qdcount; i++) {
    offset = skipName(bytes, offset);
    if (offset === -1) return null;
    offset += 4; // qtype + qclass
    if (offset > bytes.length) return null;
  }

  let minTTL = null;

  for (let i = 0; i < ancount; i++) {
    offset = skipName(bytes, offset);
    if (offset === -1) return minTTL;

    if (offset + 10 > bytes.length) return minTTL;

    const ttl = ((bytes[offset + 4] << 24) | (bytes[offset + 5] << 16) |
      (bytes[offset + 6] << 8) | bytes[offset + 7]) >>> 0;
    const rdlength = (bytes[offset + 8] << 8) | bytes[offset + 9];

    if (minTTL === null || ttl < minTTL) minTTL = ttl;

    offset += 10 + rdlength;
    if (offset > bytes.length) return minTTL;
  }

  return minTTL;
}

function computeCacheTTL(responseBuffer) {
  const recordTTL = extractMinAnswerTTL(responseBuffer);

  if (recordTTL === null) {
    // Only hit when the answer section couldn't be parsed at all (e.g.
    // malformed/truncated response) — falls back to the configured
    // default rather than failing the request.
    return CONFIG.CACHE_TTL_SECONDS;
  }

  return recordTTL;
}

function pickProfile(url) {
  return CONFIG.DEFAULT_PROFILE;
}

function selectRacers(resolvers) {
  return [...resolvers]
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      const aLat = a.lastLatencyMs ?? Number.MAX_SAFE_INTEGER;
      const bLat = b.lastLatencyMs ?? Number.MAX_SAFE_INTEGER;
      return aLat - bLat;
    })
    .slice(0, Math.max(1, Math.min(CONFIG.RACE_COUNT, resolvers.length)));
}

async function raceResolvers(nodes, packet, expectedID) {
  const controllers = nodes.map(() => new AbortController());

  try {
    const attempts = nodes.map((node, index) => relay(node, packet, expectedID, controllers[index].signal));
    const winner = await Promise.any(attempts);

    for (const controller of controllers) {
      controller.abort('winner-selected');
    }

    return winner;
  } finally {
    for (const controller of controllers) {
      controller.abort('race-finished');
    }
  }
}

async function relay(node, packet, expectedID, signal) {
  const started = Date.now();
  const timeoutController = new AbortController();
  const timeout = setTimeout(() => timeoutController.abort('timeout'), CONFIG.UPSTREAM_TIMEOUT_MS);
  const combinedSignal = anySignal([signal, timeoutController.signal]);

  try {
    const res = await fetch(node.url, {
      method: 'POST',
      headers: {
        accept: 'application/dns-message',
        'content-type': 'application/dns-message'
      },
      body: packet,
      signal: combinedSignal
    });

    if (!res.ok) {
      throw new RelayError(`Upstream HTTP ${res.status}`);
    }

    const body = await res.arrayBuffer();
    const validation = validateDNSResponse(body, expectedID);

    if (!validation.ok) {
      throw new RelayError(validation.error);
    }

    const latencyMs = Date.now() - started;
    reward(node, latencyMs);

    return {
      url: node.url,
      body,
      latencyMs
    };
  } catch (err) {
    // Single point of scoring for every failure path below, so a resolver
    // is never penalized twice for the same failed attempt (bug fix #2),
    // and never penalized just for losing a fair race to a faster
    // resolver (bug fix #1) — only a real timeout or a real failure
    // affects its score.
    recordRelayFailure(node, err, signal, timeoutController);
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

class RelayError extends Error {}

function recordRelayFailure(node, err, signal, timeoutController) {
  const timedOut = timeoutController.signal.aborted;
  const lostRace = signal.aborted && !timedOut;

  if (lostRace) {
    return;
  }

  if (timedOut) {
    node.timeout += 1;
    penalize(node, CONFIG.SCORE_TIMEOUT_DELTA, 'timeout');
    return;
  }

  const message = String(err && err.message ? err.message : err);
  penalize(node, CONFIG.SCORE_FAILURE_DELTA, message);
}

function validateDNSResponse(responseBuffer, expectedID) {
  const bytes = new Uint8Array(responseBuffer);

  if (bytes.length < 12) return { ok: false, error: 'Upstream returned short DNS response' };

  const id = (bytes[0] << 8) | bytes[1];
  const flags = (bytes[2] << 8) | bytes[3];

  if (id !== expectedID) return { ok: false, error: 'Upstream response ID mismatch' };
  if ((flags & 0x8000) === 0) return { ok: false, error: 'Upstream returned a DNS query, not response' };

  return { ok: true };
}

function anySignal(signals) {
  const controller = new AbortController();

  function abortFrom(signal) {
    if (!controller.signal.aborted) {
      controller.abort(signal.reason || 'aborted');
    }
  }

  for (const signal of signals) {
    if (!signal) continue;
    if (signal.aborted) {
      abortFrom(signal);
      break;
    }
    signal.addEventListener('abort', () => abortFrom(signal), { once: true });
  }

  return controller.signal;
}

function reward(node, latencyMs) {
  node.ok += 1;
  node.lastLatencyMs = latencyMs;
  node.lastError = null;
  node.score = clamp(node.score + CONFIG.SCORE_SUCCESS_DELTA, CONFIG.SCORE_MIN, CONFIG.SCORE_MAX);
}

function penalize(node, amount, error) {
  node.fail += 1;
  node.lastError = String(error || 'unknown').slice(0, 80);
  node.score = clamp(node.score - amount, CONFIG.SCORE_MIN, CONFIG.SCORE_MAX);
}

// --- Edge cache (Cache API) helpers ---
// Using caches.default instead of an in-memory Map means cache hits can be
// shared across isolates/requests landing on the same Cloudflare PoP,
// rather than depending on hitting the one isolate that already saw a
// given query. Only reliable on a custom domain (confirmed this
// deployment is on one) — on *.workers.dev it can be a no-op.

async function makeCacheKey(profile, questionKey) {
  const input = `${profile}|${questionKey}`;
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const hex = [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, '0')).join('');
  // Cache API keys off a Request/URL, so we synthesize a stable internal one.
  return new Request(`https://doh-cache.internal/${hex}`);
}

async function getCache(cacheKeyRequest) {
  const cache = caches.default;
  const match = await cache.match(cacheKeyRequest);

  if (!match) return null;

  const body = await match.arrayBuffer();
  return { body };
}

function setCache(cacheKeyRequest, body, ttlSeconds, ctx) {
  const cache = caches.default;
  const cacheResponse = new Response(body, {
    headers: {
      'content-type': 'application/dns-message',
      'cache-control': `public, max-age=${ttlSeconds}`
    }
  });

  const putPromise = cache.put(cacheKeyRequest, cacheResponse);

  if (ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(putPromise);
  }
}

function checkSpam(ip) {
  const now = Date.now();
  const current = APP_STATE.throttle.get(ip);
  let stats = current || { count: 0, resetAt: now + CONFIG.RATE_LIMIT_WINDOW_MS };

  if (now > stats.resetAt) {
    stats = { count: 0, resetAt: now + CONFIG.RATE_LIMIT_WINDOW_MS };
  }

  stats.count += 1;
  APP_STATE.throttle.set(ip, stats);

  trimMap(APP_STATE.throttle, CONFIG.MAX_THROTTLE_ENTRIES);

  return stats.count > CONFIG.RATE_LIMIT_MAX_REQUESTS;
}

function trimMap(map, maxEntries) {
  while (map.size > maxEntries) {
    const oldestKey = map.keys().next().value;
    map.delete(oldestKey);
  }
}

function getClientIP(req) {
  return req.headers.get('CF-Connecting-IP')
    || req.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
    || 'unknown';
}

function getHealthSnapshot() {
  const profiles = {};

  for (const [profile, nodes] of Object.entries(APP_STATE.resolversByProfile)) {
    profiles[profile] = nodes.map((node) => ({
      url: node.url,
      score: node.score,
      ok: node.ok,
      fail: node.fail,
      timeout: node.timeout,
      lastLatencyMs: node.lastLatencyMs,
      lastError: node.lastError
    }));
  }

  return {
    version: VERSION,
    cache: 'edge (Cache API, per-colo — not enumerable from the Worker)',
    throttleEntries: APP_STATE.throttle.size,
    profiles
  };
}

function dnsResponse(body, extraHeaders = {}) {
  return new Response(body, {
    status: 200,
    headers: {
      'content-type': 'application/dns-message',
      'cache-control': 'no-store',
      ...extraHeaders
    }
  });
}

function textResponse(text, status = 200, headers = {}) {
  return new Response(text, {
    status,
    headers: {
      'content-type': 'text/plain; charset=utf-8',
      ...headers
    }
  });
}

function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...headers
    }
  });
}

function httpError(message, status) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

function sanitizeHeaderValue(value) {
  return String(value).replace(/[\r\n]/g, '').slice(0, 200);
}
