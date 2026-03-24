// Global concurrency-limited fetch to prevent overwhelming the event loop
let active = 0;
const MAX_CONCURRENT = 12;
const queue: (() => void)[] = [];

// Response cache for identical GET requests within a scan
const responseCache = new Map<string, { status: number; headers: Record<string, string>; body: string; timestamp: number }>();
const CACHE_TTL = 30_000; // 30s — enough for a single scan run

const waitForSlot = (): Promise<void> => {
  if (active < MAX_CONCURRENT) {
    active++;
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    queue.push(() => {
      active++;
      resolve();
    });
  });
};

const releaseSlot = () => {
  active--;
  if (queue.length > 0) {
    const next = queue.shift()!;
    next();
  }
};

export const scanFetch = async (
  url: string,
  opts: RequestInit & { timeoutMs?: number; noCache?: boolean } = {},
): Promise<Response> => {
  const { timeoutMs = 8000, noCache, ...fetchOpts } = opts;
  const method = (fetchOpts.method || "GET").toUpperCase();

  // Cache only simple GET requests (no custom headers beyond defaults)
  const isCacheable = method === "GET" && !noCache && !fetchOpts.headers && fetchOpts.redirect !== "manual";
  if (isCacheable) {
    const cached = responseCache.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return new Response(cached.body, {
        status: cached.status,
        headers: cached.headers,
      });
    }
  }

  await waitForSlot();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...fetchOpts,
      signal: controller.signal,
    });

    // Cache successful GET responses
    if (isCacheable && res.ok) {
      const body = await res.text();
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k] = v; });
      responseCache.set(url, { status: res.status, headers, body, timestamp: Date.now() });
      // Evict old entries periodically
      if (responseCache.size > 200) {
        const now = Date.now();
        for (const [key, val] of responseCache) {
          if (now - val.timestamp > CACHE_TTL) responseCache.delete(key);
        }
      }
      return new Response(body, { status: res.status, headers });
    }

    return res;
  } finally {
    clearTimeout(timer);
    releaseSlot();
  }
};

export const clearScanCache = () => responseCache.clear();
