// Global concurrency-limited fetch with retry logic
let active = 0;
const MAX_CONCURRENT = 12;
const queue: (() => void)[] = [];

// Response cache for identical GET requests within a scan
const responseCache = new Map<string, { status: number; headers: Record<string, string>; body: string; timestamp: number }>();
const CACHE_TTL = 30_000; // 30s — enough for a single scan run
const MAX_CACHE_SIZE = 500;

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

const RETRY_DELAYS = [0, 300, 800]; // immediate, 300ms, 800ms
const RETRYABLE_ERRORS = new Set(["ECONNRESET", "ECONNREFUSED", "ETIMEDOUT", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_SOCKET"]);

const isRetryable = (err: unknown): boolean => {
  if (err instanceof DOMException && err.name === "AbortError") return false; // timeout — don't retry
  if (err instanceof TypeError) return true; // network error
  const code = (err as { code?: string })?.code;
  if (code && RETRYABLE_ERRORS.has(code)) return true;
  return false;
};

const isRetryableStatus = (status: number): boolean => {
  return status === 429 || status === 502 || status === 503 || status === 504;
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
  try {
    let lastError: unknown;

    for (let attempt = 0; attempt < RETRY_DELAYS.length; attempt++) {
      if (attempt > 0) {
        await new Promise((r) => setTimeout(r, RETRY_DELAYS[attempt]));
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);

      try {
        const res = await fetch(url, {
          ...fetchOpts,
          signal: controller.signal,
        });
        clearTimeout(timer);

        // Retry on transient server errors (but not on last attempt)
        if (isRetryableStatus(res.status) && attempt < RETRY_DELAYS.length - 1) {
          lastError = new Error(`HTTP ${res.status}`);
          continue;
        }

        // Cache successful GET responses
        if (isCacheable && res.ok) {
          const body = await res.text();
          const headers: Record<string, string> = {};
          res.headers.forEach((v, k) => { headers[k] = v; });
          responseCache.set(url, { status: res.status, headers, body, timestamp: Date.now() });
          if (responseCache.size > MAX_CACHE_SIZE) {
            const now = Date.now();
            for (const [key, val] of responseCache) {
              if (now - val.timestamp > CACHE_TTL) responseCache.delete(key);
            }
            // If still too large, drop oldest 25%
            if (responseCache.size > MAX_CACHE_SIZE) {
              const entries = [...responseCache.entries()].sort((a, b) => a[1].timestamp - b[1].timestamp);
              const toDelete = Math.floor(entries.length * 0.25);
              for (let i = 0; i < toDelete; i++) responseCache.delete(entries[i][0]);
            }
          }
          return new Response(body, { status: res.status, headers });
        }

        return res;
      } catch (err) {
        clearTimeout(timer);
        lastError = err;
        if (!isRetryable(err) || attempt === RETRY_DELAYS.length - 1) {
          throw err;
        }
      }
    }

    throw lastError;
  } finally {
    releaseSlot();
  }
};

export const clearScanCache = () => responseCache.clear();
