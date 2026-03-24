// Global concurrency-limited fetch to prevent overwhelming the event loop
let active = 0;
const MAX_CONCURRENT = 12;
const queue: (() => void)[] = [];

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
  opts: RequestInit & { timeoutMs?: number } = {},
): Promise<Response> => {
  await waitForSlot();
  const { timeoutMs = 8000, ...fetchOpts } = opts;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...fetchOpts,
      signal: controller.signal,
    });
    return res;
  } finally {
    clearTimeout(timer);
    releaseSlot();
  }
};
