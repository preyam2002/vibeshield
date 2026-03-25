/** Scanner configuration — extracted from hardcoded constants for configurability */

/** Maximum time (ms) each module is allowed to run before being killed */
export const MODULE_TIMEOUT_MS = Number(process.env.VIBESHIELD_MODULE_TIMEOUT_MS) || 120_000;

/** Maximum findings returned from a single module (prevents one module dominating results) */
export const MAX_FINDINGS_PER_MODULE = Number(process.env.VIBESHIELD_MAX_FINDINGS_PER_MODULE) || 8;

/** How many security modules to run in each parallel batch */
export const SECURITY_BATCH_SIZE = Number(process.env.VIBESHIELD_BATCH_SIZE) || 21;

/** Circuit breaker: abort scan after this many consecutive module failures */
export const CIRCUIT_BREAKER_THRESHOLD = Number(process.env.VIBESHIELD_CIRCUIT_BREAKER) || 4;

/** Maximum number of JS files to fetch during recon */
export const MAX_JS_FILES = Number(process.env.VIBESHIELD_MAX_JS_FILES) || 40;

/** Maximum concurrent scans */
export const MAX_CONCURRENT_SCANS = Number(process.env.VIBESHIELD_MAX_CONCURRENT) || 10;

/** Rate limit: max scans per target within the window */
export const RATE_LIMIT_PER_TARGET = Number(process.env.VIBESHIELD_RATE_TARGET) || 3;

/** Rate limit: max scans per IP within the window */
export const RATE_LIMIT_PER_IP = Number(process.env.VIBESHIELD_RATE_IP) || 20;

/** Rate limit window in milliseconds */
export const RATE_LIMIT_WINDOW_MS = Number(process.env.VIBESHIELD_RATE_WINDOW_MS) || 5 * 60 * 1000;

/** Maximum number of completed scans to keep in memory */
export const MAX_STORED_SCANS = Number(process.env.VIBESHIELD_MAX_SCANS) || 100;

/** Time (ms) after which a running scan is considered stale and can be evicted */
export const STALE_SCAN_TIMEOUT_MS = Number(process.env.VIBESHIELD_STALE_TIMEOUT_MS) || 5 * 60 * 1000;

/** Default fetch timeout for scan requests (ms) */
export const DEFAULT_FETCH_TIMEOUT_MS = Number(process.env.VIBESHIELD_FETCH_TIMEOUT_MS) || 10_000;
