import pino from "pino";

const level = process.env.LOG_LEVEL || (process.env.NODE_ENV === "production" ? "info" : "debug");

const logger = pino({
  level,
  transport: process.env.NODE_ENV !== "production" ? {
    target: "pino/file",
    options: { destination: 1 }, // stdout
  } : undefined,
  formatters: {
    level: (label) => ({ level: label }),
  },
  base: { service: "vibeshield" },
  timestamp: pino.stdTimeFunctions.isoTime,
});

export default logger;

// Convenience child loggers
export const scanLogger = logger.child({ component: "scanner" });
export const apiLogger = logger.child({ component: "api" });
export const authLogger = logger.child({ component: "auth" });
