import winston from "winston";
import path from "path";

// Create a logger instance
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp({
      format: "YYYY-MM-DD HH:mm:ss",
    }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: "fityard-api" },
  transports: [
    // Write all logs with importance level of `error` or less to `error.log`
    new winston.transports.File({
      filename: path.join("logs", "error.log"),
      level: "error",
    }),
    // Write all logs with importance level of `info` or less to `combined.log`
    new winston.transports.File({
      filename: path.join("logs", "combined.log"),
    }),
    // Write activity logs to a separate file
    new winston.transports.File({
      filename: path.join("logs", "activity.log"),
      level: "info",
    }),
  ],
});

// If we're not in production then log to the console as well
if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

// Helper functions for common log types
export const logActivity = (userId, action, description, ip, userAgent) => {
  logger.info("USER_ACTIVITY", {
    userId,
    action,
    description,
    ip,
    userAgent,
    timestamp: new Date().toISOString(),
  });
};

export const logError = (action, errorMessage, context = {}) => {
  logger.error("ERROR", {
    action,
    message: errorMessage,
    context,
    timestamp: new Date().toISOString(),
  });
};

export const logPayment = (
  userId,
  action,
  description,
  paymentDetails = {}
) => {
  logger.info("PAYMENT_ACTIVITY", {
    userId,
    action,
    description,
    paymentDetails,
    timestamp: new Date().toISOString(),
  });
};

export default logger;
