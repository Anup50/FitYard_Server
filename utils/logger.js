import winston from "winston";
import path from "path";

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
    new winston.transports.File({
      filename: path.join("logs", "error.log"),
      level: "error",
    }),
    new winston.transports.File({
      filename: path.join("logs", "combined.log"),
    }),
    new winston.transports.File({
      filename: path.join("logs", "activity.log"),
      level: "info",
    }),
  ],
});

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
