import rateLimit from "express-rate-limit";
import { createAuditLog } from "./auditLogger.js";

export const createRateLimitWithLogging = (options = {}) => {
  const {
    windowMs = 15 * 60 * 1000, // 15 minutes
    max = 100,
    message = "Too many requests",
    actionType = "RATE_LIMIT_VIOLATION",
    userType = "Anonymous",
    ...otherOptions
  } = options;

  return rateLimit({
    windowMs,
    max,
    message: {
      success: false,
      message: message,
      error: "Rate limit exceeded",
    },
    standardHeaders: true,
    legacyHeaders: false,
    ...otherOptions,

    handler: async (req, res) => {
      const userId = req.user?._id || req.admin?._id || null;
      const userEmail = req.user?.email || req.admin?.email || "unknown";
      const userTypeDetected = req.admin
        ? "Admin"
        : req.user
        ? "User"
        : userType;

      try {
        await createAuditLog({
          userId,
          userType: userTypeDetected,
          userEmail,
          action: actionType,
          description: `Rate limit exceeded - ${max} requests per ${
            windowMs / 1000
          }s window on ${req.path}`,
          method: req.method,
          endpoint: req.path,
          ipAddress: req.ip,
          status: "FAILURE",
          metadata: {
            statusCode: 429,
            rateLimitWindow: windowMs,
            rateLimitMax: max,
            userAgent: req.get("User-Agent"),
            referer: req.get("Referer") || "unknown",
          },
        });
      } catch (auditError) {
        console.error("Failed to log rate limit violation:", auditError);
      }

      res.status(429).json({
        success: false,
        message: message,
        error: "Rate limit exceeded",
      });
    },
  });
};

export const loginRateLimit = createRateLimitWithLogging({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: "Too many login attempts, please try again later",
  actionType: "LOGIN_RATE_LIMIT_VIOLATION",
});

// General API rate limiting
export const generalRateLimit = createRateLimitWithLogging({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per IP
  message: "Too many requests, please try again later",
  actionType: "GENERAL_RATE_LIMIT_VIOLATION",
});

// Admin rate limiting - higher limits
export const adminRateLimit = createRateLimitWithLogging({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Higher limit for admins
  message: "Too many admin requests, please try again later",
  actionType: "ADMIN_RATE_LIMIT_VIOLATION",
  userType: "Admin",
});

// Audit-specific rate limiting
export const auditRateLimit = createRateLimitWithLogging({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // 20 audit requests per 5 minutes
  message: "Too many audit requests, please try again later",
  actionType: "AUDIT_RATE_LIMIT_VIOLATION",
  userType: "Admin",
});

// Registration rate limiting
export const registrationRateLimit = createRateLimitWithLogging({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registration attempts per hour
  message: "Too many registration attempts, please try again later",
  actionType: "REGISTRATION_RATE_LIMIT_VIOLATION",
});

// Password reset rate limiting
export const passwordResetRateLimit = createRateLimitWithLogging({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 password reset attempts per IP
  message: "Too many password reset attempts, please try again later",
  actionType: "PASSWORD_RESET_RATE_LIMIT_VIOLATION",
});
