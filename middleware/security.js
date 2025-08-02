import mongoSanitize from "express-mongo-sanitize";
import helmet from "helmet";
import { createAuditLog } from "./auditLogger.js";

export const mongoSanitizer = mongoSanitize({
  onSanitize: ({ req, key }) => {
    console.warn(
      `NoSQL injection attempt blocked: ${key} in ${req.method} ${req.path} from IP: ${req.ip}`
    );

    setImmediate(async () => {
      try {
        await createAuditLog({
          userId: req.user?._id || req.admin?._id || null,
          userType: req.admin ? "Admin" : req.user ? "User" : "Anonymous",
          userEmail: req.user?.email || req.admin?.email || "unknown",
          action: "SECURITY_NOSQL_INJECTION_BLOCKED",
          description: `NoSQL injection attempt blocked on field: ${key}`,
          method: req.method,
          endpoint: req.path,
          ipAddress: req.ip,
          status: "BLOCKED",
          metadata: {
            blockedField: key,
            userAgent: req.get("User-Agent"),
            referer: req.get("Referer") || "none",
          },
        });
      } catch (error) {
        console.error("Failed to log NoSQL injection attempt:", error);
      }
    });
  },
  replaceWith: "_BLOCKED_",
});

export const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: [
        "'self'",
        "data:",
        "https:",
        "cloudinary.com",
        "*.cloudinary.com",
      ],
      connectSrc: [
        "'self'",
        "https://localhost:4000",
        "https://localhost:3000",
      ],
    },
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" },
});

export const validateAndSanitizeInput = (input, type) => {
  if (input === null || input === undefined) {
    throw new Error(`${type} is required`);
  }

  if (typeof input !== "string") {
    throw new Error(`Invalid ${type} format - must be string`);
  }

  const dangerousPatterns = [
    /\$where/i,
    /\$ne/i,
    /\$gt/i,
    /\$lt/i,
    /\$regex/i,
    /\$or/i,
    /\$and/i,
    /\$in/i,
    /\$nin/i,
    /\$exists/i,
    /javascript:/i,
    /eval\(/i,
    /function\(/i,
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(input)) {
      throw new Error(`Invalid ${type} - contains prohibited characters`);
    }
  }

  const sanitized = input.replace(/[${}]/g, "").trim();

  if (!sanitized) {
    throw new Error(`${type} cannot be empty`);
  }

  switch (type) {
    case "email":
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(sanitized)) {
        throw new Error("Invalid email format");
      }
      return sanitized.toLowerCase();

    case "password":
      if (sanitized.length < 8) {
        throw new Error("Password must be at least 8 characters");
      }
      if (sanitized.length > 128) {
        throw new Error("Password too long");
      }
      return input; // Don't modify password

    case "name":
      if (sanitized.length > 100) {
        throw new Error("Name too long");
      }

      const nameRegex = /^[a-zA-Z\s\-']+$/;
      if (!nameRegex.test(sanitized)) {
        throw new Error(
          "Name can only contain letters, spaces, hyphens, and apostrophes"
        );
      }
      return sanitized;

    case "id":
      const objectIdRegex = /^[0-9a-fA-F]{24}$/;
      if (!objectIdRegex.test(sanitized)) {
        throw new Error("Invalid ID format");
      }
      return sanitized;

    default:
      if (sanitized.length > 1000) {
        throw new Error(`${type} too long`);
      }
      return sanitized;
  }
};

export const logSecurityEvent = async (req, eventType, details) => {
  try {
    await createAuditLog({
      userId: req.user?._id || req.admin?._id || null,
      userType: req.admin ? "Admin" : req.user ? "User" : "Anonymous",
      userEmail: req.user?.email || req.admin?.email || "unknown",
      action: `SECURITY_${eventType}`,
      description: `Security event: ${eventType} - ${details}`,
      method: req.method,
      endpoint: req.path,
      ipAddress: req.ip,
      status: "DETECTED",
      metadata: {
        userAgent: req.get("User-Agent"),
        referer: req.get("Referer"),
        eventType,
        details,
      },
    });
  } catch (error) {
    console.error("Failed to log security event:", error);
  }
};
