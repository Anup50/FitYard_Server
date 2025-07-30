import express from "express";
import {
  getAuditLogs,
  getAuditStats,
  exportAuditLogs,
  getFilterOptions,
  getSecurityEvents,
} from "../controllers/auditController.js";
import adminAuth from "../middleware/adminAuth.js";
import { csrfProtection } from "../middleware/csrfProtection.js";
import {
  auditRateLimit,
  adminRateLimit,
} from "../middleware/rateLimitLogger.js";

const auditRouter = express.Router();

// All audit routes require admin authentication

// Get audit logs with basic filtering and pagination
auditRouter.get("/logs", adminAuth, auditRateLimit, getAuditLogs);

// Get basic audit statistics
auditRouter.get("/stats", adminAuth, auditRateLimit, getAuditStats);

// Get security events (NoSQL injection attempts, etc.)
auditRouter.get(
  "/security-events",
  adminAuth,
  auditRateLimit,
  getSecurityEvents
);

// Export audit logs (CSV) - CSRF protected
auditRouter.get(
  "/export",
  adminAuth,
  auditRateLimit,
  csrfProtection,
  exportAuditLogs
);

// Get available filter options for frontend
auditRouter.get("/filter-options", adminAuth, adminRateLimit, getFilterOptions);

export default auditRouter;
