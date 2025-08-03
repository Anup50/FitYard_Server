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

auditRouter.get("/logs", adminAuth, auditRateLimit, getAuditLogs);

auditRouter.get("/stats", adminAuth, auditRateLimit, getAuditStats);

auditRouter.get(
  "/security-events",
  adminAuth,
  auditRateLimit,
  getSecurityEvents
);

auditRouter.get(
  "/export",
  adminAuth,
  auditRateLimit,
  csrfProtection,
  exportAuditLogs
);

auditRouter.get("/filter-options", adminAuth, adminRateLimit, getFilterOptions);

export default auditRouter;
