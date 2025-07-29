import express from "express";
import {
  getAuditLogs,
  getAuditStats,
  exportAuditLogs,
  getFilterOptions,
} from "../controllers/auditController.js";
import adminAuth from "../middleware/adminAuth.js";
import { csrfProtection } from "../middleware/csrfProtection.js";

const auditRouter = express.Router();

// All audit routes require admin authentication

// Get audit logs with basic filtering and pagination
auditRouter.get("/logs", adminAuth, getAuditLogs);

// Get basic audit statistics
auditRouter.get("/stats", adminAuth, getAuditStats);

// Export audit logs (CSV) - CSRF protected
auditRouter.get("/export", adminAuth, csrfProtection, exportAuditLogs);

// Get available filter options for frontend
auditRouter.get("/filter-options", adminAuth, getFilterOptions);

export default auditRouter;
