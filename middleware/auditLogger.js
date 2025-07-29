import auditLogModel from "../models/auditLogModel.js";
import userModel from "../models/userModel.js";
import { logActivity, logError } from "../utils/logger.js";

// Simple audit logging function
export const createAuditLog = async (logData) => {
  try {
    const {
      userId,
      userType,
      userEmail,
      action,
      description,
      method,
      endpoint,
      ipAddress,
      status = "SUCCESS",
      metadata = {},
    } = logData;

    // Create simple audit log entry
    const auditLog = new auditLogModel({
      userId,
      userType,
      userEmail,
      action,
      description,
      method,
      endpoint,
      ipAddress,
      status,
      metadata,
    });

    await auditLog.save();

    // Also log to Winston for immediate monitoring
    logActivity(userId, action, description, ipAddress);

    return auditLog;
  } catch (error) {
    logError("Failed to create audit log", error);
    console.error("Audit logging failed:", error);
  }
};

// Simple middleware to automatically log API requests
export const auditMiddleware = () => {
  return async (req, res, next) => {
    // Store original res.end to capture when response completes
    const originalEnd = res.end;
    res.end = async function (...args) {
      try {
        // Skip health checks and static files
        const skipPatterns = [
          "/health",
          "/ping",
          "/favicon.ico",
          "/api/csrf-token",
        ];
        const shouldSkip = skipPatterns.some((pattern) =>
          req.path.includes(pattern)
        );

        if (!shouldSkip && req.originalUrl.startsWith("/api/")) {
          // Determine action based on method and path
          const action = determineAction(req.method, req.originalUrl);

          // Get user info from request - handle both auth patterns
          let userId = null;
          let userType = "Anonymous";
          let userEmail = "anonymous";

          // Check for admin authentication (sets req.admin)
          if (req.admin) {
            userId = req.admin._id;
            userType = "Admin";
            userEmail = req.admin.email;
          }
          // Check for user authentication (sets req.body.userId)
          else if (req.body?.userId) {
            try {
              const user = await userModel.findById(req.body.userId);
              if (user) {
                userId = user._id;
                userType = "User";
                userEmail = user.email;
              }
            } catch (error) {
              console.error("Error fetching user for audit:", error);
            }
          }

          // Determine status
          const status = res.statusCode >= 400 ? "FAILURE" : "SUCCESS";

          // Only log if we have a user (authenticated requests) OR it's a significant unauthenticated action
          const isSignificantUnauthenticatedAction =
            !userId &&
            (req.originalUrl.includes("/register") ||
              req.originalUrl.includes("/login") ||
              req.originalUrl.includes("/verify"));

          if (userId || isSignificantUnauthenticatedAction) {
            await createAuditLog({
              userId: userId || null,
              userType: userId ? userType : "Anonymous",
              userEmail: userId ? userEmail : "anonymous",
              action,
              description: `${req.method} ${req.originalUrl} - ${res.statusCode}`,
              method: req.method,
              endpoint: req.originalUrl,
              ipAddress: req.ip || req.connection.remoteAddress,
              status,
              metadata: {
                statusCode: res.statusCode,
                userAgent: req.get("User-Agent"),
              },
            });
          }
        }
      } catch (error) {
        console.error("Audit middleware error:", error);
      }

      return originalEnd.apply(this, args);
    };

    next();
  };
};

// Helper function to determine action from method and path
const determineAction = (method, path) => {
  const pathLower = path.toLowerCase();

  // Authentication routes
  if (pathLower.includes("/login")) return "LOGIN";
  if (pathLower.includes("/logout")) return "LOGOUT";
  if (pathLower.includes("/register")) return "REGISTER";

  // Admin routes
  if (pathLower.includes("/admin")) {
    if (pathLower.includes("/login")) return "ADMIN_LOGIN";
    if (pathLower.includes("/logout")) return "ADMIN_LOGOUT";
    return "ADMIN_ACTION";
  }

  // Product routes
  if (pathLower.includes("/product")) {
    switch (method) {
      case "POST":
        return "PRODUCT_CREATE";
      case "PUT":
        return "PRODUCT_UPDATE";
      case "DELETE":
        return "PRODUCT_DELETE";
      default:
        return "PRODUCT_VIEW";
    }
  }

  // Order routes
  if (pathLower.includes("/order")) {
    switch (method) {
      case "POST":
        return "ORDER_CREATE";
      case "PUT":
        return "ORDER_UPDATE";
      default:
        return "ORDER_VIEW";
    }
  }

  // Cart routes
  if (pathLower.includes("/cart")) {
    switch (method) {
      case "POST":
        return "CART_ADD";
      case "PUT":
        return "CART_UPDATE";
      case "DELETE":
        return "CART_REMOVE";
      default:
        return "CART_VIEW";
    }
  }

  // Profile routes
  if (pathLower.includes("/profile")) {
    return method === "PUT" ? "PROFILE_UPDATE" : "PROFILE_VIEW";
  }

  // File upload
  if (pathLower.includes("/upload")) return "FILE_UPLOAD";

  // Default action
  return "API_REQUEST";
};

// Function to log specific events (to be called from controllers)
export const logUserAction = async (
  user,
  action,
  description = "",
  metadata = {}
) => {
  await createAuditLog({
    userId: user.id || user._id,
    userType: user.isAdmin ? "Admin" : "User",
    userEmail: user.email,
    action,
    description: description || `User performed ${action}`,
    status: "SUCCESS",
    metadata,
  });
};

export default { createAuditLog, auditMiddleware, logUserAction };
