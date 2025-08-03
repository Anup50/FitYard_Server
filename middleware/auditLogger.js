import auditLogModel from "../models/auditLogModel.js";
import userModel from "../models/userModel.js";
import { logActivity, logError } from "../utils/logger.js";
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

    logActivity(userId, action, description, ipAddress);

    return auditLog;
  } catch (error) {
    logError("Failed to create audit log", error);
    console.error("Audit logging failed:", error);
  }
};
export const auditMiddleware = () => {
  return async (req, res, next) => {
    const originalEnd = res.end;
    res.end = async function (...args) {
      try {
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
          const action = determineAction(req.method, req.originalUrl);

          let userId = null;
          let userType = "Anonymous";
          let userEmail = "anonymous";

          if (req.admin) {
            userId = req.admin._id;
            userType = "Admin";
            userEmail = req.admin.email;
          } else if (req.body?.userId) {
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

          const status = res.statusCode >= 400 ? "FAILURE" : "SUCCESS";

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
const determineAction = (method, path) => {
  const pathLower = path.toLowerCase();

  if (pathLower.includes("/login")) return "LOGIN";
  if (pathLower.includes("/logout")) return "LOGOUT";
  if (pathLower.includes("/register")) return "REGISTER";

  if (pathLower.includes("/admin")) {
    if (pathLower.includes("/login")) return "ADMIN_LOGIN";
    if (pathLower.includes("/logout")) return "ADMIN_LOGOUT";
    return "ADMIN_ACTION";
  }

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

  if (pathLower.includes("/profile")) {
    return method === "PUT" ? "PROFILE_UPDATE" : "PROFILE_VIEW";
  }

  if (pathLower.includes("/upload")) return "FILE_UPLOAD";

  return "API_REQUEST";
};
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
