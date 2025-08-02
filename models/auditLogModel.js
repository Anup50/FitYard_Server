import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema(
  {
    // User Information
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: false, // Allow null for anonymous users
    },
    userType: {
      type: String,
      required: true,
      enum: ["User", "Admin", "Anonymous"],
    },
    userEmail: {
      type: String,
      required: true,
    },

    // Action performed
    action: {
      type: String,
      required: true,
      enum: [
        "LOGIN",
        "LOGOUT",
        "REGISTER",
        "PRODUCT_CREATE",
        "PRODUCT_UPDATE",
        "PRODUCT_DELETE",
        "PRODUCT_VIEW",
        "ORDER_CREATE",
        "ORDER_UPDATE",
        "ORDER_VIEW",
        "CART_ADD",
        "CART_UPDATE",
        "CART_REMOVE",
        "CART_VIEW",
        "PROFILE_UPDATE",
        "PROFILE_VIEW",
        "ADMIN_LOGIN",
        "ADMIN_LOGOUT",
        "ADMIN_ACTION",
        "FILE_UPLOAD",
        "API_REQUEST",
        "ERROR",
        "RATE_LIMIT_VIOLATION",
        "LOGIN_RATE_LIMIT_VIOLATION",
        "GENERAL_RATE_LIMIT_VIOLATION",
        "ADMIN_RATE_LIMIT_VIOLATION",
        "AUDIT_RATE_LIMIT_VIOLATION",
        "REGISTRATION_RATE_LIMIT_VIOLATION",
        "PASSWORD_RESET_RATE_LIMIT_VIOLATION",
        // Password management actions
        "PASSWORD_CHANGED",
        "PASSWORD_CHANGE_FAILED",
        "PASSWORD_RESET_REQUESTED",
        "PASSWORD_RESET_COMPLETED",
        "PASSWORD_RESET_FAILED",
        "LOGIN_PASSWORD_EXPIRED",
        "ADMIN_FORCE_PASSWORD_CHANGE",
        // Account lockout actions
        "LOGIN_ATTEMPT_LOCKED_ACCOUNT",
        "LOGIN_FAILED_ACCOUNT_LOCKED",
        "LOGIN_FAILED_INVALID_PASSWORD",
        "ADMIN_LOGIN_ATTEMPT_LOCKED_ACCOUNT",
        "ADMIN_LOGIN_FAILED_ACCOUNT_LOCKED",
        "ADMIN_LOGIN_FAILED_INVALID_PASSWORD",
        // Security events
        "SECURITY_NOSQL_INJECTION_BLOCKED",
        "SECURITY_INVALID_INPUT",
      ],
    },

    // What happened
    description: {
      type: String,
      required: true,
      maxlength: 500,
    },

    // Request details
    method: {
      type: String,
      enum: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    },
    endpoint: {
      type: String,
    },

    // Basic security info
    ipAddress: {
      type: String,
      required: true,
    },

    // Result
    status: {
      type: String,
      required: true,
      enum: ["SUCCESS", "FAILURE", "BLOCKED", "DETECTED"],
      default: "SUCCESS",
    },

    // Additional data (optional)
    metadata: {
      type: mongoose.Schema.Types.Mixed,
    },
  },
  {
    timestamps: true, // Adds createdAt and updatedAt
    collection: "auditlogs",
  }
);

// Simple indexes for basic searching
auditLogSchema.index({ userType: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ status: 1, createdAt: -1 });
auditLogSchema.index({ createdAt: -1 });

// Simple search method for admin filtering
auditLogSchema.statics.searchLogs = function (searchParams) {
  const {
    startDate,
    endDate,
    userType,
    action,
    status,
    userEmail,
    page = 1,
    limit = 50,
  } = searchParams;

  let query = {};

  // Date range filter
  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) {
      query.createdAt.$gte = new Date(startDate);
    }
    if (endDate) {
      // Add 23:59:59.999 to include the entire end date
      const endDateTime = new Date(endDate);
      endDateTime.setHours(23, 59, 59, 999);
      query.createdAt.$lte = endDateTime;
    }
  }

  // Basic filters
  if (userType) query.userType = userType;
  if (action) query.action = action;
  if (status) query.status = status;
  if (userEmail) query.userEmail = new RegExp(userEmail, "i");

  // Debug logging
  console.log("Search Query:", JSON.stringify(query, null, 2));
  console.log("Search Params:", searchParams);

  const skip = (page - 1) * limit;

  return this.find(query)
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .lean();
};

const auditLogModel = mongoose.model("AuditLog", auditLogSchema);

export default auditLogModel;
