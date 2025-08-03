import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: false,
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

        "PASSWORD_CHANGED",
        "PASSWORD_CHANGE_FAILED",
        "PASSWORD_RESET_REQUESTED",
        "PASSWORD_RESET_COMPLETED",
        "PASSWORD_RESET_FAILED",
        "LOGIN_PASSWORD_EXPIRED",
        "ADMIN_FORCE_PASSWORD_CHANGE",

        "LOGIN_ATTEMPT_LOCKED_ACCOUNT",
        "LOGIN_FAILED_ACCOUNT_LOCKED",
        "LOGIN_FAILED_INVALID_PASSWORD",
        "ADMIN_LOGIN_ATTEMPT_LOCKED_ACCOUNT",
        "ADMIN_LOGIN_FAILED_ACCOUNT_LOCKED",
        "ADMIN_LOGIN_FAILED_INVALID_PASSWORD",

        "SECURITY_NOSQL_INJECTION_BLOCKED",
        "SECURITY_INVALID_INPUT",
      ],
    },

    description: {
      type: String,
      required: true,
      maxlength: 500,
    },

    method: {
      type: String,
      enum: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    },
    endpoint: {
      type: String,
    },

    ipAddress: {
      type: String,
      required: true,
    },

    status: {
      type: String,
      required: true,
      enum: ["SUCCESS", "FAILURE", "BLOCKED", "DETECTED"],
      default: "SUCCESS",
    },

    metadata: {
      type: mongoose.Schema.Types.Mixed,
    },
  },
  {
    timestamps: true,
    collection: "auditlogs",
  }
);

auditLogSchema.index({ userType: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ status: 1, createdAt: -1 });
auditLogSchema.index({ createdAt: -1 });

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

  if (startDate || endDate) {
    query.createdAt = {};
    if (startDate) {
      query.createdAt.$gte = new Date(startDate);
    }
    if (endDate) {
      const endDateTime = new Date(endDate);
      endDateTime.setHours(23, 59, 59, 999);
      query.createdAt.$lte = endDateTime;
    }
  }

  if (userType) query.userType = userType;
  if (action) query.action = action;
  if (status) query.status = status;
  if (userEmail) query.userEmail = new RegExp(userEmail, "i");

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
