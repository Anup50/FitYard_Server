import auditLogModel from "../models/auditLogModel.js";
import { createAuditLog } from "../middleware/auditLogger.js";

// Get audit logs with basic filtering
const getAuditLogs = async (req, res) => {
  try {
    const {
      page = 1,
      limit = 50,
      startDate,
      endDate,
      userType,
      action,
      status,
      userEmail,
    } = req.query;

    // Validate pagination
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));

    // Build search parameters
    const searchParams = {
      page: pageNum,
      limit: limitNum,
      startDate,
      endDate,
      userType,
      action,
      status,
      userEmail,
    };

    // Get total count for pagination
    let countQuery = {};
    if (startDate || endDate) {
      countQuery.createdAt = {};
      if (startDate) countQuery.createdAt.$gte = new Date(startDate);
      if (endDate) {
        // Add 23:59:59.999 to include the entire end date
        const endDateTime = new Date(endDate);
        endDateTime.setHours(23, 59, 59, 999);
        countQuery.createdAt.$lte = endDateTime;
      }
    }
    if (userType) countQuery.userType = userType;
    if (action) countQuery.action = action;
    if (status) countQuery.status = status;
    if (userEmail) countQuery.userEmail = new RegExp(userEmail, "i");

    const totalLogs = await auditLogModel.countDocuments(countQuery);
    const totalPages = Math.ceil(totalLogs / limitNum);

    // Get logs using the search method
    const logs = await auditLogModel.searchLogs(searchParams);

    // Log admin's audit log access
    await createAuditLog({
      userId: req.admin._id,
      userType: "Admin",
      userEmail: req.admin.email,
      action: "ADMIN_ACTION",
      description: `Admin accessed audit logs`,
      method: req.method,
      endpoint: req.path,
      ipAddress: req.ip,
      status: "SUCCESS",
    });

    res.status(200).json({
      success: true,
      message: "Audit logs retrieved successfully",
      data: {
        logs,
        pagination: {
          currentPage: pageNum,
          totalPages,
          totalLogs,
          hasNextPage: pageNum < totalPages,
          hasPrevPage: pageNum > 1,
          limit: limitNum,
        },
      },
    });
  } catch (error) {
    console.error("Error retrieving audit logs:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve audit logs",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : "Internal server error",
    });
  }
};

// Get basic audit statistics
const getAuditStats = async (req, res) => {
  try {
    const { days = 7 } = req.query;

    // Calculate date range
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // Basic statistics
    const totalLogs = await auditLogModel.countDocuments({
      createdAt: { $gte: startDate },
    });

    const successCount = await auditLogModel.countDocuments({
      createdAt: { $gte: startDate },
      status: "SUCCESS",
    });

    const failureCount = await auditLogModel.countDocuments({
      createdAt: { $gte: startDate },
      status: "FAILURE",
    });

    // Top actions
    const topActions = await auditLogModel.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      { $group: { _id: "$action", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 5 },
    ]);

    // User type distribution
    const userTypeStats = await auditLogModel.aggregate([
      { $match: { createdAt: { $gte: startDate } } },
      { $group: { _id: "$userType", count: { $sum: 1 } } },
    ]);

    // Log admin's stats access
    await createAuditLog({
      userId: req.admin._id,
      userType: "Admin",
      userEmail: req.admin.email,
      action: "ADMIN_ACTION",
      description: `Admin accessed audit statistics`,
      method: req.method,
      endpoint: req.path,
      ipAddress: req.ip,
      status: "SUCCESS",
    });

    res.status(200).json({
      success: true,
      message: "Audit statistics retrieved successfully",
      data: {
        summary: {
          totalLogs,
          successCount,
          failureCount,
          successRate:
            totalLogs > 0 ? ((successCount / totalLogs) * 100).toFixed(1) : 0,
        },
        topActions,
        userTypeStats,
        period: `${days} days`,
      },
    });
  } catch (error) {
    console.error("Error retrieving audit stats:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve audit statistics",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : "Internal server error",
    });
  }
};

// Simple export functionality
const exportAuditLogs = async (req, res) => {
  try {
    const {
      startDate,
      endDate,
      userType,
      action,
      maxRecords = 1000,
    } = req.query;

    // Build query
    let query = {};
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) query.createdAt.$gte = new Date(startDate);
      if (endDate) {
        // Add 23:59:59.999 to include the entire end date
        const endDateTime = new Date(endDate);
        endDateTime.setHours(23, 59, 59, 999);
        query.createdAt.$lte = endDateTime;
      }
    }
    if (userType) query.userType = userType;
    if (action) query.action = action;

    const logs = await auditLogModel
      .find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(maxRecords))
      .lean();

    // Generate simple CSV
    const csvHeaders = [
      "Date",
      "User Email",
      "User Type",
      "Action",
      "Description",
      "Status",
      "IP Address",
    ];

    const csvRows = logs.map((log) => [
      new Date(log.createdAt).toISOString(),
      log.userEmail,
      log.userType,
      log.action,
      `"${log.description.replace(/"/g, '""')}"`,
      log.status,
      log.ipAddress,
    ]);

    const csvContent = [
      csvHeaders.join(","),
      ...csvRows.map((row) => row.join(",")),
    ].join("\n");

    // Log the export
    await createAuditLog({
      userId: req.admin._id,
      userType: "Admin",
      userEmail: req.admin.email,
      action: "ADMIN_ACTION",
      description: `Admin exported ${logs.length} audit log records`,
      method: req.method,
      endpoint: req.path,
      ipAddress: req.ip,
      status: "SUCCESS",
    });

    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="audit_logs_${
        new Date().toISOString().split("T")[0]
      }.csv"`
    );

    return res.status(200).send(csvContent);
  } catch (error) {
    console.error("Error exporting audit logs:", error);

    res.status(500).json({
      success: false,
      message: "Failed to export audit logs",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : "Internal server error",
    });
  }
};

// Get available filter options
const getFilterOptions = async (req, res) => {
  try {
    const [actions, userTypes, statuses] = await Promise.all([
      auditLogModel.distinct("action"),
      auditLogModel.distinct("userType"),
      auditLogModel.distinct("status"),
    ]);

    res.status(200).json({
      success: true,
      message: "Filter options retrieved successfully",
      data: {
        actions: actions.sort(),
        userTypes: userTypes.sort(),
        statuses: statuses.sort(),
      },
    });
  } catch (error) {
    console.error("Error retrieving filter options:", error);

    res.status(500).json({
      success: false,
      message: "Failed to retrieve filter options",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : "Internal server error",
    });
  }
};

// Get security events (NoSQL injection attempts, etc.)
const getSecurityEvents = async (req, res) => {
  try {
    const { page = 1, limit = 50, hours = 24 } = req.query;

    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
    const hoursNum = Math.min(168, Math.max(1, parseInt(hours))); // Max 7 days

    // Calculate time range
    const timeRange = new Date(Date.now() - hoursNum * 60 * 60 * 1000);

    // Get security events
    const securityEvents = await auditLogModel
      .find({
        action: { $regex: /^SECURITY_/ },
        createdAt: { $gte: timeRange },
      })
      .sort({ createdAt: -1 })
      .limit(limitNum)
      .skip((pageNum - 1) * limitNum)
      .lean();

    // Get summary statistics
    const totalEvents = await auditLogModel.countDocuments({
      action: { $regex: /^SECURITY_/ },
      createdAt: { $gte: timeRange },
    });

    // Group by event type
    const eventTypes = await auditLogModel.aggregate([
      {
        $match: {
          action: { $regex: /^SECURITY_/ },
          createdAt: { $gte: timeRange },
        },
      },
      {
        $group: {
          _id: "$action",
          count: { $sum: 1 },
          latestEvent: { $max: "$createdAt" },
        },
      },
      { $sort: { count: -1 } },
    ]);

    // Get top IPs with security events
    const topIPs = await auditLogModel.aggregate([
      {
        $match: {
          action: { $regex: /^SECURITY_/ },
          createdAt: { $gte: timeRange },
        },
      },
      {
        $group: {
          _id: "$ipAddress",
          count: { $sum: 1 },
          events: { $push: "$action" },
        },
      },
      { $sort: { count: -1 } },
      { $limit: 10 },
    ]);

    res.json({
      success: true,
      message: "Security events retrieved successfully",
      data: {
        events: securityEvents,
        pagination: {
          currentPage: pageNum,
          totalPages: Math.ceil(totalEvents / limitNum),
          totalEvents,
          hasNextPage: pageNum * limitNum < totalEvents,
          hasPrevPage: pageNum > 1,
        },
        summary: {
          timeRange: hoursNum,
          totalEvents,
          eventTypes,
          topIPs,
          riskLevel:
            totalEvents > 50 ? "HIGH" : totalEvents > 10 ? "MEDIUM" : "LOW",
        },
      },
    });
  } catch (error) {
    console.error("Get security events error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to retrieve security events",
    });
  }
};

export {
  getAuditLogs,
  getAuditStats,
  exportAuditLogs,
  getFilterOptions,
  getSecurityEvents,
};
