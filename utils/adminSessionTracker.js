import { logActivity, logError } from "./logger.js";

const adminSessions = new Map();
const suspiciousActivityAlerts = new Map();

const SUSPICIOUS_ACTIVITY_CONFIG = {
  MAX_FAILED_LOGINS: 3,
  MAX_SESSIONS_PER_ADMIN: 3,
  UNUSUAL_HOUR_START: 23,
  UNUSUAL_HOUR_END: 6,
  MAX_ACTIONS_PER_MINUTE: 20,
  LOCATION_CHANGE_THRESHOLD: 100,
  SESSION_TIMEOUT: 30 * 60 * 1000,
};

const adminSessionTracker = {
  trackLogin: (adminId, ip, userAgent, loginSuccess = true) => {
    const now = new Date();
    const sessionKey = `${adminId}-${ip}`;

    if (!adminSessions.has(adminId)) {
      adminSessions.set(adminId, {
        sessions: [],
        failedAttempts: [],
        actionHistory: [],
        lastKnownLocations: [],
        suspiciousFlags: [],
      });
    }

    const adminData = adminSessions.get(adminId);

    if (loginSuccess) {
      const newSession = {
        sessionId: `session_${Date.now()}_${Math.random()
          .toString(36)
          .substr(2, 9)}`,
        ip,
        userAgent,
        loginTime: now,
        lastActivity: now,
        isActive: true,
      };

      adminData.sessions.push(newSession);

      adminData.sessions = adminData.sessions.filter(
        (session) =>
          now - session.loginTime <
            SUSPICIOUS_ACTIVITY_CONFIG.SESSION_TIMEOUT || session.isActive
      );

      adminSessionTracker.detectSuspiciousActivity(adminId);

      logActivity("ADMIN_LOGIN_SUCCESS", "Admin logged in successfully", {
        adminId,
        ip,
        userAgent,
        sessionId: newSession.sessionId,
        activeSessionCount: adminData.sessions.filter((s) => s.isActive).length,
      });
    } else {
      adminData.failedAttempts.push({
        ip,
        userAgent,
        timestamp: now,
        reason: "Invalid credentials",
      });

      const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
      adminData.failedAttempts = adminData.failedAttempts.filter(
        (attempt) => attempt.timestamp > oneHourAgo
      );

      adminSessionTracker.detectBruteForce(adminId);

      logActivity("ADMIN_LOGIN_FAILED", "Admin login failed", {
        adminId,
        ip,
        userAgent,
        failedAttemptCount: adminData.failedAttempts.length,
      });
    }
  },

  trackAction: (adminId, action, ip, details = {}) => {
    const now = new Date();

    if (!adminSessions.has(adminId)) {
      return;
    }

    const adminData = adminSessions.get(adminId);

    adminData.actionHistory.push({
      action,
      ip,
      timestamp: now,
      details,
    });

    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    adminData.actionHistory = adminData.actionHistory.filter(
      (actionRecord) => actionRecord.timestamp > oneHourAgo
    );

    adminData.sessions.forEach((session) => {
      if (session.ip === ip && session.isActive) {
        session.lastActivity = now;
      }
    });

    adminSessionTracker.detectSuspiciousActivity(adminId);

    logActivity("ADMIN_ACTION_TRACKED", `Admin performed action: ${action}`, {
      adminId,
      action,
      ip,
      details,
      recentActionCount: adminData.actionHistory.length,
    });
  },

  detectSuspiciousActivity: (adminId) => {
    if (!adminSessions.has(adminId)) {
      return [];
    }

    const adminData = adminSessions.get(adminId);
    const suspiciousIndicators = [];
    const now = new Date();

    const activeSessions = adminData.sessions.filter((s) => s.isActive);
    const uniqueIPs = new Set(activeSessions.map((s) => s.ip));

    if (uniqueIPs.size > SUSPICIOUS_ACTIVITY_CONFIG.MAX_SESSIONS_PER_ADMIN) {
      suspiciousIndicators.push({
        type: "MULTIPLE_CONCURRENT_SESSIONS",
        severity: "HIGH",
        details: `${uniqueIPs.size} concurrent sessions from different IPs`,
        ips: Array.from(uniqueIPs),
        timestamp: now,
      });
    }

    const recentLogins = adminData.sessions.filter(
      (session) => now - session.loginTime < 60 * 60 * 1000
    );

    recentLogins.forEach((session) => {
      const loginHour = session.loginTime.getHours();
      if (
        loginHour >= SUSPICIOUS_ACTIVITY_CONFIG.UNUSUAL_HOUR_START ||
        loginHour <= SUSPICIOUS_ACTIVITY_CONFIG.UNUSUAL_HOUR_END
      ) {
        suspiciousIndicators.push({
          type: "UNUSUAL_LOGIN_HOUR",
          severity: "MEDIUM",
          details: `Login at ${loginHour}:${session.loginTime.getMinutes()}`,
          timestamp: session.loginTime,
          ip: session.ip,
        });
      }
    });

    const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
    const recentActions = adminData.actionHistory.filter(
      (action) => action.timestamp > oneMinuteAgo
    );

    if (
      recentActions.length > SUSPICIOUS_ACTIVITY_CONFIG.MAX_ACTIONS_PER_MINUTE
    ) {
      suspiciousIndicators.push({
        type: "RAPID_ACTIONS",
        severity: "HIGH",
        details: `${recentActions.length} actions in the last minute`,
        actions: recentActions.map((a) => a.action),
        timestamp: now,
      });
    }

    const recentUserAgents = new Set(activeSessions.map((s) => s.userAgent));

    if (recentUserAgents.size > 2) {
      suspiciousIndicators.push({
        type: "USER_AGENT_SWITCHING",
        severity: "HIGH",
        details: `Multiple user agents detected in active sessions`,
        userAgents: Array.from(recentUserAgents),
        timestamp: now,
      });
    }

    const sensitiveActions = adminData.actionHistory.filter((action) =>
      ["DELETE_PRODUCT", "UPDATE_ORDER_STATUS", "CREATE_ADMIN"].includes(
        action.action
      )
    );

    const recentSensitiveActions = sensitiveActions.filter(
      (action) => now - action.timestamp < 10 * 60 * 1000
    );

    if (recentSensitiveActions.length > 5) {
      suspiciousIndicators.push({
        type: "EXCESSIVE_SENSITIVE_ACTIONS",
        severity: "HIGH",
        details: `${recentSensitiveActions.length} sensitive actions in 10 minutes`,
        actions: recentSensitiveActions,
        timestamp: now,
      });
    }

    adminSessionTracker.detectGeographicAnomalies(
      adminId,
      adminData,
      suspiciousIndicators
    );

    if (suspiciousIndicators.length > 0) {
      adminData.suspiciousFlags.push(...suspiciousIndicators);

      const highSeverityAlerts = suspiciousIndicators.filter(
        (indicator) => indicator.severity === "HIGH"
      );

      if (highSeverityAlerts.length > 0) {
        adminSessionTracker.triggerSecurityAlert(adminId, highSeverityAlerts);
      }

      logActivity(
        "SUSPICIOUS_ACTIVITY_DETECTED",
        "Suspicious admin activity detected",
        {
          adminId,
          indicators: suspiciousIndicators,
          totalSuspiciousFlags: adminData.suspiciousFlags.length,
        }
      );
    }

    return suspiciousIndicators;
  },

  detectBruteForce: (adminId) => {
    if (!adminSessions.has(adminId)) {
      return false;
    }

    const adminData = adminSessions.get(adminId);
    const recentFailures = adminData.failedAttempts.filter(
      (attempt) => new Date() - attempt.timestamp < 15 * 60 * 1000
    );

    if (recentFailures.length >= SUSPICIOUS_ACTIVITY_CONFIG.MAX_FAILED_LOGINS) {
      const alert = {
        type: "BRUTE_FORCE_ATTEMPT",
        severity: "CRITICAL",
        details: `${recentFailures.length} failed login attempts in 15 minutes`,
        attempts: recentFailures,
        timestamp: new Date(),
      };

      adminSessionTracker.triggerSecurityAlert(adminId, [alert]);

      logError(
        "BRUTE_FORCE_DETECTED",
        "Brute force attack detected on admin account",
        {
          adminId,
          failedAttempts: recentFailures.length,
          ips: recentFailures.map((f) => f.ip),
        }
      );

      return true;
    }

    return false;
  },

  detectGeographicAnomalies: (adminId, adminData, suspiciousIndicators) => {
    const activeSessions = adminData.sessions.filter((s) => s.isActive);

    const getIPLocation = (ip) => {
      const ipParts = ip.split(".");
      return {
        country: ipParts[0] < 128 ? "US" : "International",
        city: "Unknown",
        coordinates: { lat: 0, lng: 0 },
      };
    };

    const sessionLocations = activeSessions.map((session) => ({
      ...session,
      location: getIPLocation(session.ip),
    }));

    const countries = new Set(sessionLocations.map((s) => s.location.country));
    if (countries.size > 1) {
      suspiciousIndicators.push({
        type: "GEOGRAPHIC_ANOMALY",
        severity: "HIGH",
        details: `Active sessions from multiple countries: ${Array.from(
          countries
        ).join(", ")}`,
        locations: sessionLocations,
        timestamp: new Date(),
      });
    }
  },

  triggerSecurityAlert: (adminId, alerts) => {
    const alertKey = `${adminId}-${Date.now()}`;

    suspiciousActivityAlerts.set(alertKey, {
      adminId,
      alerts,
      timestamp: new Date(),
      status: "ACTIVE",
    });

    console.log(`🚨 SECURITY ALERT for Admin ${adminId}:`);
    alerts.forEach((alert) => {
      console.log(`   - ${alert.type}: ${alert.details}`);
    });

    logError(
      "SECURITY_ALERT_TRIGGERED",
      "High-priority security alert triggered",
      {
        adminId,
        alertCount: alerts.length,
        alertTypes: alerts.map((a) => a.type),
        severity: Math.max(
          ...alerts.map((a) =>
            a.severity === "CRITICAL" ? 3 : a.severity === "HIGH" ? 2 : 1
          )
        ),
      }
    );

    const criticalAlerts = alerts.filter((a) => a.severity === "CRITICAL");
    if (criticalAlerts.length > 0) {
      adminSessionTracker.handleCriticalAlert(adminId, criticalAlerts);
    }
  },

  handleCriticalAlert: (adminId, criticalAlerts) => {
    console.log(
      `🔴 CRITICAL ALERT: Taking automatic security actions for Admin ${adminId}`
    );

    const adminData = adminSessions.get(adminId);
    if (adminData) {
      adminData.sessions.forEach((session) => {
        session.isActive = false;
        session.terminatedReason = "SECURITY_INCIDENT";
        session.terminatedAt = new Date();
      });

      logActivity(
        "SECURITY_AUTO_RESPONSE",
        "Automatic security response triggered",
        {
          adminId,
          action: "FORCE_LOGOUT_ALL_SESSIONS",
          criticalAlerts: criticalAlerts.map((a) => a.type),
        }
      );
    }
  },

  getAdminSessionSummary: (adminId) => {
    if (!adminSessions.has(adminId)) {
      return null;
    }

    const adminData = adminSessions.get(adminId);
    const now = new Date();

    return {
      adminId,
      activeSessions: adminData.sessions.filter((s) => s.isActive).length,
      totalSessions: adminData.sessions.length,
      recentFailedAttempts: adminData.failedAttempts.filter(
        (attempt) => now - attempt.timestamp < 60 * 60 * 1000
      ).length,
      recentActions: adminData.actionHistory.filter(
        (action) => now - action.timestamp < 60 * 60 * 1000
      ).length,
      suspiciousFlagsCount: adminData.suspiciousFlags.length,
      lastActivity: Math.max(
        ...adminData.sessions.map((s) => s.lastActivity.getTime())
      ),
      riskLevel: adminSessionTracker.calculateRiskLevel(adminData),
    };
  },

  calculateRiskLevel: (adminData) => {
    const now = new Date();
    const recentFlags = adminData.suspiciousFlags.filter(
      (flag) => now - flag.timestamp < 24 * 60 * 60 * 1000
    );

    const criticalCount = recentFlags.filter(
      (f) => f.severity === "CRITICAL"
    ).length;
    const highCount = recentFlags.filter((f) => f.severity === "HIGH").length;
    const mediumCount = recentFlags.filter(
      (f) => f.severity === "MEDIUM"
    ).length;

    const riskScore = criticalCount * 10 + highCount * 5 + mediumCount * 2;

    if (riskScore >= 20) return "CRITICAL";
    if (riskScore >= 10) return "HIGH";
    if (riskScore >= 5) return "MEDIUM";
    return "LOW";
  },

  cleanup: () => {
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    adminSessions.forEach((adminData, adminId) => {
      adminData.sessions = adminData.sessions.filter(
        (session) => session.loginTime > oneDayAgo
      );

      adminData.failedAttempts = adminData.failedAttempts.filter(
        (attempt) => attempt.timestamp > oneDayAgo
      );

      adminData.actionHistory = adminData.actionHistory.filter(
        (action) => action.timestamp > oneDayAgo
      );

      adminData.suspiciousFlags = adminData.suspiciousFlags.filter(
        (flag) => flag.timestamp > oneDayAgo
      );

      if (
        adminData.sessions.length === 0 &&
        adminData.failedAttempts.length === 0 &&
        adminData.actionHistory.length === 0
      ) {
        adminSessions.delete(adminId);
      }
    });

    suspiciousActivityAlerts.forEach((alert, alertKey) => {
      if (alert.timestamp < oneDayAgo) {
        suspiciousActivityAlerts.delete(alertKey);
      }
    });
  },
};

setInterval(() => {
  adminSessionTracker.cleanup();
}, 60 * 60 * 1000);

export default adminSessionTracker;
