import crypto from "crypto";

const csrfTokens = new Map();

const generateCsrfToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

export const setCsrfToken = (req, res, next) => {
  const token = generateCsrfToken();
  const sessionId = req.sessionID || req.ip + req.get("User-Agent");

  csrfTokens.set(sessionId, token);

  res.cookie("_csrf", token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 3600000, // 1 hour
  });

  res.locals.csrfToken = token;
  next();
};

export const getCsrfToken = (req, res) => {
  const token = generateCsrfToken();
  const sessionId = req.sessionID || req.ip + req.get("User-Agent");

  csrfTokens.set(sessionId, token);

  res.cookie("_csrf", token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 3600000,
  });

  res.json({
    success: true,
    csrfToken: token,
    message: "CSRF token generated successfully",
  });
};

export const csrfProtection = (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  const sessionId = req.sessionID || req.ip + req.get("User-Agent");
  const tokenFromHeader = req.get("x-csrf-token");
  const tokenFromCookie = req.cookies._csrf;
  const storedToken = csrfTokens.get(sessionId);

  const providedToken = tokenFromHeader || req.body._csrf;

  if (!providedToken || !storedToken || providedToken !== storedToken) {
    return res.status(403).json({
      success: false,
      message: "Invalid or missing CSRF token",
      error: "CSRF_TOKEN_INVALID",
    });
  }

  next();
};

export const cleanupExpiredTokens = () => {
  if (csrfTokens.size > 1000) {
    csrfTokens.clear();
  }
};

setInterval(cleanupExpiredTokens, 3600000);
