import express from "express";
import {
  adminLogin,
  loginUser,
  registerUser,
  registerAdmin,
  verifyUserOtp,
  verifyLoginOtp,
  resendRegistrationOtp,
  resendLoginOtp,
  getUserProfile,
  updateUserProfile,
  logoutUser,
  logoutAdmin,
  getAdminSecurityStatus,
  updatePassword,
  forgotPassword,
  resetPassword,
  getPasswordStatus,
  forcePasswordChange,
  checkPasswordExpiry,
} from "../controllers/userController.js";
import { loginRateLimiter } from "../middleware/loginRateLimiter.js";
import {
  loginRateLimit,
  registrationRateLimit,
  passwordResetRateLimit,
  generalRateLimit,
} from "../middleware/rateLimitLogger.js";
import { csrfProtection } from "../middleware/csrfProtection.js";
import adminAuth from "../middleware/adminAuth.js";
import authUser from "../middleware/auth.js";

const userRouter = express.Router();

userRouter.post(
  "/register",
  registrationRateLimit,
  csrfProtection,
  registerUser
);
userRouter.post("/verify-otp", loginRateLimit, csrfProtection, verifyUserOtp);
userRouter.post(
  "/resend-registration-otp",
  passwordResetRateLimit,
  csrfProtection,
  resendRegistrationOtp
);
userRouter.post("/login", loginRateLimit, csrfProtection, loginUser);
userRouter.post(
  "/verify-login-otp",
  loginRateLimit,
  csrfProtection,
  verifyLoginOtp
);
userRouter.post(
  "/resend-login-otp",
  passwordResetRateLimit,
  csrfProtection,
  resendLoginOtp
);
userRouter.get("/profile", authUser, generalRateLimit, getUserProfile);
userRouter.put(
  "/profile",
  authUser,
  generalRateLimit,
  csrfProtection,
  updateUserProfile
);
userRouter.post("/logout", generalRateLimit, csrfProtection, logoutUser);
userRouter.post("/admin", loginRateLimit, csrfProtection, adminLogin);
userRouter.post("/admin/logout", generalRateLimit, csrfProtection, logoutAdmin);
userRouter.get(
  "/admin/security-status",
  adminAuth,
  generalRateLimit,
  getAdminSecurityStatus
);
userRouter.post(
  "/admin/register",
  registrationRateLimit,
  csrfProtection,
  registerAdmin
);

// Password management routes
userRouter.post(
  "/update-password",
  authUser,
  generalRateLimit,
  csrfProtection,
  updatePassword
);
userRouter.post("/forgot-password", passwordResetRateLimit, forgotPassword);
userRouter.post("/reset-password", passwordResetRateLimit, resetPassword);
userRouter.get(
  "/password-status",
  authUser,
  generalRateLimit,
  getPasswordStatus
);

// Admin only - force password change
userRouter.post(
  "/admin/force-password-change",
  adminAuth,
  generalRateLimit,
  csrfProtection,
  forcePasswordChange
);

export default userRouter;
