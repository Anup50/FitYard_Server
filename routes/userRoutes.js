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
} from "../controllers/userController.js";
import { loginRateLimiter } from "../middleware/loginRateLimiter.js";
import { csrfProtection } from "../middleware/csrfProtection.js";
import adminAuth from "../middleware/adminAuth.js";
import authUser from "../middleware/auth.js";

const userRouter = express.Router();

userRouter.post("/register", csrfProtection, registerUser);
userRouter.post("/verify-otp", csrfProtection, verifyUserOtp);
userRouter.post(
  "/resend-registration-otp",
  loginRateLimiter,
  csrfProtection,
  resendRegistrationOtp
);
userRouter.post("/login", loginRateLimiter, csrfProtection, loginUser);
userRouter.post(
  "/verify-login-otp",
  loginRateLimiter,
  csrfProtection,
  verifyLoginOtp
);
userRouter.post(
  "/resend-login-otp",
  loginRateLimiter,
  csrfProtection,
  resendLoginOtp
);
userRouter.get("/profile", authUser, getUserProfile);
userRouter.put("/profile", authUser, csrfProtection, updateUserProfile);
userRouter.post("/logout", csrfProtection, logoutUser);
userRouter.post("/admin", csrfProtection, adminLogin);
userRouter.post("/admin/logout", csrfProtection, logoutAdmin);
userRouter.get("/admin/security-status", adminAuth, getAdminSecurityStatus);
userRouter.post("/admin/register", csrfProtection, registerAdmin); // No middleware - controller handles auth logic

export default userRouter;
