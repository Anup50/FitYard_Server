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
} from "../controllers/userController.js";
import { loginRateLimiter } from "../middleware/loginRateLimiter.js";
import adminAuth from "../middleware/adminAuth.js";
import authUser from "../middleware/auth.js";

const userRouter = express.Router();

userRouter.post("/register", registerUser);
userRouter.post("/verify-otp", verifyUserOtp);
userRouter.post(
  "/resend-registration-otp",
  loginRateLimiter,
  resendRegistrationOtp
);
userRouter.post("/login", loginRateLimiter, loginUser);
userRouter.post("/verify-login-otp", loginRateLimiter, verifyLoginOtp);
userRouter.post("/resend-login-otp", loginRateLimiter, resendLoginOtp);
userRouter.get("/profile", authUser, getUserProfile);
userRouter.put("/profile", authUser, updateUserProfile);
userRouter.post("/admin", adminLogin);
userRouter.post("/admin/register", registerAdmin); // No middleware - controller handles auth logic

export default userRouter;
