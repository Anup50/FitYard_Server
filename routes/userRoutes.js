import express from "express";
import {
  adminLogin,
  loginUser,
  registerUser,
  registerAdmin,
  verifyUserOtp,
  getUserProfile,
  updateUserProfile,
} from "../controllers/userController.js";
import adminAuth from "../middleware/adminAuth.js";
import authUser from "../middleware/auth.js";

const userRouter = express.Router();

userRouter.post("/register", registerUser);
userRouter.post("/verify-otp", verifyUserOtp);
userRouter.post("/login", loginUser);
userRouter.get("/profile", authUser, getUserProfile);
userRouter.put("/profile", authUser, updateUserProfile);
userRouter.post("/admin", adminLogin);
userRouter.post("/admin/register", registerAdmin); // No middleware - controller handles auth logic

export default userRouter;
