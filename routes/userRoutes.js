import express from "express";
import {
  adminLogin,
  loginUser,
  registerUser,
  registerAdmin,
} from "../controllers/userController.js";
import adminAuth from "../middleware/adminAuth.js";

const userRouter = express.Router();

userRouter.post("/register", registerUser);
userRouter.post("/login", loginUser);
userRouter.post("/admin", adminLogin);
userRouter.post("/admin/register", adminAuth, registerAdmin); // Protected by adminAuth

export default userRouter;
