import express from "express";
import {
  allOrders,
  placeOrder,
  placeOrderRazorpay,
  placeOrderStripe,
  updateStatus,
  userOrders,
  verifyStripe,
} from "../controllers/orderController.js";
import adminAuth from "../middleware/adminAuth.js";
import authUser from "../middleware/auth.js";
import { csrfProtection } from "../middleware/csrfProtection.js";

const orderRouter = express.Router();

orderRouter.get("/list", adminAuth, allOrders);
orderRouter.put("/status", adminAuth, csrfProtection, updateStatus);

orderRouter.post("/place", authUser, csrfProtection, placeOrder);
orderRouter.post("/stripe", authUser, csrfProtection, placeOrderStripe);
orderRouter.post("/razorpay", authUser, csrfProtection, placeOrderRazorpay);

orderRouter.get("/userorders", authUser, userOrders);

orderRouter.post("/verifystripe", authUser, csrfProtection, verifyStripe);

export default orderRouter;
