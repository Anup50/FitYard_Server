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

const orderRouter = express.Router();

//ADMIN FEATURE
orderRouter.get("/list", adminAuth, allOrders);
orderRouter.put("/status", adminAuth, updateStatus);

//PAYMENT FEATURE
orderRouter.post("/place", authUser, placeOrder);
orderRouter.post("/stripe", authUser, placeOrderStripe);
orderRouter.post("/razorpay", authUser, placeOrderRazorpay);

//USER FEATURE
orderRouter.get("/userorders", authUser, userOrders);

//VERIFY PAYMENT
orderRouter.post("/verifystripe", authUser, verifyStripe);

export default orderRouter;
