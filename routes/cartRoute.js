import express from "express";
import {
  addToCart,
  getUserCart,
  updateCart,
  getAnyUserCart,
  getAllUserCarts,
} from "../controllers/cartController.js";
import authUser from "../middleware/auth.js";
import adminAuth from "../middleware/adminAuth.js";
import { csrfProtection } from "../middleware/csrfProtection.js";

const cartRouter = express.Router();

cartRouter.get("/get", authUser, getUserCart);
// Admin: get any user's cart by userId
cartRouter.get("/user/:userId", adminAuth, getAnyUserCart);
// Admin: get all user carts
cartRouter.get("/all", adminAuth, getAllUserCarts);
cartRouter.post("/add", authUser, csrfProtection, addToCart);
cartRouter.put("/update", authUser, csrfProtection, updateCart);

export default cartRouter;
