import express from "express";
import {
  addProduct,
  listProduct,
  removeProduct,
  singleProduct,
} from "../controllers/productController.js";
import upload from "../middleware/multer.js";
import adminAuth from "../middleware/adminAuth.js";
import { csrfProtection } from "../middleware/csrfProtection.js";
import {
  adminRateLimit,
  generalRateLimit,
} from "../middleware/rateLimitLogger.js";

const productRouter = express.Router();

productRouter.post(
  "/add",
  adminAuth,
  adminRateLimit,
  csrfProtection,
  upload.fields([
    { name: "image1", maxCount: 1 },
    { name: "image2", maxCount: 1 },
    { name: "image3", maxCount: 1 },
    { name: "image4", maxCount: 1 },
  ]),
  addProduct
);
productRouter.get("/single/:id", generalRateLimit, singleProduct);
productRouter.delete(
  "/remove/:id",
  adminAuth,
  adminRateLimit,
  csrfProtection,
  removeProduct
);
productRouter.get("/list", generalRateLimit, listProduct);

export default productRouter;
