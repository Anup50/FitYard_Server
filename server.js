import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import cors from "cors";
import "dotenv/config";
import connectDB from "./config/mongodb.js";
import connectCloudinary from "./config/cloudinary.js";
import { getCsrfToken, csrfProtection } from "./middleware/csrfProtection.js";
import { auditMiddleware } from "./middleware/auditLogger.js";
import { mongoSanitizer, securityHeaders } from "./middleware/security.js";
import userRouter from "./routes/userRoutes.js";
import productRouter from "./routes/productRoute.js";
import cartRouter from "./routes/cartRoute.js";
import orderRouter from "./routes/orderRoute.js";
import auditRouter from "./routes/auditRoute.js";
import https from "https";
import fs from "fs";

const app = express();

connectDB();
connectCloudinary();
app.use(securityHeaders);

app.use(mongoSanitizer);
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());

app.use(auditMiddleware());

app.use(
  cors({
    origin: ["https://localhost:3000"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "token", "x-csrf-token"],
    optionsSuccessStatus: 200,
  })
);

app.get("/api/csrf-token", getCsrfToken);
app.use("/api/user", userRouter);
app.use("/api/product", productRouter);
app.use("/api/cart", cartRouter);
app.use("/api/order", orderRouter);
app.use("/api/audit", auditRouter); // Admin-only audit log management

app.get("/", (req, res) => {
  res.send("API WORKING");
});
const port = process.env.PORT || 4000;

const sslOptions = {
  key: fs.readFileSync(".cert/key.pem"),
  cert: fs.readFileSync(".cert/cert.pem"),
};
https.createServer(sslOptions, app).listen(port, () => {
  console.log(`HTTPS server started on https://localhost:${port}`);
});
