import express from "express";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import cors from "cors";
import "dotenv/config";
import connectDB from "./config/mongodb.js";
import connectCloudinary from "./config/cloudinary.js";
import { getCsrfToken, csrfProtection } from "./middleware/csrfProtection.js";
import { auditMiddleware } from "./middleware/auditLogger.js";
import userRouter from "./routes/userRoutes.js";
import productRouter from "./routes/productRoute.js";
import cartRouter from "./routes/cartRoute.js";
import orderRouter from "./routes/orderRoute.js";
import auditRouter from "./routes/auditRoute.js";
import https from "https";
import fs from "fs";

//App Config
const app = express();
const port = process.env.PORT || 4000;
connectDB();
connectCloudinary();

//Security Middlewares
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https://res.cloudinary.com"],
        scriptSrc: ["'self'"],
        connectSrc: [
          "'self'",
          "https://localhost:4000",
          "https://localhost:3000",
        ],
      },
    },
    crossOriginEmbedderPolicy: false, // Needed for some frontend frameworks
  })
);

//Middlewares
app.use(express.json());
app.use(cookieParser());

// Audit logging middleware - logs all requests for security monitoring
app.use(auditMiddleware());

app.use(
  cors({
    origin: [
      "https://localhost:3000",
      "http://localhost:3000",
      "https://localhost:5173",
      "http://localhost:5173",
      "https://localhost:5174",
      "http://localhost:5174",
    ],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "token", "x-csrf-token"],
    optionsSuccessStatus: 200,
  })
);

// CSRF Protection - Apply to state-changing routes only
// Note: CSRF protection will be applied selectively to routes that need it

// CSRF token endpoint
app.get("/api/csrf-token", getCsrfToken);

//API endpoints
app.use("/api/user", userRouter);
app.use("/api/product", productRouter);
app.use("/api/cart", cartRouter);
app.use("/api/order", orderRouter);
app.use("/api/audit", auditRouter); // Admin-only audit log management

app.get("/", (req, res) => {
  res.send("API WORKING");
});

const sslOptions = {
  key: fs.readFileSync(".cert/key.pem"),
  cert: fs.readFileSync(".cert/cert.pem"),
};

https.createServer(sslOptions, app).listen(port, () => {
  console.log(`HTTPS server started on https://localhost:${port} ❤️`);
});
