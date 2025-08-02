import jwt from "jsonwebtoken";
import adminModel from "../models/adminModel.js";

const adminAuth = async (req, res, next) => {
  try {
    let token = req.cookies?.token;
    if (!token && req.headers.token) {
      token = req.headers.token;
    }
    if (!token && req.headers.authorization) {
      const parts = req.headers.authorization.split(" ");
      if (parts.length === 2 && parts[0] === "Bearer") {
        token = parts[1];
      }
    }

    if (!token) {
      return res.json({
        success: false,
        message: "Not Authorized. Login Again",
      });
    }

    const tokenDecoded = jwt.verify(token, process.env.JWT_SECRET);

    if (!tokenDecoded.role || tokenDecoded.role !== "admin") {
      return res.json({
        success: false,
        message: "Not Authorized. Admin access required",
      });
    }

    const admin = await adminModel.findById(tokenDecoded.id);
    if (!admin || !admin.isActive) {
      return res.json({
        success: false,
        message: "Admin not found or deactivated",
      });
    }

    req.admin = admin;
    next();
  } catch (error) {
    console.log(error);
    res.json({ success: false, message: error.message });
  }
};

export default adminAuth;
