import jwt from "jsonwebtoken";
import adminModel from "../models/adminModel.js";

const adminAuth = async (req, res, next) => {
  try {
    const { token } = req.headers;

    if (!token) {
      return res.json({
        success: false,
        message: "Not Authorized. Login Again",
      });
    }

    // Verify JWT token
    const tokenDecoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if it's an admin token
    if (tokenDecoded.role !== "admin") {
      return res.json({
        success: false,
        message: "Not Authorized. Admin access required",
      });
    }

    // Find admin in database to ensure they still exist and are active
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
