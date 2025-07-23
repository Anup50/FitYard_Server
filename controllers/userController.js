import validator from "validator";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import userModel from "../models/userModel.js";
import adminModel from "../models/adminModel.js";

const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET);
};
//Route for user login
export const loginUser = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User does not exists" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      const token = createToken(user._id);
      res.json({ success: true, token });
    } else {
      return res.json({ success: false, message: "Invalid Credentials" });
    }
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};

//Route for user register
export const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // checking user already exist or not
    const exists = await userModel.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }

    //validating email formate and strong password
    if (!validator.isEmail(email)) {
      return res.json({
        success: false,
        message: "Please enter a valid email",
      });
    }

    if (password.length < 8) {
      return res.json({
        success: false,
        message: "Please enter a strong password",
      });
    }

    //hashing user password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new userModel({ name, email, password: hashedPassword });

    const user = await newUser.save();

    const token = createToken(user._id);

    res.json({ success: true, token });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};

//Route for Admin login
export const adminLogin = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find admin in database
    const admin = await adminModel.findOne({ email });
    if (!admin) {
      return res.json({ success: false, message: "Admin not found" });
    }

    // Check if admin is active
    if (!admin.isActive) {
      return res.json({
        success: false,
        message: "Admin account is deactivated",
      });
    }

    // Compare password with hashed password
    const isMatch = await bcrypt.compare(password, admin.password);

    if (isMatch) {
      // Update last login
      admin.lastLogin = new Date();
      await admin.save();

      // Create JWT token with admin ID and role
      const token = jwt.sign(
        { id: admin._id, email: admin.email, role: admin.role },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
      );

      res.json({
        success: true,
        token,
        admin: { name: admin.name, email: admin.email },
      });
    } else {
      res.json({ success: false, message: "Invalid credentials" });
    }
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};

//Route for Admin registration (protected - only for initial setup or by existing admin)
export const registerAdmin = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if this is initial setup (no admins exist) or if called by existing admin
    const adminCount = await adminModel.countDocuments();
    const isInitialSetup = adminCount === 0;
    
    // If not initial setup, must be called by authenticated admin
    if (!isInitialSetup && !req.admin) {
      return res.json({ 
        success: false, 
        message: "Unauthorized. Only existing admins can create new admins." 
      });
    }

    // Check if admin already exists
    const existingAdmin = await adminModel.findOne({ email });
    if (existingAdmin) {
      return res.json({ success: false, message: "Admin already exists" });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return res.json({
        success: false,
        message: "Please enter a valid email",
      });
    }

    // Validate password strength
    if (password.length < 8) {
      return res.json({
        success: false,
        message: "Password must be at least 8 characters long",
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new admin
    const newAdmin = new adminModel({
      name,
      email,
      password: hashedPassword,
    });

    const admin = await newAdmin.save();

    // Create JWT token
    const token = jwt.sign(
      { id: admin._id, email: admin.email, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({
      success: true,
      token,
      admin: { name: admin.name, email: admin.email },
      message: isInitialSetup ? "First admin created successfully" : "New admin created successfully"
    });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};
