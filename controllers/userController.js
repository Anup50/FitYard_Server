import validator from "validator";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import userModel from "../models/userModel.js";
import adminModel from "../models/adminModel.js";
import tempUserModel from "../models/tempUserModel.js";
import sendOtpEmail from "../utils/sendOtpEmail.js";

const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
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
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      });
      res.json({ success: true, message: "Login successful!" });
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

    // Check if user already exists in main or temp collection
    const exists = await userModel.findOne({ email });
    if (exists) {
      return res.json({ success: false, message: "User already exists" });
    }
    const tempExists = await tempUserModel.findOne({ email });
    if (tempExists) {
      return res.json({
        success: false,
        message: "Please verify OTP sent to your email",
      });
    }

    // Validate email and password
    if (!validator.isEmail(email)) {
      return res.json({
        success: false,
        message: "Please enter a valid email",
      });
    }
    if (
      !validator.isStrongPassword(password, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
    ) {
      return res.json({
        success: false,
        message:
          "Password must be at least 8 characters long and include uppercase, lowercase, number, and symbol.",
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

    // Store in tempUser collection
    await tempUserModel.create({
      name,
      email,
      password: hashedPassword,
      otp,
      otpExpires,
    });

    // Send OTP via email
    try {
      await sendOtpEmail(email, otp);
    } catch (err) {
      // Clean up temp user if email fails
      await tempUserModel.deleteOne({ email });
      return res.json({
        success: false,
        message: "Failed to send OTP email. Please try again.",
      });
    }

    res.json({
      success: true,
      message:
        "OTP sent to your email. Please verify to complete registration.",
    });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};

// OTP verification and final registration
export const verifyUserOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;
    const tempUser = await tempUserModel.findOne({ email });
    if (!tempUser) {
      return res.json({
        success: false,
        message: "No registration found for this email.",
      });
    }
    if (tempUser.otp !== otp) {
      return res.json({ success: false, message: "Invalid OTP." });
    }
    if (tempUser.otpExpires < new Date()) {
      await tempUserModel.deleteOne({ email });
      return res.json({
        success: false,
        message: "OTP expired. Please register again.",
      });
    }

    // Move user to main userModel
    const { name, password } = tempUser;
    // Password already validated and hashed in tempUser
    const newUser = new userModel({ name, email, password });
    await newUser.save();
    await tempUserModel.deleteOne({ email });

    const token = createToken(newUser._id);
    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });
    res.json({ success: true, message: "Registration successful!" });
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
        { expiresIn: "1d" }
      );
      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      });
      res.json({
        success: true,
        admin: { name: admin.name, email: admin.email },
        message: "Admin login successful!",
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
        message: "Unauthorized. Only existing admins can create new admins.",
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
    if (
      !validator.isStrongPassword(password, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
    ) {
      return res.json({
        success: false,
        message:
          "Password must be at least 8 characters long and include uppercase, lowercase, number, and symbol.",
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
      message: isInitialSetup
        ? "First admin created successfully"
        : "New admin created successfully",
    });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};

// Get user profile
export const getUserProfile = async (req, res) => {
  try {
    const { userId } = req.body; // userId is set by authUser middleware

    const user = await userModel.findById(userId).select("-password"); // Exclude password
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        cartData: user.cartData,
      },
    });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};

// Update user profile
export const updateUserProfile = async (req, res) => {
  try {
    const { userId, name, email, currentPassword, newPassword } = req.body;

    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    // If changing password, verify current password
    if (newPassword) {
      if (!currentPassword) {
        return res.json({
          success: false,
          message: "Current password is required to change password",
        });
      }

      const isCurrentPasswordValid = await bcrypt.compare(
        currentPassword,
        user.password
      );
      if (!isCurrentPasswordValid) {
        return res.json({
          success: false,
          message: "Current password is incorrect",
        });
      }

      if (
        !validator.isStrongPassword(newPassword, {
          minLength: 8,
          minLowercase: 1,
          minUppercase: 1,
          minNumbers: 1,
          minSymbols: 1,
        })
      ) {
        return res.json({
          success: false,
          message:
            "New password must be at least 8 characters long and include uppercase, lowercase, number, and symbol.",
        });
      }

      // Hash new password
      const salt = await bcrypt.genSalt(10);
      const hashedNewPassword = await bcrypt.hash(newPassword, salt);
      user.password = hashedNewPassword;
    }

    // Update other fields
    if (name && name.trim() !== "") {
      user.name = name.trim();
    }

    if (email && email !== user.email) {
      // Validate email format
      if (!validator.isEmail(email)) {
        return res.json({
          success: false,
          message: "Please enter a valid email",
        });
      }

      // Check if email already exists
      const emailExists = await userModel.findOne({ email });
      if (emailExists) {
        return res.json({ success: false, message: "Email already exists" });
      }

      user.email = email;
    }

    await user.save();

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (e) {
    console.log(e);
    res.json({ success: false, message: e.message });
  }
};
