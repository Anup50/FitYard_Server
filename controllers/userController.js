import validator from "validator";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import axios from "axios";

import userModel from "../models/userModel.js";
import adminModel from "../models/adminModel.js";
import tempUserModel from "../models/tempUserModel.js";
import tempLoginModel from "../models/tempLoginModel.js";
import sendOtpEmail from "../utils/sendOtpEmail.js";
import { logActivity, logError } from "../utils/logger.js";

const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};
//Route for user login
export const loginUser = async (req, res) => {
  try {
    const { email, password, captcha } = req.body;

    // Verify reCAPTCHA
    if (!captcha) {
      return res.json({ success: false, message: "Captcha is required." });
    }
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captcha}`;
    const captchaRes = await axios.post(verifyUrl);
    if (!captchaRes.data.success) {
      return res.json({
        success: false,
        message: "Captcha verification failed.",
      });
    }

    const user = await userModel.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User does not exists" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      // Generate OTP for login verification
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

      // Remove any existing temp login for this user
      await tempLoginModel.deleteOne({ userId: user._id });

      // Store OTP in tempLogin collection
      await tempLoginModel.create({
        userId: user._id,
        email: user.email,
        otp,
        otpExpires,
      });

      // Send OTP via email
      try {
        await sendOtpEmail(email, otp);

        // Log OTP sent for login
        logActivity(
          user._id,
          "LOGIN_OTP_SENT",
          `Login OTP sent to ${user.email}`,
          req.ip,
          req.get("User-Agent")
        );

        res.json({
          success: true,
          requiresOtp: true,
          message: "OTP sent to your email. Please verify to complete login.",
        });
      } catch (err) {
        // Clean up temp login if email fails
        await tempLoginModel.deleteOne({ userId: user._id });
        logError("LOGIN_OTP_EMAIL_ERROR", err.message, { email, ip: req.ip });
        return res.json({
          success: false,
          message: "Failed to send OTP email. Please try again.",
        });
      }
    } else {
      // Log failed login attempt
      logActivity(
        null,
        "LOGIN_FAILED",
        `Failed login attempt for email: ${email}`,
        req.ip,
        req.get("User-Agent")
      );
      return res.json({ success: false, message: "Invalid Credentials" });
    }
  } catch (e) {
    console.log(e);
    logError("LOGIN_ERROR", e.message, { email: req.body.email, ip: req.ip });
    res.json({ success: false, message: e.message });
  }
};

// Login OTP verification
export const verifyLoginOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    // Find temp login record
    const tempLogin = await tempLoginModel.findOne({ email });
    if (!tempLogin) {
      return res.json({
        success: false,
        message: "No pending login verification found. Please login again.",
      });
    }

    // Check if OTP matches
    if (tempLogin.otp !== otp) {
      logActivity(
        tempLogin.userId,
        "LOGIN_OTP_FAILED",
        `Invalid OTP entered for login: ${email}`,
        req.ip,
        req.get("User-Agent")
      );
      return res.json({ success: false, message: "Invalid OTP" });
    }

    // Check if OTP has expired
    if (tempLogin.otpExpires < new Date()) {
      await tempLoginModel.deleteOne({ email });
      return res.json({
        success: false,
        message: "OTP expired. Please login again.",
      });
    }

    // OTP is valid, complete the login
    const user = await userModel.findById(tempLogin.userId).select("-password");
    const token = createToken(user._id);

    res.cookie("token", token, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    // Clean up temp login record
    await tempLoginModel.deleteOne({ email });

    // Log successful login
    logActivity(
      user._id,
      "USER_LOGIN",
      `User ${user.email} logged in successfully after OTP verification`,
      req.ip,
      req.get("User-Agent")
    );

    res.json({ success: true, user, message: "Login successful!" });
  } catch (e) {
    console.log(e);
    logError("LOGIN_OTP_VERIFICATION_ERROR", e.message, {
      email: req.body.email,
      ip: req.ip,
    });
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

    // Log registration attempt
    logActivity(
      null,
      "REGISTRATION_ATTEMPT",
      `Registration OTP sent to ${email}`,
      req.ip,
      req.get("User-Agent")
    );
  } catch (e) {
    console.log(e);
    logError("REGISTRATION_ERROR", e.message, {
      email: req.body.email,
      ip: req.ip,
    });
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

    // Log successful registration
    logActivity(
      newUser._id,
      "USER_REGISTRATION",
      `User ${email} registered successfully`,
      req.ip,
      req.get("User-Agent")
    );
  } catch (e) {
    console.log(e);
    logError("OTP_VERIFICATION_ERROR", e.message, {
      email: req.body.email,
      ip: req.ip,
    });
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
      // Fetch admin object without password
      const adminData = await adminModel
        .findById(admin._id)
        .select("-password");
      res.json({
        success: true,
        user: adminData,
        message: "Admin login successful!",
      });

      // Log successful admin login
      logActivity(
        admin._id,
        "ADMIN_LOGIN",
        `Admin ${admin.email} logged in successfully`,
        req.ip,
        req.get("User-Agent")
      );
    } else {
      // Log failed admin login attempt
      logActivity(
        null,
        "ADMIN_LOGIN_FAILED",
        `Failed admin login attempt for email: ${email}`,
        req.ip,
        req.get("User-Agent")
      );
      res.json({ success: false, message: "Invalid credentials" });
    }
  } catch (e) {
    console.log(e);
    logError("ADMIN_LOGIN_ERROR", e.message, {
      email: req.body.email,
      ip: req.ip,
    });
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
    const { userId, role } = req.body; // userId and role set by authUser middleware

    let user;
    if (role === "admin") {
      user = await adminModel.findById(userId).select("-password");
    } else {
      user = await userModel.findById(userId).select("-password");
    }

    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    res.json({
      success: true,
      user,
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

// Resend OTP for registration
export const resendRegistrationOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ success: false, message: "Email is required" });
    }

    // Check if there's a pending registration
    const tempUser = await tempUserModel.findOne({ email });
    if (!tempUser) {
      return res.json({
        success: false,
        message:
          "No pending registration found for this email. Please register again.",
      });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

    // Update the existing temp user with new OTP
    tempUser.otp = otp;
    tempUser.otpExpires = otpExpires;
    await tempUser.save();

    // Send new OTP via email
    try {
      await sendOtpEmail(email, otp);

      logActivity(
        null,
        "REGISTRATION_OTP_RESENT",
        `Registration OTP resent to ${email}`,
        req.ip,
        req.get("User-Agent")
      );

      res.json({
        success: true,
        message:
          "New OTP sent to your email. Please verify to complete registration.",
      });
    } catch (err) {
      logError("REGISTRATION_OTP_RESEND_EMAIL_ERROR", err.message, {
        email,
        ip: req.ip,
      });
      return res.json({
        success: false,
        message: "Failed to send OTP email. Please try again.",
      });
    }
  } catch (e) {
    console.log(e);
    logError("REGISTRATION_OTP_RESEND_ERROR", e.message, {
      email: req.body.email,
      ip: req.ip,
    });
    res.json({ success: false, message: e.message });
  }
};

// Resend OTP for login
export const resendLoginOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ success: false, message: "Email is required" });
    }

    // Check if there's a pending login
    const tempLogin = await tempLoginModel.findOne({ email });
    if (!tempLogin) {
      return res.json({
        success: false,
        message: "No pending login verification found. Please login again.",
      });
    }

    // Generate new OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

    // Update the existing temp login with new OTP
    tempLogin.otp = otp;
    tempLogin.otpExpires = otpExpires;
    await tempLogin.save();

    // Send new OTP via email
    try {
      await sendOtpEmail(email, otp);

      logActivity(
        tempLogin.userId,
        "LOGIN_OTP_RESENT",
        `Login OTP resent to ${email}`,
        req.ip,
        req.get("User-Agent")
      );

      res.json({
        success: true,
        message: "New OTP sent to your email. Please verify to complete login.",
      });
    } catch (err) {
      logError("LOGIN_OTP_RESEND_EMAIL_ERROR", err.message, {
        email,
        ip: req.ip,
      });
      return res.json({
        success: false,
        message: "Failed to send OTP email. Please try again.",
      });
    }
  } catch (e) {
    console.log(e);
    logError("LOGIN_OTP_RESEND_ERROR", e.message, {
      email: req.body.email,
      ip: req.ip,
    });
    res.json({ success: false, message: e.message });
  }
};
