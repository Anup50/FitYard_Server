import validator from "validator";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import axios from "axios";
import crypto from "crypto";

import userModel from "../models/userModel.js";
import adminModel from "../models/adminModel.js";
import tempUserModel from "../models/tempUserModel.js";
import tempLoginModel from "../models/tempLoginModel.js";
import sendOtpEmail from "../utils/sendOtpEmail.js";
import { logActivity, logError } from "../utils/logger.js";
import { createAuditLog, logUserAction } from "../middleware/auditLogger.js";
import adminSessionTracker from "../utils/adminSessionTracker.js";
import {
  validateAndSanitizeInput,
  logSecurityEvent,
} from "../middleware/security.js";
import {
  generateResetToken,
  generateResetOTP,
  sendPasswordResetEmail,
  validatePasswordStrength,
} from "../utils/passwordReset.js";

const createToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

//Route for user login
export const loginUser = async (req, res) => {
  try {
    const { email, password, captcha } = req.body;

    // Validate and sanitize inputs
    let sanitizedEmail, sanitizedPassword;

    try {
      sanitizedEmail = validateAndSanitizeInput(email, "email");
      sanitizedPassword = validateAndSanitizeInput(password, "password");
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_LOGIN_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    // Verify reCAPTCHA
    if (!captcha) {
      return res
        .status(400)
        .json({ success: false, message: "Captcha is required." });
    }
    const verifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${captcha}`;
    const captchaRes = await axios.post(verifyUrl);
    if (!captchaRes.data.success) {
      return res.status(400).json({
        success: false,
        message: "Captcha verification failed.",
      });
    }

    const user = await userModel.findOne({ email: sanitizedEmail });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User does not exists" });
    }

    const isMatch = await bcrypt.compare(sanitizedPassword, user.password);

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

    // Check if password is expired or must be changed
    if (user.isPasswordExpired || user.mustChangePassword) {
      // Clean up temp login record
      await tempLoginModel.deleteOne({ email });

      // Log password expiry detected
      await createAuditLog({
        userId: user._id,
        userType: "User",
        userEmail: email,
        action: "LOGIN_PASSWORD_EXPIRED",
        description: `Login blocked - password expired for user: ${email}`,
        method: req.method,
        endpoint: req.path,
        ipAddress: req.ip,
        status: "FAILURE",
        metadata: {
          reason: user.mustChangePassword ? "FORCED_CHANGE" : "EXPIRED",
          passwordExpiresAt: user.passwordExpiresAt,
        },
      });

      return res.json({
        success: false,
        message:
          "Your password has expired. Please reset your password to continue.",
        passwordExpired: true,
        mustChangePassword: user.mustChangePassword,
      });
    }

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

    // Check if password expires soon (within 7 days)
    const daysUntilExpiry = Math.ceil(
      (user.passwordExpiresAt - new Date()) / (1000 * 60 * 60 * 24)
    );
    const passwordWarning = daysUntilExpiry <= 7 && daysUntilExpiry > 0;

    res.json({
      success: true,
      user,
      message: "Login successful!",
      passwordWarning: passwordWarning
        ? {
            daysUntilExpiry,
            message: `Your password will expire in ${daysUntilExpiry} day(s). Please change it soon.`,
          }
        : null,
    });
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

    // Validate and sanitize inputs
    let sanitizedName, sanitizedEmail, sanitizedPassword;

    try {
      sanitizedName = validateAndSanitizeInput(name, "name");
      sanitizedEmail = validateAndSanitizeInput(email, "email");
      sanitizedPassword = validateAndSanitizeInput(password, "password");
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_REGISTRATION_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    // Check if user already exists in main or temp collection
    const exists = await userModel.findOne({ email: sanitizedEmail });
    if (exists) {
      return res
        .status(409)
        .json({ success: false, message: "User already exists" });
    }
    const tempExists = await tempUserModel.findOne({ email: sanitizedEmail });
    if (tempExists) {
      return res.status(409).json({
        success: false,
        message: "Please verify OTP sent to your email",
      });
    }

    // Validate email format (additional check)
    if (!validator.isEmail(sanitizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email",
      });
    }

    // Validate password strength
    if (
      !validator.isStrongPassword(sanitizedPassword, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 8 characters long and include uppercase, lowercase, number, and symbol.",
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(sanitizedPassword, salt);

    // Generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 min expiry

    // Store in tempUser collection
    await tempUserModel.create({
      name: sanitizedName,
      email: sanitizedEmail,
      password: hashedPassword,
      otp,
      otpExpires,
    });

    // Send OTP via email
    try {
      await sendOtpEmail(sanitizedEmail, otp);
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

    // Validate and sanitize inputs
    let sanitizedEmail, sanitizedPassword;

    try {
      sanitizedEmail = validateAndSanitizeInput(email, "email");
      sanitizedPassword = validateAndSanitizeInput(password, "password");
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_ADMIN_LOGIN_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    // Find admin in database
    const admin = await adminModel.findOne({ email: sanitizedEmail });
    if (!admin) {
      return res
        .status(404)
        .json({ success: false, message: "Admin not found" });
    }

    // Check if admin is active
    if (!admin.isActive) {
      return res.status(403).json({
        success: false,
        message: "Admin account is deactivated",
      });
    }

    // Compare password with hashed password
    const isMatch = await bcrypt.compare(sanitizedPassword, admin.password);

    if (isMatch) {
      // Track successful admin login
      adminSessionTracker.trackLogin(
        admin._id.toString(),
        req.ip,
        req.get("User-Agent"),
        true
      );

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
      // Track failed admin login attempt
      adminSessionTracker.trackLogin(
        admin._id.toString(),
        req.ip,
        req.get("User-Agent"),
        false
      );

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

// Route for user logout
export const logoutUser = async (req, res) => {
  try {
    const userId = req.body.userId;

    // Clear the JWT cookie
    res.clearCookie("token", {
      httpOnly: true,
      secure: true, // Use secure in production
      sameSite: "strict",
      path: "/",
    });

    // Clear CSRF cookie as well for security
    res.clearCookie("_csrf", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
    });

    // Clean up any temporary login sessions
    if (userId) {
      await tempLoginModel.deleteMany({ userId });
    }

    // Log the logout activity
    logActivity("USER_LOGOUT", "User logged out successfully", {
      userId: userId || "unknown",
      ip: req.ip,
      userAgent: req.get("User-Agent"),
      timestamp: new Date(),
    });

    res.json({
      success: true,
      message: "Logged out successfully",
    });
  } catch (error) {
    logError("LOGOUT_ERROR", error.message, {
      userId: req.body.userId,
      ip: req.ip,
    });
    res.json({
      success: false,
      message: "Logout failed. Please try again.",
    });
  }
};

// Route for admin logout
export const logoutAdmin = async (req, res) => {
  try {
    const adminId = req.body.adminId;

    // Clear the JWT cookie
    res.clearCookie("token", {
      httpOnly: true,
      secure: true, // Use secure in production
      sameSite: "strict",
      path: "/",
    });

    // Clear CSRF cookie as well for security
    res.clearCookie("_csrf", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
    });

    // Log the admin logout activity
    logActivity("ADMIN_LOGOUT", "Admin logged out successfully", {
      adminId: adminId || "unknown",
      ip: req.ip,
      userAgent: req.get("User-Agent"),
      timestamp: new Date(),
    });

    res.json({
      success: true,
      message: "Admin logged out successfully",
    });
  } catch (error) {
    logError("ADMIN_LOGOUT_ERROR", error.message, {
      adminId: req.body.adminId,
      ip: req.ip,
    });
    res.json({
      success: false,
      message: "Admin logout failed. Please try again.",
    });
  }
};

// Get admin session summary and security status
export const getAdminSecurityStatus = async (req, res) => {
  try {
    const adminId = req.admin.id; // From auth middleware

    // Get session summary from tracker
    const sessionSummary = adminSessionTracker.getAdminSessionSummary(adminId);

    if (!sessionSummary) {
      return res.json({
        success: true,
        data: {
          adminId,
          activeSessions: 0,
          riskLevel: "LOW",
          message: "No active sessions found",
        },
      });
    }

    res.json({
      success: true,
      data: sessionSummary,
    });
  } catch (error) {
    logError("ADMIN_SECURITY_STATUS_ERROR", error.message, {
      adminId: req.admin?.id,
      ip: req.ip,
    });
    res.json({
      success: false,
      message: "Failed to get security status",
    });
  }
};

// Check password expiry middleware
export const checkPasswordExpiry = async (req, res, next) => {
  try {
    if (req.user && req.user.isPasswordExpired) {
      return res.status(403).json({
        success: false,
        message: "Password has expired. Please change your password.",
        passwordExpired: true,
      });
    }
    next();
  } catch (error) {
    next();
  }
};

// Update password
export const updatePassword = async (req, res) => {
  try {
    const { userId, currentPassword, newPassword } = req.body;

    // Validate and sanitize inputs
    let sanitizedUserId, sanitizedCurrentPassword, sanitizedNewPassword;

    try {
      sanitizedUserId = validateAndSanitizeInput(userId, "id");
      sanitizedCurrentPassword = validateAndSanitizeInput(
        currentPassword,
        "password"
      );
      sanitizedNewPassword = validateAndSanitizeInput(newPassword, "password");
    } catch (validationError) {
      await logSecurityEvent(
        req,
        "INVALID_PASSWORD_UPDATE_INPUT",
        validationError.message
      );
      return res.status(400).json({
        success: false,
        message: validationError.message,
      });
    }

    const user = await userModel.findById(sanitizedUserId);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(
      sanitizedCurrentPassword,
      user.password
    );
    if (!isCurrentPasswordValid) {
      // Log failed password change attempt
      await createAuditLog({
        userId: user._id,
        userType: "User",
        userEmail: user.email,
        action: "PASSWORD_CHANGE_FAILED",
        description:
          "Failed password change attempt - invalid current password",
        method: req.method,
        endpoint: req.path,
        ipAddress: req.ip,
        status: "FAILURE",
        metadata: { reason: "INVALID_CURRENT_PASSWORD" },
      });

      return res.status(401).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // Check if new password is the same as current password
    const isSamePassword = await bcrypt.compare(
      sanitizedNewPassword,
      user.password
    );
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        message: "New password cannot be the same as current password",
      });
    }

    // Validate new password strength
    const passwordValidation = validatePasswordStrength(sanitizedNewPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
      });
    }

    // Check if new password was used recently
    if (user.wasPasswordUsedRecently(sanitizedNewPassword)) {
      return res.status(400).json({
        success: false,
        message: "Cannot reuse any of your last 5 passwords",
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(sanitizedNewPassword, salt);

    // Add current password to history and update
    user.addPasswordToHistory(user.password);
    user.password = hashedNewPassword;
    await user.save();

    // Log successful password change
    await createAuditLog({
      userId: user._id,
      userType: "User",
      userEmail: user.email,
      action: "PASSWORD_CHANGED",
      description: "User successfully changed password",
      method: req.method,
      endpoint: req.path,
      ipAddress: req.ip,
      status: "SUCCESS",
    });

    res.json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.error("Password update error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update password",
    });
  }
};

// Forgot password - send reset link
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Email is required" });
    }

    const user = await userModel.findOne({ email });
    if (!user) {
      // Don't reveal that user doesn't exist for security
      return res.json({
        success: true,
        message:
          "If an account with that email exists, a password reset link has been sent.",
      });
    }

    // Generate reset token
    const resetToken = generateResetToken();
    const tokenHash = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Set reset token and expiry
    user.passwordResetToken = tokenHash;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await user.save();

    // Send reset email
    try {
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password`;
      await sendPasswordResetEmail(email, resetToken, resetUrl);

      // Log password reset request
      await createAuditLog({
        userId: user._id,
        userType: "User",
        userEmail: user.email,
        action: "PASSWORD_RESET_REQUESTED",
        description: "User requested password reset",
        method: req.method,
        endpoint: req.path,
        ipAddress: req.ip,
        status: "SUCCESS",
      });

      res.json({
        success: true,
        message: "Password reset link sent to your email",
      });
    } catch (emailError) {
      // Clear reset token if email fails
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();

      console.error("Password reset email error:", emailError);
      res.status(500).json({
        success: false,
        message: "Failed to send reset email. Please try again.",
      });
    }
  } catch (error) {
    console.error("Forgot password error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to process password reset request",
    });
  }
};

// Reset password with token
export const resetPassword = async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Email, token, and new password are required",
      });
    }

    // Hash the provided token to compare with stored hash
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    // Find user with valid reset token
    const user = await userModel.findOne({
      email,
      passwordResetToken: tokenHash,
      passwordResetExpires: { $gt: new Date() },
    });

    if (!user) {
      // Log failed reset attempt
      await createAuditLog({
        userId: null,
        userType: "User",
        userEmail: email,
        action: "PASSWORD_RESET_FAILED",
        description: "Failed password reset attempt - invalid or expired token",
        method: req.method,
        endpoint: req.path,
        ipAddress: req.ip,
        status: "FAILURE",
        metadata: { reason: "INVALID_TOKEN" },
      });

      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset token",
      });
    }

    // Validate new password strength
    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
      });
    }

    // Check if new password is the same as current password
    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        message: "New password cannot be the same as current password",
      });
    }

    // Check if new password was used recently
    if (user.wasPasswordUsedRecently(newPassword)) {
      return res.status(400).json({
        success: false,
        message: "Cannot reuse any of your last 5 passwords",
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    // Add current password to history and update
    user.addPasswordToHistory(user.password);
    user.password = hashedNewPassword;

    // Clear reset token
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();

    // Log successful password reset
    await createAuditLog({
      userId: user._id,
      userType: "User",
      userEmail: user.email,
      action: "PASSWORD_RESET_COMPLETED",
      description: "User successfully reset password",
      method: req.method,
      endpoint: req.path,
      ipAddress: req.ip,
      status: "SUCCESS",
    });

    res.json({
      success: true,
      message: "Password reset successfully",
    });
  } catch (error) {
    console.error("Reset password error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to reset password",
    });
  }
};

// Get password status (expiry info)
export const getPasswordStatus = async (req, res) => {
  try {
    const { userId } = req.body;

    const user = await userModel
      .findById(userId)
      .select("passwordExpiresAt passwordChangedAt mustChangePassword");
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    const now = new Date();
    const daysUntilExpiry = Math.ceil(
      (user.passwordExpiresAt - now) / (1000 * 60 * 60 * 24)
    );

    res.json({
      success: true,
      data: {
        passwordExpiresAt: user.passwordExpiresAt,
        passwordChangedAt: user.passwordChangedAt,
        isExpired: user.isPasswordExpired,
        daysUntilExpiry: daysUntilExpiry > 0 ? daysUntilExpiry : 0,
        mustChangePassword: user.mustChangePassword,
        needsWarning: daysUntilExpiry <= 7 && daysUntilExpiry > 0,
      },
    });
  } catch (error) {
    console.error("Get password status error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to get password status",
    });
  }
};

// Force password change (admin function)
export const forcePasswordChange = async (req, res) => {
  try {
    const { userId } = req.body;

    if (!req.admin) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized. Admin access required.",
      });
    }

    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

    user.mustChangePassword = true;
    user.passwordExpiresAt = new Date(); // Expire immediately
    await user.save();

    // Log forced password change
    await createAuditLog({
      userId: req.admin._id,
      userType: "Admin",
      userEmail: req.admin.email,
      action: "ADMIN_FORCE_PASSWORD_CHANGE",
      description: `Admin forced password change for user: ${user.email}`,
      method: req.method,
      endpoint: req.path,
      ipAddress: req.ip,
      status: "SUCCESS",
      metadata: { targetUserId: userId, targetUserEmail: user.email },
    });

    res.json({
      success: true,
      message: "User will be required to change password on next login",
    });
  } catch (error) {
    console.error("Force password change error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to force password change",
    });
  }
};
