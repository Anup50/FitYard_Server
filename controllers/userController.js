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
  sendPasswordResetEmail,
  validatePasswordStrength,
} from "../utils/passwordReset.js";

const createToken = (id, role = "user") => {
  return jwt.sign({ id, role }, process.env.JWT_SECRET, { expiresIn: "1d" });
};

export const loginUser = async (req, res) => {
  try {
    const { email, password, captcha } = req.body;

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

    const user = await userModel
      .findOne({ email: sanitizedEmail })
      .select("+password +failedLoginAttempts +accountLockedUntil");
    if (!user) {
      await logSecurityEvent(
        req,
        "LOGIN_USER_NOT_FOUND",
        `Login attempt for non-existent user: ${sanitizedEmail}`
      );
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    if (user.isLocked) {
      const lockoutEndTime = new Date(user.accountLockedUntil);
      const remainingTime = Math.ceil(
        (lockoutEndTime - Date.now()) / (1000 * 60)
      );

      await createAuditLog({
        userId: user._id,
        userType: "User",
        userEmail: user.email,
        action: "LOGIN_ATTEMPT_LOCKED_ACCOUNT",
        description: `Login attempt on locked account. Lockout ends at ${lockoutEndTime.toISOString()}`,
        method: req.method,
        endpoint: req.path,
        ipAddress: req.ip,
        status: "BLOCKED",
        metadata: {
          remainingLockoutMinutes: remainingTime,
          userAgent: req.get("User-Agent"),
        },
      });

      return res.status(423).json({
        success: false,
        message: `Account is locked due to multiple failed login attempts. Please try again in ${remainingTime} minutes.`,
        lockoutInfo: {
          lockedUntil: lockoutEndTime,
          remainingMinutes: remainingTime,
        },
      });
    }

    if (!user.password || !sanitizedPassword) {
      await logSecurityEvent(
        req,
        "LOGIN_INVALID_PASSWORD_DATA",
        `Password validation failed - missing password data for: ${sanitizedEmail}`
      );
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const isMatch = await bcrypt.compare(sanitizedPassword, user.password);

    if (isMatch) {
      if (user.failedLoginAttempts > 0) {
        await user.resetFailedAttempts();
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpires = new Date(Date.now() + 10 * 60 * 1000);
      await tempLoginModel.deleteOne({ userId: user._id });

      await tempLoginModel.create({
        userId: user._id,
        email: user.email,
        otp,
        otpExpires,
      });

      try {
        await sendOtpEmail(email, otp);

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
        await tempLoginModel.deleteOne({ userId: user._id });
        logError("LOGIN_OTP_EMAIL_ERROR", err.message, { email, ip: req.ip });
        return res.json({
          success: false,
          message: "Failed to send OTP email. Please try again.",
        });
      }
    } else {
      await user.incFailedAttempts();

      const updatedUser = await userModel
        .findById(user._id)
        .select("failedLoginAttempts accountLockedUntil isLocked");

      await createAuditLog({
        userId: user._id,
        userType: "User",
        userEmail: user.email,
        action: updatedUser.isLocked
          ? "LOGIN_FAILED_ACCOUNT_LOCKED"
          : "LOGIN_FAILED_INVALID_PASSWORD",
        description: updatedUser.isLocked
          ? `Account locked after ${updatedUser.failedLoginAttempts} failed attempts`
          : `Failed login attempt ${updatedUser.failedLoginAttempts}/5`,
        method: req.method,
        endpoint: req.path,
        ipAddress: req.ip,
        status: "FAILURE",
        metadata: {
          failedAttempts: updatedUser.failedLoginAttempts,
          accountLocked: updatedUser.isLocked,
          userAgent: req.get("User-Agent"),
        },
      });

      if (updatedUser.isLocked) {
        return res.status(423).json({
          success: false,
          message:
            "Account has been locked due to multiple failed login attempts. Please try again in 2 hours.",
          lockoutInfo: {
            lockedUntil: updatedUser.accountLockedUntil,
            remainingMinutes: 120,
          },
        });
      }

      const remainingAttempts = 5 - updatedUser.failedLoginAttempts;

      logActivity(
        null,
        "LOGIN_FAILED",
        `Failed login attempt for email: ${email} (${updatedUser.failedLoginAttempts}/5 attempts)`,
        req.ip,
        req.get("User-Agent")
      );

      return res.status(401).json({
        success: false,
        message: `Invalid credentials. ${remainingAttempts} attempts remaining before account lockout.`,
        attemptsRemaining: remainingAttempts,
      });
    }
  } catch (e) {
    console.log("Login error:", e);

    logError("LOGIN_ERROR", e.message, { email: req.body.email, ip: req.ip });

    res.status(500).json({
      success: false,
      message: "Login failed. Please try again.",
    });
  }
};

export const verifyLoginOtp = async (req, res) => {
  try {
    const { email, otp } = req.body;

    const tempLogin = await tempLoginModel.findOne({ email });
    if (!tempLogin) {
      return res.json({
        success: false,
        message: "No pending login verification found. Please login again.",
      });
    }

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

    if (tempLogin.otpExpires < new Date()) {
      await tempLoginModel.deleteOne({ email });
      return res.json({
        success: false,
        message: "OTP expired. Please login again.",
      });
    }

    const user = await userModel.findById(tempLogin.userId).select("-password");

    if (user.isPasswordExpired || user.mustChangePassword) {
      await tempLoginModel.deleteOne({ email });

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

    const token = createToken(user._id, "user");
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });

    await tempLoginModel.deleteOne({ email });

    logActivity(
      user._id,
      "USER_LOGIN",
      `User ${user.email} logged in successfully after OTP verification`,
      req.ip,
      req.get("User-Agent")
    );

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

export const registerUser = async (req, res) => {
  try {
    const { name, email, password } = req.body;

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

    if (!validator.isEmail(sanitizedEmail)) {
      return res.status(400).json({
        success: false,
        message: "Please enter a valid email",
      });
    }

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

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(sanitizedPassword, salt);

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    await tempUserModel.create({
      name: sanitizedName,
      email: sanitizedEmail,
      password: hashedPassword,
      otp,
      otpExpires,
    });

    try {
      await sendOtpEmail(sanitizedEmail, otp);
    } catch (err) {
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

    const { name, password } = tempUser;
    const newUser = new userModel({ name, email, password });
    await newUser.save();
    await tempUserModel.deleteOne({ email });

    const token = createToken(newUser._id, "user");
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });
    res.json({ success: true, message: "Registration successful!" });

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

    const admin = await adminModel
      .findOne({ email: sanitizedEmail })
      .select("+password +failedLoginAttempts +accountLockedUntil");
    if (!admin) {
      await logSecurityEvent(
        req,
        "ADMIN_LOGIN_USER_NOT_FOUND",
        `Admin login attempt for non-existent user: ${sanitizedEmail}`
      );
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    if (admin.isLocked) {
      const lockoutEndTime = new Date(admin.accountLockedUntil);
      const remainingTime = Math.ceil(
        (lockoutEndTime - Date.now()) / (1000 * 60)
      );

      await createAuditLog({
        userId: admin._id,
        userType: "Admin",
        userEmail: admin.email,
        action: "ADMIN_LOGIN_ATTEMPT_LOCKED_ACCOUNT",
        description: `Admin login attempt on locked account. Lockout ends at ${lockoutEndTime.toISOString()}`,
        method: req.method,
        endpoint: req.path,
        ipAddress: req.ip,
        status: "BLOCKED",
        metadata: {
          remainingLockoutMinutes: remainingTime,
          userAgent: req.get("User-Agent"),
        },
      });

      return res.status(423).json({
        success: false,
        message: `Admin account is locked due to multiple failed login attempts. Please try again in ${remainingTime} minutes.`,
        lockoutInfo: {
          lockedUntil: lockoutEndTime,
          remainingMinutes: remainingTime,
        },
      });
    }

    if (!admin.isActive) {
      return res.status(403).json({
        success: false,
        message: "Admin account is deactivated",
      });
    }

    if (!admin.password || !sanitizedPassword) {
      await logSecurityEvent(
        req,
        "ADMIN_LOGIN_INVALID_PASSWORD_DATA",
        `Admin password validation failed - missing password data for: ${sanitizedEmail}`
      );
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const isMatch = await bcrypt.compare(sanitizedPassword, admin.password);

    if (isMatch) {
      if (admin.failedLoginAttempts > 0) {
        await admin.resetFailedAttempts();
      }

      adminSessionTracker.trackLogin(
        admin._id.toString(),
        req.ip,
        req.get("User-Agent"),
        true
      );

      admin.lastLogin = new Date();
      await admin.save();

      const token = jwt.sign(
        { id: admin._id, email: admin.email, role: admin.role },
        process.env.JWT_SECRET,
        { expiresIn: "1d" }
      );
      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 24 * 60 * 60 * 1000,
      });
      const adminData = await adminModel
        .findById(admin._id)
        .select("-password");
      res.json({
        success: true,
        user: adminData,
        message: "Admin login successful!",
      });

      logActivity(
        admin._id,
        "ADMIN_LOGIN",
        `Admin ${admin.email} logged in successfully`,
        req.ip,
        req.get("User-Agent")
      );
    } else {
      await admin.incFailedAttempts();

      const updatedAdmin = await adminModel
        .findById(admin._id)
        .select("failedLoginAttempts accountLockedUntil isLocked");

      await createAuditLog({
        userId: admin._id,
        userType: "Admin",
        userEmail: admin.email,
        action: updatedAdmin.isLocked
          ? "ADMIN_LOGIN_FAILED_ACCOUNT_LOCKED"
          : "ADMIN_LOGIN_FAILED_INVALID_PASSWORD",
        description: updatedAdmin.isLocked
          ? `Admin account locked after ${updatedAdmin.failedLoginAttempts} failed attempts`
          : `Failed admin login attempt ${updatedAdmin.failedLoginAttempts}/5`,
        method: req.method,
        endpoint: req.path,
        ipAddress: req.ip,
        status: "FAILURE",
        metadata: {
          failedAttempts: updatedAdmin.failedLoginAttempts,
          accountLocked: updatedAdmin.isLocked,
          userAgent: req.get("User-Agent"),
        },
      });

      adminSessionTracker.trackLogin(
        admin._id.toString(),
        req.ip,
        req.get("User-Agent"),
        false
      );

      if (updatedAdmin.isLocked) {
        return res.status(423).json({
          success: false,
          message:
            "Admin account has been locked due to multiple failed login attempts. Please try again in 2 hours.",
          lockoutInfo: {
            lockedUntil: updatedAdmin.accountLockedUntil,
            remainingMinutes: 120,
          },
        });
      }

      const remainingAttempts = 5 - updatedAdmin.failedLoginAttempts;

      logActivity(
        null,
        "ADMIN_LOGIN_FAILED",
        `Failed admin login attempt for email: ${email} (${updatedAdmin.failedLoginAttempts}/5 attempts)`,
        req.ip,
        req.get("User-Agent")
      );

      res.status(401).json({
        success: false,
        message: `Invalid credentials. ${remainingAttempts} attempts remaining before account lockout.`,
        attemptsRemaining: remainingAttempts,
      });
    }
  } catch (e) {
    console.log("Admin login error:", e);

    logError("ADMIN_LOGIN_ERROR", e.message, {
      email: req.body.email,
      ip: req.ip,
    });

    res.status(500).json({
      success: false,
      message: "Admin login failed. Please try again.",
    });
  }
};

//Route for Admin registration (protected - only for initial setup or by existing admin)
export const registerAdmin = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const adminCount = await adminModel.countDocuments();
    const isInitialSetup = adminCount === 0;

    if (!isInitialSetup && !req.admin) {
      return res.json({
        success: false,
        message: "Unauthorized. Only existing admins can create new admins.",
      });
    }

    const existingAdmin = await adminModel.findOne({ email });
    if (existingAdmin) {
      return res.json({ success: false, message: "Admin already exists" });
    }

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

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newAdmin = new adminModel({
      name,
      email,
      password: hashedPassword,
    });

    const admin = await newAdmin.save();

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

export const getUserProfile = async (req, res) => {
  try {
    const { userId, role } = req.body;

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

export const updateUserProfile = async (req, res) => {
  try {
    const { userId, name, email, currentPassword, newPassword } = req.body;

    const user = await userModel.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }

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

      const salt = await bcrypt.genSalt(10);
      const hashedNewPassword = await bcrypt.hash(newPassword, salt);
      user.password = hashedNewPassword;
    }

    if (name && name.trim() !== "") {
      user.name = name.trim();
    }

    if (email && email !== user.email) {
      if (!validator.isEmail(email)) {
        return res.json({
          success: false,
          message: "Please enter a valid email",
        });
      }

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

export const resendRegistrationOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ success: false, message: "Email is required" });
    }

    const tempUser = await tempUserModel.findOne({ email });
    if (!tempUser) {
      return res.json({
        success: false,
        message:
          "No pending registration found for this email. Please register again.",
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    tempUser.otp = otp;
    tempUser.otpExpires = otpExpires;
    await tempUser.save();

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

export const resendLoginOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.json({ success: false, message: "Email is required" });
    }

    const tempLogin = await tempLoginModel.findOne({ email });
    if (!tempLogin) {
      return res.json({
        success: false,
        message: "No pending login verification found. Please login again.",
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    tempLogin.otp = otp;
    tempLogin.otpExpires = otpExpires;
    await tempLogin.save();

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

export const logoutUser = async (req, res) => {
  try {
    const userId = req.body.userId;

    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    res.clearCookie("_csrf", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    if (userId) {
      await tempLoginModel.deleteMany({ userId });
    }

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

export const logoutAdmin = async (req, res) => {
  try {
    const adminId = req.body.adminId;

    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    res.clearCookie("_csrf", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

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

export const getAdminSecurityStatus = async (req, res) => {
  try {
    const adminId = req.admin.id;

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

export const updatePassword = async (req, res) => {
  try {
    const { userId, currentPassword, newPassword } = req.body;

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

    const isCurrentPasswordValid = await bcrypt.compare(
      sanitizedCurrentPassword,
      user.password
    );
    if (!isCurrentPasswordValid) {
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

    const passwordValidation = validatePasswordStrength(sanitizedNewPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
      });
    }

    if (user.wasPasswordUsedRecently(sanitizedNewPassword)) {
      return res.status(400).json({
        success: false,
        message: "Cannot reuse any of your last 5 passwords",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(sanitizedNewPassword, salt);

    user.addPasswordToHistory(user.password);
    user.password = hashedNewPassword;
    await user.save();

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
      return res.json({
        success: true,
        message:
          "If an account with that email exists, a password reset link has been sent.",
      });
    }

    const resetToken = generateResetToken();
    const tokenHash = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    user.passwordResetToken = tokenHash;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000);
    await user.save();

    try {
      const resetUrl = `${process.env.FRONTEND_URL}/reset-password`;
      await sendPasswordResetEmail(email, resetToken, resetUrl);

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

export const resetPassword = async (req, res) => {
  try {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Email, token, and new password are required",
      });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await userModel.findOne({
      email,
      passwordResetToken: tokenHash,
      passwordResetExpires: { $gt: new Date() },
    });

    if (!user) {
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

    const passwordValidation = validatePasswordStrength(newPassword);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        success: false,
        message: passwordValidation.message,
      });
    }

    const isSamePassword = await bcrypt.compare(newPassword, user.password);
    if (isSamePassword) {
      return res.status(400).json({
        success: false,
        message: "New password cannot be the same as current password",
      });
    }

    if (user.wasPasswordUsedRecently(newPassword)) {
      return res.status(400).json({
        success: false,
        message: "Cannot reuse any of your last 5 passwords",
      });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(newPassword, salt);

    user.addPasswordToHistory(user.password);
    user.password = hashedNewPassword;

    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save();

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
    user.passwordExpiresAt = new Date();
    await user.save();

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
