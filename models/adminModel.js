import mongoose from "mongoose";
import bcrypt from "bcrypt";

const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "admin" },
  isActive: { type: Boolean, default: true },

  // Password management fields
  passwordHistory: [
    {
      password: { type: String, required: true },
      createdAt: { type: Date, default: Date.now },
    },
  ],
  passwordChangedAt: { type: Date, default: Date.now },
  passwordExpiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
  },
  mustChangePassword: { type: Boolean, default: false },

  // Password reset fields
  passwordResetToken: { type: String },
  passwordResetExpires: { type: Date },

  // Account lockout fields
  failedLoginAttempts: { type: Number, default: 0 },
  accountLockedUntil: { type: Date },

  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
});

// Virtual to check if password is expired
adminSchema.virtual("isPasswordExpired").get(function () {
  return this.passwordExpiresAt < new Date();
});

// Method to check if password was used recently
adminSchema.methods.wasPasswordUsedRecently = function (password) {
  return this.passwordHistory.some((oldPassword) =>
    bcrypt.compareSync(password, oldPassword.password)
  );
};

// Virtual to check if account is locked
adminSchema.virtual("isLocked").get(function () {
  return !!(this.accountLockedUntil && this.accountLockedUntil > Date.now());
});

// Method to increment failed attempts and lock account if needed
adminSchema.methods.incFailedAttempts = function () {
  // If we have a previous lock that has expired, restart
  if (this.accountLockedUntil && this.accountLockedUntil < Date.now()) {
    return this.updateOne({
      $unset: { accountLockedUntil: 1 },
      $set: { failedLoginAttempts: 1 },
    });
  }

  const updates = { $inc: { failedLoginAttempts: 1 } };

  // Lock account after 5 failed attempts for 2 hours
  if (this.failedLoginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = {
      accountLockedUntil: new Date(Date.now() + 2 * 60 * 60 * 1000), // 2 hours
    };
  }

  return this.updateOne(updates);
};

// Method to reset failed attempts on successful login
adminSchema.methods.resetFailedAttempts = function () {
  return this.updateOne({
    $unset: { failedLoginAttempts: 1, accountLockedUntil: 1 },
  });
};

// Method to add password to history
adminSchema.methods.addPasswordToHistory = function (hashedPassword) {
  this.passwordHistory.push({
    password: hashedPassword,
    createdAt: new Date(),
  });

  // Keep only last 5 passwords
  if (this.passwordHistory.length > 5) {
    this.passwordHistory = this.passwordHistory.slice(-5);
  }

  this.passwordChangedAt = new Date();
  this.passwordExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
  this.mustChangePassword = false;
};

const adminModel =
  mongoose.models.admin || mongoose.model("admin", adminSchema, "admins");

export default adminModel;
