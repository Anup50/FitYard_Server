import mongoose from "mongoose";
import bcrypt from "bcrypt";

const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "admin" },
  isActive: { type: Boolean, default: true },

  passwordHistory: [
    {
      password: { type: String, required: true },
      createdAt: { type: Date, default: Date.now },
    },
  ],
  passwordChangedAt: { type: Date, default: Date.now },
  passwordExpiresAt: {
    type: Date,
    default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
  },
  mustChangePassword: { type: Boolean, default: false },

  passwordResetToken: { type: String },
  passwordResetExpires: { type: Date },

  failedLoginAttempts: { type: Number, default: 0 },
  accountLockedUntil: { type: Date },

  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
});

adminSchema.virtual("isPasswordExpired").get(function () {
  return this.passwordExpiresAt < new Date();
});

adminSchema.methods.wasPasswordUsedRecently = function (password) {
  return this.passwordHistory.some((oldPassword) =>
    bcrypt.compareSync(password, oldPassword.password)
  );
};

adminSchema.virtual("isLocked").get(function () {
  return !!(this.accountLockedUntil && this.accountLockedUntil > Date.now());
});

adminSchema.methods.incFailedAttempts = function () {
  if (this.accountLockedUntil && this.accountLockedUntil < Date.now()) {
    return this.updateOne({
      $unset: { accountLockedUntil: 1 },
      $set: { failedLoginAttempts: 1 },
    });
  }

  const updates = { $inc: { failedLoginAttempts: 1 } };

  if (this.failedLoginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = {
      accountLockedUntil: new Date(Date.now() + 2 * 60 * 60 * 1000),
    };
  }

  return this.updateOne(updates);
};

adminSchema.methods.resetFailedAttempts = function () {
  return this.updateOne({
    $unset: { failedLoginAttempts: 1, accountLockedUntil: 1 },
  });
};

adminSchema.methods.addPasswordToHistory = function (hashedPassword) {
  this.passwordHistory.push({
    password: hashedPassword,
    createdAt: new Date(),
  });

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
