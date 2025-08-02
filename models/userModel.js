import mongoose from "mongoose";
import bcrypt from "bcrypt";

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
    cartData: {
      type: Object,
      default: {},
    },

    passwordHistory: [
      {
        password: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
      },
    ],
    passwordChangedAt: { type: Date, default: Date.now },
    passwordExpiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
    },
    mustChangePassword: { type: Boolean, default: false },

    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },
    isActive: { type: Boolean, default: true },

    failedLoginAttempts: { type: Number, default: 0 },
    accountLockedUntil: { type: Date },

    createdAt: { type: Date, default: Date.now },
  },
  { minimize: false }
);
userSchema.index({ passwordResetExpires: 1 }, { expireAfterSeconds: 0 });

userSchema.virtual("isPasswordExpired").get(function () {
  return this.passwordExpiresAt < new Date();
});

userSchema.methods.wasPasswordUsedRecently = function (password) {
  return this.passwordHistory.some((oldPassword) =>
    bcrypt.compareSync(password, oldPassword.password)
  );
};

userSchema.virtual("isLocked").get(function () {
  return !!(this.accountLockedUntil && this.accountLockedUntil > Date.now());
});

userSchema.methods.incFailedAttempts = function () {
  if (this.accountLockedUntil && this.accountLockedUntil < Date.now()) {
    return this.updateOne({
      $unset: { accountLockedUntil: 1 },
      $set: { failedLoginAttempts: 1 },
    });
  }

  const updates = { $inc: { failedLoginAttempts: 1 } };

  if (this.failedLoginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = {
      accountLockedUntil: new Date(Date.now() + 2 * 60 * 60 * 1000), // 2 hours Lockout
    };
  }

  return this.updateOne(updates);
};
userSchema.methods.resetFailedAttempts = function () {
  return this.updateOne({
    $unset: { failedLoginAttempts: 1, accountLockedUntil: 1 },
  });
};
userSchema.methods.addPasswordToHistory = function (hashedPassword) {
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

const userModel = mongoose.models.user || mongoose.model("user", userSchema);
export default userModel;
