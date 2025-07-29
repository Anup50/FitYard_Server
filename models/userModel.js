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

    // Password management fields
    passwordHistory: [
      {
        password: { type: String, required: true },
        createdAt: { type: Date, default: Date.now },
      },
    ], // Store last 5 passwords to prevent reuse
    passwordChangedAt: { type: Date, default: Date.now },
    passwordExpiresAt: {
      type: Date,
      default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
    },
    mustChangePassword: { type: Boolean, default: false },

    // Password reset fields
    passwordResetToken: { type: String },
    passwordResetExpires: { type: Date },

    // Account status
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
  },
  { minimize: false }
);

// Index for password reset token cleanup
userSchema.index({ passwordResetExpires: 1 }, { expireAfterSeconds: 0 });

// Virtual to check if password is expired
userSchema.virtual("isPasswordExpired").get(function () {
  return this.passwordExpiresAt < new Date();
});

// Method to check if password was used recently
userSchema.methods.wasPasswordUsedRecently = function (password) {
  return this.passwordHistory.some((oldPassword) =>
    bcrypt.compareSync(password, oldPassword.password)
  );
};

// Method to add password to history
userSchema.methods.addPasswordToHistory = function (hashedPassword) {
  this.passwordHistory.push({
    password: hashedPassword,
    createdAt: new Date(),
  });

  // Keep only last 5 passwords
  if (this.passwordHistory.length > 5) {
    this.passwordHistory = this.passwordHistory.slice(-5);
  }

  this.passwordChangedAt = new Date();
  this.passwordExpiresAt = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days
  this.mustChangePassword = false;
};

const userModel = mongoose.models.user || mongoose.model("user", userSchema);
export default userModel;
