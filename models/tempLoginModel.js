import mongoose from "mongoose";

const tempLoginSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "user", required: true },
  email: { type: String, required: true },
  otp: { type: String, required: true },
  otpExpires: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now, expires: 600 }, // Auto-delete after 10 minutes
});

const tempLoginModel =
  mongoose.models.tempLogin || mongoose.model("tempLogin", tempLoginSchema);

export default tempLoginModel;
