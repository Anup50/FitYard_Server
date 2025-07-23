import mongoose from "mongoose";

const adminSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: "admin" },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
});

const adminModel =
  mongoose.models.admin || mongoose.model("admin", adminSchema);

export default adminModel;
