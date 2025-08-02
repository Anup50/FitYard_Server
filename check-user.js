import mongoose from "mongoose";
import userModel from "./models/userModel.js";
import { config } from "dotenv";

config();

async function checkUser() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("Connected to database");

    const email = "anupkc983@gmail.com";
    const user = await userModel
      .findOne({ email })
      .select("+password +failedLoginAttempts +accountLockedUntil");

    if (user) {
      console.log("User found:");
      console.log("- ID:", user._id);
      console.log("- Name:", user.name);
      console.log("- Email:", user.email);
      console.log("- Failed attempts:", user.failedLoginAttempts || 0);
      console.log(
        "- Account locked until:",
        user.accountLockedUntil || "Not locked"
      );
      console.log(
        "- Is locked:",
        !!(user.accountLockedUntil && user.accountLockedUntil > Date.now())
      );
      console.log("- Password hash exists:", !!user.password);
      console.log(
        "- Password hash starts with:",
        user.password?.substring(0, 10) + "..."
      );
      console.log("- Is active:", user.isActive);
    } else {
      console.log("User not found!");
    }

    await mongoose.disconnect();
  } catch (error) {
    console.error("Error:", error);
  }
}

checkUser();
