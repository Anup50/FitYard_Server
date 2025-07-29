import crypto from "crypto";
import sendOtpEmail from "./sendOtpEmail.js";

// Generate secure reset token
export const generateResetToken = () => {
  return crypto.randomBytes(32).toString("hex");
};

// Generate reset OTP
export const generateResetOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send password reset email
export const sendPasswordResetEmail = async (email, resetToken, resetUrl) => {
  const resetLink = `${resetUrl}?token=${resetToken}&email=${email}`;

  // Create a well-formatted HTML email
  const emailContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f8f9fa;">
      <div style="background-color: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        
        <!-- Header with logo/brand -->
        <div style="text-align: center; margin-bottom: 30px;">
          <h1 style="color: #007bff; margin: 0; font-size: 28px;">FitYard</h1>
          <p style="color: #6c757d; margin: 5px 0 0 0; font-size: 14px;">Fitness & Wellness Platform</p>
        </div>
        
        <!-- Main content -->
        <div style="margin-bottom: 30px;">
          <h2 style="color: #333; margin-bottom: 20px; font-size: 24px;">Password Reset Request</h2>
          
          <p style="color: #555; line-height: 1.6; margin-bottom: 20px; font-size: 16px;">
            Hello,
          </p>
          
          <p style="color: #555; line-height: 1.6; margin-bottom: 25px; font-size: 16px;">
            We received a request to reset your password for your FitYard account associated with <strong>${email}</strong>.
          </p>
          
          <p style="color: #555; line-height: 1.6; margin-bottom: 30px; font-size: 16px;">
            Click the button below to reset your password:
          </p>
          
          <!-- Reset button -->
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}" 
               style="background-color: #007bff; 
                      color: white; 
                      padding: 15px 30px; 
                      text-decoration: none; 
                      border-radius: 6px; 
                      font-weight: bold; 
                      font-size: 16px; 
                      display: inline-block;
                      box-shadow: 0 2px 4px rgba(0,123,255,0.3);">
              Reset My Password
            </a>
          </div>
          
          <p style="color: #666; font-size: 14px; line-height: 1.5; margin-bottom: 20px;">
            Or copy and paste this link into your browser:
          </p>
          
          <div style="background-color: #f8f9fa; padding: 15px; border-radius: 4px; border-left: 4px solid #007bff; margin-bottom: 25px;">
            <a href="${resetLink}" style="color: #007bff; word-break: break-all; font-size: 14px;">${resetLink}</a>
          </div>
          
          <!-- Security notice -->
          <div style="background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin-bottom: 20px;">
            <p style="color: #856404; margin: 0; font-size: 14px; line-height: 1.5;">
              <strong>⚠️ Security Notice:</strong><br>
              • This link will expire in <strong>1 hour</strong><br>
              • If you didn't request this reset, please ignore this email<br>
              • Never share this link with anyone
            </p>
          </div>
          
        </div>
        
        <!-- Footer -->
        <div style="border-top: 1px solid #dee2e6; padding-top: 20px; text-align: center;">
          <p style="color: #6c757d; font-size: 12px; margin: 0; line-height: 1.4;">
            This email was sent by FitYard Password Reset System<br>
            If you have any questions, please contact our support team.
          </p>
          
          <p style="color: #6c757d; font-size: 12px; margin: 10px 0 0 0;">
            © 2025 FitYard. All rights reserved.
          </p>
        </div>
        
      </div>
    </div>
  `;

  // Fallback plain text version
  const textContent = `
FitYard - Password Reset Request

Hello,

We received a request to reset your password for your FitYard account (${email}).

Click this link to reset your password:
${resetLink}

This link will expire in 1 hour.

If you didn't request this password reset, please ignore this email.

For security reasons, never share this link with anyone.

Best regards,
FitYard Team

© 2025 FitYard. All rights reserved.
  `;

  return await sendOtpEmail(
    email,
    emailContent,
    "FitYard - Password Reset Request",
    textContent
  );
};

// Check if password meets complexity requirements
export const validatePasswordStrength = (password) => {
  const minLength = 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSymbol = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  if (password.length < minLength) {
    return {
      valid: false,
      message: "Password must be at least 8 characters long",
    };
  }

  if (!hasUpper) {
    return {
      valid: false,
      message: "Password must contain at least one uppercase letter",
    };
  }

  if (!hasLower) {
    return {
      valid: false,
      message: "Password must contain at least one lowercase letter",
    };
  }

  if (!hasNumber) {
    return {
      valid: false,
      message: "Password must contain at least one number",
    };
  }

  if (!hasSymbol) {
    return {
      valid: false,
      message: "Password must contain at least one special character",
    };
  }

  return { valid: true };
};
