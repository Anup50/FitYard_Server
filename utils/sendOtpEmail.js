import nodemailer from "nodemailer";

const sendOtpEmail = async (
  to,
  content,
  subject = "Your FitYard OTP Code",
  textContent = null
) => {
  try {
    // Check if credentials are available
    if (!process.env.GMAIL_USER || !process.env.GMAIL_PASS) {
      throw new Error(
        "Email credentials not configured. Please set GMAIL_USER and GMAIL_PASS in .env file"
      );
    }

    // Configure transporter for Gmail
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    });

    let html, text;

    // Check if this is an OTP email or a custom email (like password reset)
    if (subject === "Your FitYard OTP Code" && !textContent) {
      // Traditional OTP email
      html = `
        <div style="font-family: Arial, sans-serif; max-width: 400px; margin: auto; border: 1px solid #eee; border-radius: 8px; padding: 24px;">
          <h2 style="color: #2e7d32;">FitYard OTP Verification</h2>
          <p>Thank you for using FitYard!</p>
          <p>Your One-Time Password (OTP) is:</p>
          <div style="font-size: 2em; font-weight: bold; color: #1565c0; margin: 16px 0;">${content}</div>
          <p style="color: #888;">This OTP is valid for 10 minutes. If you did not request this, please ignore this email.</p>
          <hr style="margin: 24px 0;">
          <p style="font-size: 0.9em; color: #aaa;">&copy; ${new Date().getFullYear()} FitYard</p>
        </div>
      `;
    } else {
      // Custom email (like password reset)
      html = content;
      text = textContent;
    }

    // Send mail
    const mailOptions = {
      from: `FitYard <${process.env.GMAIL_USER}>`,
      to,
      subject,
      html,
    };

    // Add text version if provided
    if (text) {
      mailOptions.text = text;
    }

    await transporter.sendMail(mailOptions);
  } catch (error) {
    console.error("Email sending error:", error);
    throw new Error(`Failed to send OTP email: ${error.message}`);
  }
};

export default sendOtpEmail;
