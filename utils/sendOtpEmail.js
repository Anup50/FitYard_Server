import nodemailer from "nodemailer";

const sendOtpEmail = async (to, otp) => {
  // Configure transporter for Gmail
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });

  // HTML email template
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 400px; margin: auto; border: 1px solid #eee; border-radius: 8px; padding: 24px;">
      <h2 style="color: #2e7d32;">FitYard OTP Verification</h2>
      <p>Thank you for registering with FitYard!</p>
      <p>Your One-Time Password (OTP) is:</p>
      <div style="font-size: 2em; font-weight: bold; color: #1565c0; margin: 16px 0;">${otp}</div>
      <p style="color: #888;">This OTP is valid for 10 minutes. If you did not request this, please ignore this email.</p>
      <hr style="margin: 24px 0;">
      <p style="font-size: 0.9em; color: #aaa;">&copy; ${new Date().getFullYear()} FitYard</p>
    </div>
  `;

  // Send mail
  await transporter.sendMail({
    from: `FitYard <${process.env.GMAIL_USER}>`,
    to,
    subject: "Your FitYard OTP Code",
    html,
  });
};

export default sendOtpEmail;
