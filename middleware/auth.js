import jwt from "jsonwebtoken";

const authUser = async (req, res, next) => {
  // Support cookies, 'token' header, and 'Authorization' header
  let token = req.cookies?.token;
  if (!token && req.headers.token) {
    token = req.headers.token;
  }
  if (!token && req.headers.authorization) {
    // Support 'Bearer <token>'
    const parts = req.headers.authorization.split(" ");
    if (parts.length === 2 && parts[0] === "Bearer") {
      token = parts[1];
    }
  }

  if (!token) {
    return res.json({
      success: false,
      message: "Not authorized. Token missing. Please login again.",
    });
  }

  try {
    const token_decode = jwt.verify(token, process.env.JWT_SECRET);
    req.body.userId = token_decode.id;
    if (token_decode.role) {
      req.body.role = token_decode.role;
    }
    next();
  } catch (e) {
    console.log("JWT error:", e.message);
    res.json({
      success: false,
      message: "Invalid or expired token. Please login again.",
    });
  }
};

export default authUser;
