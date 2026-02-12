const express = require("express");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const requestLogger = require("./middleware/logger");
const authMiddleware = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 3000;

// ========================
// In-memory storage
// ========================
const users = {};
const loginSessions = {};
const otpStore = {};

// ========================
// MIDDLEWARE
// ========================
app.use(requestLogger);
app.use(express.json());
app.use(cookieParser());

// ========================
// ROOT
// ========================
app.get("/", (req, res) => {
  res.json({
    challenge: "Complete the Authentication Flow",
    instruction: "Complete the authentication flow and obtain a valid access token",
  });
});

// ========================
// REGISTER
// ========================
app.post("/register", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  if (users[email]) {
    return res.status(409).json({ error: "User already exists" });
  }

  users[email] = { email, password };

  return res.status(201).json({
    message: "User registered successfully",
    email,
  });
});

// ========================
// 1️⃣ LOGIN
// ========================
app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  if (!users[email] || users[email].password !== password) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const loginSessionId = Math.random().toString(36).substring(2, 10);
  const otp = Math.floor(100000 + Math.random() * 900000);

  loginSessions[loginSessionId] = {
    email,
    createdAt: Date.now(),
    expiresAt: Date.now() + 2 * 60 * 1000,
  };

  otpStore[loginSessionId] = otp;

  console.log(`[OTP] Session ${loginSessionId} generated | OTP: ${otp}`);

  return res.status(200).json({
    message: "OTP sent",
    loginSessionId,
  });
});

// ========================
// 2️⃣ VERIFY OTP
// ========================
app.post("/auth/verify-otp", (req, res) => {
  const { loginSessionId, otp } = req.body;

  if (!loginSessionId || !otp) {
    return res.status(400).json({
      error: "loginSessionId and otp required",
    });
  }

  const session = loginSessions[loginSessionId];

  if (!session) {
    return res.status(401).json({ error: "Invalid session" });
  }

  if (Date.now() > session.expiresAt) {
    delete loginSessions[loginSessionId];
    delete otpStore[loginSessionId];
    return res.status(401).json({ error: "Session expired" });
  }

  if (parseInt(otp) !== otpStore[loginSessionId]) {
    return res.status(401).json({ error: "Invalid OTP" });
  }

  res.cookie("session_token", loginSessionId, {
    httpOnly: true,
    maxAge: 15 * 60 * 1000,
    sameSite: "lax",
  });

  delete otpStore[loginSessionId];

  return res.status(200).json({
    message: "OTP verified",
  });
});

// ========================
// 3️⃣ GENERATE JWT
// ========================
app.post("/auth/token", (req, res) => {
  const sessionId = req.cookies.session_token;

  if (!sessionId) {
    return res.status(401).json({
      error: "Unauthorized - session cookie missing",
    });
  }

  const session = loginSessions[sessionId];

  if (!session) {
    return res.status(401).json({ error: "Invalid session" });
  }

  const secret = process.env.JWT_SECRET || "default-secret-key";

  const accessToken = jwt.sign(
    {
      email: session.email,
      sessionId,
    },
    secret,
    { expiresIn: "15m" }
  );

  return res.status(200).json({
    access_token: accessToken,
    expires_in: 900,
  });
});

// ========================
// 4️⃣ PROTECTED
// ========================
app.get("/protected", authMiddleware, (req, res) => {
  return res.json({
    message: "Access granted",
    user: req.user,
    success_flag: `FLAG-${Buffer.from(
      req.user.email + "_COMPLETED_ASSIGNMENT"
    ).toString("base64")}`,
  });
});

// ========================
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
