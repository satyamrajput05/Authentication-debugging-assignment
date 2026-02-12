const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
  const authHeader = req.headers.authorization;

  // Authorization header missing
  if (!authHeader) {
    return res.status(401).json({ error: "Unauthorized - token missing" });
  }

  // Must start with Bearer
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Invalid token format" });
  }

  const token = authHeader.split(" ")[1];
  const secret = process.env.JWT_SECRET || "default-secret-key";

  try {
    const decoded = jwt.verify(token, secret);

    // Attach decoded payload to request
    req.user = decoded;

    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};
