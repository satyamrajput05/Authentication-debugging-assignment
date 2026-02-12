const getSecretFromDB = async () => {
  // Simulate DB latency
  await new Promise((resolve) => setTimeout(resolve, 120));

  // Fallback so assignment never silently breaks
  if (!process.env.APPLICATION_SECRET) {
    return process.env.JWT_SECRET || "default-secret-key";
  }

  return process.env.APPLICATION_SECRET;
};

module.exports = { getSecretFromDB };
