const processRequest = (config, history) => {
  const { rps, userAgent, path } = config;

  // Layer 1: Volumetric (Rate Limiting)
  if (rps > 10) {
    return { status: 429, label: 'VOLUMETRIC_BLOCK', message: 'Rate Limit Triggered' };
  }

  // Layer 2: Signature (Fingerprinting)
  if (userAgent.toLowerCase().includes('python') || userAgent.toLowerCase().includes('curl')) {
    return { status: 403, label: 'SIGNATURE_MATCH', message: 'Bot Signature Detected' };
  }

  // Layer 3: Behavioral (Pattern Analysis)
  const loginAttempts = history.filter(h => h.path === '/login').length;
  if (loginAttempts > 20 && path === '/login') {
    return { status: 401, label: 'CHALLENGE_REQUIRED', message: 'Anomaly: Credential Stuffing' };
  }

  return { status: 200, label: 'CLEAN_TRAFFIC', message: 'Verified Request' };
};