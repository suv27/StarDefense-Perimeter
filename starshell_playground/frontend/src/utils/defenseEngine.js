// src/utils/defenseEngine.js

export const calculateRisk = (config) => {
  let score = 0.1; // Base score

  // 1. Volumetric (RPS) logic
  if (config.rps > 15) score += 0.3;
  if (config.rps > 50) score += 0.5;

  // 2. Signature logic
  const isBotUA = /python|curl|postman/i.test(config.userAgent);
  if (isBotUA) score += 0.5;

  // 3. Path logic
  if (config.path.includes('/login')) score += 0.2;

  const finalScore = Math.min(score, 1.0).toFixed(4);
  
  let level = 'CLEAN';
  let color = 'text-emerald-500';
  if (finalScore > 0.4) { level = 'SUSPICIOUS'; color = 'text-yellow-500'; }
  if (finalScore > 0.7) { level = 'CRITICAL'; color = 'text-red-500'; }

  return { score: finalScore, threatLevel: level, color };
};