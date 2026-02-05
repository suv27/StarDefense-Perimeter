import React, { useState, useEffect } from 'react';
import StatsRibbon from './components/StatsRibbon';
import LiveEventLog from './components/LiveEventLog';
import { Shield, Zap, Activity, Cpu, Globe } from 'lucide-react';

const calculateRisk = (config) => {
  let score = 0.1000;
  if (config.rps > 15) score += 0.3500;
  if (config.rps > 60) score += 0.4500;
  const isBotUA = /python|curl|postman/i.test(config.userAgent);
  if (isBotUA) score += 0.5000;
  if (config.path.includes('/login')) score += 0.1500;

  const finalScore = Math.min(score, 1.0).toFixed(4);
  let level = 'BEHAVIORAL';
  let color = 'text-emerald-400';
  let border = 'border-emerald-500/20';

  if (finalScore > 0.45) { level = 'PATTERN'; color = 'text-yellow-400'; border = 'border-yellow-500/20'; }
  if (finalScore > 0.80) { level = 'SIGNATURE'; color = 'text-red-500'; border = 'border-red-500/40'; }

  return { score: finalScore, threatLevel: level, color, border };
};

function App() {
  const [events, setEvents] = useState([]);
  const [attackConfig, setAttackConfig] = useState({ rps: 1, userAgent: 'Chrome/121.0', path: '/api/v1/data', isInitiated: false });
  const [riskMetrics, setRiskMetrics] = useState(calculateRisk(attackConfig));

  useEffect(() => {
    if (!attackConfig.isInitiated) return;
    const interval = setInterval(() => {
      const currentRisk = calculateRisk(attackConfig);
      const newEvent = {
        timestamp: new Date().toLocaleTimeString(),
        method: 'GET',
        path: attackConfig.path,
        verdict: parseFloat(currentRisk.score) > 0.75 ? 'BLOCK' : 'ALLOW',
        status: parseFloat(currentRisk.score) > 0.75 ? 'blocked' : 'allowed'
      };
      setEvents(prev => [newEvent, ...prev].slice(0, 50));
      setRiskMetrics(currentRisk);
    }, 1000 / Math.min(attackConfig.rps, 10));
    return () => clearInterval(interval);
  }, [attackConfig]);

  const updateConfig = (params) => {
    const updated = { ...attackConfig, ...params };
    setAttackConfig(updated);
    setRiskMetrics(calculateRisk(updated));
  };

  return (
    <div className="p-6 max-w-[1600px] mx-auto">
      <header className="flex justify-between items-center mb-10">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/50 rounded-lg shadow-[0_0_15px_rgba(6,182,212,0.3)]">
            <Shield size={32} className="text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-black italic tracking-tighter text-glow-cyan uppercase">Star Defense <span className="text-white">Perimeter</span></h1>
            <div className="flex gap-3 text-[9px] text-slate-500 font-bold tracking-[0.2em]">
              <span className="flex items-center gap-1"><Cpu size={10}/> SYS_ACTIVE</span>
              <span className="flex items-center gap-1"><Globe size={10}/> NODE: US-EAST-01</span>
            </div>
          </div>
        </div>
      </header>

      <StatsRibbon events={events} />

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 mt-8">
        <aside className="space-y-6">
          <div className="glass-panel p-6 rounded-2xl">
            <h2 className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-6 flex items-center gap-2">
              <Zap size={12} className="text-yellow-400" /> Bot Profile Configuration
            </h2>
            <div className="space-y-8">
              <div>
                <div className="flex justify-between text-[10px] mb-3 font-bold">
                  <span className="text-slate-500">REQUEST RATE</span>
                  <span className="text-cyan-400">{attackConfig.rps} RPS</span>
                </div>
                <input type="range" min="1" max="100" value={attackConfig.rps} onChange={(e) => updateConfig({ rps: parseInt(e.target.value) })} className="w-full accent-cyan-400 bg-slate-800 h-1 rounded-lg appearance-none" />
              </div>
              <button onClick={() => updateConfig({ isInitiated: !attackConfig.isInitiated })} 
                className={`w-full py-4 rounded-xl font-black text-[10px] tracking-[0.2em] transition-all border-b-4 ${attackConfig.isInitiated ? 'bg-red-900/20 text-red-500 border-red-600 shadow-[0_0_20px_rgba(220,38,38,0.2)] animate-pulse' : 'bg-cyan-950/20 text-cyan-400 border-cyan-600'}`}>
                {attackConfig.isInitiated ? ':: TERMINATE ATTACK ::' : ':: COMMENCE INFILTRATION ::'}
              </button>
            </div>
          </div>

          <div className={`glass-panel p-8 rounded-2xl text-center border-t-2 ${riskMetrics.border} transition-all duration-500`}>
            <Activity size={24} className={`mx-auto mb-4 ${riskMetrics.color} opacity-50`} />
            <div className="relative inline-block">
               <svg className="w-32 h-20">
                 <path d="M 10 70 A 50 50 0 0 1 120 70" fill="none" stroke="#1e293b" strokeWidth="8" strokeLinecap="round" />
                 <path d="M 10 70 A 50 50 0 0 1 120 70" fill="none" stroke="currentColor" strokeWidth="8" strokeLinecap="round" className={riskMetrics.color} style={{ strokeDasharray: 180, strokeDashoffset: 180 - (180 * parseFloat(riskMetrics.score)) }} />
               </svg>
               <div className={`absolute top-10 left-0 right-0 text-3xl font-black font-mono tracking-tighter ${riskMetrics.color}`}>
                 {riskMetrics.score}
               </div>
            </div>
            <p className="text-[9px] text-slate-500 uppercase font-bold mt-4">Risk Index / {riskMetrics.threatLevel}</p>
          </div>
        </aside>

        <section className="lg:col-span-3">
          <LiveEventLog events={events} />
        </section>
      </div>
    </div>
  );
}

export default App;