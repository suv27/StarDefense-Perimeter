import React from 'react';
import { Terminal, ShieldCheck, ShieldAlert, Clock } from 'lucide-react';

const LiveEventLog = ({ events }) => {
  return (
    <div className="glass-panel rounded-2xl overflow-hidden relative min-h-[600px]">
      <div className="scanline" />
      
      <div className="bg-white/5 p-5 flex justify-between items-center border-b border-white/5">
        <div className="flex items-center gap-3">
          <Terminal size={18} className="text-cyan-400" />
          <h2 className="text-xs font-black text-white uppercase tracking-[0.3em]">Defense Live Stream</h2>
        </div>
        <div className="flex items-center gap-4 text-[9px] font-bold text-slate-500">
          <span className="hidden md:inline">PROTOCOL: L7_SECURE_v2</span>
          <div className="flex items-center gap-2 px-3 py-1 bg-red-500/10 rounded-full border border-red-500/20">
            <span className="w-2 h-2 rounded-full bg-red-500 pulse-glow" />
            <span className="text-red-500">LIVE INTERCEPT</span>
          </div>
        </div>
      </div>

      <div className="p-6 space-y-4 max-h-[700px] overflow-y-auto custom-scrollbar relative z-20">
        {events.length === 0 ? (
          <div className="h-[400px] flex flex-col items-center justify-center opacity-20">
            <ShieldCheck size={64} className="mb-4" />
            <p className="text-[10px] uppercase tracking-[0.5em]">System Idle // Waiting for Traffic</p>
          </div>
        ) : (
          events.map((event, i) => {
            const isBlocked = event.status === 'blocked' || event.verdict === 'BLOCK';
            return (
              <div key={i} className={`glass-panel border-l-4 p-4 transition-all duration-300 ${isBlocked ? 'border-l-red-500 bg-red-500/5' : 'border-l-emerald-500 bg-emerald-500/5'}`}>
                <div className="flex justify-between items-center mb-3">
                  <span className={`text-[9px] font-black px-2 py-0.5 rounded tracking-widest ${isBlocked ? 'text-red-500 bg-red-500/10' : 'text-emerald-400 bg-emerald-500/10'}`}>
                    {isBlocked ? 'THREAT NEUTRALIZED' : 'CLEAN TRAFFIC'}
                  </span>
                  <span className="text-[9px] font-mono text-slate-500 flex items-center gap-1 uppercase"><Clock size={10}/> {event.timestamp}</span>
                </div>
                <div className="flex gap-6 font-mono">
                  <div className="flex flex-col"><span className="text-[8px] text-slate-500 font-bold uppercase">Method</span><span className="text-xs text-cyan-400 font-bold">{event.method}</span></div>
                  <div className="flex flex-col"><span className="text-[8px] text-slate-500 font-bold uppercase">Target Path</span><span className="text-xs text-slate-300">{event.path}</span></div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default LiveEventLog;