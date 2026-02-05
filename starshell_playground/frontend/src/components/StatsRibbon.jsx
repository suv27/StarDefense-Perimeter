import React from 'react';
import { Activity, ShieldAlert, CheckCircle } from 'lucide-react';

const StatsRibbon = ({ events = [] }) => {
  // Logic is now calculated instantly from the events list
  const throughput = events.length;
  const threats = events.filter(e => e.verdict === 'BLOCK' || e.message?.includes('blocked')).length;
  const clean = throughput - threats;

  const stats = [
    { title: "Total Throughput", value: throughput, icon: Activity, bg: 'bg-blue-500/10', text: 'text-blue-400' },
    { title: "Threats Mitigated", value: threats, icon: ShieldAlert, bg: 'bg-red-500/10', text: 'text-red-500' },
    { title: "Clean Traffic", value: clean, icon: CheckCircle, bg: 'bg-green-500/10', text: 'text-emerald-500' }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
      {stats.map((s, i) => (
        <div key={i} className="bg-defense-card border border-slate-700 p-4 rounded-lg flex items-center gap-4">
          <div className={`p-3 rounded-full ${s.bg}`}>
            <s.icon className={s.text} size={24} />
          </div>
          <div>
            <p className="text-slate-400 text-xs uppercase tracking-wider font-bold">{s.title}</p>
            <p className="text-2xl font-mono font-bold text-white">{s.value}</p>
          </div>
        </div>
      ))}
    </div>
  );
};

export default StatsRibbon;