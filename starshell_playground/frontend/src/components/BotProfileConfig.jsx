// src/components/BotProfileConfig.jsx
const BotProfileConfig = ({ config, onUpdate }) => {
  return (
    <div className="p-4 bg-slate-900 rounded-lg">
      <label className="text-xs text-slate-500 uppercase">Request Rate (RPS)</label>
      <input 
        type="range" 
        className="w-full accent-cyan-400"
        min="1" 
        max="100" 
        value={config.rps}
        onChange={(e) => onUpdate({ rps: parseInt(e.target.value) })}
      />
      <div className="flex justify-between text-[10px] font-mono text-cyan-400">
        <span>1.0</span>
        <span>{config.rps}.0</span>
        <span>100.0</span>
      </div>
    </div>
  );
};