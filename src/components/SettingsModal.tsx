import React, { useState } from 'react';
import { X, Settings, ShieldCheck, Save, Sliders } from 'lucide-react';
import { SystemConfig } from '../types';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  config: SystemConfig;
  onSaveConfig: (cfg: SystemConfig) => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  config,
  onSaveConfig,
}) => {
  if (!isOpen) return null;

  const [localConfig, setLocalConfig] = useState<SystemConfig>({ ...config });
  const [savedMessage, setSavedMessage] = useState(false);

  const handleSave = () => {
    onSaveConfig(localConfig);
    setSavedMessage(true);
    setTimeout(() => {
      setSavedMessage(false);
      onClose();
    }, 1000);
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-750 rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden font-mono text-xs">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-2">
            <Settings className="w-5 h-5 text-emerald-400" />
            <h3 className="text-sm font-bold text-slate-100">
              CYBERWORLD OPERATIONAL CONFIGURATION
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-4 text-slate-300">
          {/* Risk Thresholds */}
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
            <h4 className="text-slate-200 font-bold uppercase text-[11px] text-cyan-400 flex items-center justify-between">
              <span>Threat Level Risk Thresholds</span>
              <span className="text-slate-500 text-[10px]">P(A) Cutoffs</span>
            </h4>

            <div className="space-y-2">
              <div>
                <div className="flex justify-between text-[11px] text-amber-400 mb-1">
                  <span>Elevated Risk Threshold</span>
                  <span>{(localConfig.riskThresholds.normal * 100).toFixed(0)}%</span>
                </div>
                <input
                  type="range"
                  min="0.1"
                  max="0.5"
                  step="0.05"
                  value={localConfig.riskThresholds.normal}
                  onChange={(e) =>
                    setLocalConfig({
                      ...localConfig,
                      riskThresholds: {
                        ...localConfig.riskThresholds,
                        normal: Number(e.target.value),
                      },
                    })
                  }
                  className="w-full accent-amber-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-[11px] text-orange-400 mb-1">
                  <span>High Risk Threshold</span>
                  <span>{(localConfig.riskThresholds.elevated * 100).toFixed(0)}%</span>
                </div>
                <input
                  type="range"
                  min="0.5"
                  max="0.8"
                  step="0.05"
                  value={localConfig.riskThresholds.elevated}
                  onChange={(e) =>
                    setLocalConfig({
                      ...localConfig,
                      riskThresholds: {
                        ...localConfig.riskThresholds,
                        elevated: Number(e.target.value),
                      },
                    })
                  }
                  className="w-full accent-orange-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-[11px] text-red-400 mb-1">
                  <span>Critical Risk Threshold</span>
                  <span>{(localConfig.riskThresholds.high * 100).toFixed(0)}%</span>
                </div>
                <input
                  type="range"
                  min="0.8"
                  max="0.95"
                  step="0.05"
                  value={localConfig.riskThresholds.high}
                  onChange={(e) =>
                    setLocalConfig({
                      ...localConfig,
                      riskThresholds: {
                        ...localConfig.riskThresholds,
                        high: Number(e.target.value),
                      },
                    })
                  }
                  className="w-full accent-red-500"
                />
              </div>
            </div>
          </div>

          {/* Temporal Window & Horizon */}
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 grid grid-cols-2 gap-3">
            <div>
              <label className="text-slate-400 text-[10px] uppercase block mb-1">
                Window Duration
              </label>
              <select
                value={localConfig.defaultWindowSeconds}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, defaultWindowSeconds: Number(e.target.value) })
                }
                className="w-full bg-slate-900 border border-slate-750 rounded px-2.5 py-1.5 text-slate-200"
              >
                <option value={10}>10 Seconds (Recommended)</option>
                <option value={30}>30 Seconds</option>
                <option value={60}>60 Seconds</option>
                <option value={120}>120 Seconds</option>
              </select>
            </div>

            <div>
              <label className="text-slate-400 text-[10px] uppercase block mb-1">
                Forecast Horizon K
              </label>
              <select
                value={localConfig.forecastHorizon}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, forecastHorizon: Number(e.target.value) })
                }
                className="w-full bg-slate-900 border border-slate-750 rounded px-2.5 py-1.5 text-slate-200"
              >
                <option value={5}>5 Steps (50s)</option>
                <option value={10}>10 Steps (100s)</option>
              </select>
            </div>
          </div>

          {/* Deduplication & Active Model */}
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
            <div>
              <label className="text-slate-400 text-[10px] uppercase block mb-1">
                Alert Deduplication Suppression Window (Sec)
              </label>
              <input
                type="number"
                value={localConfig.deduplicationWindowSeconds}
                onChange={(e) =>
                  setLocalConfig({
                    ...localConfig,
                    deduplicationWindowSeconds: Number(e.target.value),
                  })
                }
                className="w-full bg-slate-900 border border-slate-750 rounded px-2.5 py-1.5 text-slate-200"
              />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-3 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
          <span className="text-emerald-400 text-xs">
            {savedMessage && 'Configuration saved successfully!'}
          </span>
          <div className="flex space-x-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold flex items-center space-x-1"
            >
              <Save className="w-3.5 h-3.5" />
              <span>Save Changes</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
