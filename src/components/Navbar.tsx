import React from 'react';
import {
  ShieldAlert,
  Radio,
  Clock,
  TrendingUp,
  AlertTriangle,
  FileSearch,
  ClipboardList,
  Cpu,
  BarChart3,
  Database,
  Play,
  Pause,
  RotateCcw,
  StepForward,
  Download,
  Settings,
  GitBranch,
  SlidersHorizontal,
  Presentation,
  Bell,
} from 'lucide-react';
import { SIMULATION_SCENARIOS } from '../mockData/scenarios';

const QUICK_SCENARIOS = [
  { label: 'Port Scan', scenarioId: 'full-killchain', windowIndex: 6 },
  { label: 'Brute Force', scenarioId: 'full-killchain', windowIndex: 10 },
  { label: 'C2 Beacon', scenarioId: 'stealth-c2', windowIndex: 8 },
  { label: 'Exfiltration', scenarioId: 'data-exfiltration', windowIndex: 16 },
];

interface NavbarProps {
  currentTab: string;
  setCurrentTab: (tab: string) => void;
  activeScenarioId: string;
  onSelectScenario: (id: string) => void;
  isSimulating: boolean;
  onToggleSimulate: () => void;
  onStepForward: () => void;
  onResetSimulation: () => void;
  simSpeed: number;
  setSimSpeed: (speed: number) => void;
  onOpenReportModal: () => void;
  onOpenSettingsModal: () => void;
  onOpenCopilot: () => void;
  currentWindow: number;
  totalWindows: number;
  threatLevel: string;
  isDemoMode: boolean;
  onToggleDemoMode: () => void;
  demoStepIndex: number;
  demoStepCount: number;
  onDemoPrevious: () => void;
  onDemoNext: () => void;
  onQuickScenario: (scenarioId: string, windowIndex: number) => void;
  unreadNotificationCount?: number;
  onToggleNotificationTray?: () => void;
  isNotificationTrayOpen?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  activeScenarioId,
  onSelectScenario,
  isSimulating,
  onToggleSimulate,
  onStepForward,
  onResetSimulation,
  simSpeed,
  setSimSpeed,
  onOpenReportModal,
  onOpenSettingsModal,
  onOpenCopilot,
  currentWindow,
  totalWindows,
  threatLevel,
  isDemoMode,
  onToggleDemoMode,
  demoStepIndex,
  demoStepCount,
  onDemoPrevious,
  onDemoNext,
  onQuickScenario,
  unreadNotificationCount = 0,
  onToggleNotificationTray,
  isNotificationTrayOpen = false,
}) => {
  const tabs = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: TrendingUp },
    { id: 'live-monitor', label: 'Live Monitor & Replay', icon: Radio },
    { id: 'forecasts', label: 'Infiltration Forecasts', icon: Clock },
    { id: 'what-if', label: 'What-If Simulator', icon: SlidersHorizontal },
    { id: 'digital-twin', label: 'Attack Digital Twin', icon: GitBranch },
    { id: 'alerts', label: 'Alerts & Incidents', icon: AlertTriangle },
    { id: 'timeline', label: 'Incident Timeline', icon: Clock },
    { id: 'investigation', label: 'Investigation', icon: FileSearch },
    { id: 'cases', label: 'SOC Cases', icon: ClipboardList },
    { id: 'explainability', label: 'SHAP Explainability', icon: Cpu },
    { id: 'benchmarks', label: 'Model Benchmarks', icon: BarChart3 },
    { id: 'datasets', label: 'Datasets & Training', icon: Database },
  ];

  return (
    <header className="border-b border-slate-800 bg-[#090d16]/95 backdrop-blur sticky top-0 z-40">
      {/* Top Identity & Quick Simulation Bar */}
      <div className="px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 border-b border-slate-850">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-emerald-500/20 via-cyan-500/20 to-blue-600/30 border border-emerald-500/40 flex items-center justify-center shadow-lg shadow-emerald-950/40">
            <ShieldAlert className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-wider text-slate-100 font-mono">
                CYBER<span className="text-emerald-400">WORLD</span>
              </span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 font-semibold">
                World Model v1.2
              </span>
            </div>
            <p className="text-xs text-slate-400 hidden sm:block">
              Predictive Network Defence &bull;{' '}
              <span className="text-slate-300 italic">"Don't just detect the attack. Forecast where it goes next."</span>
            </p>
          </div>
        </div>

        {/* Live Simulation Controls & Scenario Selector */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Scenario selector */}
          <select
            value={activeScenarioId}
            onChange={(e) => onSelectScenario(e.target.value)}
            className="bg-slate-900 border border-slate-750 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-emerald-500 font-mono"
          >
            {activeScenarioId === 'uploaded' && (
              <option value="uploaded">Uploaded Telemetry Replay</option>
            )}
            {SIMULATION_SCENARIOS.map((sc) => (
              <option key={sc.id} value={sc.id}>
                {sc.name}
              </option>
            ))}
          </select>

          {/* Speed selector */}
          <div className="flex items-center bg-slate-900 rounded-lg border border-slate-750 p-0.5">
            {[0.5, 1, 2, 5].map((spd) => (
              <button
                key={spd}
                onClick={() => setSimSpeed(spd)}
                className={`px-2 py-1 text-xs font-mono rounded ${
                  simSpeed === spd
                    ? 'bg-emerald-600 text-white font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {spd}x
              </button>
            ))}
          </div>

          {/* Replay controller buttons */}
          <div className="flex items-center space-x-1">
            <button
              onClick={onToggleSimulate}
              id="btn-toggle-sim"
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold font-mono shadow transition-all ${
                isSimulating
                  ? 'bg-amber-600 hover:bg-amber-500 text-white shadow-amber-950/50'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-950/50'
              }`}
            >
              {isSimulating ? (
                <>
                  <Pause className="w-3.5 h-3.5" />
                  <span>PAUSE</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>START ATTACK SIM</span>
                </>
              )}
            </button>

            <button
              onClick={onStepForward}
              title="Step forward 10s window"
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-750"
            >
              <StepForward className="w-3.5 h-3.5" />
            </button>

            <button
              onClick={onResetSimulation}
              title="Reset simulation to T=0"
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-750"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Guided SIH demonstration controls */}
          <div className="flex items-center gap-1.5">
            {isDemoMode && (
              <>
                <button
                  type="button"
                  onClick={onDemoPrevious}
                  disabled={demoStepIndex === 0}
                  className="rounded-lg border border-amber-700/80 bg-amber-950/40 px-2 py-1.5 text-xs font-mono font-semibold text-amber-200 transition-colors hover:bg-amber-900/50 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  ← Prev
                </button>
                <span className="whitespace-nowrap text-[11px] font-mono font-bold text-amber-400">
                  Step {demoStepIndex + 1} / {demoStepCount}
                </span>
                <button
                  type="button"
                  onClick={onDemoNext}
                  disabled={demoStepIndex === demoStepCount - 1}
                  className="rounded-lg border border-amber-700/80 bg-amber-950/40 px-2 py-1.5 text-xs font-mono font-semibold text-amber-200 transition-colors hover:bg-amber-900/50 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Next →
                </button>
              </>
            )}
            <button
              type="button"
              onClick={onToggleDemoMode}
              className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs font-mono font-bold transition-colors ${
                isDemoMode
                  ? 'border-amber-300 bg-amber-500 text-slate-950 shadow-lg shadow-amber-950/60'
                  : 'border-amber-700/80 bg-amber-950/45 text-amber-300 hover:bg-amber-900/60 hover:text-amber-100'
              }`}
              title="Start the guided SIH demonstration"
              aria-pressed={isDemoMode}
            >
              <Presentation className="h-3.5 w-3.5" />
              <span>Demo Mode</span>
            </button>
          </div>

          {/* Window progress badge */}
          <div className="flex items-center space-x-2 bg-slate-900/80 border border-slate-800 px-2.5 py-1.5 rounded-lg text-xs font-mono">
            <span className="text-slate-400">Window:</span>
            <span className="text-emerald-400 font-bold">
              {currentWindow + 1}/{totalWindows}
            </span>
            <span className="text-slate-500">({(currentWindow + 1) * 10}s)</span>
          </div>

          {/* Actions: Notification Bell, Copilot, Report & Settings */}
          {onToggleNotificationTray && (
            <button
              onClick={onToggleNotificationTray}
              className={`relative p-1.5 rounded-lg border transition-colors ${
                isNotificationTrayOpen
                  ? 'bg-rose-950/80 border-rose-500/80 text-rose-300 shadow-md shadow-rose-950/40'
                  : unreadNotificationCount > 0
                  ? 'bg-slate-850 hover:bg-slate-800 border-rose-700/60 text-rose-400'
                  : 'bg-slate-850 hover:bg-slate-800 border-slate-700 text-slate-300'
              }`}
              title="Live Threat Notifications"
            >
              <Bell className="w-3.5 h-3.5" />
              {unreadNotificationCount > 0 && (
                <span className="absolute -top-1 -right-1 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-rose-600 px-1 text-[9px] font-bold text-white shadow-sm ring-2 ring-slate-900 animate-pulse font-mono">
                  {unreadNotificationCount > 9 ? '9+' : unreadNotificationCount}
                </span>
              )}
            </button>
          )}

          <button
            onClick={onOpenCopilot}
            className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg border border-emerald-600/70 bg-emerald-950/50 text-emerald-300 text-xs font-mono transition-colors hover:bg-emerald-900/60 hover:text-emerald-100"
            title="Open AI SOC Copilot"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span className="hidden md:inline">Copilot</span>
          </button>

          <button
            onClick={onOpenReportModal}
            className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg bg-slate-850 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono"
            title="Export SOC Incident Report"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden md:inline">Report</span>
          </button>

          <button
            onClick={onOpenSettingsModal}
            className="p-1.5 rounded-lg bg-slate-850 hover:bg-slate-800 border border-slate-700 text-slate-300"
            title="System Settings"
          >
            <Settings className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Navigation Tab Bar */}
      <nav className="px-4 flex space-x-1 overflow-x-auto py-1.5 scrollbar-none">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = currentTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setCurrentTab(tab.id)}
              className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-colors ${
                isActive
                  ? 'bg-slate-800 text-emerald-400 border border-slate-700 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-emerald-400' : 'text-slate-500'}`} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </nav>

      <div className="flex items-center gap-1.5 overflow-x-auto border-t border-slate-850 px-4 py-1.5 scrollbar-none">
        <span className="mr-1 whitespace-nowrap text-[10px] font-mono font-bold tracking-wider text-slate-500">QUICK SCENARIO</span>
        {QUICK_SCENARIOS.map(({ label, scenarioId, windowIndex }) => (
          <button
            key={scenarioId + label}
            type="button"
            onClick={() => onQuickScenario(scenarioId, windowIndex)}
            className="whitespace-nowrap rounded-full border border-slate-700 bg-slate-900 px-2.5 py-1 text-[10px] font-mono text-slate-300 transition-colors hover:border-cyan-700 hover:text-cyan-300"
          >
            {label}
          </button>
        ))}
      </div>
    </header>
  );
};
