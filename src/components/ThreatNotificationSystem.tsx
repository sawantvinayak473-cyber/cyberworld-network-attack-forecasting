import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Zap,
  X,
  FileSearch,
  Bot,
  ShieldCheck,
  CheckCheck,
  Trash2,
  Radio,
  ArrowRight,
  Clock,
  AlertTriangle,
} from 'lucide-react';
import { ThreatNotification, Alert } from '../types';
import { ATTACK_STAGE_INFO } from '../mockData/scenarios';

interface ToastProps {
  notification: ThreatNotification;
  onDismiss: (id: string) => void;
  onInvestigate: (notification: ThreatNotification) => void;
  onSOAR: (notification: ThreatNotification) => void;
  onCopilot: (notification: ThreatNotification) => void;
}

const ThreatToastItem: React.FC<ToastProps> = ({
  notification,
  onDismiss,
  onInvestigate,
  onSOAR,
  onCopilot,
}) => {
  const [progress, setProgress] = useState(100);
  const [isPaused, setIsPaused] = useState(false);
  const durationMs = 8000;

  useEffect(() => {
    if (isPaused) return;
    const interval = 100;
    const step = (interval / durationMs) * 100;

    const timer = setInterval(() => {
      setProgress((prev) => {
        if (prev <= 0) {
          clearInterval(timer);
          onDismiss(notification.id);
          return 0;
        }
        return prev - step;
      });
    }, interval);

    return () => clearInterval(timer);
  }, [isPaused, notification.id, onDismiss]);

  const isCritical = notification.severity === 'CRITICAL';
  const isHigh = notification.severity === 'HIGH';

  const borderColor = isCritical
    ? 'border-rose-500/80 shadow-rose-950/70'
    : isHigh
    ? 'border-amber-500/80 shadow-amber-950/70'
    : 'border-cyan-500/80 shadow-cyan-950/70';

  const glowBadgeBg = isCritical
    ? 'bg-rose-500/20 text-rose-300 border-rose-600/60'
    : isHigh
    ? 'bg-amber-500/20 text-amber-300 border-amber-600/60'
    : 'bg-cyan-500/20 text-cyan-300 border-cyan-600/60';

  const currentStageInfo = ATTACK_STAGE_INFO[notification.currentStage];
  const nextStageInfo = ATTACK_STAGE_INFO[notification.predictedNextStage];

  return (
    <div
      onMouseEnter={() => setIsPaused(true)}
      onMouseLeave={() => setIsPaused(false)}
      className={`pointer-events-auto w-full rounded-xl border bg-slate-950/95 backdrop-blur-md p-3.5 shadow-2xl transition-all duration-300 transform animate-in slide-in-from-top-4 ${borderColor}`}
      role="alert"
    >
      {/* Top Meta Bar */}
      <div className="flex items-center justify-between gap-2 border-b border-slate-800/80 pb-2 mb-2.5">
        <div className="flex items-center gap-1.5 flex-wrap">
          <span
            className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider border uppercase ${glowBadgeBg}`}
          >
            {isCritical ? (
              <ShieldAlert className="w-3 h-3 text-rose-400 animate-pulse" />
            ) : (
              <Zap className="w-3 h-3 text-amber-400 animate-pulse" />
            )}
            {notification.severity} THREAT
          </span>

          {notification.earlyWarningSeconds > 0 && (
            <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-950/70 border border-amber-700/60 text-amber-300 text-[10px] font-mono font-semibold">
              <Clock className="w-2.5 h-2.5" />
              {notification.earlyWarningSeconds}s Lead Time
            </span>
          )}
        </div>

        <button
          onClick={() => onDismiss(notification.id)}
          className="text-slate-400 hover:text-slate-200 p-1 rounded-md hover:bg-slate-800/60 transition-colors"
          title="Dismiss notification"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Title & Stage Forecast */}
      <div className="mb-2">
        <h4 className="text-xs font-bold font-mono text-slate-100 flex items-center gap-1.5">
          <span>{notification.title}</span>
        </h4>
        <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-2">
          {notification.description}
        </p>

        {/* Attack Stage Progression */}
        <div className="mt-2 flex items-center gap-1.5 bg-slate-900/90 border border-slate-800 rounded-lg p-1.5 text-[11px] font-mono">
          <span className="text-slate-400 text-[10px]">STAGE:</span>
          <span className="font-semibold text-slate-200">
            {currentStageInfo?.name || notification.currentStage}
          </span>
          <ArrowRight className="w-3 h-3 text-emerald-400 mx-0.5" />
          <span className="font-semibold text-rose-400">
            {nextStageInfo?.name || notification.predictedNextStage}
          </span>
          <span className="ml-auto text-emerald-400 font-bold text-[10px]">
            {(notification.attackProbability * 100).toFixed(0)}% PROB
          </span>
        </div>
      </div>

      {/* Target & Source IP row */}
      <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-3 px-1">
        <span>SRC: <strong className="text-slate-200">{notification.sourceIp}</strong></span>
        <span>DST: <strong className="text-slate-200">{notification.destinationIp}</strong></span>
      </div>

      {/* Quick Action Buttons */}
      <div className="grid grid-cols-3 gap-1.5 pt-1 border-t border-slate-800/80">
        <button
          onClick={() => onInvestigate(notification)}
          className="flex items-center justify-center gap-1 px-2 py-1.5 rounded-lg bg-slate-850 hover:bg-slate-800 border border-slate-700 text-slate-200 text-[11px] font-mono transition-colors"
          title="Jump to Investigation View"
        >
          <FileSearch className="w-3 h-3 text-cyan-400" />
          <span>Investigate</span>
        </button>

        <button
          onClick={() => onSOAR(notification)}
          className="flex items-center justify-center gap-1 px-2 py-1.5 rounded-lg bg-rose-950/70 hover:bg-rose-900/80 border border-rose-700/80 text-rose-200 text-[11px] font-mono font-semibold transition-colors"
          title="Trigger SOAR Active Containment"
        >
          <ShieldCheck className="w-3 h-3 text-rose-400" />
          <span>1-Click Mitigate</span>
        </button>

        <button
          onClick={() => onCopilot(notification)}
          className="flex items-center justify-center gap-1 px-2 py-1.5 rounded-lg bg-emerald-950/70 hover:bg-emerald-900/80 border border-emerald-700/80 text-emerald-200 text-[11px] font-mono transition-colors"
          title="Triage with AI SOC Copilot"
        >
          <Bot className="w-3 h-3 text-emerald-400" />
          <span>Copilot</span>
        </button>
      </div>

      {/* Auto-dismiss progress bar */}
      <div className="w-full bg-slate-800/60 h-0.5 rounded-full mt-2.5 overflow-hidden">
        <div
          className={`h-full transition-all duration-100 ${
            isCritical ? 'bg-rose-500' : isHigh ? 'bg-amber-500' : 'bg-cyan-500'
          }`}
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  );
};

export const ThreatNotificationToastContainer: React.FC<{
  toasts: ThreatNotification[];
  onDismiss: (id: string) => void;
  onInvestigate: (notification: ThreatNotification) => void;
  onSOAR: (notification: ThreatNotification) => void;
  onCopilot: (notification: ThreatNotification) => void;
}> = ({ toasts, onDismiss, onInvestigate, onSOAR, onCopilot }) => {
  if (toasts.length === 0) return null;

  return (
    <aside
      aria-label="Live Threat Notifications"
      className="fixed top-16 right-4 z-50 flex flex-col gap-2.5 max-w-sm sm:max-w-md w-full pointer-events-none"
    >
      {toasts.map((toast) => (
        <ThreatToastItem
          key={toast.id}
          notification={toast}
          onDismiss={onDismiss}
          onInvestigate={onInvestigate}
          onSOAR={onSOAR}
          onCopilot={onCopilot}
        />
      ))}
    </aside>
  );
};

export const ThreatNotificationTray: React.FC<{
  isOpen: boolean;
  onClose: () => void;
  notifications: ThreatNotification[];
  onDismiss: (id: string) => void;
  onInvestigate: (notification: ThreatNotification) => void;
  onSOAR: (notification: ThreatNotification) => void;
  onCopilot: (notification: ThreatNotification) => void;
  onMarkAllRead: () => void;
  onClearAll: () => void;
}> = ({
  isOpen,
  onClose,
  notifications,
  onDismiss,
  onInvestigate,
  onSOAR,
  onCopilot,
  onMarkAllRead,
  onClearAll,
}) => {
  if (!isOpen) return null;

  const unreadCount = notifications.filter((n) => !n.isRead).length;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/50 backdrop-blur-xs transition-opacity animate-in fade-in">
      <div
        className="w-full max-w-md bg-[#090d16] border-l border-slate-800 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200"
        role="dialog"
        aria-modal="true"
        aria-label="Threat Notification Feed"
      >
        {/* Tray Header */}
        <div className="p-4 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-rose-500/20 border border-rose-500/40 flex items-center justify-center">
              <Radio className="w-4 h-4 text-rose-400 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold font-mono text-sm text-slate-100">
                  LIVE THREAT FEED
                </h3>
                {unreadCount > 0 && (
                  <span className="px-1.5 py-0.2 rounded bg-rose-500/20 border border-rose-500/50 text-rose-300 font-mono text-[10px] font-bold">
                    {unreadCount} NEW
                  </span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 font-mono">
                Predictive Kill-Chain & Anomaly Broadcast
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/80 transition-colors"
            title="Close tray"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Toolbar: Mark all read / Clear */}
        <div className="px-4 py-2 border-b border-slate-850 bg-slate-950/40 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-500 text-[11px]">
            {notifications.length} Total Incident Broadcasts
          </span>
          <div className="flex items-center gap-3">
            {unreadCount > 0 && (
              <button
                onClick={onMarkAllRead}
                className="flex items-center gap-1 text-slate-400 hover:text-emerald-400 transition-colors"
                title="Mark all notifications as read"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                <span>Mark Read</span>
              </button>
            )}
            {notifications.length > 0 && (
              <button
                onClick={onClearAll}
                className="flex items-center gap-1 text-slate-400 hover:text-rose-400 transition-colors"
                title="Clear notification history"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}
          </div>
        </div>

        {/* Notification List */}
        <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
          {notifications.length === 0 ? (
            <div className="h-64 flex flex-col items-center justify-center text-center p-6 text-slate-500 font-mono">
              <ShieldCheck className="w-10 h-10 text-emerald-500/40 mb-2" />
              <p className="text-xs font-semibold text-slate-300">
                Network Telemetry Normal
              </p>
              <p className="text-[11px] text-slate-500 mt-1 max-w-xs">
                No active threat escalations detected. Run attack simulation or hardware sniffer to see live telemetry alerts.
              </p>
            </div>
          ) : (
            notifications.map((item) => {
              const isCrit = item.severity === 'CRITICAL';
              const isH = item.severity === 'HIGH';
              const currInfo = ATTACK_STAGE_INFO[item.currentStage];
              const nextInfo = ATTACK_STAGE_INFO[item.predictedNextStage];

              return (
                <div
                  key={item.id}
                  className={`rounded-xl border p-3 transition-all font-mono ${
                    !item.isRead
                      ? isCrit
                        ? 'border-rose-500/70 bg-rose-950/20'
                        : isH
                        ? 'border-amber-500/70 bg-amber-950/20'
                        : 'border-cyan-500/70 bg-cyan-950/20'
                      : 'border-slate-800 bg-slate-900/60 opacity-80 hover:opacity-100'
                  }`}
                >
                  <div className="flex items-center justify-between gap-1.5 mb-1.5">
                    <div className="flex items-center gap-1.5">
                      {!item.isRead && (
                        <span className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
                      )}
                      <span
                        className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase border ${
                          isCrit
                            ? 'bg-rose-500/20 text-rose-300 border-rose-600/50'
                            : isH
                            ? 'bg-amber-500/20 text-amber-300 border-amber-600/50'
                            : 'bg-cyan-500/20 text-cyan-300 border-cyan-600/50'
                        }`}
                      >
                        {item.severity}
                      </span>
                      <span className="text-[10px] text-slate-400">
                        {item.timeOffsetSeconds !== undefined
                          ? `T+${item.timeOffsetSeconds}s`
                          : item.timestamp}
                      </span>
                    </div>

                    {item.earlyWarningSeconds > 0 && (
                      <span className="text-[10px] text-amber-400 font-semibold">
                        ⚡ {item.earlyWarningSeconds}s Lead
                      </span>
                    )}
                  </div>

                  <h5 className="text-xs font-bold text-slate-200 mb-1">
                    {item.title}
                  </h5>

                  <div className="text-[11px] bg-slate-950/60 rounded p-1.5 mb-2 border border-slate-800/80 flex items-center justify-between text-slate-300">
                    <span className="text-slate-400">{currInfo?.name || item.currentStage}</span>
                    <ArrowRight className="w-3 h-3 text-emerald-400" />
                    <span className="text-rose-400 font-semibold">{nextInfo?.name || item.predictedNextStage}</span>
                    <span className="text-emerald-400 font-bold ml-1">
                      {(item.attackProbability * 100).toFixed(0)}%
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-400 mb-2">
                    <span>SRC: <span className="text-slate-300">{item.sourceIp}</span></span>
                    <span>DST: <span className="text-slate-300">{item.destinationIp}</span></span>
                  </div>

                  <div className="flex items-center gap-1.5 pt-1.5 border-t border-slate-800/60">
                    <button
                      onClick={() => onInvestigate(item)}
                      className="flex-1 py-1 rounded bg-slate-800 hover:bg-slate-750 text-slate-200 text-[10px] flex items-center justify-center gap-1"
                    >
                      <FileSearch className="w-2.5 h-2.5 text-cyan-400" />
                      Investigate
                    </button>
                    <button
                      onClick={() => onSOAR(item)}
                      className="flex-1 py-1 rounded bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-rose-200 text-[10px] flex items-center justify-center gap-1 font-semibold"
                    >
                      <ShieldCheck className="w-2.5 h-2.5 text-rose-400" />
                      Mitigate
                    </button>
                    <button
                      onClick={() => onCopilot(item)}
                      className="flex-1 py-1 rounded bg-emerald-950/80 hover:bg-emerald-900 border border-emerald-800 text-emerald-200 text-[10px] flex items-center justify-center gap-1"
                    >
                      <Bot className="w-2.5 h-2.5 text-emerald-400" />
                      Copilot
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Tray Footer */}
        <div className="p-3 border-t border-slate-800 bg-slate-950 text-center text-[10px] font-mono text-slate-500">
          World Model Predictive Network Defence &bull; Telemetry Engine Active
        </div>
      </div>
    </div>
  );
};
