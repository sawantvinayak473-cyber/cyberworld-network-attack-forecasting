/**
 * CYBERWORLD — Predictive Network Defence Using World Models
 * "Don't just detect the attack. Forecast where it goes next."
 */

import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { KPICards } from './components/KPICards';
import { DashboardView } from './components/DashboardView';
import { LiveMonitorView } from './components/LiveMonitorView';
import { ForecastView } from './components/ForecastView';
import { WhatIfSimulatorView } from './components/WhatIfSimulatorView';
import { AttackDigitalTwin } from './components/AttackDigitalTwin';
import { AlertsView } from './components/AlertsView';
import { IncidentTimelineView } from './components/IncidentTimelineView';
import { InvestigationView } from './components/InvestigationView';
import { CaseManagementView } from './components/CaseManagementView';
import { ExplainabilityView } from './components/ExplainabilityView';
import { BenchmarksView } from './components/BenchmarksView';
import { DatasetTrainingView } from './components/DatasetTrainingView';
import { ReportModal } from './components/ReportModal';
import { SettingsModal } from './components/SettingsModal';
import { CopilotDrawer } from './components/CopilotDrawer';
import type { CopilotContext } from './api/copilotApi';
import {
  createCase,
  getAllCases,
} from './engine/caseStorage';
import type { SOCCase } from './engine/caseStorage';
import {
  generateScenarioData,
  computeWorldModelInference,
  computeEWES,
  computeResidualAnomaly,
  getSeverityFromProb,
  getRiskLevel,
} from './engine/worldModelSimulator';
import { DEMO_SCRIPT } from './engine/demoScript';
import {
  fetchExplainability,
  fetchForecast,
  fetchPrediction,
} from './api/cyberWorldApi';
import {
  Alert,
  AlertStatus,
  ForecastStep,
  NetworkFlow,
  NetworkStateVector,
  SimulationScenario,
  SystemConfig,
  ThreatNotification,
} from './types';
import {
  ThreatNotificationToastContainer,
  ThreatNotificationTray,
} from './components/ThreatNotificationSystem';
import { DEFAULT_CONFIG } from './mockData/scenarios';

// Try backend API first; falls back to client-side simulator if unavailable.
const USE_BACKEND_API = true;

type WorldModelInference = ReturnType<typeof computeWorldModelInference>;

function createPendingInference(
  currentState: NetworkStateVector,
  allStates: NetworkStateVector[],
  currentWindowIndex: number,
): WorldModelInference {
  return {
    currentState,
    attackProbability: 0,
    predictedCurrentStage: 'BENIGN',
    predictedNextStage: 'BENIGN',
    forecasts: [],
    attributions: [],
    mitreCandidates: [],
    earlyWarningLeadTime: 0,
    historyStates: allStates.slice(Math.max(0, currentWindowIndex - 9), currentWindowIndex + 1),
  };
}

export default function App() {
  const [currentTab, setCurrentTab] = useState<string>('dashboard');
  const [activeScenarioId, setActiveScenarioId] = useState<string>('full-killchain');
  const [uploadedStateVectors, setUploadedStateVectors] = useState<NetworkStateVector[] | null>(null);
  const [currentWindow, setCurrentWindow] = useState<number>(5);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [simSpeed, setSimSpeed] = useState<number>(1);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);
  const [isSettingsModalOpen, setIsSettingsModalOpen] = useState<boolean>(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState<boolean>(false);
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [demoStepIndex, setDemoStepIndex] = useState(0);
  const [demoCopilotMessage, setDemoCopilotMessage] = useState('');
  const [config, setConfig] = useState<SystemConfig>(DEFAULT_CONFIG);
  const [backendInference, setBackendInference] = useState<WorldModelInference | null>(null);
  const [previousForecasts, setPreviousForecasts] = useState<ForecastStep[]>([]);
  const [notifications, setNotifications] = useState<ThreatNotification[]>([]);
  const [activeToasts, setActiveToasts] = useState<ThreatNotification[]>([]);
  const [isNotificationTrayOpen, setIsNotificationTrayOpen] = useState<boolean>(false);
  const notifiedAlertsRef = useRef<Set<string>>(new Set());
  const previousInferenceRef = useRef<{ window: number; forecasts: ForecastStep[] } | null>(null);
  const previousScenarioRef = useRef<string | null>(null);

  // Generate scenario data whenever scenarioId changes
  const scenarioData = useMemo(() => {
    if (activeScenarioId === 'uploaded' && uploadedStateVectors?.length) {
      const uploadedScenario: SimulationScenario = {
        id: 'uploaded',
        name: 'Uploaded Telemetry Replay',
        description: 'Chronological windows generated from analyst-uploaded network telemetry.',
        expectedKillChain: ['BENIGN'],
        totalWindows: uploadedStateVectors.length,
        attackStartWindow: 0,
        leadTimeExpectedSec: 0,
      };
      return {
        stateVectors: uploadedStateVectors,
        allFlows: [] as NetworkFlow[],
        scenario: uploadedScenario,
      };
    }
    return generateScenarioData(activeScenarioId);
  }, [activeScenarioId, uploadedStateVectors]);

  const { stateVectors, allFlows, scenario } = scenarioData;

  // Inactive simulation timer loop
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (isSimulating) {
      const intervalMs = Math.round(2000 / simSpeed);
      timerRef.current = setInterval(() => {
        setCurrentWindow((prev) => {
          if (prev >= stateVectors.length - 1) {
            setIsSimulating(false);
            return prev;
          }
          return prev + 1;
        });
      }, intervalMs);
    } else if (timerRef.current) {
      clearInterval(timerRef.current);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [isSimulating, simSpeed, stateVectors.length]);

  // Handle scenario change
  const handleSelectScenario = (id: string) => {
    setIsDemoMode(false);
    setDemoCopilotMessage('');
    setIsSimulating(false);
    setPreviousForecasts([]);
    setBackendInference(null);
    previousInferenceRef.current = null;
    notifiedAlertsRef.current.clear();
    setActiveToasts([]);
    setActiveScenarioId(id);
    setCurrentWindow(id === 'uploaded' ? 0 : 3); // Start near beginning
  };

  const handleUseUploadedTelemetry = (stateVectors: NetworkStateVector[]) => {
    if (!stateVectors.length) return;
    setIsDemoMode(false);
    setDemoCopilotMessage('');
    setIsSimulating(false);
    setPreviousForecasts([]);
    setBackendInference(null);
    previousInferenceRef.current = null;
    notifiedAlertsRef.current.clear();
    setActiveToasts([]);
    setUploadedStateVectors(stateVectors);
    setActiveScenarioId('uploaded');
    setCurrentWindow(0);
    setCurrentTab('dashboard');
  };

  const applyDemoStep = (stepIndex: number) => {
    const step = DEMO_SCRIPT[stepIndex];
    if (!step) return;

    setIsSimulating(false);
    setPreviousForecasts([]);
    setBackendInference(null);
    previousInferenceRef.current = null;
    setDemoStepIndex(stepIndex);
    setCurrentWindow(step.windowIndex);
    setCurrentTab(step.tab);
    setDemoCopilotMessage(step.copilotMessage || '');
    setIsCopilotOpen(Boolean(step.copilotMessage));
  };

  const handleToggleDemoMode = () => {
    if (isDemoMode) {
      setIsDemoMode(false);
      setDemoCopilotMessage('');
      return;
    }

    // Every demo beat was authored against the complete kill-chain replay.
    setActiveScenarioId('full-killchain');
    setIsDemoMode(true);
    applyDemoStep(0);
  };

  const handleDemoPrevious = () => {
    if (demoStepIndex > 0) applyDemoStep(demoStepIndex - 1);
  };

  const handleDemoNext = () => {
    if (demoStepIndex < DEMO_SCRIPT.length - 1) applyDemoStep(demoStepIndex + 1);
  };

  const handleQuickScenario = (scenarioId: string, windowIndex: number) => {
    setIsDemoMode(false);
    setDemoCopilotMessage('');
    setIsCopilotOpen(false);
    setIsSimulating(false);
    setPreviousForecasts([]);
    setBackendInference(null);
    previousInferenceRef.current = null;
    notifiedAlertsRef.current.clear();
    setActiveToasts([]);
    setActiveScenarioId(scenarioId);
    setCurrentWindow(windowIndex);
    setCurrentTab('dashboard');
  };

  const handleToggleSimulate = () => {
    if (currentWindow >= stateVectors.length - 1) {
      setPreviousForecasts([]);
      previousInferenceRef.current = null;
      notifiedAlertsRef.current.clear();
      setActiveToasts([]);
      setCurrentWindow(0);
    }
    setIsSimulating(!isSimulating);
  };

  const handleStepForward = () => {
    setIsSimulating(false);
    setCurrentWindow((prev) => Math.min(stateVectors.length - 1, prev + 1));
  };

  const handleResetSimulation = () => {
    setIsSimulating(false);
    setPreviousForecasts([]);
    previousInferenceRef.current = null;
    notifiedAlertsRef.current.clear();
    setActiveToasts([]);
    setCurrentWindow(0);
  };

  // The simulator remains the offline fallback; uploaded telemetry opts into
  // the backend model endpoints so each replay window uses real inference.
  const simulatorInference = useMemo(() => {
    return computeWorldModelInference(currentWindow, stateVectors, activeScenarioId);
  }, [currentWindow, stateVectors, activeScenarioId]);
  const shouldUseBackendInference = USE_BACKEND_API || activeScenarioId === 'uploaded';

  const pendingInference = useMemo(
    () => createPendingInference(
      stateVectors[currentWindow] || stateVectors[0],
      stateVectors,
      currentWindow,
    ),
    [currentWindow, stateVectors],
  );
  useEffect(() => {
    if (!shouldUseBackendInference) return;

    let cancelled = false;
    const historyStates = stateVectors.slice(Math.max(0, currentWindow - 9), currentWindow + 1);
    const currentState = stateVectors[currentWindow] || stateVectors[0];

    void Promise.all([
      fetchPrediction(historyStates),
      fetchForecast(historyStates, Math.max(10, config.forecastHorizon)),
      fetchExplainability(historyStates),
    ]).then(([prediction, forecast, explainability]) => {
      if (cancelled) return;
      setBackendInference({
        currentState,
        attackProbability: prediction.attackProbability,
        predictedCurrentStage: prediction.predictedStage,
        predictedNextStage: prediction.predictedNextStage,
        forecasts: forecast.forecasts,
        attributions: explainability.attributions,
        // The full-inference route intentionally focuses on model outputs;
        // technique candidates remain populated by the simulator-only path.
        mitreCandidates: [],
        earlyWarningLeadTime: prediction.earlyWarningLeadTime,
        historyStates,
      });
    }).catch(() => {
      if (!cancelled) setBackendInference(null);
    });

    return () => {
      cancelled = true;
    };
  }, [shouldUseBackendInference, currentWindow, stateVectors, config.forecastHorizon]);

  const inference = shouldUseBackendInference
    ? backendInference || simulatorInference || pendingInference
    : simulatorInference!;

  const {
    currentState,
    attackProbability,
    predictedCurrentStage,
    predictedNextStage,
    forecasts,
    attributions,
    mitreCandidates,
    earlyWarningLeadTime,
  } = inference;

  const currentRiskLevel = getRiskLevel(attackProbability);
  const ewes = useMemo(() => computeEWES({
    attackProbability,
    forecasts,
    earlyWarningLeadTimeSec: earlyWarningLeadTime,
    currentStage: predictedCurrentStage,
  }), [attackProbability, forecasts, earlyWarningLeadTime, predictedCurrentStage]);

  // Retain the prior observed window's one-step rollout so the next state can
  // be evaluated as a prediction residual rather than a second inference.
  useEffect(() => {
    if (previousScenarioRef.current !== activeScenarioId) {
      previousScenarioRef.current = activeScenarioId;
      previousInferenceRef.current = { window: currentWindow, forecasts };
      setPreviousForecasts([]);
      return;
    }

    const previousInference = previousInferenceRef.current;
    if (previousInference && previousInference.window !== currentWindow) {
      setPreviousForecasts(previousInference.forecasts);
    }
    previousInferenceRef.current = { window: currentWindow, forecasts };
  }, [activeScenarioId, currentWindow, forecasts]);

  const residualAnomaly = useMemo(
    () => computeResidualAnomaly(currentState, previousForecasts[0] || null),
    [currentState, previousForecasts],
  );

  // Dynamic alert store with deduplication
  const [alertsState, setAlertsState] = useState<Alert[]>([]);
  const [cases, setCases] = useState<SOCCase[]>(() => getAllCases());
  const refreshCases = useCallback(() => setCases(getAllCases()), []);

  // Synchronize alerts as simulation advances
  useEffect(() => {
    if (shouldUseBackendInference) {
      let cancelled = false;
      const sequences = Array.from({ length: currentWindow + 1 }, (_, windowIndex) => (
        stateVectors.slice(Math.max(0, windowIndex - 9), windowIndex + 1)
      ));

      void Promise.all(sequences.map((sequence) => fetchPrediction(sequence))).then((predictions) => {
        if (cancelled) return;

        const generatedAlerts: Alert[] = [];
        const seenIps: Record<string, number> = {};

        predictions.forEach((prediction, windowIndex) => {
          const state = stateVectors[windowIndex];
          if (prediction.attackProbability < config.riskThresholds.normal) return;

          const key = `${state.groundTruthStage}-${windowIndex < 10 ? 'recon' : 'attack'}`;
          if (seenIps[key] === undefined) {
            seenIps[key] = generatedAlerts.length;
            generatedAlerts.push({
              id: `ALT-2026-${String(1040 + generatedAlerts.length).padStart(4, '0')}`,
              incidentId: `INC-${activeScenarioId.toUpperCase()}-01`,
              timestamp: state.timestamp,
              timeOffsetSeconds: state.timeOffsetSeconds,
              severity: getSeverityFromProb(prediction.attackProbability),
              status: 'NEW',
              sourceIp: activeScenarioId === 'uploaded' ? 'uploaded-telemetry' : '192.168.1.105',
              destinationIp: activeScenarioId === 'uploaded'
                ? 'uploaded-telemetry'
                : prediction.predictedStage === 'COMMAND_AND_CONTROL' ? '198.51.100.44' : '10.0.0.12',
              dstPortSummary: activeScenarioId === 'uploaded'
                ? 'Captured flow telemetry'
                : prediction.predictedStage === 'RECONNAISSANCE' ? 'Ports 1000-2000' : 'Port 445/3389',
              currentStage: prediction.predictedStage,
              predictedNextStage: prediction.predictedNextStage,
              attackProbability: prediction.attackProbability,
              confidence: 0.92,
              forecastHorizonSteps: prediction.forecasts.length,
              earlyWarningSeconds: prediction.earlyWarningLeadTime,
              topContributingFeatures: prediction.attributions,
              mitreCandidates: [],
              recommendedActions: [],
              deduplicationCount: 1,
              analystNotes: '',
              rawFlowCount: state.flowCount,
            });
          } else {
            generatedAlerts[seenIps[key]].deduplicationCount += 1;
          }
        });

        setAlertsState(generatedAlerts);
      }).catch(() => {
        if (!cancelled) setAlertsState([]);
      });

      return () => {
        cancelled = true;
      };
    }

    // Generate alerts for all elapsed windows that exceeded elevated threshold
    const generatedAlerts: Alert[] = [];
    const seenIps: Record<string, number> = {};

    for (let w = 0; w <= currentWindow; w++) {
      const winInf = computeWorldModelInference(w, stateVectors, activeScenarioId);
      if (winInf.attackProbability >= config.riskThresholds.normal) {
        const key = `${winInf.currentState.groundTruthStage}-${w < 10 ? 'recon' : 'attack'}`;
        if (seenIps[key] === undefined) {
          seenIps[key] = generatedAlerts.length;
          generatedAlerts.push({
            id: `ALT-2026-${String(1040 + generatedAlerts.length).padStart(4, '0')}`,
            incidentId: `INC-${activeScenarioId.toUpperCase()}-01`,
            timestamp: winInf.currentState.timestamp,
            timeOffsetSeconds: winInf.currentState.timeOffsetSeconds,
            severity: getSeverityFromProb(winInf.attackProbability),
            status: 'NEW',
            sourceIp: activeScenarioId === 'uploaded' ? 'uploaded-telemetry' : '192.168.1.105',
            destinationIp: activeScenarioId === 'uploaded'
              ? 'uploaded-telemetry'
              : winInf.predictedCurrentStage === 'COMMAND_AND_CONTROL' ? '198.51.100.44' : '10.0.0.12',
            dstPortSummary: activeScenarioId === 'uploaded'
              ? 'Captured flow telemetry'
              : winInf.predictedCurrentStage === 'RECONNAISSANCE' ? 'Ports 1000-2000' : 'Port 445/3389',
            currentStage: winInf.predictedCurrentStage,
            predictedNextStage: winInf.predictedNextStage,
            attackProbability: winInf.attackProbability,
            confidence: 0.92,
            forecastHorizonSteps: 5,
            earlyWarningSeconds: winInf.earlyWarningLeadTime,
            topContributingFeatures: winInf.attributions,
            mitreCandidates: winInf.mitreCandidates,
            recommendedActions: winInf.mitreCandidates.map((m) => m.recommendedAction),
            deduplicationCount: 1,
            analystNotes: '',
            rawFlowCount: winInf.currentState.flowCount,
          });
        } else {
          // Increment deduplication counter
          generatedAlerts[seenIps[key]].deduplicationCount += 1;
        }
      }
    }

    setAlertsState(generatedAlerts);
  }, [shouldUseBackendInference, currentWindow, stateVectors, activeScenarioId, config.riskThresholds.normal]);

  // Cases are durable local records. An alert can be regenerated during a
  // replay, but its stable alert ID is linked to at most one automatic case.
  useEffect(() => {
    const linkedAlertIds = new Set(
      getAllCases().flatMap((socCase) => socCase.linkedAlertIds),
    );
    let createdCase = false;

    alertsState.forEach((alert) => {
      if (
        (alert.severity === 'CRITICAL' || alert.severity === 'HIGH')
        && !linkedAlertIds.has(alert.id)
      ) {
        createCase(alert);
        linkedAlertIds.add(alert.id);
        createdCase = true;
      }
    });

    if (createdCase) refreshCases();
  }, [alertsState, refreshCases]);

  const handleUpdateAlertStatus = (alertId: string, status: AlertStatus) => {
    setAlertsState((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, status } : a))
    );
    if (selectedAlert?.id === alertId) {
      setSelectedAlert((prev) => (prev ? { ...prev, status } : null));
    }
  };

  const handleUpdateAnalystNotes = (alertId: string, notes: string) => {
    setAlertsState((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, analystNotes: notes } : a))
    );
    if (selectedAlert?.id === alertId) {
      setSelectedAlert((prev) => (prev ? { ...prev, analystNotes: notes } : null));
    }
  };

  const handleSelectAlertForInvestigation = (alert: Alert) => {
    setSelectedAlert(alert);
    setCurrentTab('investigation');
  };

  // Live Threat Notification Engine:
  // Monitors real-time alerts and triggers HUD toasts and notification feed entries
  useEffect(() => {
    alertsState.forEach((alert) => {
      if (
        (alert.severity === 'CRITICAL' || alert.severity === 'HIGH' || alert.severity === 'ELEVATED') &&
        !notifiedAlertsRef.current.has(alert.id)
      ) {
        notifiedAlertsRef.current.add(alert.id);

        const isCrit = alert.severity === 'CRITICAL';
        const isH = alert.severity === 'HIGH';
        const title = isCrit
          ? `Critical Threat: ${alert.currentStage.replace(/_/g, ' ')} Escalation`
          : isH
          ? `High-Risk Anomaly: ${alert.currentStage.replace(/_/g, ' ')} Active`
          : `Elevated Anomaly: ${alert.currentStage.replace(/_/g, ' ')}`;

        const desc =
          alert.predictedNextStage && alert.predictedNextStage !== 'BENIGN'
            ? `World Model forecasts progression to ${alert.predictedNextStage.replace(/_/g, ' ')} with ${(alert.attackProbability * 100).toFixed(0)}% probability.`
            : `Abnormal flow pattern detected on ${alert.destinationIp} with ${(alert.attackProbability * 100).toFixed(0)}% attack probability.`;

        const newNotification: ThreatNotification = {
          id: `notif-${alert.id}-${Date.now()}`,
          timestamp: alert.timestamp,
          timeOffsetSeconds: alert.timeOffsetSeconds,
          severity: alert.severity,
          title,
          description: desc,
          currentStage: alert.currentStage,
          predictedNextStage: alert.predictedNextStage,
          attackProbability: alert.attackProbability,
          earlyWarningSeconds: alert.earlyWarningSeconds,
          sourceIp: alert.sourceIp,
          destinationIp: alert.destinationIp,
          alertId: alert.id,
          alertRef: alert,
          isRead: false,
          createdAt: Date.now(),
        };

        setNotifications((prev) => [newNotification, ...prev]);

        // Push to active toasts if HIGH or CRITICAL (capped at 3 simultaneous toasts)
        if (isCrit || isH) {
          setActiveToasts((prev) => [newNotification, ...prev.slice(0, 2)]);
        }
      }
    });
  }, [alertsState]);

  const handleDismissToast = (id: string) => {
    setActiveToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const handleInvestigateNotification = (notif: ThreatNotification) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === notif.id ? { ...n, isRead: true } : n))
    );
    handleDismissToast(notif.id);
    setIsNotificationTrayOpen(false);

    const targetAlert = notif.alertRef || alertsState.find((a) => a.id === notif.alertId);
    if (targetAlert) {
      setSelectedAlert(targetAlert);
    }
    setCurrentTab('investigation');
  };

  const handleSOARNotification = (notif: ThreatNotification) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === notif.id ? { ...n, isRead: true } : n))
    );
    handleDismissToast(notif.id);
    setIsNotificationTrayOpen(false);

    const targetAlert = notif.alertRef || alertsState.find((a) => a.id === notif.alertId);
    if (targetAlert) {
      setSelectedAlert(targetAlert);
    }
    setCurrentTab('investigation');
  };

  const handleCopilotNotification = (notif: ThreatNotification) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === notif.id ? { ...n, isRead: true } : n))
    );
    handleDismissToast(notif.id);
    setIsCopilotOpen(true);
  };

  const handleMarkAllNotificationsRead = () => {
    setNotifications((prev) => prev.map((n) => ({ ...n, isRead: true })));
  };

  const handleClearNotifications = () => {
    setNotifications([]);
    setActiveToasts([]);
  };

  const unreadNotificationCount = useMemo(
    () => notifications.filter((n) => !n.isRead).length,
    [notifications]
  );

  const copilotContext = useMemo(() => {
    const activeAlert = selectedAlert || alertsState[0];
    return {
      alertId: activeAlert?.id || '',
      sourceIp: activeAlert?.sourceIp || '',
      destinationIp: activeAlert?.destinationIp || '',
      currentStage: predictedCurrentStage,
      predictedNextStage,
      attackProbability,
      earlyWarningLeadTimeSec: earlyWarningLeadTime,
      forecasts: forecasts.map((forecast) => ({
        step: forecast.step,
        horizonSeconds: forecast.horizonSeconds,
        predictedStage: forecast.predictedStage,
        attackProbability: forecast.attackProbability,
      })),
      topAttributions: attributions.slice(0, 5).map((attribution) => ({
        displayName: attribution.displayName,
        contribution: attribution.contribution,
        direction: attribution.direction,
      })),
      mitreCandidates: mitreCandidates.map((candidate) => ({
        id: candidate.id,
        name: candidate.name,
        tactic: candidate.tactic,
        confidence: candidate.confidence,
        evidence: candidate.evidence,
        recommendedAction: candidate.recommendedAction,
      })),
      residualAnomaly,
    } satisfies Omit<CopilotContext, 'conversationHistory'>;
  }, [
    selectedAlert,
    alertsState,
    predictedCurrentStage,
    predictedNextStage,
    attackProbability,
    earlyWarningLeadTime,
    forecasts,
    attributions,
    mitreCandidates,
    residualAnomaly,
  ]);

  const currentDemoStep = DEMO_SCRIPT[demoStepIndex];

  return (
    <div className="min-h-screen bg-[#090d16] text-slate-100 flex flex-col font-sans selection:bg-emerald-500 selection:text-black">
      {isDemoMode && (
        <div
          className="pointer-events-none fixed inset-0 z-[60] border-2 border-amber-400/45 shadow-[inset_0_0_36px_rgba(245,158,11,0.13)]"
          aria-hidden="true"
        />
      )}
      {/* Top Navbar & Simulation Controller */}
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        activeScenarioId={activeScenarioId}
        onSelectScenario={handleSelectScenario}
        isSimulating={isSimulating}
        onToggleSimulate={handleToggleSimulate}
        onStepForward={handleStepForward}
        onResetSimulation={handleResetSimulation}
        simSpeed={simSpeed}
        setSimSpeed={setSimSpeed}
        onOpenReportModal={() => setIsReportModalOpen(true)}
        onOpenSettingsModal={() => setIsSettingsModalOpen(true)}
        onOpenCopilot={() => setIsCopilotOpen(true)}
        currentWindow={currentWindow}
        totalWindows={stateVectors.length}
        threatLevel={currentRiskLevel}
        isDemoMode={isDemoMode}
        onToggleDemoMode={handleToggleDemoMode}
        demoStepIndex={demoStepIndex}
        demoStepCount={DEMO_SCRIPT.length}
        onDemoPrevious={handleDemoPrevious}
        onDemoNext={handleDemoNext}
        onQuickScenario={handleQuickScenario}
        unreadNotificationCount={unreadNotificationCount}
        onToggleNotificationTray={() => setIsNotificationTrayOpen((prev) => !prev)}
        isNotificationTrayOpen={isNotificationTrayOpen}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-5">
        {/* Universal Top KPI Strip */}
        <KPICards
          attackProbability={attackProbability}
          currentStage={predictedCurrentStage}
          predictedNextStage={predictedNextStage}
          forecastHorizonSec={config.forecastHorizon * 10}
          earlyWarningLeadTimeSec={earlyWarningLeadTime}
          activeAlertCount={alertsState.filter((a) => a.status !== 'RESOLVED').length}
          ewes={ewes}
          residualAnomaly={residualAnomaly}
        />

        {/* View Switcher */}
        {currentTab === 'dashboard' && (
          <DashboardView
            currentWindow={currentWindow}
            allStates={stateVectors}
            attackProbability={attackProbability}
            currentStage={predictedCurrentStage}
            predictedNextStage={predictedNextStage}
            forecasts={forecasts}
            attributions={attributions}
            mitreCandidates={mitreCandidates}
            alerts={alertsState}
            residualAnomaly={residualAnomaly}
            onNavigateTab={setCurrentTab}
            onSelectAlertForInvestigation={handleSelectAlertForInvestigation}
          />
        )}

        {currentTab === 'live-monitor' && (
          <LiveMonitorView
            allStates={stateVectors}
            allFlows={allFlows}
            currentWindow={currentWindow}
            isSimulating={isSimulating}
            onToggleSimulate={handleToggleSimulate}
            onStepForward={handleStepForward}
            onResetSimulation={handleResetSimulation}
            simSpeed={simSpeed}
            setSimSpeed={setSimSpeed}
            activeScenarioId={activeScenarioId}
            onSelectScenario={handleSelectScenario}
            attackProbability={attackProbability}
            currentStage={predictedCurrentStage}
          />
        )}

        {currentTab === 'forecasts' && (
          <ForecastView
            forecasts={forecasts}
            currentWindow={currentWindow}
            currentState={currentState}
            currentStage={predictedCurrentStage}
            predictedNextStage={predictedNextStage}
            attackProbability={attackProbability}
            earlyWarningLeadTimeSec={earlyWarningLeadTime}
          />
        )}

        {currentTab === 'what-if' && (
          <WhatIfSimulatorView
            baseState={currentState}
            allStates={stateVectors}
            currentWindow={currentWindow}
            scenarioId={activeScenarioId}
            currentStage={predictedCurrentStage}
            attackProbability={attackProbability}
          />
        )}

        {currentTab === 'digital-twin' && (
          <AttackDigitalTwin
            predictedCurrentStage={predictedCurrentStage}
            predictedNextStage={predictedNextStage}
            attackProbability={attackProbability}
            forecasts={forecasts}
            earlyWarningLeadTimeSec={earlyWarningLeadTime}
          />
        )}

        {currentTab === 'alerts' && (
          <AlertsView
            alerts={alertsState}
            onUpdateAlertStatus={handleUpdateAlertStatus}
            onSelectAlertForInvestigation={handleSelectAlertForInvestigation}
          />
        )}

        {currentTab === 'timeline' && (
          <IncidentTimelineView
            alertsState={alertsState}
            forecasts={forecasts}
            currentWindow={currentWindow}
            totalWindows={stateVectors.length}
            predictedCurrentStage={predictedCurrentStage}
            onSelectAlertForInvestigation={handleSelectAlertForInvestigation}
          />
        )}

        {currentTab === 'investigation' && (
          <InvestigationView
            selectedAlert={selectedAlert || alertsState[0] || null}
            onBackToAlerts={() => setCurrentTab('alerts')}
            onUpdateAnalystNotes={handleUpdateAnalystNotes}
          />
        )}

        {currentTab === 'cases' && (
          <CaseManagementView
            cases={cases}
            alerts={alertsState}
            copilotContext={copilotContext}
            onCasesChanged={refreshCases}
            onOpenInvestigation={handleSelectAlertForInvestigation}
          />
        )}

        {currentTab === 'explainability' && (
          <ExplainabilityView
            attributions={attributions}
            currentWindow={currentWindow}
            currentState={currentState}
            attackProbability={attackProbability}
            copilotContext={copilotContext}
          />
        )}

        {currentTab === 'benchmarks' && <BenchmarksView />}

        {currentTab === 'datasets' && (
          <DatasetTrainingView onUseUploadedTelemetry={handleUseUploadedTelemetry} />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#070a12] py-3 px-6 text-center text-xs text-slate-500 font-mono">
        <span>CYBERWORLD &bull; SIH Predictive Network Defence &bull; World Model Transition Dynamics </span>
        <span className="text-emerald-400 font-semibold">P(S_t+1 | S_t)</span>
        <span> &bull; Chronological Data Pipeline &bull; Offline & Air-Gapped Ready</span>
      </footer>

      {isDemoMode && currentDemoStep && (
        <div
          className="pointer-events-none fixed inset-x-4 bottom-5 z-[61] mx-auto max-w-3xl rounded-xl border border-amber-500/55 bg-[#221a0b]/95 px-4 py-3 text-center shadow-xl shadow-black/45 backdrop-blur sm:inset-x-8"
          role="status"
          aria-live="polite"
        >
          <span className="mr-2 text-[10px] font-mono font-bold uppercase tracking-[0.18em] text-amber-500">SIH Demo</span>
          <span className="text-sm font-medium text-amber-100">{currentDemoStep.annotation}</span>
        </div>
      )}

      <CopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        context={copilotContext}
        prefilledQuestion={demoCopilotMessage}
      />

      {/* Modals */}
      <ReportModal
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        currentAlert={selectedAlert || alertsState[0] || null}
        currentState={currentState}
        forecasts={forecasts}
        attackProbability={attackProbability}
        currentStage={predictedCurrentStage}
        predictedNextStage={predictedNextStage}
        earlyWarningLeadTimeSec={earlyWarningLeadTime}
      />

      <SettingsModal
        isOpen={isSettingsModalOpen}
        onClose={() => setIsSettingsModalOpen(false)}
        config={config}
        onSaveConfig={setConfig}
      />

      {/* Real-time Threat HUD Toasts */}
      <ThreatNotificationToastContainer
        toasts={activeToasts}
        onDismiss={handleDismissToast}
        onInvestigate={handleInvestigateNotification}
        onSOAR={handleSOARNotification}
        onCopilot={handleCopilotNotification}
      />

      {/* Slide-over Threat Notification Feed Tray */}
      <ThreatNotificationTray
        isOpen={isNotificationTrayOpen}
        onClose={() => setIsNotificationTrayOpen(false)}
        notifications={notifications}
        onDismiss={handleDismissToast}
        onInvestigate={handleInvestigateNotification}
        onSOAR={handleSOARNotification}
        onCopilot={handleCopilotNotification}
        onMarkAllRead={handleMarkAllNotificationsRead}
        onClearAll={handleClearNotifications}
      />
    </div>
  );
}
