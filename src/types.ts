export type AttackStage = 
  | 'BENIGN'
  | 'RECONNAISSANCE'
  | 'INITIAL_ACCESS'
  | 'LATERAL_MOVEMENT'
  | 'COMMAND_AND_CONTROL'
  | 'EXFILTRATION';

export type RiskLevel = 'NORMAL' | 'ELEVATED' | 'HIGH' | 'CRITICAL';

export type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface NetworkFlow {
  id: string;
  timestamp: string; // ISO or relative
  timeOffsetSeconds: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'OTHER';
  flags: {
    syn: boolean;
    ack: boolean;
    fin: boolean;
    rst: boolean;
    psh: boolean;
    urg: boolean;
  };
  bytes: number;
  packets: number;
  durationMs: number;
  iatMeanMs: number;
  iatVarianceMs: number;
  ttl: number;
  windowSize: number;
  payloadSize: number;
  label: AttackStage;
  isAttack: boolean;
}

export interface NetworkStateVector {
  windowIndex: number;
  timestamp: string;
  timeOffsetSeconds: number;
  // Traffic volume
  flowCount: number;
  totalBytes: number;
  totalPackets: number;
  packetsPerSec: number;
  bytesPerSec: number;
  bytesPerPacket: number;
  // Protocol distribution
  tcpRatio: number;
  udpRatio: number;
  icmpRatio: number;
  // TCP Flags & behaviour
  synCount: number;
  ackCount: number;
  rstCount: number;
  finCount: number;
  pshCount: number;
  synAckRatio: number;
  rstFlowRatio: number;
  // Topology & Diversity
  uniqueSrcIps: number;
  uniqueDstIps: number;
  uniqueDstPorts: number;
  portDiversity: number; // 0 - 1
  srcDstConcentration: number;
  // Timing & Inter-arrival
  meanDurationMs: number;
  meanIatMs: number;
  iatVarianceMs: number;
  burstiness: number;
  // Packet characteristics
  meanPacketLength: number;
  packetLengthVariance: number;
  packetSizeEntropy: number;
  meanTtl: number;
  ttlVariance: number;
  // Ground truth / current status
  groundTruthStage: AttackStage;
  isGroundTruthAttack: boolean;
}

export interface MitreTechniqueCandidate {
  id: string; // e.g. T1046
  name: string; // e.g. Network Service Scanning
  tactic: string; // e.g. Reconnaissance
  confidence: number; // 0 to 1
  evidence: string[];
  recommendedAction: string;
}

export interface FeatureAttribution {
  featureName: string;
  displayName: string;
  value: number;
  formattedValue: string;
  contribution: number; // positive = pushes towards attack, negative = pushes towards benign
  direction: 'RISK_INCREASE' | 'RISK_DECREASE';
  category: 'VOLUME' | 'FLAGS' | 'TOPOLOGY' | 'TIMING' | 'PACKET';
}

export interface ForecastStep {
  step: number; // 1 to 10
  horizonSeconds: number; // e.g. 10s, 20s, 30s...
  predictedStage: AttackStage;
  attackProbability: number; // 0 to 1
  confidence: number; // 0 to 1
  lowerConfidenceBound: number; // 0 to 1
  upperConfidenceBound: number; // 0 to 1
  riskLevel: RiskLevel;
  predictedStateSummary: {
    synAckRatio: number;
    portDiversity: number;
    burstiness: number;
    flowCount: number;
  };
}

export interface CalibrationBucket {
  bucketLabel: string;
  predictedMidpoint: number;
  empiricalFrequency: number;
  sampleCount: number;
  calibrationError: number;
}

export interface Alert {
  id: string;
  incidentId: string;
  timestamp: string;
  timeOffsetSeconds: number;
  severity: AlertSeverity;
  status: AlertStatus;
  sourceIp: string;
  destinationIp: string;
  dstPortSummary: string;
  currentStage: AttackStage;
  predictedNextStage: AttackStage;
  attackProbability: number;
  confidence: number;
  forecastHorizonSteps: number;
  earlyWarningSeconds: number;
  topContributingFeatures: FeatureAttribution[];
  mitreCandidates: MitreTechniqueCandidate[];
  recommendedActions: string[];
  deduplicationCount: number;
  analystNotes?: string;
  rawFlowCount: number;
}

export interface IncidentCampaign {
  id: string;
  title: string;
  startedAt: string;
  lastUpdated: string;
  severity: AlertSeverity;
  status: 'ACTIVE' | 'CONTAINED' | 'RESOLVED';
  involvedIps: string[];
  targetIps: string[];
  progressionStages: AttackStage[];
  predictedNextStage: AttackStage;
  peakAttackProbability: number;
  earlyWarningSecTotal: number;
  alerts: Alert[];
  playbookActionsTaken: string[];
  analystSummary: string;
}

export interface BenchmarkMetrics {
  modelName: string;
  precision: number;
  recall: number;
  f1Score: number;
  rocAuc: number;
  prAuc: number;
  falsePositiveRate: number;
  detectionLatencyMs: number;
  earlyWarningLeadTimeSec: number;
  forecastAccuracyT1: number;
  forecastAccuracyT3: number;
  forecastAccuracyT5: number;
  isWorldModel: boolean;
}

export interface SimulationScenario {
  id: string;
  name: string;
  description: string;
  expectedKillChain: AttackStage[];
  totalWindows: number;
  attackStartWindow: number;
  leadTimeExpectedSec: number;
}

export interface SystemConfig {
  riskThresholds: {
    normal: number;
    elevated: number;
    high: number;
    critical: number;
  };
  defaultWindowSeconds: number;
  forecastHorizon: number;
  deduplicationWindowSeconds: number;
  activeModelVersion: string;
}
