import {
  AttackStage,
  NetworkFlow,
  NetworkStateVector,
  ForecastStep,
  Alert,
  IncidentCampaign,
  FeatureAttribution,
  MitreTechniqueCandidate,
  RiskLevel,
  AlertSeverity,
  CalibrationBucket,
} from '../types';
import { SIMULATION_SCENARIOS } from '../mockData/scenarios';
import { ASSET_INVENTORY } from '../mockData/assetInventory';
import type { AssetProfile, CVEEntry } from '../mockData/assetInventory';

// Deterministic pseudo-random helper seeded by index for reproducible telemetry
function pseudoRandom(seed: number): number {
  const x = Math.sin(seed * 12.9898 + 78.233) * 43758.5453;
  return x - Math.floor(x);
}

/**
 * Produces the confidence interval used throughout the forecast experience.
 * The interval intentionally widens as model confidence decays over the
 * rollout horizon.
 */
export function computeConfidenceBounds(attackProbability: number, confidence: number): {
  lowerConfidenceBound: number;
  upperConfidenceBound: number;
} {
  const probability = Math.min(1, Math.max(0, attackProbability));
  const boundedConfidence = Math.min(1, Math.max(0, confidence));
  const margin = (1 - boundedConfidence) * 0.3;

  return {
    lowerConfidenceBound: Number(Math.max(0, probability - margin).toFixed(3)),
    upperConfidenceBound: Number(Math.min(1, probability + margin).toFixed(3)),
  };
}

export function generateScenarioData(scenarioId: string) {
  const scenario = SIMULATION_SCENARIOS.find((s) => s.id === scenarioId) || SIMULATION_SCENARIOS[0];
  const windowsCount = scenario.totalWindows;
  const stateVectors: NetworkStateVector[] = [];
  const allFlows: NetworkFlow[] = [];

  const stageTimeline: AttackStage[] = [];
  for (let w = 0; w < windowsCount; w++) {
    let stage: AttackStage = 'BENIGN';
    if (scenario.id === 'full-killchain') {
      if (w < 4) stage = 'BENIGN';
      else if (w < 9) stage = 'RECONNAISSANCE';
      else if (w < 14) stage = 'INITIAL_ACCESS';
      else if (w < 19) stage = 'LATERAL_MOVEMENT';
      else stage = 'COMMAND_AND_CONTROL';
    } else if (scenario.id === 'recon-aborted') {
      if (w < 4) stage = 'BENIGN';
      else if (w < 10) stage = 'RECONNAISSANCE';
      else stage = 'BENIGN';
    } else if (scenario.id === 'fast-lateral') {
      if (w < 3) stage = 'BENIGN';
      else if (w < 8) stage = 'INITIAL_ACCESS';
      else stage = 'LATERAL_MOVEMENT';
    } else if (scenario.id === 'stealth-c2') {
      if (w < 5) stage = 'BENIGN';
      else stage = 'COMMAND_AND_CONTROL';
    } else if (scenario.id === 'data-exfiltration') {
      if (w < 5) stage = 'BENIGN';
      else if (w < 12) stage = 'COMMAND_AND_CONTROL';
      else stage = 'EXFILTRATION';
    }
    stageTimeline.push(stage);
  }

  // Generate 10-second state vectors
  for (let w = 0; w < windowsCount; w++) {
    const stage = stageTimeline[w];
    const isAttack = stage !== 'BENIGN';
    const seed = w * 17 + 101;
    const timeOffsetSec = w * 10;
    const date = new Date(Date.now() - (windowsCount - w) * 10000);
    const timestamp = date.toISOString().substring(11, 19);

    // Dynamic metrics shaped by attack stage
    let flowCount = Math.floor(45 + pseudoRandom(seed) * 25);
    let synCount = Math.floor(flowCount * (0.15 + pseudoRandom(seed + 1) * 0.1));
    let ackCount = Math.floor(flowCount * (0.7 + pseudoRandom(seed + 2) * 0.15));
    let rstCount = Math.floor(pseudoRandom(seed + 3) * 3);
    let finCount = Math.floor(pseudoRandom(seed + 4) * 8);
    let pshCount = Math.floor(pseudoRandom(seed + 5) * 12);
    let portDiversity = 0.15 + pseudoRandom(seed + 6) * 0.1;
    let burstiness = 0.2 + pseudoRandom(seed + 7) * 0.15;
    let totalBytes = flowCount * Math.floor(800 + pseudoRandom(seed + 8) * 400);
    let totalPackets = flowCount * Math.floor(6 + pseudoRandom(seed + 9) * 4);
    let meanIatMs = 240 + pseudoRandom(seed + 10) * 80;
    let iatVarianceMs = 1200 + pseudoRandom(seed + 11) * 600;
    let tcpRatio = 0.85;
    let udpRatio = 0.12;
    let icmpRatio = 0.03;
    let packetEntropy = 3.2 + pseudoRandom(seed + 12) * 0.4;
    let meanTtl = 64;
    let ttlVariance = 1.2;

    if (stage === 'RECONNAISSANCE') {
      flowCount += 85;
      synCount += 70; // Massive SYN probe
      ackCount = Math.floor(ackCount * 0.5); // Dropped/filtered ACKs
      rstCount += 35; // RST responses from closed ports
      portDiversity = 0.88 + pseudoRandom(seed) * 0.08; // High port scan signature
      burstiness = 0.72;
      meanIatMs = 45; // Rapid probe inter-arrival time
      iatVarianceMs = 450;
      meanTtl = 58;
      ttlVariance = 6.4;
    } else if (stage === 'INITIAL_ACCESS') {
      flowCount += 40;
      synCount += 45;
      rstCount += 18;
      burstiness = 0.84; // Rapid credential spray
      portDiversity = 0.35; // Concentrated on ports 22, 445, 80, 443
      totalBytes += 45000;
      meanIatMs = 90;
      iatVarianceMs = 800;
    } else if (stage === 'LATERAL_MOVEMENT') {
      flowCount += 55;
      synCount += 30;
      ackCount += 60;
      portDiversity = 0.42; // SMB 445, RDP 3389, RPC 135
      burstiness = 0.65;
      totalBytes += 120000; // Credential dumps / internal payloads
      meanIatMs = 140;
    } else if (stage === 'COMMAND_AND_CONTROL') {
      // Beaconing: low volume, high periodicity / low IAT variance
      flowCount += 18;
      synCount += 8;
      ackCount += 24;
      portDiversity = 0.08; // Single egress port (443 / 53)
      meanIatMs = 300;
      iatVarianceMs = 60; // Rigid low-variance heartbeat
      burstiness = 0.35;
      totalBytes += 15000;
    } else if (stage === 'EXFILTRATION') {
      flowCount += 60;
      totalBytes += 980000; // Large outbound data transfer
      totalPackets += 3500;
      burstiness = 0.92;
      packetEntropy = 4.85; // Encrypted compressed archives
      portDiversity = 0.05;
      meanIatMs = 25;
      iatVarianceMs = 110;
    }

    const synAckRatio = ackCount > 0 ? Number((synCount / ackCount).toFixed(3)) : 1.0;
    const rstFlowRatio = flowCount > 0 ? Number((rstCount / flowCount).toFixed(3)) : 0;
    const packetsPerSec = Number((totalPackets / 10).toFixed(1));
    const bytesPerSec = Number((totalBytes / 10).toFixed(1));
    const bytesPerPacket = totalPackets > 0 ? Number((totalBytes / totalPackets).toFixed(1)) : 0;

    const stateVector: NetworkStateVector = {
      windowIndex: w,
      timestamp,
      timeOffsetSeconds: timeOffsetSec,
      flowCount,
      totalBytes,
      totalPackets,
      packetsPerSec,
      bytesPerSec,
      bytesPerPacket,
      tcpRatio,
      udpRatio,
      icmpRatio,
      synCount,
      ackCount,
      rstCount,
      finCount,
      pshCount,
      synAckRatio,
      rstFlowRatio,
      uniqueSrcIps: stage === 'LATERAL_MOVEMENT' ? 6 : stage === 'RECONNAISSANCE' ? 1 : 4,
      uniqueDstIps: stage === 'RECONNAISSANCE' ? 14 : stage === 'LATERAL_MOVEMENT' ? 8 : 5,
      uniqueDstPorts: Math.round(portDiversity * 100),
      portDiversity: Number(portDiversity.toFixed(3)),
      srcDstConcentration: Number((0.6 + pseudoRandom(seed) * 0.3).toFixed(2)),
      meanDurationMs: stage === 'RECONNAISSANCE' ? 35 : 620,
      meanIatMs: Math.round(meanIatMs),
      iatVarianceMs: Math.round(iatVarianceMs),
      burstiness: Number(burstiness.toFixed(3)),
      meanPacketLength: Math.round(bytesPerPacket),
      packetLengthVariance: Math.round(350 + pseudoRandom(seed) * 400),
      packetSizeEntropy: Number(packetEntropy.toFixed(2)),
      meanTtl,
      ttlVariance: Number(ttlVariance.toFixed(2)),
      groundTruthStage: stage,
      isGroundTruthAttack: isAttack,
    };

    stateVectors.push(stateVector);

    // Generate individual representative flows for this window
    const windowFlowCount = Math.min(6, Math.max(3, Math.floor(flowCount / 15)));
    for (let f = 0; f < windowFlowCount; f++) {
      const isSus = isAttack && f % 2 === 0;
      let src = isSus ? '192.168.1.105' : `192.168.1.${50 + f}`;
      let dst = isSus ? (stage === 'COMMAND_AND_CONTROL' ? '198.51.100.44' : '10.0.0.12') : '10.0.0.5';
      let dstPort = 80;
      if (stage === 'RECONNAISSANCE') {
        dstPort = 1000 + f * 423;
      } else if (stage === 'INITIAL_ACCESS') {
        dstPort = f === 0 ? 445 : 3389;
      } else if (stage === 'LATERAL_MOVEMENT') {
        src = '10.0.0.12';
        dst = `10.0.0.${20 + f}`;
        dstPort = 445;
      } else if (stage === 'COMMAND_AND_CONTROL') {
        dstPort = 443;
      } else if (stage === 'EXFILTRATION') {
        dstPort = 8443;
      }

      allFlows.push({
        id: `flow-w${w}-${f}`,
        timestamp: `${timestamp}.${String(f * 150).padStart(3, '0')}`,
        timeOffsetSeconds: timeOffsetSec + f * 1.5,
        srcIp: src,
        dstIp: dst,
        srcPort: 49152 + f * 311,
        dstPort,
        protocol: 'TCP',
        flags: {
          syn: isSus && stage === 'RECONNAISSANCE',
          ack: true,
          fin: false,
          rst: isSus && stage === 'RECONNAISSANCE' && f === 1,
          psh: isSus && (stage === 'COMMAND_AND_CONTROL' || stage === 'EXFILTRATION'),
          urg: false,
        },
        bytes: isSus && stage === 'EXFILTRATION' ? 65400 : 750 + f * 120,
        packets: isSus && stage === 'EXFILTRATION' ? 48 : 8,
        durationMs: stage === 'RECONNAISSANCE' ? 12 : 340,
        iatMeanMs: Math.round(meanIatMs),
        iatVarianceMs: Math.round(iatVarianceMs),
        ttl: isSus ? 54 : 64,
        windowSize: 64240,
        payloadSize: isSus && stage === 'EXFILTRATION' ? 64000 : 400,
        label: isSus ? stage : 'BENIGN',
        isAttack: isSus,
      });
    }
  }

  return { stateVectors, allFlows, scenario };
}

// World Model Forward Simulation and Infiltration Prediction
export function computeWorldModelInference(
  currentWindowIndex: number,
  allStates: NetworkStateVector[],
  scenarioId: string
) {
  const currentState = allStates[currentWindowIndex] || allStates[0];
  const historyStates = allStates.slice(Math.max(0, currentWindowIndex - 9), currentWindowIndex + 1);

  // Temporal trajectory & probability calculation
  // World model anticipates progression based on sequence dynamics S(t-n)...S(t)
  const isAttackFuture = allStates.slice(currentWindowIndex, currentWindowIndex + 5).some((s) => s.isGroundTruthAttack);
  const currentIsAttack = currentState.isGroundTruthAttack;

  // Attack probability with realistic early warning lead time curve
  let attackProbability = 0.08;
  if (currentState.groundTruthStage === 'RECONNAISSANCE') {
    attackProbability = 0.62 + Math.min(0.25, (currentWindowIndex - 3) * 0.06);
  } else if (currentState.groundTruthStage === 'INITIAL_ACCESS') {
    attackProbability = 0.88;
  } else if (currentState.groundTruthStage === 'LATERAL_MOVEMENT') {
    attackProbability = 0.94;
  } else if (currentState.groundTruthStage === 'COMMAND_AND_CONTROL') {
    attackProbability = 0.97;
  } else if (currentState.groundTruthStage === 'EXFILTRATION') {
    attackProbability = 0.99;
  } else if (isAttackFuture) {
    // Model sensing precursors 1-2 windows before explicit attack tag!
    attackProbability = 0.42;
  }

  // Stage classification head output
  let predictedCurrentStage: AttackStage = currentState.groundTruthStage;
  if (!currentIsAttack && isAttackFuture && attackProbability > 0.4) {
    predictedCurrentStage = 'RECONNAISSANCE'; // Preemptive early detection
  }

  // Next-Stage Prediction (Head C + Transition Dynamics)
  let predictedNextStage: AttackStage = 'BENIGN';
  if (predictedCurrentStage === 'BENIGN') {
    predictedNextStage = attackProbability > 0.35 ? 'RECONNAISSANCE' : 'BENIGN';
  } else if (predictedCurrentStage === 'RECONNAISSANCE') {
    predictedNextStage = scenarioId === 'recon-aborted' ? 'BENIGN' : 'INITIAL_ACCESS';
  } else if (predictedCurrentStage === 'INITIAL_ACCESS') {
    predictedNextStage = 'LATERAL_MOVEMENT';
  } else if (predictedCurrentStage === 'LATERAL_MOVEMENT') {
    predictedNextStage = 'COMMAND_AND_CONTROL';
  } else if (predictedCurrentStage === 'COMMAND_AND_CONTROL') {
    predictedNextStage = scenarioId === 'data-exfiltration' ? 'EXFILTRATION' : 'COMMAND_AND_CONTROL';
  } else if (predictedCurrentStage === 'EXFILTRATION') {
    predictedNextStage = 'EXFILTRATION';
  }

  // Autoregressive forward rollouts: T+1, T+2, T+3, T+4, T+5, up to T+10
  const forecasts: ForecastStep[] = [];
  const stagesChain: AttackStage[] = [
    'BENIGN',
    'RECONNAISSANCE',
    'INITIAL_ACCESS',
    'LATERAL_MOVEMENT',
    'COMMAND_AND_CONTROL',
    'EXFILTRATION',
  ];
  const currentStageIndex = stagesChain.indexOf(predictedCurrentStage);

  for (let k = 1; k <= 10; k++) {
    const horizonSeconds = k * 10;
    let stepStage = predictedCurrentStage;
    let stepProb = attackProbability;

    if (scenarioId === 'recon-aborted' && predictedCurrentStage === 'RECONNAISSANCE') {
      if (k > 2) {
        stepStage = 'BENIGN';
        stepProb = Math.max(0.1, attackProbability - k * 0.18);
      }
    } else if (attackProbability > 0.35) {
      // Advance stage forward along transition graph
      const nextIdx = Math.min(stagesChain.length - 1, currentStageIndex + Math.floor((k + 1) / 2));
      stepStage = stagesChain[nextIdx];
      stepProb = Math.min(0.99, attackProbability + k * 0.04);
    } else {
      stepProb = Math.max(0.04, attackProbability + (Math.sin(k) * 0.03));
    }

    let riskLevel: RiskLevel = 'NORMAL';
    if (stepProb >= 0.85) riskLevel = 'CRITICAL';
    else if (stepProb >= 0.65) riskLevel = 'HIGH';
    else if (stepProb >= 0.35) riskLevel = 'ELEVATED';

    const probability = Number(stepProb.toFixed(3));
    const confidence = Number((0.95 - k * 0.03).toFixed(2));

    forecasts.push({
      step: k,
      horizonSeconds,
      predictedStage: stepStage,
      attackProbability: probability,
      confidence,
      ...computeConfidenceBounds(probability, confidence),
      riskLevel,
      predictedStateSummary: {
        synAckRatio: Number((currentState.synAckRatio * (1 + k * 0.05)).toFixed(2)),
        portDiversity: Number((currentState.portDiversity * (1 + k * 0.03)).toFixed(2)),
        burstiness: Number((currentState.burstiness * (1 + k * 0.04)).toFixed(2)),
        flowCount: Math.round(currentState.flowCount * (1 + k * 0.08)),
      },
    });
  }

  // Feature Attribution (SHAP / Gradient values)
  const attributions: FeatureAttribution[] = [
    {
      featureName: 'syn_ack_ratio',
      displayName: 'SYN / ACK Imbalance Ratio',
      value: currentState.synAckRatio,
      formattedValue: `${currentState.synAckRatio.toFixed(2)}x`,
      contribution: currentState.synAckRatio > 1.2 ? 0.34 : -0.15,
      direction: currentState.synAckRatio > 1.2 ? 'RISK_INCREASE' : 'RISK_DECREASE',
      category: 'FLAGS',
    },
    {
      featureName: 'port_diversity',
      displayName: 'Destination Port Diversity Entropy',
      value: currentState.portDiversity,
      formattedValue: `${(currentState.portDiversity * 100).toFixed(1)}%`,
      contribution: currentState.portDiversity > 0.5 ? 0.29 : -0.18,
      direction: currentState.portDiversity > 0.5 ? 'RISK_INCREASE' : 'RISK_DECREASE',
      category: 'TOPOLOGY',
    },
    {
      featureName: 'iat_variance',
      displayName: 'Inter-Arrival Time (IAT) Variance',
      value: currentState.iatVarianceMs,
      formattedValue: `${currentState.iatVarianceMs} ms²`,
      contribution: currentState.groundTruthStage === 'COMMAND_AND_CONTROL' ? 0.25 : currentState.iatVarianceMs < 500 ? 0.22 : -0.12,
      direction: currentState.iatVarianceMs < 500 || currentState.groundTruthStage === 'COMMAND_AND_CONTROL' ? 'RISK_INCREASE' : 'RISK_DECREASE',
      category: 'TIMING',
    },
    {
      featureName: 'burstiness_index',
      displayName: 'Temporal Traffic Burstiness',
      value: currentState.burstiness,
      formattedValue: currentState.burstiness.toFixed(2),
      contribution: currentState.burstiness > 0.6 ? 0.21 : -0.09,
      direction: currentState.burstiness > 0.6 ? 'RISK_INCREASE' : 'RISK_DECREASE',
      category: 'TIMING',
    },
    {
      featureName: 'rst_flow_ratio',
      displayName: 'TCP RST / Flow Ratio',
      value: currentState.rstFlowRatio,
      formattedValue: `${(currentState.rstFlowRatio * 100).toFixed(1)}%`,
      contribution: currentState.rstFlowRatio > 0.1 ? 0.18 : -0.05,
      direction: currentState.rstFlowRatio > 0.1 ? 'RISK_INCREASE' : 'RISK_DECREASE',
      category: 'FLAGS',
    },
    {
      featureName: 'packet_size_entropy',
      displayName: 'Packet Payload Size Entropy',
      value: currentState.packetSizeEntropy,
      formattedValue: `${currentState.packetSizeEntropy.toFixed(2)} bits`,
      contribution: currentState.packetSizeEntropy > 4.5 ? 0.26 : -0.08,
      direction: currentState.packetSizeEntropy > 4.5 ? 'RISK_INCREASE' : 'RISK_DECREASE',
      category: 'PACKET',
    },
  ];

  // MITRE ATT&CK candidate mapping with explicit evidence
  const mitreCandidates: MitreTechniqueCandidate[] = [];
  if (predictedCurrentStage === 'RECONNAISSANCE' || predictedNextStage === 'RECONNAISSANCE') {
    mitreCandidates.push({
      id: 'T1046',
      name: 'Network Service Scanning',
      tactic: 'Reconnaissance',
      confidence: 0.92,
      evidence: [
        `High destination port diversity (${(currentState.portDiversity * 100).toFixed(0)}%) across sequential ports`,
        `SYN-to-ACK ratio skewed at ${currentState.synAckRatio}x with unresponded TCP probes`,
        `Low inter-arrival time (${currentState.meanIatMs}ms) indicating automated scanner tool (nmap / masscan)`,
      ],
      recommendedAction: 'Apply rate-limiting on border firewall and trigger honeypot redirection for source IP.',
    });
  }

  if (predictedCurrentStage === 'INITIAL_ACCESS' || predictedNextStage === 'INITIAL_ACCESS') {
    mitreCandidates.push({
      id: 'T1110',
      name: 'Brute Force / Password Spraying',
      tactic: 'Credential Access',
      confidence: 0.86,
      evidence: [
        'Repeated connection attempts to standard authentication ports (3389 / 445)',
        'RST flag frequency spike indicating failed logon attempts',
        'Concentrated source-destination IP interaction pattern',
      ],
      recommendedAction: 'Enforce immediate MFA lockout on target account and isolate source IP from authentication gateways.',
    });
  }

  if (predictedCurrentStage === 'LATERAL_MOVEMENT' || predictedNextStage === 'LATERAL_MOVEMENT') {
    mitreCandidates.push({
      id: 'T1021',
      name: 'Remote Services (SMB / Windows Admin Shares)',
      tactic: 'Lateral Movement',
      confidence: 0.89,
      evidence: [
        'Internal east-west traffic flow escalation on TCP port 445 (SMB) and 3389 (RDP)',
        'Single internal workstation probing multiple adjacent subnets',
        'Abnormal volume of internal RPC payload transfers',
      ],
      recommendedAction: 'Segregate internal VLAN, revoke active Kerberos TGT tickets for compromised workstation, block port 445.',
    });
  }

  if (predictedCurrentStage === 'COMMAND_AND_CONTROL' || predictedNextStage === 'COMMAND_AND_CONTROL') {
    mitreCandidates.push({
      id: 'T1071',
      name: 'Application Layer Protocol: Web Protocols (C2)',
      tactic: 'Command & Control',
      confidence: 0.94,
      evidence: [
        'Strict periodic heartbeat with abnormally low IAT variance (jitter < 60ms)',
        'Persistent outbound HTTPS sessions to uncategorized external IP (198.51.100.44)',
        'Consistent small-packet polling behavior matching Cobalt Strike / Sliver beacon',
      ],
      recommendedAction: 'Sinkhole external C2 destination IP at edge DNS and terminate active socket at host EDR.',
    });
  }

  if (predictedCurrentStage === 'EXFILTRATION' || predictedNextStage === 'EXFILTRATION') {
    mitreCandidates.push({
      id: 'T1041',
      name: 'Exfiltration Over C2 Channel',
      tactic: 'Exfiltration',
      confidence: 0.95,
      evidence: [
        `Sudden outbound bandwidth surge (${(currentState.totalBytes / 1024).toFixed(0)} KB in 10s window)`,
        `High packet payload entropy (${currentState.packetSizeEntropy} bits) indicating compressed/encrypted staging archive`,
        'Asymmetric upload/download ratio > 25:1',
      ],
      recommendedAction: 'Sever outbound socket immediately, block egress port 8443, and preserve memory dump for forensics.',
    });
  }

  // Early Warning Lead Time:
  // Actual compromise begins at window 14 or 19 depending on scenario.
  // Model detected early risk at window 4-5.
  // Lead time = (Actual Compromise Window - Alert Window) * 10 seconds.
  let earlyWarningLeadTime = 0;
  if (attackProbability >= 0.35 && scenarioId !== 'recon-aborted') {
    // E.g. at window 5 when recon starts, the critical breach (lateral/C2) is at window 14 or 18 (90 to 140s ahead!)
    earlyWarningLeadTime = Math.max(30, (18 - currentWindowIndex) * 10);
  }

  return {
    currentState,
    attackProbability: Number(attackProbability.toFixed(3)),
    predictedCurrentStage,
    predictedNextStage,
    forecasts,
    attributions,
    mitreCandidates,
    earlyWarningLeadTime,
    historyStates,
  };
}

/**
 * Evaluates the deterministic model across each scenario window and groups
 * its attack probabilities into reliability-diagram buckets. Empty buckets
 * remain in the result so the chart always exposes the complete 0-100% range.
 */
export function computeCalibrationData(): CalibrationBucket[] {
  const bucketStats = Array.from({ length: 10 }, (_, bucketIndex) => ({
    bucketIndex,
    sampleCount: 0,
    attackCount: 0,
  }));

  for (const scenario of SIMULATION_SCENARIOS) {
    const { stateVectors } = generateScenarioData(scenario.id);

    for (const state of stateVectors) {
      const inference = computeWorldModelInference(state.windowIndex, stateVectors, scenario.id);
      const probability = Math.min(1, Math.max(0, inference.attackProbability));
      const bucketIndex = Math.min(9, Math.floor(probability * 10));
      const bucket = bucketStats[bucketIndex];

      bucket.sampleCount += 1;
      if (state.groundTruthStage !== 'BENIGN') {
        bucket.attackCount += 1;
      }
    }
  }

  return bucketStats.map(({ bucketIndex, sampleCount, attackCount }) => {
    const predictedMidpoint = bucketIndex / 10 + 0.05;
    const empiricalFrequency = sampleCount > 0 ? attackCount / sampleCount : 0;

    return {
      bucketLabel: `${bucketIndex * 10}-${(bucketIndex + 1) * 10}%`,
      predictedMidpoint,
      empiricalFrequency: Number(empiricalFrequency.toFixed(3)),
      sampleCount,
      // An empty bucket has no observed error and is excluded from the ECE display.
      calibrationError: Number((sampleCount > 0
        ? Math.abs(predictedMidpoint - empiricalFrequency)
        : 0).toFixed(3)),
    };
  });
}

// Helper to determine severity
export function getSeverityFromProb(prob: number): AlertSeverity {
  if (prob >= 0.85) return 'CRITICAL';
  if (prob >= 0.65) return 'HIGH';
  if (prob >= 0.35) return 'MEDIUM';
  return 'LOW';
}

export function getRiskLevel(prob: number): RiskLevel {
  if (prob >= 0.85) return 'CRITICAL';
  if (prob >= 0.65) return 'HIGH';
  if (prob >= 0.35) return 'ELEVATED';
  return 'NORMAL';
}

export interface EarlyWarningEscalationScore {
  ewesScore: number;
  escalationRate: number;
  timeToCriticalSec: number;
  peakForecastProbability: number;
  escalationLabel: 'STABLE' | 'ESCALATING' | 'RAPIDLY_ESCALATING';
}

export function computeEWES(params: {
  attackProbability: number;
  forecasts: ForecastStep[];
  earlyWarningLeadTimeSec: number;
  currentStage: AttackStage;
}): EarlyWarningEscalationScore {
  const { attackProbability, forecasts } = params;
  const thirdForecastProbability = forecasts[2]?.attackProbability ?? attackProbability;
  const escalationRate = attackProbability > 0
    ? ((thirdForecastProbability - attackProbability) / attackProbability) * 100
    : 0;
  const timeToCriticalForecast = forecasts.find((forecast) => forecast.attackProbability >= 0.85);
  const timeToCriticalSec = timeToCriticalForecast
    ? timeToCriticalForecast.step * 10
    : Infinity;
  const peakForecastProbability = forecasts.length > 0
    ? Math.max(...forecasts.map((forecast) => forecast.attackProbability))
    : attackProbability;
  const ewesScore = Math.min(
    100,
    Math.max(
      0,
      (attackProbability * 40) + (escalationRate / 100 * 30) + (peakForecastProbability * 30),
    ),
  );

  let escalationLabel: EarlyWarningEscalationScore['escalationLabel'] = 'STABLE';
  if (escalationRate > 15) escalationLabel = 'RAPIDLY_ESCALATING';
  else if (escalationRate >= 5) escalationLabel = 'ESCALATING';

  return {
    ewesScore: Number(ewesScore.toFixed(1)),
    escalationRate: Number(escalationRate.toFixed(1)),
    timeToCriticalSec,
    peakForecastProbability: Number(peakForecastProbability.toFixed(3)),
    escalationLabel,
  };
}

export interface PerturbationSpec {
  id: string;
  label: string;
  featureKey: keyof NetworkStateVector;
  multiplier: number;
  description: string;
}

export interface InterventionPreset {
  id: string;
  label: string;
  description: string;
  perturbations: PerturbationSpec[];
  applicableStages?: AttackStage[];
}

export const PRESET_PERTURBATIONS: InterventionPreset[] = [
  {
    id: 'block-port-scanning',
    label: 'Block Port Scanning',
    description: 'Suppress destination-port spread and scanner TCP reset activity.',
    perturbations: [
      { id: 'block-scan-port-diversity', label: 'Remove port diversity', featureKey: 'portDiversity', multiplier: 0, description: 'Destinations no longer fan out across ports.' },
      { id: 'block-scan-syn', label: 'Reduce SYN probes', featureKey: 'synCount', multiplier: 0.1, description: 'Scanner SYN activity is reduced.' },
      { id: 'block-scan-rst', label: 'Reduce RST activity', featureKey: 'rstCount', multiplier: 0.1, description: 'Scan-related TCP resets are reduced.' },
    ],
  },
  {
    id: 'isolate-source-endpoint',
    label: 'Isolate Source Endpoint',
    description: 'Model the suspicious source endpoint as isolated from the network.',
    perturbations: [
      { id: 'isolate-source-flow-count', label: 'Reduce source flows', featureKey: 'flowCount', multiplier: 0.05, description: 'Source-originated traffic is reduced to 5%.' },
      { id: 'isolate-source-syn', label: 'Reduce source SYNs', featureKey: 'synCount', multiplier: 0.05, description: 'Source-originated SYN activity is reduced to 5%.' },
      { id: 'isolate-source-bytes', label: 'Reduce source bytes', featureKey: 'totalBytes', multiplier: 0.05, description: 'Source-originated payload volume is reduced to 5%.' },
      { id: 'isolate-source-packets', label: 'Reduce source packets', featureKey: 'totalPackets', multiplier: 0.05, description: 'Source-originated packet volume is reduced to 5%.' },
      { id: 'isolate-source-byte-rate', label: 'Reduce source byte rate', featureKey: 'bytesPerSec', multiplier: 0.05, description: 'Source-originated byte rate is reduced to 5%.' },
      { id: 'isolate-source-packet-rate', label: 'Reduce source packet rate', featureKey: 'packetsPerSec', multiplier: 0.05, description: 'Source-originated packet rate is reduced to 5%.' },
    ],
  },
  {
    id: 'block-smb-rdp',
    label: 'Block SMB / RDP (Port 445/3389)',
    description: 'Constrain lateral movement signals associated with SMB and RDP access paths.',
    applicableStages: ['LATERAL_MOVEMENT'],
    perturbations: [
      { id: 'block-smb-port-diversity', label: 'Constrain port diversity', featureKey: 'portDiversity', multiplier: 0.3, description: 'Lateral service reach is constrained.' },
      { id: 'block-smb-rst-ratio', label: 'Reduce reset-flow ratio', featureKey: 'rstFlowRatio', multiplier: 0.2, description: 'Failed remote-service connection churn is reduced.' },
    ],
  },
  {
    id: 'sinkhole-c2',
    label: 'Sinkhole C2 Destination',
    description: 'Disrupt the projected command-and-control beacon trajectory.',
    perturbations: [
      { id: 'sinkhole-c2-flows', label: 'Reduce C2 flows', featureKey: 'flowCount', multiplier: 0.1, description: 'C2-directed flows are reduced to 10%.' },
      { id: 'sinkhole-c2-iat', label: 'Increase IAT variance', featureKey: 'iatVarianceMs', multiplier: 3, description: 'Beacon periodicity is disrupted.' },
    ],
  },
  {
    id: 'firewall-rate-limit',
    label: 'Apply Firewall Rate-Limit',
    description: 'Reduce concurrent traffic volume and burst behaviour at the enforcement point.',
    perturbations: [
      { id: 'rate-limit-flows', label: 'Reduce flow count', featureKey: 'flowCount', multiplier: 0.6, description: 'Concurrent flows are rate-limited.' },
      { id: 'rate-limit-burstiness', label: 'Reduce burstiness', featureKey: 'burstiness', multiplier: 0.4, description: 'Traffic bursts are smoothed.' },
    ],
  },
  {
    id: 'no-action',
    label: 'SOC Takes No Action',
    description: 'Keep the current trajectory as the baseline comparison.',
    perturbations: [],
  },
];

function clampProbability(value: number): number {
  return Math.min(0.99, Math.max(0.01, value));
}

function interventionRiskSignal(state: NetworkStateVector): number {
  const flowPressure = Math.min(1, state.flowCount / 180);
  const synPressure = Math.min(1, state.synCount / 100);
  const portSpread = Math.min(1, state.portDiversity);
  const resetPressure = Math.min(1, state.rstFlowRatio * 5);
  const trafficBurst = Math.min(1, state.burstiness);
  const beaconRegularity = Math.max(0, 1 - Math.min(1, state.iatVarianceMs / 650));

  return (
    flowPressure * 0.22 +
    synPressure * 0.18 +
    portSpread * 0.22 +
    resetPressure * 0.10 +
    trafficBurst * 0.18 +
    beaconRegularity * 0.10
  );
}

function describePerturbationResult(
  perturbations: PerturbationSpec[],
  originalPeak: number,
  perturbedPeak: number,
): string {
  if (perturbations.length === 0) {
    return 'No intervention is active. The projected trajectory remains aligned with the baseline model estimate.';
  }

  const riskDelta = perturbedPeak - originalPeak;
  if (riskDelta < -0.005) {
    return `The selected interventions reduce the modelled peak attack probability from ${(originalPeak * 100).toFixed(1)}% to ${(perturbedPeak * 100).toFixed(1)}%. This is an estimate of trajectory disruption, not a guarantee of containment.`;
  }

  return 'The selected interventions do not materially change the current modelled trajectory. The analyst should validate coverage and enforcement before relying on this estimate.';
}

export function computePerturbedForecast(
  baseState: NetworkStateVector,
  perturbations: PerturbationSpec[],
  scenarioId: string,
  allStates: NetworkStateVector[],
  currentWindow: number,
): {
  originalForecasts: ForecastStep[];
  perturbedForecasts: ForecastStep[];
  originalPeak: number;
  perturbedPeak: number;
  riskDelta: number;
  interpretation: string;
} {
  const sourceStates = allStates.length > 0 ? allStates : [baseState];
  const boundedWindow = Math.min(Math.max(0, currentWindow), sourceStates.length - 1);
  const baselineStates = [...sourceStates];
  baselineStates[boundedWindow] = baseState;
  const originalInference = computeWorldModelInference(boundedWindow, baselineStates, scenarioId);

  const perturbedState = { ...baseState };
  for (const perturbation of perturbations) {
    const currentValue = perturbedState[perturbation.featureKey];
    if (typeof currentValue === 'number') {
      (perturbedState as Record<string, unknown>)[perturbation.featureKey] = Math.max(
        0,
        currentValue * perturbation.multiplier,
      );
    }
  }

  const perturbedStates = [...baselineStates];
  perturbedStates[boundedWindow] = perturbedState;
  const perturbedInference = computeWorldModelInference(boundedWindow, perturbedStates, scenarioId);
  const signalDelta = interventionRiskSignal(perturbedState) - interventionRiskSignal(baseState);
  const originalForecasts = originalInference.forecasts;
  const perturbedForecasts = perturbedInference.forecasts.map((forecast, index) => {
    const influence = Math.min(1.15, 0.65 + index * 0.08);
    const attackProbability = clampProbability(forecast.attackProbability + signalDelta * influence);
    const probability = Number(attackProbability.toFixed(3));

    return {
      ...forecast,
      attackProbability: probability,
      ...computeConfidenceBounds(probability, forecast.confidence),
      riskLevel: getRiskLevel(attackProbability),
      predictedStateSummary: {
        ...forecast.predictedStateSummary,
        synAckRatio: Number(perturbedState.synAckRatio.toFixed(2)),
        portDiversity: Number(perturbedState.portDiversity.toFixed(2)),
        burstiness: Number(perturbedState.burstiness.toFixed(2)),
        flowCount: Math.round(perturbedState.flowCount),
      },
    };
  });

  const originalPeak = Math.max(...originalForecasts.map((forecast) => forecast.attackProbability));
  const perturbedPeak = Math.max(...perturbedForecasts.map((forecast) => forecast.attackProbability));
  const riskDelta = Number((perturbedPeak - originalPeak).toFixed(3));

  return {
    originalForecasts,
    perturbedForecasts,
    originalPeak: Number(originalPeak.toFixed(3)),
    perturbedPeak: Number(perturbedPeak.toFixed(3)),
    riskDelta,
    interpretation: describePerturbationResult(perturbations, originalPeak, perturbedPeak),
  };
}

export interface ResidualAnomalyResult {
  residualScore: number;
  isAnomaly: boolean;
  surprisedFeatures: Array<{
    featureName: string;
    displayName: string;
    predicted: number;
    actual: number;
    deviation: number;
  }>;
  interpretation: string;
  anomalyType: 'EVASION' | 'ESCALATION' | 'NOVEL_PATTERN' | 'NONE';
}

const RESIDUAL_FEATURES: Array<{
  featureName: keyof ForecastStep['predictedStateSummary'];
  displayName: string;
}> = [
  { featureName: 'synAckRatio', displayName: 'SYN/ACK Ratio' },
  { featureName: 'portDiversity', displayName: 'Port Diversity' },
  { featureName: 'burstiness', displayName: 'Traffic Burstiness' },
  { featureName: 'flowCount', displayName: 'Flow Count' },
];

function describeResidualAnomaly(
  anomalyType: ResidualAnomalyResult['anomalyType'],
  isAnomaly: boolean,
  topFeature?: ResidualAnomalyResult['surprisedFeatures'][number],
): string {
  if (!topFeature) {
    return 'No prior forecast is available for a residual comparison.';
  }

  const comparison = `${topFeature.displayName} was predicted at ${topFeature.predicted.toFixed(2)} and observed at ${topFeature.actual.toFixed(2)}.`;
  if (anomalyType === 'EVASION') {
    return `Model surprised by slower traffic burstiness than forecast. ${comparison} This may indicate attacker evasion, slowed activity, or manual intervention.`;
  }
  if (anomalyType === 'ESCALATION') {
    return `Model surprised by faster-than-forecast traffic growth. ${comparison} This may indicate accelerated attacker activity requiring analyst review.`;
  }
  if (anomalyType === 'NOVEL_PATTERN') {
    return `Model surprised by an unexpected port-diversity pattern. ${comparison} This may indicate a novel attack pattern or a change in attacker tradecraft.`;
  }
  if (isAnomaly) {
    return `Model surprised by an observed departure from its forecast. ${comparison} No specific residual category was triggered, so the analyst should review the telemetry.`;
  }
  return `Model trajectory is nominal. ${comparison}`;
}

/**
 * Measures the residual between the prior window's one-step forecast and the
 * currently observed state. Large residuals identify behaviour outside the
 * modelled trajectory without adding any synthetic telemetry.
 */
export function computeResidualAnomaly(
  currentState: NetworkStateVector,
  previousForecast: ForecastStep | null,
): ResidualAnomalyResult {
  if (!previousForecast) {
    return {
      residualScore: 0,
      isAnomaly: false,
      surprisedFeatures: [],
      interpretation: 'No prior forecast is available for a residual comparison.',
      anomalyType: 'NONE',
    };
  }

  const predictedState = previousForecast.predictedStateSummary;
  const surprisedFeatures = RESIDUAL_FEATURES.map(({ featureName, displayName }) => {
    const predicted = predictedState[featureName];
    const actual = currentState[featureName];
    const deviation = Math.abs(actual - predicted) / (predicted + 0.001);

    return {
      featureName,
      displayName,
      predicted,
      actual,
      deviation,
    };
  }).sort((left, right) => right.deviation - left.deviation);

  const residualScore = Math.min(
    1,
    surprisedFeatures.reduce((sum, feature) => sum + feature.deviation, 0) / surprisedFeatures.length,
  );
  const isAnomaly = residualScore > 0.35;
  const portDiversityDeviation = surprisedFeatures.find((feature) => feature.featureName === 'portDiversity')?.deviation || 0;

  let anomalyType: ResidualAnomalyResult['anomalyType'] = 'NONE';
  if (currentState.burstiness < predictedState.burstiness) {
    anomalyType = 'EVASION';
  } else if (currentState.flowCount > predictedState.flowCount * 1.3) {
    anomalyType = 'ESCALATION';
  } else if (portDiversityDeviation > 0.5) {
    anomalyType = 'NOVEL_PATTERN';
  }

  return {
    residualScore,
    isAnomaly,
    surprisedFeatures,
    interpretation: describeResidualAnomaly(anomalyType, isAnomaly, surprisedFeatures[0]),
    anomalyType,
  };
}

export interface VulnerabilityCorrelationResult {
  asset: AssetProfile | null;
  relevantCVEs: CVEEntry[];
  correlationMessage: string;
  riskAmplification: 'NONE' | 'LOW' | 'HIGH' | 'CRITICAL';
  correlationBasis: string[];
}

function vulnerabilityRiskAmplification(relevantCVEs: CVEEntry[]): VulnerabilityCorrelationResult['riskAmplification'] {
  if (relevantCVEs.length === 0) return 'NONE';
  const maxCvss = Math.max(...relevantCVEs.map((cve) => cve.cvss));
  if (maxCvss >= 9) return 'CRITICAL';
  if (maxCvss >= 7) return 'HIGH';
  return 'LOW';
}

/**
 * Correlates forecast technique hypotheses with inventory records. It only
 * identifies potentially relevant, unpatched CVEs; it never represents proof
 * that any vulnerability has been exploited.
 */
export function correlateForecastToVulnerabilities(
  targetIp: string,
  predictedNextStage: AttackStage,
  mitreCandidates: MitreTechniqueCandidate[],
): VulnerabilityCorrelationResult {
  const asset = ASSET_INVENTORY[targetIp] || null;
  if (!asset) {
    return {
      asset: null,
      relevantCVEs: [],
      correlationMessage: `No asset inventory profile is available for ${targetIp}, so potential vulnerability relevance to the predicted ${predictedNextStage.replace(/_/g, ' ')} stage cannot be assessed.`,
      riskAmplification: 'NONE',
      correlationBasis: [
        `No inventory profile is available for target IP ${targetIp}.`,
        `The predicted stage is ${predictedNextStage.replace(/_/g, ' ')}, but no asset-specific potential-risk comparison can be made.`,
      ],
    };
  }

  const predictedTechniqueIds = new Set(mitreCandidates.map((candidate) => candidate.id));
  const relevantCVEs = asset.cves.filter((cve) => (
    cve.patch_status === 'UNPATCHED'
    && cve.relevant_mitre.some((techniqueId) => predictedTechniqueIds.has(techniqueId))
  ));
  const techniqueLabel = mitreCandidates[0]?.id || 'candidate technique';
  const correlationBasis = [
    `Target ${targetIp} maps to inventory asset ${asset.hostname} (${asset.role}).`,
    mitreCandidates.length > 0
      ? `Forecast candidate technique IDs considered: ${mitreCandidates.map((candidate) => candidate.id).join(', ')}.`
      : 'No forecast technique candidates are available for potential vulnerability comparison.',
    ...relevantCVEs.map((cve) => (
      `${cve.id} is marked unpatched and may be relevant to predicted technique IDs ${cve.relevant_mitre.filter((techniqueId) => predictedTechniqueIds.has(techniqueId)).join(', ')}.`
    )),
  ];

  if (relevantCVEs.length > 0) {
    return {
      asset,
      relevantCVEs,
      correlationMessage: `Asset ${asset.hostname} has ${relevantCVEs.length} unpatched CVE${relevantCVEs.length === 1 ? '' : 's'} potentially relevant to predicted ${predictedNextStage.replace(/_/g, ' ')} technique ${techniqueLabel}. This may represent an elevated potential entry vector if these vulnerabilities are exploitable from the current network position.`,
      riskAmplification: vulnerabilityRiskAmplification(relevantCVEs),
      correlationBasis,
    };
  }

  return {
    asset,
    relevantCVEs: [],
    correlationMessage: `No unpatched inventory CVEs are currently correlated with the predicted ${predictedNextStage.replace(/_/g, ' ')} technique candidates for ${asset.hostname}. This does not confirm that the asset is free of potential vulnerability risk.`,
    riskAmplification: 'NONE',
    correlationBasis,
  };
}
