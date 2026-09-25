export interface DemoScriptStep {
  windowIndex: number;
  tab: string;
  copilotMessage: string | null;
  annotation: string;
}

export const DEMO_SCRIPT: DemoScriptStep[] = [
  {
    windowIndex: 3,
    tab: 'dashboard',
    copilotMessage: null,
    annotation: 'Baseline benign traffic — EWES gauge nominal',
  },
  {
    windowIndex: 6,
    tab: 'dashboard',
    copilotMessage: null,
    annotation: 'Reconnaissance detected — 62% attack probability, 140s early warning advantage',
  },
  {
    windowIndex: 6,
    tab: 'what-if',
    copilotMessage: null,
    annotation: 'Intervention: Block port scanning — watch probability drop to 31%',
  },
  {
    windowIndex: 10,
    tab: 'investigation',
    copilotMessage: 'Why is this critical and what happens next?',
    annotation: 'INITIAL_ACCESS alert — Copilot explains in plain language',
  },
  {
    windowIndex: 14,
    tab: 'digital-twin',
    copilotMessage: null,
    annotation: 'Attack Digital Twin — particle at LATERAL_MOVEMENT, C2 node glowing in red',
  },
  {
    windowIndex: 18,
    tab: 'investigation',
    copilotMessage: 'Generate an incident report for management',
    annotation: 'Copilot generates executive summary',
  },
  {
    windowIndex: 18,
    tab: 'benchmarks',
    copilotMessage: null,
    annotation: 'Benchmark comparison — World Model vs RF: 142s early warning advantage',
  },
];
