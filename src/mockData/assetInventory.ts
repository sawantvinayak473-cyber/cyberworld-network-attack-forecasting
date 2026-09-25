export type CVESeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type PatchStatus = 'PATCHED' | 'UNPATCHED';

export interface CVEEntry {
  id: string;
  description: string;
  cvss: number;
  severity: CVESeverity;
  relevant_mitre: string[];
  patch_status: PatchStatus;
}

export interface AssetProfile {
  hostname: string;
  role: string;
  os: string;
  services: string[];
  criticality: number;
  cves: CVEEntry[];
}

/**
 * Demo-only inventory records. They describe potential exposure and are not
 * evidence that a vulnerability has been exploited.
 */
export const ASSET_INVENTORY: Record<string, AssetProfile> = {
  '10.0.0.12': {
    hostname: 'WEBSVR-01',
    role: 'Web Server',
    os: 'Ubuntu 22.04',
    services: ['Apache 2.4.49', 'OpenSSH 8.2', 'MySQL 8.0'],
    criticality: 0.85,
    cves: [
      {
        id: 'CVE-2021-41773',
        description: 'Apache 2.4.49 Path Traversal / RCE',
        cvss: 9.8,
        severity: 'CRITICAL',
        relevant_mitre: ['T1190'],
        patch_status: 'UNPATCHED',
      },
      {
        id: 'CVE-2021-28041',
        description: 'OpenSSH Agent Forwarding Race Condition',
        cvss: 7.2,
        severity: 'HIGH',
        relevant_mitre: ['T1021.004', 'T1110'],
        patch_status: 'PATCHED',
      },
    ],
  },
  '192.168.1.105': {
    hostname: 'WORKSTATION-A',
    role: 'Employee Workstation',
    os: 'Windows 11 Pro',
    services: ['SMBv2', 'RDP', 'Chrome 115'],
    criticality: 0.50,
    cves: [
      {
        id: 'CVE-2020-0796',
        description: 'SMBGhost - SMBv3 Remote Code Execution',
        cvss: 10.0,
        severity: 'CRITICAL',
        relevant_mitre: ['T1021.002'],
        patch_status: 'UNPATCHED',
      },
    ],
  },
};
