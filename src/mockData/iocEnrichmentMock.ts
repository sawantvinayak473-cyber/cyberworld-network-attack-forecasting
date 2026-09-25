export interface IOCEnrichmentData {
  ip: string;
  abuse_confidence_pct: number;
  country_code: string;
  country_name: string;
  asn: string;
  isp: string;
  threat_types: string[];
  is_known_malicious: boolean;
  otx_pulse_count: number;
  known_campaigns: string[];
  first_seen: string;
  last_seen: string;
  enrichment_sources: string[];
  cached: boolean;
  cached_at: string;
}

interface OfflineIOCEnrichmentData extends IOCEnrichmentData {
  // Retained as concise demo-map aliases for easy scenario authoring.
  abuse: number;
  country: string;
}

/**
 * Deterministic IOC context for every IP used across the five demo scenarios.
 * This is intentionally separate from live enrichment so air-gapped demos do
 * not rely on a third-party service or imply live reputation data.
 */
export const IOC_ENRICHMENT_OFFLINE_MAP: Record<string, OfflineIOCEnrichmentData> = {
  '192.168.1.105': {
    ip: '192.168.1.105',
    abuse: 0,
    country: 'Internal',
    abuse_confidence_pct: 0,
    country_code: 'INTERNAL',
    country_name: 'Internal',
    asn: '',
    isp: '',
    threat_types: [],
    is_known_malicious: false,
    otx_pulse_count: 0,
    known_campaigns: [],
    first_seen: '',
    last_seen: '',
    enrichment_sources: ['Offline demo data'],
    cached: false,
    cached_at: '',
  },
  '198.51.100.44': {
    ip: '198.51.100.44',
    abuse: 94,
    country: 'NL',
    abuse_confidence_pct: 94,
    country_code: 'NL',
    country_name: 'Netherlands',
    asn: '',
    isp: '',
    threat_types: ['C2', 'Cobalt Strike'],
    is_known_malicious: true,
    otx_pulse_count: 0,
    known_campaigns: ['APT-CobaltStrike-2026-09'],
    first_seen: '',
    last_seen: '',
    enrichment_sources: ['Offline demo data'],
    cached: false,
    cached_at: '',
  },
  '10.0.0.12': {
    ip: '10.0.0.12',
    abuse: 0,
    country: 'Internal',
    abuse_confidence_pct: 0,
    country_code: 'INTERNAL',
    country_name: 'Internal',
    asn: '',
    isp: '',
    threat_types: [],
    is_known_malicious: false,
    otx_pulse_count: 0,
    known_campaigns: [],
    first_seen: '',
    last_seen: '',
    enrichment_sources: ['Offline demo data'],
    cached: false,
    cached_at: '',
  },
};

export function getOfflineIOCEnrichment(ip: string): IOCEnrichmentData | null {
  return IOC_ENRICHMENT_OFFLINE_MAP[ip] || null;
}
