import React, { useEffect, useState } from 'react';
import {
  DatabaseZap,
  Globe2,
  ShieldCheck,
  ShieldQuestion,
} from 'lucide-react';
import {
  getOfflineIOCEnrichment,
  IOCEnrichmentData,
} from '../mockData/iocEnrichmentMock';

interface IOCEnrichmentCardProps {
  ip: string;
  label: 'Source' | 'Destination' | 'C2 Server';
}

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const ENRICHMENT_API_URL = `${API_BASE_URL}/api/enrich/ip`;
const REQUEST_TIMEOUT_MS = 2_500;

function countryFlag(countryCode: string): string {
  if (!/^[A-Z]{2}$/.test(countryCode)) return '🏢';
  return String.fromCodePoint(...[...countryCode].map((character) => 127397 + character.charCodeAt(0)));
}

function reputationStyle(confidence: number): { label: string; bar: string; text: string } {
  if (confidence < 0) return { label: 'Unavailable', bar: 'bg-slate-600', text: 'text-slate-400' };
  if (confidence < 30) return { label: 'Low risk', bar: 'bg-emerald-500', text: 'text-emerald-400' };
  if (confidence <= 70) return { label: 'Moderate risk', bar: 'bg-amber-500', text: 'text-amber-400' };
  return { label: 'High risk', bar: 'bg-red-500', text: 'text-red-400' };
}

function LoadingSkeleton(): React.ReactElement {
  return (
    <div className="animate-pulse rounded-xl border border-slate-800 bg-slate-900/80 p-4">
      <div className="mb-4 h-3 w-32 rounded bg-slate-800" />
      <div className="mb-3 h-5 w-48 rounded bg-slate-800" />
      <div className="mb-2 h-2 rounded bg-slate-800" />
      <div className="h-3 w-2/3 rounded bg-slate-800" />
    </div>
  );
}

export const IOCEnrichmentCard: React.FC<IOCEnrichmentCardProps> = ({ ip, label }) => {
  const [enrichment, setEnrichment] = useState<IOCEnrichmentData | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    setIsLoading(true);
    setEnrichment(null);

    const fetchEnrichment = async () => {
      try {
        const response = await fetch(`${ENRICHMENT_API_URL}?ip=${encodeURIComponent(ip)}`, {
          signal: controller.signal,
        });
        if (!response.ok) throw new Error(`Enrichment request failed (${response.status})`);

        const liveData = await response.json() as IOCEnrichmentData;
        // A valid backend response without sources represents an offline
        // upstream result, so prefer the static demo context if it exists.
        const resolvedData = liveData.enrichment_sources.length > 0
          ? liveData
          : getOfflineIOCEnrichment(ip);
        if (active) setEnrichment(resolvedData);
      } catch {
        if (active) setEnrichment(getOfflineIOCEnrichment(ip));
      } finally {
        window.clearTimeout(timeoutId);
        if (active) setIsLoading(false);
      }
    };

    void fetchEnrichment();
    return () => {
      active = false;
      window.clearTimeout(timeoutId);
      controller.abort();
    };
  }, [ip]);

  if (isLoading) return <LoadingSkeleton />;

  if (!enrichment) {
    return (
      <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 text-xs font-mono text-slate-500">
        <div className="flex items-center gap-2 text-slate-400">
          <ShieldQuestion className="h-4 w-4" />
          <span className="font-semibold">{label} IOC: {ip}</span>
        </div>
        <p className="mt-3">No enrichment data available (offline mode)</p>
      </div>
    );
  }

  const reputation = reputationStyle(enrichment.abuse_confidence_pct);
  const reputationWidth = Math.max(0, Math.min(100, enrichment.abuse_confidence_pct));

  return (
    <article className="rounded-xl border border-slate-800 bg-slate-900/80 p-4 shadow-sm">
      <header className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold font-mono text-slate-100">{enrichment.ip}</span>
            <span className="rounded border border-cyan-800 bg-cyan-950 px-1.5 py-0.5 text-[10px] font-mono font-bold uppercase text-cyan-300">
              {label}
            </span>
          </div>
          <div className="mt-1 flex items-center gap-1.5 text-xs text-slate-400">
            <Globe2 className="h-3.5 w-3.5" />
            <span>{countryFlag(enrichment.country_code)}</span>
            <span>{enrichment.country_name || 'Country unavailable'}</span>
          </div>
        </div>
        {enrichment.is_known_malicious ? (
          <ShieldCheck className="h-4 w-4 shrink-0 text-red-400" aria-label="Known malicious indicator" />
        ) : (
          <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-400" aria-label="No known malicious enrichment" />
        )}
      </header>

      <div className="mt-4">
        <div className="flex items-center justify-between text-[10px] font-mono uppercase">
          <span className="text-slate-500">AbuseIPDB confidence</span>
          <span className={`font-bold ${reputation.text}`}>
            {enrichment.abuse_confidence_pct < 0 ? reputation.label : `${enrichment.abuse_confidence_pct}% · ${reputation.label}`}
          </span>
        </div>
        <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-slate-800">
          <div className={`h-full rounded-full ${reputation.bar}`} style={{ width: `${reputationWidth}%` }} />
        </div>
      </div>

      {enrichment.threat_types.length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {enrichment.threat_types.map((threatType) => (
            <span key={threatType} className="rounded border border-red-800/60 bg-red-950/50 px-2 py-0.5 text-[10px] font-mono font-semibold text-red-300">
              {threatType}
            </span>
          ))}
        </div>
      )}

      {enrichment.known_campaigns.length > 0 && (
        <div className="mt-3 border-t border-slate-800 pt-3">
          <div className="mb-1 text-[10px] font-mono uppercase text-slate-500">Known campaigns</div>
          <ul className="space-y-1 text-[11px] font-mono text-amber-300">
            {enrichment.known_campaigns.map((campaign) => <li key={campaign}>• {campaign}</li>)}
          </ul>
        </div>
      )}

      <footer className="mt-3 flex items-center gap-1.5 border-t border-slate-800 pt-2 text-[10px] text-slate-500">
        <DatabaseZap className="h-3 w-3" />
        <span>Enrichment sources: {enrichment.enrichment_sources.join(', ') || 'none'}</span>
      </footer>
    </article>
  );
};
