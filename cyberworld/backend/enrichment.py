"""IOC enrichment with a short-lived local cache and failure-safe lookups."""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

import httpx

from cyberworld.storage.database import CyberWorldDatabase


class IOCEnrichmentService:
    """Enrich public IP indicators without making external availability a dependency."""

    CACHE_TTL_HOURS = 24
    REQUEST_TIMEOUT_SECONDS = 5.0

    def __init__(self, database: Optional[CyberWorldDatabase] = None):
        self.database = database or CyberWorldDatabase()

    @staticmethod
    def _now() -> datetime:
        return datetime.now(timezone.utc)

    @classmethod
    def _timestamp(cls) -> str:
        return cls._now().isoformat()

    @staticmethod
    def _string(value: Any, default: str = "") -> str:
        return value.strip() if isinstance(value, str) else default

    @staticmethod
    def _integer(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _unique(values: Iterable[str]) -> List[str]:
        seen = set()
        result = []
        for value in values:
            normalized = value.strip() if isinstance(value, str) else ""
            if normalized and normalized not in seen:
                seen.add(normalized)
                result.append(normalized)
        return result

    def _empty_result(self, ip: str) -> Dict[str, Any]:
        return {
            "ip": ip,
            "abuse_confidence_pct": -1,
            "country_code": "",
            "country_name": "",
            "asn": "",
            "isp": "",
            "threat_types": [],
            "is_known_malicious": False,
            "otx_pulse_count": 0,
            "known_campaigns": [],
            "first_seen": "",
            "last_seen": "",
            "enrichment_sources": [],
            "cached": False,
            "cached_at": "",
        }

    def _get_cached(self, ip: str) -> Optional[Dict[str, Any]]:
        with self.database.get_connection() as conn:
            row = conn.execute(
                "SELECT enrichment_json, cached_at FROM ioc_cache WHERE ip = ?", (ip,)
            ).fetchone()

        if not row:
            return None

        try:
            cached_at = datetime.fromisoformat(row["cached_at"].replace("Z", "+00:00"))
            if cached_at.tzinfo is None:
                cached_at = cached_at.replace(tzinfo=timezone.utc)
            if self._now() - cached_at > timedelta(hours=self.CACHE_TTL_HOURS):
                return None

            result = json.loads(row["enrichment_json"])
            if not isinstance(result, dict):
                return None
            result["cached"] = True
            result["cached_at"] = row["cached_at"]
            return result
        except (TypeError, ValueError, json.JSONDecodeError):
            return None

    def _save_cache(self, ip: str, result: Dict[str, Any]) -> str:
        cached_at = self._timestamp()
        cache_value = {**result, "cached": False, "cached_at": cached_at}
        with self.database.get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ioc_cache (ip, enrichment_json, cached_at) VALUES (?, ?, ?)",
                (ip, json.dumps(cache_value), cached_at),
            )
            conn.commit()
        return cached_at

    def _fetch_abuseipdb(self, client: httpx.Client, ip: str) -> Optional[Dict[str, Any]]:
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return None

        try:
            response = client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
            return payload.get("data") if isinstance(payload, dict) else None
        except (httpx.HTTPError, ValueError):
            return None

    def _fetch_otx(self, client: httpx.Client, ip: str) -> Optional[Dict[str, Any]]:
        try:
            response = client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            )
            response.raise_for_status()
            payload = response.json()
            return payload if isinstance(payload, dict) else None
        except (httpx.HTTPError, ValueError):
            return None

    def _fetch_ipapi(self, client: httpx.Client, ip: str) -> Optional[Dict[str, Any]]:
        try:
            response = client.get(f"https://ipapi.co/{ip}/json/")
            response.raise_for_status()
            payload = response.json()
            return payload if isinstance(payload, dict) and not payload.get("error") else None
        except (httpx.HTTPError, ValueError):
            return None

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Return normalized enrichment, using cached or available source data only."""
        cached = self._get_cached(ip)
        if cached is not None:
            return cached

        result = self._empty_result(ip)
        source_responses = 0

        try:
            with httpx.Client(timeout=self.REQUEST_TIMEOUT_SECONDS, follow_redirects=True) as client:
                abuse_data = self._fetch_abuseipdb(client, ip)
                otx_data = self._fetch_otx(client, ip)
                ipapi_data = self._fetch_ipapi(client, ip)
        except httpx.HTTPError:
            abuse_data = None
            otx_data = None
            ipapi_data = None

        if abuse_data is not None:
            source_responses += 1
            result["enrichment_sources"].append("AbuseIPDB")
            result["abuse_confidence_pct"] = max(
                0, min(100, self._integer(abuse_data.get("abuseConfidenceScore"), -1))
            )
            result["country_code"] = self._string(abuse_data.get("countryCode"))
            result["country_name"] = self._string(abuse_data.get("countryName"))
            result["isp"] = self._string(abuse_data.get("isp"))
            result["last_seen"] = self._string(abuse_data.get("lastReportedAt"))

        if otx_data is not None:
            source_responses += 1
            result["enrichment_sources"].append("OTX")
            pulse_info = otx_data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
            if not isinstance(pulses, list):
                pulses = []

            result["otx_pulse_count"] = self._integer(
                pulse_info.get("count") if isinstance(pulse_info, dict) else 0
            )
            result["threat_types"] = self._unique(
                tag for pulse in pulses if isinstance(pulse, dict)
                for tag in pulse.get("tags", []) if isinstance(tag, str)
            )
            result["known_campaigns"] = self._unique(
                self._string(pulse.get("name")) for pulse in pulses if isinstance(pulse, dict)
            )
            dates = [
                self._string(pulse.get("created")) for pulse in pulses if isinstance(pulse, dict)
            ]
            modified_dates = [
                self._string(pulse.get("modified")) for pulse in pulses if isinstance(pulse, dict)
            ]
            result["first_seen"] = min((date for date in dates if date), default="")
            if not result["last_seen"]:
                result["last_seen"] = max((date for date in modified_dates if date), default="")

        if ipapi_data is not None:
            source_responses += 1
            result["enrichment_sources"].append("ipapi.co")
            result["country_code"] = result["country_code"] or self._string(ipapi_data.get("country_code"))
            result["country_name"] = result["country_name"] or self._string(ipapi_data.get("country_name"))
            result["asn"] = self._string(ipapi_data.get("asn"))
            result["isp"] = result["isp"] or self._string(ipapi_data.get("org"))

        result["enrichment_sources"] = self._unique(result["enrichment_sources"])
        result["is_known_malicious"] = (
            result["abuse_confidence_pct"] > 0
            or result["otx_pulse_count"] > 0
            or bool(result["threat_types"])
        )

        # Do not cache a total outage: it should be retried once connectivity returns.
        if source_responses:
            result["cached_at"] = self._save_cache(ip, result)
        return result
