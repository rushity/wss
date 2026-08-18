"""
core/confidence.py — Confidence Tier Tracker
=============================================
Defines three evidence tiers for injection/exploit findings and enforces
automatic severity/CVSS capping so that weak-signal signals never appear as
Critical or High.

Tiers
-----
CONFIRMED   Direct proof: reflected unique token, OOB callback received,
            timing delta reproduced ≥3×, or actual data exfiltrated.
LIKELY      Two or more independent weak signals agree (e.g. error pattern
            PLUS response-time anomaly), but no direct proof.
UNCONFIRMED Single weak signal only (e.g. one error substring, one generic
            500 response). Auto-capped to severity=Low, CVSS≤3.9.
PENDING     OOB probe sent; awaiting external callback. Resolved to CONFIRMED
            or EXPIRED at end-of-scan.

Usage
-----
    from scanners.core.confidence import ConfidenceTracker as CT

    sev  = CT.cap_severity(severity, confidence)
    cvss = CT.cap_cvss(cvss_score, confidence)

    self.add_vuln(..., severity=sev, cvss_score=cvss, confidence=confidence)
"""

from __future__ import annotations


class ConfidenceTracker:
    # Canonical tier strings (use these constants everywhere)
    CONFIRMED   = "Confirmed"
    LIKELY      = "Likely"
    UNCONFIRMED = "Unconfirmed"
    PENDING     = "Pending"

    VALID_TIERS = {CONFIRMED, LIKELY, UNCONFIRMED, PENDING}

    # Severity order (ascending)
    _SEV_ORDER = ["Info", "Low", "Medium", "High", "Critical"]

    # Maximum allowed severity per tier
    _MAX_SEV: dict[str, str] = {
        CONFIRMED:   "Critical",   # no cap
        LIKELY:      "High",       # confirmed-tier cap not needed; High is reasonable
        UNCONFIRMED: "Low",        # single weak signal — never escalate
        PENDING:     "Medium",     # OOB probe sent but no callback yet
    }

    # Maximum allowed CVSS per tier
    _MAX_CVSS: dict[str, float] = {
        CONFIRMED:   10.0,
        LIKELY:       6.9,
        UNCONFIRMED:  3.9,
        PENDING:      5.9,
    }

    # ------------------------------------------------------------------
    @classmethod
    def cap_severity(cls, severity: str, confidence: str) -> str:
        """
        Return severity capped to the tier maximum.

        Example:
            cap_severity("Critical", "Unconfirmed") → "Low"
            cap_severity("Critical", "Confirmed")   → "Critical"
        """
        confidence = cls.normalize(confidence)
        max_sev = cls._MAX_SEV.get(confidence, "Low")

        try:
            sev_idx = cls._SEV_ORDER.index(severity)
        except ValueError:
            sev_idx = 2  # default to Medium index

        try:
            max_idx = cls._SEV_ORDER.index(max_sev)
        except ValueError:
            max_idx = 2

        return cls._SEV_ORDER[min(sev_idx, max_idx)]

    # ------------------------------------------------------------------
    @classmethod
    def cap_cvss(cls, cvss: float, confidence: str) -> float:
        """
        Return CVSS score capped to the tier maximum.

        Example:
            cap_cvss(9.8, "Unconfirmed") → 3.9
            cap_cvss(9.8, "Likely")      → 6.9
            cap_cvss(9.8, "Confirmed")   → 9.8
        """
        confidence = cls.normalize(confidence)
        max_cvss = cls._MAX_CVSS.get(confidence, 3.9)
        return min(float(cvss), max_cvss)

    # ------------------------------------------------------------------
    @classmethod
    def normalize(cls, confidence: str) -> str:
        """Return a valid tier string, defaulting to UNCONFIRMED for unknown values."""
        if confidence in cls.VALID_TIERS:
            return confidence
        # Case-insensitive lookup
        for tier in cls.VALID_TIERS:
            if confidence.lower() == tier.lower():
                return tier
        return cls.UNCONFIRMED

    # ------------------------------------------------------------------
    @classmethod
    def apply(
        cls,
        severity: str,
        cvss: float,
        confidence: str,
    ) -> tuple[str, float, str]:
        """
        Convenience: return (capped_severity, capped_cvss, normalized_confidence).

        Usage:
            sev, cvss, conf = ConfidenceTracker.apply(sev, cvss, confidence)
            self.add_vuln(..., severity=sev, cvss_score=cvss, confidence=conf)
        """
        conf = cls.normalize(confidence)
        return cls.cap_severity(severity, conf), cls.cap_cvss(cvss, conf), conf
