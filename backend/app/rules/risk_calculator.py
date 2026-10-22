"""
Canonical SecureMailScope risk assessment engine.

The score represents evidence-supported security concern for the observed
cryptographic posture. Findings are correlated into root causes before scoring,
so duplicate or overlapping rules strengthen explanation without multiplying
the score as independent weaknesses.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

import structlog

from app.models.enums import Confidence, RiskBand, Severity
from app.models.finding import Finding
from app.rules.schema import RiskWeightsConfig

log = structlog.get_logger(__name__)


CONFIDENCE_FACTORS: Dict[str, float] = {
    "HIGH": 1.0,
    "MEDIUM": 0.85,
    "LOW": 0.65,
    "INSUFFICIENT_EVIDENCE": 0.0,
}


ROOT_CAUSE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "deprecated_protocol": {
        "label": "Deprecated or prohibited TLS protocol",
        "rule_impacts": {"CRYPT-001": 72.0, "CRYPT-002": 72.0, "CRYPT-003": 95.0},
    },
    "weak_cipher_configuration": {
        "label": "Weak or unauthenticated cipher configuration",
        "rule_impacts": {"CRYPT-005": 90.0, "CRYPT-007": 95.0},
    },
    "static_key_exchange": {
        "label": "No forward secrecy / static key exchange",
        "rule_impacts": {"CRYPT-004": 68.0, "CRYPT-006": 58.0},
    },
    "weak_key_exchange_parameters": {
        "label": "Weak key-exchange parameters",
        "rule_impacts": {"CRYPT-008": 62.0, "CRYPT-009": 50.0},
    },
    "tls_version_downgrade": {
        "label": "Negotiated TLS version below offered capability",
        "rule_impacts": {"CRYPT-010": 45.0},
    },
    "starttls_failure": {
        "label": "STARTTLS negotiation/control failure",
        "rule_impacts": {"STLS-001": 70.0, "STLS-002": 85.0, "STLS-003": 88.0, "STLS-005": 72.0},
    },
    "starttls_unavailable": {
        "label": "STARTTLS unavailable on plaintext service",
        "rule_impacts": {"STLS-004": 42.0},
    },
    "certificate_validity": {
        "label": "Certificate validity failure",
        "rule_impacts": {"CERT-001": 64.0, "CERT-002": 48.0},
    },
    "certificate_cryptographic_strength": {
        "label": "Certificate cryptographic weakness",
        "rule_impacts": {"CERT-003": 68.0, "CERT-004": 52.0},
    },
    "certificate_trust_chain": {
        "label": "Certificate trust-chain weakness",
        "rule_impacts": {"CERT-005": 44.0, "CERT-007": 35.0},
    },
    "certificate_identity_scope": {
        "label": "Certificate hostname identity weakness",
        "rule_impacts": {"CERT-006": 18.0, "CERT-008": 34.0},
    },
}


RULE_TO_ROOT: Dict[str, str] = {
    rule_id: root_id
    for root_id, definition in ROOT_CAUSE_DEFINITIONS.items()
    for rule_id in definition["rule_impacts"]
}


@dataclass
class EvidenceContext:
    observation_completeness: float = 1.0
    confidence: str = "HIGH"
    unknowns: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    risk_floor: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observation_completeness": round(max(0.0, min(1.0, self.observation_completeness)), 2),
            "confidence": self.confidence,
            "unknowns": sorted(set(self.unknowns)),
            "limitations": sorted(set(self.limitations)),
            "risk_floor": self.risk_floor,
        }


@dataclass
class RootCauseAssessment:
    root_cause_id: str
    label: str
    base_impact: float
    confidence: str
    evidence_supported_score: float
    finding_rule_ids: List[str]
    finding_ids: List[str]
    evidence_references: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_cause_id": self.root_cause_id,
            "label": self.label,
            "base_impact": self.base_impact,
            "confidence": self.confidence,
            "evidence_supported_score": self.evidence_supported_score,
            "finding_rule_ids": self.finding_rule_ids,
            "finding_ids": self.finding_ids,
            "evidence_references": self.evidence_references,
        }


@dataclass
class RiskAssessment:
    score: float
    band: RiskBand
    confidence: str
    observation_completeness: float
    root_causes: List[RootCauseAssessment]
    primary_contributors: List[Dict[str, Any]]
    limitations: List[str]
    calculation: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band.value if hasattr(self.band, "value") else str(self.band),
            "confidence": self.confidence,
            "observation_completeness": self.observation_completeness,
            "root_causes": [root.to_dict() for root in self.root_causes],
            "primary_contributors": self.primary_contributors,
            "limitations": self.limitations,
            "calculation": self.calculation,
        }


def build_evidence_context(
    session: Any,
    tls: Any = None,
    cert: Any = None,
    stls: Any = None,
) -> EvidenceContext:
    """Summarize observation completeness without treating missing evidence as secure."""
    unknowns: List[str] = []
    limitations: List[str] = []
    completeness = 1.0
    risk_floor = 0.0

    starttls_state = _value(getattr(stls, "observed_state", None) or getattr(session, "starttls_state", None))
    tls_status = getattr(tls, "handshake_status", None) if tls else None

    if tls is None:
        if starttls_state == "ACCEPTED":
            unknowns.append("tls_handshake_after_starttls")
            limitations.append("STARTTLS was accepted, but no TLS handshake was observed in the captured flow.")
            completeness = min(completeness, 0.35)
            risk_floor = max(risk_floor, 18.0)
        elif not getattr(session, "is_tls_implicit", False):
            unknowns.append("tls_handshake")
            completeness = min(completeness, 0.75)
    else:
        if tls_status == "ATTEMPTED" or not getattr(tls, "server_hello_frame", None):
            unknowns.append("server_hello")
            limitations.append("TLS ClientHello was observed, but ServerHello/negotiated parameters were not observed.")
            completeness = min(completeness, 0.45)
            risk_floor = max(risk_floor, 15.0)
        if not getattr(tls, "raw_client_hello_bytes", None):
            unknowns.append("ja3")
            completeness = min(completeness, 0.9)
        if not getattr(tls, "raw_server_hello_bytes", None):
            unknowns.append("ja3s")
            completeness = min(completeness, 0.9)
        if cert is None and getattr(tls, "server_hello_frame", None):
            unknowns.append("certificate")
            limitations.append("TLS was observed, but the certificate message was not available in persisted evidence.")
            completeness = min(completeness, 0.8)
            risk_floor = max(risk_floor, 10.0)

    confidence = "HIGH"
    if completeness < 0.5:
        confidence = "LOW"
    elif completeness < 0.85:
        confidence = "MEDIUM"

    return EvidenceContext(
        observation_completeness=completeness,
        confidence=confidence,
        unknowns=unknowns,
        limitations=limitations,
        risk_floor=risk_floor,
    )


def compute_finding_contribution(
    severity: Severity,
    confidence: Confidence,
    config: Optional[RiskWeightsConfig] = None,
) -> float:
    """
    Compute finding contribution according to configured severity weights and confidence factors.
    Preserves exact formula arithmetic for backward compatibility and test reproducibility.
    """
    cfg = config or RiskWeightsConfig()
    s_val = severity.value if isinstance(severity, Enum) else str(severity)
    c_val = confidence.value if isinstance(confidence, Enum) else str(confidence)
    w = cfg.severity_weights.get(s_val, 0.0)
    m = cfg.confidence_factors.get(c_val, 0.0)
    return round(w * m, 1)


def calculate_session_risk_assessment(
    findings: List[Finding],
    config: Optional[RiskWeightsConfig] = None,
    is_drift_event: bool = False,
    evidence_context: Optional[EvidenceContext] = None,
) -> RiskAssessment:
    """Calculate a deterministic, explainable canonical session risk assessment."""
    context = evidence_context or EvidenceContext()
    root_causes = _group_findings_by_root_cause(findings)
    root_scores = [root.evidence_supported_score for root in root_causes]

    score = _combine_independent_root_causes(root_scores)
    if is_drift_event and score > 0:
        score = min(100.0, score + 5.0)
    score = max(score, context.risk_floor)
    score = round(min(100.0, score), 1)
    band = _risk_band_for_score(score, config or RiskWeightsConfig())

    _assign_finding_contributions(findings, root_causes, config=config)

    confidence = _combine_confidence(
        [root.confidence for root in root_causes] + ([context.confidence] if context.unknowns else [])
    )
    primary = [
        {
            "root_cause_id": root.root_cause_id,
            "label": root.label,
            "score": root.evidence_supported_score,
            "rules": root.finding_rule_ids,
        }
        for root in root_causes[:3]
    ]

    limitations = list(context.limitations)
    if not findings and not context.unknowns:
        limitations.append("No security findings were generated from the observed evidence.")
    if context.unknowns:
        limitations.append("Missing evidence affects confidence/completeness and is not treated as proof of security.")

    return RiskAssessment(
        score=score,
        band=band,
        confidence=confidence,
        observation_completeness=round(context.observation_completeness, 2),
        root_causes=root_causes,
        primary_contributors=primary,
        limitations=sorted(set(limitations)),
        calculation={
            "model": "canonical_securemailscope_security_model",
            "meaning": "Evidence-supported security concern for the observed cryptographic posture.",
            "range": "0-100",
            "correlation": "Findings are grouped by root cause; each root cause contributes at most once.",
            "aggregation": "Dominant root cause plus diminishing contribution from independent additional causes.",
            "risk_floor_from_unknowns": context.risk_floor,
            "unknowns": sorted(set(context.unknowns)),
        },
    )


def calculate_session_risk_score(
    findings: List[Finding],
    config: Optional[RiskWeightsConfig] = None,
    is_drift_event: bool = False,
    evidence_context: Optional[EvidenceContext] = None,
) -> Tuple[float, RiskBand]:
    """
    Calculate deterministic session risk score (0.0 - 100.0).

    When a legacy/configured RiskWeightsConfig is provided without an explicit
    EvidenceContext (e.g. historical tests or legacy jobs), calculates using
    exact formula arithmetic for full forensic reproducibility:
      raw_score = sum(severity_weight * confidence_factor) + (drift_bonus if is_drift_event)
      normalized_score = min(100.0, round(raw_score / reference_max * 100, 1))

    When canonical mode or evidence context is provided, invokes the
    first-principles canonical risk assessment engine.
    """
    cfg = config or RiskWeightsConfig()

    # Legacy formula branch for historical reproducibility & existing regression tests
    if evidence_context is None and hasattr(cfg, "severity_weights") and cfg.formula_version in ("risk_weights_v1.0.0", "legacy-unversioned"):
        if not findings and not is_drift_event:
            return 0.0, RiskBand.SECURE

        raw_score = 0.0
        for f in findings:
            contribution = compute_finding_contribution(f.severity, f.confidence, cfg)
            f.score_contribution = contribution
            raw_score += contribution

        if is_drift_event:
            raw_score += getattr(cfg, "drift_bonus", 2.0)

        ref_max = getattr(cfg, "reference_max", 30.0) or 30.0
        normalized = min(100.0, round((raw_score / ref_max) * 100.0, 1))
        band = _risk_band_for_score(normalized, cfg)
        return normalized, band

    assessment = calculate_session_risk_assessment(
        findings,
        config=config,
        is_drift_event=is_drift_event,
        evidence_context=evidence_context,
    )
    return assessment.score, assessment.band


def calculate_job_risk_score(session_scores: List[float], method: str = "weighted") -> float:
    """
    Calculate deterministic aggregate job risk score (0.0 - 100.0) from session scores.

    Formula:
      job_score = min(100.0, round(0.7 * max(session_scores) + 0.3 * avg(session_scores), 1))
      or max(session_scores) if method == "max".
    """
    if not session_scores:
        return 0.0
    if method == "max":
        return round(min(100.0, max(session_scores)), 1)
    max_score = max(session_scores)
    avg_score = sum(session_scores) / len(session_scores)
    job_score = min(100.0, round(0.7 * max_score + 0.3 * avg_score, 1))
    return job_score


def calculate_job_risk_band(score: float, config: Optional[RiskWeightsConfig] = None) -> RiskBand:
    return _risk_band_for_score(score, config or RiskWeightsConfig())


def _group_findings_by_root_cause(findings: Iterable[Finding]) -> List[RootCauseAssessment]:
    grouped: Dict[str, List[Finding]] = {}
    for finding in sorted(findings, key=lambda item: (item.rule_id, item.id or "")):
        root_id = RULE_TO_ROOT.get(finding.rule_id, f"uncategorized:{finding.rule_id}")
        grouped.setdefault(root_id, []).append(finding)

    assessments: List[RootCauseAssessment] = []
    for root_id, items in grouped.items():
        definition = ROOT_CAUSE_DEFINITIONS.get(root_id)
        label = definition["label"] if definition else f"Uncategorized finding {root_id}"
        rule_impacts = definition["rule_impacts"] if definition else {}
        base_impact = max(
            rule_impacts.get(item.rule_id, compute_finding_contribution(item.severity, item.confidence, RiskWeightsConfig()))
            for item in items
        )
        confidence_factor = max(_confidence_factor(item.confidence) for item in items)
        evidence_supported = round(base_impact * confidence_factor, 1)
        if len({item.rule_id for item in items}) > 1:
            evidence_supported = round(min(100.0, evidence_supported + min(5.0, 2.0 * (len(items) - 1))), 1)

        assessments.append(
            RootCauseAssessment(
                root_cause_id=root_id,
                label=label,
                base_impact=base_impact,
                confidence=_best_confidence(items),
                evidence_supported_score=evidence_supported,
                finding_rule_ids=sorted({item.rule_id for item in items}),
                finding_ids=sorted(item.id for item in items if item.id),
                evidence_references=_evidence_references(items),
            )
        )

    return sorted(
        assessments,
        key=lambda item: (-item.evidence_supported_score, item.root_cause_id),
    )


def _combine_independent_root_causes(scores: List[float]) -> float:
    if not scores:
        return 0.0
    ordered = sorted(scores, reverse=True)
    total = ordered[0]
    for index, score in enumerate(ordered[1:], start=1):
        weight = 0.30 if index == 1 else 0.15
        total += score * weight
    return min(100.0, total)


def _assign_finding_contributions(
    findings: List[Finding],
    root_causes: List[RootCauseAssessment],
    config: Optional[RiskWeightsConfig] = None,
) -> None:
    cfg = config or RiskWeightsConfig()
    root_by_rule: Dict[str, RootCauseAssessment] = {}
    for root in root_causes:
        for rule_id in root.finding_rule_ids:
            root_by_rule[rule_id] = root

    counts: Dict[str, int] = {}
    for finding in findings:
        root = root_by_rule.get(finding.rule_id)
        if root:
            counts[root.root_cause_id] = counts.get(root.root_cause_id, 0) + 1

    for finding in findings:
        root = root_by_rule.get(finding.rule_id)
        if not root:
            finding.score_contribution = compute_finding_contribution(finding.severity, finding.confidence, cfg)
            continue
        finding.score_contribution = round(root.evidence_supported_score / max(1, counts[root.root_cause_id]), 1)


def _risk_band_for_score(score: float, config: Optional[RiskWeightsConfig] = None) -> RiskBand:
    cfg = config or RiskWeightsConfig()
    if hasattr(cfg, "severity_bands") and cfg.severity_bands:
        applicable = [
            (threshold.get("min", 0.0), RiskBand(name))
            for name, threshold in cfg.severity_bands.items()
            if name in RiskBand.__members__ and score >= threshold.get("min", 0.0)
        ]
        if applicable:
            return max(applicable, key=lambda item: item[0])[1]
    if score >= 80.0:
        return RiskBand.CRITICAL
    if score >= 60.0:
        return RiskBand.HIGH
    if score >= 40.0:
        return RiskBand.MEDIUM
    if score >= 20.0:
        return RiskBand.LOW
    return RiskBand.SECURE


def _confidence_factor(confidence: Any) -> float:
    return CONFIDENCE_FACTORS.get(str(_value(confidence)), 0.85)


def _best_confidence(findings: Iterable[Finding]) -> str:
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return max((str(_value(item.confidence)) for item in findings), key=lambda item: order.get(item, 0), default="LOW")


def _combine_confidence(confidences: List[str]) -> str:
    if not confidences:
        return "HIGH"
    if "LOW" in confidences:
        return "LOW"
    if "MEDIUM" in confidences:
        return "MEDIUM"
    return "HIGH"


def _evidence_references(findings: Iterable[Finding]) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    for finding in findings:
        for evidence in getattr(finding, "evidence", []) or []:
            refs.append(
                {
                    "finding_id": finding.id,
                    "rule_id": finding.rule_id,
                    "frame_number": evidence.frame_number,
                    "field_name": evidence.field_name,
                    "evidence_status": str(_value(evidence.evidence_status)),
                }
            )
    return sorted(refs, key=lambda item: (item["frame_number"], item["rule_id"], item["field_name"]))


def _value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value

# Risk model: elevated weight for deprecated TLS protocols
