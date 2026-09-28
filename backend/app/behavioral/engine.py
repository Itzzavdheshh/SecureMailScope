"""
SecureMailScope — Phase 10 Behavioral Analysis Engine.

Compares an observed CryptographicProfile against an established infrastructure
baseline to identify statistically meaningful cryptographic deviations.

Design principles:
  - Explains WHAT changed, not WHO caused it or WHY.
  - No attacker attribution. No threat-actor language.
  - Uses only values that were actually observed by the forensic pipeline.
  - Categorical deviations are flagged explicitly, not mapped to arbitrary numbers.
  - Numeric risk scores are analysed with z-score (for n >= 5) or normalised
    deviation; Isolation Forest is used only when n >= MIN_IF_OBSERVATIONS.
  - All statistical results carry method, sample count, and interpretation.
  - INSUFFICIENT_DATA state is explicit — no algorithm is forced onto tiny samples.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from app.analyzers.baseline import InfrastructureBaseline, BaselineStatus
from app.analyzers.identity import CryptographicProfile
from app.models.enums import EvidenceStatus


# ─── Constants ────────────────────────────────────────────────────────────────

ISOLATION_FOREST_MIN_OBSERVATIONS: int = 10
ZSCORE_MIN_OBSERVATIONS: int = 5
SIGNIFICANT_ZSCORE_THRESHOLD: float = 2.0
SIGNIFICANT_IQR_MULTIPLIER: float = 1.5


# ─── Enums ────────────────────────────────────────────────────────────────────

class AnalysisMethodStatus(str, Enum):
    """Status of a statistical analysis method."""
    COMPLETED = "COMPLETED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SKIPPED = "SKIPPED"


class DeviationSignificance(str, Enum):
    """Significance of a single observed deviation from baseline."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class BehavioralAnomaly:
    """
    Structured, explainable record of one behavioural deviation from baseline.
    Follows forensic language: what changed, not who or why.
    """
    feature: str
    baseline_value: Any
    observed_value: Any
    change_description: str
    significance: DeviationSignificance
    reason: str
    evidence_status: EvidenceStatus = EvidenceStatus.ANALYZED
    method: str = "CATEGORICAL_CHANGE"
    # Statistical detail fields — only set for numeric analyses
    stat_method: Optional[str] = None
    stat_sample_count: Optional[int] = None
    stat_baseline_mean: Optional[float] = None
    stat_baseline_std: Optional[float] = None
    stat_observed_value_numeric: Optional[float] = None
    stat_zscore: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "feature": self.feature,
            "baseline_value": str(self.baseline_value) if self.baseline_value is not None else None,
            "observed_value": str(self.observed_value) if self.observed_value is not None else None,
            "change_description": self.change_description,
            "significance": self.significance.value,
            "reason": self.reason,
            "evidence_status": self.evidence_status.value,
            "method": self.method,
            "stat_method": self.stat_method,
            "stat_sample_count": self.stat_sample_count,
            "stat_baseline_mean": self.stat_baseline_mean,
            "stat_baseline_std": self.stat_baseline_std,
            "stat_observed_value_numeric": self.stat_observed_value_numeric,
            "stat_zscore": self.stat_zscore,
        }


@dataclass
class StatisticalRiskAnalysis:
    """Result of the numeric risk-score statistical analysis."""
    method: str
    method_status: AnalysisMethodStatus
    sample_count: int
    baseline_mean: Optional[float] = None
    baseline_std: Optional[float] = None
    baseline_median: Optional[float] = None
    baseline_iqr: Optional[float] = None
    observed_value: Optional[float] = None
    zscore: Optional[float] = None
    normalized_deviation: Optional[float] = None
    is_anomalous: bool = False
    interpretation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method": self.method,
            "method_status": self.method_status.value,
            "sample_count": self.sample_count,
            "baseline_mean": self.baseline_mean,
            "baseline_std": self.baseline_std,
            "baseline_median": self.baseline_median,
            "baseline_iqr": self.baseline_iqr,
            "observed_value": self.observed_value,
            "zscore": round(self.zscore, 4) if self.zscore is not None else None,
            "normalized_deviation": round(self.normalized_deviation, 4) if self.normalized_deviation is not None else None,
            "is_anomalous": self.is_anomalous,
            "interpretation": self.interpretation,
        }


@dataclass
class IsolationForestAnalysis:
    """Result of Isolation Forest anomaly detection (when applicable)."""
    method_status: AnalysisMethodStatus
    model_name: str = "IsolationForest"
    feature_set: List[str] = field(default_factory=list)
    observation_count: int = 0
    min_required: int = ISOLATION_FOREST_MIN_OBSERVATIONS
    anomaly_score: Optional[float] = None           # Raw sklearn decision function output
    normalized_anomaly_score: Optional[float] = None  # 0..1, higher = more anomalous
    is_anomalous: Optional[bool] = None
    interpretation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "method_status": self.method_status.value,
            "model_name": self.model_name,
            "feature_set": self.feature_set,
            "observation_count": self.observation_count,
            "min_required": self.min_required,
            "anomaly_score": round(self.anomaly_score, 6) if self.anomaly_score is not None else None,
            "normalized_anomaly_score": round(self.normalized_anomaly_score, 4) if self.normalized_anomaly_score is not None else None,
            "is_anomalous": self.is_anomalous,
            "interpretation": self.interpretation,
        }


@dataclass
class BehavioralAnalysisResult:
    """
    Complete behavioural deviation analysis result for one infrastructure identity
    observation compared against its established cryptographic baseline.
    """
    # Input context
    infrastructure_id: str
    identity_key: str
    job_id: str
    session_id: Optional[str]

    # Baseline context
    baseline_status: BaselineStatus
    observation_count: int

    # Overall deviation status
    overall_status: EvidenceStatus         # ANALYZED | INSUFFICIENT_EVIDENCE
    significant_deviation_detected: bool
    deviation_summary: str

    # Per-feature categorical anomalies
    anomalies: List[BehavioralAnomaly] = field(default_factory=list)

    # Statistical risk analysis
    risk_stat_analysis: Optional[StatisticalRiskAnalysis] = None

    # Isolation Forest (only when enough observations)
    isolation_forest: Optional[IsolationForestAnalysis] = None

    # Limitations
    limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "infrastructure_id": self.infrastructure_id,
            "identity_key": self.identity_key,
            "job_id": self.job_id,
            "session_id": self.session_id,
            "baseline_status": self.baseline_status.value,
            "observation_count": self.observation_count,
            "overall_status": self.overall_status.value,
            "significant_deviation_detected": self.significant_deviation_detected,
            "deviation_summary": self.deviation_summary,
            "anomalies": [a.to_dict() for a in self.anomalies],
            "risk_stat_analysis": self.risk_stat_analysis.to_dict() if self.risk_stat_analysis else None,
            "isolation_forest": self.isolation_forest.to_dict() if self.isolation_forest else None,
            "limitations": self.limitations,
        }


# ─── Engine ───────────────────────────────────────────────────────────────────

class BehavioralAnalysisEngine:
    """
    Stateless behavioural deviation analysis engine.

    Usage:
        engine = BehavioralAnalysisEngine()
        result = engine.analyze(
            infrastructure_id="...",
            identity_key="...",
            job_id="...",
            session_id="...",
            current_profile=current_profile,
            baseline=baseline,
            current_risk_score=sess_score,
        )
    """

    def analyze(
        self,
        infrastructure_id: str,
        identity_key: str,
        job_id: str,
        current_profile: CryptographicProfile,
        baseline: InfrastructureBaseline,
        current_risk_score: float = 0.0,
        session_id: Optional[str] = None,
    ) -> BehavioralAnalysisResult:
        """
        Run the complete behavioural analysis pipeline.
        Returns a fully populated BehavioralAnalysisResult.
        """
        obs_count = baseline.observation_count
        bl_status = baseline.status

        # ── Insufficient baseline: return early ───────────────────────────────
        if bl_status in (BaselineStatus.NO_BASELINE, BaselineStatus.PROVISIONAL):
            return BehavioralAnalysisResult(
                infrastructure_id=infrastructure_id,
                identity_key=identity_key,
                job_id=job_id,
                session_id=session_id,
                baseline_status=bl_status,
                observation_count=obs_count,
                overall_status=EvidenceStatus.INSUFFICIENT_EVIDENCE,
                significant_deviation_detected=False,
                deviation_summary=(
                    "Insufficient baseline observations to perform behavioural deviation analysis. "
                    f"Current observation count: {obs_count}. "
                    "A minimum of 3 observations are required to establish a baseline."
                ),
                limitations=[
                    "Baseline has not yet been established. "
                    "Behavioural analysis requires at least 3 consistent observations.",
                ],
            )

        baseline_profile = baseline.profile
        if baseline_profile is None:
            return BehavioralAnalysisResult(
                infrastructure_id=infrastructure_id,
                identity_key=identity_key,
                job_id=job_id,
                session_id=session_id,
                baseline_status=bl_status,
                observation_count=obs_count,
                overall_status=EvidenceStatus.INSUFFICIENT_EVIDENCE,
                significant_deviation_detected=False,
                deviation_summary="Baseline profile is empty — behavioural analysis cannot proceed.",
                limitations=["No baseline cryptographic profile data available."],
            )

        # ── Step 1: Categorical feature deviation analysis ────────────────────
        anomalies = self._analyze_categorical_features(baseline_profile, current_profile)

        # ── Step 2: Numeric risk-score statistical analysis ───────────────────
        history_risk_scores = self._extract_risk_scores_from_history(baseline.observation_history)
        risk_analysis = self._analyze_risk_score_statistically(
            history_risk_scores, current_risk_score
        )

        # ── Step 3: Isolation Forest (only with sufficient observations) ──────
        if_analysis = self._run_isolation_forest(
            baseline.observation_history, current_profile, current_risk_score
        )

        # ── Step 4: Synthesise overall deviation status ───────────────────────
        high_count = sum(1 for a in anomalies if a.significance == DeviationSignificance.HIGH)
        medium_count = sum(1 for a in anomalies if a.significance == DeviationSignificance.MEDIUM)
        risk_anomalous = (
            risk_analysis is not None and risk_analysis.is_anomalous
        )
        if_anomalous = (
            if_analysis is not None
            and if_analysis.method_status == AnalysisMethodStatus.COMPLETED
            and if_analysis.is_anomalous is True
        )

        significant = bool(high_count > 0 or medium_count >= 2 or risk_anomalous or if_anomalous)

        if anomalies or significant:
            if significant:
                summary_parts = [
                    "Significant cryptographic behavioural deviation detected "
                    "relative to the established infrastructure baseline."
                ]
            else:
                summary_parts = [
                    "Minor cryptographic deviation observed relative to baseline. "
                    "No significant anomaly threshold was exceeded."
                ]
            if anomalies:
                changed = ", ".join(a.feature for a in anomalies)
                summary_parts.append(f"Changed features: {changed}.")
        else:
            summary_parts = [
                "No significant cryptographic behavioural deviation detected. "
                "Observed profile is consistent with the established baseline."
            ]

        deviation_summary = " ".join(summary_parts)

        limitations = [
            "Behavioural deviation does not establish attacker identity, intent, or causality.",
            "Analysis is based solely on passively observed PCAP evidence.",
            "Baseline is derived from stored observations and may not reflect all historical behaviour.",
        ]
        if obs_count < ISOLATION_FOREST_MIN_OBSERVATIONS:
            limitations.append(
                f"Isolation Forest model was not executed: "
                f"{obs_count} observations are available but {ISOLATION_FOREST_MIN_OBSERVATIONS} are required."
            )

        return BehavioralAnalysisResult(
            infrastructure_id=infrastructure_id,
            identity_key=identity_key,
            job_id=job_id,
            session_id=session_id,
            baseline_status=bl_status,
            observation_count=obs_count,
            overall_status=EvidenceStatus.ANALYZED,
            significant_deviation_detected=significant,
            deviation_summary=deviation_summary,
            anomalies=anomalies,
            risk_stat_analysis=risk_analysis,
            isolation_forest=if_analysis,
            limitations=limitations,
        )

    # ── Private: Categorical feature comparison ───────────────────────────────

    def _analyze_categorical_features(
        self,
        baseline: CryptographicProfile,
        current: CryptographicProfile,
    ) -> List[BehavioralAnomaly]:
        """
        Compare categorical cryptographic attributes between baseline and
        current observation. Each change is flagged explicitly with significance.
        """
        anomalies: List[BehavioralAnomaly] = []

        # TLS Version — HIGH: version changes carry material security implications
        if (
            baseline.negotiated_tls_version
            and current.negotiated_tls_version
            and baseline.negotiated_tls_version != current.negotiated_tls_version
        ):
            sig = self._tls_version_significance(
                baseline.negotiated_tls_version, current.negotiated_tls_version
            )
            anomalies.append(BehavioralAnomaly(
                feature="negotiated_tls_version",
                baseline_value=baseline.negotiated_tls_version,
                observed_value=current.negotiated_tls_version,
                change_description=(
                    f"Negotiated TLS version changed: "
                    f"{baseline.negotiated_tls_version} → {current.negotiated_tls_version}"
                ),
                significance=sig,
                reason=(
                    "Observed TLS version differs from the established infrastructure baseline. "
                    "A change from a newer to an older version may indicate protocol misconfiguration."
                ),
                method="CATEGORICAL_CHANGE",
            ))

        # Cipher Suite — MEDIUM
        if (
            baseline.negotiated_cipher_suite
            and current.negotiated_cipher_suite
            and baseline.negotiated_cipher_suite != current.negotiated_cipher_suite
        ):
            anomalies.append(BehavioralAnomaly(
                feature="negotiated_cipher_suite",
                baseline_value=baseline.negotiated_cipher_suite,
                observed_value=current.negotiated_cipher_suite,
                change_description=(
                    f"Negotiated cipher suite changed: "
                    f"{baseline.negotiated_cipher_suite} → {current.negotiated_cipher_suite}"
                ),
                significance=DeviationSignificance.MEDIUM,
                reason=(
                    "Observed cipher suite differs from the established infrastructure baseline."
                ),
                method="CATEGORICAL_CHANGE",
            ))

        # Forward Secrecy — HIGH: loss of FS is a material security regression
        if (
            baseline.forward_secrecy is True
            and current.forward_secrecy is False
        ):
            anomalies.append(BehavioralAnomaly(
                feature="forward_secrecy",
                baseline_value=True,
                observed_value=False,
                change_description="Forward secrecy changed: Enabled → Disabled",
                significance=DeviationSignificance.HIGH,
                reason=(
                    "The observed key exchange no longer provides forward secrecy, "
                    "whereas the established baseline did. "
                    "Static key exchange does not protect previously captured sessions."
                ),
                method="CATEGORICAL_CHANGE",
            ))
        elif (
            baseline.forward_secrecy is False
            and current.forward_secrecy is True
        ):
            anomalies.append(BehavioralAnomaly(
                feature="forward_secrecy",
                baseline_value=False,
                observed_value=True,
                change_description="Forward secrecy changed: Disabled → Enabled",
                significance=DeviationSignificance.LOW,
                reason="Forward secrecy was gained relative to baseline.",
                method="CATEGORICAL_CHANGE",
            ))

        # Certificate fingerprint — MEDIUM
        if (
            baseline.leaf_cert_sha256
            and current.leaf_cert_sha256
            and baseline.leaf_cert_sha256 != current.leaf_cert_sha256
        ):
            anomalies.append(BehavioralAnomaly(
                feature="leaf_cert_sha256",
                baseline_value=baseline.leaf_cert_sha256[:16] + "...",
                observed_value=current.leaf_cert_sha256[:16] + "...",
                change_description=(
                    f"Certificate fingerprint changed: "
                    f"{baseline.leaf_cert_sha256[:16]}... → {current.leaf_cert_sha256[:16]}..."
                ),
                significance=DeviationSignificance.MEDIUM,
                reason=(
                    "The server certificate fingerprint changed from the established baseline. "
                    "This may represent certificate rotation or an unexpected certificate substitution."
                ),
                method="CATEGORICAL_CHANGE",
            ))

        # Certificate signature algorithm — MEDIUM
        if (
            baseline.cert_signature_algorithm
            and current.cert_signature_algorithm
            and baseline.cert_signature_algorithm != current.cert_signature_algorithm
        ):
            anomalies.append(BehavioralAnomaly(
                feature="cert_signature_algorithm",
                baseline_value=baseline.cert_signature_algorithm,
                observed_value=current.cert_signature_algorithm,
                change_description=(
                    f"Certificate signature algorithm changed: "
                    f"{baseline.cert_signature_algorithm} → {current.cert_signature_algorithm}"
                ),
                significance=DeviationSignificance.MEDIUM,
                reason="Certificate signature algorithm differs from baseline.",
                method="CATEGORICAL_CHANGE",
            ))

        # Certificate key size — LOW / MEDIUM
        if (
            baseline.cert_public_key_bits is not None
            and current.cert_public_key_bits is not None
            and baseline.cert_public_key_bits != current.cert_public_key_bits
        ):
            sig = (
                DeviationSignificance.MEDIUM
                if current.cert_public_key_bits < (baseline.cert_public_key_bits or 0)
                else DeviationSignificance.LOW
            )
            anomalies.append(BehavioralAnomaly(
                feature="cert_public_key_bits",
                baseline_value=baseline.cert_public_key_bits,
                observed_value=current.cert_public_key_bits,
                change_description=(
                    f"Certificate public key size changed: "
                    f"{baseline.cert_public_key_bits} bits → {current.cert_public_key_bits} bits"
                ),
                significance=sig,
                reason="Certificate public key size differs from baseline.",
                method="CATEGORICAL_CHANGE",
            ))

        # STARTTLS state — HIGH if ACCEPTED → REJECTED/DISABLED
        if (
            baseline.starttls_state in ("ACCEPTED", "TLS_FOLLOWED")
            and current.starttls_state in ("REJECTED", "FAILED", "ANOMALOUS", "DISABLED")
        ):
            anomalies.append(BehavioralAnomaly(
                feature="starttls_state",
                baseline_value=baseline.starttls_state,
                observed_value=current.starttls_state,
                change_description=(
                    f"STARTTLS negotiation outcome changed: "
                    f"{baseline.starttls_state} → {current.starttls_state}"
                ),
                significance=DeviationSignificance.HIGH,
                reason=(
                    "STARTTLS was previously accepted by this server. "
                    "The observed session shows a different outcome. "
                    "This represents a meaningful change in the server's encryption behaviour."
                ),
                method="CATEGORICAL_CHANGE",
            ))

        return anomalies

    def _tls_version_significance(
        self, baseline_ver: str, current_ver: str
    ) -> DeviationSignificance:
        """
        Assign significance to a TLS version change.
        Categorical ordering: TLS 1.3 > TLS 1.2 > TLS 1.1 > TLS 1.0 > SSL 3.0 > SSL 2.0.
        A downgrade is HIGH; an upgrade is LOW.
        """
        order = {
            "ssl 2.0": 0, "ssl 3.0": 1,
            "tls 1.0": 2, "tls 1.1": 3, "tls 1.2": 4, "tls 1.3": 5
        }
        b = order.get(baseline_ver.lower(), -1)
        c = order.get(current_ver.lower(), -1)
        if b == -1 or c == -1:
            return DeviationSignificance.MEDIUM   # Unknown version — flag it
        if c < b:
            return DeviationSignificance.HIGH     # Version downgrade
        return DeviationSignificance.LOW          # Version upgrade

    # ── Private: Numeric risk score analysis ──────────────────────────────────

    def _extract_risk_scores_from_history(
        self, history: list
    ) -> List[float]:
        """Extract risk_score values from observation history dicts (if present)."""
        scores: List[float] = []
        for obs in history:
            if isinstance(obs, dict) and "risk_score" in obs:
                val = obs["risk_score"]
                if isinstance(val, (int, float)) and not math.isnan(val):
                    scores.append(float(val))
        return scores

    def _analyze_risk_score_statistically(
        self,
        history_scores: List[float],
        current_risk: float,
    ) -> Optional[StatisticalRiskAnalysis]:
        """
        Perform z-score or normalised deviation analysis on the risk score.
        Only runs when there are sufficient history entries that include risk_score.
        """
        n = len(history_scores)

        if n < 2:
            return StatisticalRiskAnalysis(
                method="Z_SCORE",
                method_status=AnalysisMethodStatus.INSUFFICIENT_DATA,
                sample_count=n,
                observed_value=current_risk,
                interpretation=(
                    f"Insufficient risk score history for statistical analysis "
                    f"(n={n}, minimum required: 2)."
                ),
            )

        arr = np.array(history_scores, dtype=float)
        mean = float(np.mean(arr))
        std = float(np.std(arr, ddof=1)) if n > 1 else 0.0
        median = float(np.median(arr))

        # IQR
        q1, q3 = float(np.percentile(arr, 25)), float(np.percentile(arr, 75))
        iqr = q3 - q1

        if n >= ZSCORE_MIN_OBSERVATIONS and std > 0.0:
            method = "Z_SCORE"
            calc_zscore = float((current_risk - mean) / std)
            calc_norm_dev = float((current_risk - mean) / mean) if mean > 0.0 else 0.0
            is_anomalous = abs(calc_zscore) > SIGNIFICANT_ZSCORE_THRESHOLD
            interpretation = (
                f"Z-score: {calc_zscore:.3f} (n={n}). "
                f"{'Anomalous — exceeds ±2σ threshold relative to baseline sample.' if is_anomalous else 'Within normal ±2σ range of baseline sample.'}"
            )
        else:
            method = "NORMALIZED_DEVIATION"
            calc_zscore = None
            calc_norm_dev = float((current_risk - mean) / mean) if mean > 0.0 else 0.0
            is_anomalous = abs(calc_norm_dev) > 0.50
            reason_detail = "baseline variance is zero" if std == 0.0 else f"sample count n={n} < {ZSCORE_MIN_OBSERVATIONS}"
            interpretation = (
                f"Baseline deviation: {calc_norm_dev:.3f} relative to mean ({mean:.2f}) [{reason_detail}]. "
                f"{'Significant baseline deviation.' if is_anomalous else 'Within expected baseline range.'} "
                f"Not a statistically validated anomaly probability."
            )

        return StatisticalRiskAnalysis(
            method=method,
            method_status=AnalysisMethodStatus.COMPLETED,
            sample_count=n,
            baseline_mean=round(mean, 3),
            baseline_std=round(std, 3) if std > 0.0 else None,
            baseline_median=round(median, 3),
            baseline_iqr=round(iqr, 3),
            observed_value=round(current_risk, 3),
            zscore=round(calc_zscore, 4) if calc_zscore is not None else None,
            normalized_deviation=round(calc_norm_dev, 4),
            is_anomalous=is_anomalous,
            interpretation=interpretation,
        )

    # ── Private: Isolation Forest ─────────────────────────────────────────────

    def _run_isolation_forest(
        self,
        observation_history: List[Dict[str, Any]],
        current_profile: CryptographicProfile,
        current_risk: float,
    ) -> Optional[IsolationForestAnalysis]:
        """
        Run Isolation Forest ONLY when there are at least
        ISOLATION_FOREST_MIN_OBSERVATIONS observations.
        Returns None if sklearn is not available (should not happen in this env).
        """
        n = len(observation_history)
        FEATURE_SET = ["risk_score_numeric", "forward_secrecy_numeric", "tls_version_numeric"]

        if n < ISOLATION_FOREST_MIN_OBSERVATIONS:
            return IsolationForestAnalysis(
                method_status=AnalysisMethodStatus.INSUFFICIENT_DATA,
                feature_set=FEATURE_SET,
                observation_count=n,
                min_required=ISOLATION_FOREST_MIN_OBSERVATIONS,
                interpretation=(
                    f"Isolation Forest not executed: {n} observations available, "
                    f"{ISOLATION_FOREST_MIN_OBSERVATIONS} required."
                ),
            )

        # ── Feature extraction ─────────────────────────────────────────────
        # We use only features that can be extracted safely from stored history dicts.
        # Categorical (TLS version) is ordinally encoded for IF only —
        # the result is labelled "ordinal encoding for IF only" to prevent misuse.
        tls_order = {
            "ssl 2.0": 0, "ssl 3.0": 1,
            "tls 1.0": 2, "tls 1.1": 3, "tls 1.2": 4, "tls 1.3": 5
        }

        def extract_features(obs_dict: Dict[str, Any]) -> Optional[List[float]]:
            try:
                risk = float(obs_dict.get("risk_score", 0.0) or 0.0)
                fs = 1.0 if obs_dict.get("forward_secrecy") else 0.0
                tls_ver = str(obs_dict.get("negotiated_tls_version") or "").lower()
                tls_num = float(tls_order.get(tls_ver, 4))  # default to TLS 1.2 if unknown
                return [risk, fs, tls_num]
            except (TypeError, ValueError):
                return None

        X_rows = [extract_features(obs) for obs in observation_history]
        X_rows_clean = [row for row in X_rows if row is not None]

        if len(X_rows_clean) < ISOLATION_FOREST_MIN_OBSERVATIONS:
            return IsolationForestAnalysis(
                method_status=AnalysisMethodStatus.INSUFFICIENT_DATA,
                feature_set=FEATURE_SET,
                observation_count=len(X_rows_clean),
                min_required=ISOLATION_FOREST_MIN_OBSERVATIONS,
                interpretation=(
                    f"Isolation Forest not executed: only {len(X_rows_clean)} observations "
                    f"had complete feature data."
                ),
            )

        # ── Build current observation feature vector ───────────────────────
        cur_fs = 1.0 if current_profile.forward_secrecy else 0.0
        cur_tls_ver = (current_profile.negotiated_tls_version or "").lower()
        cur_tls_num = float(tls_order.get(cur_tls_ver, 4))
        X_current = [[current_risk, cur_fs, cur_tls_num]]

        try:
            from sklearn.ensemble import IsolationForest as _IsolationForest
            X_train = np.array(X_rows_clean, dtype=float)
            X_cur = np.array(X_current, dtype=float)

            # contamination=0.1: expect up to 10% of baseline to be anomalous
            # random_state=42 for deterministic output given same training data
            clf = _IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=1,
            )
            clf.fit(X_train)
            decision_scores = clf.decision_function(X_cur)  # Higher = more normal
            raw_score = float(decision_scores[0])
            # Normalise: decision_function range is approximately -0.5 to 0.5
            # Map to 0..1 where 1 = most anomalous
            normalized = max(0.0, min(1.0, 0.5 - raw_score))
            is_anomalous = clf.predict(X_cur)[0] == -1

            interpretation = (
                f"Isolation Forest: normalised anomaly score = {normalized:.4f}. "
                f"Trained on {len(X_rows_clean)} baseline observations. "
                f"{'Flagged as anomalous (score > 0.5).' if is_anomalous else 'Classified as consistent with baseline.'}"
                f" Note: Isolation Forest uses ordinal TLS version encoding for ranking only; "
                f"categorical deviations are documented separately above."
            )

            return IsolationForestAnalysis(
                method_status=AnalysisMethodStatus.COMPLETED,
                feature_set=FEATURE_SET,
                observation_count=len(X_rows_clean),
                min_required=ISOLATION_FOREST_MIN_OBSERVATIONS,
                anomaly_score=raw_score,
                normalized_anomaly_score=round(normalized, 4),
                is_anomalous=is_anomalous,
                interpretation=interpretation,
            )

        except ImportError:
            return IsolationForestAnalysis(
                method_status=AnalysisMethodStatus.SKIPPED,
                feature_set=FEATURE_SET,
                observation_count=len(X_rows_clean),
                min_required=ISOLATION_FOREST_MIN_OBSERVATIONS,
                interpretation="scikit-learn not available — Isolation Forest skipped.",
            )
        except Exception as exc:
            return IsolationForestAnalysis(
                method_status=AnalysisMethodStatus.SKIPPED,
                feature_set=FEATURE_SET,
                observation_count=len(X_rows_clean),
                min_required=ISOLATION_FOREST_MIN_OBSERVATIONS,
                interpretation=f"Isolation Forest skipped due to internal error: {type(exc).__name__}.",
            )
