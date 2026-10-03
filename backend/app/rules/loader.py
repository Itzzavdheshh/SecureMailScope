"""
Safe YAML Rule Loader & Validator.
Parses rule YAML files from rules/ directory using safe YAML parsing without eval().
Validates rule schema, enabled status, and risk weights configuration.
"""

from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml
import structlog

from app.models.enums import FindingCategory, Severity
from app.rules.schema import RuleDefinition, RuleSet, RiskWeightsConfig

log = structlog.get_logger(__name__)


def get_default_rules_dir() -> Path:
    """Locate workspace rules directory."""
    # Look in root workspace directory C:\Users\itzza\SecureMailScope\rules
    base_dir = Path(__file__).resolve().parent.parent.parent.parent
    rules_dir = base_dir / "rules"
    if rules_dir.exists():
        return rules_dir
    # Fallback to backend/rules if present
    fallback_dir = Path(__file__).resolve().parent.parent / "rules_dir"
    return fallback_dir


def load_yaml_file(filepath: Path) -> Optional[Dict]:
    """Safely parse a YAML file without code execution."""
    try:
        if not filepath.exists():
            return None
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            return data if isinstance(data, dict) else None
    except Exception as exc:
        log.error("yaml_load_failed", path=str(filepath), error=str(exc))
        return None


def derive_category_from_rule_id(rule_id: str) -> FindingCategory:
    """Infer FindingCategory from rule ID prefix if category not set."""
    prefix = rule_id.split("-")[0].upper()
    if prefix in ("CRYPT", "TLS"):
        return FindingCategory.TLS_CRYPTO
    elif prefix in ("CERT", "X509"):
        return FindingCategory.X509_CERT
    elif prefix in ("STLS", "STARTTLS"):
        return FindingCategory.STARTTLS
    return FindingCategory.PROTOCOL_ANOMALY


def load_rules_from_directory(rules_dir: Optional[Path] = None) -> List[RuleDefinition]:
    """
    Load and validate all rule definitions from YAML files in rules_dir.
    Ignores disabled rules and skips invalid rule files safely.
    """
    target_dir = rules_dir or get_default_rules_dir()
    loaded_rules: List[RuleDefinition] = []

    if not target_dir.exists():
        log.warning("rules_directory_not_found", path=str(target_dir))
        return loaded_rules

    yaml_files = list(target_dir.glob("*.yaml")) + list(target_dir.glob("*.yml"))

    for filepath in yaml_files:
        if filepath.name == "risk_weights.yaml":
            continue

        raw_data = load_yaml_file(filepath)
        if not raw_data or "rules" not in raw_data:
            continue

        try:
            rule_set = RuleSet(**raw_data)
            for rule in rule_set.rules:
                if not rule.enabled:
                    continue
                if rule.category is None:
                    rule.category = derive_category_from_rule_id(rule.id)
                loaded_rules.append(rule)
        except Exception as exc:
            log.error("rule_validation_failed", path=str(filepath), error=str(exc))

    log.info("rules_loaded_successfully", total_rules=len(loaded_rules), directory=str(target_dir))
    return loaded_rules


def load_risk_weights_config(rules_dir: Optional[Path] = None) -> RiskWeightsConfig:
    """Load risk weights configuration from risk_weights.yaml."""
    target_dir = rules_dir or get_default_rules_dir()
    weights_path = target_dir / "risk_weights.yaml"

    raw_data = load_yaml_file(weights_path)
    if not raw_data:
        return RiskWeightsConfig()

    try:
        sev_w = raw_data.get("severity_weights", {})
        conf_f = raw_data.get("confidence_factors", {})
        ref_max = raw_data.get("normalization", {}).get("reference_max", 30.0)
        drift_b = raw_data.get("drift_bonus", 2.0)
        bands = raw_data.get("severity_bands", {})

        return RiskWeightsConfig(
            formula_version=str(raw_data.get("formula_version", "risk_weights_v1.0.0")),
            severity_weights=sev_w if sev_w else RiskWeightsConfig().severity_weights,
            confidence_factors=conf_f if conf_f else RiskWeightsConfig().confidence_factors,
            reference_max=float(ref_max),
            drift_bonus=float(drift_b),
            severity_bands=bands if bands else RiskWeightsConfig().severity_bands,
        )
    except Exception as exc:
        log.error("risk_weights_load_failed", error=str(exc))
        return RiskWeightsConfig()
