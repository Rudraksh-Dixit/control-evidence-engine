from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "cee.yaml"
DEFAULT_RUNS_DIR = PROJECT_ROOT / "runs"

DEFAULT_CONFIG: dict[str, Any] = {
    "github": {
        "org": "",
        "repo": "",
        "token_env": "GITHUB_TOKEN",
    },
    "aws": {
        "profile": "",
        "regions": ["ap-south-1", "us-east-1"],
    },
    "wazuh": {
        "alerts_path": "",
        "freshness_hours": 24,
    },
    "sigma": {
        "rules_dir": "",
        "required_techniques": [],
    },
    "backup": {
        "path": "",
        "max_age_hours": 24,
        "min_retention_days": 7,
    },
    "trivy": {
        "report_path": "",
        "critical_sla_days": 7,
        "high_sla_days": 30,
    },
    "manual": {
        "registry": "manual_evidence/index.json",
    },
    "report": {
        "organization": "Acme SaaS",
        "prepared_by": "Security Engineering",
        "reviewer": "",
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: Path | str | None = None) -> dict[str, Any]:
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return dict(DEFAULT_CONFIG)
    with config_path.open("r", encoding="utf-8") as fh:
        payload = yaml.safe_load(fh) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"Configuration in {config_path} must be a mapping")
    merged = _deep_merge(DEFAULT_CONFIG, payload)
    registry = Path(str(merged["manual"]["registry"]))
    if not registry.is_absolute():
        merged["manual"]["registry"] = str((config_path.parent / registry).resolve())
    return merged
