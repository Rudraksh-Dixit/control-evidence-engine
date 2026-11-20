from __future__ import annotations

from pathlib import Path

import yaml

from cee.models import THEME_ORDER, Control, Framework

FRAMEWORKS_DIR = Path(__file__).resolve().parent / "frameworks"
DEFAULT_FRAMEWORK = "iso27001-2022"


class CatalogError(ValueError):
    pass


def framework_path(framework_id: str = DEFAULT_FRAMEWORK) -> Path:
    candidate = Path(framework_id)
    if candidate.suffix in (".yaml", ".yml"):
        return candidate
    path = FRAMEWORKS_DIR / f"{framework_id.replace('-', '_')}.yaml"
    if not path.exists():
        available = ", ".join(sorted(p.stem for p in FRAMEWORKS_DIR.glob("*.yaml")))
        raise CatalogError(f"Unknown framework '{framework_id}'. Available: {available}")
    return path


def load_framework(framework_id: str = DEFAULT_FRAMEWORK) -> Framework:
    path = framework_path(framework_id)
    with path.open("r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)

    if not isinstance(raw, dict) or "controls" not in raw:
        raise CatalogError(f"{path} is not a valid framework catalog")

    meta = raw.get("framework", {})
    controls: list[Control] = []
    seen: set[str] = set()
    for entry in raw["controls"]:
        control_id = str(entry.get("id", "")).strip()
        if not control_id:
            raise CatalogError(f"Control without id in {path}")
        if control_id in seen:
            raise CatalogError(f"Duplicate control id {control_id} in {path}")
        seen.add(control_id)
        theme = str(entry.get("theme", "")).strip().lower()
        if theme not in THEME_ORDER:
            raise CatalogError(f"Control {control_id} has invalid theme '{theme}'")
        check_ids = [str(c) for c in (entry.get("checks") or [])]
        controls.append(
            Control(
                id=control_id,
                title=str(entry.get("title", "")).strip(),
                theme=theme,
                objective=str(entry.get("objective", "")).strip(),
                evidence_expectation=str(entry.get("evidence_expectation", "")).strip(),
                check_ids=check_ids,
                automated=bool(check_ids),
                references=[str(r) for r in (entry.get("references") or [])],
                applicability=str(entry.get("applicability", "All organizations")),
            )
        )

    if not controls:
        raise CatalogError(f"No controls found in {path}")

    return Framework(
        id=str(meta.get("id", framework_id)),
        name=str(meta.get("name", "Unnamed framework")),
        version=str(meta.get("version", "n/a")),
        description=str(meta.get("description", "")),
        source=str(meta.get("source", "")),
        controls=controls,
    )


def theme_stats(framework: Framework) -> dict[str, dict[str, int]]:
    stats = {theme: {"total": 0, "automated": 0, "manual": 0} for theme in THEME_ORDER}
    for control in framework.controls:
        bucket = stats[control.theme]
        bucket["total"] += 1
        if control.automated:
            bucket["automated"] += 1
        else:
            bucket["manual"] += 1
    return stats
