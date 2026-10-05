"""Machine-readable JSON exporter for NSAT Phase 4A."""

import json
from typing import Any

from nsat.correlation.models import Phase4SecurityModel


def export_json_report(model: Phase4SecurityModel) -> dict[str, Any]:
    """
    Format Phase4SecurityModel into standardized machine-readable JSON structure.
    Consumed by downstream Phase 4B/4C AI engines and CI/CD pipelines.
    """
    return {
        "summary": {
            "project_name": model.project.get("name", ""),
            "target_path": model.project.get("target_path", ""),
            "primary_type": model.project.get("primary_type", ""),
            "total_findings": len(model.findings),
            "validated_findings": model.risk.validated_findings_count,
            "attack_paths_count": len(model.attack_paths),
            "blast_radius_tier": model.blast_radius.tier,
            "timestamp": model.timestamp,
        },
        "risk": json.loads(model.risk.model_dump_json()),
        "findings": [json.loads(f.model_dump_json()) for f in model.findings],
        "attack_paths": [json.loads(ap.model_dump_json()) for f in [model.attack_paths] for ap in f],
        "blast_radius": json.loads(model.blast_radius.model_dump_json()),
        "graph": json.loads(model.graph.model_dump_json()),
        "coverage": json.loads(model.coverage.model_dump_json()),
        "limitations": json.loads(model.limitations.model_dump_json()),
    }


def export_json_str(model: Phase4SecurityModel, indent: int = 2) -> str:
    """Serialize model to pretty-printed JSON string."""
    data = export_json_report(model)
    return json.dumps(data, indent=indent)
