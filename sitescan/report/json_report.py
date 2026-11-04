from __future__ import annotations

import json

from ..core.orchestrator import ScanResult


def render_json(result: ScanResult, extra: dict | None = None) -> str:
    data = result.to_dict()
    if extra:
        data.update(extra)
    return json.dumps(data, indent=2, ensure_ascii=False)
