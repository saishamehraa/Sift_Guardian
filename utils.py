from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_event(logs: List[Dict[str, Any]], agent: str, action: str, detail: Dict[str, Any]) -> None:
    logs.append(
        {
            "timestamp": utc_now_iso(),
            "agent": agent,
            "action": action,
            "detail": detail,
        }
    )


def print_logs(logs: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for entry in logs:
        lines.append(
            f"[{entry['timestamp']}] {entry['agent']}::{entry['action']} -> "
            f"{json.dumps(entry['detail'], sort_keys=True)}"
        )
    return "\n".join(lines)


def load_mock_data(base_path: str | Path) -> Dict[str, Any]:
    mock_path = Path(base_path) / "mock_data.json"
    with mock_path.open("r", encoding="utf-8") as file:
        return json.load(file)

