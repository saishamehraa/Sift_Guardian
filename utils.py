from __future__ import annotations

import csv
import json
import os
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


def _normalize_process_record(record: Dict[str, Any]) -> Dict[str, Any]:
    pid_value = record.get("pid", record.get("PID", record.get("ProcessId", "")))
    try:
        pid = int(pid_value)
    except (TypeError, ValueError):
        pid = 0

    name = str(
        record.get("name", record.get("Name", record.get("ImageFileName", "unknown_process")))
    )
    user = str(
        record.get("user", record.get("UserName", record.get("Username", "unknown_user")))
    )
    cmdline = str(record.get("cmdline", record.get("CommandLine", "")))
    start_time = str(record.get("start_time", record.get("CreateTime", "")))
    memory_indicator = str(record.get("memory_indicator", "unknown"))

    return {
        "pid": pid,
        "name": name,
        "user": user,
        "cmdline": cmdline,
        "memory_indicator": memory_indicator,
        "start_time": start_time,
        "collection_source": "real_sift_export",
    }


def _read_real_process_export(export_path: Path) -> List[Dict[str, Any]]:
    suffix = export_path.suffix.lower()
    rows: List[Dict[str, Any]] = []

    if suffix == ".csv":
        with export_path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            rows = [dict(row) for row in reader]
    elif suffix == ".ndjson":
        with export_path.open("r", encoding="utf-8") as file:
            for line in file:
                stripped = line.strip()
                if not stripped:
                    continue
                value = json.loads(stripped)
                if isinstance(value, dict):
                    rows.append(value)
    elif suffix == ".json":
        with export_path.open("r", encoding="utf-8") as file:
            value = json.load(file)
        if isinstance(value, list):
            rows = [item for item in value if isinstance(item, dict)]
        elif isinstance(value, dict):
            candidates = value.get("process_list", value.get("rows", []))
            if isinstance(candidates, list):
                rows = [item for item in candidates if isinstance(item, dict)]
    else:
        raise ValueError(f"Unsupported process export format: {export_path.suffix}")

    return [_normalize_process_record(row) for row in rows]


def _normalize_timeline_record(record: Dict[str, Any]) -> Dict[str, Any]:
    timestamp = str(
        record.get(
            "timestamp",
            record.get("datetime", record.get("DateTime", record.get("Timestamp", ""))),
        )
    )
    source = str(
        record.get(
            "source",
            record.get("sourcetype", record.get("parser", record.get("SourceType", "unknown_source"))),
        )
    )
    event_type = str(
        record.get(
            "event_type",
            record.get("event", record.get("EventType", record.get("message_type", "unknown_event"))),
        )
    )
    artifact = str(
        record.get(
            "artifact",
            record.get(
                "path",
                record.get("filename", record.get("key_path", record.get("url", "unknown_artifact"))),
            ),
        )
    )
    details = str(record.get("details", record.get("message", record.get("description", ""))))

    return {
        "timestamp": timestamp,
        "source": source,
        "event_type": event_type,
        "artifact": artifact,
        "details": details,
        "collection_source": "real_sift_export",
    }


def _read_real_timeline_export(export_path: Path) -> List[Dict[str, Any]]:
    suffix = export_path.suffix.lower()
    rows: List[Dict[str, Any]] = []

    if suffix == ".csv":
        with export_path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            rows = [dict(row) for row in reader]
    elif suffix == ".ndjson":
        with export_path.open("r", encoding="utf-8") as file:
            for line in file:
                stripped = line.strip()
                if not stripped:
                    continue
                value = json.loads(stripped)
                if isinstance(value, dict):
                    rows.append(value)
    elif suffix == ".json":
        with export_path.open("r", encoding="utf-8") as file:
            value = json.load(file)
        if isinstance(value, list):
            rows = [item for item in value if isinstance(item, dict)]
        elif isinstance(value, dict):
            candidates = value.get("timeline", value.get("rows", []))
            if isinstance(candidates, list):
                rows = [item for item in candidates if isinstance(item, dict)]
    else:
        raise ValueError(f"Unsupported timeline export format: {export_path.suffix}")

    return [_normalize_timeline_record(row) for row in rows]


def load_process_list_with_real_fallback(base_path: str | Path, mock_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    base_dir = Path(base_path)
    env_override = os.environ.get("SIFT_PROCESS_LIST_PATH", "").strip()
    configured_path = Path(env_override) if env_override else (base_dir / "real_tool_output" / "process_list.json")

    if configured_path.exists():
        try:
            real_rows = _read_real_process_export(configured_path)
            if real_rows:
                return real_rows
        except Exception:
            pass

    return mock_data.get("process_list", [])


def load_timeline_with_real_fallback(base_path: str | Path, mock_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    base_dir = Path(base_path)
    env_override = os.environ.get("SIFT_TIMELINE_PATH", "").strip()
    configured_path = Path(env_override) if env_override else (base_dir / "real_tool_output" / "timeline.json")

    if configured_path.exists():
        try:
            real_rows = _read_real_timeline_export(configured_path)
            if real_rows:
                return real_rows
        except Exception:
            pass

    return mock_data.get("timeline", [])

