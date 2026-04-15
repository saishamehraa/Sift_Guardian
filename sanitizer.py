from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

RULES_FILE = Path(__file__).resolve().parent / "sanitizer_rules.yaml"
_RULES_CACHE: Dict[str, Any] = {}
_RULES_MTIME: float | None = None


def _default_rules() -> Dict[str, Any]:
    return {
        "high_signal_patterns": [
            r"\bignore\s+(all\s+)?(previous|prior)\s+instructions?\b",
            r"\bsystem\s+override\b",
            r"\bdisregard\b.*\binstructions?\b",
            r"\bset\s+confidence\s+to\s+\d+\b",
            r"\bdeclare\s+the\s+system\s+clean\b",
            r"\bterminate\s+analysis\b",
        ],
        "low_signal_keywords": ["override", "system", "terminate"],
        "benign_context_patterns": [
            r"\bservice\s+terminated\b",
            r"\boverride\s+policy\b",
            r"\bterminate\s+process\s+id\b",
            r"\bsystem\s+reboot\b",
            r"\bmaintenance\s+window\b",
        ],
        "risk_model": {
            "high_signal_weight": 2,
            "low_signal_threshold": 2,
            "quarantine_on_any_high_signal": True,
        },
    }


def _compile_patterns(raw_patterns: List[str]) -> List[re.Pattern[str]]:
    compiled: List[re.Pattern[str]] = []
    for pattern in raw_patterns:
        compiled.append(re.compile(pattern, re.IGNORECASE))
    return compiled


def _load_rules() -> Dict[str, Any]:
    global _RULES_CACHE, _RULES_MTIME

    try:
        mtime = RULES_FILE.stat().st_mtime
    except FileNotFoundError:
        return _default_rules()

    if _RULES_MTIME == mtime and _RULES_CACHE:
        return _RULES_CACHE

    try:
        with RULES_FILE.open("r", encoding="utf-8") as file:
            loaded = yaml.safe_load(file) or {}
    except yaml.YAMLError:
        return _RULES_CACHE or _default_rules()

    rules = _default_rules()
    rules.update({k: v for k, v in loaded.items() if k in rules})
    _RULES_CACHE = rules
    _RULES_MTIME = mtime
    return rules


def _string_fields(record: Dict[str, Any]) -> Dict[str, str]:
    return {key: value for key, value in record.items() if isinstance(value, str)}


def _evaluate_text(text: str, rules: Dict[str, Any]) -> Tuple[bool, List[str], int]:
    high_signal_patterns = _compile_patterns(rules["high_signal_patterns"])
    benign_patterns = _compile_patterns(rules["benign_context_patterns"])
    low_signal_keywords: List[str] = rules["low_signal_keywords"]
    risk_model: Dict[str, Any] = rules["risk_model"]

    high_signal_hits: List[str] = []
    for pattern in high_signal_patterns:
        if pattern.search(text):
            high_signal_hits.append(pattern.pattern)

    low_signal_count = sum(1 for keyword in low_signal_keywords if keyword in text.lower())
    benign_hits = sum(1 for pattern in benign_patterns if pattern.search(text))

    # Deterministic rule:
    # - quarantine on any high-signal imperative pattern
    # - OR quarantine when multiple low-signal terms appear with no benign context
    suspicious = (
        (risk_model["quarantine_on_any_high_signal"] and bool(high_signal_hits))
        or (low_signal_count >= risk_model["low_signal_threshold"] and benign_hits == 0)
    )
    score = (len(high_signal_hits) * risk_model["high_signal_weight"]) + low_signal_count - benign_hits
    return suspicious, high_signal_hits, max(score, 0)


def sanitize_tool_output(
    tool_name: str, records: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    rules = _load_rules()
    safe_records: List[Dict[str, Any]] = []
    quarantined_records: List[Dict[str, Any]] = []
    sanitization_events: List[Dict[str, Any]] = []

    for record in records:
        text_fields = _string_fields(record)
        field_results = []
        should_quarantine = False

        for field_name, field_value in text_fields.items():
            suspicious, hits, score = _evaluate_text(field_value, rules)
            if suspicious:
                should_quarantine = True
            field_results.append(
                {
                    "field": field_name,
                    "suspicious": suspicious,
                    "matched_patterns": hits,
                    "risk_score": score,
                }
            )

        if should_quarantine:
            quarantined_records.append(
                {
                    "source": tool_name,
                    "record": deepcopy(record),
                    "reason": "prompt_injection_suspected",
                    "field_results": field_results,
                }
            )
            sanitization_events.append(
                {
                    "tool": tool_name,
                    "decision": "quarantine",
                    "record_hint": str(record.get("artifact", record.get("event_type", "unknown_record"))),
                    "rules_source": str(RULES_FILE.name),
                    "field_results": field_results,
                }
            )
            continue

        safe_records.append(record)
        sanitization_events.append(
            {
                "tool": tool_name,
                "decision": "allow",
                "record_hint": str(record.get("artifact", record.get("event_type", "unknown_record"))),
                "rules_source": str(RULES_FILE.name),
                "field_results": field_results,
            }
        )

    return safe_records, quarantined_records, sanitization_events

