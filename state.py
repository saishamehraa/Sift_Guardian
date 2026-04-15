from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class InvestigationState:
    max_iterations: int = 4
    current_iteration: int = 0
    verified: bool = False
    failed: bool = False
    finding: str = "Investigation did not run."
    confidence: int = 0
    confidence_history: List[int] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    quarantined_evidence: List[Dict[str, Any]] = field(default_factory=list)
    sanitization_events: List[Dict[str, Any]] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)
    attempted_tools: List[str] = field(default_factory=list)
    strategy_log: List[str] = field(default_factory=list)
    logs: List[Dict[str, Any]] = field(default_factory=list)
    scratchpad: Dict[str, Any] = field(default_factory=dict)

    def register_tool_use(self, tool_name: str) -> None:
        self.attempted_tools.append(tool_name)

    def add_strategy(self, strategy: str) -> None:
        self.strategy_log.append(strategy)

    def add_evidence(self, tool_name: str, item: Dict[str, Any], trace_id: str) -> None:
        self.evidence.append({"source": tool_name, "data": item, "trace_id": trace_id})

    def add_quarantined_evidence(self, item: Dict[str, Any]) -> None:
        self.quarantined_evidence.append(item)

