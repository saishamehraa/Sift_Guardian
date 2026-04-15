from __future__ import annotations

from copy import deepcopy
from typing import Any, Callable, Dict, List, Tuple

from sanitizer import sanitize_tool_output
from state import InvestigationState
from utils import log_event

ToolFn = Callable[[], List[Dict[str, Any]]]


def _sources_from_evidence(evidence: List[Dict[str, Any]]) -> List[str]:
    return sorted({item["source"] for item in evidence})


def investigator_agent(state: InvestigationState, tools: Dict[str, ToolFn]) -> None:
    if state.current_iteration == 1:
        tool_name = "get_process_list"
        state.add_strategy("Initial triage from volatile process memory only")
    else:
        preferred_order = ["extract_timeline", "get_login_events", "get_process_list"]
        tool_name = next((name for name in preferred_order if name not in state.attempted_tools), preferred_order[0])
        state.add_strategy(f"Pivoting analysis strategy to {tool_name}")

    state.register_tool_use(tool_name)
    try:
        records = tools[tool_name]()
    except Exception as exc:  # noqa: BLE001 - intentional boundary hardening
        state.scratchpad["last_tool_error"] = str(exc)
        log_event(
            state.logs,
            "Investigator",
            "tool_call_failed",
            {
                "iteration": state.current_iteration,
                "selected_tool": tool_name,
                "error": str(exc),
            },
        )
        state.finding = "Tool access failure encountered; investigation requires alternate evidence source."
        return
    safe_records, quarantined_records, sanitization_events = sanitize_tool_output(tool_name, records)
    quarantine_index = 0
    for event in sanitization_events:
        if event.get("decision") == "quarantine":
            trace_id = f"{tool_name}_{state.current_iteration}_q_{quarantine_index}"
            event["trace_id"] = trace_id
            quarantine_index += 1
        state.sanitization_events.append(event)
    for record in safe_records:
        trace_id = f"{tool_name}_{state.current_iteration}_{len(state.evidence)}"
        state.add_evidence(tool_name, record, trace_id=trace_id)
        log_event(
            state.logs,
            "Investigator",
            "evidence_ingested",
            {
                "iteration": state.current_iteration,
                "selected_tool": tool_name,
                "trace_id": trace_id,
                "artifact": str(record.get("artifact", record.get("event_type", "unknown_record"))),
            },
        )
    for idx, record in enumerate(quarantined_records):
        record["trace_id"] = f"{tool_name}_{state.current_iteration}_q_{idx}"
        state.add_quarantined_evidence(record)

    log_event(
        state.logs,
        "EvidenceFirewall",
        "sanitization_result",
        {
            "iteration": state.current_iteration,
            "selected_tool": tool_name,
            "total_records": len(records),
            "safe_records": len(safe_records),
            "quarantined_records": len(quarantined_records),
        },
    )

    if tool_name == "get_process_list":
        suspicious = [
            p
            for p in safe_records
            if "powershell" in p.get("name", "").lower() and "enc" in p.get("cmdline", "").lower()
        ]
        if suspicious:
            state.finding = "Potential malicious PowerShell execution detected."
        else:
            state.finding = "No obvious suspicious process patterns found."
    elif tool_name == "extract_timeline":
        has_outbound = any("network_connection" == row.get("event_type") for row in safe_records)
        if has_outbound:
            state.finding = "Process execution likely progressed to outbound command-and-control traffic."
        else:
            state.finding = "Timeline does not yet show external communications."
    else:
        remote_logins = [row for row in safe_records if row.get("auth_type") == "RDP" and row.get("result") == "success"]
        if remote_logins:
            state.finding = "Suspicious remote access precedes execution chain."
        else:
            state.finding = "No suspicious authentication behavior observed."

    log_event(
        state.logs,
        "Investigator",
        "analysis_complete",
        {
            "iteration": state.current_iteration,
            "selected_tool": tool_name,
            "evidence_count": len(state.evidence),
            "quarantined_evidence_count": len(state.quarantined_evidence),
            "finding": state.finding,
        },
    )


def skeptic_agent(state: InvestigationState) -> Tuple[bool, List[str]]:
    reasons: List[str] = []
    sources = _sources_from_evidence(state.evidence)
    if len(sources) < 2:
        reasons.append("Rejected: fewer than 2 independent evidence sources.")
    if "likely" in state.finding.lower() and len(sources) < 3:
        reasons.append("Rejected: probabilistic claim without broad corroboration.")
    if not state.finding.strip():
        reasons.append("Rejected: missing finding statement.")

    accepted = len(reasons) == 0
    log_event(
        state.logs,
        "Skeptic",
        "review",
        {
            "iteration": state.current_iteration,
            "accepted": accepted,
            "reasons": reasons,
            "sources": sources,
        },
    )
    return accepted, reasons


def re_executor_agent(state: InvestigationState, rejection_reasons: List[str]) -> None:
    state.scratchpad["rejection_reasons"] = rejection_reasons
    preferred_order = ["extract_timeline", "get_login_events", "get_process_list"]
    next_tool = next((name for name in preferred_order if name not in state.attempted_tools), preferred_order[0])

    if state.attempted_tools and state.attempted_tools[-1] == next_tool:
        for candidate in preferred_order:
            if candidate != next_tool:
                next_tool = candidate
                break

    state.add_strategy(f"Re-executor pivoted to {next_tool} due to skeptic rejection")
    log_event(
        state.logs,
        "Re-Executor",
        "strategy_pivot",
        {
            "iteration": state.current_iteration,
            "rejection_reasons": rejection_reasons,
            "next_tool": next_tool,
            "attempted_tools": state.attempted_tools,
            "strategy_log": state.strategy_log,
        },
    )


def contradiction_engine(state: InvestigationState) -> List[str]:
    contradictions: List[str] = []
    timeline_events = [item["data"] for item in state.evidence if item["source"] == "extract_timeline"]
    login_events = [item["data"] for item in state.evidence if item["source"] == "get_login_events"]
    process_items = [item["data"] for item in state.evidence if item["source"] == "get_process_list"]

    has_remote_login = any(e.get("auth_type") == "RDP" and e.get("result") == "success" for e in login_events)
    has_exec_chain = any(e.get("event_type") == "process_start" for e in timeline_events)
    if has_exec_chain and not has_remote_login:
        contradictions.append("Timeline indicates execution chain, but no corresponding remote login evidence exists.")

    memory_suspicious = any("suspicious" in p.get("memory_indicator", "") for p in process_items)
    disk_script_drop = any("file_create" == t.get("event_type") and ".ps1" in t.get("artifact", "") for t in timeline_events)
    if memory_suspicious and not disk_script_drop:
        contradictions.append("Memory indicates suspicious PowerShell, but disk timeline lacks script drop artifacts.")

    return contradictions


def verifier_agent(state: InvestigationState, skeptic_accepted: bool) -> None:
    contradictions = contradiction_engine(state)
    state.contradictions = contradictions
    source_count = len(_sources_from_evidence(state.evidence))
    base_confidence = min(35 + (source_count * 25), 95)
    penalty = 15 * len(contradictions)
    if not skeptic_accepted:
        penalty += 20
    state.confidence = max(base_confidence - penalty, 5)
    state.confidence_history.append(state.confidence)

    if skeptic_accepted and state.confidence >= 65 and not contradictions:
        state.verified = True

    if state.current_iteration >= state.max_iterations and not state.verified:
        state.failed = True
        state.finding = (
            "Low-confidence assessment: suspicious activity detected, "
            "but evidence remains insufficient for a high-confidence conclusion."
        )

    log_event(
        state.logs,
        "Verifier",
        "verification_step",
        {
            "iteration": state.current_iteration,
            "skeptic_accepted": skeptic_accepted,
            "confidence": state.confidence,
            "contradictions": contradictions,
            "verified": state.verified,
            "failed": state.failed,
        },
    )


def reporter_agent(state: InvestigationState) -> Dict[str, Any]:
    confidence_reasoning = [
        f"{len(state.evidence)} evidence sources analyzed",
        f"{len(state.contradictions)} contradictions detected",
        "Cross-source validation achieved" if state.verified else "Partial validation only",
    ]

    failure_reason = ""
    if state.failed:
        failure_reason = "Max iterations reached without sufficient cross-source corroboration"

    output = {
        "finding": state.finding,
        "confidence": state.confidence,
        "confidence_history": state.confidence_history,
        "confidence_reasoning": confidence_reasoning,
        "evidence": state.evidence,
        "contradictions": state.contradictions,
        "failure_reason": failure_reason,
        "iterations_required": state.current_iteration,
    }
    log_event(state.logs, "Reporter", "final_output", deepcopy(output))
    return output

