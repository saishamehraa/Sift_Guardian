from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from agents import (
    investigator_agent,
    re_executor_agent,
    reporter_agent,
    skeptic_agent,
    verifier_agent,
)
from state import InvestigationState
from utils import (
    load_mock_data,
    load_process_list_with_real_fallback,
    load_timeline_with_real_fallback,
    log_event,
    print_logs,
)

BASE_PATH = Path(__file__).resolve().parent
DATA = load_mock_data(BASE_PATH)


def get_process_list() -> List[Dict[str, Any]]:
    return load_process_list_with_real_fallback(BASE_PATH, DATA)


def extract_timeline() -> List[Dict[str, Any]]:
    return load_timeline_with_real_fallback(BASE_PATH, DATA)


def get_login_events() -> List[Dict[str, Any]]:
    return DATA["login_events"]


TOOLS = {
    "get_process_list": get_process_list,
    "extract_timeline": extract_timeline,
    "get_login_events": get_login_events,
}


def run_investigation(max_iterations: int = 4) -> Dict[str, Any]:
    state = InvestigationState(max_iterations=max_iterations)

    log_event(
        state.logs,
        "System",
        "run_started",
        {"max_iterations": state.max_iterations, "tools_available": list(TOOLS.keys())},
    )

    while not state.verified and not state.failed:
        state.current_iteration += 1
        log_event(
            state.logs,
            "System",
            "iteration_start",
            {"iteration": state.current_iteration},
        )

        investigator_agent(state, TOOLS)
        skeptic_accepted, reasons = skeptic_agent(state)

        if not skeptic_accepted:
            re_executor_agent(state, reasons)

        verifier_agent(state, skeptic_accepted=skeptic_accepted)
        log_event(
            state.logs,
            "System",
            "iteration_end",
            {
                "iteration": state.current_iteration,
                "verified": state.verified,
                "failed": state.failed,
                "confidence": state.confidence,
            },
        )

        if state.current_iteration >= state.max_iterations and not state.verified:
            state.failed = True

    output = reporter_agent(state)
    output["logs"] = state.logs
    output["printable_logs"] = print_logs(state.logs)
    output["strategy_log"] = state.strategy_log
    output["attempted_tools"] = state.attempted_tools
    output["quarantined_evidence"] = state.quarantined_evidence
    output["sanitization_events"] = state.sanitization_events
    return output


if __name__ == "__main__":
    result = run_investigation()
    print(json.dumps(result, indent=2))

