from __future__ import annotations

import pandas as pd
import streamlit as st

from main import run_investigation

st.set_page_config(page_title="SIFT-Guardian", layout="wide")
st.title("SIFT-Guardian: Self-Correcting Autonomous Incident Response Agent")
st.caption("DFIR prototype with skeptic checks, strategy pivots, and traceable evidence.")

if st.button("Run Investigation"):
    result = run_investigation()
    quarantined = result.get("quarantined_evidence", [])
    sanitization_events = result.get("sanitization_events", [])
    evidence = result.get("evidence", [])

    if quarantined:
        st.error(
            f"High-priority IOC: {len(quarantined)} artifact(s) quarantined by EvidenceFirewall for prompt-injection behavior."
        )
    else:
        st.success("No prompt-injection artifacts quarantined in this run.")

    left_col, right_col = st.columns(2)

    with left_col:
        st.subheader("Final Finding (Structured JSON)")
        structured_output = {
            "finding": result["finding"],
            "confidence": result["confidence"],
            "confidence_history": result["confidence_history"],
            "confidence_reasoning": result.get("confidence_reasoning", []),
            "evidence": result["evidence"],
            "contradictions": result["contradictions"],
            "failure_reason": result.get("failure_reason", ""),
            "iterations_required": result["iterations_required"],
        }
        st.json(structured_output)

        st.subheader("Final Evidence Lineage (Trace IDs)")
        lineage_rows = []
        for item in evidence:
            record = item.get("data", {})
            lineage_rows.append(
                {
                    "trace_id": item.get("trace_id", "n/a"),
                    "source_tool": item.get("source", "n/a"),
                    "artifact": record.get("artifact", record.get("name", "n/a")),
                    "event_type": record.get("event_type", "process_record"),
                }
            )
        if lineage_rows:
            st.dataframe(pd.DataFrame(lineage_rows), use_container_width=True)
        else:
            st.info("No evidence collected in this run.")

        st.subheader("Operational Metadata")
        st.write("Attempted tools:", result["attempted_tools"])
        st.write("Strategy changes:", result["strategy_log"])
        st.write("Quarantined artifacts:", len(quarantined))

        if quarantined:
            st.subheader("Quarantined Artifacts (IOC Queue)")
            ioc_rows = []
            for item in quarantined:
                record = item.get("record", {})
                matching_event = next(
                    (
                        event
                        for event in sanitization_events
                        if event.get("decision") == "quarantine"
                        and event.get("record_hint") == record.get("artifact", record.get("event_type", "n/a"))
                        and event.get("tool") == item.get("source")
                    ),
                    {},
                )
                ioc_rows.append(
                    {
                        "trace_id": matching_event.get("trace_id", "quarantine_only"),
                        "source_tool": item.get("source"),
                        "artifact": record.get("artifact", "n/a"),
                        "event_type": record.get("event_type", "n/a"),
                        "reason": item.get("reason", "n/a"),
                    }
                )
            st.dataframe(pd.DataFrame(ioc_rows), use_container_width=True)
            st.json(quarantined)

    with right_col:
        st.subheader("Confidence Tracking")
        confidence_df = pd.DataFrame(
            {
                "iteration": list(range(1, len(result["confidence_history"]) + 1)),
                "confidence": result["confidence_history"],
            }
        ).set_index("iteration")
        st.line_chart(confidence_df)

        st.subheader("Structured Logs")
        st.text_area("Printable Logs", value=result["printable_logs"], height=420)

        st.subheader("🛡️ EvidenceFirewall (Adversarial Input Defense Layer)")
        st.text_area(
            "EvidenceFirewall Decisions",
            value="\n".join(
                [
                    f"{event['tool']} | {event['decision']} | {event['record_hint']}"
                    for event in sanitization_events
                ]
            ),
            height=220,
        )

