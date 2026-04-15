# Try It Out

This guide walks through running SIFT-Guardian locally in less than 10 minutes.

## Prerequisites

- Python 3.10+ recommended
- `pip` available in your shell

## 1) Install

From the `sift_guardian` directory:

```bash
python -m venv .venv
```

Activate virtual environment:

- Windows PowerShell:

```bash
.\.venv\Scripts\Activate.ps1
```

- macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## 2) Run the MCP API

```bash
uvicorn mcp_server:app --reload --port 8000
```

Then open API docs at:

- `http://127.0.0.1:8000/docs`

## 3) Run a CLI Investigation

In another terminal:

```bash
python main.py
```

You should get a JSON report with:

- finding
- confidence and confidence history
- corroborated evidence
- contradiction list
- strategy log and attempted tools
- quarantined/sanitization details

## 4) Run the Streamlit Dashboard

```bash
streamlit run app.py
```

Click **Run Investigation** to execute the full workflow and inspect:

- confidence trend chart
- final JSON output
- detailed agent logs
- quarantine and sanitization decisions

## 5) Optional: Validate Behavior via Tests

```bash
pytest -q
```

## 6) Optional: Tune Sanitizer Rules Live

Edit `sanitizer_rules.yaml`, then run investigation again (CLI or dashboard).
No Python code change is needed for rule updates to be applied.

## 7) Optional: Feed Real SIFT Tool Outputs

You can replace mock process and timeline telemetry with real forensic exports:

1. Generate a process list file from your SIFT workflow (for example, Volatility `windows.pslist`).
2. Generate a timeline file (for example, Plaso/Log2Timeline output).
3. Save outputs as JSON/NDJSON/CSV.
4. Point SIFT-Guardian at those files:

Windows PowerShell:

```bash
$env:SIFT_PROCESS_LIST_PATH="C:\path\to\process_list.json"
$env:SIFT_TIMELINE_PATH="C:\path\to\timeline.ndjson"
python main.py
```

Or use default paths without env vars:

- `sift_guardian/real_tool_output/process_list.json`
- `sift_guardian/real_tool_output/timeline.json`

When present and parseable, `/get_process_list`, `/extract_timeline`, and the CLI use real exports automatically.
