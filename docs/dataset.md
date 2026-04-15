# Dataset Documentation

## Overview

SIFT-Guardian currently ships with a single mock DFIR dataset in `mock_data.json`.
The dataset is designed to demonstrate how the agent loop handles:

- suspicious endpoint behavior
- cross-source evidence correlation
- prompt-injection-like artifacts in forensic data

## Data Sources

The dataset contains three source collections:

1. `process_list`
   - running process metadata (PID, user, command line, start time)
2. `timeline`
   - timestamped disk-derived events (file creation, process launch, network connection, logs)
3. `login_events`
   - authentication records (RDP and interactive login context)

## Included Scenario

The mock scenario models a potentially malicious PowerShell execution chain:

- hidden/encoded `powershell.exe` command observed in process telemetry
- script drop and suspicious outbound network event in timeline data
- near-time remote login event that can increase suspicion
- one malicious instruction-like artifact (`C:\Temp\notes.txt`) intentionally crafted to test sanitization
- one benign operational log (`C:\Logs\ops.log`) that should remain usable as evidence

## Format Notes

- All timestamps use UTC ISO-8601 format.
- Records are intentionally compact and human-readable.
- Source fields are stable and map directly to MCP endpoints:
  - `/get_process_list`
  - `/extract_timeline`
  - `/get_login_events`

## Extending the Dataset

To add additional scenarios:

1. Append records in `mock_data.json` under the existing source keys.
2. Keep timestamp ordering logical for timeline-style interpretation.
3. Preserve realistic host/user/event relationships across sources.
4. Re-run tests to validate behavior:

```bash
pytest -q
```
