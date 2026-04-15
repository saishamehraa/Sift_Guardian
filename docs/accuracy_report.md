# Accuracy Report

## Scope

This report captures behavior-based accuracy for the current prototype implementation of SIFT-Guardian.
Because the project is a deterministic mock-environment prototype, accuracy is evaluated through repeatable automated tests.

## Test Baseline

- Command run: `pytest -q`
- Result: `5 passed in 7.18s`
- Date: 2026-04-15

## Behavioral Checks Covered

The current test suite validates the following accuracy-relevant outcomes:

1. **Self-correction and confidence growth**
   - Initial weak single-source finding is rejected by the Skeptic.
   - Re-Executor pivots tool strategy.
   - Confidence increases and finishes above acceptance threshold.

2. **Boundary enforcement**
   - Write-style MCP requests are rejected.
   - Investigation continues with graceful handling of rejected operations.

3. **Graceful degradation**
   - With missing corroborating sources, the system does not overclaim.
   - It reaches iteration cap and returns a low-confidence assessment.

4. **Prompt-injection sanitization quality**
   - Malicious instruction-like artifact is quarantined.
   - Benign operational override log remains available.

5. **Hot-reload correctness for sanitization rules**
   - YAML rule updates alter sanitization outcome without code restart.

## Interpretation

- **Prototype reliability:** High for the included mock scenario and covered edge cases.
- **Generalization:** Not yet measured across large or real forensic corpora.
- **Current confidence claim:** The system is accurate for tested behaviors, not yet statistically benchmarked for production incident response workloads.

## Recommended Next Accuracy Milestones

1. Add multi-scenario datasets (benign, noisy, ransomware-like, credential abuse).
2. Introduce per-scenario expected findings and confidence bounds.
3. Track precision/recall for detection labels across scenarios.
4. Publish trend snapshots as tests and datasets expand.
