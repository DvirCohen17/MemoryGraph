# MemoryGraph — Phase A-G Implementation Notes

This revision applies the cleanup and architecture work through Phase G without packaging the application as an EXE.

## Phase A — Clean current project

- Removed `.venv`, `.pytest_cache`, `__pycache__`, and `.pyc` artifacts from the source tree.
- Kept `tests/` and `DemoProvider`; both remain useful during development.
- Updated `README.md` to describe the actual current application.
- Updated `requirements.txt` with PySide6, Volatility 3, and pytest.

## Phase B — Normalized evidence model

`app/models.py` now contains explicit models for:

- `Process`
- `DLL`
- `NetworkConnection`
- `MemoryRegion`
- `EvidenceItem`
- `TimelineEvent`
- `PluginResult`
- `Indication`
- `AnalysisResult`

Network address and port fields are stored separately. Legacy saved investigations containing combined `local`/`remote` endpoints are still accepted.

## Phase C — Rule engine infrastructure

The old monolithic indicator implementation is now split into:

```text
app/analysis/indicators/
├── base.py
├── engine.py
├── correlation.py
└── rules/
    ├── process.py
    ├── path.py
    ├── commandline.py
    ├── memory.py
    ├── dll.py
    ├── network.py
    └── handles.py
```

`app/analysis/indicator_engine.py` remains as a compatibility facade so existing imports do not have to change immediately.

## Phase D — Deterministic process/path/command rules

Implemented generic process relationships, process/path anomalies, command-line indicators, and configurable-style thresholds without making Office-specific relationships the core detection model.

The previous Office→PowerShell rule was removed.

## Phase E — Memory/DLL/network/handle rules

Implemented normalized evidence rules for memory, DLLs, network context and handles.

Network connections are not findings by themselves. Network evidence is used primarily when another investigation-relevant characteristic exists, or as a low-priority relationship/correlation observation.

## Phase F — Correlation

`correlation.py` combines independent findings while preserving the individual findings. Correlation records the rule IDs, evidence and source plugins that support it.

## Phase G — GUI integration

The GUI now consumes the richer normalized model and indication metadata, including:

- rule ID
- severity
- confidence
- evidence
- source plugins
- related processes

The network view consumes normalized address/port fields, and the timeline consumes normalized `TimelineEvent` objects.

## Validation

The project passes the current automated test suite in the development environment used for this revision.

EXE packaging is intentionally not part of this phase.

## Next investigation-workspace update

The next iteration adds normalized field-level provenance (plugin + original row), a combined evidence timeline, computer/system information, global cross-artifact search, indication filtering, terminal-style plugin output, improved process-tree navigation/overview, network PID-to-process resolution, and Volatility-backed dump actions for processes, file handles, DLLs and malfind memory pages.
