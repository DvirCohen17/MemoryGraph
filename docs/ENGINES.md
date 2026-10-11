# Engines: one per operating system

MemoryGraph has two halves.

* The **front end** is everything that does not depend on the operating system of the memory image: the windows and views (`app/windows`), the pipeline, the case file
  (notes, bookmarks, triage), the Volatility runner, the plugin cache and timing store, IOC lists, the models (`app/models.py`). It works on one result type, `AnalysisResult`.
* An **engine** (`app/engines/<os>`) turns an image of that operating system into an `AnalysisResult` and judges it.

```text
app/
  analysis/              shared, OS-independent: pipeline, case_state, volatility_runner, plugin_cache, plugin_timing, ioc, story, hexview, registry_core, rows, dump,
                         indicators/{base, scoring, correlation, corroboration}     (the building blocks every engine's rules use)
  windows/               the GUI (windows, views, widgets)  -- NOT the Windows engine
  engines/
    base.py              the Engine interface, Capabilities, Terms, ViewSpec, EngineNotImplemented
    __init__.py          get_engine("windows"|"linux"), engine_for(result), engine_for_settings(settings)
    windows/             the Windows engine (complete)
      analysis/          plugin_registry, real_provider, normalizer, os_profile, vol2_*, timeline_*, dumper, fileindex, file_report, compare, registry_tree, injection, known_good ...
      indicators/        the rules (rules/), baseline, attack, helpers, engine
      data/              ATT&CK descriptions
    linux/               the Linux engine (SKELETON: every function exists and raises EngineNotImplemented)
      analysis/          provider, plugin_registry (placeholder data), normalizer, os_profile, timeline, dumper, quality, files, compare
      indicators/        engine, baseline, attack, helpers, rules/
      data/
```

## What the front end asks of an engine

Everything goes through `app/engines/base.py: Engine`. `engine_for(result)` picks the engine from `result.target_os`; the start window's choice is `settings["target_os"]`.

| Method | Used by | Linux file |
|---|---|---|
| `plugin_registry()` | Settings (plugin groups), the provider | `analysis/plugin_registry.py` (data: edit freely) |
| `default_settings()` | switching to this OS for the first time | `__init__.py` |
| `make_provider(settings)` → `.run(dump, progress, plugin_event, cancel)` / `.rerun(result, names, ...)` | the analysis controller | `analysis/provider.py` |
| `make_dumper(dump, volatility_path, global_args)` | process window, process tree | `analysis/dumper.py` |
| `normalize(dump, plugins)` | the pipeline | `analysis/normalizer.py` |
| `build_timeline(result)`, `apply_timeline_severity(result)` | the pipeline | `analysis/timeline.py` |
| `data_quality_warnings(result)` | the pipeline | `analysis/quality.py` |
| `describe_os(result)` | headers, report | `analysis/os_profile.py` |
| `indicator_engine(iocs)` → `.evaluate(result)`, `.errors` | the pipeline | `indicators/engine.py` |
| `rule_name`, `rule_catalog`, `attack_for` | Indications view, case notes | `indicators/engine.py`, `indicators/attack.py` |
| `refresh_image_hash_findings(result, iocs)` | "Hash all process images" | (only if `capabilities.process_images`) |
| `is_risky_path`, `is_trusted_path` | colouring of module paths | `indicators/helpers.py`, `indicators/baseline.py` |
| `view_specs()` | the dashboard's navigation | `__init__.py` |
| `capabilities`, `terms`, `implemented`, `status_note` | the windows' words and buttons | `__init__.py` |

`Capabilities` says what the OS has (`registry`, `legacy_network_engine`, `process_images`, `known_good`, `file_explorer`, `compare`): the windows show only what applies.
`Terms` holds the words that differ (DLLs / libraries, handles / open files, the file filter of the Browse dialog, the title of the start window, the symbol hint of Settings).
`view_specs()` lists the navigation; an entry with `available=False` is shown with a "not available yet" page that says what it is waiting for (`app/windows/placeholder_view.py`).

## What the Linux engine has to produce

`normalize()` returns an `app.models.AnalysisResult`. The front end reads these fields, and every field that comes from a plugin should keep its provenance (plugin name and row
index, as the Windows normalizer does with `provenance` and `EvidenceItem`):

* `processes`: `Process(pid, ppid, name, path, image_base, user, session, create_time, command_line, dlls=[library ...], network=[...], memory_regions=[...], handles=[...], ...)`
* `connections`: `NetworkConnection(pid, process, local_address, local_port, remote_address, remote_port, state, protocol, source_plugins)`
* `memory_regions` (malfind), `system_info` (rows with `Variable` / `Value`), `capture_time`, `users` / `accounts`, `warnings`, `plugins` (the raw `PluginResult` list, untouched)
* `target_os = "linux"` (the pipeline sets it)

Rules are `IndicatorRule` subclasses (`app/analysis/indicators/base.py`): `evaluate(result)` returns `Indication` objects made with `self.make(...)`. Each finding names its
rule id, severity, confidence, the process, reasons, evidence lines, source plugins and structured `EvidenceItem`s. Three shared building blocks already exist and should be used:

* `scoring` (severity ranks and scores), `correlation` (several kinds of evidence on one process → CORR-001 / CORR-002),
* `corroboration.require_second_source`: a finding of a rule listed in `SINGLE_SOURCE_RULES` is Medium unless a second plugin points at the same process. Add the Linux rule ids
  whose High rests on one plugin.

## Switching the operating system

`app/settings.py: switch_target_os(settings, new_os)` swaps the settings that belong to one OS (`Engine.os_settings_keys`: plugin groups, symbol folders, the YARA file) and keeps the
others. The previous OS's values are stored under `settings["os_profiles"][old]` and come back when the user switches back. The start window's switch
(`app/windows/os_switch.py`) calls it on every change, saves the settings, and changes the window's texts. A saved investigation carries `target_os`, so loading a Linux investigation
moves the switch to Linux; an investigation saved before engines existed is a Windows one.

## The demo

`LinuxEngine.demo_result()` (`app/engines/linux/demo.py`) returns a complete `AnalysisResult` of invented data so the interface can be seen without an engine.
It is the best example of what the engine has to produce: processes with parents, hidden/exited flags, memory regions, connections, findings with `LNX-` rule ids, a timeline and raw plugin rows.
Set `Capabilities.demo = False` (and delete the file) when the real engine exists.

## Order of work for the Linux engine

1. `analysis/os_profile.py`: parse the `banners.Banners` row; decide which ISF the image needs (and say so when it is missing: the symbol message in
   `app/analysis/volatility_runner.py: classify_failure` already points to Settings → symbol folders).
2. `analysis/provider.py`: model it on `app/engines/windows/analysis/real_provider.py` (banners first, then the enabled plugins in parallel, `plugin_cache`, `plugin_timing`).
   Test with `tests/fake_vol.py` (it imitates the Volatility command line; give it a fixture with `linux.*` rows).
3. `analysis/normalizer.py`: processes first (the dashboard works as soon as there are processes), then sockets, then malfind regions.
4. `indicators/baseline.py` + `rules/`: start with process parentage and paths (`indicators/rules/__init__.py` lists the families).
5. Mark views available in `LinuxEngine.view_specs()` as their back ends appear (Files, Injection, Compare).
6. Add a Linux case to `tools/realworld/scenarios.py` (synthetic rows) and run `tools/realworld/run_report.py --simulate`; add real images with an expected-results file when you have them.

A test for the engine contract already exists (`tests/test_engines.py`): it fails when a method is missing from either engine.
