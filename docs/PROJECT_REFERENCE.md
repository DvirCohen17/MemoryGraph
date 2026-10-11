# MemoryGraph - project reference

*Generated 2026-10-10 from the source code. Lists every file, class and function with its purpose.*

## At a glance

- **160 Python files**, about **27,069 lines**, **1752 classes and functions** (small helper functions nested inside other functions are not listed separately).
- Folders: `app/` (the program), `tools/` (real-world testing and the offline report), `tests/` (automated tests), `docs/` (documentation).
- MemoryGraph is a PySide6 desktop program that runs **Volatility** on a memory image, normalizes the evidence, applies investigation **rules** and shows the result in a dashboard. It never connects to the internet.

## How the parts fit together

1. **Start window** (`app/windows/home_window.py`): pick Windows or Linux (`os_switch.py`), choose a memory image, run.
2. **Controller** (`app/analysis/controller.py`) starts a background task (`app/tasks.py`) that asks the chosen **engine** (`app/engines/`) for a provider.
3. **Provider** (Windows: `engines/windows/analysis/real_provider.py`) runs the Volatility plugins of the **plugin registry** with cache, timeouts and progress (`app/analysis/volatility_runner.py`).
4. **Pipeline** (`app/analysis/pipeline.py`): normalizer (plugin rows to an `AnalysisResult`, defined in `app/models.py`), then timeline, then **rules** (`engines/<os>/indicators`), then the second-source rule and correlation.
5. **Dashboard** (`app/windows/dashboard_window.py`) shows the result in views: Overview, Search, Process Tree, Indications, Injection, Plugin Output, Files, Registry, Network, Timeline, Lifetimes, Compare, Case Notes, Computer Info.
6. **Case state** (`app/analysis/case_state.py`) keeps the investigator's triage, notes, bookmarks and baselines inside the saved investigation file.
7. **Linux** is a skeleton (`app/engines/linux`): every function exists and says "not implemented yet", plus a made-up demo investigation (`demo.py`).

## Contents

- Project root: 1 file(s)
- app - core modules: 9 file(s)
- app/analysis - shared analysis code: 16 file(s)
- app/analysis/indicators - shared rule helpers: 5 file(s)
- app/engines - the engine interface: 2 file(s)
- app/engines/linux - the Linux engine (skeleton): 3 file(s)
- app/engines/linux/analysis - Linux evidence (skeleton): 10 file(s)
- app/engines/linux/indicators - Linux rules (skeleton): 5 file(s)
- app/engines/linux/indicators/rules - Linux rule families (empty): 1 file(s)
- app/engines/windows - the Windows engine: 1 file(s)
- app/engines/windows/analysis - Windows evidence: 19 file(s)
- app/engines/windows/indicators - Windows rules: 5 file(s)
- app/engines/windows/indicators/rules - rule families: 21 file(s)
- app/windows - the GUI: 28 file(s)
- tools/realworld - real-world testing and reporting: 6 file(s)
- tests - automated tests: 28 file(s)
- Non-code files


---

## Project root

*Entry point and top-level files.*

### `main.py`  (37 lines)

**Purpose:** Program entry point: sets up logging and the crash handler, creates the Qt application, applies the dark theme and fonts, shows the splash screen and then the main window.

| Name | Kind | Purpose |
|---|---|---|
| `main()` | function | Starts the application: logging, global exception hook, QApplication, theme and hover glow, splash screen, then opens the HomeWindow and runs the event loop. |


---

## app - core modules

*Shared building blocks: data model, settings, errors, paths, tasks, theme, helpers.*

### `app/__init__.py`  (1 lines)

**Purpose:** Marks `app` as a Python package (no code).

*(no classes or functions)*

### `app/errors.py`  (116 lines)

**Purpose:** Friendly error types plus the safety nets that keep a GUI error from crashing the program.

| Name | Kind | Purpose |
|---|---|---|
| `class MemoryGraphError(Exception)` | class | Base class for errors that already carry a user-friendly message. |
| `MemoryGraphError.__init__(message, details)` | method | Stores the user-readable message and the technical details of an error. |
| `class VolatilityNotFound(MemoryGraphError)` | class | Error: the Volatility program could not be found. |
| `class DumpFileError(MemoryGraphError)` | class | Error: the memory dump file is missing, empty, unreadable or of an unusable kind. |
| `class AnalysisCancelled(MemoryGraphError)` | class | Raised inside a background task when the user cancels an analysis. |
| `class VolatilityUnusable(MemoryGraphError)` | class | Volatility ran but cannot read this image (symbols / OS / format). |
| `format_exception(exc)` | function | Turns an exception into its full traceback text for the log. |
| `short_message(exc)` | function | Gives the one-line message to show the user (the friendly message of a MemoryGraphError, otherwise the exception text). |
| `report_exception(exc, context, parent, show_dialog)` | function | Logs an exception and, when a GUI exists, shows an error box instead of crashing. |
| `safe_slot(func)` | function | Decorator for GUI slots: any exception inside is reported to the user and the log rather than breaking the interface. |
| `install_global_excepthook()` | function | Routes uncaught exceptions of the main thread and worker threads to the log and a dialog. |

### `app/logging_setup.py`  (38 lines)

**Purpose:** Central logging configuration (log file and console).

| Name | Kind | Purpose |
|---|---|---|
| `setup_logging(level)` | function | Configures the MemoryGraph logger once (rotating file in the log folder and console output). |
| `get_logger(name)` | function | Returns a named child logger of the MemoryGraph logger. |

### `app/models.py`  (401 lines)

**Purpose:** The shared data model: dataclasses for processes, DLLs, connections, memory regions, findings, plugin results and the whole AnalysisResult, plus save/load of an investigation file.

| Name | Kind | Purpose |
|---|---|---|
| `class DLL` | class | A module (DLL / shared library) loaded by a process: name, path, base address, size, suspicious flag. |
| `class NetworkConnection` | class | One network connection or listening socket belonging to a process (addresses, ports, state, protocol, creation time, source plugins). |
| `NetworkConnection.local()` | method | The local endpoint as text ("address:port"). |
| `NetworkConnection.remote()` | method | The remote endpoint as text ("address:port"). |
| `NetworkConnection.from_legacy(pid, process, local, remote, state, **kwargs)` | method | Builds a connection from older "address:port" text fields. |
| `class MemoryRegion` | class | A memory region of a process (range, protection, flags, hex dump, disassembly) as reported by malfind or vadinfo. |
| `MemoryRegion.range()` | method | The region's address range as "start - end" text. |
| `class TimelineEvent` | class | One dated fact on the investigation timeline (time, category, description, process, severity, source). |
| `class EvidenceItem` | class | One piece of evidence behind a finding, with the plugin and row it came from. |
| `class Process` | class | A normalized process: ids, name, path, command line, user, times, flags (hidden, exited), DLLs, handles, connections and memory regions. |
| `class Indication` | class | A finding produced by a rule: rule id, severity, score, confidence, title, summary, evidence, ATT&CK tags and triage state. |
| `class PluginResult` | class | The outcome of one Volatility plugin run (status, rows, error, timing). |
| `PluginResult.skipped()` | method | True when the plugin was deliberately not run (does not exist for this OS version); not a failure. |
| `PluginResult.failed()` | method | True when the plugin ran and did not complete. |
| `class AnalysisResult` | class | Everything known about one image: dump path, OS, processes, connections, findings, timeline, plugin results, warnings, notes and triage. |
| `_join_endpoint(address, port)` | function | Joins an address and a port into "address:port" text (handles IPv6 and empty values). |
| `split_endpoint(value)` | function | Splits "address:port" text back into address and port (handles IPv6 and wildcards). |
| `_known(data)` | function | Keeps only the dictionary keys that are fields of a dataclass (so old and new saved files both load). |
| `_int(value, default)` | function | Converts a value to int, falling back to a default. |
| `_dll_from_dict(data)` | function | Rebuilds a DLL from saved JSON data. |
| `_network_from_dict(data)` | function | Rebuilds a NetworkConnection from saved JSON data. |
| `_memory_from_dict(data)` | function | Rebuilds a MemoryRegion from saved JSON data. |
| `_evidence_from_dict(data)` | function | Rebuilds an EvidenceItem from saved JSON data. |
| `_handle_from_any(value)` | function | Normalizes a saved handle entry (old string form or new dict form) into a dict. |
| `_process_from_dict(item)` | function | Rebuilds a Process, with its DLLs, connections and regions, from saved JSON data. |
| `_indication_from_dict(item)` | function | Rebuilds an Indication and its evidence items from saved JSON data. |
| `analysis_result_to_dict(result, compact_plugins)` | function | Converts an AnalysisResult to plain JSON-ready data (optionally keeping the plugin rows compact). |
| `analysis_result_from_dict(data)` | function | Rebuilds an AnalysisResult from saved data, validating that it really is an investigation and filling in missing fields of older files. |
| `save_analysis_result(result, file_path)` | function | Writes an investigation to a file atomically (temporary file then rename); .gz paths are compressed. |
| `load_analysis_result(file_path)` | function | Reads an investigation file (plain or gzip) and returns the AnalysisResult, with clear errors for bad files. |

### `app/paths.py`  (41 lines)

**Purpose:** Where MemoryGraph keeps its files: settings, logs, plugin-output cache and the project root.

| Name | Kind | Purpose |
|---|---|---|
| `project_root()` | function | The folder holding app/ and tools/ (used to find drop-in tools such as Volatility 2). |
| `app_dir()` | function | The per-user MemoryGraph data folder (created when needed; can be redirected with MEMORYGRAPH_HOME). |
| `log_dir()` | function | The folder for log files. |
| `cache_dir()` | function | The folder for the cache of plugin output. |
| `settings_path()` | function | The path of settings.json. |

### `app/settings.py`  (153 lines)

**Purpose:** Persistent settings: defaults, validation, loading, saving and the per-operating-system settings profiles.

| Name | Kind | Purpose |
|---|---|---|
| `sanitize(values)` | function | Merges settings with the defaults and forces every value into a safe range or type. |
| `load_settings()` | function | Reads settings.json (or the defaults when it is missing or broken). |
| `save_settings(values)` | function | Writes settings.json atomically. |
| `remember_recent(values, key, item)` | function | Puts an item at the top of a "recent" list (max 10, no duplicates). |
| `switch_target_os(settings, new_os)` | function | Changes the chosen operating system and swaps the settings that belong to one OS (plugin choices, symbol folders) in and out of their saved profiles. |

### `app/tasks.py`  (95 lines)

**Purpose:** Runs a function on a background Qt thread and reports back through signals so the GUI never freezes.

| Name | Kind | Purpose |
|---|---|---|
| `class _Worker(QObject)` | class | Qt object that lives in the worker thread and runs the task function. |
| `_Worker.__init__(fn, cancel_event)` | method | Remembers the function to run and the cancel flag. |
| `_Worker.run()` | method | Runs the function and emits done, cancelled or failed. |
| `class BackgroundTask(QObject)` | class | A cancellable background job with finished / failed / cancelled signals. |
| `BackgroundTask.__init__(fn, parent)` | method | Creates the thread and worker and connects their signals. |
| `BackgroundTask.running()` | method | True while the job is running. |
| `BackgroundTask.start()` | method | Starts the thread. |
| `BackgroundTask.cancel()` | method | Sets the cancel flag the job polls. |
| `BackgroundTask._end()` | method | Marks the job as no longer running and stops the thread. |
| `BackgroundTask._on_done(result)` | method | Passes the result on through the finished signal. |
| `BackgroundTask._on_failed(message, details)` | method | Passes the error on through the failed signal. |
| `BackgroundTask._on_cancelled()` | method | Emits the cancelled signal. |
| `BackgroundTask._cleanup()` | method | Releases the worker once the thread is finished. |

### `app/theme.py`  (722 lines)

**Purpose:** The one dark theme: colour palette, the Qt stylesheet built from it, severity/category colours and font scaling.

| Name | Kind | Purpose |
|---|---|---|
| `_icon(name, points, width, colour)` | function | Draws a small line icon (tick, chevron) once into the MemoryGraph folder and returns the stylesheet `image:` rule for it. |
| `_check_icon()` | function | The tick shown in checked boxes. |
| `_chevron_up_icon()` | function | The up arrow of spin boxes. |
| `_chevron_icon()` | function | The down arrow of drop-down lists and spin boxes. |
| `build_style()` | function | Fills the stylesheet template with the palette and icons. |
| `resolve_theme(name)` | function | Always returns "Dark" (older Light/System settings mean the dark theme). |
| `scale_fonts(style, base_pt)` | function | Rescales every font size in the stylesheet to a chosen base size. |
| `get_theme_style(name, font_pt)` | function | The finished stylesheet at the chosen font size. |

### `app/util.py`  (149 lines)

**Purpose:** Small shared helpers: times, integers, hex, sizes, text cleaning and Windows path handling.

| Name | Kind | Purpose |
|---|---|---|
| `parse_time(value)` | function | Parses the timestamp formats Volatility prints into a UTC datetime. |
| `time_key(value)` | function | A sortable number for a timestamp (unparsable ones sort last). |
| `format_time(value, with_seconds)` | function | Formats a timestamp for display. |
| `format_delta(seconds)` | function | Formats a time difference such as "-12m 05s" or "+2d 03h". |
| `to_int(value, default)` | function | Converts decimal/hex text or numbers to int, or a default. |
| `to_hex(value)` | function | Formats a number as hex text. |
| `human_size(value)` | function | Formats a byte count such as "1.5 MB". |
| `clean_text(value)` | function | Converts None to "" and anything else to text. |
| `norm_path(path)` | function | Lower-cases a Windows path and turns NT prefixes (\Device\..., \??\) into drive-letter form so paths compare equal. |
| `path_dir(path)` | function | The folder part of a Windows path. |
| `path_file(path)` | function | The file-name part of a Windows path. |
| `first(iterable, default)` | function | First item of an iterable, or a default. |


---

## app/analysis - shared analysis code

*Code that is the same for every operating system: the pipeline, Volatility runner, cache, IOC lists, case state, story, hex helpers.*

### `app/analysis/__init__.py`  (1 lines)

**Purpose:** Marks `app.analysis` (the part of the analysis code shared by every operating system) as a package.

*(no classes or functions)*

### `app/analysis/case_state.py`  (289 lines)

**Purpose:** The investigator's own work stored inside an investigation: triage decisions (reviewed / false positive), notes, bookmarks and known-good baselines.

| Name | Kind | Purpose |
|---|---|---|
| `empty_case()` | function | A new, empty case record (findings, notes, bookmarks, baselines, image hashes). |
| `ensure_case(result)` | function | The case dict of `result` with every section present (tolerates missing/garbled data from old or edited files). |
| `_now()` | function | Current UTC time as ISO text (stamps notes and decisions). |
| `_digest(*parts, length)` | function | Short stable hash of some values (used to build identifiers). |
| `_process_of(result, ind)` | function | The Process a finding belongs to, or None. |
| `finding_signature(ind, proc)` | function | A text signature of a finding that stays the same across images (rule, process name, path class), used by baselines. |
| `finding_key(ind, proc)` | function | A stable identifier of one finding in one image (signature + PID + start time), used to remember its triage. |
| `process_target(proc)` | function | The identifier under which notes and bookmarks refer to a process. |
| `network_target(conn)` | function | The identifier of a network connection for notes and bookmarks. |
| `event_target(event)` | function | The identifier of a timeline event for notes and bookmarks. |
| `dll_target(proc, dll)` | function | A module loaded in one process (same process identity as process_target, plus the module name and base address). |
| `plugin_row_target(plugin_name, row)` | function | One row of a plugin's output, identified by its content (row order can change when a plugin is run again). |
| `region_target(proc, region)` | function | The identifier of a memory region for notes and bookmarks. |
| `baseline_signatures(case)` | function | Collects the finding signatures of every imported baseline, with the baseline each came from. |
| `apply_case(result)` | function | Stamp `triage` / `triage_note` on every finding from the case (idempotent; safe to call after any re-analysis). |
| `set_finding_status(result, ind, status, note, reapply)` | function | Record the investigator's decision for `ind` and re-apply the case. Returns the finding key. |
| `finding_entry(result, ind)` | function | The saved triage entry of a finding, if any. |
| `add_note(result, kind, target, label, text, pid)` | function | Adds a note about a process, connection, event or finding and returns it. |
| `delete_note(result, note_id)` | function | Removes a note by id; True if it existed. |
| `notes_for(result, target)` | function | All notes attached to one target. |
| `toggle_bookmark(result, kind, target, label, pid)` | function | Add or remove a bookmark; returns True when the target is bookmarked afterwards. |
| `is_bookmarked(result, target)` | function | True when a target is bookmarked. |
| `has_marks(result, target)` | function | Tells whether a target is bookmarked and whether it has notes. |
| `export_baseline(result, path, name, only_false_positives)` | function | Write a baseline file; returns how many findings it contains. |
| `import_baseline(result, path)` | function | Add a baseline file to the case and re-apply it. Returns (baseline name, entries). |
| `remove_baseline(result, name)` | function | Removes an imported baseline from the case and re-applies the case; True if it existed. |
| `export_markdown(result, path)` | function | Case notes as a Markdown report: bookmarks, notes and triage decisions, each with where it came from. |

### `app/analysis/controller.py`  (96 lines)

**Purpose:** GUI-facing controller that starts, cancels and reports the background jobs: analysis, loading a saved investigation, re-running plugins.

| Name | Kind | Purpose |
|---|---|---|
| `class AnalysisController(QObject)` | class | Owns the background task and exposes progress / plugin_event / finished / failed / cancelled signals to the windows. |
| `AnalysisController.__init__(parent)` | method | Creates the controller with no task running. |
| `AnalysisController.is_running()` | method | True while a job runs. |
| `AnalysisController.start(dump_path, settings)` | method | Starts a full analysis of a dump with the engine chosen in the settings. |
| `AnalysisController.rerun_failed(result, settings)` | method | Re-runs only the plugins of an existing result that failed. |
| `AnalysisController.run_plugins(result, settings, names)` | method | Run the named plugins on the image of `result` and merge their output into it (cache is bypassed). |
| `AnalysisController.load(file_path, rebuild, settings)` | method | Load a saved investigation; `rebuild` re-runs normalization + rules on its stored plugin output. |
| `AnalysisController.cancel()` | method | Asks the running job to stop. |
| `AnalysisController._emit_progress(text, value)` | method | Forwards a progress text and percentage to the GUI. |
| `AnalysisController._emit_plugin(name, state, detail)` | method | Forwards "plugin started / finished / failed" events to the GUI. |
| `AnalysisController._launch(fn)` | method | Starts a background task unless one is already running and wires its signals. |

### `app/analysis/decoders.py`  (55 lines)

**Purpose:** Turns unreadable evidence (such as base64 PowerShell commands) into readable text for display only.

| Name | Kind | Purpose |
|---|---|---|
| `class DecodedCommand` | class | The result of decoding a command line: the decoded script and which switch carried it. |
| `decode_encoded_command(command_line)` | function | Decode the payload of `powershell -EncodedCommand <base64>`; None if absent or not a clean UTF-16LE script. |

### `app/analysis/demo_provider.py`  (75 lines)

**Purpose:** A synthetic provider that fabricates plugin rows so rules and the GUI can be tried without a memory image.

| Name | Kind | Purpose |
|---|---|---|
| `_plugins(scenario)` | function | Builds the fake plugin outputs for a scenario ("clean" or "correlated" attack). |
| `class DemoProvider` | class | Synthetic provider used for GUI/rule development without a memory dump. |
| `DemoProvider.run(dump_path, progress, scenario)` | method | Pretends to run an analysis: builds the fake plugin rows, normalizes them and runs the rules. |

### `app/analysis/dump.py`  (31 lines)

**Purpose:** Checks on the memory image file (exists, not empty, not a folder, not a compressed/known-wrong kind) common to every OS.

| Name | Kind | Purpose |
|---|---|---|
| `validate_dump(path)` | function | Checks the memory image path (exists, not empty, a file) and returns it cleaned, or raises an error with a message a person can act on. |

### `app/analysis/hexview.py`  (251 lines)

**Purpose:** Pure helpers for the hex viewer: parsing and formatting hexdumps, search patterns, disassembly. No Qt, so it is unit-tested alone.

| Name | Kind | Purpose |
|---|---|---|
| `parse_hexdump(text)` | function | Turns a Volatility hexdump text (two possible layouts) back into bytes. |
| `region_bytes(region)` | function | The bytes of a memory region taken from its stored hexdump. |
| `class Layout` | class | Where each column (address, hex bytes, ASCII) starts in the text that format_dump produces, so a text position can be mapped to a byte offset. |
| `Layout.address_digits()` | method | 8 or 16 hex digits, depending on the size of the addresses. |
| `Layout.hex_start()` | method | Text column where the hex bytes begin. |
| `Layout.ascii_start()` | method | Text column where the ASCII column begins. |
| `Layout.hex_column(offset)` | method | Text column of the hex pair of a byte offset. |
| `Layout.ascii_column(offset)` | method | Text column of the ASCII character of a byte offset. |
| `Layout.line_of(offset)` | method | The text line a byte offset is on. |
| `Layout.offset_at(line, column)` | method | Byte offset behind a text position (in the hex or the ASCII column), None for the address column or outside the data. |
| `format_dump(data, base, width)` | function | Formats bytes as "address  hex bytes  ascii" lines and returns the text plus its Layout. |
| `inspect_at(data, offset)` | function | One line describing the bytes at `offset` as integers (little endian) and text. |
| `compile_pattern(text, mode, ignore_case)` | function | Compiled bytes pattern. `hex`: `4d 5a` / `4d5a` / `0x4d 0x5a` with `??` for any byte; `ascii`; `utf16` (little endian). |
| `find_next(data, pattern, start, wrap)` | function | Finds the first match of a pattern at or after a position, wrapping around to the beginning; returns (offset, length) or None. |
| `find_previous(data, pattern, before, wrap)` | function | Finds the last match that starts before a position, wrapping around to the end; returns (offset, length) or None. |
| `count_matches(data, pattern, cap)` | function | Counts pattern matches in the data (capped). |
| `class Instruction` | class | One disassembled instruction (address, bytes, mnemonic, operands). |
| `capstone_available()` | function | True when the optional capstone disassembler is installed. |
| `disassemble(data, base, bits, start, limit)` | function | Up to `limit` x86 instructions from `data[start:]`; bytes that do not decode become `db 0x..` and decoding goes on after them. |
| `find_dump_file(directory, pid, start, end)` | function | The `pid.<pid>.vad.<start>-<end>.dmp` file of a region in `directory` (exact range first, then same start), or None. |
| `read_file(path, limit)` | function | Reads up to a limit of bytes from a file and returns them with the file's total size. |

### `app/analysis/indicator_engine.py`  (6 lines)

**Purpose:** Backward-compatible shortcut that re-exports the Windows indicator engine under its old name.

*(no classes or functions)*

### `app/analysis/ioc.py`  (394 lines)

**Purpose:** User-supplied indicators of compromise (IPs, domains, hashes, mutexes, files): reading text/STIX/MISP lists, matching evidence against them and generating YARA rules.

| Name | Kind | Purpose |
|---|---|---|
| `class Ioc` | class | One indicator: kind, normalized value, original text, list name and note. |
| `Ioc.describe()` | method | A readable description ("IP IOC 1.2.3.4 from list 'x'"). |
| `class IocSet` | class | A collection of indicators with matching helpers. |
| `IocSet.__init__(items)` | method | Creates the set from a list of indicators. |
| `IocSet.__bool__()` | method | True when the set is not empty. |
| `IocSet.__len__()` | method | Number of indicators. |
| `IocSet.of(kind)` | method | The indicators of one kind. |
| `IocSet.counts()` | method | How many indicators of each kind the set holds. |
| `IocSet.match_ip(host)` | method | Indicators (IP or CIDR) that cover an address. |
| `IocSet.match_domains(text)` | method | IOC domains that occur as a host name in `text` (exact host or a sub-domain of it). |
| `IocSet.match_hash(digest)` | method | Hash indicators equal to a digest. |
| `IocSet.match_mutex(name)` | method | Mutex indicators matching a mutex name. |
| `IocSet.match_file(path)` | method | File indicators matching a path. |
| `_refang(text)` | function | Undoes defanging in a copied indicator (hxxp, [.]). |
| `_host_of(value)` | function | The host part of a URL or domain text. |
| `_guess_kind(value)` | function | Decides whether a bare list line is an IP, domain, hash, mutex or file. |
| `make_ioc(kind, raw, list_name, note)` | function | Build one normalised IOC; raises ValueError with a reason when `raw` is not valid for `kind`. |
| `parse_ioc_text(text, list_name)` | function | Parse the text of an IOC list. Returns (iocs, warnings); bad lines are reported, never fatal. |
| `_stix_kind(obj)` | function | Maps a STIX object type to an indicator kind. |
| `parse_stix(data, list_name)` | function | IOCs from the patterns of STIX 2.x `indicator` objects (a bundle, a list of objects, or one object). |
| `parse_misp(data, list_name)` | function | IOCs from MISP attributes anywhere in the JSON (event exports, search results). Attributes with `to_ids` false are skipped. |
| `_dedupe(items)` | function | Removes duplicate indicators. |
| `parse_ioc_json(text, list_name)` | function | STIX 2 or MISP JSON -> (iocs, warnings); None when `text` is not JSON at all (the caller then treats it as a text list). |
| `load_ioc_file(path)` | function | Read one IOC list: plain text (see the module docstring), a STIX 2 bundle, or a MISP JSON export. |
| `load_from_settings(settings)` | function | The IOC set configured in Settings (`ioc_files`) and the problems found while reading it. (None, []) when none is set. |
| `_yara_text(value)` | function | Escapes text so it can sit inside a YARA string. |
| `yara_rules_from_iocs(iocs)` | function | YARA source that finds your domains, IP addresses and mutex names in process memory, and the number of strings in it. |

### `app/analysis/pipeline.py`  (85 lines)

**Purpose:** The shared pipeline normalize -> timeline -> rules -> corroboration -> correlation, used for live analysis and for re-analysing saved investigations; driven by the engine in use.

| Name | Kind | Purpose |
|---|---|---|
| `analyze_plugins(dump_path, plugins, progress, case, iocs, engine)` | function | Runs normalization, timeline and rules on plugin results, carrying over the case (triage, notes, baselines) and IOC set; used by live analysis and by re-analysis of saved files. |
| `data_quality_warnings(result)` | function | Things about the image itself that limit what the rules can say (the engine of the result decides). |
| `reanalyze(result, progress, iocs)` | function | Rebuild processes, timeline and indications from the plugin rows stored in `result` (the case state is kept). |
| `refresh_image_hash_findings(result, iocs)` | function | Re-evaluate only rule IOC-007 (hashes of dumped process images vs. the IOC list) after "Hash all process images…". Returns the number of IOC-007 findings. |

### `app/analysis/plugin_cache.py`  (92 lines)

**Purpose:** On-disk cache of finished plugin output so a repeated run of the same image skips work.

| Name | Kind | Purpose |
|---|---|---|
| `_dump_identity(dump_path)` | function | Identity text of an image file (path, size, modification time). |
| `cache_key(dump_path, plugin, vol_version)` | function | The cache file key for an image + plugin + Volatility version. |
| `_path(key)` | function | The cache file path for a key. |
| `load(dump_path, plugin, vol_version)` | function | Returns the cached PluginResult for an image/plugin, or None. |
| `store(dump_path, plugin, vol_version, result)` | function | Saves a completed PluginResult in the cache. |
| `size_bytes()` | function | Total size of the cache in bytes. |
| `clear()` | function | Deletes the cache and returns how many files were removed. |

### `app/analysis/plugin_timing.py`  (91 lines)

**Purpose:** Learns how long each plugin takes per gigabyte of image from earlier runs and uses that for time estimates.

| Name | Kind | Purpose |
|---|---|---|
| `_path()` | function | Where the timings file is stored. |
| `_learned()` | function | Reads the learned timings. |
| `seconds_per_gb(name, learned)` | function | Seconds per GB for a plugin (learned, or a built-in guess). |
| `record(name, seconds, image_bytes)` | function | Remember how long `name` took (blended with what was known: a single odd run does not rule). |
| `expected(name, image_bytes, learned)` | function | Expected seconds for a plugin on an image of a given size. |
| `order(names, image_bytes)` | function | Slowest first (stable for equal estimates). |
| `estimate_total(names, image_bytes, workers)` | function | Wall-clock seconds when `workers` plugins run at a time and the slowest are started first (greedy list scheduling). |
| `describe(seconds)` | function | Turns seconds into "under a minute" / "about 12 min" text. |

### `app/analysis/registry_core.py`  (151 lines)

**Purpose:** The data structures every engine uses to describe its plugin list: plugin specs, Settings bundles and the registry class.

| Name | Kind | Purpose |
|---|---|---|
| `class PluginSpec` | class | One plugin an engine can run: name, group, Volatility plugin name, arguments, timeouts, whether required or opt-in. |
| `PluginSpec.volatility_plugin()` | method | The real Volatility plugin name to run. |
| `PluginSpec.choice_id()` | method | The settings key under which the plugin is switched on or off. |
| `PluginSpec.inapplicable(profile)` | method | Why this plugin makes no sense for the image's OS version (an OS profile with `known`, `version` and `short_name`), or '' when it does or the OS is unknown. |
| `PluginSpec.volatility_names()` | method | Every Volatility name this plugin is known under, preferred one first. |
| `class Bundle` | class | A group of plugins that is ticked as one in Settings. `members` are spec names; the settings keys behind them stay what they were (`enabled_plugins` for core plugins, `run_extended_plugins` for the extended ones,… |
| `class PluginRegistry` | class | The set of plugin specs and bundles of one engine with lookup helpers. |
| `PluginRegistry.__init__(specs, bundles)` | method | Builds the lookup tables from the specs and bundles. |
| `PluginRegistry.plugin_names_used_by(rule_id)` | method | Result names of the plugin runs whose output the given rule reads. |
| `PluginRegistry.names(group)` | method | Names of the plugins in a group. |
| `PluginRegistry.get(name)` | method | The spec of a plugin by name (error if unknown). |
| `PluginRegistry.find(name)` | method | The spec of a plugin by name, or None. |
| `PluginRegistry.known(name)` | method | True when the name is a known plugin. |
| `PluginRegistry.required_names()` | method | The plugins that always run. |
| `PluginRegistry.optional_choices()` | method | The opt-in plugins as (id, label, warning, members) for the Settings page. |
| `PluginRegistry.bundle_of(spec_name)` | method | The Settings bundle a plugin belongs to. |
| `PluginRegistry._member_on(spec, settings)` | method | Whether a plugin is switched on in the given settings. |
| `PluginRegistry.bundle_state(bundle, settings)` | method | Whether a bundle is fully on, fully off or partly on in the given settings. |
| `PluginRegistry.apply_bundles(settings, choices)` | method | Write the Settings checkboxes back into the settings keys. `choices`: bundle id -> `"on"` / `"off"` / `"keep"` (leave members as they are). |

### `app/analysis/rows.py`  (23 lines)

**Purpose:** Helpers that flatten the nested JSON tree Volatility prints into simple rows (the same for every operating system).

| Name | Kind | Purpose |
|---|---|---|
| `flatten_rows(rows)` | function | Flatten Volatility's `__children` tree into a list (idempotent, iterative). |

### `app/analysis/story.py`  (111 lines)

**Purpose:** Builds "the story of one process": every fact known about it placed on one clock, without any Qt code.

| Name | Kind | Purpose |
|---|---|---|
| `class StoryItem` | class | One line of a process story (time, kind, text, severity). |
| `_relative(moment, start)` | function | Seconds between two moments, or None. |
| `build(result, pid)` | function | The ordered story of process `pid` (empty when the process is not in the result). |
| `describe_offset(seconds)` | function | Formats a time relative to the process start such as "+12 s" or "-3 min". |
| `display_time(item)` | function | A story item's time formatted for display. |

### `app/analysis/volatility_runner.py`  (546 lines)

**Purpose:** Finds Volatility 3 reliably and runs plugins as a separate process with timeouts, progress, JSON parsing and clear failure messages.

| Name | Kind | Purpose |
|---|---|---|
| `class VolatilityTool` | class | A located Volatility command (executable/script, version, description). |
| `_creation_flags()` | function | Windows flag so no console window flashes when Volatility starts. |
| `_env()` | function | The environment for Volatility (UTF-8 output). |
| `_python_for_scripts()` | function | A real Python interpreter to run vol.py with (sys.executable is the app itself when frozen). |
| `_script_tool(path)` | function | Builds a tool from a vol.py script path. |
| `find_volatility(custom_path)` | function | Find Volatility 3. Order: settings path, the active environment, PATH, vol.py, python module. |
| `global_args(settings)` | function | Options placed before `-f` on every Volatility 3 command. `--offline` is always there: MemoryGraph never connects to the internet, so a missing symbol file fails at once with Volatility's own message instead of waiting for… |
| `check_tool(tool, timeout)` | function | Run `vol -h` once: proves Volatility starts, and reads its version. |
| `parse_plugin_list(help_text)` | function | Plugin names (`windows.netscan`) listed in `vol -h`; None when the list cannot be read. |
| `plugin_available(tool, plugin)` | function | True/False when the installed Volatility's plugin list is known, None when it is not. |
| `resolve_plugin_name(tool, preferred, alternatives)` | function | Chooses the plugin name to run: the preferred one unless the installed Volatility only has a renamed alternative. |
| `version_key(text)` | function | Turns a version text into a comparable tuple. |
| `version_note(tool)` | function | A factual remark when the installed Volatility differs from the release MemoryGraph is tested with. |
| `describe_tool(tool)` | function | Text describing a tool and its version. |
| `compatibility_report(tool, plugin_names)` | function | Multi-line text for the Settings → Test button: version, version note and which requested plugins exist. |
| `describe_os(info_plugin)` | function | One line about the image's Windows version, taken from `windows.info` ('' when unavailable). |
| `_tail(text, lines)` | function | The last few non-empty lines of some output (for error messages). |
| `classify_failure(stderr, plugin)` | function | Reason for a failure, only when Volatility's own output says so ('' = no known pattern, show the output as it is). |
| `explain_failure(stderr, returncode, plugin, tool, os_info)` | function | Readable failure text. The last line is always Volatility's own last output line (or the reason when there is none), because summaries elsewhere in the GUI show only the last line. |
| `run_plugin(tool, dump_path, plugin, idle_timeout, max_seconds, cancel, on_progress, os_info, volatility_plugin, args, alternatives)` | function | Runs one plugin (timeouts, progress, cancel) and returns a PluginResult; never raises except for cancellation. |
| `_kill(proc)` | function | Terminates a Volatility process and its children. |
| `_read_rows(path)` | function | Return `(rows, raw_text_if_unparsed, parse_error)`. |
| `_rows_from(raw)` | function | Extracts the row list from Volatility's JSON output. |


---

## app/analysis/indicators - shared rule helpers

*Rule base class, scoring, correlation and the second-source requirement.*

### `app/analysis/indicators/__init__.py`  (1 lines)

**Purpose:** Package of the rule helpers shared by every operating system (base class, scoring, correlation, corroboration).

*(no classes or functions)*

### `app/analysis/indicators/base.py`  (150 lines)

**Purpose:** The rule base class and the small helpers every rule uses to read normalized evidence (names, IP classification, plugin rows, parent lookup).

| Name | Kind | Purpose |
|---|---|---|
| `class IndicatorRule` | class | Base class. A rule inspects *normalized* evidence and returns investigation leads. |
| `IndicatorRule.evaluate(result)` | method | Abstract: a rule inspects an AnalysisResult and returns findings. |
| `IndicatorRule.make(title, severity, summary, reasons, evidence, source_plugins, process, related_processes, confidence, evidence_items)` | method | Builds an Indication with the rule's id, name, ATT&CK tags and score filled in. |
| `name(value)` | function | Cleans a text value (None -> "", stripped). |
| `lower(value)` | function | Cleaned, lower-case text. |
| `proc_name(p)` | function | A process's lower-case name. |
| `display(p)` | function | "name (PID n)" text of a process. |
| `endpoint_host(value)` | function | The host part of an endpoint text (strips brackets and ports). |
| `is_private_or_local(host)` | function | True for private, loopback, link-local, reserved and test addresses. |
| `is_public_ip(host)` | function | True for a routable public IP address. |
| `process_map(result)` | function | Dictionary pid -> Process. |
| `children_of(result, pid)` | function | The child processes of a PID. |
| `active(result)` | function | Processes that were still running at capture time (not exited). |
| `plugin_rows(result, plugin_name)` | function | The rows of a completed plugin in the result. |
| `plugin_rows_indexed(result, plugin_name)` | function | Like plugin_rows but also yields each row's position in the plugin output, which is what evidence provenance points at. |
| `plugin_completed(result, plugin_name)` | function | True when the plugin ran successfully and produced rows (an empty or failed plugin gives a rule nothing to compare). |
| `row_value(row, *keys, default)` | function | Reads a field from a plugin row, tolerant to differences in key spelling. |
| `pid_from_row(row)` | function | The PID of a plugin row. |
| `process_for_pid(result, pid)` | function | The Process with a PID, or None. |
| `parent_of(result_map, proc)` | function | Parent process, ignoring PID reuse (a 'parent' created after its child is not its parent). |

### `app/analysis/indicators/correlation.py`  (74 lines)

**Purpose:** Combines independent findings about the same process into one stronger CORR-001 finding without replacing them.

| Name | Kind | Purpose |
|---|---|---|
| `correlate(result, findings)` | function | Combine independent findings; never replaces them. |

### `app/analysis/indicators/corroboration.py`  (65 lines)

**Purpose:** The second-source rule: a High finding that only one plugin supports is lowered to Medium until another plugin agrees.

| Name | Kind | Purpose |
|---|---|---|
| `_sources(finding)` | function | The set of plugins a finding's evidence came from. |
| `second_source(finding, others)` | function | Other findings about the same process (or, for a kernel finding, the same kernel area) that come from different plugins. |
| `require_second_source(findings)` | function | Lower the single-plugin High findings that no second plugin supports to Medium (in place; returns the lowered ones). |

### `app/analysis/indicators/scoring.py`  (85 lines)

**Purpose:** How severity and confidence become a score, and how findings add up per process.

| Name | Kind | Purpose |
|---|---|---|
| `is_active(indication)` | function | False for findings the investigator marked as false positive or a known-good baseline suppressed. |
| `active_findings(indications)` | function | The findings that are not false positives or suppressed by a baseline. |
| `severity_rank(severity)` | function | A number for sorting severities (High > Medium > Low). |
| `finding_score(severity, confidence)` | function | Score of one finding from its severity and confidence. |
| `max_severity(severities)` | function | The highest severity of a group. |
| `class ProcessRisk` | class | The combined risk of one process: score, severity, finding count, rule ids. |
| `risk_by_pid(indications)` | function | Aggregate findings per process: one score, one severity, the contributing rule ids. |


---

## app/engines - the engine interface

*How an operating system plugs in: the Engine interface and the registry of engines.*

### `app/engines/__init__.py`  (41 lines)

**Purpose:** The engine registry: finds the engine (Windows or Linux) for a setting, a saved result or an id.

| Name | Kind | Purpose |
|---|---|---|
| `get_engine(os_id)` | function | The engine with this id (an unknown or empty id gives the Windows engine, which is what every older saved investigation was made by). |
| `all_engines()` | function | Every available engine. |
| `engine_for(result)` | function | The engine that analysed a given result (by its target OS). |
| `engine_for_settings(settings)` | function | The engine chosen in the settings. |

### `app/engines/base.py`  (161 lines)

**Purpose:** The engine interface: every operating-system-specific thing the windows, views and pipeline ask an engine for, with its capabilities, words and view list.

| Name | Kind | Purpose |
|---|---|---|
| `class EngineNotImplemented(MemoryGraphError)` | class | Raised by a part of an engine that has not been written yet. The message names the engine and the function, so the window can say exactly what is missing. |
| `EngineNotImplemented.__init__(engine, function)` | method | Builds the "this engine does not implement X yet" message. |
| `class ViewSpec` | class | One entry of the dashboard's navigation. `available=False` shows the entry with a page that says why (instead of hiding it), so a missing part is visible. |
| `class Capabilities` | class | What the operating system has, so the windows show only what applies (a Linux image has no registry). |
| `class Terms` | class | The words the windows use for things that have another name on this operating system. |
| `class Engine` | class | Base class of an operating-system engine. Subclasses fill in the attributes and override the methods (the defaults raise EngineNotImplemented). |
| `Engine.plugin_registry()` | method | The engine's plugin registry module/object: `REGISTRY`, `BUNDLES`, `names`, `get`, `find`, `optional_choices`, `bundle_state`, `apply_bundles`. |
| `Engine.default_settings()` | method | The values of `os_settings_keys` a fresh profile of this operating system starts with. |
| `Engine.make_provider(settings)` | method | An object with `run(dump_path, progress, plugin_event, cancel) -> AnalysisResult` and `rerun(result, names, progress, plugin_event, cancel)`. |
| `Engine.make_dumper(dump_path, volatility_path, global_args)` | method | An object that dumps processes, modules, files and memory regions out of the image (`dump_process`, `dump_dlls`, `dump_handles`, `dump_malfind_pages` ...). |
| `Engine.normalize(dump_path, plugins)` | method | Converts plugin results into an AnalysisResult (processes, connections, regions, system info) without findings. |
| `Engine.build_timeline(result)` | method | The `TimelineEvent` list of the result (process starts, connections, module loads, execution history ...). |
| `Engine.apply_timeline_severity(result)` | method | Mark each timeline event with the highest severity of the findings of its process. |
| `Engine.data_quality_warnings(result)` | method | Things about the image that limit what the rules can say (partly readable lists, an acquisition that was still running ...). |
| `Engine.describe_os(result)` | method | One line naming the operating system of the image (`Windows 10 (x64, build 15063)`). |
| `Engine.indicator_engine(iocs)` | method | An object with `evaluate(result) -> list[Indication]` and `errors`; `iocs` is the investigator's own indicator set. |
| `Engine.rule_name(rule_id)` | method | Abstract: the readable name of a rule id. |
| `Engine.rule_catalog()` | method | The rules that exist, as a dictionary rule id -> object with name and description. |
| `Engine.attack_for(rule_id)` | method | The MITRE ATT&CK techniques the rule is commonly associated with (local data, nothing is fetched). |
| `Engine.refresh_image_hash_findings(result, iocs)` | method | Match the stored process-image hashes against the IOC list (rule IOC-007); returns how many findings that gives. |
| `Engine.demo_result()` | method | A made-up AnalysisResult for the "Show a demo investigation" button (only when the engine has a demo). |
| `Engine.is_risky_path(path)` | method | A folder code should not normally run from (temporary, downloads, world-writable). The views use it to colour module paths; False when unknown. |
| `Engine.is_trusted_path(path)` | method | A folder system files normally live in; False when unknown. |
| `Engine.view_specs()` | method | The dashboard's navigation, in order. |
| `Engine.__repr__()` | method | Short text for debugging. |


---

## app/engines/linux - the Linux engine (skeleton)

*Linux entry point and the demo investigation.*

### `app/engines/linux/__init__.py`  (132 lines)

**Purpose:** The Linux engine skeleton: every function the interface needs exists and says "not implemented yet"; the words, capabilities, views and demo are real.

| Name | Kind | Purpose |
|---|---|---|
| `class LinuxEngine(Engine)` | class | The Linux engine: connects the interface to the Linux folders and exposes the demo investigation. |
| `LinuxEngine.plugin_registry()` | method | The Linux plugin list. |
| `LinuxEngine.default_settings()` | method | The Linux defaults (no plugins chosen yet, no symbol folders). |
| `LinuxEngine.make_provider(settings)` | method | Creates the Linux provider (skeleton). |
| `LinuxEngine.make_dumper(dump_path, volatility_path, global_args)` | method | Creates the Linux dumper (skeleton). |
| `LinuxEngine.normalize(dump_path, plugins)` | method | Turns plugin rows into a result (skeleton). |
| `LinuxEngine.build_timeline(result)` | method | Builds the timeline (skeleton). |
| `LinuxEngine.apply_timeline_severity(result)` | method | Colours timeline events by findings (skeleton). |
| `LinuxEngine.data_quality_warnings(result)` | method | Warnings about limits of the image (skeleton). |
| `LinuxEngine.describe_os(result)` | method | A text describing the kernel/distribution (skeleton). |
| `LinuxEngine.indicator_engine(iocs)` | method | Creates the Linux rule engine (skeleton). |
| `LinuxEngine.rule_name(rule_id)` | method | The name of a Linux rule (real for the demo's rules). |
| `LinuxEngine.rule_catalog()` | method | The Linux rule catalogue (demo rules). |
| `LinuxEngine.attack_for(rule_id)` | method | ATT&CK techniques of a Linux rule (skeleton). |
| `LinuxEngine.refresh_image_hash_findings(result, iocs)` | method | Recomputes hash-based findings (skeleton). |
| `LinuxEngine.demo_result()` | method | The demo investigation (made-up data): lets every view be seen before the engine is written. Defined in `demo.py`; delete that file and `capabilities.demo` to remove it. |
| `LinuxEngine.is_risky_path(path)` | method | True for risky Linux directories such as /tmp or /dev/shm. |
| `LinuxEngine.is_trusted_path(path)` | method | True for trusted Linux directories such as /usr/bin. |
| `LinuxEngine.view_specs()` | method | Like Windows, minus the Registry (Linux has none), and with placeholders where a view needs engine code that does not exist yet. |

### `app/engines/linux/_todo.py`  (10 lines)

**Purpose:** The one helper that makes every Linux placeholder fail the same readable way.

| Name | Kind | Purpose |
|---|---|---|
| `todo(function)` | function | Raises the "not implemented yet" error naming the Linux function that still has to be written; every placeholder body is `return todo("name")`. |

### `app/engines/linux/demo.py`  (238 lines)

**Purpose:** Builds the made-up Linux "demo investigation" (host web-prod-01) so every view can be seen before the Linux engine exists.

| Name | Kind | Purpose |
|---|---|---|
| `_t(day, hour, minute, second)` | function | Builds a timestamp text on the demo's capture day. |
| `_process(pid, ppid, name, path, cmdline, user, created, threads, exited, hidden, session)` | function | Creates a demo Process with its fields filled. |
| `_libs(proc, *libs)` | function | Adds demo libraries to a process. |
| `_connection(procs, pid, proto, laddr, lport, raddr, rport, state, when)` | function | Creates a demo connection and attaches it to its process. |
| `_finding(rule_id, severity, title, summary, reasons, evidence, pid, process, plugins, confidence, category)` | function | Creates a demo finding with the right rule text. |
| `build()` | function | Builds the whole demo AnalysisResult: processes, connections, findings, timeline and raw plugin rows. |


---

## app/engines/linux/analysis - Linux evidence (skeleton)

*Placeholders for Linux collection, normalization, timeline and dumping.*

### `app/engines/linux/analysis/__init__.py`  (2 lines)

**Purpose:** Linux engine, analysis half (collection, normalization, OS profile, timeline, dumping): placeholder package.

*(no classes or functions)*

### `app/engines/linux/analysis/compare.py`  (10 lines)

**Purpose:** Linux comparison of two investigations (skeleton).

| Name | Kind | Purpose |
|---|---|---|
| `compare(current, reference)` | function | Placeholder: compares a result with a reference. |

### `app/engines/linux/analysis/dumper.py`  (33 lines)

**Purpose:** Linux dumping of files and process images out of the image (skeleton).

| Name | Kind | Purpose |
|---|---|---|
| `class LinuxDumper` | class | Placeholder for dumping process images and libraries. |
| `LinuxDumper.__init__(dump_path, volatility_path, global_args)` | method | Remembers the image path and Volatility settings. |
| `LinuxDumper.dump_process(pid, output_dir)` | method | The process image / its mappings (`linux.proc.Maps --dump`, `linux.elfs --dump`). |
| `LinuxDumper.dump_dlls(pid, output_dir)` | method | The shared libraries of a process (the window calls them "Libraries"). |
| `LinuxDumper.dump_handles(pid, output_dir)` | method | The files the process has open (`linux.lsof`, `linux.pagecache.Files --dump`). |
| `LinuxDumper.dump_malfind_pages(pid, output_dir)` | method | Executable anonymous regions (`linux.malfind --dump`). |
| `LinuxDumper.dump_all_process_images(output_dir)` | method | Placeholder: dump every process executable. |

### `app/engines/linux/analysis/files.py`  (15 lines)

**Purpose:** Linux back end of the Files view (skeleton; the view shows a "not implemented yet" page).

| Name | Kind | Purpose |
|---|---|---|
| `entries_from_rows(rows)` | function | File entries from `linux.pagecache.Files` / `linux.lsof` rows. |

### `app/engines/linux/analysis/normalizer.py`  (18 lines)

**Purpose:** Linux conversion of plugin rows into an AnalysisResult (skeleton).

| Name | Kind | Purpose |
|---|---|---|
| `normalize(dump_path, plugins)` | function | Placeholder: normalize Linux plugin output. |

### `app/engines/linux/analysis/os_profile.py`  (50 lines)

**Purpose:** Linux kernel/distribution identification and the symbol table it needs (skeleton).

| Name | Kind | Purpose |
|---|---|---|
| `class LinuxProfile` | class | The facts the engine needs about the image's kernel (filled from the `banners.Banners` row). |
| `LinuxProfile.known()` | method | True once the kernel is known. The generic parts of MemoryGraph use `known`, `version` and `short_name` of any OS profile. |
| `LinuxProfile.version()` | method | A comparable `(major, minor)` of the kernel, like Windows' NT version: plugins can say which kernels they exist for. |
| `LinuxProfile.short_name()` | method | Placeholder: short name of the Linux version. |
| `parse_banner(text)` | function | Reads a Linux kernel banner text ("Linux version 5.15.0-91-generic ...") into a LinuxProfile. |
| `from_rows(rows)` | function | The profile from the rows of `banners.Banners`. |
| `from_result(result)` | function | Placeholder: read the profile from a result. |
| `describe_os(result)` | function | One line for the window header: `Ubuntu 22.04 (kernel 5.15.0-91-generic, x86_64)`. |

### `app/engines/linux/analysis/plugin_registry.py`  (74 lines)

**Purpose:** The Linux plugins and Settings groups (placeholder data to edit).

*(no classes or functions)*

### `app/engines/linux/analysis/provider.py`  (41 lines)

**Purpose:** Linux provider that will run the Volatility 3 linux.* plugins (skeleton).

| Name | Kind | Purpose |
|---|---|---|
| `class LinuxProvider` | class | Placeholder provider. |
| `LinuxProvider.__init__(settings)` | method | Remembers the settings. |
| `LinuxProvider.run(dump_path, progress, plugin_event, cancel)` | method | Run the enabled plugins on `dump_path` and return the normalized, judged AnalysisResult (`result.target_os == "linux"`). |
| `LinuxProvider.rerun(result, names, progress, plugin_event, cancel)` | method | Run `names` (default: the plugins of `result` that failed) again and rebuild the analysis with the merged plugin results. |

### `app/engines/linux/analysis/quality.py`  (12 lines)

**Purpose:** Linux data-quality warnings (skeleton).

| Name | Kind | Purpose |
|---|---|---|
| `data_quality_warnings(result)` | function | Placeholder: warnings about what limits the rules. |

### `app/engines/linux/analysis/timeline.py`  (17 lines)

**Purpose:** Linux timeline builder (skeleton).

| Name | Kind | Purpose |
|---|---|---|
| `build_timeline(result)` | function | Placeholder: build the Linux timeline. |
| `apply_severity(result)` | function | Give every timeline event the highest severity among the findings of its process. |


---

## app/engines/linux/indicators - Linux rules (skeleton)

*Placeholders for Linux rules, baselines and helpers.*

### `app/engines/linux/indicators/__init__.py`  (7 lines)

**Purpose:** Linux rules half of the engine (skeleton package).

*(no classes or functions)*

### `app/engines/linux/indicators/attack.py`  (18 lines)

**Purpose:** Linux ATT&CK mapping of rules (skeleton).

| Name | Kind | Purpose |
|---|---|---|
| `attack_for(rule_id)` | function | The techniques of a rule, as objects with `id`, `name` and `info` (tactics, summary, what to look for). |
| `technique_info(technique_id)` | function | Placeholder: description of a technique. |

### `app/engines/linux/indicators/baseline.py`  (15 lines)

**Purpose:** Tables of what is normal on Linux (empty, to be filled).

*(no classes or functions)*

### `app/engines/linux/indicators/engine.py`  (40 lines)

**Purpose:** The Linux rule engine (skeleton) and the rule catalogue of the demo.

| Name | Kind | Purpose |
|---|---|---|
| `rule_name(rule_id)` | function | The display name of a rule; the demo's name (`demo.RULE_NAMES`) or the id itself until the rule exists. A real rule in `RULE_CATALOG` always wins. |
| `rule_catalog()` | function | The Linux rules that exist (for now the demo's), with names and descriptions. |
| `class IndicatorEngine` | class | Placeholder rule engine. |
| `IndicatorEngine.__init__(rules, iocs)` | method | Takes the rule list and IOC set. |
| `IndicatorEngine.evaluate(result)` | method | Placeholder: run the rules over a result. |

### `app/engines/linux/indicators/helpers.py`  (17 lines)

**Purpose:** Linux helpers for the rules (path classes such as risky/trusted directories).

| Name | Kind | Purpose |
|---|---|---|
| `is_risky_dir(path)` | function | A directory code should not normally run from (`/tmp`, `/dev/shm`, `/var/tmp` ...). Uses `baseline.HIGH_RISK_DIR_FRAGMENTS`; False while that table is empty. |
| `is_trusted_dir(path)` | function | A directory system programs normally live in. Uses `baseline.TRUSTED_DIR_FRAGMENTS`; False while that table is empty. |


---

## app/engines/linux/indicators/rules - Linux rule families (empty)

*Where the Linux rule modules will go.*

### `app/engines/linux/indicators/rules/__init__.py`  (15 lines)

**Purpose:** Package where Linux rule families will live (empty skeleton).

*(no classes or functions)*


---

## app/engines/windows - the Windows engine

*The complete Windows engine's entry point.*

### `app/engines/windows/__init__.py`  (107 lines)

**Purpose:** The complete Windows engine: connects the interface to the Windows analysis and rule folders (plugins, normalizer, timeline, rules, ATT&CK, known-good lists).

| Name | Kind | Purpose |
|---|---|---|
| `class WindowsEngine(Engine)` | class | The Windows engine class (XP/2003 to Windows 11). |
| `WindowsEngine.plugin_registry()` | method | The Windows plugin list. |
| `WindowsEngine.default_settings()` | method | The Windows defaults for plugin choices and symbol folders. |
| `WindowsEngine.make_provider(settings)` | method | Creates the Volatility 3 provider that collects the Windows evidence. |
| `WindowsEngine.make_dumper(dump_path, volatility_path, global_args)` | method | Creates the dumper for process images, DLLs, malfind pages and files. |
| `WindowsEngine.normalize(dump_path, plugins)` | method | Turns plugin rows into a normalized AnalysisResult. |
| `WindowsEngine.build_timeline(result)` | method | Builds the investigation timeline. |
| `WindowsEngine.apply_timeline_severity(result)` | method | Colours timeline events by the findings of their process. |
| `WindowsEngine.data_quality_warnings(result)` | method | Warnings about image limits (e.g. partial page tables). |
| `WindowsEngine.describe_os(result)` | method | The Windows version text of the image. |
| `WindowsEngine.indicator_engine(iocs)` | method | Creates the Windows rule engine. |
| `WindowsEngine.rule_name(rule_id)` | method | The readable name of a Windows rule id. |
| `WindowsEngine.rule_catalog()` | method | The catalogue of all Windows rules (id, name, description). |
| `WindowsEngine.attack_for(rule_id)` | method | ATT&CK techniques of a rule. |
| `WindowsEngine.refresh_image_hash_findings(result, iocs)` | method | Re-evaluates IOC-007 (process image hashes against the IOC list). |
| `WindowsEngine.demo_result()` | method | The Windows engine has no demo (its start window offers real images; `capabilities.demo` is False). |
| `WindowsEngine.is_risky_path(path)` | method | True for directories malware often runs from (Temp, AppData, Downloads...). |
| `WindowsEngine.is_trusted_path(path)` | method | True for trusted directories (System32, Program Files...). |
| `WindowsEngine.view_specs()` | method | The list of dashboard views the Windows engine offers. |


---

## app/engines/windows/analysis - Windows evidence

*Collecting, normalizing and presenting Windows evidence: plugins, provider, normalizer, timeline, dumping, registry, comparison, Volatility 2.*

### `app/engines/windows/analysis/__init__.py`  (1 lines)

**Purpose:** Package of everything that collects and normalizes Windows evidence; exposes the plugin registry.

*(no classes or functions)*

### `app/engines/windows/analysis/compare.py`  (359 lines)

**Purpose:** Compares two investigations (two images, or one system at two moments): new, gone and changed processes, modules, connections, findings and plugin rows.

| Name | Kind | Purpose |
|---|---|---|
| `class DiffRow` | class | One difference between two investigations (section, change type, key, current/reference description). |
| `class Comparison` | class | The result of a comparison: the rows per section, counts and truncation notes. |
| `Comparison.counts()` | method | How many new / gone / changed rows each section has. |
| `Comparison.all_rows()` | method | Every difference in display order. |
| `_clip(rows, section, comparison)` | function | Cuts a section to the maximum number of rows and notes how many were dropped. |
| `_process_start_key(p)` | function | Matching key "same boot": name + start time. |
| `_process_image_key(p)` | function | Matching key "different boot": name + image path. |
| `same_boot_fraction(current, reference)` | function | Share of the reference's processes that also exist, with the same start time, in the current investigation (0..1). |
| `suggest_mode(current, reference)` | function | Chooses "same boot" when many processes keep their start time between the two images, otherwise "different boot". |
| `_describe(p)` | function | One-line description of a process for a difference row. |
| `_label(result)` | function | Name and capture time of an investigation for headings. |
| `_processes(current, reference, mode, out)` | function | Process rows, and `{current pid: reference pid}` for the processes that exist in both (for the module / memory sections). |
| `_modules(current, reference, mode, paired, out)` | function | Differences in the loaded modules of matched processes. |
| `_connections(result)` | function | All connections of a result. |
| `_connection_key(conn)` | function | Matching key of a connection (listening sockets match by process and port). |
| `_network(current, reference)` | function | Differences in network connections. |
| `_findings(current, reference)` | function | Differences in findings between the two results. |
| `_memory(current, reference, paired)` | function | malfind regions by address in processes that exist in both images (only meaningful for the same boot). |
| `_row_identity(plugin_name)` | function | Which columns identify a row of a given plugin. |
| `_identity_text(plugin_name, row, columns)` | function | The identifying text of a plugin row. |
| `_plugin_rows(current, reference)` | function | Differences in the raw rows of the plugins both runs completed. |
| `compare(current, reference, mode)` | function | Differences between the open investigation and a reference. `mode` defaults to suggest_mode. |
| `export_csv(comparison, path)` | function | Write every difference to a CSV file (Section, Change, Item, Detail, PID); returns the number of rows. |

### `app/engines/windows/analysis/dumper.py`  (174 lines)

**Purpose:** Dumps things out of the image with Volatility: process executables, DLLs, injected pages, handle files, file objects; hashes what it writes.

| Name | Kind | Purpose |
|---|---|---|
| `class DumpedFile` | class | One file written by a dump (path, size, SHA-256, MD5, error). |
| `DumpedFile.readable()` | method | True when the file was written and hashed without error. |
| `snapshot_dir(directory)` | function | The files directly inside a folder with their size and time, to see which files a dump added. |
| `hash_file(path)` | function | SHA-256 and MD5 of a file, read in blocks. |
| `hash_new_files(directory, before)` | function | Hash the files that appeared (or were rewritten) since `before` was taken. |
| `write_manifest(directory, files, plugin, pid, source_image, command)` | function | Append one row per dumped file to `memorygraph_hashes.csv` (created with a header on first use). |
| `class VolatilityDumper` | class | Runs the Volatility dump plugins for one image. |
| `VolatilityDumper.__init__(dump_path, volatility_path, global_args)` | method | Remembers the image, the Volatility path and extra arguments. |
| `VolatilityDumper.find_executable(custom_path)` | method | Kept for backward compatibility: path of the Volatility launcher. |
| `VolatilityDumper._run(plugin, pid, output_dir, *extra, timeout)` | method | Runs one dump plugin for a PID into a folder and collects the new files with their hashes. |
| `VolatilityDumper.dump_process(pid, output_dir)` | method | Dumps a process's executable. |
| `VolatilityDumper.dump_all_process_images(output_dir)` | method | Dump the executable of every process in one run (`windows.pslist --dump` without a PID filter). |
| `VolatilityDumper.dump_dlls(pid, output_dir)` | method | Dumps a process's DLLs. |
| `VolatilityDumper.dump_handles(pid, output_dir)` | method | Dumps the files a process has open. |
| `VolatilityDumper.dump_malfind_pages(pid, output_dir)` | method | Dumps a process's suspicious executable memory pages. |
| `VolatilityDumper.dump_file_objects(offsets, output_dir)` | method | Dump the files found by filescan (`Offset` = the FILE_OBJECT's address as filescan prints it, a kernel virtual address) with ONE windows.dumpfiles run. |
| `VolatilityDumper.dump_file_object(offset, output_dir)` | method | Dumps one file object by memory offset. |

### `app/engines/windows/analysis/file_report.py`  (316 lines)

**Purpose:** Read-only report about a file dumped from memory: type, hashes, entropy, PE headers/sections/imports/exports and interesting strings.

| Name | Kind | Purpose |
|---|---|---|
| `class Section` | class | One section of a PE file (name, sizes, flags, entropy). |
| `class PEInfo` | class | The parsed PE header information (machine, subsystem, timestamp, sections, imports, exports). |
| `class FileReport` | class | The complete report of one file. |
| `shannon_entropy(data)` | function | Bits per byte (0 = constant, 8 = random/compressed/encrypted). |
| `detect_type(data)` | function | Recognizes the file type from its first bytes (PE, ELF, script, archive...). |
| `extract_strings(data, limit)` | function | Printable ASCII and UTF-16LE strings of at least 6 characters, in file order, without duplicates. |
| `_first(pattern, strings, limit)` | function | First strings matching a pattern. |
| `parse_pe(data)` | function | Headers, sections, imports and exports of a PE file; None when `data` is not a PE. Tolerates truncated / zero-filled dumps. |
| `_read_imports(data, info, to_offset, read_cstring, plus, rva)` | function | Reads the import table of a PE file. |
| `_read_exports(data, info, to_offset, read_cstring, rva)` | function | Reads the export table of a PE file. |
| `build_report(path, max_bytes)` | function | Hash the whole file and analyse its first `max_bytes`. |

### `app/engines/windows/analysis/fileindex.py`  (277 lines)

**Purpose:** Builds a folder tree over the file objects windows.filescan found in memory (no Qt).

| Name | Kind | Purpose |
|---|---|---|
| `class FileEntry` | class | One file object found by filescan (device, path, offset, access). |
| `FileEntry.name()` | method | The file name. |
| `FileEntry.folder()` | method | The folder part of the path. |
| `FileEntry.extension()` | method | The lower-case extension. |
| `FileEntry.full_name()` | method | The full display name including the device (raw text for damaged names). |
| `FileEntry.target()` | method | Stable key for notes / bookmarks (device + lower-case path; the offset changes between dumps of the same system). |
| `split_name(raw)` | function | Splits a filescan name into its device and path parts. |
| `is_damaged(device, path)` | function | A name that cannot be a path: it does not start with a backslash (no device and no root), or it holds control / replacement characters. filescan reads names out of pool memory; freed or half-overwritten objects leave fragments… |
| `entries_from_rows(rows)` | function | File entries from windows.filescan rows (rows without a name or a usable offset are skipped). Damaged names go to one pseudo volume, each as a single flat name. |
| `flags_for(entry)` | function | Reasons this file deserves a look (the same ones rule FILE-001 reports), or []. |
| `class Folder` | class | A folder node of the tree with files and subfolders. |
| `Folder.path()` | method | The folder's path without the device. |
| `Folder.total()` | method | How many files are in the folder and below (cached). |
| `Folder.subfolders()` | method | Child folders, sorted (damaged names last). |
| `Folder.all_files()` | method | Every file in the folder and below. |
| `class FileIndex` | class | All entries plus the tree: roots are devices (`HarddiskVolume2`), below them the folders. |
| `FileIndex.__init__(entries)` | method | Builds the device/folder tree from the entries and notes which folders hold flagged files. |
| `FileIndex._device(device)` | method | The root node of a device, created when needed. |
| `FileIndex.drive_hint(folder)` | method | "C:" for the device that holds \Windows\System32 (the system volume), empty for others. |
| `FileIndex.label(folder)` | method | Name shown for a folder: the volume gets its drive letter when it can be told (`HarddiskVolume2 (C:)`). |
| `FileIndex.breadcrumb(folder)` | method | The chain of folders from the root to a folder. |
| `FileIndex.resolve(text)` | method | The folder a typed address names: `This image › HarddiskVolume2 (C:) › Windows`, `HarddiskVolume2\Windows`, `C:\Windows` or just `\Windows\System32` (tried on every volume, the system volume first). None when no such folder… |
| `FileIndex.folder_for(entry)` | method | The folder node an entry belongs to, creating it on the way. |
| `FileIndex.search(text, scope)` | method | Entries in `scope` (default: everything) whose path contains every word of `text` (case-insensitive). |
| `index_dump_dir(directory)` | function | Lists the files a dumpfiles run wrote, grouped by the file object they belong to. |
| `dump_files_for(directory, offset)` | function | The dumped files (cache kind, path) of one file object. |

### `app/engines/windows/analysis/image_hashes.py`  (20 lines)

**Purpose:** Re-evaluates the IOC-007 rule (hashes of dumped process images against the IOC list) on its own after "Hash all process images".

| Name | Kind | Purpose |
|---|---|---|
| `refresh_image_hash_findings(result, iocs)` | function | Re-evaluate only rule IOC-007; returns the number of IOC-007 findings now in `result` (the rest of the analysis is left as it is). |

### `app/engines/windows/analysis/injection.py`  (172 lines)

**Purpose:** Builds process-injection chains: the evidence about one process from several plugins as one story (no Qt).

| Name | Kind | Purpose |
|---|---|---|
| `class Step` | class | One step of an injection chain (kind, text, source). |
| `class Chain` | class | A chain of steps about one process. |
| `Chain.kinds()` | method | The set of step kinds in the chain. |
| `Chain.score()` | method | Distinct kinds of evidence, weighted by the worst severity of each (High counts 3, Medium 2, Low 1). |
| `access_names(mask)` | function | Names of the access rights in a process-handle mask. |
| `process_access_can_inject(mask)` | function | Write into the process's memory (VM_OPERATION + VM_WRITE), start a thread in it, or everything. |
| `_handles_into(result)` | function | Groups the raw handle rows by the process they point to (holder, kind, access mask). |
| `build_chains(result)` | function | Chains of every process that has at least one memory-level sign, most evidence first. |
| `parent_line(result, pid)` | function | A text describing a process's parent. |

### `app/engines/windows/analysis/known_good.py`  (133 lines)

**Purpose:** Known-good module lists: which DLLs a program normally loads on a given Windows (plain JSON files made from a clean image).

| Name | Kind | Purpose |
|---|---|---|
| `folder()` | function | The folder holding the known-good lists. |
| `_base(path)` | function | The file name part of a normalized path. |
| `mapped_images(result)` | function | The lower-case image names each process has mapped according to dlllist, ldrmodules and vadinfo (file-backed images only). |
| `build(result, name)` | function | The known-good list of `result` (every module every program of this system had), ready to be saved. |
| `save(data, path)` | function | Writes a known-good list to a file. |
| `install(path)` | function | Copy a known-good file into the library; returns `(name, modules)`. Raises ValueError for a file that is not one. |
| `class KnownGood` | class | The merged lists that apply to one Windows version. |
| `KnownGood.__init__(lists)` | method | Builds the lookup from the loaded lists. |
| `KnownGood.__bool__()` | method | True when any list is loaded. |
| `KnownGood.knows(program, module)` | method | True when a program normally loads a module. |
| `_lists()` | function | Loads (and caches) every list in the folder. |
| `for_result(result)` | function | The installed lists made on the same Windows as `result` (same NT version and 32/64-bit; an unknown version matches nothing). |

### `app/engines/windows/analysis/normalizer.py`  (415 lines)

**Purpose:** Turns raw Volatility 3 plugin rows into the normalized models (processes, DLLs, connections, regions, handles) with provenance of each field.

| Name | Kind | Purpose |
|---|---|---|
| `_key(name)` | function | Normalizes a column name (lower-case, no spaces/underscores). |
| `class Row` | class | Case/space/underscore-insensitive access to one plugin row. |
| `Row.__init__(raw)` | method | Wraps a raw row with tolerant column lookup. |
| `Row.get(names, default)` | method | Return `(value, original_key)` for the first name present with a non-None value. |
| `Row.value(names, default)` | method | The value of the first matching column. |
| `Row.text(names, default)` | method | The value as text. |
| `Row.integer(names, default)` | method | The value as an integer. |
| `_prov(plugin, row_index, field, raw_key, value)` | function | Builds the provenance record (plugin, row, field) of a value. |
| `_iter_rows(plugins, name)` | function | Yield `(row_index, Row)` for every dict row of a successfully completed plugin. |
| `_plugin_ok(plugins, name)` | function | True when a plugin completed. |
| `_build_processes(plugins, warnings)` | function | Creates the Process objects from pslist/psscan/pstree and notes hidden or exited ones. |
| `_enrich_from_pstree(processes, plugins)` | function | Adds path/tree information from pstree. |
| `_apply_cmdline(processes, plugins)` | function | Adds command lines. |
| `_apply_dlls(processes, plugins)` | function | Adds loaded DLLs. |
| `_apply_sids(processes, plugins)` | function | Adds owners (SIDs) and the list of accounts. |
| `_network_rows(plugins)` | function | Yields the network rows of every source: netstat/netscan of Volatility 3 and, for XP or missing symbols, Volatility 2 rows converted to the same shape. |
| `_apply_network(processes, plugins)` | function | Merges netscan/netstat/Volatility-2 rows into connections. |
| `_apply_malfind(processes, plugins)` | function | Adds suspicious memory regions. |
| `_apply_handles(processes, plugins)` | function | Adds open handles. |
| `_system_context(plugins)` | function | Collects image-wide facts (info rows, capture time). |
| `normalize(dump_path, plugins)` | function | Builds an AnalysisResult (no findings, no timeline yet) from the plugin results. |

### `app/engines/windows/analysis/os_profile.py`  (146 lines)

**Purpose:** Decides which Windows an image is (version, build, service pack) and what that means for plugins and rules.

| Name | Kind | Purpose |
|---|---|---|
| `class OsProfile` | class | The identified Windows version. |
| `OsProfile.known()` | method | True when a version was found. |
| `OsProfile.version()` | method | The (major, minor) NT version. |
| `OsProfile.legacy()` | method | NT 5.x: Windows 2000, XP, Server 2003. Volatility 3's network plugins do not support these. |
| `OsProfile.family()` | method | Family name such as "xp", "7", "10" or "11". |
| `OsProfile.name()` | method | Full readable name with build and service pack. |
| `OsProfile.short_name()` | method | The name without the build details. |
| `OsProfile.vol2_profile()` | method | The Volatility 2 profile for this image, '' when there is no Volatility 2 profile (Windows 10+ is handled by Volatility 3). |
| `_service_pack(major, minor, build, lab)` | function | Works out the service pack from version, build and the image's own label. |
| `_value(rows, *names)` | function | Reads a value from the info rows by several possible names. |
| `from_rows(rows)` | function | Profile from `windows.info` rows (`{"Variable": ..., "Value": ...}`); unknown values give `OsProfile()` with `known` False. |
| `from_result(result)` | function | Identifies the Windows version from the windows.info rows of a result. |
| `parse_imageinfo(text)` | function | Profile names from Volatility 2's `imageinfo` text ("Suggested Profile(s) : Win7SP1x64, Win7SP0x64 (Instantiated with ...)"). |
| `debug_addresses(rows)` | function | The kernel debugger block and directory-table addresses from windows.info, which make Volatility 2 start much faster. |

### `app/engines/windows/analysis/plugin_registry.py`  (197 lines)

**Purpose:** The Windows plugin list (name, group, arguments, what each is used for) and the Settings bundles that group them.

*(no classes or functions)*

### `app/engines/windows/analysis/process_images.py`  (78 lines)

**Purpose:** Stores and reads the SHA-256 hashes of the process images dumped from an image.

| Name | Kind | Purpose |
|---|---|---|
| `parse_dump_name(name)` | function | Reads the PID and name from a dumped file's name. |
| `entries_from_artifacts(artifacts, processes)` | function | One entry per dumped file that belongs to a known process (`artifacts` are `dumper.DumpedFile` objects). |
| `unreadable(artifacts)` | function | Names of dumped process images that could not be hashed (`DumpedFile.error` set), for the message shown to the investigator. |
| `store(result, entries, source_dir)` | function | Keep the hashes in the investigation (replacing an earlier list). Returns how many entries were stored. |
| `stored(result)` | function | The hash entries already stored in the case. |
| `export_csv(result, path)` | function | Write the stored list as CSV (PID, process, path, size, SHA-256, MD5): a list that can be checked against feeds offline. |

### `app/engines/windows/analysis/quality.py`  (32 lines)

**Purpose:** Windows image-quality warnings (e.g. paged-out memory) shown with the other analysis warnings.

| Name | Kind | Purpose |
|---|---|---|
| `data_quality_warnings(result)` | function | Warnings about things that limit what the rules can say. |

### `app/engines/windows/analysis/real_provider.py`  (383 lines)

**Purpose:** The Windows provider: runs the chosen plugins (in parallel, with cache, timeouts, Volatility 2 for XP network), then runs the pipeline.

| Name | Kind | Purpose |
|---|---|---|
| `_shutdown_pool(pool, futures)` | function | Cancel work that has not started, then wait for running jobs (works on Python 3.8+; `shutdown(cancel_futures=True)` only exists from 3.9). |
| `class RealProvider` | class | Volatility 3 provider: collection/normalization first, detection second. |
| `RealProvider.__init__(settings)` | method | Reads the plugin choices from the settings. |
| `RealProvider.run(dump_path, progress, plugin_event, cancel)` | method | Runs a whole analysis: find Volatility, run plugins, normalize, apply rules, return the AnalysisResult. |
| `RealProvider.rerun(result, names, progress, plugin_event, cancel)` | method | Run the given plugins (default: the failed ones) again and rebuild the analysis. |
| `RealProvider._tool_info()` | method | What produced this result (saved with the investigation; shown under Computer Info). |
| `RealProvider._skipped_warnings()` | method | The list of plugins skipped on purpose, as warnings. |
| `RealProvider._notify(progress, text, value)` | method | Calls the progress callback safely. |
| `RealProvider._event(callback, name, state, detail)` | method | Calls the plugin-event callback safely. |
| `RealProvider._prepare_tool()` | method | Finds and checks the Volatility tool. |
| `RealProvider._collect(dump, names, progress, plugin_event, cancel, use_cache, known)` | method | Runs the plugin list (parallel, cached, with events) and returns the results; a re-run can reuse earlier results. |
| `RealProvider._vol2_tool()` | method | The configured Volatility 2 (checked once) or the reason there is none. |
| `RealProvider._plan(rest, profile, results, fractions, plugin_event, vol2_state, info)` | method | Split the remaining plugins into those that make sense for this Windows and those that are skipped with a reason; plan the Volatility 2 network jobs for images Volatility 3 cannot read (NT 5.x: Windows XP / 2003). |
| `RealProvider._vol2_fallback(profile, results, vol2_state, fractions, plugin_event, already)` | method | Vista / 7 / 8: when Volatility 3 could not read the network (usually the tcpip symbols are not available offline), Volatility 2's `netscan` has built-in profiles and needs no symbol files. Only runs after both Volatility 3… |
| `RealProvider._require_process_list(plugins)` | method | Stops with a clear message when no plugin produced a process list. |

### `app/engines/windows/analysis/registry_tree.py`  (138 lines)

**Purpose:** Builds one registry tree from every windows.registry.printkey result (no Qt).

| Name | Kind | Purpose |
|---|---|---|
| `class Value` | class | One registry value (name, type, data). |
| `class KeyNode` | class | One registry key with its values and subkeys. |
| `KeyNode.full_path()` | method | The key's path including the hive. |
| `KeyNode.subkeys()` | method | Child keys sorted by name. |
| `KeyNode.count()` | method | Number of keys at and below this node. |
| `split_key(key)` | function | Splits a printkey Key value into the hive name and the path inside the hive. |
| `class RegistryTree` | class | The merged tree of all hives seen in the plugin output. |
| `RegistryTree.__init__(plugins)` | method | Builds the tree from the plugin results. |
| `RegistryTree._node(hive, path, source)` | method | The node for a hive and path, created when needed. |
| `RegistryTree._add(source, rows)` | method | Adds the rows of one printkey result. |
| `RegistryTree.roots()` | method | The hive roots sorted by name. |
| `RegistryTree.find(text, limit)` | method | Keys whose name or path contains every word of `text`, and values whose key path, name or data does (value matches carry the value). |
| `RegistryTree.lookup(hive_and_path)` | method | The node of a "hive\path" text, or None. |

### `app/engines/windows/analysis/timeline_builder.py`  (130 lines)

**Purpose:** Builds the investigation timeline from normalized evidence and the extra timeline sources.

| Name | Kind | Purpose |
|---|---|---|
| `build_timeline(result)` | function | Creates the sorted list of timeline events (process starts/exits, connections, DLL loads, registry/task/execution history). |
| `apply_severity(result)` | function | Tag timeline events with the process risk severity (Medium and above only). |

### `app/engines/windows/analysis/timeline_sources.py`  (177 lines)

**Purpose:** Timeline events from the opt-in registry and execution-history plugins (registry keys, scheduled tasks, UserAssist, Amcache, Shimcache).

| Name | Kind | Purpose |
|---|---|---|
| `covers(plugin_name)` | function | True when this module builds the events of `plugin_name` (the generic 'any row with a time' fallback must skip it). |
| `_text(row, *keys)` | function | A cleaned text value of a row. |
| `routine(path)` | function | A bare file name, or a file in Windows / Program Files that is not in a temporary folder. |
| `third_party(command)` | function | True when the program, or a path in its arguments, is outside the routine system folders. |
| `_interesting_key(plugin_name, key, values)` | function | True when a registry key is interesting enough for the timeline. |
| `_registry_events(plugin, add)` | function | Events from registry key last-write times. |
| `_task_events(plugin, add)` | function | Events from scheduled tasks. |
| `_userassist_events(plugin, add)` | function | Events from UserAssist program-run records. |
| `_amcache_events(plugin, add)` | function | Events from Amcache entries. |
| `_shimcache_events(plugin, add)` | function | Events from Shimcache entries. |
| `add_events(plugin, add)` | function | Add the events of one (completed) plugin; returns how many were offered to `add`. |

### `app/engines/windows/analysis/vol2_adapter.py`  (91 lines)

**Purpose:** Converts Volatility 2 network rows to the shape of Volatility 3 netscan rows so one normalizer handles both.

| Name | Kind | Purpose |
|---|---|---|
| `_key(name)` | function | Normalizes a column name. |
| `_get(row, *names)` | function | Reads the first present column from a row. |
| `_split(endpoint)` | function | Splits "address:port" text (including "*:*", ":::0" and "[::1]:80") into address and port. |
| `_unset(address, port)` | function | A remote endpoint that only says "any": listening sockets and UDP. |
| `network_rows(result_name, rows)` | function | Rows of one Volatility 2 network plugin as netscan-style dicts (`Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created`). |

### `app/engines/windows/analysis/vol2_runner.py`  (252 lines)

**Purpose:** Runs Volatility 2 (standalone exe or vol.py) as a separate program for the XP/2003 network plugins, picking the profile from the image.

| Name | Kind | Purpose |
|---|---|---|
| `class Vol2Unusable(MemoryGraphError)` | class | Volatility 2 is configured but cannot be started. |
| `class Vol2Tool` | class | A located Volatility 2 command. |
| `_env()` | function | The environment for Volatility 2. |
| `find_python2(configured)` | function | Command prefix of a Python 2 interpreter (a configured path, then `py -2`, `python2`, `python2.7`, `C:\Python27`), or None. |
| `bundled_location()` | function | The Volatility 2 dropped into the project's `tools/volatility2` folder (a standalone .exe or a vol.py), or '' when there is none. |
| `find_vol2(path, python2)` | function | The Volatility 2 described by Settings: an `.exe` (run directly), a `vol.py` (run with Python 2) or a folder containing either. Returns None when nothing is configured (Volatility 2 is optional); raises Vol2Unusable when a… |
| `check_vol2(tool, timeout)` | function | Start it once (`-h`) to prove it runs and read the version. |
| `class _Outcome` | class | The result of one Volatility 2 command (exit code, output, timing). |
| `_run(tool, args, timeout, cancel)` | function | Runs one Volatility 2 command with timeout, cancel and output capture. |
| `parse_json_rows(text)` | function | Rows of a Volatility 2 `--output=json` result (`{"columns": [...], "rows": [[...], ...]}`) as dicts. |
| `imageinfo_profiles(tool, dump, timeout, cancel)` | function | Profiles Volatility 2's own `imageinfo` suggests (slow: it scans the image). Only used when the derived profile is refused. |
| `run_vol2(tool, dump, result_name, profile, kdbg, dtb, timeout, cancel)` | function | Run one network plugin and return its rows (raw Volatility 2 columns) as a PluginResult named `result_name` (`vol2.connections`). |


---

## app/engines/windows/indicators - Windows rules

*The Windows rule engine, baselines, ATT&CK mapping and helpers.*

### `app/engines/windows/indicators/__init__.py`  (1 lines)

**Purpose:** Package of the Windows investigation rules and the baselines of what is normal on Windows.

*(no classes or functions)*

### `app/engines/windows/indicators/attack.py`  (129 lines)

**Purpose:** Maps each rule to MITRE ATT&CK techniques and reads technique descriptions from a local JSON file (nothing is fetched online).

| Name | Kind | Purpose |
|---|---|---|
| `class TechniqueInfo` | class | What MemoryGraph knows about a technique offline (`app/engines/windows/data/attack_techniques.json`). |
| `class Technique` | class | One technique tag (id, name) attached to a rule. |
| `Technique.info()` | method | Tactics, a short description and what to look for, read from the local data file. Nothing is fetched from the internet; an id missing from the file simply has empty details. |
| `_local_details()` | function | Loads the offline technique descriptions. |
| `attack_for(rule_id)` | function | The techniques a rule maps to. |

### `app/engines/windows/indicators/baseline.py`  (116 lines)

**Purpose:** Data tables describing what is normal on Windows: core processes and their parents/paths, singleton processes, interpreters, trusted and risky folders, network-free programs, look-alike targets.

*(no classes or functions)*

### `app/engines/windows/indicators/engine.py`  (104 lines)

**Purpose:** The Windows rule engine: the list of all rules, the catalogue (id, name, description) and the defensive evaluation loop.

| Name | Kind | Purpose |
|---|---|---|
| `rule_name(rule_id)` | function | The readable name of a rule id. |
| `class IndicatorEngine` | class | Runs every rule defensively: a failing rule is logged and reported, never fatal. |
| `IndicatorEngine.__init__(rules, iocs)` | method | Takes the rule list and the user's IOC set; IOC rules are a separate family that never changes the behavioural rules. |
| `IndicatorEngine.evaluate(result)` | method | Runs every rule (and the IOC rules), collects findings, records rule errors without stopping, and returns the findings. |

### `app/engines/windows/indicators/helpers.py`  (166 lines)

**Purpose:** Helpers the Windows rules share: path classes (temporary, user-writable, trusted, system), command-line parsing, obfuscation checks, NT version of the image.

| Name | Kind | Purpose |
|---|---|---|
| `is_interpreter(value)` | function | True for cmd, PowerShell and script hosts. |
| `interpreter_category(value)` | function | The kind of interpreter (shell, PowerShell, script host...). |
| `full_name(p)` | function | Image name without Volatility's 14-character truncation when the path gives the full name. |
| `_canon(path)` | function | Normalized lower-case form of a path. |
| `looks_temp(path)` | function | True when a path is in a Temp folder. |
| `is_high_risk_dir(path)` | function | True for Temp, Downloads, Public, Recycle Bin and similar folders. |
| `is_appdata(path)` | function | True for paths under AppData. |
| `is_vendor_appdata(path)` | function | True for AppData folders of well-known vendors. |
| `looks_user_writable(path)` | function | Broad check (kept for compatibility): high-risk directories or any AppData. |
| `is_trusted_dir(path)` | function | True for Windows and Program Files folders. |
| `is_system_path(path)` | function | True for System32 / SysWOW64. |
| `in_dir(path, directory)` | function | True when a path is directly inside a folder. |
| `expand_env_path(text)` | function | Replace the usual `%SystemRoot%` / `%TEMP%` style variables and NT prefixes (`\??\`, `\SystemRoot`) by plain paths. |
| `split_command(text)` | function | Splits a command line or service ImagePath into program path and arguments, expanding environment variables. |
| `has_encoded_powershell(cmd)` | function | True when a command line has a PowerShell -EncodedCommand switch (any abbreviation) with a base64 payload. |
| `looks_obfuscated(cmd)` | function | Strong obfuscation signals only (a long path or a stray quote is not obfuscation). |
| `nt_version(result)` | function | The (major, minor) NT version of the image (5,1 = XP, 6,1 = Windows 7, 10,0 = Windows 10/11), or (0,0) when unknown. |
| `nt_major(result)` | function | Major NT version of the image from windows.info (5 = XP / 2003, 6 = Vista - 8.1, 10 = Windows 10 / 11); 0 when unknown. |


---

## app/engines/windows/indicators/rules - rule families

*One module per family of rules (process, path, command line, memory, network, persistence, kernel, IOC...).*

### `app/engines/windows/indicators/rules/__init__.py`  (1 lines)

**Purpose:** Package of the rule families (one module per family).

*(no classes or functions)*

### `app/engines/windows/indicators/rules/autostart.py`  (61 lines)

**Purpose:** Rule PER-002: Winlogon, AppInit_DLLs and Image File Execution Options changed.

| Name | Kind | Purpose |
|---|---|---|
| `autostart_issue(key, name, data)` | function | Judges one Winlogon / AppInit_DLLs / IFEO value and returns (reason, severity) or empty when normal; also used by the timeline. |
| `class AutostartKeyRule(IndicatorRule)` | class | Reads those registry values and reports unusual ones. |
| `AutostartKeyRule.evaluate(result)` | method | Checks the printkey rows of the autostart keys and builds findings. |

### `app/engines/windows/indicators/rules/behaviour.py`  (77 lines)

**Purpose:** Rule BEH-001: a behavioural lead for programs running from the user's own folders, independent of any name or hash.

| Name | Kind | Purpose |
|---|---|---|
| `user_folder_of(path)` | function | The name of the user's own folder (Desktop, Documents...) a program path is in, or empty. |
| `class UserFolderProgramRule(IndicatorRule)` | class | Reports a program that was not installed (Desktop, Documents, Pictures, OneDrive, profile folder). |
| `UserFolderProgramRule.evaluate(result)` | method | Finds such processes and adds a lead when they also have other signs (injected memory, network). |

### `app/engines/windows/indicators/rules/commandline.py`  (136 lines)

**Purpose:** Command-line rules CL-001..004; command lines are only judged for programs that can act on them.

| Name | Kind | Purpose |
|---|---|---|
| `class PowerShellAbuseRule(IndicatorRule)` | class | CL-001: suspicious PowerShell command lines (encoded commands, hidden windows, bypass, download cradles). |
| `PowerShellAbuseRule.evaluate(result)` | method | Checks each PowerShell process's command line. |
| `class LolbinAbuseRule(IndicatorRule)` | class | CL-002: signed Windows tools (certutil, mshta, regsvr32...) used to fetch or run code. |
| `LolbinAbuseRule.evaluate(result)` | method | Checks each LOLBin's arguments. |
| `class InterpreterRunsFromRiskyPathRule(IndicatorRule)` | class | CL-003: an interpreter launching content from Temp/Downloads/Public/Recycle Bin. |
| `InterpreterRunsFromRiskyPathRule.evaluate(result)` | method | Checks interpreter command lines for risky paths. |
| `class ObfuscatedInterpreterRule(IndicatorRule)` | class | CL-004: obfuscated interpreter arguments (long base64, char-code joins, caret/backtick tricks). |
| `ObfuscatedInterpreterRule.evaluate(result)` | method | Checks interpreter command lines for obfuscation. |

### `app/engines/windows/indicators/rules/crossview.py`  (73 lines)

**Purpose:** Rules that compare views of the same objects: PX-001 (process cross-view) and BASE-001 (process list vs. a clean baseline).

| Name | Kind | Purpose |
|---|---|---|
| `process_key(proc)` | function | How a baseline recognises 'the same program': image name + image path, no PID, no times. |
| `class CrossViewRule(IndicatorRule)` | class | PX-001: a process hidden from the process list and the pool scan. |
| `CrossViewRule.evaluate(result)` | method | Reads psxview rows and reports processes missing from several views. |
| `class NewProcessRule(IndicatorRule)` | class | BASE-001: a process that is not in the imported known-good baseline. |
| `NewProcessRule.evaluate(result)` | method | Compares running processes with the baseline's process list. |

### `app/engines/windows/indicators/rules/dll.py`  (79 lines)

**Purpose:** Loaded-module rules DLL-001 and DLL-002, judged relative to the process that loaded them.

| Name | Kind | Purpose |
|---|---|---|
| `_same_app_dir(process_path, dll_path)` | function | True when the DLL ships next to (or below) the executable's own folder. |
| `class UntrustedModuleLocationRule(IndicatorRule)` | class | DLL-001: a module loaded from a temporary or untrusted location. |
| `UntrustedModuleLocationRule.evaluate(result)` | method | Checks each process's DLL paths. |
| `class SystemDllImpostorRule(IndicatorRule)` | class | DLL-002: a system DLL name loaded from a non-system folder (hijacking / side-loading). |
| `SystemDllImpostorRule.evaluate(result)` | method | Checks core DLL names against their folders. |

### `app/engines/windows/indicators/rules/environment.py`  (49 lines)

**Purpose:** Rule ENV-001: environment variables (COMSPEC, SystemRoot, windir) with unusual values (needs windows.envars).

| Name | Kind | Purpose |
|---|---|---|
| `class EnvironmentVariableRule(IndicatorRule)` | class | Reports an unusual value of a fixed system variable. |
| `EnvironmentVariableRule.evaluate(result)` | method | Reads the envars rows and groups unusual values per process. |

### `app/engines/windows/indicators/rules/files.py`  (53 lines)

**Purpose:** Rule FILE-001: executable file objects in unusual folders (needs windows.filescan).

| Name | Kind | Purpose |
|---|---|---|
| `class FileObjectRule(IndicatorRule)` | class | Reports programs or scripts found in memory in Public, Recycle Bin, Windows\Temp and similar. |
| `FileObjectRule.evaluate(result)` | method | Reads the filescan rows and builds strict/loose/disguised findings. |

### `app/engines/windows/indicators/rules/handles.py`  (39 lines)

**Purpose:** Rule HND-001: handles to lsass.exe with memory-read access.

| Name | Kind | Purpose |
|---|---|---|
| `class LsassHandleRule(IndicatorRule)` | class | Reports a process that holds a handle to lsass with PROCESS_VM_READ (credential dumping sign). |
| `LsassHandleRule.evaluate(result)` | method | Checks the handle rows of every process against the lsass PID. |

### `app/engines/windows/indicators/rules/ioc.py`  (231 lines)

**Purpose:** The IOC rule family: matches evidence against indicators the investigator supplied (IPs, domains, mutexes, files, YARA hits, image hashes).

| Name | Kind | Purpose |
|---|---|---|
| `class _IocRule(IndicatorRule)` | class | Base class of the IOC rules; holds the IOC set. |
| `_IocRule.__init__(iocs)` | method | Stores the IOC set. |
| `_IocRule.hit(ioc, what, severity, process, evidence, sources, items)` | method | Builds the finding for one indicator match. |
| `class IpIocRule(_IocRule)` | class | IOC-001: a connection to an IP or range on the list. |
| `IpIocRule.evaluate(result)` | method | Checks every connection against the IP indicators. |
| `class DomainIocRule(_IocRule)` | class | IOC-002: a domain on the list in a command line or similar. |
| `DomainIocRule.evaluate(result)` | method | Searches command lines for listed domains. |
| `class MutexIocRule(_IocRule)` | class | IOC-004: a mutex name on the list. |
| `MutexIocRule.evaluate(result)` | method | Checks the mutantscan rows. |
| `class FileIocRule(_IocRule)` | class | IOC-005: a file path on the list in memory (filescan, modules, handles). |
| `FileIocRule.evaluate(result)` | method | Checks file evidence against the file indicators. |
| `class ImageHashIocRule(_IocRule)` | class | IOC-007: a dumped process image whose hash is on the list. |
| `ImageHashIocRule.evaluate(result)` | method | Checks the stored image hashes against the hash indicators. |
| `readable_match(value)` | function | windows.vadyarascan prints the matched bytes as hex (`77 69 6e`). Show them as text when they are text (ASCII or UTF-16LE), with the hex kept. |
| `class YaraHitRule(IndicatorRule)` | class | Matches of the investigator's own YARA rules (windows.vadyarascan --yara-file). Needs the opt-in plugin and a rule file in Settings. |
| `YaraHitRule.evaluate(result)` | method | IOC-006: groups the YARA rule matches per process into findings. |
| `ioc_rules(iocs)` | function | The IOC rules for this run. YARA hits need no IOC list (they are driven by the plugin), the others need one. |

### `app/engines/windows/indicators/rules/kernel.py`  (68 lines)

**Purpose:** Rule DRV-001: a driver found by scanning but missing from the loaded-module list (needs modules + modscan).

| Name | Kind | Purpose |
|---|---|---|
| `_readable(value)` | function | Text from pool memory is sometimes garbage (a driver object whose name was overwritten): show it only when it looks like text. |
| `class HiddenDriverRule(IndicatorRule)` | class | Reports hidden drivers. |
| `HiddenDriverRule.evaluate(result)` | method | Compares the modscan and modules lists. |

### `app/engines/windows/indicators/rules/kernel_objects.py`  (178 lines)

**Purpose:** Kernel object rules: DRV-002 (driver code outside any module), SSDT-001 (system-call table hooks), CBK-001 (callbacks pointing outside modules).

| Name | Kind | Purpose |
|---|---|---|
| `class DriverObjectRule(IndicatorRule)` | class | DRV-002: a driver object whose code is in no loaded module. |
| `DriverObjectRule.evaluate(result)` | method | Compares driverscan start addresses with the module ranges. |
| `class SsdtHookRule(IndicatorRule)` | class | SSDT-001: system call entries pointing outside the kernel. |
| `SsdtHookRule.evaluate(result)` | method | Checks the ssdt rows. |
| `_executable_ranges(result)` | function | The address ranges of the executable regions of every process, from malfind and vadinfo. |
| `_looks_like_code(address)` | function | True when the little-endian bytes of the value contain two x86-64 mov opcodes with a REX prefix (48 89 / 48 8b / 4c 89 / 4c 8b). |
| `class UnbackedCallbackRule(IndicatorRule)` | class | CBK-001: a kernel callback whose address is in no loaded module. |
| `UnbackedCallbackRule.evaluate(result)` | method | Checks callbacks against module ranges and the executable ranges of processes. |

### `app/engines/windows/indicators/rules/malware.py`  (239 lines)

**Purpose:** Rules MAL-001..007 for Volatility 3's malware-hunting plugins (hollowing, suspicious threads, PEB masquerade, ghosting, hidden services, IRP hooks, ETW patching).

| Name | Kind | Purpose |
|---|---|---|
| `class _PerProcess(IndicatorRule)` | class | Shared shape: rows of one plugin grouped per process, one finding per process. |
| `_PerProcess.rows(result)` | method | The (row index, row, pid) tuples to report; subclasses filter them. |
| `_PerProcess.line(row)` | method | One-line text of a plugin row for a finding. |
| `_PerProcess.evaluate(result)` | method | Groups rows per process and creates one finding per process. |
| `_PerProcess.severity_for(proc, items)` | method | The severity of a group of rows (overridden by some rules). |
| `class HollowedProcessRule(_PerProcess)` | class | MAL-001: a hollowed process. |
| `HollowedProcessRule.line(row)` | method | The plugin's note as the evidence line. |
| `class SuspiciousThreadRule(_PerProcess)` | class | MAL-002: a thread started outside any module. |
| `SuspiciousThreadRule.rows(result)` | method | Keeps the thread rows worth reporting (and ignores legacy-Windows noise). |
| `SuspiciousThreadRule.line(row)` | method | Evidence line for a thread (TID, context, address, note). |
| `SuspiciousThreadRule.severity_for(proc, items)` | method | Medium when the thread is in non-file-backed memory, else Low. |
| `class PebMasqueradeRule(_PerProcess)` | class | MAL-003: the PEB path or command line differs from the kernel's record. |
| `PebMasqueradeRule.path_differs(row)` | method | The plugin's own flag, checked: the PEB path (`C:\WINDOWS\...`) and the kernel's (`\Device\HarddiskVolume1\WINDOWS\...`) are the same file in two notations, which the plugin sometimes reports as different (seen on a real XP… |
| `PebMasqueradeRule.rows(result)` | method | Skips the System/smss rows that legitimately differ. |
| `PebMasqueradeRule.line(row)` | method | Evidence line comparing PEB and kernel values. |
| `PebMasqueradeRule.severity_for(proc, items)` | method | High when the image path differs, otherwise Medium. |
| `class ProcessGhostingRule(_PerProcess)` | class | MAL-004: a process started from a deleted file. |
| `ProcessGhostingRule.line(row)` | method | Evidence line with the path and delete flags. |
| `class HiddenServiceRule(_PerProcess)` | class | MAL-005: a service found by scanning but missing from the service list. |
| `HiddenServiceRule.line(row)` | method | Evidence line with the service name and binary. |
| `class IrpHookRule(IndicatorRule)` | class | MAL-006: a driver IRP handler pointing outside every module. |
| `IrpHookRule.evaluate(result)` | method | Compares IRP handler addresses with the driver's and kernel's ranges. |
| `class EtwPatchRule(_PerProcess)` | class | MAL-007: a patched ETW tracing function. |
| `EtwPatchRule.line(row)` | method | Evidence line with the DLL, function and offset. |

### `app/engines/windows/indicators/rules/memory.py`  (91 lines)

**Purpose:** Rule MEM-001: executable private memory found by malfind, with every region scored because many hits are harmless (JIT, antivirus).

| Name | Kind | Purpose |
|---|---|---|
| `_hex_bytes(region)` | function | Lower-case hex of the stored bytes. (Volatility's dump text ends each line with an ASCII column; parse_hexdump leaves it out, where stripping every non-hex character would have turned its letters a-f into extra bytes.) |
| `classify_region(region, module_names, legacy)` | function | Return `(severity, [reasons])` for one malfind region. |
| `class InjectedMemoryRule(IndicatorRule)` | class | One lead per process, scored from the content of its regions. |
| `InjectedMemoryRule.evaluate(result)` | method | Classifies each malfind region and reports the process with the reasons. |

### `app/engines/windows/indicators/rules/network.py`  (68 lines)

**Purpose:** Network rules NET-001 and NET-002; a connection alone is never a finding.

| Name | Kind | Purpose |
|---|---|---|
| `external_connections(process)` | function | A process's connections to public addresses. |
| `class NetworkWithOtherSuspicionRule(IndicatorRule)` | class | NET-001: an external connection from a process that already looks suspicious. |
| `NetworkWithOtherSuspicionRule.evaluate(result)` | method | Combines the public-IP connections with other signs of the same process. |
| `class UnexpectedNetworkProcessRule(IndicatorRule)` | class | NET-002: a process that normally has no connections holding one to a public address. |
| `UnexpectedNetworkProcessRule.evaluate(result)` | method | Checks the network-free process list against connections. |

### `app/engines/windows/indicators/rules/path.py`  (143 lines)

**Purpose:** Process identity rules PR-001..004: look-alike names, wrong install paths, risky folders, name/image mismatch.

| Name | Kind | Purpose |
|---|---|---|
| `_distance(a, b)` | function | Damerau-Levenshtein (optimal string alignment) distance. |
| `lookalike_of(name)` | function | Return the core name `name` imitates, or None. |
| `class LookalikeNameRule(IndicatorRule)` | class | PR-001: a name one typo or homoglyph away from a core Windows process. |
| `LookalikeNameRule.evaluate(result)` | method | Compares every process name with the core names. |
| `class CoreProcessPathRule(IndicatorRule)` | class | PR-002: a core Windows process running from the wrong folder. |
| `CoreProcessPathRule.evaluate(result)` | method | Checks core process paths. |
| `class RiskyPathExecutionRule(IndicatorRule)` | class | PR-003: an executable running from Temp, Downloads, Public or similar. |
| `RiskyPathExecutionRule.evaluate(result)` | method | Checks every process path and rates the folder. |
| `class NameMismatchRule(IndicatorRule)` | class | PR-004: the process name differs from its image file. |
| `NameMismatchRule.evaluate(result)` | method | Compares the reported name with the file name of the path. |

### `app/engines/windows/indicators/rules/persistence.py`  (152 lines)

**Purpose:** Persistence rules PER-003 (services in the registry) and PER-004 (scheduled tasks).

| Name | Kind | Purpose |
|---|---|---|
| `_program_name(command)` | function | The program name in a command line. |
| `command_reasons(command)` | function | Reasons a command that starts at boot, logon or schedule is suspicious (risky folder, encoded text), as (reason, severity); shared by PER-003 and PER-004. |
| `_worst(severities)` | function | The more serious of a set of severities. |
| `class ServiceKeyRule(IndicatorRule)` | class | PER-003: a service whose binary is in a risky place or whose command is encoded. |
| `ServiceKeyRule.evaluate(result)` | method | Reads the service keys and judges each ImagePath. |
| `class ScheduledTaskRule(IndicatorRule)` | class | PER-004: a scheduled task that runs code from a risky place or through an interpreter. |
| `ScheduledTaskRule.evaluate(result)` | method | Reads the task store and judges each action. |

### `app/engines/windows/indicators/rules/process.py`  (171 lines)

**Purpose:** Process hierarchy rules PT-001..005, driven by the baseline tables.

| Name | Kind | Purpose |
|---|---|---|
| `class CoreProcessParentRule(IndicatorRule)` | class | PT-001: a core Windows process with an unexpected parent. |
| `CoreProcessParentRule.evaluate(result)` | method | Compares each core process with its expected parent. |
| `class MissingOnThisWindowsRule(IndicatorRule)` | class | PT-005: a system process that does not exist on this Windows version. |
| `MissingOnThisWindowsRule.evaluate(result)` | method | Compares process names with the NT version. |
| `class SingletonProcessRule(IndicatorRule)` | class | PT-002: a duplicate of a single-instance process. |
| `SingletonProcessRule.evaluate(result)` | method | Counts the running copies of each singleton. |
| `class HiddenProcessRule(IndicatorRule)` | class | PT-003: a process seen by psscan but not in pslist. |
| `HiddenProcessRule.evaluate(result)` | method | Compares the two lists and downgrades processes created during capture. |
| `class InterpreterParentRule(IndicatorRule)` | class | PT-004: an interpreter started by an unusual parent. |
| `InterpreterParentRule.evaluate(result)` | method | Checks the parent of cmd/PowerShell/script hosts. |

### `app/engines/windows/indicators/rules/registry.py`  (112 lines)

**Purpose:** Registry rules PER-001 (Run keys) and UA-001 (UserAssist execution history).

| Name | Kind | Purpose |
|---|---|---|
| `class RunKeyRule(IndicatorRule)` | class | PER-001: an autorun entry that starts code from a risky place or through an interpreter. |
| `RunKeyRule.evaluate(result)` | method | Reads the Run/RunOnce rows and judges each command. |
| `class UserAssistRule(IndicatorRule)` | class | UA-001: a program started by the user from a temporary or user-writable folder. |
| `UserAssistRule.evaluate(result)` | method | Reads UserAssist rows and groups strict and other matches. |

### `app/engines/windows/indicators/rules/services.py`  (50 lines)

**Purpose:** Rule SVC-001: a service whose binary is in a temporary or user-writable folder (needs svcscan).

| Name | Kind | Purpose |
|---|---|---|
| `class RiskyServiceBinaryRule(IndicatorRule)` | class | Reports services started from risky folders. |
| `RiskyServiceBinaryRule.evaluate(result)` | method | Judges each svcscan row's binary path. |

### `app/engines/windows/indicators/rules/vad.py`  (167 lines)

**Purpose:** Memory-map rules VAD-001 and LDR-001 (need vadinfo, dllist, ldrmodules).

| Name | Kind | Purpose |
|---|---|---|
| `lists_incomplete(names)` | function | True when a process's module list lacks core DLLs (so "unlisted" would be noise). |
| `_base(path)` | function | File name part of a normalized path. |
| `quiet_finding(rule, title, summary, reasons, quiet, source_plugins, kind)` | function | ONE Low finding for all the processes whose unlisted images are all in trusted Windows folders (`quiet`: `[(process, pid, [(row, path)])]`). On a real Windows 10 image these were 43 separate Low findings (one per process) that… |
| `class UnlistedImageRule(IndicatorRule)` | class | VAD-001: an executable image mapped in a process but missing from its module list. |
| `UnlistedImageRule.evaluate(result)` | method | Compares vadinfo mappings with the dlllist. |
| `class UnlinkedModuleRule(IndicatorRule)` | class | LDR-001: a module mapped in a process but absent from all three loader lists. |
| `UnlinkedModuleRule.evaluate(result)` | method | Reads ldrmodules rows and reports modules unlinked everywhere. |


---

## app/windows - the GUI

*Every window and view: start page, dashboard, settings, views, widgets, motion.*

### `app/windows/__init__.py`  (1 lines)

**Purpose:** Marks `app.windows` (all the GUI code) as a package.

*(no classes or functions)*

### `app/windows/case_actions.py`  (45 lines)

**Purpose:** Small GUI helpers shared by the views that let the investigator bookmark, annotate and triage.

| Name | Kind | Purpose |
|---|---|---|
| `find_dashboard(widget)` | function | The DashboardWindow above `widget` (anything offering `case_changed`), or None when used standalone. |
| `notify_case_changed(widget)` | function | Tells the dashboard that notes/bookmarks changed so other views refresh. |
| `notify_triage_changed(widget)` | function | Tells the dashboard that a finding's triage changed so counts and lists refresh. |
| `toggle_bookmark(widget, result, kind, target, label, pid)` | function | Adds or removes a bookmark on a target and refreshes the views. |
| `ask_and_add_note(widget, result, kind, target, label, pid)` | function | Asks for a note text in a dialog and attaches it to a target. |

### `app/windows/case_window.py`  (210 lines)

**Purpose:** The Case Notes view: bookmarks, notes, triage decisions and baselines of the investigation, with export and import.

| Name | Kind | Purpose |
|---|---|---|
| `class CaseView(QWidget)` | class | The Case Notes page. |
| `CaseView.__init__(result, parent)` | method | Builds the tabs for bookmarks, notes, triage and baselines. |
| `CaseView._table(columns, rows, payloads, widths, empty_text)` | method | Builds one tab holding a table with a remove/open button row. |
| `CaseView.refresh_after_triage(*_)` | method | Rebuilds the tabs after a triage change. |
| `CaseView._open(payload)` | method | Opens the item a row refers to (process, connection...). |
| `CaseView._remove(payload)` | method | Removes a bookmark/note/baseline after asking. |
| `CaseView.export_notes(*_)` | method | Saves the case as a Markdown report. |
| `CaseView.export_baseline(only_false_positives)` | method | Saves findings as a baseline file (all, or only false positives). |
| `CaseView.export_known_good(*_)` | method | The modules every program of THIS (clean) system has loaded, as a list other investigations of the same Windows can use. |
| `CaseView.install_known_good(*_)` | method | Makes known-good module lists from this image. |
| `CaseView.import_baseline(*_)` | method | Imports a baseline file into the case. |

### `app/windows/compare_window.py`  (186 lines)

**Purpose:** The Compare view: this investigation against another saved one (another image or the same system earlier).

| Name | Kind | Purpose |
|---|---|---|
| `class CompareView(QWidget)` | class | The Compare page. |
| `CompareView.__init__(result, parent)` | method | Builds the controls and empty tabs. |
| `CompareView._build_tabs()` | method | Creates one tab per section of differences. |
| `CompareView.choose_reference(*_)` | method | Asks for the reference investigation file. |
| `CompareView.load_reference(path)` | method | Loads the reference in the background. |
| `CompareView._loaded(path, reference)` | method | Stores the reference and compares. |
| `CompareView._load_failed(message, details)` | method | Shows the loading error. |
| `CompareView.set_reference(reference, path)` | method | Use an investigation that is already in memory (used by tests and callers that have one). |
| `CompareView.recompare(*_)` | method | Runs the comparison again (same boot / different boot mode). |
| `CompareView.apply_filters(*_)` | method | Applies the "new / gone / changed" filters to the tables. |
| `CompareView._open(row)` | method | Opens the process of a difference row. |
| `CompareView.export_csv(*_)` | method | Saves the differences as CSV. |

### `app/windows/dashboard_window.py`  (452 lines)

**Purpose:** The investigation dashboard: top bar, sidebar navigation with a sliding marker and the views built on first use.

| Name | Kind | Purpose |
|---|---|---|
| `class DashboardWindow(QWidget)` | class | The page that shows one AnalysisResult. |
| `DashboardWindow.__init__(result, home, settings)` | method | Builds the top bar, sidebar and the stack of views for the engine's view list. |
| `DashboardWindow._indicator_rect(index)` | method | Where the navigation marker belongs for an entry. |
| `DashboardWindow._move_indicator(animate)` | method | Slides the marker to the selected entry. |
| `DashboardWindow.showEvent(event)` | method | Positions the marker when shown. |
| `DashboardWindow.resizeEvent(event)` | method | Keeps the marker aligned after a resize. |
| `DashboardWindow._factory_for(spec)` | method | The function that builds the view called `spec.id`; a placeholder page when the engine does not provide it yet. Views are imported when first built. |
| `DashboardWindow._ensure(index)` | method | Builds a view the first time it is needed. |
| `DashboardWindow._scrolling(widget)` | method | Every view sits in a scroll area: on a small window the page scrolls, instead of squeezing the lists in it down to their header row (each list has a minimum height, see `make_table`). When the window is large enough the view… |
| `DashboardWindow._inner(index)` | method | The view itself (not its scroll area) at `index`; the placeholder widget while the view is not built. |
| `DashboardWindow._error_view(name, exc)` | method | A page that shows why a view could not be built, instead of crashing. |
| `DashboardWindow.select_view(index)` | method | Shows a view (building it if needed) and moves the marker. |
| `DashboardWindow.view(name)` | method | The widget of a named view. |
| `DashboardWindow._layout_settings()` | method | The settings dict that holds saved layouts. |
| `DashboardWindow.capture_layout()` | method | Store the splitter positions and column widths of every view that has been opened (called when the app closes). |
| `DashboardWindow._flagged_count()` | method | Number of processes with Medium/High findings (shown beside "Indications"). |
| `DashboardWindow.mark_dirty()` | method | Notes that the case has unsaved changes. |
| `DashboardWindow.clear_dirty()` | method | Clears the unsaved-changes note. |
| `DashboardWindow._built_view(name)` | method | The view if already built, else None. |
| `DashboardWindow._forget_view(name)` | method | Drop a built view so it is rebuilt from the current data the next time it is opened. |
| `DashboardWindow.rebuild_views(*_)` | method | Drop every built view and rebuild the current one (after a theme / font change: views pick colours when they are built). |
| `DashboardWindow.case_changed(*_)` | method | A note or bookmark changed (no finding was re-judged). |
| `DashboardWindow.triage_changed(*_)` | method | A finding was reviewed / marked false positive / suppressed: scores, counts and colours change. |
| `DashboardWindow.make_overview()` | method | Builds the Overview page: count cards, warnings and the "top processes to review" table. |
| `DashboardWindow._open_ranked(pid)` | method | Opens the process of a row clicked in the overview. |
| `DashboardWindow.show_process(pid)` | method | Goes to the Process Tree and selects a process. |
| `DashboardWindow.open_search(*_)` | method | Goes to Search with the text typed in the global search box. |
| `DashboardWindow.go_home(*_)` | method | Back to the start page. |
| `DashboardWindow.save_current_analysis(*_)` | method | Saves the investigation (through the home window). |
| `DashboardWindow.live_settings()` | method | The settings in force now (Settings changes replace the home window's dict, so prefer it over the one captured at construction). |
| `DashboardWindow.run_plugins(names, view, *_)` | method | Run the given plugins on this image now (e.g. windows.filescan from the Files view); the dashboard is rebuilt with the new results. |
| `DashboardWindow.rerun_failed(*_)` | method | Re-runs plugins that failed (through the home window). |

### `app/windows/files_window.py`  (861 lines)

**Purpose:** The Files view: the file objects windows.filescan found, in an explorer style (folder tree, list, details, dumping, reports).

| Name | Kind | Purpose |
|---|---|---|
| `_key(path)` | function | Lower-case path without drive/device, comparable between filescan names, handle names and module paths. |
| `class FilesView(QWidget)` | class | The Files page. |
| `FilesView.__init__(result, parent)` | method | Builds the tree, list, details panel and toolbar. |
| `FilesView._empty_page()` | method | The page shown when filescan was not run. |
| `FilesView._tool(icon, tip)` | method | Creates a small toolbar button. |
| `FilesView._explorer_page()` | method | Builds the explorer layout. |
| `FilesView._settings()` | method | The settings dict (for the remembered dump folder). |
| `FilesView._plugin()` | method | The filescan PluginResult. |
| `FilesView.reload(*_)` | method | Rebuilds the view from the filescan result stored in the investigation. |
| `FilesView._build_tree()` | method | Fills the folder tree. |
| `FilesView.navigate(folder, record)` | method | Open `folder` (and remember it for Back / Forward). |
| `FilesView._tree_selected(current, _previous)` | method | Shows the files of the folder selected in the tree. |
| `FilesView.go_back(*_)` | method | History: back. |
| `FilesView.go_forward(*_)` | method | History: forward. |
| `FilesView.go_up(*_)` | method | Goes to the parent folder. |
| `FilesView.address_entered(*_)` | method | Goes to the folder typed in the address bar. |
| `FilesView.focus_address(*_)` | method | Puts the cursor in the address bar. |
| `FilesView.focus_search(*_)` | method | Puts the cursor in the search box. |
| `FilesView.open_current(*_)` | method | Opens the selected item (folder or file). |
| `FilesView.open_item(item)` | method | Folders open; a dumped file opens in the hex view; any other file shows its properties. |
| `FilesView._items()` | method | The subfolders and files of the open folder (or the matches of a search over the whole subtree). |
| `FilesView.populate(*_)` | method | Fills the list with the current folder's files and filters. |
| `FilesView._location_text(entry)` | method | The folder text of a file for the list. |
| `FilesView._dump_state(entry)` | method | Text showing whether a file was already dumped. |
| `FilesView._selected_items()` | method | The selected list payloads. |
| `FilesView._selected()` | method | The selected files only. |
| `FilesView._current()` | method | The current file, if any. |
| `FilesView.selection_changed(*_)` | method | Updates the details panel for the selected file. |
| `FilesView._references()` | method | Which processes hold or load each file path (handles and modules). |
| `FilesView._ioc_set()` | method | The IOC set from the settings (cached). |
| `FilesView._table(rows)` | method | Formats label/value pairs as an HTML table. |
| `FilesView._folder_html(folder)` | method | HTML summary of a folder. |
| `FilesView._properties_html(entry)` | method | Everything known about a file object *without* its content: that only exists after a dump. |
| `FilesView.actions_for(item)` | method | The right-click menu of a row as `[(label, handler)]` (a list, so it can be tested without opening a menu). |
| `FilesView._context_menu(position)` | method | The right-click menu. |
| `FilesView.dump_folder(folder, *_)` | method | Dumps every file of a folder. |
| `FilesView._show_dumped(entry)` | method | Lists the dumped files of the current file. |
| `FilesView.dumped_selected(*_)` | method | Opens the report of a dumped file. |
| `FilesView._report_ready(path, report)` | method | Stores a finished file report and shows it. |
| `FilesView._report_html(rep)` | method | HTML of a file report (type, hashes, entropy, PE, strings). |
| `FilesView.choose_dump_dir(*_)` | method | Asks for the folder to write dumps into. |
| `FilesView._set_dump_dir(path)` | method | Remembers the dump folder. |
| `FilesView._update_dump_label()` | method | Updates the "dumped files" label. |
| `FilesView._rescan_dumps()` | method | Re-attach files `windows.dumpfiles` wrote earlier to their entries (the names carry the FILE_OBJECT address). |
| `FilesView._ensure_dump_dir()` | method | Makes sure there is a usable dump folder. |
| `FilesView.dump_selected(*_)` | method | Dumps the selected files. |
| `FilesView.dump_all_shown(*_)` | method | Dumps every file in the list. |
| `FilesView._dump(entries)` | method | Runs the dump in the background. |
| `FilesView._set_busy(busy, text)` | method | Enables/disables the buttons while dumping. |
| `FilesView._dump_done(entries, outcome)` | method | Handles a finished dump (hashes, IOC check, list update). |
| `FilesView._dump_failed(message, details)` | method | Shows a dump error. |
| `FilesView.open_hex(*_)` | method | Opens the hex viewer on a dumped file. |
| `FilesView.open_dump_folder(*_)` | method | Opens the dump folder in the file manager. |
| `FilesView.run_filescan(*_)` | method | Starts filescan when it was not run. |
| `FilesView.toggle_bookmark_current(*_)` | method | Bookmarks the selected file. |
| `FilesView.add_note_current(*_)` | method | Adds a note to the selected file. |
| `FilesView.select_target(target)` | method | Open the folder of the file a bookmark/note refers to and select the file (called from Case Notes). |

### `app/windows/hex_view.py`  (375 lines)

**Purpose:** The hex viewer dialog for a memory region or a dumped file: offsets, search, byte inspector, disassembly, bookmarks.

| Name | Kind | Purpose |
|---|---|---|
| `class HexViewDialog(QDialog)` | class | The hex viewer window. |
| `HexViewDialog.__init__(region, process, parent, result, dump_dir, subject)` | method | Builds the viewer for a memory region, or for a plain dumped file when a "subject" is given. |
| `HexViewDialog._set_data(data, source, total)` | method | Shows new bytes and their source. |
| `HexViewDialog.use_malfind_bytes(*_)` | method | Shows the bytes malfind stored for the region. |
| `HexViewDialog.load_file(*_)` | method | Loads the region's dumped file from disk. |
| `HexViewDialog.load_path(path)` | method | Loads a chosen file. |
| `HexViewDialog._range_selections(offset, length, color)` | method | Highlight selections for a byte range. |
| `HexViewDialog._apply_highlights()` | method | Re-applies the highlights (cursor, search hit, instruction). |
| `HexViewDialog._goto(offset)` | method | Moves to a byte offset. |
| `HexViewDialog._cursor_moved(*_)` | method | Updates the inspector for the byte under the cursor. |
| `HexViewDialog._mode_changed(*_)` | method | Adapts the search options to the chosen mode. |
| `HexViewDialog._pattern()` | method | Compiles the search pattern from the text and mode. |
| `HexViewDialog._show_hit(hit, pattern)` | method | Shows a search result. |
| `HexViewDialog.find_next(*_)` | method | Finds the next match. |
| `HexViewDialog.find_previous(*_)` | method | Finds the previous match. |
| `HexViewDialog.go_to(*_)` | method | Goes to the offset or address typed. |
| `HexViewDialog._disassemble(start)` | method | Disassembles from an offset into the table. |
| `HexViewDialog.disassemble_from_start(*_)` | method | Disassembles from the first byte. |
| `HexViewDialog.disassemble_from_cursor(*_)` | method | Disassembles from the cursor. |
| `HexViewDialog._instruction_selected(*_)` | method | Highlights the instruction's bytes. |
| `HexViewDialog._target()` | method | The bookmark target of what is shown. |
| `HexViewDialog._label()` | method | The label of what is shown. |
| `HexViewDialog._refresh_marks()` | method | Updates the bookmark/note buttons. |
| `HexViewDialog.toggle_region_bookmark(*_)` | method | Bookmarks the region/file. |
| `HexViewDialog.add_region_note(*_)` | method | Adds a note to the region/file. |

### `app/windows/home_window.py`  (547 lines)

**Purpose:** The main window: start page, progress page, settings page and dashboard in one stack; runs analyses, saves and loads investigations.

| Name | Kind | Purpose |
|---|---|---|
| `class HomeWindow(QMainWindow)` | class | The main window. |
| `HomeWindow.__init__()` | method | Builds the pages, the controller and the signal wiring. |
| `HomeWindow.engine()` | method | The engine of the operating system picked with the switch (`settings["target_os"]`). |
| `HomeWindow._build_home_page()` | method | The start page: a centred column in a scroll area. On a short window the page scrolls; no control is ever squeezed on top of another (each has a minimum height). |
| `HomeWindow.showEvent(event)` | method | Plays the entrance animation when first shown. |
| `HomeWindow.open_demo(*_)` | method | Open the engine's demo investigation (made-up data in the shape of a real result), to see how a run looks without an image. |
| `HomeWindow.on_os_changed(os_id, *_)` | method | The operating system was switched: swap the settings that belong to it, save, and change the words on this page. |
| `HomeWindow.apply_os_terms(animate)` | method | Title, hint, file filter and the "not written yet" note of the chosen operating system (the title and hint cross-fade). |
| `HomeWindow._cross_fade(label, text)` | method | Changes a label's text with a fade. |
| `HomeWindow._refresh_recent()` | method | Refills the list of recent dumps and investigations. |
| `HomeWindow._remember(key, path)` | method | Adds an entry to a recent list and saves. |
| `HomeWindow._page_key()` | method | Which layout key (home or dashboard) the current page uses. |
| `HomeWindow._save_page_geometry()` | method | Saves the window size of the current page. |
| `HomeWindow._restore_page_geometry(key, width, height)` | method | Restores the saved size for a page. |
| `HomeWindow.show_home(*_)` | method | Goes back to the start page (asking when an analysis runs). |
| `HomeWindow.resume_dashboard(*_)` | method | Returns to the open dashboard. |
| `HomeWindow.show_settings(*_)` | method | Open the settings as a page of this window (not a pop-up); Apply, Cancel or Esc brings back the page you came from. |
| `HomeWindow._close_settings(applied, *_)` | method | Closes the settings page and returns to the page before it. |
| `HomeWindow.browse(*_)` | method | File dialog for a memory image. |
| `HomeWindow.run_analysis(*_)` | method | Validates the image path and starts an analysis. |
| `HomeWindow.start_analysis(dump_path)` | method | Starts the background analysis and shows the progress page. |
| `HomeWindow.rerun_failed(*_)` | method | Re-runs failed plugins of the open result. |
| `HomeWindow.run_plugins(names, view, *_)` | method | Run plugins on the open investigation (for example windows.filescan from the Files view), then show `view` again. |
| `HomeWindow.retry_last(*_)` | method | Repeats the last analysis or load. |
| `HomeWindow.on_finished(result)` | method | Shows the dashboard when a job finishes. |
| `HomeWindow.on_failed(message, details)` | method | Shows the error on the progress page. |
| `HomeWindow.on_cancelled(*_)` | method | Shows the cancelled state. |
| `HomeWindow.show_dashboard(result)` | method | Always build a fresh dashboard for `result` (never reuse the previous investigation's view). |
| `HomeWindow.save_current_analysis(*_)` | method | Saves the open investigation to a file in the background. |
| `HomeWindow._save_done(file_name)` | method | Confirms a finished save. |
| `HomeWindow._save_failed(message, details)` | method | Shows a save error. |
| `HomeWindow.load_previous_analysis(*_)` | method | File dialog to load a saved investigation. |
| `HomeWindow.load_analysis_file(file_name)` | method | Loads a saved investigation in the background. |
| `HomeWindow.open_recent(item, *_)` | method | Opens an entry of the recent list. |
| `HomeWindow.closeEvent(event)` | method | Saves layout/settings and asks about unsaved work before closing. |

### `app/windows/indications_window.py`  (384 lines)

**Purpose:** The Indications view (findings grouped by process and ranked) and the finding-details dialog with triage controls.

| Name | Kind | Purpose |
|---|---|---|
| `class IndicationDetails(QDialog)` | class | Dialog showing one finding: evidence, reasoning, ATT&CK, triage buttons. |
| `IndicationDetails.__init__(indication, parent, on_show_process, command_line, result)` | method | Builds the dialog text from the finding and the result. |
| `IndicationDetails._add_triage_controls(layout)` | method | Adds the reviewed / false-positive / reset buttons and the reason box. |
| `IndicationDetails._decide(status, *_)` | method | Records the investigator's decision for the finding. |
| `IndicationDetails._add_note(*_)` | method | Attaches a note to the finding's process. |
| `IndicationDetails.show_process(*_)` | method | Closes the dialog so the caller can open the process. |
| `class IndicationsView(QWidget)` | class | The Indications page. |
| `IndicationsView.__init__(result, parent)` | method | Builds the cards, filters and tree. |
| `IndicationsView._fill_cards()` | method | Fills the High / Medium / Low / processes-flagged cards. |
| `IndicationsView.bulk_triage(status, *_)` | method | Apply one decision to every open finding that passes the current filters (asks first; nothing is deleted). |
| `IndicationsView.refresh_after_triage(*_)` | method | Called by the dashboard after a finding was re-judged: recompute scores and cards, keep filters. |
| `IndicationsView._filtered()` | method | The findings that pass the filters. |
| `IndicationsView.refresh(*_)` | method | Rebuilds the cards and tree. |
| `IndicationsView._fill_grouped(findings)` | method | Fills the tree grouped by process. |
| `IndicationsView._finding_item(ind, with_process)` | method | Creates the tree item of one finding. |
| `IndicationsView.open_item(item, _column)` | method | Opens the finding (or process) of a double-clicked item. |
| `IndicationsView._show_process(pid)` | method | Goes to the process in the Process Tree. |

### `app/windows/injection_window.py`  (115 lines)

**Purpose:** The Injection view: for each process with a memory-level sign, the evidence of all plugins as one chain.

| Name | Kind | Purpose |
|---|---|---|
| `class InjectionView(QWidget)` | class | The Injection page. |
| `InjectionView.__init__(result, parent)` | method | Builds the table of processes and the chain panel. |
| `InjectionView.refresh_after_triage(*_)` | method | Rebuild the chains (a finding marked as false positive no longer counts). |
| `InjectionView._current()` | method | The chain of the selected row. |
| `InjectionView.show_chain(*_)` | method | Shows the selected chain's steps. |
| `InjectionView.on_link(url)` | method | Handles links in the chain text (open region, process). |
| `InjectionView.open_process(chain)` | method | Opens the chain's process in the Process Tree. |

### `app/windows/layout_state.py`  (88 lines)

**Purpose:** Remembers window sizes, splitter positions and column widths between sessions.

| Name | Kind | Purpose |
|---|---|---|
| `_enabled(settings)` | function | True when the "remember layout" setting is on. |
| `_section(settings, name)` | function | The saved-layout section of the settings (created when missing). |
| `save_geometry(settings, key, widget)` | function | Saves a window's size and position. |
| `restore_geometry(settings, key, widget)` | function | True when a saved geometry existed and was applied. |
| `_headers(view)` | function | The table headers of a view that can be saved. |
| `capture_columns(settings, view_key, view)` | function | Remember the column widths of every table/tree in a view (only the widths, never sort order or hidden columns). |
| `apply_columns(settings, view_key, view)` | function | Restores saved column widths. |
| `capture_splitters(settings, view_key, view)` | function | Saves splitter positions of a view. |
| `apply_splitters(settings, view_key, view)` | function | Restores saved splitter positions. |

### `app/windows/lifetimes_window.py`  (356 lines)

**Purpose:** The Lifetimes view: one lane per process from start to exit (or to capture), coloured by risk, with zoom.

| Name | Kind | Purpose |
|---|---|---|
| `class Lane` | class | One lane (process, start, end, severity, hidden/running flags, tooltip). |
| `build_lanes(result)` | function | Creates the lanes from the result and returns them with the capture time and the number of processes without a usable start time. |
| `class LaneCanvas(QWidget)` | class | The painted chart. |
| `LaneCanvas.__init__(parent)` | method | Sets up the canvas. |
| `LaneCanvas.set_data(lanes, capture, t0, t1)` | method | Gives the chart its lanes and time range. |
| `LaneCanvas._x(t)` | method | Pixel position of a time. |
| `LaneCanvas.lane_at(y)` | method | The lane at a y position. |
| `LaneCanvas.bar_rect(lane, index)` | method | The rectangle of a lane's bar. |
| `LaneCanvas.paintEvent(event)` | method | Paints the axis, stripes, bars, connectors and the capture line. |
| `LaneCanvas.wheelEvent(event)` | method | Ctrl + wheel zooms the time axis around the mouse pointer; the plain wheel scrolls the lanes (handled by the scroll area). |
| `LaneCanvas.mouseMoveEvent(event)` | method | Shows the tooltip of the lane under the mouse. |
| `LaneCanvas.mousePressEvent(event)` | method | Selects a lane. |
| `LaneCanvas.mouseDoubleClickEvent(event)` | method | Opens the lane's process. |
| `class LifetimesView(QWidget)` | class | The Lifetimes page. |
| `LifetimesView.__init__(result, parent)` | method | Builds filters and the scrolling chart. |
| `LifetimesView._load()` | method | Builds the lanes from the result. |
| `LifetimesView.refresh_after_triage(*_)` | method | Recolours after a triage change. |
| `LifetimesView.refresh(*_)` | method | Applies the filters and redraws. |
| `LifetimesView.on_zoom(t0, t1, *_)` | method | Zooms the time axis to a range. |
| `LifetimesView.reset_zoom(*_)` | method | Shows the whole capture again. |
| `LifetimesView.save_image(*_)` | method | Saves the chart as a PNG. |
| `LifetimesView.open_process(pid)` | method | Opens a process in the Process Tree. |

### `app/windows/motion.py`  (159 lines)

**Purpose:** Everything that moves in the interface: fades, staggered entrances, animated stack, button glow, eased values.

| Name | Kind | Purpose |
|---|---|---|
| `_keep(owner, name, animation)` | function | Remember the running animation on its owner (one per property: a new one replaces the old) so Python does not collect it while it runs. |
| `fade_in(widget, ms, start, delay)` | function | Fade `widget` in from `start` to fully visible. Nothing happens when motion is off or the widget is not on screen. |
| `stagger_in(widgets, ms, step)` | function | Fade the widgets in one after the other, each `step` ms after the one before. |
| `fade_in_later(widget, effect, ms, delay)` | function | Starts a fade after a delay. |
| `animate_geometry(widget, target, ms)` | function | Glide `widget` to `target` (instantly when motion is off). |
| `animate_value(bar, value, ms)` | function | Run a progress bar to `value` (never backwards by animation: a restart goes to its value at once). |
| `class AnimatedStack(QStackedWidget)` | class | A stacked widget that fades the page you switch to. |
| `AnimatedStack.setCurrentIndex(index)` | method | Switches page and fades the new page in. |
| `class GlowFilter(QObject)` | class | Application-wide event filter: a primary button glows (a soft shadow in the accent colour that grows) while the mouse is over it. |
| `GlowFilter.eventFilter(obj, event)` | method | Makes primary buttons glow when the mouse enters and fade when it leaves. |
| `GlowFilter._glow(button, on)` | method | Animates the drop-shadow of a button on or off. |

### `app/windows/network_window.py`  (139 lines)

**Purpose:** The Network view: connections merged from netscan/netstat with filters, bookmarks and notes.

| Name | Kind | Purpose |
|---|---|---|
| `class NetworkView(QWidget)` | class | The Network page. |
| `NetworkView.__init__(result, parent)` | method | Builds filters, table and buttons. |
| `NetworkView._current()` | method | The selected connection. |
| `NetworkView._label(conn)` | method | A text naming a connection for notes. |
| `NetworkView.on_select(*_)` | method | Enables the bookmark/note buttons. |
| `NetworkView.toggle_bookmark_current(*_)` | method | Bookmarks the selected connection. |
| `NetworkView.add_note_current(*_)` | method | Adds a note to the selected connection. |
| `NetworkView.apply(*_)` | method | Applies the state / external-only / listening filters. |
| `_port(value)` | function | Parses a port number text. |

### `app/windows/os_switch.py`  (257 lines)

**Purpose:** The Windows/Linux switch of the start window: two options with a sliding thumb, hover and keyboard control.

| Name | Kind | Purpose |
|---|---|---|
| `_mix(a, b, t)` | function | Blends two colours. |
| `paint_windows_icon(p, box, colour)` | function | The four-pane window flag, a little waved like the logo. |
| `paint_linux_icon(p, box, body, belly)` | function | A small penguin: dark body, light belly, round head with eyes, orange beak and feet. |
| `class OsSwitch(QWidget)` | class | The switch widget. |
| `OsSwitch.__init__(options, current, parent)` | method | Builds the switch from the two options (id and label) and the current one. |
| `OsSwitch.os_id()` | method | The chosen operating system id. |
| `OsSwitch.set_os(os_id, animate, emit)` | method | Chooses an OS (animated) and optionally emits the change signal. |
| `OsSwitch._get_position()` | method | Animation property: thumb position (getter). |
| `OsSwitch._set_position(value)` | method | Animation property: thumb position (setter, repaints). |
| `OsSwitch._get_glow()` | method | Animation property: glow (getter). |
| `OsSwitch._set_glow(value)` | method | Animation property: glow (setter, repaints). |
| `OsSwitch._half(index)` | method | The rectangle of one half of the track. |
| `OsSwitch._track()` | method | The rectangle of the whole track. |
| `OsSwitch.paintEvent(_event)` | method | Paints the track, thumb, icons and labels. |
| `OsSwitch._index_at(x)` | method | Which half an x position is in. |
| `OsSwitch.mousePressEvent(event)` | method | Chooses the clicked half. |
| `OsSwitch.mouseMoveEvent(event)` | method | Tracks which half is hovered. |
| `OsSwitch.leaveEvent(_event)` | method | Clears the hover. |
| `OsSwitch.keyPressEvent(event)` | method | Left/Right/Space switch with the keyboard. |
| `OsSwitch.focusInEvent(event)` | method | Repaints with the focus ring. |
| `OsSwitch.focusOutEvent(event)` | method | Repaints without the focus ring. |

### `app/windows/placeholder_view.py`  (27 lines)

**Purpose:** The page of a navigation entry whose engine code does not exist yet (Linux Files, Injection, Compare).

| Name | Kind | Purpose |
|---|---|---|
| `class PlaceholderView(QWidget)` | class | The "not available yet" page. |
| `PlaceholderView.__init__(engine, spec, parent)` | method | Builds the explanatory text for an engine and view. |

### `app/windows/plugin_output_window.py`  (319 lines)

**Purpose:** The Plugin Output view: every plugin's raw rows in a sortable table or terminal-style text, with bookmarks, notes and re-run of failed plugins.

| Name | Kind | Purpose |
|---|---|---|
| `class PluginOutputView(QWidget)` | class | The Plugin Output page. |
| `PluginOutputView.__init__(result, parent)` | method | Builds the plugin list, table and text stack. |
| `PluginOutputView._rows(index)` | method | The flattened rows of a plugin (cached). |
| `PluginOutputView.show_plugin(index)` | method | Shows a plugin's output. |
| `PluginOutputView._build_table(rows, plugin)` | method | Builds the table for the rows. |
| `PluginOutputView._marked_targets(plugin_name)` | method | The bookmarked/noted rows of a plugin. |
| `PluginOutputView._fill_marks(plugin_name)` | method | Put ★/✎ in the first column. Rows are only hashed when this plugin has marks at all (big plugins have tens of thousands of rows). |
| `PluginOutputView._refresh_marks()` | method | Marks bookmarked rows. |
| `PluginOutputView._current_row()` | method | The selected row. |
| `PluginOutputView._row_label(plugin_name, row)` | method | A short label for a row. |
| `PluginOutputView.on_row_selected(*_)` | method | Enables the row buttons. |
| `PluginOutputView.toggle_bookmark_current(*_)` | method | Bookmarks the selected row. |
| `PluginOutputView.add_note_current(*_)` | method | Adds a note to the selected row. |
| `PluginOutputView.show_plugin_by_name(name)` | method | Selects a plugin by name. |
| `PluginOutputView.select_row_target(target)` | method | Select (and scroll to) the row a bookmark or note refers to, in the plugin that is currently shown. |
| `PluginOutputView.apply_filter(*_)` | method | Filters the rows by text. |
| `PluginOutputView.toggle_mode(checked)` | method | Switches between table and text view. |
| `PluginOutputView.load_more_text(*_)` | method | Loads more of a long text output. |
| `PluginOutputView.rerun_failed(*_)` | method | Re-runs failed plugins through the dashboard. |
| `_cell(value)` | function | Formats a cell value as text. |

### `app/windows/process_tree_window.py`  (617 lines)

**Purpose:** The Process Tree view: a collapsible parent/child tree with colours by risk, filters, a summary panel and image hashing.

| Name | Kind | Purpose |
|---|---|---|
| `short_time(value)` | function | A compact time text for the tree. |
| `class ProcessTreeView(QWidget)` | class | The Process Tree page. |
| `ProcessTreeView.__init__(result, parent)` | method | Builds the tree, filters, summary panel and buttons. |
| `ProcessTreeView._process_images()` | method | The process-image hashing module of the engine (only called when `capabilities.process_images` is true: Windows). |
| `ProcessTreeView._load_findings()` | method | Risk and per-process findings from the findings that are not hidden by triage (false positive / baseline). |
| `ProcessTreeView.refresh_after_triage(*_)` | method | Dashboard hook: a finding was re-judged. Recompute risk colours and the detail panel, keep the selection. |
| `ProcessTreeView._build_relations()` | method | Works out parents, children and roots (ignoring PID reuse). |
| `ProcessTreeView._preorder()` | method | The processes in tree order. |
| `ProcessTreeView._severity(pid)` | method | The severity colour class of a process. |
| `ProcessTreeView._matches(proc, text)` | method | True when a process matches the search text. |
| `ProcessTreeView._visible_set()` | method | The processes that pass the filters (with their ancestors). |
| `ProcessTreeView.rebuild(*_)` | method | Rebuilds the tree from the filters, keeping the selection. |
| `ProcessTreeView._add(parent_item, proc, visible, filtering, placed, depth)` | method | Adds a process and its children recursively. |
| `ProcessTreeView._split_groups(kids, filtering)` | method | Groups repeated sibling processes into one line. |
| `ProcessTreeView._make_item(proc)` | method | Creates the tree item of a process. |
| `ProcessTreeView.smart_expand(*_)` | method | Expands only the branches with findings. |
| `ProcessTreeView.current_pid()` | method | The selected PID. |
| `ProcessTreeView.select_pid(pid)` | method | Selects a process by PID. |
| `ProcessTreeView.on_selection(current, _previous)` | method | Updates the summary panel. |
| `ProcessTreeView.summary_html(proc)` | method | HTML summary of a process (path, user, times, findings). |
| `ProcessTreeView.toggle_bookmark_current(*_)` | method | Bookmarks the selected process. |
| `ProcessTreeView.add_note_current(*_)` | method | Adds a note to the selected process. |
| `ProcessTreeView._refresh_marks(pid)` | method | Update the ★/✎ markers and the detail panel without rebuilding the tree (keeps expansion and scroll). |
| `ProcessTreeView.on_link(url)` | method | Handles links in the summary. |
| `ProcessTreeView.on_activate(item, _column)` | method | Opens the details of a double-clicked process. |
| `ProcessTreeView.open_current(*_)` | method | Opens the details of the selected process. |
| `ProcessTreeView._update_hash_buttons()` | method | Enables the hash buttons. |
| `ProcessTreeView.hash_images(*_)` | method | Dump every process's image with one Volatility run, hash the files and check them against the IOC list. |
| `ProcessTreeView._live_settings()` | method | The current settings. |
| `ProcessTreeView._hashes_done(folder, outcome)` | method | Handles finished hashing of the process images. |
| `ProcessTreeView._hashes_failed(message, details)` | method | Shows a hashing error. |
| `ProcessTreeView.export_image_hashes(*_)` | method | Saves the process image hashes as CSV. |
| `ProcessTreeView.open_pid(pid)` | method | Opens the details window of a PID. |

### `app/windows/process_window.py`  (424 lines)

**Purpose:** The full-details window of one process in tabs: Summary, Modules, Network, Memory, Handles, Libraries/Identity, Story; with dump actions.

| Name | Kind | Purpose |
|---|---|---|
| `class ProcessWindow(QDialog)` | class | The process details dialog. |
| `ProcessWindow.__init__(process, parent, dump_path, findings, volatility_path, iocs, global_args)` | method | Builds the tabs for the process, its findings and the dump actions. |
| `ProcessWindow._story_tab()` | method | Everything known about this process on one clock: who started it, what was written or run around it, its connections, what it started. |
| `ProcessWindow._summary_tab()` | method | The Summary tab: identity, times, findings, story. |
| `ProcessWindow._modules_tab()` | method | The DLL/library list with an "unusual only" filter and bookmarks. |
| `ProcessWindow._dll_marks(dll)` | method | Bookmark/note marks of a module. |
| `ProcessWindow._current_dll()` | method | The selected module. |
| `ProcessWindow._dll_label(dll)` | method | A text naming a module for notes. |
| `ProcessWindow._refresh_dll_marks()` | method | Updates the module list marks. |
| `ProcessWindow._on_dll_selected(*_)` | method | Enables the module buttons. |
| `ProcessWindow.toggle_dll_bookmark(*_)` | method | Bookmarks the selected module. |
| `ProcessWindow.add_dll_note(*_)` | method | Adds a note to the selected module. |
| `ProcessWindow._toggle_unusual(checked)` | method | Shows only unusual modules. |
| `ProcessWindow._network_tab()` | method | The Network tab of the process. |
| `ProcessWindow._memory_tab()` | method | The Memory tab: suspicious regions with hexdump and disassembly preview. |
| `ProcessWindow.open_hex_view(*_)` | method | Opens the hex viewer for the selected region. |
| `ProcessWindow._show_region(*_)` | method | Shows the selected region's details. |
| `ProcessWindow._handles_tab()` | method | The Handles tab. |
| `ProcessWindow._identity_tab()` | method | The Identity tab (owner, session, parent, provenance). |
| `ProcessWindow._set_busy(busy, text)` | method | Disables the dump buttons while a dump runs. |
| `ProcessWindow._run_dump(label, action)` | method | Runs a dump action in the background. |
| `ProcessWindow._dump_done(label, output_dir, result)` | method | Reports a finished dump and its hashes. |
| `ProcessWindow._dump_failed(label, message, details)` | method | Reports a dump failure. |
| `ProcessWindow._dumper()` | method | Creates the engine's dumper for this image. |
| `ProcessWindow.dump_process(*_)` | method | Dumps the process executable. |
| `ProcessWindow.dump_dlls(*_)` | method | Dumps the process modules. |
| `ProcessWindow.dump_memory(*_)` | method | Dumps the suspicious memory pages. |
| `ProcessWindow.dump_handles(*_)` | method | Dumps the files the process has open. |
| `ProcessWindow.show_provenance(*_)` | method | Shows which plugin and row each field came from. |

### `app/windows/progress_window.py`  (200 lines)

**Purpose:** The progress page: bar, status, elapsed time, a per-plugin table, cancel, and a recoverable failure state.

| Name | Kind | Purpose |
|---|---|---|
| `class ProgressWindow(QWidget)` | class | The progress page. |
| `ProgressWindow.__init__(dump_path)` | method | Builds the title, bar, plugin table and buttons. |
| `ProgressWindow.begin(title, dump_path, show_plugins)` | method | Starts a new progress display (title, dump path). |
| `ProgressWindow.set_dump_path(dump_path)` | method | Remembers the dump path shown. |
| `ProgressWindow.set_home(home)` | method | Gives the page the main window for retry/back actions. |
| `ProgressWindow.update_progress(text, value)` | method | Updates the status text and the smooth bar. |
| `ProgressWindow.plugin_event(name, state, detail)` | method | Updates a plugin's row (running / done / failed / cached / skipped). |
| `ProgressWindow._tick(*_)` | method | Updates the elapsed-time label every second. |
| `ProgressWindow._on_cancel(*_)` | method | Asks the controller to cancel. |
| `ProgressWindow._toggle_details(*_)` | method | Shows or hides the failure details. |
| `ProgressWindow.finish_ok()` | method | Shows the finished state. |
| `ProgressWindow.show_failure(message, details)` | method | Shows the error with retry / back options. |
| `ProgressWindow.show_cancelled()` | method | Shows the cancelled state. |

### `app/windows/registry_window.py`  (269 lines)

**Purpose:** The Registry view: browse the registry keys Volatility read, search them and fetch more keys.

| Name | Kind | Purpose |
|---|---|---|
| `class FetchKeyDialog(QDialog)` | class | Asks for a key path (and whether to read its subkeys too). |
| `FetchKeyDialog.__init__(parent, start)` | method | Builds the dialog asking for a key path to fetch. |
| `class RegistryView(QWidget)` | class | The Registry page. |
| `RegistryView.__init__(result, parent)` | method | Builds the key tree, value table and search. |
| `RegistryView.reload(*_)` | method | Rebuilds the tree from the plugin results. |
| `RegistryView._key_selected(current, _previous)` | method | Shows the values of the selected key. |
| `RegistryView._show_values(node, highlight)` | method | Fills the value table (optionally highlighting one). |
| `RegistryView.find_first(*_)` | method | Searches keys and values and selects the first match. |
| `RegistryView.find_next(*_)` | method | Goes to the next match. |
| `RegistryView._settings()` | method | The current settings. |
| `RegistryView.fetch_dialog(*_)` | method | Asks for a key and fetches it with printkey. |
| `RegistryView.fetch_key(key, recurse)` | method | Read `key` from the memory image with `windows.registry.printkey` (in the background) and add the rows to the investigation. |
| `RegistryView._fetched(key, res)` | method | Adds the fetched key to the investigation. |
| `RegistryView._first_node(res)` | method | The first key of a fetched result. |
| `RegistryView._fetch_failed(message, details)` | method | Shows a fetch error. |

### `app/windows/screen_fit.py`  (68 lines)

**Purpose:** Keeps every window inside the screen it opens on (shrinks and moves oversized ones).

| Name | Kind | Purpose |
|---|---|---|
| `_screen_of(widget)` | function | The screen a widget is on. |
| `fit_window(widget, fraction)` | function | Shrink and/or move `widget` so it fits the usable area of its screen. Returns True when anything changed. |
| `class ScreenFit(QObject)` | class | Application event filter: fits each top-level window to the screen the first time (and every time) it is shown. |
| `ScreenFit.eventFilter(obj, event)` | method | Fits each top-level window when it is shown. |
| `install(app)` | function | Installs the filter on the application. |

### `app/windows/search_window.py`  (140 lines)

**Purpose:** Global search across processes, modules, endpoints, findings, users and plugins.

| Name | Kind | Purpose |
|---|---|---|
| `class RelatedDetails(QDialog)` | class | Dialog listing everything related to a search hit. |
| `RelatedDetails.__init__(title, text, parent)` | method | Builds the text dialog. |
| `class GlobalSearchView(QWidget)` | class | The Search page. |
| `GlobalSearchView.__init__(result, parent)` | method | Builds the query box and result table. |
| `GlobalSearchView._collect(text)` | method | Finds all matches for a text. |
| `GlobalSearchView.refresh(text)` | method | Re-runs the search and fills the table. |
| `GlobalSearchView.open_result(index)` | method | Opens the item of a result row. |
| `GlobalSearchView._dll_text(dll)` | method | Text describing a module match. |
| `GlobalSearchView._network_text(conn)` | method | Text describing a connection match. |

### `app/windows/settings_window.py`  (591 lines)

**Purpose:** The Settings page of the main window: sidebar with Appearance, Volatility, Plugins, Indicators and Performance pages.

| Name | Kind | Purpose |
|---|---|---|
| `_small(text, tip)` | function | Creates a small button. |
| `_path_row(edit, *buttons)` | function | A row with a path box and its buttons. |
| `member_summary(bundle, registry)` | function | The plugins behind a bundle, short: `pslist · psscan · registry keys (Run, ...)`. |
| `class SettingsWindow(QWidget)` | class | The settings *page*: it is shown inside the main window (in its page stack), not in a window of its own. `done(applied)` is emitted by Apply / Cancel / Esc; the main window then goes back to the page it came from. |
| `SettingsWindow.__init__(parent)` | method | Builds the sidebar, page header, pages and footer buttons. |
| `SettingsWindow.accept()` | method | Signals "applied" so the main window leaves the page. |
| `SettingsWindow.reject()` | method | Signals "cancelled". |
| `SettingsWindow.keyPressEvent(event)` | method | Esc goes back without saving. |
| `SettingsWindow._show_page(row, *_)` | method | Shows a page and updates the title and description. |
| `SettingsWindow._scroll_page(page)` | method | Wraps a page in a scroll area. |
| `SettingsWindow._page(*groups)` | method | Lays out the groups of a page. |
| `SettingsWindow._page_appearance()` | method | The Appearance page: font size, remembered layout, result options. |
| `SettingsWindow._page_volatility()` | method | The Volatility page: paths, symbol folders, Volatility 2 for XP. |
| `SettingsWindow._page_plugins()` | method | The Plugins page: presets and the plugin bundles. |
| `SettingsWindow._set_bundles(wanted)` | method | Tick exactly the bundles `wanted` (the always-on ones stay on) and say how long that takes on an image of the usual size. |
| `SettingsWindow.preset_quick(*_)` | method | Ticks only processes, network and injected code. |
| `SettingsWindow.preset_default(*_)` | method | Ticks the recommended groups. |
| `SettingsWindow.preset_all(*_)` | method | Ticks every group. |
| `SettingsWindow._bundle_row(bundle)` | method | One bundle row with its description and plugins. |
| `SettingsWindow._page_indicators()` | method | The Indicators page: IOC lists. |
| `SettingsWindow._page_performance()` | method | The Performance page: parallelism, timeouts, cache and logs. |
| `SettingsWindow._cache_text()` | method | Text with the cache size. |
| `SettingsWindow.clear_cache(*_)` | method | Deletes the plugin cache. |
| `SettingsWindow.open_logs(*_)` | method | Opens the log folder. |
| `SettingsWindow.add_symbol_dir(*_)` | method | Adds a symbol folder. |
| `SettingsWindow.make_yara_from_iocs(*_)` | method | Write a YARA file that finds the IOC list's domains / IPs / mutex names in memory, and use it for windows.vadyarascan. |
| `SettingsWindow.browse_yara(*_)` | method | Chooses the YARA rule file. |
| `SettingsWindow.add_ioc_file(*_)` | method | Adds an IOC list file. |
| `SettingsWindow.browse_volatility(*_)` | method | Chooses Volatility 3. |
| `SettingsWindow.browse_vol2(*_)` | method | Chooses Volatility 2. |
| `SettingsWindow.browse_python2(*_)` | method | Chooses Python 2.7. |
| `SettingsWindow.test_volatility(*_)` | method | Tests the Volatility 3 path in the background. |
| `SettingsWindow._test_ok(text)` | method | Shows a successful test. |
| `SettingsWindow._test_failed(message, _details)` | method | Shows a failed test. |
| `SettingsWindow.test_vol2(*_)` | method | Tests Volatility 2 in the background. |
| `SettingsWindow.apply_and_close(*_)` | method | Reads every control, saves the settings, applies the font size and leaves the page. |
| `SettingsWindow.reset_layout(*_)` | method | Forgets the saved window layout. |

### `app/windows/splash_window.py`  (51 lines)

**Purpose:** The start-up splash screen with the logo and a fade/progress animation.

| Name | Kind | Purpose |
|---|---|---|
| `class SplashWindow(QDialog)` | class | The splash dialog. |
| `SplashWindow.__init__()` | method | Builds the logo and bar. |
| `SplashWindow.showEvent(event)` | method | Starts the entrance animation. |

### `app/windows/system_info_window.py`  (93 lines)

**Purpose:** The Computer Info view: key facts of the machine first, then the full info table and identities.

| Name | Kind | Purpose |
|---|---|---|
| `describe_os(info)` | function | A readable operating-system text from the info rows. |
| `class SystemInfoView(QWidget)` | class | The Computer Info page. |
| `SystemInfoView.__init__(result, parent)` | method | Builds the facts, info table and identities. |

### `app/windows/timeline_window.py`  (423 lines)

**Purpose:** The Timeline view: an activity chart you can drag a range on, plus a filterable event table with export.

| Name | Kind | Purpose |
|---|---|---|
| `category_color(category, known)` | function | The colour of a timeline category. |
| `class ActivityChart(QWidget)` | class | Stacked histogram of events over time with drag-to-select. |
| `ActivityChart.__init__(parent)` | method | Sets up the chart. |
| `ActivityChart.set_events(points, categories, capture)` | method | Gives the chart its events, categories and capture time. |
| `ActivityChart.clear_selection()` | method | Removes the selected range. |
| `ActivityChart._plot()` | method | The plotting rectangle. |
| `ActivityChart._x_of(t)` | method | Pixel of a time. |
| `ActivityChart._t_of(x)` | method | Time of a pixel. |
| `ActivityChart.paintEvent(event)` | method | Paints the stacked bars, axis, capture marker and selection. |
| `ActivityChart.mousePressEvent(event)` | method | Starts selecting a range. |
| `ActivityChart.mouseMoveEvent(event)` | method | Extends the range. |
| `ActivityChart.mouseReleaseEvent(event)` | method | Finishes the range and emits it. |
| `ActivityChart.mouseDoubleClickEvent(event)` | method | Clears the range. |
| `class TimelineView(QWidget)` | class | The Timeline page. |
| `TimelineView.__init__(result, parent)` | method | Builds chart, filters, table and details. |
| `TimelineView.on_filter_changed(*_)` | method | Re-applies the filters. |
| `TimelineView.on_range(selection)` | method | Applies a range chosen on the chart. |
| `TimelineView.on_quick(index)` | method | Applies a quick range ("last hour before capture"...). |
| `TimelineView.apply_filters()` | method | Filters events by category, text, flagged processes and range. |
| `TimelineView.on_select(*_)` | method | Shows the details of the selected event. |
| `TimelineView._selected_event()` | method | The selected event. |
| `TimelineView.toggle_event_bookmark(*_)` | method | Bookmarks the event. |
| `TimelineView.add_event_note(*_)` | method | Adds a note to the event. |
| `TimelineView.export_csv(*_)` | method | Saves the shown events as CSV. |

### `app/windows/widgets.py`  (370 lines)

**Purpose:** Reusable GUI pieces shared by all views: tables and models, flow layout, labels, info cards, message boxes.

| Name | Kind | Purpose |
|---|---|---|
| `escape(value)` | function | HTML-escapes text. |
| `decoded_command_html(command_line, pid)` | function | HTML block with the decoded `-EncodedCommand` payload, or '' when the command line has none. Shows where the text came from; the original command line stays the evidence. |
| `severity_color(severity)` | function | Colour of a severity. |
| `badge_html(severity, text)` | function | HTML badge of a severity. |
| `class FlowLayout(QLayout)` | class | Lays widgets out left to right and wraps to the next line when the row is full. |
| `FlowLayout.__init__(parent, h_spacing, v_spacing)` | method | Creates a wrapping layout. |
| `FlowLayout.addItem(item)` | method | Adds an item. |
| `FlowLayout.count()` | method | Number of items. |
| `FlowLayout.itemAt(index)` | method | Item by index. |
| `FlowLayout.takeAt(index)` | method | Removes an item. |
| `FlowLayout.expandingDirections()` | method | No expansion. |
| `FlowLayout.hasHeightForWidth()` | method | Says the height depends on the width. |
| `FlowLayout.heightForWidth(width)` | method | The height needed for a width. |
| `FlowLayout.setGeometry(rect)` | method | Places the items. |
| `FlowLayout.sizeHint()` | method | Preferred size. |
| `FlowLayout.minimumSize()` | method | Minimum size. |
| `FlowLayout._arrange(rect, apply)` | method | Places items in wrapping rows. |
| `compact_combo(combo, chars)` | function | A combo box whose width follows `chars` characters instead of its longest item (long items would widen the window). |
| `class ElidedLabel(QLabel)` | class | One-line label that shortens long text with "…" (full text in the tooltip) instead of forcing its window wider. |
| `ElidedLabel.minimumSizeHint()` | method | Allows the label to shrink. |
| `ElidedLabel.paintEvent(event)` | method | Draws the text with "…" when too long. |
| `muted(text, wrap)` | function | A grey explanatory label (wrapping or elided). |
| `section_title(text)` | function | A section heading label. |
| `banner(text, kind)` | function | A coloured warning/error banner label. |
| `info_card(title, value, severity)` | function | A card showing a number and its title. |
| `show_error(parent, title, message, details)` | function | Shows an error box with optional details. |
| `show_info(parent, title, message)` | function | Shows an information box. |
| `confirm(parent, title, message)` | function | Asks a yes/no question. |
| `_auto_sort_value(value)` | function | Numbers sort numerically, everything else case-insensitively (numbers first). |
| `class TableModel(QAbstractTableModel)` | class | Read-only model over a list of rows. |
| `TableModel.__init__(columns, rows, sort_rows, payloads, colors, parent, icons, icon_column)` | method | Creates a table model from columns and rows (with payloads, colours, sort keys). |
| `TableModel.rowCount(parent)` | method | Number of rows. |
| `TableModel.columnCount(parent)` | method | Number of columns. |
| `TableModel.headerData(section, orientation, role)` | method | Column titles. |
| `TableModel.data(index, role)` | method | Cell text, colour, tooltip and sort key. |
| `TableModel.row_values(source_row)` | method | The values of a source row. |
| `TableModel.payload(source_row)` | method | The object attached to a row. |
| `class FilterProxy(QSortFilterProxyModel)` | class | Sorting on `SORT_ROLE`, free-text filter over all columns and an optional predicate. |
| `FilterProxy.__init__(parent)` | method | Creates the sorting/filtering proxy. |
| `FilterProxy.set_text(text)` | method | Sets the text filter. |
| `FilterProxy.set_predicate(predicate)` | method | Sets an extra row filter function (payload, values) -> bool, or removes it with None. |
| `FilterProxy.filterAcceptsRow(source_row, source_parent)` | method | Accepts rows that match the text and predicate. |
| `FilterProxy.lessThan(left, right)` | method | Compares by the sort key so numbers sort as numbers. |
| `FilterProxy.payload_at(index)` | method | Payload of the row behind a *proxy* index (as delivered by view signals). |
| `make_table(model, widths, sort_column, descending)` | function | Build a ready-to-use `(QTableView, FilterProxy)` pair for `model`. |


---

## tools/realworld - real-world testing and reporting

*Scripts that run MemoryGraph on real or synthetic images and write the testing report (they work offline).*

### `tools/realworld/checks.py`  (327 lines)

**Purpose:** Checks that compare MemoryGraph's result with the raw Volatility output it came from (process counts, DLLs, malfind, network, handles) and evaluate "expected facts" about an image.

| Name | Kind | Purpose |
|---|---|---|
| `class Check` | class | One check outcome (area, name, status, detail, items). |
| `Check.as_dict()` | method | The check as a plain dictionary for the report. |
| `N(result, key)` | function | The name of the plugin that answers `key` for the operating system of `result`. |
| `plugin(result, name)` | function | The completed plugin result called `name` (None when it did not run or did not complete). |
| `_first(row, *keys, default)` | function | First non-empty value of several keys. |
| `_text(value)` | function | Cleans a cell to text ("None", "N/A" and "-" become empty). |
| `check_processes(result)` | function | Compares the processes of the result with pslist/psscan rows. |
| `check_dlls(result)` | function | Compares loaded modules with dlllist rows. |
| `check_memory(result)` | function | Compares memory regions with malfind rows. |
| `_addr(value)` | function | Normalizes an address for comparison. |
| `_proto(value)` | function | Normalizes a protocol name (strips v4/v6). |
| `check_network(result)` | function | Compares connections with netscan/netstat rows. |
| `check_handles(result)` | function | Compares handles with handles-plugin rows. |
| `classify_plugin(p)` | function | Gives a plugin result a category (OK, failed, symbols missing...) using only Volatility's own words. |
| `plugin_table(result)` | function | A table of every plugin with status, rows and time. |
| `all_checks(result)` | function | Runs every check. |
| `_matching_processes(result, fact)` | function | The processes that match an expected-fact description. |
| `_fact_requirements(result, fact)` | function | Which plugins a fact needs (so it can be marked inconclusive when they did not run). |
| `evaluate_fact(result, fact)` | function | Decides whether one expected fact is confirmed, contradicted or inconclusive. |
| `evaluate_facts(result, facts)` | function | Evaluates a list of facts into report rows. |
| `review_findings(result, review)` | function | Every visible finding with a verdict taken from the expected-results file (True Positive / False Positive); anything not listed there is 'Unreviewed', never guessed. |

### `tools/realworld/report_builder.py`  (297 lines)

**Purpose:** Builds the testing report (Markdown and HTML) from the results of a run: per-image results, scores, rule outcomes and recommendations; works offline.

| Name | Kind | Purpose |
|---|---|---|
| `_pct(part, whole)` | function | Formats a percentage. |
| `_rate_score(passed, failed)` | function | A 0-10 score from passed and failed counts. |
| `_score_text(score)` | function | Text of a score ("not measured" when none). |
| `_cell(value)` | function | Cleans text for a Markdown table cell. |
| `collect(entries, scenarios)` | function | Totals over every tested dump (and the synthetic scenarios). |
| `scores(t)` | function | Computes the 0-10 scores per category with an explanation of how much data they rest on; "not measured" when there is none. |
| `recommendations(t, scenarios)` | function | Turns the run totals into prioritized recommendations. |
| `build_markdown(entries, env, scenarios, title, note)` | function | Writes the whole report as Markdown. |
| `_inline(text)` | function | Converts light Markdown (bold, code) to HTML. |
| `markdown_to_html(md, title)` | function | The small Markdown subset the report uses (headings, tables, lists, bold, code), as one HTML file with its own style and no external resource. |

### `tools/realworld/run_realworld.py`  (181 lines)

**Purpose:** Runs MemoryGraph on real images through the actual program code and writes a comparison with the raw Volatility output.

| Name | Kind | Purpose |
|---|---|---|
| `load_json(path)` | function | Reads a JSON file. |
| `locate(entry, dumps_dir)` | function | Finds the image file of a manifest entry. |
| `environment(settings)` | function | Describes the versions of Volatility, Python and the libraries. |
| `_version(module)` | function | Version of a Python module. |
| `make_settings(profile, os_id)` | function | Builds the settings of a run for a profile and operating system. |
| `run_one(entry, path, settings, out_dir, expected, with_ui)` | function | Analyses one image, runs the checks and the UI checks and returns its report entry. |
| `_profile(result)` | function | What the engine says about the image's operating system (Windows adds the structured profile). |
| `write_report(out_dir, report)` | function | Writes report.json and the Markdown report. |
| `main(argv)` | function | Command-line entry point. |

### `tools/realworld/run_report.py`  (199 lines)

**Purpose:** The offline report script: analyses images given on the command line (or a folder / the manifest / synthetic scenarios) and writes the report without internet.

| Name | Kind | Purpose |
|---|---|---|
| `slug(text)` | function | Makes a safe file-name part. |
| `sha256_of(path)` | function | SHA-256 of a file. |
| `preflight(volatility, out_dir, dumps)` | function | Checks everything the run needs (Volatility, folders, images) without any network and returns OK/WARN/PROBLEM lines. |
| `expected_for(path, entry_id, explicit)` | function | Finds the expected-results file of an image. |
| `analyse(entry, path, settings, out_dir, explicit_expected, with_ui)` | function | Analyses one image and returns its entry. |
| `main(argv)` | function | Command-line entry point. |

### `tools/realworld/scenarios.py`  (283 lines)

**Purpose:** Synthetic malware-shaped memory images (as plugin rows) used to check that the rules fire on the behaviours they are meant for.

| Name | Kind | Purpose |
|---|---|---|
| `win(*parts)` | function | Joins parts into a Windows path. |
| `class Image` | class | A small Windows 10 x64 memory image made of plugin rows (built up by the scenarios). |
| `Image.__init__()` | method | Starts an empty fake image. |
| `Image.process(pid, ppid, name, image, cmdline, created, session, threads, visible, exited, libraries)` | method | Adds a process to pslist/psscan/cmdline rows. |
| `Image.dll(pid, process, name, path, loaded)` | method | Adds a loaded module row. |
| `Image.malfind(pid, process, start, size, hexdump, protection)` | method | Adds a malfind row. |
| `Image.connection(pid, owner, remote, port, state, local, lport)` | method | Adds a network row. |
| `Image.handle(holder, holder_name, target, access)` | method | Adds a handle row. |
| `Image.plugin(name, rows)` | method | Adds rows of any plugin. |
| `Image._clean_system()` | method | Adds a normal, clean set of Windows system processes. |
| `Image.results()` | method | The rows as PluginResult objects. |
| `class Expectation` | class | What a scenario must (or must not) produce. |
| `class Scenario` | class | A named scenario with its builder and expectations. |
| `s_clean(img)` | function | A clean machine (must produce no High finding). |
| `sys32_path(name)` | function | Path of a file in System32. |
| `s_injection(img)` | function | Process injection by an unknown program. |
| `s_hollowing(img)` | function | A hollowed svchost. |
| `s_hidden(img)` | function | A hidden process. |
| `s_persistence(img)` | function | Run-key persistence. |
| `s_macro_dropper(img)` | function | Office spawning a script that downloads code. |
| `s_kernel_rootkit(img)` | function | A hidden kernel driver and system-call hooks. |
| `s_masquerade(img)` | function | A fake svchost from a public folder. |
| `s_portable_tool(img)` | function | A program run from the user's desktop. |
| `s_benign_lookalikes(img)` | function | Things that looked like malware on real images and were not (the false positives found by running MemoryGraph on a real Windows 10 and a real Windows XP image). |
| `run_scenario(scenario)` | function | Run one scenario through the real Windows engine; returns what was found and how each expectation did. |
| `run_all()` | function | Runs every scenario and returns the outcomes. |

### `tools/realworld/ui_checks.py`  (102 lines)

**Purpose:** Checks on the real dashboard windows: whether what was computed actually reaches the screen (counts in the process tree, findings, network, timeline).

| Name | Kind | Purpose |
|---|---|---|
| `_count_tree(tree)` | function | Counts the items of a tree widget. |
| `run(result)` | function | Builds the dashboard offscreen and compares what its views show with the result. |


---

## tests - automated tests

*The pytest suite and the fake Volatility programs it uses.*

### `tests/conftest.py`  (42 lines)

**Purpose:** Shared pytest set-up: isolated MemoryGraph home folder, blocked modal dialogs and switched-off animations for every test.

| Name | Kind | Purpose |
|---|---|---|
| `isolated_memorygraph_home(tmp_path_factory, monkeypatch)` | function | Every test gets its own empty MemoryGraph home (settings, cache, known-good lists): a test never reads or changes the real ~/.memorygraph. |
| `no_blocking_dialogs(monkeypatch)` | function | A modal message box in a headless test waits for a click that never comes and the whole run hangs. Any dialog a test did not replace itself fails the test at once. |
| `no_motion(monkeypatch)` | function | Animations make a test wait for the event loop; motion is off unless a test asks for it (tests/test_engines.py and tests/test_motion.py do). |

### `tests/fake_vol.py`  (92 lines)

**Purpose:** A stand-in for the `vol` command that imitates Volatility 3 (JSON output, crashes, hangs, bad JSON, missing symbols, slow progress) so the collection path is tested without an image.

| Name | Kind | Purpose |
|---|---|---|
| `main(argv)` | function | Plays the behaviour chosen by environment variables. |

### `tests/fake_vol2.py`  (57 lines)

**Purpose:** A stand-in for Volatility 2 (imageinfo, netscan-style output) for the XP network tests.

| Name | Kind | Purpose |
|---|---|---|
| `main(argv)` | function | Plays the behaviour chosen by environment variables. |

### `tests/test_analysis_provider.py`  (22 lines)

**Purpose:** Tests of the demo provider and the basic pipeline result.

| Name | Kind | Purpose |
|---|---|---|
| `test_demo_provider_returns_normalized_investigation()` | function | Test: Demo provider returns normalized investigation. |
| `test_benign_scenario_has_no_findings()` | function | Test: Benign scenario has no findings. |
| `test_demo_attack_chain_is_correlated_once_per_process()` | function | Test: Demo attack chain is correlated once per process. |

### `tests/test_case_and_ioc.py`  (451 lines)

**Purpose:** Tests of triage, notes, bookmarks, baselines and the IOC list family (IP, domain, mutex, file, hash, YARA).

| Name | Kind | Purpose |
|---|---|---|
| `fresh()` | function | A fresh result to test on. |
| `finding(result, rule_id, pid)` | function | Finds one finding of a result. |
| `test_false_positive_leaves_scores_and_survives_reanalysis_and_save_load(tmp_path)` | function | Test: False positive leaves scores and survives reanalysis and save load. |
| `test_reviewed_keeps_counting_reopen_restores_and_status_is_validated()` | function | Test: Reviewed keeps counting reopen restores and status is validated. |
| `test_finding_keys_distinguish_reused_pids_and_signatures_ignore_pids()` | function | Test: Finding keys distinguish reused pids and signatures ignore pids. |
| `test_garbled_or_missing_case_data_is_tolerated(tmp_path)` | function | Test: Garbled or missing case data is tolerated. |
| `test_rerun_of_failed_plugins_keeps_the_investigators_work(tmp_path)` | function | Test: Rerun of failed plugins keeps the investigators work. |
| `test_notes_bookmarks_and_markdown_report(tmp_path)` | function | Test: Notes bookmarks and markdown report. |
| `test_baseline_from_a_clean_dump_suppresses_the_same_findings_elsewhere(tmp_path)` | function | Test: Baseline from a clean dump suppresses the same findings elsewhere. |
| `test_baseline_from_false_positives_only_and_bad_files(tmp_path)` | function | Test: Baseline from false positives only and bad files. |
| `test_ioc_list_parsing_normalises_and_reports_bad_lines()` | function | Test: Ioc list parsing normalises and reports bad lines. |
| `test_ioc_matching_rules()` | function | Test: Ioc matching rules. |
| `test_ioc_files_from_settings(tmp_path)` | function | Test: Ioc files from settings. |
| `iocs(text)` | function | Builds an IOC set from text. |
| `evaluate(result, ioc_set)` | function | Runs the IOC rules on a result. |
| `test_ioc_rules_never_change_the_behavioural_findings()` | function | Test: Ioc rules never change the behavioural findings. |
| `test_ioc_findings_are_not_fed_into_behavioural_correlation()` | function | Test: Ioc findings are not fed into behavioural correlation. |
| `test_ioc_domain_mutex_file_and_yara_rules()` | function | Test: Ioc domain mutex file and yara rules. |
| `test_without_an_ioc_list_only_yara_hits_can_appear()` | function | Test: Without an ioc list only yara hits can appear. |
| `test_ioc_rules_end_to_end_through_the_provider_and_reanalysis(tmp_path)` | function | Test: Ioc rules end to end through the provider and reanalysis. |
| `test_ioc_family_is_catalogued_and_has_explicit_attack_entries()` | function | Test: Ioc family is catalogued and has explicit attack entries. |
| `with_plugins(*plugins)` | function | A result with extra plugin rows. |
| `by_rule(result, rule_id)` | function | The findings of one rule. |
| `test_file_object_rule_groups_and_ignores_normal_files()` | function | Test: File object rule groups and ignores normal files. |
| `test_userassist_rule()` | function | Test: Userassist rule. |
| `test_run_key_rule_reads_every_printkey_invocation()` | function | Test: Run key rule reads every printkey invocation. |
| `test_environment_rule_groups_by_odd_value()` | function | Test: Environment rule groups by odd value. |
| `test_driver_object_rule()` | function | Test: Driver object rule. |
| `test_ssdt_rule_finds_foreign_modules_and_holes()` | function | Test: Ssdt rule finds foreign modules and holes. |
| `test_callback_rule()` | function | Test: Callback rule. |
| `test_unlisted_image_rule_needs_dlllist_and_ignores_wow64_and_private_maps()` | function | Test: Unlisted image rule needs dlllist and ignores wow64 and private maps. |
| `run_with(tmp_path, data_extra, **settings_extra)` | function | Runs the provider with fake plugin data and settings. |
| `test_run_keys_choice_runs_printkey_four_times_with_arguments(tmp_path)` | function | Test: Run keys choice runs printkey four times with arguments. |
| `test_vadyarascan_needs_a_rule_file_and_passes_it_on(tmp_path)` | function | Test: Vadyarascan needs a rule file and passes it on. |
| `test_missing_yara_dependency_is_reported_as_unavailable_plugin(tmp_path)` | function | Test: Missing yara dependency is reported as unavailable plugin. |

### `tests/test_case_gui.py`  (187 lines)

**Purpose:** GUI tests of triage buttons, case notes, bookmarks and settings bundles.

| Name | Kind | Purpose |
|---|---|---|
| `app()` | function | The Qt application fixture. |
| `dashboard(app)` | function | A dashboard on the fixture result. |
| `click(widget, text)` | function | Clicks the button with a text. |
| `answer_note(monkeypatch, text, ok)` | function | Makes the note dialog answer with a text. |
| `test_false_positive_flow_updates_every_view(app, dashboard)` | function | Test: False positive flow updates every view. |
| `test_only_not_yet_reviewed_and_family_filters(app, dashboard)` | function | Test: Only not yet reviewed and family filters. |
| `test_process_tree_bookmark_and_note(app, dashboard, monkeypatch)` | function | Test: Process tree bookmark and note. |
| `test_timeline_event_bookmark_and_note(app, dashboard, monkeypatch)` | function | Test: Timeline event bookmark and note. |
| `test_case_view_remove_reopens_a_decision_and_exports(app, dashboard, tmp_path, monkeypatch)` | function | Test: Case view remove reopens a decision and exports. |
| `test_baseline_import_through_the_case_view(app, dashboard, tmp_path, monkeypatch)` | function | Test: Baseline import through the case view. |
| `test_unsaved_case_work_is_tracked_and_cleared_on_save(app, dashboard)` | function | Test: Unsaved case work is tracked and cleared on save. |
| `test_settings_window_bundles_yara_and_ioc_lists(app, monkeypatch)` | function | Test: Settings window bundles yara and ioc lists. |
| `test_dump_result_reports_hash_ioc_matches(app, monkeypatch)` | function | Test: Dump result reports hash ioc matches. |

### `tests/test_engines.py`  (328 lines)

**Purpose:** Tests of the engine split: Windows engine, Linux skeleton, the OS switch, per-OS settings and saved investigations.

| Name | Kind | Purpose |
|---|---|---|
| `instant_switch()` | function | The switch animates by default; every test but the animation test wants an instant change. |
| `linux_result()` | function | A Linux-flagged result. |
| `test_engines_are_found_by_id_by_result_and_by_settings_and_unknown_means_windows()` | function | Test: Engines are found by id by result and by settings and unknown means windows. |
| `test_both_engines_implement_the_whole_interface_and_only_linux_is_a_skeleton()` | function | Test: Both engines implement the whole interface and only linux is a skeleton. |
| `test_the_windows_engine_does_what_the_pipeline_asks_of_it()` | function | Test: The windows engine does what the pipeline asks of it. |
| `test_every_linux_function_exists_and_says_what_is_missing()` | function | Test: Every linux function exists and says what is missing. |
| `test_the_linux_plugin_list_is_consistent_and_works_with_the_same_settings_keys()` | function | Test: The linux plugin list is consistent and works with the same settings keys. |
| `test_a_linux_analysis_fails_with_a_message_not_a_crash(app, tmp_path)` | function | Test: A linux analysis fails with a message not a crash. |
| `test_the_pipeline_given_the_linux_engine_stops_with_the_missing_function(tmp_path)` | function | Test: The pipeline given the linux engine stops with the missing function. |
| `test_switching_the_operating_system_swaps_only_the_settings_that_belong_to_one()` | function | Test: Switching the operating system swaps only the settings that belong to one. |
| `test_the_operating_system_is_saved_with_the_investigation_and_old_files_mean_windows(tmp_path)` | function | Test: The operating system is saved with the investigation and old files mean windows. |
| `test_the_switch_changes_by_click_key_and_code_and_says_so_once(app)` | function | Test: The switch changes by click key and code and says so once. |
| `test_the_switch_really_animates_when_animation_is_on(app)` | function | Test: The switch really animates when animation is on. |
| `test_the_start_window_follows_the_switch_in_words_filter_settings_and_file(app, tmp_path)` | function | Test: The start window follows the switch in words filter settings and file. |
| `test_a_saved_investigation_of_the_other_operating_system_moves_the_switch(app)` | function | Test: A saved investigation of the other operating system moves the switch. |
| `test_the_dashboard_of_a_linux_investigation_has_no_registry_and_placeholders_where_the_engine_is_missing(app)` | function | Test: The dashboard of a linux investigation has no registry and placeholders where the engine is missing. |
| `test_the_process_window_uses_the_words_of_the_operating_system(app)` | function | Test: The process window uses the words of the operating system. |
| `test_settings_show_the_plugin_groups_and_pages_of_the_chosen_operating_system(app, monkeypatch)` | function | Test: Settings show the plugin groups and pages of the chosen operating system. |
| `test_one_settings_object_never_changes_the_defaults_of_the_next()` | function | Test: One settings object never changes the defaults of the next. |

### `tests/test_gui_polish.py`  (327 lines)

**Purpose:** Tests of motion, the navigation marker, the start window layout, the Linux demo and the settings page.

| Name | Kind | Purpose |
|---|---|---|
| `motion_on(monkeypatch)` | function | Switches animations on for a test. |
| `instant_switch(monkeypatch)` | function | Makes the OS switch instant. |
| `test_a_fade_appears_runs_and_removes_its_effect_and_is_skipped_when_motion_is_off(app, motion_on, monkeypatch)` | function | Test: A fade appears runs and removes its effect and is skipped when motion is off. |
| `test_the_progress_bar_runs_forwards_and_jumps_back(app, motion_on)` | function | Test: The progress bar runs forwards and jumps back. |
| `test_a_page_change_in_the_animated_stack_fades_the_new_page(app, motion_on)` | function | Test: A page change in the animated stack fades the new page. |
| `test_a_primary_button_glows_under_the_mouse_and_other_buttons_do_not(app, motion_on)` | function | Test: A primary button glows under the mouse and other buttons do not. |
| `test_the_navigation_marker_sits_beside_the_selected_entry(app)` | function | Test: The navigation marker sits beside the selected entry. |
| `test_the_theme_draws_its_tick_for_checked_boxes_into_the_home_folder()` | function | Test: The theme draws its tick for checked boxes into the home folder. |
| `test_no_control_of_the_start_window_overlaps_another_at_any_size(app, size)` | function | Test: No control of the start window overlaps another at any size. |
| `test_the_start_window_keeps_its_content_in_a_centred_column_of_limited_width(app)` | function | Test: The start window keeps its content in a centred column of limited width. |
| `test_the_demo_button_exists_only_for_the_operating_system_that_has_a_demo(app)` | function | Test: The demo button exists only for the operating system that has a demo. |
| `test_the_demo_investigation_is_coherent_made_up_and_says_so()` | function | Test: The demo investigation is coherent made up and says so. |
| `test_opening_the_demo_shows_a_linux_dashboard_with_every_view_working(app)` | function | Test: Opening the demo shows a linux dashboard with every view working. |
| `test_every_demo_process_window_and_finding_opens(app)` | function | Test: Every demo process window and finding opens. |
| `test_the_settings_window_has_a_sidebar_a_page_header_and_fits_a_small_screen(app)` | function | Test: The settings window has a sidebar a page header and fits a small screen. |
| `test_the_settings_open_inside_the_main_window_and_go_back_to_the_page_they_came_from(app, monkeypatch)` | function | Test: The settings open inside the main window and go back to the page they came from. |

### `tests/test_hexview.py`  (335 lines)

**Purpose:** Tests of the hex viewer helpers and dialog (parsing, search, disassembly, bookmarks).

| Name | Kind | Purpose |
|---|---|---|
| `test_parse_hexdump_reads_the_json_layout_and_volatility_text_layout_and_offsets()` | function | Test: Parse hexdump reads the json layout and volatility text layout and offsets. |
| `test_ascii_column_letters_do_not_become_bytes_in_the_malfind_rule()` | function | The old rule helper stripped every non-hex character, so the letters a-f of an ASCII column became extra 'bytes'. |
| `test_layout_maps_text_positions_to_offsets_and_back()` | function | Test: Layout maps text positions to offsets and back. |
| `test_search_hex_wildcards_text_utf16_and_wrap_around()` | function | Test: Search hex wildcards text utf16 and wrap around. |
| `test_disassembly_covers_more_than_the_stored_bytes_and_resynchronises()` | function | Test: Disassembly covers more than the stored bytes and resynchronises. |
| `test_disassembly_without_capstone_explains_itself(monkeypatch)` | function | Test: Disassembly without capstone explains itself. |
| `test_dump_file_lookup_by_malfind_naming(tmp_path)` | function | Test: Dump file lookup by malfind naming. |
| `app()` | function | The Qt application fixture. |
| `dispose(app, *windows)` | function | Close AND delete windows: an app-wide stylesheet change re-polishes every widget that is still alive, so leftovers slow later tests. |
| `dashboard(app)` | function | A dashboard on the fixture result. |
| `select_payload(view, proxy, wanted, key)` | function | Select the row whose payload is `wanted` (the tables sort themselves, so row numbers say nothing about the data). |
| `answer_note(monkeypatch, text)` | function | Makes the note dialog answer. |
| `process_window(dashboard, app, pid)` | function | Opens a process window. |
| `test_hex_view_shows_offsets_finds_bytes_and_disassembles(app, dashboard, monkeypatch, tmp_path)` | function | Test: Hex view shows offsets finds bytes and disassembles. |
| `test_hex_view_region_bookmark_and_note_are_listed_in_case_notes(app, dashboard, monkeypatch)` | function | Test: Hex view region bookmark and note are listed in case notes. |
| `test_dll_bookmark_and_note_show_marks_and_survive_save_load(app, dashboard, monkeypatch, tmp_path)` | function | Test: Dll bookmark and note show marks and survive save load. |
| `test_process_window_without_an_investigation_disables_module_marks(app)` | function | Test: Process window without an investigation disables module marks. |
| `test_plugin_row_bookmark_note_marks_and_jump_from_case_notes(app, dashboard, monkeypatch)` | function | Test: Plugin row bookmark note marks and jump from case notes. |

### `tests/test_indicators_and_network.py`  (123 lines)

**Purpose:** Tests of core rules and the network merge.

| Name | Kind | Purpose |
|---|---|---|
| `make_process(pid, name, ppid, path, command_line, create)` | function | Builds a test process. |
| `evaluate(*processes, regions)` | function | Runs the rules on given processes. |
| `ids(findings)` | function | The rule ids of findings. |
| `test_network_columns_with_separate_ports()` | function | Test: Network columns with separate ports. |
| `test_network_connection_is_not_an_indication_by_itself()` | function | Test: Network connection is not an indication by itself. |
| `test_encoded_powershell_is_detected_but_ordinary_shell_use_is_not()` | function | Test: Encoded powershell is detected but ordinary shell use is not. |
| `test_core_process_with_wrong_parent_and_duplicate_singleton()` | function | Test: Core process with wrong parent and duplicate singleton. |
| `test_lookalike_names_but_not_legitimate_neighbours()` | function | Test: Lookalike names but not legitimate neighbours. |
| `test_truncated_image_name_is_not_a_mismatch()` | function | Test: Truncated image name is not a mismatch. |
| `test_vendor_appdata_programs_are_not_reported_but_temp_is()` | function | Test: Vendor appdata programs are not reported but temp is. |
| `_region(pid, hexdump, protection)` | function | Builds a memory region. |
| `test_malfind_is_one_finding_per_process_and_scored_by_content()` | function | Test: Malfind is one finding per process and scored by content. |
| `test_low_findings_never_trigger_correlation()` | function | Test: Low findings never trigger correlation. |
| `test_correlation_uses_multiple_independent_artifacts()` | function | Test: Correlation uses multiple independent artifacts. |
| `test_a_failing_rule_does_not_stop_the_engine()` | function | Test: A failing rule does not stop the engine. |

### `tests/test_list_sizes.py`  (63 lines)

**Purpose:** Checks that every list/table in every view is tall enough to read.

| Name | Kind | Purpose |
|---|---|---|
| `lists_of(view)` | function | The list widgets of a view. |
| `test_no_list_is_squeezed_to_its_header_and_each_view_scrolls_instead(app, size)` | function | Test: No list is squeezed to its header and each view scrolls instead. |
| `test_a_large_window_gives_the_extra_room_to_the_lists_not_to_empty_space(app)` | function | Test: A large window gives the extra room to the lists not to empty space. |

### `tests/test_malware_scenarios.py`  (173 lines)

**Purpose:** Tests of the synthetic malware scenarios and the report builder's scoring.

| Name | Kind | Purpose |
|---|---|---|
| `test_every_scenario_is_detected_as_expected_and_the_controls_stay_quiet(scenario)` | function | Test: Every scenario is detected as expected and the controls stay quiet. |
| `test_the_scenarios_cover_the_main_attack_families_and_two_controls()` | function | Test: The scenarios cover the main attack families and two controls. |
| `test_a_scenario_that_is_not_detected_is_reported_not_hidden()` | function | Test: A scenario that is not detected is reported not hidden. |
| `entry(name, status, rows, category, checks, facts, findings, ui, tested)` | function | Builds a report entry. |
| `test_the_report_has_every_section_and_says_so_when_nothing_could_be_measured()` | function | Test: The report has every section and says so when nothing could be measured. |
| `test_scores_are_the_stated_arithmetic_and_failures_become_recommendations()` | function | Test: Scores are the stated arithmetic and failures become recommendations. |
| `test_unexplained_plugin_failures_cost_more_than_explained_ones()` | function | Test: Unexplained plugin failures cost more than explained ones. |
| `test_the_html_report_is_one_self_contained_file()` | function | Test: The html report is one self contained file. |
| `test_check_mode_reports_what_is_missing_without_a_network(tmp_path, capsys)` | function | Test: Check mode reports what is missing without a network. |
| `test_simulate_mode_writes_the_three_report_files_without_any_image(tmp_path, capsys)` | function | Test: Simulate mode writes the three report files without any image. |
| `test_a_linux_image_is_listed_as_not_tested_with_the_reason_not_a_crash(tmp_path, capsys)` | function | Test: A linux image is listed as not tested with the reason not a crash. |
| `test_the_manifest_mode_lists_every_requested_image_that_is_missing(tmp_path, monkeypatch)` | function | Test: The manifest mode lists every requested image that is missing. |
| `test_one_real_run_of_the_script_on_a_small_fake_image_end_to_end(tmp_path)` | function | The whole script with the fake Volatility of the tests: analysis, checks, report files. |
| `test_the_false_positive_score_needs_most_findings_to_have_a_verdict()` | function | Test: The false positive score needs most findings to have a verdict. |

### `tests/test_pipeline_and_runner.py`  (329 lines)

**Purpose:** Tests of the provider and the Volatility runner with the fake `vol` (crashes, timeouts, cancel, cache) and the fixture loader.

| Name | Kind | Purpose |
|---|---|---|
| `class env` | class | Context manager: set environment variables, restore afterwards. |
| `env.__init__(**values)` | function | Remembers environment values. |
| `env.__enter__()` | function | Sets the environment values. |
| `env.__exit__(*exc)` | function | Restores the environment. |
| `make_dump(tmp_path)` | function | Creates a fake dump file. |
| `settings(tmp_path, **extra)` | function | Builds settings for a test run. |
| `run_provider(tmp_path, extra_env, cancel, **settings_extra)` | function | Runs the provider against the fake tool. |
| `load_fixture_result(established)` | function | The real Windows 10 fixture. Two of its processes (3828, 6120) were created AFTER the acquisition started (the capture time is the start of the acquisition), so PT-003 correctly rates them Low. `established=True` moves the… |
| `test_command_line_path_user_and_unicode_are_parsed()` | function | Test: Command line path user and unicode are parsed. |
| `test_path_is_not_just_the_process_name()` | function | Test: Path is not just the process name. |
| `test_malfind_ranges_and_privacy_flags_are_filled()` | function | Test: Malfind ranges and privacy flags are filled. |
| `test_hidden_process_detected_and_capture_time_known()` | function | Test: Hidden process detected and capture time known. |
| `test_clean_system_produces_few_findings_and_no_high()` | function | Test: Clean system produces few findings and no high. |
| `test_timeline_is_sorted_deduplicated_and_free_of_garbage_times()` | function | Test: Timeline is sorted deduplicated and free of garbage times. |
| `test_nested_pstree_rows_are_flattened()` | function | Test: Nested pstree rows are flattened. |
| `test_legacy_investigation_file_still_loads(tmp_path)` | function | Test: Legacy investigation file still loads. |
| `test_corrupt_and_wrong_files_give_friendly_errors(tmp_path)` | function | Test: Corrupt and wrong files give friendly errors. |
| `test_save_is_atomic_and_gzip_round_trips(tmp_path)` | function | Test: Save is atomic and gzip round trips. |
| `test_reanalysis_rebuilds_from_stored_plugin_rows(tmp_path)` | function | Test: Reanalysis rebuilds from stored plugin rows. |
| `test_full_run_with_fake_volatility(tmp_path)` | function | Test: Full run with fake volatility. |
| `test_one_failing_plugin_becomes_a_warning_not_an_abort(tmp_path)` | function | Test: One failing plugin becomes a warning not an abort. |
| `test_no_process_list_gives_clear_error(tmp_path)` | function | Test: No process list gives clear error. |
| `test_hung_plugin_is_stopped_by_idle_timeout(tmp_path)` | function | Test: Hung plugin is stopped by idle timeout. |
| `test_runner_idle_timeout_and_progress_keepalive(tmp_path)` | function | Test: Runner idle timeout and progress keepalive. |
| `test_runner_reports_bad_json_and_crash(tmp_path)` | function | Test: Runner reports bad json and crash. |
| `test_cancel_stops_the_analysis(tmp_path)` | function | Test: Cancel stops the analysis. |
| `test_cache_serves_second_run_and_rerun_fixes_failed_plugin(tmp_path)` | function | Test: Cache serves second run and rerun fixes failed plugin. |
| `test_dump_validation_messages(tmp_path)` | function | Test: Dump validation messages. |
| `test_missing_volatility_is_explained(tmp_path)` | function | Test: Missing volatility is explained. |
| `test_settings_are_sanitised(tmp_path)` | function | Test: Settings are sanitised. |
| `test_works_with_python38_style_executor_without_cancel_futures(tmp_path)` | function | ThreadPoolExecutor.shutdown(cancel_futures=...) only exists on Python 3.9+; the provider must not use it. |

### `tests/test_process_tree_gui.py`  (141 lines)

**Purpose:** GUI tests of the process tree and process windows.

| Name | Kind | Purpose |
|---|---|---|
| `app()` | function | The Qt application fixture. |
| `view(app)` | function | A process tree view. |
| `process_windows(app)` | function | Opens process windows. |
| `process_item(view, pid)` | function | The tree item of a PID. |
| `double_click(app, view, item)` | function | The event sequence Windows delivers for a double-click: press, release, double-click, release. (QTest.mouseDClick does not reach QAbstractItemView's double-click handling under the offscreen platform.) |
| `test_single_click_selects_but_opens_nothing(app, view)` | function | Test: Single click selects but opens nothing. |
| `test_one_double_click_opens_exactly_one_window(app, view)` | function | Test: One double click opens exactly one window. |
| `test_repeated_double_click_reuses_the_window_and_other_processes_get_their_own(app, view)` | function | Test: Repeated double click reuses the window and other processes get their own. |
| `test_close_and_reopen(app, view)` | function | Test: Close and reopen. |
| `test_enter_key_and_button_each_open_one_window(app, view)` | function | Test: Enter key and button each open one window. |
| `_encoded_process(result)` | function | Adds a process with an encoded command. |
| `test_finding_details_show_decoded_command_and_attack_tags(app)` | function | Test: Finding details show decoded command and attack tags. |
| `test_process_window_and_tree_panel_show_decoded_command(app)` | function | Test: Process window and tree panel show decoded command. |

### `tests/test_real_provider.py`  (33 lines)

**Purpose:** Tests of the real provider on the fixture plugin output.

| Name | Kind | Purpose |
|---|---|---|
| `test_save_load_preserves_normalized_network_fields(tmp_path)` | function | Test: Save load preserves normalized network fields. |
| `test_provider_plugin_configuration()` | function | Test: Provider plugin configuration. |
| `test_field_provenance_round_trip()` | function | Test: Field provenance round trip. |

### `tests/test_realworld_harness.py`  (89 lines)

**Purpose:** Tests of the real-world run/report tools.

| Name | Kind | Purpose |
|---|---|---|
| `by_name(items, fragment)` | function | Finds report items by a name fragment. |
| `test_an_undamaged_result_passes_every_integrity_check()` | function | Test: An undamaged result passes every integrity check. |
| `test_a_dropped_process_a_wrong_parent_a_lost_dll_and_a_lost_connection_are_each_noticed()` | function | Test: A dropped process a wrong parent a lost dll and a lost connection are each noticed. |
| `test_a_plugin_that_did_not_complete_makes_the_check_inconclusive_not_failed()` | function | Test: A plugin that did not complete makes the check inconclusive not failed. |
| `test_failures_are_classified_only_from_volatilitys_own_words()` | function | Test: Failures are classified only from volatilitys own words. |
| `test_expected_facts_and_finding_review_never_guess()` | function | Test: Expected facts and finding review never guess. |

### `tests/test_realworld_regressions.py`  (98 lines)

**Purpose:** Regression tests for false positives and misses found on real images.

| Name | Kind | Purpose |
|---|---|---|
| `userassist(name, count)` | function | Builds a UserAssist row. |
| `test_rw001_shortcuts_on_the_public_desktop_are_not_programs_started_from_a_risky_folder()` | function | Test: Rw001 shortcuts on the public desktop are not programs started from a risky folder. |
| `driver_rows()` | function | The USBSTOR driver of WinDump.mem: driverirp (name unreadable, handlers inside the driver's own image), driverscan, and a driver object with no name at all. |
| `test_rw002_irp_handlers_inside_the_drivers_own_unloaded_image_are_not_a_hook()` | function | Test: Rw002 irp handlers inside the drivers own unloaded image are not a hook. |
| `test_rw003_images_are_not_reported_unlisted_when_the_process_own_loader_lists_are_incomplete()` | function | Test: Rw003 images are not reported unlisted when the process own loader lists are incomplete. |
| `test_rw004_a_user_mode_callback_value_is_medium_and_code_bytes_are_not_a_hook()` | function | Test: Rw004 a user mode callback value is medium and code bytes are not a hook. |
| `test_rw005_the_symbol_failure_message_does_not_tell_an_offline_tool_to_download()` | function | Test: Rw005 the symbol failure message does not tell an offline tool to download. |

### `tests/test_roadmap_features.py`  (205 lines)

**Purpose:** Tests of roadmap features: rules, services, tasks, encoded commands, offline guard.

| Name | Kind | Purpose |
|---|---|---|
| `plugin(name, rows, status)` | function | Builds a plugin result. |
| `with_plugins(*plugins)` | function | A result with extra plugins. |
| `findings(result, rule_id)` | function | The findings of one rule. |
| `test_registry_keeps_the_original_core_plugin_order_and_is_consistent()` | function | Test: Registry keeps the original core plugin order and is consistent. |
| `test_provider_runs_optional_plugins_only_when_chosen()` | function | Test: Provider runs optional plugins only when chosen. |
| `test_optional_and_extended_plugins_run_through_the_provider_and_feed_the_rules(tmp_path)` | function | Test: Optional and extended plugins run through the provider and feed the rules. |
| `test_hidden_driver_rule_needs_both_plugins_and_stays_quiet_without_them()` | function | Test: Hidden driver rule needs both plugins and stays quiet without them. |
| `test_hidden_driver_rule_separates_stale_objects_from_risky_ones_and_keeps_provenance()` | function | Test: Hidden driver rule separates stale objects from risky ones and keeps provenance. |
| `svc(name, binary, kind, dll, registry)` | function | Builds a service row. |
| `test_risky_service_rule()` | function | Test: Risky service rule. |
| `encoded(script)` | function | Base64-encodes a PowerShell script. |
| `test_encoded_command_is_decoded_and_bad_input_is_not_guessed()` | function | Test: Encoded command is decoded and bad input is not guessed. |
| `test_decoded_command_html_names_its_source()` | function | Test: Decoded command html names its source. |
| `test_every_technique_used_by_a_rule_has_local_details_and_the_app_has_no_web_links()` | function | Test: Every technique used by a rule has local details and the app has no web links. |
| `test_every_rule_has_an_attack_entry_and_tags_are_well_formed()` | function | Test: Every rule has an attack entry and tags are well formed. |
| `test_hashing_helpers_and_manifest(tmp_path)` | function | Test: Hashing helpers and manifest. |
| `test_dumper_returns_hashes_and_survives_a_dump_that_wrote_nothing(tmp_path)` | function | Test: Dumper returns hashes and survives a dump that wrote nothing. |

### `tests/test_round3.py`  (346 lines)

**Purpose:** Tests of persistence, lifetimes, comparison and timeline.

| Name | Kind | Purpose |
|---|---|---|
| `app()` | function | The Qt application fixture. |
| `dashboard(app)` | function | A dashboard on the fixture result. |
| `key_rows(key, **values)` | function | Builds registry key rows. |
| `test_autostart_rule_flags_winlogon_appinit_and_ifeo_but_not_normal_values()` | function | Test: Autostart rule flags winlogon appinit and ifeo but not normal values. |
| `test_run_key_rule_does_not_read_the_autostart_runs()` | function | Test: Run key rule does not read the autostart runs. |
| `test_autostart_choice_runs_three_printkey_invocations(tmp_path)` | function | Test: Autostart choice runs three printkey invocations. |
| `test_crossview_rule_only_flags_the_stricter_hiding()` | function | Test: Crossview rule only flags the stricter hiding. |
| `with_new_process(result)` | function | Adds a new process to a result. |
| `with_new_process_row(result)` | function | A new process added the way real data arrives: as a windows.pslist row (so a re-analysis keeps it). |
| `test_baseline_with_process_list_reports_only_what_is_new(tmp_path)` | function | Test: Baseline with process list reports only what is new. |
| `test_old_style_and_false_positive_baselines_have_no_process_list(tmp_path)` | function | Test: Old style and false positive baselines have no process list. |
| `test_baseline_findings_survive_reanalysis_and_have_a_family_filter(app, tmp_path)` | function | Test: Baseline findings survive reanalysis and have a family filter. |
| `test_stix_bundle_and_misp_export_become_iocs(tmp_path)` | function | Test: Stix bundle and misp export become iocs. |
| `test_json_that_is_neither_and_text_lists_still_work(tmp_path)` | function | Test: Json that is neither and text lists still work. |
| `test_network_bookmark_and_note(app, dashboard, monkeypatch)` | function | Test: Network bookmark and note. |
| `wheel(canvas, x, delta, ctrl)` | function | Sends a wheel event to a canvas. |
| `test_lanes_ctrl_wheel_zoom_reset_and_plain_wheel_scrolls(app, dashboard)` | function | Test: Lanes ctrl wheel zoom reset and plain wheel scrolls. |
| `test_lanes_draw_parent_child_connectors_and_save_an_image(app, dashboard, tmp_path, monkeypatch)` | function | Test: Lanes draw parent child connectors and save an image. |
| `test_column_widths_round_trip_and_ignore_stale_data(app)` | function | Test: Column widths round trip and ignore stale data. |
| `test_dashboard_remembers_the_process_tree_column_widths(app)` | function | Test: Dashboard remembers the process tree column widths. |
| `test_new_plugins_are_registered_with_their_rules()` | function | Test: New plugins are registered with their rules. |

### `tests/test_round4.py`  (198 lines)

**Purpose:** Tests of service/task rules and timeline sources.

| Name | Kind | Purpose |
|---|---|---|
| `reg(key, **values)` | function | Builds a registry row. |
| `test_new_choices_run_the_expected_printkey_commands(tmp_path)` | function | Test: New choices run the expected printkey commands. |
| `test_run_key_rule_understands_environment_variables_and_quoted_paths()` | function | Test: Run key rule understands environment variables and quoted paths. |
| `test_active_setup_only_reads_stubpath_and_ignores_routine_rundll32()` | function | Test: Active setup only reads stubpath and ignores routine rundll32. |
| `service_rows()` | function | Builds service rows. |
| `test_service_key_rule_flags_risky_images_and_dlls_but_not_system_services()` | function | Test: Service key rule flags risky images and dlls but not system services. |
| `test_service_key_rule_is_silent_without_its_plugin_and_flags_encoded_failure_commands()` | function | Test: Service key rule is silent without its plugin and flags encoded failure commands. |
| `task(name, action, args, **extra)` | function | Builds a task row. |
| `test_scheduled_task_rule_flags_risky_actions_and_hiding_options_only()` | function | Test: Scheduled task rule flags risky actions and hiding options only. |
| `test_scheduled_task_plugin_is_found_under_its_older_name(tmp_path)` | function | Volatility 2.11 only lists windows.scheduled_tasks; the result keeps the stable name windows.registry.scheduled_tasks. |
| `test_compatibility_report_accepts_either_name_of_a_renamed_plugin()` | function | Test: Compatibility report accepts either name of a renamed plugin. |
| `events_of(result, category)` | function | Timeline events of a category. |
| `rebuilt(result)` | function | Re-analyses a result. |
| `test_timeline_gets_registry_task_and_execution_events_with_provenance()` | function | Test: Timeline gets registry task and execution events with provenance. |
| `test_timeline_covered_plugins_are_not_added_a_second_time_by_the_generic_path()` | function | Test: Timeline covered plugins are not added a second time by the generic path. |
| `test_timeline_event_cap_adds_a_warning()` | function | Test: Timeline event cap adds a warning. |
| `test_attack_tags_and_rule_catalog_know_the_new_rules()` | function | Test: Attack tags and rule catalog know the new rules. |

### `tests/test_round5.py`  (642 lines)

**Purpose:** Tests of the Files view, settings, Volatility 2 setup and messages.

| Name | Kind | Purpose |
|---|---|---|
| `filescan_rows()` | function | Builds filescan rows. |
| `test_volatility_is_always_started_offline_and_symbol_folders_are_added()` | function | Test: Volatility is always started offline and symbol folders are added. |
| `test_offline_option_reaches_every_volatility_command(tmp_path)` | function | Test: Offline option reaches every volatility command. |
| `test_settings_window_saves_symbol_folders_volatility_2_and_bundles(tmp_path, monkeypatch)` | function | Test: Settings window saves symbol folders volatility 2 and bundles. |
| `test_file_index_splits_devices_builds_the_tree_and_flags_like_file_001()` | function | Test: File index splits devices builds the tree and flags like file 001. |
| `test_dump_files_are_found_by_the_object_address(tmp_path)` | function | Test: Dump files are found by the object address. |
| `make_pe(path, packed)` | function | A small but valid PE32+ DLL: .text (RWX, high entropy) and .idata importing VirtualAlloc from kernel32.dll. |
| `test_report_reads_pe_structure_hashes_and_strings(tmp_path)` | function | Test: Report reads pe structure hashes and strings. |
| `test_report_copes_with_other_files_truncated_pes_and_zero_pages(tmp_path)` | function | Test: Report copes with other files truncated pes and zero pages. |
| `test_dumper_dumps_several_file_objects_in_one_run(tmp_path)` | function | Test: Dumper dumps several file objects in one run. |
| `test_controller_can_run_one_more_plugin_on_an_open_investigation(tmp_path)` | function | The Files view's 'Run windows.filescan now' merges the new plugin into the existing result and keeps the case. |
| `app()` | function | The Qt application fixture. |
| `dispose(app, *windows)` | function | Close AND delete windows: an app-wide stylesheet change re-polishes every widget that is still alive, so leftovers slow later tests. |
| `wait_for(app, condition, seconds)` | function | Processes events until a condition holds. |
| `files_dashboard(app, tmp_path)` | function | A dashboard with filescan data. |
| `patch_messages(monkeypatch)` | function | Replaces message boxes with recorders. |
| `test_files_view_without_filescan_explains_and_offers_to_run_it(app)` | function | Test: Files view without filescan explains and offers to run it. |
| `listing(view)` | function | The names and kinds of what the open folder of the Files view shows, in order. |
| `test_files_view_is_an_explorer_folders_first_double_click_to_enter_address_bar_back_forward_up(app, files_dashboard)` | function | Test: Files view is an explorer folders first double click to enter address bar back forward up. |
| `test_search_and_filters_list_matching_files_of_the_whole_subtree_with_their_location(app, files_dashboard)` | function | Test: Search and filters list matching files of the whole subtree with their location. |
| `test_selecting_a_file_shows_only_what_is_known_about_it_not_its_content(app, files_dashboard)` | function | Test: Selecting a file shows only what is known about it not its content. |
| `test_right_click_menu_depends_on_what_is_under_the_mouse(app, files_dashboard)` | function | Test: Right click menu depends on what is under the mouse. |
| `select_name(view, name)` | function | Selects a file by name in a view. |
| `test_details_show_flags_references_and_notes(app, files_dashboard, monkeypatch)` | function | Test: Details show flags references and notes. |
| `test_dump_flow_hashes_checks_iocs_reports_and_opens_the_hex_view(app, files_dashboard, monkeypatch, tmp_path)` | function | Test: Dump flow hashes checks iocs reports and opens the hex view. |
| `test_dump_failure_is_reported_not_raised(app, files_dashboard, monkeypatch)` | function | Test: Dump failure is reported not raised. |
| `mutated_pair()` | function | Two results that differ, for comparison tests. |
| `test_compare_same_boot_finds_new_gone_and_changed()` | function | Test: Compare same boot finds new gone and changed. |
| `test_compare_notices_new_connections_findings_regions_and_plugin_rows()` | function | Test: Compare notices new connections findings regions and plugin rows. |
| `test_compare_different_systems_matches_by_image_and_path_and_ignores_addresses()` | function | Test: Compare different systems matches by image and path and ignores addresses. |
| `test_compare_exports_csv_and_handles_empty_input(tmp_path)` | function | Test: Compare exports csv and handles empty input. |
| `test_compare_view_loads_a_saved_investigation_and_filters(app, tmp_path, monkeypatch)` | function | Test: Compare view loads a saved investigation and filters. |
| `test_real_filescan_shapes_folder_objects_servicing_leftovers_and_shortcuts()` | function | windows.filescan 2.28 prints names without a device, lists opened folders as objects, and the offsets are kernel virtual addresses. |
| `test_dump_command_uses_virtual_addresses()` | function | filescan's Offset is a kernel virtual address (0xd98d...); --physaddr would read the wrong object. |
| `test_report_explains_empty_tables_and_made_up_compile_times(tmp_path)` | function | Real dumps of Windows files: compile time 2074 (a hash, not a date) and import/export tables on pages that were not in memory. |
| `test_names_that_filescan_read_from_damaged_pool_memory_are_listed_together_not_as_folders()` | function | Test: Names that filescan read from damaged pool memory are listed together not as folders. |

### `tests/test_round6.py`  (369 lines)

**Purpose:** Tests of IOC lists, YARA generation, STIX/MISP, and legacy Windows rules.

| Name | Kind | Purpose |
|---|---|---|
| `artifact(name, content)` | function | Writes a test file. |
| `iocs_from(text)` | function | Parses IOC text. |
| `test_dump_names_are_parsed_and_attributed_to_processes()` | function | Test: Dump names are parsed and attributed to processes. |
| `test_image_hashes_live_in_the_case_and_ioc_007_matches_them(tmp_path)` | function | Test: Image hashes live in the case and ioc 007 matches them. |
| `test_image_hash_list_exports_as_csv(tmp_path)` | function | Test: Image hash list exports as csv. |
| `test_dump_all_images_is_one_pslist_run_without_a_pid(tmp_path)` | function | Test: Dump all images is one pslist run without a pid. |
| `test_process_tree_hash_button_stores_matches_and_refreshes_the_findings(tmp_path, monkeypatch)` | function | Test: Process tree hash button stores matches and refreshes the findings. |
| `test_generated_yara_rules_compile_and_find_domains_ips_and_mutexes_in_memory()` | function | Test: Generated yara rules compile and find domains ips and mutexes in memory. |
| `test_settings_button_writes_the_rules_and_sets_the_yara_file(tmp_path, monkeypatch)` | function | Test: Settings button writes the rules and sets the yara file. |
| `set_nt_version(result, major)` | function | Sets the NT version of a result. |
| `test_services_and_lsass_under_winlogon_are_normal_on_windows_xp_only()` | function | Test: Services and lsass under winlogon are normal on windows xp only. |
| `test_the_xp_ifeo_placeholder_is_not_a_finding_but_a_real_debugger_still_is()` | function | Test: The xp ifeo placeholder is not a finding but a real debugger still is. |
| `test_ldrmodules_ignores_data_mappings_fonts_and_the_system_process_but_keeps_executable_ones()` | function | Test: Ldrmodules ignores data mappings fonts and the system process but keeps executable ones. |
| `test_known_xp_shared_section_is_low_but_an_injected_pe_at_the_same_address_is_not()` | function | Test: Known xp shared section is low but an injected pe at the same address is not. |
| `test_callbacks_into_user_mode_are_medium_duplicates_are_listed_once_and_code_bytes_are_not_a_hook()` | function | Test: Callbacks into user mode are medium duplicates are listed once and code bytes are not a hook. |
| `test_one_unreadable_dumped_file_does_not_cost_the_hashes_of_the_others(tmp_path, monkeypatch)` | function | Test: One unreadable dumped file does not cost the hashes of the others. |
| `test_the_hash_message_names_files_an_antivirus_blocked(tmp_path, monkeypatch)` | function | Test: The hash message names files an antivirus blocked. |
| `test_known_plugins_without_an_event_source_do_not_leak_into_the_timeline()` | function | vadyarascan / vadinfo rows carry the process's CreateTime: the generic 'any plugin with a time column' path used to add them as events. |
| `test_timeline_window_leaves_file_times_off_until_asked(tmp_path)` | function | Test: Timeline window leaves file times off until asked. |
| `test_a_failed_requirement_check_blames_the_plugin_when_windows_info_already_worked()` | function | Test: A failed requirement check blames the plugin when windows info already worked. |
| `test_yara_match_bytes_are_shown_as_text_when_they_are_text()` | function | Test: Yara match bytes are shown as text when they are text. |

### `tests/test_round7.py`  (387 lines)

**Purpose:** Tests of the XP network via Volatility 2 and the Windows-version-aware rules.

| Name | Kind | Purpose |
|---|---|---|
| `no_bundled_vol2(monkeypatch, tmp_path_factory)` | function | The project's tools/volatility2 folder holds the real Volatility 2 exe: these tests must not depend on what is in it. |
| `test_the_volatility_2_dropped_into_tools_volatility2_is_found_without_any_setting(monkeypatch, tmp_path)` | function | Test: The volatility 2 dropped into tools volatility2 is found without any setting. |
| `info_rows(major, minor, lab, is64, build)` | function | Builds windows.info rows. |
| `vol2_fixture(tmp_path, pid)` | function | A fake Volatility 2 setup. |
| `vol2_setup(tmp_path, monkeypatch)` | function | Settings that make a `vol.py`-style Volatility 2 available (the stand-in runs under the current Python in place of Python 2). |
| `calls(record)` | function | The recorded calls of a fake. |
| `test_os_profile_names_the_windows_version_service_pack_and_volatility_2_profile()` | function | Test: Os profile names the windows version service pack and volatility 2 profile. |
| `test_plugins_state_which_windows_versions_they_exist_for()` | function | Test: Plugins state which windows versions they exist for. |
| `test_every_plugin_belongs_to_exactly_one_bundle_and_defaults_match_the_old_behaviour()` | function | Test: Every plugin belongs to exactly one bundle and defaults match the old behaviour. |
| `test_bundle_choices_are_written_back_to_the_existing_settings_keys()` | function | Test: Bundle choices are written back to the existing settings keys. |
| `test_find_vol2_accepts_an_exe_or_vol_py_and_explains_what_is_missing(tmp_path, monkeypatch)` | function | Test: Find vol2 accepts an exe or vol py and explains what is missing. |
| `test_a_standalone_executable_is_run_directly(tmp_path)` | function | Test: A standalone executable is run directly. |
| `test_run_vol2_passes_the_profile_and_debugger_addresses_and_survives_wrong_ones(tmp_path, vol2_setup)` | function | Test: Run vol2 passes the profile and debugger addresses and survives wrong ones. |
| `test_xp_image_skips_vol3_network_plugins_and_gets_one_merged_connection_list_from_vol2(tmp_path, vol2_setup)` | function | Test: Xp image skips vol3 network plugins and gets one merged connection list from vol2. |
| `test_deep_scan_adds_connscan_and_the_same_connection_is_shown_once_with_both_sources(tmp_path, vol2_setup)` | function | Test: Deep scan adds connscan and the same connection is shown once with both sources. |
| `test_xp_without_volatility_2_says_so_instead_of_failing(tmp_path)` | function | Test: Xp without volatility 2 says so instead of failing. |
| `test_a_broken_volatility_2_setting_is_reported_not_raised(tmp_path)` | function | Test: A broken volatility 2 setting is reported not raised. |
| `test_windows_7_uses_volatility_3_and_only_falls_back_to_volatility_2_when_it_cannot_read_the_network(tmp_path, vol2_setup)` | function | Test: Windows 7 uses volatility 3 and only falls back to volatility 2 when it cannot read the network. |
| `test_windows_10_is_untouched_by_all_of_this(tmp_path, vol2_setup)` | function | Test: Windows 10 is untouched by all of this. |
| `test_a_failed_vol2_job_can_be_rerun_and_is_cached(tmp_path, vol2_setup)` | function | Test: A failed vol2 job can be rerun and is cached. |
| `test_adapter_reads_the_real_volatility_2_column_names_and_endpoint_formats()` | function | Column and endpoint formats taken from the Volatility 2 source (connections / connscan / sockets / sockscan / netscan). |
| `with_os(result, major, minor)` | function | A result of a given Windows version. |
| `plugin_result(name, rows)` | function | Builds a plugin result. |
| `rule_findings(result, rule_id)` | function | The findings of one rule. |
| `with_rows(name, rows)` | function | A result with rows. |
| `test_hollowed_ghosted_and_etw_patched_processes_are_reported_per_process()` | function | Test: Hollowed ghosted and etw patched processes are reported per process. |
| `test_suspicious_threads_ignore_the_xp_artefacts_of_the_plugin()` | function | Test: Suspicious threads ignore the xp artefacts of the plugin. |
| `test_peb_masquerade_ignores_smss_and_reports_other_changes()` | function | Test: Peb masquerade ignores smss and reports other changes. |
| `test_irp_handlers_outside_every_module_are_hooks_and_normal_forwarding_is_not()` | function | Test: Irp handlers outside every module are hooks and normal forwarding is not. |
| `test_services_hidden_from_the_list_are_reported_and_the_plugin_is_windows_10_only()` | function | Test: Services hidden from the list are reported and the plugin is windows 10 only. |
| `test_system_processes_that_do_not_exist_on_the_image_windows_are_reported()` | function | Test: System processes that do not exist on the image windows are reported. |
| `test_every_rule_has_a_catalog_entry_and_an_attack_entry()` | function | Test: Every rule has a catalog entry and an attack entry. |

### `tests/test_round8.py`  (229 lines)

**Purpose:** Tests of the registry view and injection chains.

| Name | Kind | Purpose |
|---|---|---|
| `run_rows()` | function | Builds Run-key rows. |
| `user_rows()` | function | Builds UserAssist rows. |
| `test_key_paths_are_reduced_to_a_hive_and_the_path_inside_it()` | function | Test: Key paths are reduced to a hive and the path inside it. |
| `test_printkey_results_are_merged_into_one_tree_without_duplicates_and_failed_ones_are_ignored()` | function | Test: Printkey results are merged into one tree without duplicates and failed ones are ignored. |
| `registry_dashboard(app, tmp_path)` | function | A dashboard with registry data. |
| `test_registry_view_shows_hives_keys_and_values_and_finds_text(app, registry_dashboard)` | function | Test: Registry view shows hives keys and values and finds text. |
| `test_fetching_another_key_runs_printkey_adds_it_to_the_investigation_and_marks_it_changed(app, registry_dashboard)` | function | Test: Fetching another key runs printkey adds it to the investigation and marks it changed. |
| `test_a_failing_fetch_reports_the_error_and_changes_nothing(app, registry_dashboard)` | function | Test: A failing fetch reports the error and changes nothing. |
| `handle_row(holder_pid, holder, target, kind, mask)` | function | Builds a handle row. |
| `chain_result(handles)` | function | A result prepared for injection chains. |
| `test_access_masks_decide_which_process_handles_could_inject()` | function | Test: Access masks decide which process handles could inject. |
| `test_a_process_with_a_memory_sign_gets_a_chain_with_the_writer_and_what_it_did_next()` | function | Test: A process with a memory sign gets a chain with the writer and what it did next. |
| `test_operating_system_handle_holders_weak_masks_and_self_handles_are_not_evidence()` | function | Test: Operating system handle holders weak masks and self handles are not evidence. |
| `test_a_handle_into_a_clean_process_alone_does_not_make_a_chain_and_the_writer_gets_an_afterwards_step()` | function | Test: A handle into a clean process alone does not make a chain and the writer gets an afterwards step. |
| `test_a_false_positive_decision_removes_the_sign_from_the_chain()` | function | Test: A false positive decision removes the sign from the chain. |
| `test_chains_are_empty_without_any_memory_sign()` | function | Test: Chains are empty without any memory sign. |
| `test_injection_view_lists_chains_tells_the_story_and_follows_triage(app)` | function | Test: Injection view lists chains tells the story and follows triage. |

### `tests/test_round9.py`  (300 lines)

**Purpose:** Tests of the latest rule fixes, behavioural lead, hidden-process timing and preset estimates.

| Name | Kind | Purpose |
|---|---|---|
| `path(*parts)` | function | Builds a Windows path. |
| `first_pid(result, exclude)` | function | The first PID not excluded. |
| `test_a_single_plugin_high_is_medium_until_a_second_plugin_points_at_the_same_process()` | function | Test: A single plugin high is medium until a second plugin points at the same process. |
| `test_the_second_source_helper_counts_only_other_plugins_and_other_rules()` | function | Test: The second source helper counts only other plugins and other rules. |
| `test_executable_regions_in_a_dotnet_host_are_explained_by_the_memory_map_not_only_by_dlllist()` | function | Test: Executable regions in a dotnet host are explained by the memory map not only by dlllist. |
| `ldr_rows(pid, name, images)` | function | Builds ldrmodules rows. |
| `test_trusted_system_images_are_one_low_finding_and_images_elsewhere_stay_one_finding_per_process()` | function | Test: Trusted system images are one low finding and images elsewhere stay one finding per process. |
| `test_a_known_good_list_made_on_a_clean_system_silences_what_is_normal_on_that_windows(tmp_path)` | function | Test: A known good list made on a clean system silences what is normal on that windows. |
| `hidden_result(created, capture)` | function | A result with a hidden process. |
| `test_a_process_created_after_the_acquisition_started_is_low_an_older_unlinked_one_is_medium()` | function | Test: A process created after the acquisition started is low an older unlinked one is medium. |
| `test_a_user_mode_callback_is_checked_against_the_executable_memory_of_the_processes()` | function | Test: A user mode callback is checked against the executable memory of the processes. |
| `beh_result(image_path, network, parent_name)` | function | A result for the behavioural rule. |
| `test_a_program_running_from_the_users_own_folders_is_a_low_lead_and_medium_with_a_second_sign()` | function | Test: A program running from the users own folders is a low lead and medium with a second sign. |
| `test_the_behavioural_lead_is_not_a_second_source_for_a_high_finding()` | function | Test: The behavioural lead is not a second source for a high finding. |
| `test_plugin_durations_are_learned_and_the_slowest_plugins_start_first()` | function | Test: Plugin durations are learned and the slowest plugins start first. |
| `test_a_run_records_what_each_plugin_took_and_announces_an_estimate(tmp_path)` | function | Test: A run records what each plugin took and announces an estimate. |
| `test_the_story_of_a_process_puts_parent_start_children_and_findings_on_one_clock()` | function | Test: The story of a process puts parent start children and findings on one clock. |
| `test_the_process_window_has_a_story_tab(app)` | function | Test: The process window has a story tab. |
| `test_tool_info_is_saved_and_loaded_and_loader_list_problems_are_reported_once(tmp_path)` | function | Test: Tool info is saved and loaded and loader list problems are reported once. |
| `test_the_quick_triage_preset_ticks_processes_network_and_injected_code_only(app)` | function | Test: The quick triage preset ticks processes network and injected code only. |

### `tests/test_ui_roadmap.py`  (315 lines)

**Purpose:** Tests of the dark theme, fonts, remembered layout, timeline/lifetimes and other GUI roadmap items.

| Name | Kind | Purpose |
|---|---|---|
| `app()` | function | The Qt application fixture. |
| `dark_after(app)` | function | Resets the theme after a test. |
| `dashboard(app)` | function | A dashboard on the fixture result. |
| `test_the_stylesheet_is_one_dark_theme_built_from_the_palette_and_parsed_by_qt(app, dark_after)` | function | Test: The stylesheet is one dark theme built from the palette and parsed by qt. |
| `test_the_colour_tokens_the_views_import_are_stable_dicts()` | function | Test: The colour tokens the views import are stable dicts. |
| `test_font_scaling_and_limits()` | function | Test: Font scaling and limits. |
| `test_theme_and_font_settings_are_sanitised()` | function | Test: Theme and font settings are sanitised. |
| `test_settings_window_applies_font_and_resets_layout_and_has_no_theme_choice(app, monkeypatch, dark_after)` | function | Test: Settings window applies font and resets layout and has no theme choice. |
| `test_geometry_and_splitters_round_trip(app)` | function | Test: Geometry and splitters round trip. |
| `test_layout_memory_is_optional_and_ignores_stale_or_garbled_entries(app)` | function | Test: Layout memory is optional and ignores stale or garbled entries. |
| `test_dashboard_captures_and_restores_splitter_positions(app)` | function | Test: Dashboard captures and restores splitter positions. |
| `test_lanes_reflect_start_exit_capture_and_risk()` | function | Test: Lanes reflect start exit capture and risk. |
| `test_lanes_stop_counting_findings_hidden_by_triage()` | function | Test: Lanes stop counting findings hidden by triage. |
| `test_lifetimes_view_filters_windows_and_opens_the_process(app, dashboard)` | function | Test: Lifetimes view filters windows and opens the process. |
| `test_lifetimes_view_follows_triage_and_paints(app, dashboard)` | function | Test: Lifetimes view follows triage and paints. |
| `test_theme_change_rebuilds_the_open_views(app, dashboard)` | function | Test: Theme change rebuilds the open views. |
| `test_attack_column_and_search(app, dashboard)` | function | Test: Attack column and search. |
| `test_bulk_triage_marks_only_open_findings_that_are_shown(app, dashboard, monkeypatch)` | function | Test: Bulk triage marks only open findings that are shown. |
| `test_bulk_triage_can_be_cancelled_and_handles_nothing_to_do(app, dashboard, monkeypatch)` | function | Test: Bulk triage can be cancelled and handles nothing to do. |
| `test_unlinked_module_rule()` | function | Test: Unlinked module rule. |
| `test_ldrmodules_is_registered_and_runs_through_the_provider()` | function | Test: Ldrmodules is registered and runs through the provider. |

### `tests/test_volatility_compat.py`  (109 lines)

**Purpose:** Tests of how failures of the different Volatility versions are recognised and explained.

| Name | Kind | Purpose |
|---|---|---|
| `failed(result, name)` | function | Whether a plugin failed in a result. |
| `test_plugin_list_is_parsed_from_real_help_format()` | function | Test: Plugin list is parsed from real help format. |
| `test_version_comparison_and_note()` | function | Test: Version comparison and note. |
| `test_describe_os_from_info_rows()` | function | Test: Describe os from info rows. |
| `test_missing_plugin_is_reported_without_stopping_the_investigation(tmp_path)` | function | Test: Missing plugin is reported without stopping the investigation. |
| `test_unsupported_windows_build_is_distinguished_from_a_version_problem(tmp_path)` | function | Test: Unsupported windows build is distinguished from a version problem. |
| `test_netstat_that_logs_an_error_and_returns_nothing_is_not_reported_as_empty_success(tmp_path)` | function | Test: Netstat that logs an error and returns nothing is not reported as empty success. |
| `test_internal_plugin_crash_and_missing_dependency(tmp_path)` | function | Test: Internal plugin crash and missing dependency. |
| `test_old_version_is_named_in_the_failure_and_unknown_plugin_list_still_runs(tmp_path)` | function | Test: Old version is named in the failure and unknown plugin list still runs. |
| `test_compatibility_report_lists_missing_plugins(tmp_path)` | function | Test: Compatibility report lists missing plugins. |

### `tests/test_window_fit.py`  (180 lines)

**Purpose:** Tests that windows fit the screen and keep their proportions.

| Name | Kind | Purpose |
|---|---|---|
| `app()` | function | The Qt application fixture. |
| `real_fonts(app)` | function | The offscreen platform has no fonts (text measures about twice as wide). Use Segoe UI, the font the app uses, when present. |
| `usable(app)` | function | The usable screen area. |
| `test_oversized_window_is_shrunk_to_the_screen_but_not_made_full_screen(app)` | function | Test: Oversized window is shrunk to the screen but not made full screen. |
| `test_windows_that_already_fit_are_left_alone_and_off_screen_ones_are_moved_back(app)` | function | Test: Windows that already fit are left alone and off screen ones are moved back. |
| `test_special_windows_are_skipped(app)` | function | Test: Special windows are skipped. |
| `test_installed_filter_fits_dialogs_when_they_are_shown(app)` | function | Test: Installed filter fits dialogs when they are shown. |
| `test_flow_layout_wraps_and_only_needs_the_widest_item(app)` | function | Test: Flow layout wraps and only needs the widest item. |
| `test_elided_label_shortens_long_text_instead_of_widening(app)` | function | Test: Elided label shortens long text instead of widening. |
| `test_dashboard_with_every_view_open_fits_a_laptop_screen(app, real_fonts)` | function | Test: Dashboard with every view open fits a laptop screen. |
| `test_settings_window_content_fits_its_default_width_and_height_is_bounded(app, real_fonts)` | function | Test: Settings window content fits its default width and height is bounded. |
| `test_other_windows_fit_and_keep_their_proportions(app, real_fonts)` | function | Test: Other windows fit and keep their proportions. |


---

## Non-code files

| File | Purpose |
|---|---|
| `README.md` | Overview of the project: what it does, how to install and run it, features, settings, the engines, the project structure and the tests. |
| `requirements.txt` | The Python packages the program needs (PySide6, Volatility 3 and optional extras). |
| `.venv.zip` | A zipped copy of the Python virtual environment (not project code; a backup that can be deleted). |
| `docs/CHANGES.md` | Change log of what was added or fixed in each round of work. |
| `docs/ENGINES.md` | How the engine split works and what the Linux engine still has to provide, in the order to write it. |
| `docs/IDEAS.md` | The original list of ideas for later; each is tracked in the roadmap. |
| `docs/OFFLINE.md` | How to use MemoryGraph with no internet: symbol tables, tools and dependencies. |
| `docs/PHASE_A_G.md` | Notes of the early development phases A to G. |
| `docs/REALWORLD_REPORT.md` | The report of testing on real memory images: method, results, bugs found and fixed. |
| `docs/ROADMAP.md` | Status of every planned feature (done / partial / not started), known limits and the decided to-do list. |
| `docs/PROJECT_REFERENCE.md` | This file: every file, class and function with its purpose. |
| `docs/realworld/local-win10.json, local-win10.md` | Machine-readable and readable results of testing the Windows 10 image. |
| `docs/realworld/local-xp-sp3.json, local-xp-sp3.md` | Machine-readable and readable results of testing the Windows XP SP3 image. |
| `docs/realworld/volatility-versions/` | Comparison of Volatility 2 and 3 on the XP and Windows 10 images: summary, JSON and error logs. |
| `app/engines/linux/data/README.md` | Explains the folder reserved for Linux data tables. |
| `app/engines/windows/data/attack_techniques.json` | Offline descriptions of the MITRE ATT&CK techniques the Windows rules map to. |
| `tests/fixtures/mini_plugins.json` | A small real Volatility-shaped set of plugin output used by many tests. |
| `tools/realworld/README.md` | How to use the real-world run and offline report tools. |
| `tools/realworld/manifest.json` | List of the real memory images (and public samples) the tools know how to test, with their expected facts. |
| `tools/realworld/expected/local-win10.json` | Expected facts for the Windows 10 test image. |
| `tools/realworld/expected/local-xp-sp3.json` | Expected facts for the Windows XP test image. |
| `tools/realworld/run_report.bat` | Windows launcher for the offline report script. |
| `tools/realworld/run_report.sh` | Linux/macOS launcher for the offline report script. |
| `tools/volatility2/README.txt` | Where to put Volatility 2 for the XP network support. |
| `tools/volatility2/volatility_2.6_win64_standalone.exe` | The standalone Volatility 2.6 program (a separate GPL program that MemoryGraph runs; not part of its code). |
