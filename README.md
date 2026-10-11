# MemoryGraph

MemoryGraph is a Windows memory-forensics investigation tool built with Python, PySide6 and Volatility 3.
Load a memory image, let it run the Volatility plugins, and review the result as a process tree, tables,
a timeline and a short, ranked list of investigation leads.

**Status: development / pre-release** (not packaged as an EXE yet). Python 3.8 or newer.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows   (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
python main.py
```

1. **Run analysis** – choose a `.raw / .mem / .dmp / .vmem` image. Volatility needs the symbol table of the image's Windows build: by default
   it must be on this computer: MemoryGraph never connects to the internet and always runs Volatility with `--offline`. Add the folder that holds your
   symbol files under **Settings → Volatility 3 → Extra symbol folders** (see `docs/OFFLINE.md`).
2. **Load existing** – reopen a saved investigation (`.json` or `.json.gz`). Saved files are re-analysed with the
   current rules by default (Settings → *Re-analyse saved investigations…*), so improvements to the rules apply to old work.
3. **← New analysis** (top-left of the dashboard) goes back to start another dump; the previous investigation stays available
   through *Back to current investigation*.

## What the dashboard contains

| View | What it is for |
|------|----------------|
| Overview | counts, plugin health (with *Re-run N failed plugin(s)*), the processes most worth reviewing |
| Search | one search box over PIDs, names, DLLs, endpoints, rules, users, plugin names |
| Process Tree | collapsible tree, repeated siblings folded, risky branches opened, detail panel, double-click for the full process view |
| Indications | findings grouped per process and ranked; Low findings hidden by default; evidence and reasoning per finding |
| Injection | every process with a memory-level sign (executable private memory, image in no loader list, thread outside any module, hollowing, rewritten PEB, patched ETW) with who could have written into it (write-capable process / thread handles; the operating system's own processes are left out) and what it did afterwards (children, external connections, handles it holds into others). A reading of the evidence, not a verdict |
| Plugin Output | the original Volatility output per plugin: sortable table or terminal-style text |
| Files | a file explorer for the file objects `windows.filescan` found: folder tree on the left, folders-first list with an address bar, back / forward / up and double-click to open a folder. Selecting a file shows only what the image knows about it (path, FILE_OBJECT address, flags, where else it was seen), **not its content**; **dump** it (one `windows.dumpfiles` run) and the Content tab shows hashes, type, PE structure and strings, and opens the hex view. *Run windows.filescan now* runs the plugin on demand |
| Registry | the registry keys Volatility read (Run keys, Winlogon / IFEO / AppInit, Active Setup, Services…) merged into one tree: hive → keys → values, search, and **Fetch another key…** (`windows.registry.printkey --key … [--recurse]`) for any key not read yet; fetched keys are saved with the investigation |
| Network | merged `netscan` + `netstat`, filters for external / listening / state |
| Timeline | activity chart (drag to select a range), filters, time relative to capture, CSV export; with the opt-in plugins also registry keys written (Run, services, Active Setup, …), scheduled tasks created / last run, and program execution history (UserAssist, Amcache, shimcache) |
| Lifetimes | one lane per process from start to exit (or to the capture), coloured by risk; zoom to the last 24 h / 6 h / hour / 15 min before the capture |
| Compare | this investigation against another saved one (a later/earlier image, or a clean machine): new / gone / changed processes, modules, connections, findings, memory regions and plugin rows (drivers, services, tasks, Run keys, files…); CSV export |
| Case Notes | your bookmarks, notes, reviewed / false-positive decisions and baselines; Markdown export; baseline import/export |
| Computer Info | `windows.info`, accounts found in the image |

**Triage.** In a finding's details: *Mark reviewed*, *False positive — hide* (out of scores and counts, kept in Case Notes) or *Reopen*.
Bookmarks and notes are on the Files view, the Process Tree, a process's Modules tab (DLLs), its memory regions (hex view), the Network view, the Timeline,
rows of the Plugin Output tables and on findings; Case Notes jumps back to the process or to the plugin row. All of it is saved with the investigation (the header shows
"unsaved notes / triage" until you save) and survives re-analysis. A baseline (export from a clean dump, import into another
investigation) suppresses the same findings there.

**Hex view.** In a process's Memory tab, double-click a malfind region: addresses and offsets, a byte inspector, search (hex with `??`
wildcards, ASCII, UTF-16) and a disassembly (capstone) of every loaded byte. malfind itself keeps only the first 64 bytes of a region; after
*Dump malfind pages*, *Load bytes from file…* opens the region's `pid.<pid>.vad.<start>-<end>.dmp` (the first 2 MiB are loaded).

Windows always open inside the usable screen area (never full screen), and the control bars wrap on narrow windows.

**Your own indicators** (Settings → IOC lists, YARA rule file) produce a separate `IOC-*` family: IPs/CIDR, domains, mutexes, file
names/paths, hashes (checked on dumped files and on **all process images**: Process Tree → *Hash all process images…*, rule IOC-007, CSV export of the list) and YARA matches.
*Settings → Make YARA rules from this list…* turns your domains, IPs and mutex names into YARA rules so `windows.vadyarascan` can find them in process memory.
Lists can be plain text, a STIX 2 bundle or a MISP export (detected automatically); see the docstring of `app/analysis/ioc.py`.

## How the analysis runs

```text
Home → AnalysisController (background thread)
         → RealProvider
              1. validate the dump file, find + test Volatility
              2. windows.info alone first (builds the symbol cache once)
              3. all other plugins in parallel (Settings → parallel plugins), each in its own process
              4. normalizer  → processes, modules, network, memory regions, handles, accounts
              5. timeline builder, then the rule engine + correlation
         → Dashboard (rebuilt for every result)
```

Reliability features of the plugin runner (`app/analysis/volatility_runner.py`):

* output is read as UTF-8 and written to a temp file (no Windows code-page crashes, no pipe deadlocks);
* Volatility's `Progress:` output is parsed for a live progress display;
* the time limit is an **inactivity** limit (default 15 min without output or progress), so a slow scan of a big image is
  never killed, but a hung plugin is;
* **Cancel** stops Volatility immediately;
* failures are translated into readable messages (missing symbols, locked file, out of memory, …) and shown with details;
* one failed plugin is a warning (with *Re-run N failed plugin(s)*), not the end of the analysis;
* finished plugins are cached per dump (path + size + modification time + Volatility version), so a second run or a re-run
  after a crash skips what already succeeded (Settings → *Reuse cached plugin output*; *Clear cache* is in Settings).

## Indications (investigation leads, not verdicts)

Rules compare the evidence with what is normal on Windows (`app/engines/windows/indicators/baseline.py` holds all the tables,
so you can review/extend them without touching rule code).

| Rule | Looks for |
|------|-----------|
| PT-001 / PT-002 | core Windows process with the wrong parent / second copy of lsass, services, wininit… |
| PT-003 | process found by `psscan` but missing from `pslist` (unlinked / hidden) |
| PT-004 | cmd/PowerShell/script host started by a non-shell parent (Low) |
| PR-001 | name imitating a core process (`svch0st.exe`, `scvhost.exe`) |
| PR-002 | core process running from the wrong folder |
| PR-003 | executable in Temp/Downloads/Public/Recycle Bin (Medium) or other AppData (Low) |
| PR-004 | process name differs from the image file (14-character truncation aware) |
| CL-001…004 | encoded/hidden PowerShell, LOLBin download/exec patterns, interpreter + risky path, obfuscation |
| MEM-001 | executable private memory (malfind) – **one finding per process**, scored from the content (MZ header, shellcode bytes, empty/JIT pages) |
| DLL-001 / DLL-002 | modules from temp/untrusted places; system DLL names loaded from non-system folders |
| NET-001 / NET-002 | external connection from an already suspicious process / from a process that normally has none |
| HND-001 | non-system process holding a memory-read handle to lsass |
| DRV-001 | driver found by `modscan` but missing from `modules` (needs *extended plugins*); stale unloaded drivers are one Low finding, ones in Temp/Public/Downloads are Medium |
| SVC-001 | service binary/DLL in Temp/Public/Downloads (Medium) or per-user AppData (Low) (needs the opt-in `windows.svcscan`) |
| DRV-002 / SSDT-001 / CBK-001 | driver object in no module / system-call table entries outside the kernel / kernel callbacks in no module |
| PER-001 / UA-001 | autorun entries (Run/RunOnce incl. 32-bit and Policies\Explorer\Run, Active Setup StubPath) from risky places (also written as `%TEMP%`) or interpreters / programs the user started from Temp, Downloads, Public |
| PER-003 / PER-004 | services as registered in the registry (`ImagePath`, `ServiceDll`, `FailureCommand`) / scheduled tasks whose action runs from a risky place, is encoded, or uses hidden-window / bypass / download options |
| LDR-001 | image mapped in a process but in none of the three loader lists (`ldrmodules`) |
| PER-002 / PX-001 | altered Winlogon / AppInit_DLLs / IFEO debugger / a process hidden from pslist **and** psscan (`psxview`) |
| BASE-001 | **your** baseline: processes (image name + path) not in the clean dump it was made from |
| FILE-001 / ENV-001 / VAD-001 | executables in unusual folders (`filescan`) / odd COMSPEC, SystemRoot, windir (`envars`) / mapped images missing from the module list (`vadinfo`) |
| IOC-001/002/004/005/006/007 | **your** lists: IP, domain, mutex, file, YARA, hash of a process image (separate family, never mixed with the rules above) |

| CORR-001 / CORR-002 | independent evidence kinds on one process / suspicious parent + child |

The rules for extended and opt-in plugins are silent unless Settings turns the plugin on (and the installed Volatility has it).
Plugins that were renamed between Volatility versions (scheduled tasks and Amcache moved from `windows.*` to `windows.registry.*`) are run
under whichever name the installed version lists.

Each finding's details show the MITRE ATT&CK techniques the behaviour is commonly associated with (context only, `indicators/attack.py`)
and, for PowerShell `-EncodedCommand`, the decoded script with its source. Plugins are declared once in
`app/engines/windows/analysis/plugin_registry.py`; opt-in ones are ticked in Settings. Every process/DLL/handle dump writes `memorygraph_hashes.csv`
(SHA-256 + MD5 per file) next to the dumped files. What is done and what is planned: `docs/ROADMAP.md`.

Noise control: findings are grouped per process, scored once per rule, Low findings never trigger correlation and are hidden
in the Indications view by default, and ordinary software (OneDrive, Chrome helpers, Defender, .NET JIT hosts) is recognised.

## Settings

Theme (Dark, Light, or System = follow Windows), font size (8–18 pt), and remembered window size / panel positions (with *Reset saved layout*) are in Settings → Appearance.

Volatility path, symbol folders, which plugins to run, parallel plugins, inactivity / absolute timeouts, plugin cache, re-analyse-on-load, the *Test* button next to the
Volatility path, *Open log folder*. **Plugins are grouped** (Settings → Plugins): *Processes*, *Network connections*, *Injected code and modules*, *Open handles*,
*Deep check for hidden code* (psxview + ldrmodules + vadinfo), *Kernel integrity*, *Persistence* (services, Run keys, Winlogon / IFEO / AppInit, Active Setup, scheduled tasks),
*Execution history* (UserAssist, Amcache, shimcache), *Files and objects*, *Malware hunting* and *YARA scan*. A group is one tick box; it replaces the long list of single plugins
(for example `pslist` + `psscan` + `pstree` + `cmdline` + `getsids` are one group, *Processes*). The slow groups say so. Settings, cache and logs live in `~/.memorygraph/`
(override with the `MEMORYGRAPH_HOME` environment variable). Logs: `~/.memorygraph/logs/memorygraph.log`.

## Windows version, skipped plugins and Windows XP / 7

MemoryGraph reads the Windows version from `windows.info` (NT version, service pack, 32/64-bit) and uses it in three ways:

* **Plugins that do not exist for that Windows are skipped, not failed.** `windows.netscan` / `netstat` need Vista or later, `scheduled_tasks` and `amcache` Vista / 7 or later,
  `svcdiff` Windows 10 (build 15063) or later. They are shown as "skipped" with the reason; nothing turns red and the *Plugins ok* count does not drop.
* **Rules know the Windows version.** For example `services.exe` and `lsass.exe` are expected under `winlogon.exe` on XP, and rule **PT-005** reports a system process that did not
  exist yet on that Windows (such as `wininit.exe` on XP).
* **Volatility 2 supplies the network connections of XP / 2003** (optional, **Settings → Volatility 2**). Volatility 3 cannot read them. Point MemoryGraph at either the
  standalone `.exe` or the source folder (`vol.py`, needs Python 2.7); or drop it in `tools/volatility2/`. It is only started when needed (XP / 2003, and on Vista / 7 only when the
  Volatility 3 network plugins failed), uses the list-walking plugins (`connections`, `sockets`, `netscan` for Vista / 7), takes the profile (`WinXPSP3x86`, `Win7SP1x64`, …) from
  `windows.info` and passes `--kdbg` / `--dtb` so it does not have to scan the whole image, and falls back to `imageinfo` if a profile guess is wrong. The Volatility 2 and
  Volatility 3 results are **merged into one connection list**; each connection names the engine(s) that saw it. *Deep scan* (`connscan`, `sockscan`) is optional because it is slow.
  Volatility 2 is GPL and is not part of this project.

## If plugins do not run

* **Settings → Volatility path → Test** shows which Volatility is used and whether it starts.
* Progress page lists every plugin with its state; failures show Volatility's own message. Common causes:
  missing symbol files (add the folder under Settings → Extra symbol folders — see `docs/OFFLINE.md`), the file is not a Windows image, or a locked/truncated image.
* The log file contains the full command lines and error output.

### Volatility versions

`requirements.txt` also installs `capstone` (disassembly in the malfind view) and `yara-python` (`windows.vadyarascan`); without
`yara-python` that plugin is simply reported as not available.

MemoryGraph is developed and tested with **Volatility 3 2.28.2** (pinned in `requirements.txt`; the constant is
`RECOMMENDED_VERSION` in `volatility_runner.py`). Other releases are not blocked: MemoryGraph reads the version and the plugin list
from `vol -h`, skips plugins the installed Volatility does not have, and every failure message states the plugin, the Volatility
version, the Windows version of the image (from `windows.info`) and Volatility's own last output line. **Settings → Test** lists
the plugins that are missing. On another computer use `pip install -r requirements.txt` in the same environment as MemoryGraph.

Notes on the network plugins (checked in the 2.11.0 and 2.28.2 sources): both exist under the same names with the same output
columns. `windows.netscan` has no Windows XP/2003 support in either version (MemoryGraph skips it there and uses Volatility 2, see above); both plugins need the tcpip.sys symbols. In 2.11.0 `windows.netstat` does not handle
unreadable pages or missing tcpip symbols and ends with a Python traceback; 2.28.2 handles them (often an empty result plus an ERROR
log line, which MemoryGraph now reports as a failed plugin instead of "0 connections").

## Tests

```bash
pip install -r requirements.txt
pytest
```

`tests/fake_vol.py` imitates the `vol` command line (crashes, hangs, bad JSON, missing symbols, slow progress) so the
whole collection path is tested without a memory image. `tests/fixtures/mini_plugins.json` is real Volatility-shaped data.

## Windows and Linux (engines)

The start window has a switch with two options, **Windows** and **Linux**. The choice changes the window's words, the file filter of *Browse*, the plugin groups and symbol folders in
Settings (the ones of the other operating system are kept and come back when you switch back), the navigation of the dashboard (Linux has no Registry) and which engine analyses the
image. A saved investigation remembers its operating system and the switch follows it when it is loaded. Everything else (font size, Volatility path, timeouts, IOC lists, the notes
and triage of a case) is shared.

The code is split the same way: `app/engines/windows` is the complete Windows engine; `app/engines/linux` is a **skeleton** (every function exists and says "not implemented yet";
an analysis stops with a message naming the missing function). To see what a finished Linux run looks like, choose Linux and press *Show a demo investigation*: it opens a made-up
investigation (clearly marked DEMO DATA) in the real dashboard. `docs/ENGINES.md` says what the Linux engine has to provide and in which order.

## Project structure

```text
main.py
app/
  analysis/         shared by every engine: pipeline, controller, volatility_runner, plugin_cache + plugin_timing, case_state, ioc, story, hexview,
                    registry_core (plugin specs and Settings groups), rows, dump, indicators/ (base, scoring, correlation, corroboration)
  engines/
    base.py         the Engine interface (what the windows ask of an operating system)
    windows/        analysis/ (plugin registry, provider, normalizer, os_profile, Volatility 2, timeline, dumper, files, compare, registry, injection, known-good)
                    indicators/ (the rules, baselines, ATT&CK mapping)  data/
    linux/          the same layout, skeleton
  windows/          the GUI: home (with the OS switch), progress, dashboard, process tree, process details, indications, injection, plugin output, files, registry,
                    network, timeline, compare, system info, search, settings, widgets, placeholder pages
  models.py         evidence models + versioned, tolerant save/load
  errors.py         friendly errors, global exception hook, safe_slot
  settings.py  paths.py  logging_setup.py  tasks.py  theme.py  util.py
tools/volatility2/  drop-in folder for Volatility 2 (optional; the 2.6 standalone is included)
tools/realworld/    the testing report: run on real memory images, offline (see its README)
tests/  docs/
```

## Real-world tests

`tools/realworld/run_report.py` runs MemoryGraph on real memory images (real Volatility 3, real rules, real windows), compares the result with Volatility's raw output and writes a report
(Markdown, a self-contained HTML page and JSON) **on a computer with no internet**: `run_report.bat --check`, then `run_report.bat --dump image.raw`. `--simulate` runs synthetic
malware-shaped scenarios through the rules without any image. See `tools/realworld/README.md`. The results of the first runs, the bugs they found and a score per category are in
`docs/REALWORLD_REPORT.md`.
