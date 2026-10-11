# Roadmap status

`IDEAS.md` is the source of truth for the backlog and is not edited. This file tracks where each idea stands in the code.
Status values: **done**, **partial**, **not started**, **not planned (decision)**. Last updated against the code on 2026-10-08 (see the test count in the README).

## Ground rules for new features

* **Behavioural rules vs. your own reference data.** Built-in rules (`PT-`, `PR-`, `CL-`, `MEM-`, `DLL-`, `NET-`, `HND-`, `DRV-`, `SSDT-`,
  `CBK-`, `SVC-`, `PER-`, `UA-`, `FILE-`, `ENV-`, `VAD-`, `LDR-`, `PX-`, `CORR-`) describe suspicious *behaviour or structure*. Two families
  come from what the investigator supplies and are kept apart: **`IOC-*`** (IOC lists, YARA rules) and **`BASE-*`** (differences from an
  imported known-good baseline). The behavioural rules never read them, their findings are kept out of behavioural correlation, every one
  names the list/baseline it came from, and the Indications view can show either family on its own.
* **Provenance.** A finding keeps `source_plugins` and `EvidenceItem(source_plugin, row_index, field, value)`; decoders only display
  what the evidence says and show where it came from; ATT&CK tags are context and never change severity.
* **Plugins.** One `PluginSpec` in `app/engines/windows/analysis/plugin_registry.py` per plugin run (fixed arguments, an argument taken from a setting,
  a Settings checkbox shared by several runs, a "skipped unless this setting is set" rule). Availability/version problems are reported
  by the runner (`volatility_runner.py`: version, `vol -h` plugin list, missing dependencies such as yara-python), raw output stays in
  `PluginResult`, and rules read rows through `plugin_rows_indexed`. A rule whose plugin did not run produces nothing and does not fail.
* **The investigator's work** (triage, notes, bookmarks, baselines) lives in `AnalysisResult.case`, not on findings, because findings
  are rebuilt on every load. See `app/analysis/case_state.py`.
* **Windows fit the screen.** `app/windows/screen_fit.py` shrinks any window that is larger than the usable screen area (never full
  screen), and control bars wrap (`FlowLayout`) so no view forces a window wider than a laptop screen (the dashboard needs about 970 px).

## Status

| Idea (from IDEAS.md) | Status | What exists / what is left |
|---|---|---|
| Reviewed / false-positive button | **done** | Finding details: *Mark reviewed* (stays visible and counted), *False positive — hide* (hidden, out of scores/counts/colours), *Reopen*, with a reason. Indications: "Only not yet reviewed", "Show false positives / baseline-suppressed", and bulk *Mark shown as … reviewed / false positive* for the findings that pass the current filters. Decisions are keyed by process + PID + start time and survive re-analysis, re-running plugins and save/load. |
| Optionally exported as a baseline | **done** | *Case Notes → Export baseline from false positives…* |
| Notes and bookmarks | **done** | Process tree (★/✎ markers), a process's **modules** (Marks column), **memory regions** (in the hex view), timeline events, network connections, **rows of any plugin's output** (Plugin Output, Marks column) and findings. **Case Notes** lists them, jumps to the process (or to the plugin row), removes entries, exports a Markdown report. Plugin rows are identified by their content, so the marks survive running the plugin again. |
| Known-good baseline | **done** | Analyse a clean dump → *Export baseline from all findings…* → *Import baseline…* elsewhere. Findings with the same rule + process name + path + title are suppressed (listed in Case Notes, reversible), **and** rule **BASE-001** lists the processes (image name + path) that are not in the clean dump. Baselines exported by older versions still work for findings; they carry no process list. |
| More plugins (opt-in) | **done** | `svcscan` → SVC-001; `modules`+`modscan` → DRV-001; `driverscan` → DRV-002; `ssdt` → SSDT-001; `callbacks` → CBK-001; `userassist` → UA-001; Run/RunOnce (`printkey` ×4) → PER-001; Winlogon, AppInit_DLLs, IFEO (`printkey` ×3) → PER-002; `envars` → ENV-001; `filescan` → FILE-001, IOC-005; `mutantscan` → IOC-004; `vadinfo` → VAD-001; `ldrmodules` → LDR-001; `psxview` → PX-001; `vadyarascan --yara-file` → IOC-006; **more registry keys:** 32-bit Run/RunOnce, `Policies\Explorer\Run` (machine + user) and Active Setup `StubPath` (`printkey` ×5, choice *more registry autostart keys*) → PER-001; the registry's **services** (`printkey ControlSet001\Services --recurse`) → PER-003; **scheduled tasks** (`windows.registry.scheduled_tasks`, also found as `windows.scheduled_tasks` in older Volatility) → PER-004; `windows.registry.amcache` (`windows.amcache`) and `windows.shimcachemem` → Timeline only. |
| `-EncodedCommand` decoder | **done** | `app/analysis/decoders.py`; finding details, process-tree panel and process window, with source. Limits: PowerShell `-EncodedCommand` only (no `FromBase64String` payloads, no nested layers). |
| Hex / disassembly view for malfind | **done** | Memory tab → double-click a region: addresses + offsets, byte inspector, search (hex with `??`, ASCII, UTF-16; next/previous with all matches highlighted), go to address/offset, and a capstone disassembly of every loaded byte (32/64-bit, from the cursor, up to 5000 instructions, undecodable bytes shown as `db`). malfind itself stores only 64 bytes per region: *Dump malfind pages* + *Load bytes from file…* loads the region's dump (first 2 MiB). Without capstone the hex view still works. |
| Timeline events from more plugins | **done** | Registry keys written (Run keys, Active Setup, services, Winlogon/AppInit/IFEO values the rules object to), scheduled tasks created / last ran, UserAssist, Amcache, shimcache. System entries (Windows / Program Files) are left out, at most 2000 events per plugin (a result warning says when more were dropped), every event keeps plugin + row as provenance. Not added: `mftscan` (huge). |
| Hash dumped files, export hash list | **done** (artifacts) | Every dump writes SHA-256 + MD5 of each new file to `memorygraph_hashes.csv`, shows the SHA-256 list and checks hash IOCs. **Hashing the memory image itself: not planned (decision)** (slow on large images). |
| ATT&CK technique tags | **done** | `indicators/attack.py`, every rule has an explicit entry (some deliberately empty); shown in finding details, as a column in the Indications list, and searchable by id (`T1055`). |
| User-supplied IOC lists | **done** | Settings → IOC lists (+ YARA rule file). Text lists, **STIX 2 bundles and MISP exports** (format detected). IP/CIDR → IOC-001, domain → IOC-002, mutex → IOC-004, file name/path → IOC-005, YARA → IOC-006, hash → checked on dumped files. Hash IOCs are checked on every file dumped from the Files view and from the Process window, **and against every process image at once**: Process Tree → *Hash all process images…* dumps them with one `windows.pslist --dump` run, stores SHA-256 + MD5 per process in the investigation (CSV export too) and rule **IOC-007** matches them (a file that an antivirus blocks is reported and skipped, the others keep their hashes). **Domains, IPs and mutex names in process memory:** Settings → *Make YARA rules from this list…* writes a YARA file from the IOC list (ASCII + UTF-16, case-insensitive for domains and mutexes) for `windows.vadyarascan`; hits are IOC-006 findings with the matched text decoded. Nothing is left from the original IOC to-do list except Linux. |
| Process-lifetime lanes (Gantt) | **done** | **Lifetimes** view: lanes from start to exit/capture, risk colours that follow triage, psscan-only outline, capture line, parent→child connectors, filters, windows down to "last 15 min", **Ctrl + wheel zoom** with *Reset zoom*, tooltips, double-click opens the process, **Save image…** (PNG). |
| One dark theme | **done** | Light / System themes were removed on purpose: a single dark theme built from one colour palette (`app/theme.py` `PALETTE`), with gradients on primary buttons and cards, a slim scrollbar, a tab underline and a check-mark icon drawn at start. Old settings that say Light/System still load and mean Dark. |
| Adjustable font size | **done** | Settings → Font size (8–18 pt). A few fixed sizes inside widgets (timeline chart labels, splash logo) are not scaled. |
| Saved window layout | **done** | Window size/position (home and dashboard), splitter positions and **column widths**, restored on the next start; optional, with *Reset saved layout*. The last open view is deliberately not restored (a new analysis starts at the Overview). |
| Windows too large for the screen | **done** | Settings and every other window now open inside the usable screen area (see ground rules); long opt-in plugin descriptions wrap. |
| Memory dump comparison | **done** | **Compare** view: choose another saved investigation as reference. Matching by *same boot* (image name + start time; memory regions by address) or *different boot / system* (image name + path), chosen automatically from how many start times agree. Sections: processes (new / gone / changed), modules, network, findings (new / gone / severity changed), memory regions, plugin rows (drivers, services, tasks, Run keys, UserAssist, Amcache, shimcache, mutants, file objects, …). CSV export. To compare with another image, analyse and save it first. |
| File explorer for `filescan` | **done** | **Files** view: device / folder tree (system volume labelled `C:`), list with type, offset and FILE-001 flags, filter, bookmarks and notes, "seen elsewhere" (handles, modules, images), IOC file matches. *Run windows.filescan now* runs the plugin on an open investigation. **Dump** selected / all shown / one file with one `windows.dumpfiles --virtaddr` run (up to 500 at once; filescan's Offset is a kernel virtual address); dumps are re-attached from the dump folder later; each dumped file gets SHA-256 + MD5 (also `memorygraph_hashes.csv`), IOC hash check, type, entropy, PE sections / imports / exports, strings, and opens in the hex view. |
| No internet needed | **done** | The application makes no web requests and there is no "offline mode" switch any more: Volatility is always started with `--offline`. The ATT&CK link became a local file (`app/engines/windows/data/attack_techniques.json`: tactics, summary, what to look for). The symbol files Volatility needs must be on the computer (*symbol folders*, `-s`, in Settings); how to prepare them and the Python packages: `docs/OFFLINE.md`. |
| Plugin groups in Settings | **done** | 11 groups (`plugin_registry.BUNDLES`) replace the long list; each plugin belongs to exactly one group; a group writes back to the same settings keys as before (`enabled_plugins`, `run_extended_plugins`, `optional_plugins`). |
| Idea 1: OS-aware plugin applicability | **done** | `os_profile.py` reads NT version, service pack and architecture from `windows.info`; plugins declare the Windows versions they exist for (`min_nt`, `max_nt`); an inapplicable plugin is **Skipped** with the reason, not Failed, and does not count against *Plugins ok*. |
| Idea 2: OS-specific rule profiles | **done** | Rules read `nt_major` / `nt_version` (XP parents, legacy-only benign regions, PT-005 for system processes that do not exist on that Windows, svcdiff only on Windows 10). |
| Idea 3: malware-hunting plugins + rules | **done** (constructed rows) | `hollowprocesses` → MAL-001, `suspicious_threads` → MAL-002, `pebmasquerade` → MAL-003, `processghosting` → MAL-004, `svcdiff` → MAL-005, `driverirp` → MAL-006, `etwpatch` → MAL-007, all with ATT&CK entries. Tested on constructed rows in the plugins' column layout (checked against the Volatility sources); the rules were tuned against the real XP image, but no real image with hollowing or ETW patching was available. |
| Idea 5: injection chains | **done** | **Injection** view and `app/engines/windows/analysis/injection.py`; see the README. A chain needs a sign inside the process itself; handles and children alone never make one. |
| Idea 9: registry hive browser | **done** | **Registry** view and `app/engines/windows/analysis/registry_tree.py`; *Fetch another key…* runs `windows.registry.printkey --key` and saves the rows with the investigation. |
| Windows XP / 2003 network (Volatility 2) | **done; run against the real Volatility 2.6 standalone on a real XP image** (19 sockets read and merged; no established TCP connection was available to test) | `vol2_runner.py` / `vol2_adapter.py`, Settings → Volatility 2 (exe or `vol.py` + Python 2.7), automatic profile from `windows.info`, `--kdbg` / `--dtb` hints, `imageinfo` fallback, only started when needed, one merged connection list. Tested with a stand-in (`tests/fake_vol2.py`); the output columns and options were read from the Volatility 2 source. Volatility 2 and Python 2 are not installed on the development computer, so the first run on a real XP image may need small corrections. |
| Readable lists on small windows | **done** | Every dashboard view scrolls instead of squeezing its lists; minimum list sizes; `filescan` names damaged in memory are grouped under `(damaged names)` (`tests/test_list_sizes.py`). |
| Windows / Linux engines | **done (Linux: skeleton)** | `app/engines/windows` complete, `app/engines/linux` with every function declared and raising "not implemented yet"; animated OS switch on the start window that swaps the settings of each OS; the dashboard hides the Registry for Linux and shows placeholder pages for the Linux views that need engine code; a saved investigation carries `target_os`. `docs/ENGINES.md` is the guide for writing the Linux engine. |
| Offline testing report | **done** | `tools/realworld/run_report.py`: analyse an image, compare with the raw Volatility output, write REPORT.md / REPORT.html / REPORT.json on a computer with no internet (`--check` first); `--simulate` for ten synthetic malware scenarios. Linux checks are provisional until real Linux images exist. |
| Second source for High, BEH-001, known-good lists, process story, Quick triage | **done** | see `docs/REALWORLD_REPORT.md` section 1b. |
| HTML / PDF report | **not planned (decision)** | Markdown export of Case Notes exists. |
| **Linux image support** | **deferred (TODO, on purpose)** | `RealProvider` is Windows-only (plugin names, normalizer, rules). Needs a provider interface first: the plugin registry already separates "what to run" from "how"; the normalizer and rules would need an OS switch. |

## Rules (all silent unless their plugin / reference data is present)

| Rule | Plugin(s) | Finds | Noise control |
|---|---|---|---|
| DRV-001 | modules + modscan | driver object found by scan, missing from the module list | stale unloaded drivers = one Low finding; Temp/Public/Downloads paths = own Medium |
| DRV-002 | driverscan + modules | driver object whose start is in no module and whose name matches no module | one low-confidence finding |
| SSDT-001 | ssdt | system-call entries in non-kernel modules, indexes pointing into no module | one finding |
| CBK-001 | callbacks | kernel callbacks with no owning module | one finding |
| SVC-001 | svcscan | service binary/DLL in Temp/Public/Downloads (Medium) or per-user AppData (Low) | vendor AppData ignored |
| PER-001 | printkey (Run keys, 32-bit Run keys, Policies\Explorer\Run, Active Setup) | autorun entry from a risky folder (also `%TEMP%`, `%PUBLIC%`), encoded command, or interpreter/LOLBin | duplicates across the runs reported once; Active Setup: only `StubPath`, and only script hosts count (rundll32/regsvr32 are normal there) |
| PER-002 | printkey (Winlogon, AppInit, IFEO) | altered Winlogon Shell/Userinit, AppInit_DLLs, IFEO debugger | Process Explorer as Task Manager replacement = Low |
| PER-003 | printkey [Services] | service whose `ImagePath`, `ServiceDll` or `FailureCommand` is in Temp/Public/Downloads (Medium) or per-user AppData (Low), is encoded, or is a script host | disabled services (Start = 4) one level lower; `\SystemRoot\…`, `\??\…`, relative driver paths and `%SystemRoot%` are expanded first |
| PER-004 | scheduled_tasks | task action in a risky folder, encoded, or started with hidden-window / bypass / download options or a URL | a script host or LOLBin alone is not flagged; disabled tasks one level lower; COM-handler tasks skipped |
| UA-001 | userassist | programs the user launched from Temp/Downloads/Public/Recycle Bin | grouped: one Medium + one Low |
| FILE-001 | filescan | executables in Public/Recycle Bin/Windows\Temp, in Temp/Downloads, `name.pdf.exe` | at most three findings |
| ENV-001 | envars | COMSPEC / SystemRoot / windir with unusual values | one finding per distinct value |
| VAD-001 | vadinfo + dlllist | executable file-backed image mapped but not in the module list | low confidence; WOW64 DLLs excluded; needs dlllist |
| LDR-001 | ldrmodules | image mapped in a process but in none of the three loader lists | one per process; `apisetschema.dll` and WOW64 DLLs ignored; Low when the path is trusted |
| PX-001 | psxview | running process missing from pslist **and** psscan but seen by thread scan or csrss | psscan-only unlinking stays PT-003; exited processes ignored |
| BASE-001 | (any) + imported baseline | processes whose image name + path are not in the baseline | one finding; Medium only when a new process runs from a risky folder |
| PT-005 | windows.info + pslist | system process that did not exist yet on this Windows (e.g. `wininit.exe` on XP) | needs the Windows version |
| MAL-001 … MAL-007 | hollowprocesses, suspicious_threads, pebmasquerade, processghosting, svcdiff, driverirp, etwpatch | hollowed image, thread outside every module, PEB that differs from the kernel's record, deleted image file, service hidden from the list, IRP handler outside every module, patched ETW | XP artefacts of suspicious_threads ignored; smss.exe and same-file path notations ignored in the PEB check; svcdiff Windows 10 only |
| IOC-001/002/004/005/006/007 | netscan/netstat, cmdline, mutantscan+handles, filescan+modules+handles, vadyarascan, stored process-image hashes | matches against your lists / YARA rules / hashes | separate family |

## Checked on a second real image (Windows XP, 512 MB, a malware-lab machine)

The whole tool was run on `TEST-50F6D361CC-20260924-154417.raw` (NT 5.1; 27 processes): every core, extended and opt-in plugin (13 min, 23 completed with rows, netscan / netstat
and scheduled tasks are not supported on XP), all 12 views, all 27 process windows with every tab, the hex view of all 11 regions of one process, Compare (against a different
image and against itself: 0 differences), real hashing of every process image and a real `vadyarascan` with rules made from an IOC list. What it showed and what changed:

* **PT-001** reported `services.exe` and `lsass.exe` "started by unexpected parent winlogon.exe" (High, x2): on NT 5.x that is the normal parent. The rule now reads the
  Windows version (`windows.info`) and expects `winlogon.exe` there; a wrong parent on XP is still reported.
* **PER-002** reported the inert default IFEO entry `Your Image File Name Here without a path = ntsd -d` that XP / 2003 ship.
* **LDR-001** (5 findings) reported font files, theme / resource DLLs opened as data, and everything in the System process. It now ignores files that cannot be program images,
  the System process, and (with vadinfo) mappings that are not executable; an executable unlinked image is still Medium.
* **MEM-001**: the 1 MB region at `0x7f6f0000` that every XP GUI process has is reported one level lower (an MZ header or shellcode there is still High).
* **CBK-001** found something real: a kernel callback whose address is `0x1375c085`, a user-mode address, with no owning module. User-mode targets are now their own **High**
  finding; the other module-less callbacks stay Medium, and duplicate lines are listed once. **DRV-001** no longer prints garbage pool text as a driver path.
* Hashing the dumped process images failed completely because Windows blocked reading the malware sample (`Errno 22`): each file is now hashed on its own and the blocked ones
  are named in the message.
* A failed requirement check of a plugin is no longer explained as a symbol problem when `windows.info` already read the image (it is the plugin that does not support that Windows).
* The timeline got a "Vadyarascan" category (that plugin repeats each process's start time) and a chart range stretched back to 2009 by file modification times. Plugins MemoryGraph
  knows are no longer read by the generic time-column fallback, and shimcache file dates are their own *File time* category, off until ticked.
* Still reported on that image, correctly: Medium FILE-001 for `\RECYCLER\...\Dc23.exe1.0-rc2_signed.exe`, Low FILE-001 for `winup.exe` in a Temp folder, and the shimcache entries
  that show `PracticalMalwareAnalysis` programs and `procexp.exe` were executed.

## Checked on a real image

`windows.info`, `windows.filescan` (32,613 rows) and `windows.dumpfiles` were run on a real 5 GB Windows 10 image (Volatility 2.28.2) and the
results went through the Files view code. What that showed, and what was changed because of it:

* filescan 2.28 prints names **without a device** (`\Windows\System32\x.dll`) and lists opened **folders** as objects (about 72 % of the rows). Folders are now
  recognised (a name that is the parent of another name) and shown in the tree, not as files. A device-less volume is shown as *(volume not named)*, with `C:`
  when it holds `\Windows\System32`.
* The **Offset is a kernel virtual address**, so dumping uses `--virtaddr` (not `--physaddr`).
* FILE-001 and the Files view flagged Windows servicing leftovers (`WinSxS\Temp\PendingDeletes`) and `.lnk` shortcuts. Both are excluded now, which leaves the one
  genuine hit of that image (`\Windows\Temp\…\reach.exe`; its contents were not cached in memory, so the dump says "not cached").
* Dumping kernel32.dll and cmd.exe took 30 s in one run and produced their data and image sections. Most of an image-section dump is zero pages (57–65 %), so the
  report says so, and it explains an import / export table that is empty because its pages were not in memory. Windows' own files carry a hash instead of a compile
  time (year 2074); that is reported as such.
* Opening the Files view with 32 k rows took 47 s (a directory listing per file object, Python sorting on every rebuild); it now takes about 3 s.

## Known limitations

* The Volatility 2 integration and the network merge are tested against a stand-in and the Volatility 2 source only (see the status table). MAL-001 … MAL-007, the injection chains and the registry browser were tested on constructed rows; the real-image checks above were done before they existed, so the Injection and Registry views were only exercised on test data.
* Windows 7 is read by Volatility 3 itself (its network plugins start at Vista); Volatility 2 is only a fallback there, when the tcpip symbols are not available.

* The rules for the extended / opt-in plugins were tested on constructed rows in Volatility's column layout (checked against the 2.11.0 and
  2.28.2 plugin sources), not on a real image with those plugins; expect to tune thresholds after the first real runs. Large plugins
  (`filescan`, `vadinfo`) make the investigation file large.
* `windows.registry.printkey` is run for fixed keys only: Run/RunOnce (machine, user, 32-bit), Policies\Explorer\Run (machine, user), Winlogon, Windows/AppInit, IFEO, Active Setup and `ControlSet001\Services` (not ControlSet002 or other persistence keys such as Image hijacks under `Classes`, BHOs, Startup folders).
* Baselines and IOC lists are matched by text (names/paths/titles); a baseline fits other dumps of the same system best (user names appear in paths).
* The dark theme, motion, the start window layout, the Linux demo, the lifetimes view and the window fitting were checked on rendered screenshots and measurements on a headless display
  (with Segoe UI loaded for realistic widths), not on a real monitor.
* `windows.ssdt` only covers the kernel's own table (Volatility's limit).
* The malfind hexdump the investigation stores is 64 bytes; a longer view needs the dump file (*Dump malfind pages*). The hex view reads that file and the stored text only, never the memory image.
* The new timeline sources (registry keys, tasks, Amcache, shimcache) and rules PER-003/PER-004 were tested on constructed rows in the plugins' column layout (checked against the 2.11.0 and 2.28.2 sources), not on a real image.


## Motion and the Linux demo (2026-10-10)

| Item | Status | Notes |
|---|---|---|
| Smooth motion | **done** | `app/windows/motion.py`: page fade (`AnimatedStack`), staggered entrance of the start page, a glide for the navigation marker, a glow on primary buttons, an eased progress bar, and an overshoot slide in the OS switch. Everything is switched off in tests and by `motion.ENABLED = False`. Only checked in headless renders, not on a real monitor. |
| Start window layout | **done** | Content in a centred scrolling column (max width), fixed minimum control sizes, no squeezing on short windows; the window opens at 1100x760 and cannot be made smaller than 760x520. |
| Linux demo investigation | **done** | Start window, Linux selected: *Show a demo investigation*. Made-up host `web-prod-01` (reverse shell from nginx, a miner in /dev/shm, a hidden module, cron persistence) in `app/engines/linux/demo.py`; marked DEMO DATA in the dashboard. It is not an analysis of anything and the Linux engine is still a skeleton. |

## To do (decided, not started)

| Item | Status | Notes |
|---|---|---|
| **Known-guilty behaviour list** (behavioural "hashes") | **not started** | When an indication is judged really bad, store its *behaviour fingerprint* in a local list, so the same behaviour is reported as guilty the next time, on any image. A fingerprint is what stays the same between machines, not what changes: rule id + normalised process name + parent name + the kind of evidence (for example `LNX-PR-... | sh <- nginx | outbound :4444`, or `MAL-001 | image path class | RWX private region with PE header`), with user names, PIDs, addresses and timestamps removed. Stored as a JSON file in the MemoryGraph home next to the baselines and IOC lists; exportable and importable by hand (no network, ever). A match raises the finding to High with the reason "matches a behaviour confirmed guilty on <date> in <case>" and is visible in the finding details. |
| **Malware hash list that fills itself** | **not started** | Show the SHA-256 / MD5 of each dumped process image and file in the interface (Process window, Files view; partly there: the hash list of dumped files). The program never looks a hash up online. A hash is added to the local *known-guilty hashes* list when the finding that covers that file is judged guilty; a later image that contains the same hash is then reported by IOC-007 as guilty, with the date and the case it came from. The same list can be filled by hand or from an offline file (STIX / MISP / text, already supported for IOC lists). |
| Deciding "guilty" | **to decide** | Proposal: a finding is added to either list only when the analyst presses **Confirm guilty** (a new triage state next to *Reviewed* and *False positive*), or when two independent evidence sources reach High with a hash or behaviour match. Adding automatically from a High score alone would let one false positive mark every later image as guilty, so each entry keeps its source, can be removed, and shows how often it matched. |
| Shared by both engines | **to decide** | The lists live in the shared core (`app/analysis`) and are keyed by engine, so the Linux engine can use them from its first rule. |


**Done:** the Settings are a page of the main window (sidebar, page header, footer), not a pop-up. Apply, Cancel, *← Back* or Esc return to the page you came from.
