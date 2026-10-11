# MemoryGraph real-world test report

Date of the tests: 2026-10-08. Everything below was produced by running the real program on real memory images (`tools/realworld/run_realworld.py`: real Volatility 3,
the real `RealProvider`, the real rule engine, the real dashboard windows). No fixture, no `fake_vol.py`, no saved result was used for any number in this report.
The raw material is in `docs/realworld/` (per-image `*.md` / `*.json`, and the Volatility version comparison).

## 1. Executive summary

**Only 2 of the 17 requested images could be tested.** The public ones cannot be fetched by a script from this computer (section 3). The two tested images are the user's
own: a Windows XP SP3 machine (512 MB) and a Windows 10 machine (5 GB). No MemLabs or Volatility-wiki image, no known-clean image and no image with a documented
ground truth was available. So **detection recall (does MemoryGraph find real malware?) was not measured** and no score below should be read as a claim about it.

| | Windows XP SP3 | Windows 10 (15063) |
|---|---|---|
| Plugins | 42 completed, 5 skipped by design, **0 failed** | 47 completed, **0 failed** |
| Analysis time | 8 min | 42 min |
| MemoryGraph vs raw Volatility (processes, parents, command lines, hidden processes, DLLs, malfind regions, handles, network) | all 8 checks PASS, network INCONCLUSIVE (no Volatility 3 network plugin exists for XP) | all 10 checks PASS |
| Dashboard (19 UI checks: 13 views, process tree, network, plugin output, indications, 27 / 155 process windows) | 19 / 19 PASS | 19 / 19 PASS |
| Findings | 10 (1 High, 2 Medium, 7 Low) | 71 (5 High, 9 Medium, 57 Low) |
| Verdicts (checked against raw rows) | 1 true lead, 1 inconclusive, 8 unreviewed | 1 true lead, **3 false positives**, 6 inconclusive, 61 unreviewed |

* **What MemoryGraph gets right:** it keeps what Volatility printed. On 182 processes, 6,951 DLL rows, 34 malfind regions, 266 network rows (merged to 141 distinct
  connections, exactly what the dashboard shows) and 49,223 handles, no process, parent, command line, DLL, region, connection or handle count was lost or altered.
  Plugins that do not exist for XP are skipped with a reason instead of shown as failed.
* **What it gets wrong:** its *rules* are too loud on a real system. 5 findings in the Windows 10 image are High; of the 14 High + Medium findings only 1 is a confirmed
  lead, 3 are confirmed false positives and 6 could not be decided. A High finding that is built on an unreadable or stale Volatility output (callbacks, IRP handlers)
  is presented as a High finding. Five concrete bugs were found (section 9), each with an automated regression test; **all five were fixed in the second run (section 1a)**.
* **Volatility versions:** for the network plugins the difference between computers is the **symbol files, not the Volatility version**. Volatility 2.11.0 and 2.28.2
  give byte-identical `windows.netscan` / `windows.netstat` output on the Windows 10 image once both can see the same symbol files; without them 2.11.0 fails
  (section 5).
* **Overall:** the *data layer* is trustworthy on the two images tested. The *rule layer* is not yet trustworthy enough to rank findings for an investigator without
  review. Reliability for malware detection is **unmeasured**.

## 1a. Second run (same day): the five fixes, and Volatility 2 on both images

**Volatility 2.6 was added** (`tools/volatility2/volatility_2.6_win64_standalone.exe`, found automatically; GPL, started as a separate program, never imported).

**Windows XP, through the whole program** (`run_realworld.py`, real Volatility 2.6.1 inside MemoryGraph): the profile `WinXPSP3x86` was derived from `windows.info`,
`vol2.connections` (0 rows: XP had no active TCP connection, 15 s) and `vol2.sockets` (19 rows, 11 s) ran, and the Network view holds **19 connections** (TCP listeners 135 / 139 / 445
and UDP sockets). Harness: all 19 Volatility 2 rows are in MemoryGraph, no extra; 19 / 19 UI checks pass; the whole analysis took 6.8 min (first run: 8 min, without network). Run
directly, `connscan` returned 0 rows and `sockscan` 19. **Limit:** this image has no established TCP connection, so a real XP connection with a remote endpoint was not seen.

**Windows 10, do both Volatility versions run?** Yes, with a limit.
* Volatility 3 (2.28.2, and 2.11.0 with the same symbols): complete and identical (section 5).
* Volatility 2.6 has Windows 10 profiles only up to build 14393; this image is build 15063. With `Win10x64_14393`, `Win10x64_10586` and `Win10x64` it still **runs** (146 `netscan` rows,
  40 to 138 s) and finds **all 79 connections that have a remote endpoint** (the same endpoints Volatility 3 reports), but the **PID and owner columns are wrong**
  (only 80 of 146 rows have a plausible PID; the rest print pointer values or nothing). So on Windows 10 the right engine is Volatility 3. MemoryGraph already behaves correctly:
  it derives no Volatility 2 profile for this build (`volatility2_profile` is empty), so it never calls Volatility 2 there.

**The five bugs, fixed** (each has a regression test built from the real rows, `tests/test_realworld_regressions.py`; the `xfail` markers are gone):

| Id | Fix | Windows 10 result, before to after (same stored Volatility rows, current rules) |
|---|---|---|
| RW-004 | CBK-001: a user-mode callback value is Medium (was High: one unverified plugin value); a value whose bytes are x86-64 instructions is Low "look like code bytes" | CBK-001 High + Medium became Medium + Low; XP: High became Medium |
| RW-002 | MAL-006: a handler inside the driver's own image (driverscan Start..Start+Size, joined on the driver object) is not a hook; an unreadable driver name is Low | MAL-006: 3 High became 1 Low (USBSTOR and WudfRd gone) |
| RW-001 | UA-001 ignores `.lnk` shortcuts on the Public Desktop (a shortcut elsewhere, or a program in Public, is still reported) | UA-001 Medium gone (the Low one for Downloads stays) |
| RW-003 | LDR-001 / VAD-001 skip a process whose own lists are incomplete (ntdll / kernel32 / KernelBase mapped but "in no list") | LDR-001 21 became 17, VAD-001 29 became 26 |
| RW-005 | the symbol-failure messages (kernel symbols and tcpip) no longer tell the user to download; they point to Settings, Extra symbol folders, and say that each Volatility install has its own symbols folder | none |

| Windows 10, visible findings | before | after |
|---|---|---|
| total / High / Medium / Low | 71 / 5 / 9 / 57 | **61 / 1 / 7 / 53** |
| confirmed false positives | 3 | **0** |
| High + Medium findings: confirmed lead / inconclusive / unreviewed | 1 / 6 / 4 (and 3 confirmed false) | **1 / 5 / 2** (8 in total) |

The one High left is MAL-001 (hollowprocesses' note for svchost 2756, truth inconclusive). Every Windows 10 and XP fact in `expected/*.json` passes except the unverified `XP-L1` (Lab12-03.exe).
The fixes remove noise; they do not prove recall. Two of the Medium findings left (CBK-001 user-mode, MEM-001 on taskhostw) are still probably benign.

**Found afterwards from a screenshot (the Files view):** on a laptop-sized window the file list was squeezed to its header row, because the details pane under it refused
to shrink. Every list of every view was then measured at 1280x640, 1100x600 and 960x560. Fixed: every view now sits in a scroll area (a small window scrolls instead of crushing a list),
every table has a minimum height (190 px, the Files list 240 px), the Files / Registry trees 220 px, the plugin list of Plugin Output a minimum width (it was 54 px wide at 1100 px), and the
Files tree starts wider. `tests/test_list_sizes.py` keeps it that way. The same screenshot showed folders such as `" buildType="release"` in the tree: they are **Volatility's raw
`filescan` names** (444 of 32,613 on the Windows 10 image: fragments of Windows Update XML and garbled characters read from freed pool memory), which MemoryGraph turned into top-level
folders. They are now listed together in one pseudo volume, `(damaged names)`, last in the tree, still dumpable by address.

A test bug surfaced by the bundled exe: two existing unit tests assumed that no Volatility 2 exists; they now point `BUNDLED_DIR` at an empty folder (`tests/test_round7.py`), and a new test
checks that an exe dropped into `tools/volatility2/` is found without any setting.

## 1b. Third pass (2026-10-09): the weak spots, the engines and the offline report

**The weak spots that were left open are fixed.** Same stored Volatility rows, current rules; the facts of both expected-results files all pass.

| Weak spot | Fix | Windows 10 | Windows XP |
|---|---|---|---|
| High from one plugin row (MAL-001 …) | `analysis/indicators/corroboration.py`: a finding of MAL-001/003/004/006/007 is Medium (confidence Low) unless a second plugin points at the same process (or, for a kernel finding, the same kernel area); the reason is added to the finding | MAL-001 High → Medium | – |
| MEM-001 on a .NET host | the modules of a process now include what ldrmodules / vadinfo show mapped, not only dlllist | taskhostw 7252 Medium → Low | – |
| 53 Low VAD-001 / LDR-001 findings | trusted system images are ONE Low finding for all processes (a known-good list for the Windows silences what is normal); images outside the Windows folders stay one finding per process | 43 → 2 | – |
| PT-003 cannot tell unlinked from mid-creation | a process created at or after the capture start recorded by `windows.info` is Low ("caught mid-creation"); older ones that csrss and the thread scan still know are Medium with High confidence. The acquisition of the 5 GB image took minutes: 7 processes were created after its recorded start | both Medium → Low | – |
| CBK-001 user-mode value never cross-checked | the value is checked against the executable memory of the processes (malfind + vadinfo): inside one → High; in none → Low "holds no executable code"; not checkable → Medium; instruction bytes → Low | High/Medium → Low | High → Low |
| Nothing flags `Lab12-03.exe` | new rule **BEH-001**: a program running from the user's own folders (Desktop, Documents, Pictures, OneDrive, the profile) is a Low lead, Medium with a second sign (public connection, started by a document viewer, hidden, MZ / shellcode in memory) | – | Lab12-03.exe, procexp.exe, DumpIt.exe: 3 Low leads |
| DRV-002 for an unloaded driver | a driver object whose start lies in an image that modscan still lists is not an orphan | USBSTOR gone | – |

| Visible findings | before this pass | after |
|---|---|---|
| Windows 10 (155 processes) | 61: High 1, Medium 7, Low 53 | **20: High 0, Medium 4, Low 16** |
| Windows XP (27 processes) | 9: High 0, Medium 3, Low 6 | 12: High 0, Medium 2, Low 10 (3 of them the new leads) |

**Also fixed in this pass (found by the tests, not by the images):** the plugin timing file lost updates when plugins finished in parallel threads (lock + atomic write); `sanitize`
copied the default settings shallowly so one settings object could change the defaults of the next (deep copy); a test hung for 20 minutes on a modal dialog, so every dialog now fails
a test at once (`tests/conftest.py`); the full suite takes 2 minutes.

**Ideas added:** the process **Story** tab (parent, start, connections, children, registry and execution events about the same file, findings, on one clock); **known-good lists** (Case
Notes: export from a clean system, install on the computer you investigate with); **Quick triage** preset and plugin timing (the slowest plugins start first; an estimate before a run).

**Engines.** The Windows and Linux code now live in `app/engines/<os>`; the start window has an animated Windows / Linux switch that swaps the settings of each; the Linux engine is a
skeleton (`docs/ENGINES.md`). **Offline report.** `tools/realworld/run_report.py` (+ `.bat`, `.sh`) analyses an image and writes this kind of report with no internet: sections 1–12 are
generated from the run, scores carry their formula and their sample size, and a category that cannot be measured says so. `--simulate` runs ten synthetic scenarios (injection,
hollowing, hidden process, persistence, macro dropper, kernel rootkit, masquerading, a portable tool with a public connection, and two controls) through the real Windows engine:
25 of 25 expectations are detected, with one caveat that matters: two scenarios first failed because of **my** row data (columns that differ from the real plugin, and documentation
IP addresses that Python treats as private); I fixed the data, not the expectations. These scenarios show that the rules recognise the patterns, not that Volatility prints such rows
for a real sample, and not recall on real malware, which is still unmeasured.

A real run of the new script on the XP image (3.5 minutes, with `--simulate --hash`): 49 plugin runs (44 completed, 5 skipped by design, 0 failed), 10 integrity checks passed, 19 dashboard
checks passed, 10 of 10 expected facts met.

## 2. Test environment

| | |
|---|---|
| OS | Windows 11 Pro Education 10.0.26200 |
| Python | 3.12 (project venv) |
| Volatility 3 | 2.28.2 (project venv, `--offline`, symbol folder of that install) and 2.11.0 (separate scratch environment, for the version comparison) |
| MemoryGraph | source tree of 2026-10-08 (no version number exists; 249 unit tests + 5 harness tests pass; 5 expected-failure regression tests) |
| Dependencies | capstone 5.0.9, yara-python 4.5.4, pefile 2024.8.26, PySide6 (offscreen) |
| Volatility 2 | 2.6 standalone (`volatility_2.6_win64_standalone.exe`, now in `tools/volatility2/`, no Python 2 needed). **Not available in the first run**; used in the second run (section 1a) |
| Plugins run | `--plugins all`: core + extended + all opt-in groups except `vadyarascan` (needs a rule file) |

## 3. Test dataset and matrix

Download status was checked on 2026-10-08. Nothing was downloaded (MemoryGraph has no internet access by design and the sources cannot be scripted).

| Id | Dump | Source / URL | OS, arch | Challenge | Result |
|---|---|---|---|---|---|
| local-xp-sp3 | TEST-50F6D361CC-…raw (512 MiB, DumpIt) | the user's VM | Windows XP SP3 x86 | malware-analysis lab machine | **tested** |
| local-win10 | WinDump.mem (4,992 MiB, DumpIt) | the user's machine | Windows 10 build 15063 x64 | none; **not clean** (holds `\Windows\Temp\2964312081\reach.exe`) | **tested** |
| memlabs-1 … 6 | MemoryDump_Lab1–6 | https://github.com/stuxnet999/MemLabs (Lab 1–6) | unknown | Beginner's Luck, A New World, The Evil's Den, Obsession, Black Tuesday, The Reckoning | **NOT TESTED**: every image is on mega.nz (links in `manifest.json`); not scriptable, needs a browser or a Mega client |
| vf-cridex | Cridex | `http://files.sempersecurus.org/dumps/cridex_memdump.zip` | XP SP2 (per wiki) | Cridex | **NOT TESTED**: HTTP 403 |
| vf-shylock | Shylock | `http://various-things.googlecode.com/files/vmem2.zip` | XP SP3 (per wiki) | Shylock | **NOT TESTED**: HTTP 404 (Google Code is gone) |
| vf-r2d2 | R2D2 / 0zapftis | `http://www.mediafire.com/file/yxqodp1p2aca91x/0zapftis.rar` | XP SP2 (per wiki) | R2D2 | **NOT TESTED**: a MediaFire HTML page, not a direct download |
| vf-blackenergy, coreflood, sality, zeus, silentbanker | – | **not on** the wiki page `Memory-Samples` (checked) | unknown | – | **NOT TESTED**: no source found on the page you named |
| (not requested) Moyix fuzzy hidden-process sample, NIST, M57, Honeynet | on the same wiki page | links listed there | XP / Vista | – | not tried |

To test the missing ones: download an image yourself, put it in `testdumps/` under the name in `tools/realworld/manifest.json`, write `tools/realworld/expected/<id>.json`
(copy `local-xp-sp3.json`), run `python tools/realworld/run_realworld.py`. See `tools/realworld/README.md`.

## 4. Volatility baseline and MemoryGraph comparison

The baseline is the raw output of the Volatility plugins that MemoryGraph ran (kept in the investigation file). The checks re-derive the facts from those raw rows with plain
column lookups, independently of the normalizer, and compare. Full tables: `docs/realworld/local-xp-sp3.md`, `docs/realworld/local-win10.md`.

| Check | XP | Windows 10 |
|---|---|---|
| Same processes as `pslist ∪ psscan` | PASS 27 / 27 | PASS 155 / 155 |
| Process names, parent PIDs, command lines | PASS (27) | PASS (155 / 139 / 139) |
| Hidden processes (psscan only, not exited) | PASS (none) | PASS ([3828, 6120] both sides) |
| DLL lists per process (`dlllist`) | PASS (1,172 rows, 26 processes) | PASS (5,779 rows, 124 processes) |
| malfind regions (pid + start) | PASS 15 / 15 | PASS 19 / 19 |
| Network (netscan + netstat) | INCONCLUSIVE (plugins not supported on XP) | PASS: 266 rows → 141 distinct connections, all in MemoryGraph, no extra |
| Handle counts per process | PASS (5,751) | PASS (43,472) |
| Dashboard views build / process tree / network table / plugin output / every process window | PASS 19 / 19 | PASS 19 / 19 |

A check that damaged data would fail is itself tested (`tests/test_realworld_harness.py`: a dropped process, a wrong parent, a lost DLL, a lost connection and a lost
region are each noticed).

## 5. Plugin compatibility

All 94 plugin runs on the two images: **89 completed, 5 skipped by MemoryGraph on purpose, 0 failed.**

| Plugin | Windows 10, Vol 2.28.2 | Windows XP, Vol 2.28.2 | Reason / classification |
|---|---|---|---|
| windows.netscan | Completed (174 rows, 70 s) | not run: skipped (needs Vista+) | **Volatility plugin limitation**: Volatility itself says `NotImplementedError: This version of Windows is not supported: 5.1 15.2600!` (also in 2.11.0 with symbols) |
| windows.netstat | Completed (92 rows, 3–5 s) | not run: skipped | same |
| windows.registry.scheduled_tasks | Completed (232) | skipped (needs Vista+) | not applicable to XP (MemoryGraph's applicability table) |
| windows.registry.amcache | Completed (1,230) | skipped (needs 7+) | not applicable to XP |
| windows.malware.svcdiff | Completed (0 rows) | skipped (needs Win 10) | not applicable |
| hollowprocesses, processghosting, etwpatch | Completed (1 / 0 / 0 rows) | Completed (0 / 0 / 0) | 0 rows = nothing found; indistinguishable from "plugin saw nothing" |
| every other plugin (40) | Completed | Completed | – |
| windows.vadyarascan | not run | not run | needs a rule file (reported as a warning) |

**Volatility version comparison (`windows.netscan` / `windows.netstat`, `--offline`):**

| Image | 2.11.0, fresh install | 2.11.0 + symbol folder of the 2.28.2 install | 2.28.2 |
|---|---|---|---|
| Windows 10 netstat | **fails** (`Unable to validate the plugin requirements: ['plugins.NetStat.kernel.symbol_table_name']`) | completes, 27,931 bytes | completes, 27,931 bytes, **byte-identical** |
| Windows 10 netscan | **fails** (same) | completes, 52,709 bytes | completes, 52,709 bytes, **byte-identical** |
| Windows XP netscan / netstat | fails: kernel symbols `ntkrnlpa.pdb` not available offline | `NotImplementedError: … not supported: 5.1` | `NotImplementedError: … not supported: 5.1` |

So the failure that appears "on different computers" is **missing symbol files in that Volatility installation** (the 2.28.2 install here has a `symbols/windows/` folder with
`ntkrnlmp.pdb`, `ntkrnlpa.pdb`, `tcpip.pdb`; a fresh 2.11.0 has none). It is **not** a Volatility 2.11.0 vs 2.28.2 difference and **not** a MemoryGraph bug. MemoryGraph's own
classifier recognises all three messages. The fix on any computer is Settings → Extra symbol folders (this is also why the application passes `-s`). MemoryGraph's message
for this case is wrong in one respect (bug RW-005). Not tested: Volatility versions other than these two, and a Volatility that lacks `windows.netscan`.

## 6. Detection results (expected facts)

`tools/realworld/expected/*.json`. "Verified" = read from raw Volatility rows by hand; the one unverified fact is marked.

Windows XP:

| Expected finding | MemoryGraph | Result |
|---|---|---|
| Lab12-03.exe PID 1780 started by explorer.exe PID 1556; procexp.exe 2016; DumpIt.exe 2044 | present with those parents | PASS ×3 |
| services.exe and lsass.exe started by winlogon.exe (normal on XP) | correct, and **no PT-001 false alarm** | PASS ×2 |
| netscan / netstat reported as skipped, not failed | Skipped with reason | PASS ×2 |
| FILE-001 Medium: executable in the Recycle Bin (`Dc23.exe1.0-rc2_signed.exe`) | reported | PASS (a lead; content not analysed) |
| CBK-001 High: IoRegisterFsRegistrationChange 0x1375c085 | reported | PASS, but see section 6a: probably a Volatility artifact |
| Something is reported about Lab12-03.exe (a Practical Malware Analysis sample on the Desktop) | nothing is reported | **FAIL (unverified expectation)**: judged from the file path only; the sample was not analysed |

Windows 10:

| Expected finding | MemoryGraph | Result |
|---|---|---|
| System PID 4; services.exe and lsass.exe under wininit.exe | correct | PASS ×3 |
| PIDs 3828 and 6120 are in psscan + thrdscan but not pslist, no exit time | both flagged hidden; PT-003 Medium on both | PASS ×2 (whether they are really unlinked is **inconclusive**) |
| reach.exe in `\Windows\Temp\2964312081` | FILE-001 Medium | PASS (a lead; content not analysed) |
| hollowprocesses' note for svchost 2756 | MAL-001 High | PASS (relays the plugin; truth **inconclusive**) |
| netscan / netstat complete | complete, 141 connections | PASS ×2 |

### 6a. Every High and Medium finding on the Windows 10 image

| Rule | Sev | Subject | Verdict | Evidence |
|---|---|---|---|---|
| FILE-001 | Medium | `\Windows\Temp\2964312081\reach.exe` | **True positive (lead)** | file object in raw filescan |
| UA-001 | Medium | `Public\Desktop\BatteryMon.lnk`, `Google Chrome.lnk` | **False positive** | raw userassist rows are shortcuts, not programs started from Public (RW-001) |
| MAL-006 | High | driver named `ퟀ㮓讅…` | **False positive** | driverscan: `\Driver\USBSTOR` at 0xf802214b0000; modscan lists `USBSTOR.SYS` there: an unloaded driver, name unreadable (RW-002) |
| MAL-006 | High | WudfRd, "?" | unreviewed (same pattern as above, not proven) | |
| LDR-001 | Low | svchost.exe 844 | **False positive** | dlllist of PID 844 has no KernelBase.dll: its loader lists were incomplete (RW-003) |
| CBK-001 | High / Medium | 0x1f850f21394c; 0x894808708948 | inconclusive, probable Volatility artifact | no module; the second value looks like instruction bytes; same pattern on the XP image (RW-004) |
| MAL-001 | High | svchost.exe 2756 | inconclusive | relays "no VAD at the image base"; could be unreadable page tables |
| PT-003 | Medium ×2 | svchost 3828, taskhostw 6120 | inconclusive | in psscan/thrdscan (6120 also csrss), no exit time: unlinked, or caught while being created/terminated |
| MEM-001 | Medium | taskhostw.exe 7252 | inconclusive (likely benign) | two RWX regions that hold data, started `ngentask.exe` when the .NET NGEN task existed; circumstantial only |
| MAL-002, DRV-002, VAD-001 (software_repor, 44 images) | Medium | | unreviewed | |

False-positive control: 71 findings on one workstation. 50 of them are Low `VAD-001` / `LDR-001` (hidden by default in the Indications view, which showed 21 rows). Of the 14
visible High + Medium findings, 1 is a confirmed lead and 3 are confirmed false positives; 6 are undecided.

## 7. Missed detections

**None established. None could be.** With no image that has a documented ground truth, "MemoryGraph missed X" cannot be shown. The only candidate is `Lab12-03.exe` on the XP
image: a sample that is probably malicious (judged only from its folder name) runs under explorer.exe and MemoryGraph reports nothing about it. That is consistent with the
design (no signature or name rules; the process shows no injection, no network, no persistence entry in the plugins that ran), so it is recorded as an **unverified
expectation that failed**, not as a bug. The XP network connections were not read at all (Volatility 2 not installed), so any malware network activity on that image is
unknown.

## 8. UI / data integrity problems

None found: 38 / 38 UI checks passed (every view builds, the process tree lists every process, the Network view holds every connection, Plugin Output offers all 44 (Windows 10) and 39 (XP) completed plugins with rows,
all 182 process windows open). Two limits: the checks read the models behind the views, not rendered pixels; and the Indications view hides Low findings by default
(by design), so 71 findings appear as 21 rows.

## 9. Compatibility problems and bugs

| Id | Type | Description | Root cause | Impact | Regression test |
|---|---|---|---|---|---|
| RW-001 | MemoryGraph bug (rule) | UA-001 reports `.lnk` shortcuts on `C:\Users\Public\Desktop` as "programs started from Public" (Medium) | the rule checks the folder prefix only; UserAssist also records shortcut launches | false Medium on every machine that has Public Desktop shortcuts | `test_shortcuts_on_the_public_desktop…` |
| RW-002 | MemoryGraph bug (rule) | MAL-006 reports High for a stale driver object (unloaded USBSTOR) | the rule treats "handler outside every loaded module" as hooking; it does not consult `modscan` / `driverscan` for an unloaded image | false High | `test_irp_handlers_of_an_unloaded_driver…` |
| RW-003 | MemoryGraph bug (rule) | LDR-001 reports images "in no loader list" for a process whose own `dlllist` is incomplete (svchost 844, no KernelBase.dll) | the rule cannot tell an unlinked image from an unreadable list | 50 Low findings of noise | `test_ldr_findings_are_not_reported…` |
| RW-004 | MemoryGraph bug (confidence) + Volatility artifact (probable) | CBK-001 is High on an IoRegisterFsRegistrationChange value that is a user-mode address / instruction bytes (both images) | the rule trusts a `windows.callbacks` value that is probably mis-parsed (the same bogus value appears three times on XP) | a High finding that may be nothing | `test_a_callback_value_repeated_identically…` |
| RW-005 | MemoryGraph bug (message) | The symbol-failure text says the first analysis "needs internet access to download symbols" although MemoryGraph never goes online | `classify_failure` text predates the removal of the online mode | misleading advice; should point to Settings → Extra symbol folders | `test_the_symbol_failure_message…` |
| – | Volatility limitation | `windows.netscan` / `netstat` on XP (all versions tested) | `NotImplementedError: … not supported: 5.1` | no network data for XP unless Volatility 2 is configured | – |
| – | Environment | Volatility fresh install without symbols fails on every Windows 10 network plugin | no `symbols/windows/*.pdb` | see section 5 | – |
| – | Not tested | Volatility 2 integration | no Volatility 2 / Python 2 here | XP network data unverified | – |

No dependency problem occurred (yara-python, capstone, pefile present). No bug was fixed in the first pass (fixing was not part of that request). All five were fixed in the second run (section 1a) and the `xfail` markers were removed.

## 10. Recommendations

**Critical**
1. Obtain images with a documented ground truth (MemLabs, Cridex, Zeus, …) and run the harness on them. Until then nothing is known about recall.

**High**
2. RW-004: do not rate a `windows.callbacks` row High when its value is a user-mode address, not a plausible pointer, or the same bogus value repeated; show it as Low "unreliable plugin output".
3. RW-002: make MAL-006 consult `modscan` / `driverscan` so the handlers of an unloaded driver are at most Low.
4. Make single-plugin findings (MAL-001 from one hollowprocesses note) Medium until a second source agrees.

**Medium**
5. RW-001: ignore `.lnk` entries in UA-001 (or treat the shortcut target).
6. RW-003: skip LDR-001 / VAD-001 for a process whose `dlllist` lacks `ntdll.dll` / `KernelBase.dll`, and say "loader lists incomplete" once per process.
7. RW-005: correct the symbol message.
8. Test the Volatility 2 integration on a real XP image (install Volatility 2 standalone and run the harness).

**Low**
9. Show the Volatility version in the investigation header and in saved reports.
10. Report "0 rows" plugins as "nothing found" and distinguish them from "output truncated".

## 11. Final score (0–10, not inflated)

| Category | Score | Why |
|---|---|---|
| Plugin reliability | 8 | 89 of 94 runs completed, 5 skipped with a stated reason, 0 unexplained failures; but only two images and one Volatility 3 build per image |
| Process analysis | 9 | 182 processes, parents, command lines, hidden processes all match the raw output; PT-003 cannot tell an unlinked process from a transient one |
| Memory analysis | 6 | malfind and VAD data carried exactly, but triage is noisy (50 Low VAD / LDR findings) and the Medium on taskhostw cannot be justified or refuted |
| Network analysis | 7 | Windows 10: exact merge of 266 rows into 141 connections with every field. Windows XP: now works through the real Volatility 2.6 (19 sockets merged and shown); no established TCP connection was available to prove the connection path |
| Detection rules | 5 | after the fixes: 8 High + Medium findings on Windows 10: 1 lead, 5 undecided, 2 unreviewed, 0 confirmed false; recall still unmeasured |
| False-positive control | 5 | 1 High left on a workstation (undecided), 3 confirmed false positives removed; 53 Low findings of VAD / LDR / MEM noise remain |
| Evidence integrity | 8 | all raw data preserved, findings link to rows; findings built on unreliable plugin output carry no warning |
| UI / data presentation | 9 | 38 / 38 checks; only models were read, not pixels |
| Volatility compatibility | 8 | Volatility 3 2.11.0 and 2.28.2 identical with the same symbols; failures classified and now with correct advice; Volatility 2.6 runs on XP and is correctly kept away from Windows 10 build 15063; other versions untested |
| Overall forensic usefulness | 7 | a reliable data viewer with a less noisy rule layer after the fixes; recall is still unmeasured until ground-truth images are tested |

## 12. Next development priorities

1. Run the harness on ground-truth images (MemLabs 1–6, Cridex, Zeus…) and add their `expected/*.json`.
2. Done (section 1a): RW-004, RW-002, RW-001, RW-003, RW-005. Next: the remaining Medium noise (CBK-001 user-mode, MEM-001 on .NET hosts) and a second source for MAL-001.
3. Done with Volatility 2.6 (19 sockets). Still needed: an XP / 2003 image with an established TCP connection.
4. Require a second source for any High finding that rests on one plugin row.
5. Keep the harness in the release routine: `python tools/realworld/run_realworld.py` before each release.
