# What changed in this version

## Why a new dump did not seem to run the plugins

Reading the old code turned up several independent defects; any of them looks like "the plugins don't run":

1. **The dashboard was never rebuilt.** `show_dashboard()` only swapped `dashboard.result`. After loading a saved
   investigation (or finishing a first run) every later analysis showed the *old* data. The dashboard is now built
   fresh for each result.
2. **Fixed 120 s / 300 s timeouts** killed `windows.info`/`pslist` on large images and during the first-time symbol
   download; the timed-out plugin was simply retried with the same limit. If `pslist` failed the whole tree was empty.
3. **Windows code page.** `subprocess.run(text=True)` decodes with the ANSI code page, but Volatility emits UTF-8:
   a single non-ASCII process or file name made a plugin "fail".
4. **Dead end on failure.** The error appeared in a tiny label on a page with no way back; the analysis could not be
   cancelled, and a second analysis stacked a new controller on the old one.
5. A blocking `read(512)` on Volatility's progress pipe would have hidden progress and made busy plugins look idle
   (found and fixed while testing the new idle-timeout logic).

## Data bugs that made the rules blind or noisy

* The command line column is called **`Args`** in Volatility 3; it was never read, so every command-line rule was dead
  and no process had a command line.
* `pslist` has no path, so every process path was just its name; paths now come from `pstree`/`dlllist`.
* `malfind` columns are `Start VPN`/`End VPN`; ranges were empty. `PrivateMemory` was ignored.
* Users were shown as bare SIDs; names are now resolved from `getsids` (owner = first SID).
* The same fact was listed once per plugin (timeline) and the same malfind region was reported by four rules.

## Indications: 731 → 9 on your WinDump dump

Removed/rewritten the rules that produced the spam (handle-type diversity, "similar process names", "same DLL at two paths",
"process without network role", one finding per malfind page, parent/child correlation of Low findings) and replaced them
with baseline-driven rules (see README). Per-rule/per-process aggregation, scoring and `Low` hidden by default.
Re-analysing your saved `WinDump_analysis.json` with the new engine gives 9 findings (3 Medium, 6 Low) on that dump.

## New / changed pieces

* Plugin runner, cache, parallel execution, cancel, live progress, per-plugin status page, *Re-run N failed plugin(s)*.
* Process tree rewritten as a collapsible tree with detail panel (the diagram view is gone).
* Timeline rebuilt: one event per fact, process exits, network creation, third-party module loads, capture-time anchor,
  Δ relative to capture, activity chart with range selection, severity colouring, CSV export, implausible timestamps dropped.
* Error handling everywhere: file validation, friendly messages with details, background tasks, `safe_slot`, global
  exception hook, per-view isolation in the dashboard, per-rule isolation in the engine, atomic saves, tolerant loading
  of old files, logging to `~/.memorygraph/logs`.
* Saved investigations: compact JSON (no duplicated raw output), optional `.json.gz`, schema version.

## Fixes after the first real run

* `ThreadPoolExecutor.shutdown(cancel_futures=...)` only exists on Python 3.9+. On older Python the analysis
  stopped right after `windows.info`. The provider now cancels pending work itself; the code base is syntax-checked
  for Python 3.8 and a regression test imitates a 3.8 executor.
* *Try again* after a failed analysis crashed with "QThread already deleted": the controller asked a thread that
  Qt had already scheduled for deletion whether it was running. A task now tracks its own state.
