# Real-world tests and the testing report

Runs MemoryGraph on real memory images, compares what it shows with what Volatility printed, and writes a report. **No internet is needed or used**: MemoryGraph never opens a
network connection, Volatility runs with `--offline`, and the report is plain files (Markdown, one self-contained HTML page, JSON) you can read anywhere.

## On the computer with no internet

1. Copy the whole project folder (including `.venv`, or install the packages from a wheelhouse: `docs/OFFLINE.md`) and the memory images.
2. Check that the computer is ready:

   ```text
   tools\realworld\run_report.bat --check                 (Linux / macOS: tools/realworld/run_report.sh --check)
   ```

   It checks Python, PySide6, Volatility 3 (version, plugin count), the symbol folders, Volatility 2, free disk space and the images, and says what is missing.
3. Analyse an image and get the report:

   ```text
   tools\realworld\run_report.bat --dump D:\images\case1.raw
   tools\realworld\run_report.bat --dump a.raw --dump b.mem --out D:\reports\run1
   tools\realworld\run_report.bat --dump x.lime --os linux
   ```

   The report is `realworld_report_<time>\REPORT.html` (also `REPORT.md` and `REPORT.json`). Each image also gets `<image>\result.json.gz`: open it in MemoryGraph with *Load existing*.
   A 5 GB Windows 10 image takes about 40 minutes with every plugin (`--plugins standard` is much faster); the start of the run prints an estimate from earlier runs on that computer.
4. Without any image (what the rules recognise on constructed malware-shaped rows):

   ```text
   tools\realworld\run_report.bat --simulate
   ```

Other options: `--expected FILE` (what is in the image, see below), `--volatility PATH`, `--no-ui` (skip the dashboard checks; they need PySide6), `--hash` (SHA-256 of each image),
`--from-manifest --dumps-dir testdumps` (every image of `manifest.json` that is in that folder; the others are listed as NOT TESTED with the reason), `--title TEXT`.

## What the report contains

1. Executive summary: dumps, plugin runs (completed / skipped / failed / unexplained), integrity checks, dashboard checks, expected facts, findings and their verdicts.
2. Test environment (operating system, Python, Volatility version, PySide6, dependencies).
3. Test dataset (every image, its size, operating system, time, or why it was not tested).
4. Plugin compatibility: status of every plugin run, classified **only from Volatility's own words** (unsupported operating system, missing dependency, version incompatibility,
   symbols unavailable, plugin crash, unclassified). A failure is never called a MemoryGraph bug without evidence.
5. MemoryGraph against the raw Volatility output: processes, names, parents, command lines, hidden processes, module lists, malfind regions, network connections (Volatility 3 and 2),
   handle counts, and the dashboard (every view builds, the process tree / network / plugin output / indications show what the result holds, every process window opens).
6. Detection results: each expected fact PASS / FAIL / INCONCLUSIVE (and the synthetic scenarios when `--simulate` is given).
7. Every finding with a verdict (True Positive / False Positive / Inconclusive from the expected-results file, otherwise **Unreviewed**: never guessed).
8. Missed detections and false positives.
9. Compatibility problems by cause.
10. Recommendations: Critical (integrity failures, missed verified facts), High, Medium, Low.
11. Scores 0–10, each with the formula that produced it. They are computed indicators, not an expert's judgement; a category that could not be measured says "not measured".
12. Next development priorities.

## The expected-results file

What is *in* the image cannot be read out of the image: you write it down. One JSON file per image (`<image>.expected.json` next to the image, `--expected FILE`, or
`tools/realworld/expected/<id>.json`); `expected/local-xp-sp3.json` is a real example.

```json
{
 "facts": [
  {"id": "P1", "type": "process",    "name": "reader_sl.exe", "pid": 1640, "ppid": 1484, "description": "...", "verified": true, "source": "windows.pslist"},
  {"id": "P2", "type": "parent",     "name": "services.exe", "parent_name": "winlogon.exe", "description": "..."},
  {"id": "N1", "type": "connection", "remote_address": "41.168.5.140", "remote_port": 8080, "pid": 1484, "description": "..."},
  {"id": "M1", "type": "region",     "pid": 1484, "protection": "PAGE_EXECUTE_READWRITE", "description": "..."},
  {"id": "D1", "type": "dll",        "name": "explorer.exe", "dll": "evil.dll", "description": "..."},
  {"id": "F1", "type": "finding",    "rule_id": "MEM-001", "pid": 1484, "min_severity": "High", "description": "..."},
  {"id": "F2", "type": "any_finding","process": "Lab12-03.exe", "min_severity": "Low", "description": "..."},
  {"id": "X1", "type": "plugin",     "name": "windows.netscan", "status": "Skipped", "description": "..."},
  {"id": "C1", "type": "max_severity", "severity": "Medium", "description": "a clean image has nothing above Medium"}
 ],
 "findings_review": {
  "true_positive":  [{"rule_id": "FILE-001", "severity": "Medium", "evidence_contains": "reach.exe", "why": "..."}],
  "false_positive": [{"rule_id": "UA-001", "title_contains": "Public", "why": "..."}],
  "inconclusive":   [{"rule_id": "MAL-001", "pid": 2756, "why": "..."}]
 }
}
```

`"verified": true` means you checked the fact against the raw plugin output (the report scores only verified facts; unverified ones are listed). A finding matches a review entry when
every key given matches (`rule_id`, `severity`, `pid`, `process`, `title_contains`, `evidence_contains`).

## The synthetic malware scenarios (`scenarios.py`)

Nine scenarios of constructed Volatility-shaped rows: a clean control, process injection, hollowing, a hidden process, persistence, an Office macro dropper that phones home, a kernel
rootkit, masquerading system processes, a portable tool with a public connection, and a control of benign look-alikes (the false positives found on real images). They go through the
real Windows engine. A pass shows the **rules recognise the pattern**; it does not show that Volatility prints such rows for a real sample and says nothing about recall on real
malware. Add a scenario by writing a function that fills an `Image` and listing what must be reported (`tests/test_malware_scenarios.py` runs them all).

## Getting public images

Nothing is downloaded: the public sources cannot be scripted (MemLabs is on mega.nz; several Volatility wiki links are dead; see `manifest.json` → `status`). Download an image on a
computer with internet, copy it to `testdumps/` under one of the names of its `manifest.json` entry, and run `--from-manifest`.

## Files

* `run_report.py` (+ `.bat`, `.sh`): the command described above. `run_realworld.py`: the per-image analysis it uses (also runnable on its own). `report_builder.py`: the report.
* `checks.py`: the comparisons with the raw Volatility rows. `ui_checks.py`: the dashboard checks. `scenarios.py`: the synthetic scenarios.
* `manifest.json`, `expected/`: the images that were asked for and the facts known about the ones that were tested.
* `tests/test_realworld_harness.py`, `tests/test_malware_scenarios.py`: the tests of all of this (a damaged result must fail the check that should notice it).
