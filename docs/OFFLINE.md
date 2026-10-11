# Running MemoryGraph without internet

MemoryGraph itself never connects to the internet: it has no update check, no telemetry, no web requests and no links that open a
browser (a test, `test_every_technique_used_by_a_rule_has_local_details_and_the_app_has_no_web_links`, fails if a networking library or a
web address is added to the application code). Everything it shows is computed from the memory image and from files on this computer.

What used to point to the web is now a local file:

| Was | Now |
|-----|-----|
| MITRE ATT&CK technique page (link built from the technique id) | `app/engines/windows/data/attack_techniques.json`: tactics, a short description and "look for" advice per technique, shown in a finding's details. Edit the file to add or change entries. |

Two things outside MemoryGraph still need preparation on a computer without internet.

## 1. Volatility's symbol files

To read a Windows memory image, Volatility 3 needs the symbol table (an "ISF" JSON file) of that Windows build's kernel, and of
`tcpip.sys` for `windows.netscan` / `windows.netstat`. When a file is missing Volatility downloads it from Microsoft's symbol server on
the first run. MemoryGraph never allows that download (it always passes `--offline`), so the files have to be put in place beforehand:

1. On a computer **with** internet, either
   * download Volatility's ready-made Windows symbol pack (`windows.zip`, from the Volatility Foundation's download page) and unpack it, or
   * run Volatility once on a sample image of the same Windows build (it stores what it downloads in `%APPDATA%\volatility3\symbols`), or
   * build ISF files from PDB files with Volatility's `pdbconv` tool.
2. Copy the `.json` / `.json.xz` files to the offline computer into a folder, for example `D:\symbols\windows`.
3. In MemoryGraph: **Settings → Volatility 3 → Extra symbol folders → Add folder…**.

There is no offline switch: `--offline` is always passed to Volatility, so a missing symbol file fails at once with Volatility's own message instead of
waiting for network timeouts on every plugin. The folders are passed with `-s`. Symbols are not installed by MemoryGraph and are not
bundled with it (there are thousands of them, one per Windows build).

If an analysis fails with a symbol message, the failure text names the plugin and the Volatility version; the full Volatility output is in
Plugin Output and in the log folder (Settings → Open log folder).

Volatility 2 (optional, for Windows XP / 2003 network connections) needs no symbol files: its profiles are built in, MemoryGraph picks the profile from the image
itself, and it never connects to the internet. Copy the standalone `.exe`, or the source folder plus a Python 2.7, to the offline computer (see `tools/volatility2/README.txt`).

## 2. Installing the Python packages

`pip install -r requirements.txt` needs a package index. On a computer with internet:

```text
pip download -r requirements.txt -d wheelhouse
```

Copy the `wheelhouse` folder to the offline computer and install with

```text
pip install --no-index --find-links wheelhouse -r requirements.txt
```

(use the same Python version and operating system for both steps).

## What stays the same offline

* Analysing, saving and loading investigations, comparing investigations, the Files view and every dump use local files only.
* IOC lists, STIX/MISP files and YARA rules are read from local files you choose; MemoryGraph never fetches threat-intelligence feeds.
