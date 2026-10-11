"""A tiny stand-in for the Volatility 3 command line, used by the tests.

Usage mirrors the real tool:  fake_vol.py -f DUMP -r json PLUGIN
Behaviour is controlled with environment variables:
  FAKE_VOL_FIXTURE   path of a JSON file {plugin: [rows]}
  FAKE_VOL_FAIL      comma separated plugins that exit with an error
  FAKE_VOL_HANG      plugin that prints nothing and never finishes
  FAKE_VOL_SLOW      plugin that keeps printing progress for ~3 seconds before finishing
  FAKE_VOL_BADJSON   plugin whose output is not valid JSON
  FAKE_VOL_NOSYMBOLS exit with Volatility's "symbol table requirement" error for every plugin
  FAKE_VOL_VERSION   version printed by the banner (default 2.99.0)
  FAKE_VOL_PLUGINS   comma separated plugins listed by `-h` (like the real plugin list); asking for another one is "invalid choice"
  FAKE_VOL_ERRTEXT   "plugin::text": that plugin exits with code 1 and prints text on stderr
  FAKE_VOL_ERRLOG    plugin that logs an ERROR line, returns no rows and still exits with 0 (like netstat without tcpip symbols)
  FAKE_VOL_DUMPFILES comma separated FILE_OBJECT addresses (0x...): `windows.dumpfiles --virtaddr` writes a data-section file into -o DIR for
                     these (named like the real plugin does: file.<object>.<section>.DataSectionObject.<name>.dat) and nothing for the others
"""
import json
import os
import sys
import time


def main(argv):
    version = os.environ.get("FAKE_VOL_VERSION", "2.99.0")
    listed = [p for p in os.environ.get("FAKE_VOL_PLUGINS", "").split(",") if p]
    if "-h" in argv or "--help" in argv:
        print("usage: vol [-h] [-f FILE] [-r RENDERER] plugin ...")
        for name in listed:
            print(f"    {name}.{name.rsplit('.', 1)[-1].capitalize()}   description")
        sys.stderr.write(f"Volatility 3 Framework {version}\n")
        return 0
    # `... -r json PLUGIN [ARGS...]`: the plugin follows the renderer name (plugins may take arguments)
    plugin = argv[argv.index("-r") + 2] if "-r" in argv else next((a for a in argv if a.startswith(("windows.", "linux.", "mac."))), argv[-1])
    sys.stderr.write(f"Volatility 3 Framework {version}\n")
    if plugin == "windows.dumpfiles" and "--virtaddr" in argv and "-o" in argv:
        wanted = {int(x, 0) for x in os.environ.get("FAKE_VOL_DUMPFILES", "").split(",") if x}
        out = argv[argv.index("-o") + 1]
        for text in argv[argv.index("--virtaddr") + 1:]:
            if text.startswith("-"):
                break
            if int(text, 0) in wanted:
                name = f"file.{int(text, 0):#x}.0xffffa80012345678.DataSectionObject.dropped.exe.dat"
                with open(os.path.join(out, name), "wb") as handle:
                    handle.write(b"MZ" + bytes(range(256)) * 4 + b"http://evil.test/payload.bin\x00" + b"C:\\Users\\Public\\x.exe")
        return 0
    if listed and plugin not in listed:
        sys.stderr.write(f"vol.py: error: argument plugin: invalid choice: '{plugin}'\n")
        return 2
    target, _, text = os.environ.get("FAKE_VOL_ERRTEXT", "").partition("::")
    if plugin == target and text:
        sys.stderr.write(text.replace("\\n", "\n") + "\n")
        return 1
    if plugin == os.environ.get("FAKE_VOL_ERRLOG"):
        sys.stderr.write("ERROR    volatility3.plugins.windows.netstat: Unable to locate symbols for the memory image's tcpip module\n")
        sys.stdout.write("[]")
        return 0
    if os.environ.get("FAKE_VOL_NOSYMBOLS"):
        sys.stderr.write("Unsatisfied requirement plugins.PsList.kernel.symbol_table_name: A symbol table requirement was not fulfilled\n")
        return 1
    if plugin == os.environ.get("FAKE_VOL_HANG"):
        time.sleep(600)
        return 0
    if plugin in os.environ.get("FAKE_VOL_FAIL", "").split(","):
        sys.stderr.write("Traceback (most recent call last):\nRuntimeError: simulated plugin crash\n")
        return 1
    steps = 6 if plugin == os.environ.get("FAKE_VOL_SLOW") else 2
    for i in range(steps + 1):
        sys.stderr.write(f"\rProgress: {i * 100 / steps:6.2f}\t\tScanning FileLayer using PageMapScanner")
        sys.stderr.flush()
        if steps > 2:
            time.sleep(0.5)
    sys.stderr.write("\n")
    if plugin == os.environ.get("FAKE_VOL_BADJSON"):
        sys.stdout.write("this is not json {")
        return 0
    with open(os.environ["FAKE_VOL_FIXTURE"], encoding="utf-8") as handle:
        data = json.load(handle)
    rows = data.get(plugin, [])
    if "--key" in argv:                         # printkey --key K: the fixture may hold "windows.registry.printkey K" rows; arguments are recorded for the tests
        key = argv[argv.index("--key") + 1]
        rows = data.get(f"{plugin} {key}", rows)
        if os.environ.get("FAKE_VOL_ARGLOG"):
            with open(os.environ["FAKE_VOL_ARGLOG"], "a", encoding="utf-8") as handle:
                handle.write(" ".join(argv) + "\n")
    sys.stdout.buffer.write(json.dumps(rows, ensure_ascii=False).encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
