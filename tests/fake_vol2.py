"""A stand-in for Volatility 2 (``vol.py`` / the standalone .exe), used by the tests. It follows the real command line:

    fake_vol2.py -f DUMP --profile=NAME [--kdbg=0x..] [--dtb=0x..] --output=json PLUGIN
    fake_vol2.py -f DUMP imageinfo
    fake_vol2.py -h

Environment:
  FAKE_VOL2_FIXTURE   JSON file {plugin: {"columns": [...], "rows": [[...], ...]}} (what ``--output=json`` prints)
  FAKE_VOL2_PROFILES  comma separated profiles it accepts (others: "Invalid profile ... selected", exit 1); empty = accepts any
  FAKE_VOL2_SUGGEST   what ``imageinfo`` suggests ("Suggested Profile(s) : ...")
  FAKE_VOL2_NOKDBG    fail when --kdbg is given (a wrong address)
  FAKE_VOL2_RECORD    file that receives one JSON line with the argv of every call
  FAKE_VOL2_NOT       print the Volatility 3 banner instead (to test the "wrong program" message)
"""
import json
import os
import sys


def main(argv):
    record = os.environ.get("FAKE_VOL2_RECORD")
    if record:
        with open(record, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(argv) + "\n")
    if "-h" in argv or "--help" in argv:
        if os.environ.get("FAKE_VOL2_NOT"):
            sys.stderr.write("Volatility 3 Framework 2.28.2\n")
        else:
            sys.stderr.write("Volatility Foundation Volatility Framework 2.6.1\n")
        print("Usage: Volatility - A memory forensics analysis platform.")
        return 0
    sys.stderr.write("Volatility Foundation Volatility Framework 2.6.1\n")
    profile = next((a.split("=", 1)[1] for a in argv if a.startswith("--profile=")), "")
    plugin = argv[-1]
    if plugin == "imageinfo":
        print("INFO    : volatility.debug    : Determining profile based on KDBG search...")
        print("          Suggested Profile(s) : " + os.environ.get("FAKE_VOL2_SUGGEST", "No suggestion (Instantiated with no profile)"))
        return 0
    allowed = [p for p in os.environ.get("FAKE_VOL2_PROFILES", "").split(",") if p]
    if allowed and profile not in allowed:
        sys.stderr.write(f"ERROR   : volatility.debug    : Invalid profile {profile} selected\n")
        return 1
    if os.environ.get("FAKE_VOL2_NOKDBG") and any(a.startswith("--kdbg=") for a in argv):
        sys.stderr.write("ERROR   : volatility.debug    : No suitable address space mapping found\n")
        return 1
    with open(os.environ["FAKE_VOL2_FIXTURE"], encoding="utf-8") as handle:
        data = json.load(handle)
    if plugin not in data:
        sys.stderr.write(f"ERROR   : volatility.debug    : You must specify something to do (try -h)\n")
        return 1
    sys.stdout.write(json.dumps(data[plugin]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
