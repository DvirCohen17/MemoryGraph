from app.analysis.indicator_engine import IndicatorEngine
from app.models import AnalysisResult, MemoryRegion, NetworkConnection, PluginResult, Process, split_endpoint


def make_process(pid, name, ppid=0, path=r"C:\Windows\System32\test.exe", command_line="", create="2026-01-01T00:00:00+00:00"):
    return Process(pid, ppid, name, path, "", "", 0, create, command_line)


def evaluate(*processes, regions=None):
    result = AnalysisResult("memory.raw", list(processes), [], [PluginResult("windows.pstree", "Completed", [])],
                            memory_regions=regions or [])
    return IndicatorEngine().evaluate(result)


def ids(findings):
    return {f.rule_id for f in findings}


def test_network_columns_with_separate_ports():
    assert split_endpoint("10.0.0.5:51432") == ("10.0.0.5", "51432")
    assert split_endpoint("[fe80::1]:443") == ("fe80::1", "443")
    assert split_endpoint("185.220.101.42:443") == ("185.220.101.42", "443")


def test_network_connection_is_not_an_indication_by_itself():
    p = make_process(100, "example.exe", path=r"C:\Program Files\Example\example.exe")
    p.network = [NetworkConnection(100, "example.exe", "10.0.0.5", "51432", "185.220.101.42", "443", "ESTABLISHED")]
    assert not any(f.rule_id.startswith("NET-") for f in evaluate(p))


def test_encoded_powershell_is_detected_but_ordinary_shell_use_is_not():
    parent = make_process(100, "explorer.exe", path=r"C:\Windows\explorer.exe")
    bad = make_process(200, "powershell.exe", 100, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=")
    fine = make_process(300, "cmd.exe", 100, r"C:\Windows\System32\cmd.exe", "cmd.exe /c dir")
    findings = evaluate(parent, bad, fine)
    assert "CL-001" in ids(findings)
    assert not any(f.process_pid == 300 for f in findings)      # interactive cmd from explorer: silence


def test_core_process_with_wrong_parent_and_duplicate_singleton():
    wininit = make_process(500, "wininit.exe", 0, r"C:\Windows\System32\wininit.exe")
    lsass = make_process(600, "lsass.exe", 500, r"C:\Windows\System32\lsass.exe", create="2026-01-01T00:00:05+00:00")
    fake = make_process(1700, "lsass.exe", 4321, r"C:\Users\Public\lsass.exe", create="2026-01-01T01:00:00+00:00")
    explorer = make_process(4321, "explorer.exe", 0, r"C:\Windows\explorer.exe", create="2026-01-01T00:30:00+00:00")
    findings = evaluate(wininit, lsass, fake, explorer)
    assert "PT-001" in ids(findings)       # wrong parent
    assert "PT-002" in ids(findings)       # two lsass
    assert "PR-002" in ids(findings)       # wrong path


def test_lookalike_names_but_not_legitimate_neighbours():
    from app.engines.windows.indicators.rules.path import lookalike_of
    assert lookalike_of("svch0st.exe") == "svchost.exe"
    assert lookalike_of("scvhost.exe") == "svchost.exe"
    assert lookalike_of("lsasss.exe") == "lsass.exe"
    for legit in ("svchost.exe", "taskhost.exe", "taskhostw.exe", "sihost.exe", "dllhost.exe", "conhost.exe", "chrome.exe", "OneDrive.exe"):
        assert lookalike_of(legit) is None, legit


def test_truncated_image_name_is_not_a_mismatch():
    p = make_process(10, "software_repor", 4, r"C:\Users\x\AppData\Local\Google\Chrome\User Data\SwReporter\1.0\software_reporter_tool.exe")
    assert "PR-004" not in ids(evaluate(p))
    q = make_process(11, "notepad.exe", 4, r"C:\Users\x\evil.exe")
    assert "PR-004" in ids(evaluate(q))


def test_vendor_appdata_programs_are_not_reported_but_temp_is():
    onedrive = make_process(10, "OneDrive.exe", 4, r"C:\Users\x\AppData\Local\Microsoft\OneDrive\OneDrive.exe")
    temp = make_process(11, "dropper.exe", 4, r"C:\Users\x\AppData\Local\Temp\dropper.exe")
    findings = evaluate(onedrive, temp)
    assert not any(f.process_pid == 10 for f in findings)
    assert any(f.process_pid == 11 and f.rule_id == "PR-003" for f in findings)


def _region(pid, hexdump, protection="PAGE_EXECUTE_READWRITE"):
    return MemoryRegion(pid, "x.exe", "0x1000", "0x1fff", "4.0 KB", protection, True, True, True, True, "windows.malfind",
                        {"Hexdump": hexdump})


def test_malfind_is_one_finding_per_process_and_scored_by_content():
    pe = make_process(10, "x.exe", 4)
    benign = make_process(11, "y.exe", 4)
    regions = [_region(10, "4d 5a 90 00"), _region(10, "00 00 00 00 00 00 00 00"),
               _region(11, "00 00 00 00 00 00 00 00"), _region(11, "00 00 00 00 00 00 00 00")]
    findings = [f for f in evaluate(pe, benign, regions=regions) if f.rule_id == "MEM-001"]
    by_pid = {f.process_pid: f for f in findings}
    assert len(findings) == 2
    assert by_pid[10].severity == "High"
    assert by_pid[11].severity == "Low"


def test_low_findings_never_trigger_correlation():
    p = make_process(10, "x.exe", 4, r"C:\Users\x\AppData\Roaming\Unknown\x.exe")
    findings = evaluate(p, regions=[_region(10, "00 00 00 00 00 00 00 00")])
    assert all(f.severity == "Low" for f in findings)
    assert not any(f.rule_id.startswith("CORR") for f in findings)


def test_correlation_uses_multiple_independent_artifacts():
    p = make_process(200, "powershell.exe", 100, r"C:\Users\User\AppData\Local\Temp\powershell.exe",
                     "powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=")
    p.memory_regions = [_region(200, "4d 5a 90 00")]
    p.network = [NetworkConnection(200, p.name, "10.0.0.5", "51432", "185.220.101.42", "443", "ESTABLISHED")]
    parent = make_process(100, "explorer.exe", path=r"C:\Windows\explorer.exe")
    findings = evaluate(parent, p, regions=p.memory_regions)
    corr = [f for f in findings if f.rule_id == "CORR-001" and f.process_pid == 200]
    assert len(corr) == 1 and corr[0].severity == "High"
    assert "NET-001" in ids(findings)


def test_a_failing_rule_does_not_stop_the_engine():
    class Broken:
        rule_id = "X-001"

        def evaluate(self, result):
            raise RuntimeError("boom")

    engine = IndicatorEngine(rules=[Broken()] + list(IndicatorEngine().rules))
    result = AnalysisResult("m", [make_process(1, "a.exe")], [], [])
    engine.evaluate(result)
    assert any("X-001" in e for e in engine.errors)
