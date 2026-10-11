"""Problems found by running MemoryGraph on real memory images (tools/realworld, report in docs/REALWORLD_REPORT.md), now fixed.

Each test holds the rows exactly as Volatility printed them for the real image (Windows 10 build 15063, WinDump.mem; the XP image for the callbacks) and
states what a correct result is. They failed before the fixes (see the report, "RW-001" ... "RW-005").
"""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from test_round7 import rule_findings, with_rows, plugin_result  # noqa: E402
from test_pipeline_and_runner import load_fixture_result  # noqa: E402


def userassist(name, count=1):
    return {"Count": count, "Last Updated": "2018-06-21T06:46:00+00:00", "Name": name,
            "Path": "ntuser.dat\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Count"}


def test_rw001_shortcuts_on_the_public_desktop_are_not_programs_started_from_a_risky_folder():
    result = with_rows("windows.registry.userassist", [userassist("C:\\Users\\Public\\Desktop\\BatteryMon.lnk"), userassist("C:\\Users\\Public\\Desktop\\Google Chrome.lnk", 4)])
    assert rule_findings(result, "UA-001") == []
    # a program really run from Public, and a shortcut in a place that is not the Public Desktop, are still reported
    result = with_rows("windows.registry.userassist", [userassist("C:\\Users\\Public\\Desktop\\BatteryMon.lnk"), userassist("C:\\Users\\Public\\Libraries\\evil.exe"),
                                                      userassist("C:\\Users\\bob\\Downloads\\invoice.lnk")])
    found = {f.severity: f for f in rule_findings(result, "UA-001")}
    assert set(found) == {"Medium", "Low"} and "evil.exe" in found["Medium"].evidence[0] and "BatteryMon" not in " ".join(found["Medium"].evidence)
    assert "invoice.lnk" in found["Low"].evidence[0]


def driver_rows():
    """The USBSTOR driver of WinDump.mem: driverirp (name unreadable, handlers inside the driver's own image), driverscan, and a driver object with no name at all."""
    garbled = "ퟀ㮓讅\uffffԘꦡ翹"
    irp = [{"Address": 272688032314144, "Driver Name": garbled, "IRP": "IRP_MJ_CREATE", "Module": None, "Offset": 239203797328608, "Symbol": None},
           {"Address": 272688032314384, "Driver Name": garbled, "IRP": "IRP_MJ_CLOSE", "Module": None, "Offset": 239203797328608, "Symbol": None},
           {"Address": 272688032410352, "Driver Name": "WudfRd", "IRP": "IRP_MJ_CREATE", "Module": None, "Offset": 239203727892064, "Symbol": None}]
    scan = [{"Driver Name": garbled, "Name": "\\Driver\\USBSTOR", "Offset": "0xd98df95e62e0", "Service Key": "USBSTOR", "Size": "0x25000", "Start": "0xf802214b0000"},
            {"Driver Name": "WudfRd", "Name": "\\Driver\\WudfRd", "Offset": "0xd98df53ade60", "Service Key": "WudfRd", "Size": "0x3d000", "Start": "0xf802214e0000"}]
    return irp, scan


def test_rw002_irp_handlers_inside_the_drivers_own_unloaded_image_are_not_a_hook():
    irp, scan = driver_rows()
    result = load_fixture_result()
    result.plugins.append(plugin_result("windows.driverirp", irp))
    result.plugins.append(plugin_result("windows.driverscan", scan))
    assert rule_findings(result, "MAL-006") == []                            # USBSTOR and WudfRd: handlers lie in their own scanned images
    # the same handler outside the driver's own image is a hook (High) when the driver's name is readable...
    moved = [dict(irp[2], Address=0xF802219F0000)]
    result = load_fixture_result()
    result.plugins.append(plugin_result("windows.driverirp", moved))
    result.plugins.append(plugin_result("windows.driverscan", scan))
    found = rule_findings(result, "MAL-006")
    assert [f.severity for f in found] == ["Medium"] and "WudfRd" in found[0].title                   # one plugin only: Medium until a second plugin agrees
    result.plugins.append(plugin_result("windows.modules", [{"Base": 0xF80000000000, "Size": 0x1000, "Name": "ntoskrnl.exe", "Path": "x"}]))
    assert [f.severity for f in rule_findings(result, "MAL-006")] == ["High"]                          # driverscan now finds an object no loaded module backs (DRV-002)
    # ...and Low when the object's name is unreadable (a stale object: nothing is proven)
    result = load_fixture_result()
    result.plugins.append(plugin_result("windows.driverirp", [dict(irp[0], Address=0xD98DF58A6540, Offset=0xD98DF58A6590, **{"Driver Name": None})]))
    result.plugins.append(plugin_result("windows.driverscan", scan))
    found = rule_findings(result, "MAL-006")
    assert [f.severity for f in found] == ["Low"] and "unreadable name" in found[0].title


def test_rw003_images_are_not_reported_unlisted_when_the_process_own_loader_lists_are_incomplete():
    result = load_fixture_result()
    pid = next(p.pid for p in result.processes if p.pid > 4)
    row = lambda base, path: {"Base": base, "InInit": False, "InLoad": False, "InMem": False, "MappedPath": path, "Pid": pid, "Process": "svchost.exe"}
    result.plugins.append(plugin_result("windows.ldrmodules", [row(140710206570496, "\\Windows\\System32\\KernelBase.dll"), row(140710206570496 + 0x100000, "\\Windows\\System32\\umpnpmgr.dll")]))
    assert [f for f in rule_findings(result, "LDR-001") if f.process_pid == pid] == []           # KernelBase.dll "unlisted": the lists were only partly readable
    # a process whose core DLLs are listed and that has one unlisted image is still reported
    result = load_fixture_result()
    result.plugins.append(plugin_result("windows.ldrmodules", [row(0x7FF900000000, "\\Windows\\System32\\umpnpmgr.dll")]))
    found = rule_findings(result, "LDR-001")
    assert len(found) == 1 and found[0].process_pid == 0 and "umpnpmgr.dll" in found[0].evidence[0] and found[0].title.startswith("Trusted system images")
    # (trusted system images of all such processes are ONE Low finding; an image outside the Windows folders would be its own finding for the process)


def test_rw004_a_user_mode_callback_value_is_medium_and_code_bytes_are_not_a_hook():
    result = load_fixture_result()
    row = lambda kind, value, module=None: {"Callback": value, "Detail": None, "Module": module, "Symbol": None, "Type": kind}
    # Windows XP image: the same value three times, no module (and a normal one with a module)
    result.plugins.append(plugin_result("windows.callbacks", [row("IoRegisterFsRegistrationChange", 0x1375C085)] * 3 + [row("IoRegisterFsRegistrationChange", 0xF84D6876, "sr")]))
    assert {f.severity for f in rule_findings(result, "CBK-001")} == {"Medium"}
    # Windows 10 image: a value whose bytes are x86-64 instructions (48 89 08 70 48 89)
    result = load_fixture_result()
    result.plugins.append(plugin_result("windows.callbacks", [row("GenericKernelCallback", 0x894808708948)]))
    found = rule_findings(result, "CBK-001")
    assert [f.severity for f in found] == ["Low"] and "code bytes" in found[0].title


def test_rw005_the_symbol_failure_message_does_not_tell_an_offline_tool_to_download():
    from app.analysis.volatility_runner import classify_failure
    # the words Volatility 2.11.0 printed for a Windows 10 image without symbol files (real run, 2026-10-08)
    message = classify_failure("Unable to validate the plugin requirements: ['plugins.NetStat.kernel.symbol_table_name']", "windows.netstat")
    assert "internet" not in message.lower() and "symbol folders" in message.lower() and "--offline" in message
    tcpip = classify_failure("Unable to locate symbols for the memory image's tcpip module", "windows.netstat")
    assert "internet" not in tcpip.lower() and "symbol folders" in tcpip.lower()
