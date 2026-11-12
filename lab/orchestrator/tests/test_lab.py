"""Tests for the lab orchestrator without VMware, 7-Zip, gh or the internet:  python -m unittest discover -s tests"""
import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from mglab import bazaar, package, pipeline, storage, vmware
from mglab.config import ConfigError, load_families, load_lab_config

HERE = Path(__file__).resolve().parent.parent


class TempDir(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


SAFE_VMX = """.encoding = "windows-1252"
displayName = "victim-win10"
mainMem.useNamedFile = "TRUE"
ethernet0.present = "TRUE"
ethernet0.connectionType = "custom"
ethernet0.vnet = "VMnet9"
isolation.tools.hgfs.disable = "TRUE"
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
usb.present = "FALSE"
"""


def write_lab_toml(root: Path, vmx: Path) -> Path:
    text = (HERE / "lab.toml.example").read_text(encoding="utf-8")
    text = text.replace(r"D:\malware-lab\vms\victim-win10\victim-win10.vmx", str(vmx))
    text = text.replace(r"D:\malware-lab\work", str(root / "work")).replace(r"D:\malware-lab\samples", str(root / "samples"))
    text = text.replace(r"D:\malware-lab\memorygraph-dumps", str(root / "dumps-repo"))
    path = root / "lab.toml"
    path.write_text(text, encoding="utf-8")
    return path


class ConfigTests(TempDir):
    def test_example_config_and_families_load(self):
        cfg = load_lab_config(write_lab_toml(self.tmp, self.tmp / "v.vmx"))
        self.assertEqual(set(cfg.guests), {"win7", "win10", "win11"})
        self.assertEqual(cfg.volume_size, "1900m")
        families = load_families(HERE / "families.toml")
        self.assertGreaterEqual(len(families), 10)
        for f in families:
            self.assertTrue(set(f.guests) <= {"win7", "win10", "win11"}, f.name)
            self.assertTrue(f.description and f.look_for, f.name)
        self.assertEqual(next(f for f in families if f.name == "Emotet").signature, "Heodo")

    def test_bad_file_type_is_refused(self):
        path = self.tmp / "f.toml"
        path.write_text('[[family]]\nname="X"\nsignature="X"\nguests=["win10"]\nfile_types=["docm"]\n', encoding="utf-8")
        with self.assertRaises(ConfigError):
            load_families(path)

    def test_auth_key_from_environment(self):
        cfg = load_lab_config(write_lab_toml(self.tmp, self.tmp / "v.vmx"))
        os.environ.pop(cfg.auth_key_env, None)
        with self.assertRaises(ConfigError):
            cfg.auth_key()
        os.environ[cfg.auth_key_env] = "abc"
        try:
            self.assertEqual(cfg.auth_key(), "abc")
        finally:
            os.environ.pop(cfg.auth_key_env, None)


FAMILY = SimpleNamespace(name="AgentTesla", slug="agenttesla", file_types=["exe"], dll_export="DllRegisterServer",
                         description="A .NET stealer.", look_for=["SMTP connections"])


class BazaarTests(TempDir):
    def test_query_sends_auth_key_and_parses(self):
        seen = {}

        def opener(request, timeout):
            seen["key"] = request.get_header("Auth-key")
            seen["body"] = request.data.decode()
            return json.dumps({"query_status": "ok", "data": [
                {"sha256_hash": "A" * 64, "file_type": "exe", "file_size": 1000, "signature": "AgentTesla", "file_name": "x.exe"},
                {"sha256_hash": "b" * 64, "file_type": "docx", "file_size": 1000},
                {"sha256_hash": "c" * 64, "file_type": "exe", "file_size": 999 * 2**20},
                {"sha256_hash": "d" * 64, "file_type": "exe", "file_size": 2000},
            ]}).encode()

        rows = bazaar.BazaarClient("KEY", opener=opener).samples_for_signature("AgentTesla", 5)
        self.assertEqual(seen["key"], "KEY")
        self.assertIn("query=get_siginfo", seen["body"])
        picked = bazaar.pick_samples(rows, FAMILY, 5, 20, exclude=set())
        self.assertEqual([s.sha256 for s in picked], ["a" * 64, "d" * 64])          # lower-cased, docx and huge skipped
        self.assertEqual(bazaar.pick_samples(rows, FAMILY, 5, 20, exclude={"a" * 64})[0].sha256, "d" * 64)

    def test_no_results_and_failed_download(self):
        client = bazaar.BazaarClient("KEY", opener=lambda r, t: b'{"query_status": "no_results"}')
        self.assertEqual(client.samples_for_signature("Nothing"), [])
        with self.assertRaises(bazaar.BazaarError):
            client.download("e" * 64)

    def test_cache_round_trip(self):
        cache = bazaar.SampleCache(self.tmp / "samples")
        sample = bazaar.Sample.from_api("AgentTesla", {"sha256_hash": "f" * 64, "file_type": "exe", "file_size": 5, "tags": ["exe"]})
        cache.add(sample, b"PK\x03\x04data")
        self.assertTrue(cache.archive_path(sample.sha256).is_file())
        self.assertEqual(cache.samples("AgentTesla")[0].tags, ("exe",))
        cache.mark_run(sample.sha256, "win10", "win10-agenttesla-ffffffff-x")
        self.assertEqual(cache.already_run(sample.sha256, "win10"), "win10-agenttesla-ffffffff-x")
        self.assertIsNone(cache.already_run(sample.sha256, "win11"))


class VmwareTests(TempDir):
    def test_isolation_check(self):
        vmx = self.tmp / "a.vmx"
        vmx.write_text(SAFE_VMX, encoding="utf-8")
        self.assertEqual(vmware.check_isolation(vmx, "VMnet9"), [])
        vmx.write_text(SAFE_VMX.replace('"custom"', '"nat"'), encoding="utf-8")
        self.assertTrue(any("nat" in p for p in vmware.check_isolation(vmx, "VMnet9")))
        vmx.write_text(SAFE_VMX + 'ethernet1.present = "TRUE"\n', encoding="utf-8")       # second NIC defaults to bridged
        self.assertTrue(any("ethernet1" in p for p in vmware.check_isolation(vmx, "VMnet9")))
        vmx.write_text(SAFE_VMX.replace('hgfs.disable = "TRUE"', 'hgfs.disable = "FALSE"') + 'sharedFolder0.present = "TRUE"\n', encoding="utf-8")
        problems = vmware.check_isolation(vmx, "VMnet9")
        self.assertTrue(any("hgfs" in p for p in problems) and any("shared folder" in p for p in problems))
        vmx.write_text(SAFE_VMX.replace("VMnet9", "VMnet8"), encoding="utf-8")
        self.assertTrue(vmware.check_isolation(vmx, "VMnet9"))

    def test_memory_settings(self):
        vmx = self.tmp / "a.vmx"
        vmx.write_text(SAFE_VMX + 'encryption.keySafe = "x"\n', encoding="utf-8")
        self.assertTrue(any("encrypted" in n for n in vmware.check_memory_settings(vmx)))

    def test_find_memory_files_after_suspend(self):
        old = self.tmp / "victim-Snapshot1.vmem"
        old.write_bytes(b"old")
        os.utime(old, (time.time() - 3600, time.time() - 3600))
        since = time.time()
        (self.tmp / "victim-1a2b.vmem").write_bytes(b"ram")
        (self.tmp / "victim-1a2b.vmss").write_bytes(b"state")
        memory, state = vmware.find_memory_files(self.tmp, since)
        self.assertEqual((memory.name, state.name), ("victim-1a2b.vmem", "victim-1a2b.vmss"))
        with self.assertRaises(vmware.VmrunError):
            vmware.find_memory_files(self.tmp, time.time() + 100)

    def test_vmrun_command_lines(self):
        calls = []
        vm = vmware.Vmrun("vmrun.exe", "analyst", "pw", runner=lambda args, t: (calls.append(list(args)) or (0, "ok")))
        vm.run_powershell("v.vmx", r"C:\lab\collect.ps1")
        vm.revert("v.vmx", "ready")
        self.assertEqual(calls[0][:7], ["vmrun.exe", "-T", "ws", "-gu", "analyst", "-gp", "pw"])
        self.assertIn("-interactive", calls[0])
        self.assertTrue(calls[0][-1].endswith(r"-File C:\lab\collect.ps1"))
        self.assertEqual(calls[1], ["vmrun.exe", "-T", "ws", "revertToSnapshot", "v.vmx", "ready"])
        failing = vmware.Vmrun("vmrun.exe", "a", "b", runner=lambda args, t: (255, "Error: The virtual machine is not powered on"))
        with self.assertRaises(vmware.VmrunError):
            failing.revert("v.vmx", "ready")
        failing.stop("v.vmx")                                # stop never raises


LAUNCH = "2026-11-12T15:00:00Z"
TRUTH = {
    "taken_utc": "2026-11-12T15:03:00Z", "collector_pid": 900,
    "os": {"product": "Windows 10 Pro", "display_version": "22H2", "build": "19045", "ubr": "2965"},
    "processes": [
        {"pid": 4, "ppid": 0, "name": "System", "created_utc": "2026-11-12T14:00:00Z"},
        {"pid": 3000, "ppid": 600, "name": "explorer.exe", "created_utc": "2026-11-12T14:01:00Z"},
        {"pid": 4100, "ppid": 3000, "name": "invoice.exe", "created_utc": "2026-11-12T15:00:01Z"},
        {"pid": 4200, "ppid": 4100, "name": "powershell.exe", "created_utc": "2026-11-12T15:00:05Z"},   # child of the sample: counts
        {"pid": 4300, "ppid": 4100, "name": "RegAsm.exe", "created_utc": "2026-11-12T15:00:06Z"},
        {"pid": 5000, "ppid": 700, "name": "AppLaunch.exe", "created_utc": "2026-11-12T15:01:00Z"},     # new after launch, unrelated parent
        {"pid": 900, "ppid": 1576, "name": "powershell.exe", "created_utc": "2026-11-12T15:03:00Z"},    # the collector
        {"pid": 901, "ppid": 900, "name": "netstat.exe", "created_utc": "2026-11-12T15:03:01Z"},
        {"pid": 950, "ppid": 700, "name": "WmiPrvSE.exe", "created_utc": "2026-11-12T15:03:00Z"},       # lab noise
        {"pid": 5044, "ppid": 700, "name": "vmtoolsd.exe", "created_utc": "2026-11-12T14:00:00Z"},
        {"pid": 1576, "ppid": 5044, "name": "cmd.exe", "created_utc": "2026-11-12T15:02:59Z"},          # lab's cmd /c wrapper
        {"pid": 960, "ppid": 960, "name": "svchost.exe", "created_utc": "2026-11-12T14:00:00Z"},
    ],
    "connections": [
        {"proto": "TCP", "local": "10.66.0.10:49700", "remote": "10.66.0.1:587", "state": "ESTABLISHED", "pid": 4300},
        {"proto": "TCP", "local": "10.66.0.10:49701", "remote": "10.66.0.1:587", "state": "TIME_WAIT", "pid": 4300},
        {"proto": "TCP", "local": "0.0.0.0:135", "remote": "0.0.0.0:0", "state": "LISTENING", "pid": 4100},
        {"proto": "TCP", "local": "10.66.0.10:49702", "remote": "10.66.0.1:80", "state": "ESTABLISHED", "pid": 960},
    ],
}
DETONATION = {"status": "launched", "pids": [4100], "launched_utc": LAUNCH, "launch": 'explorer.exe "C:\\Users\\analyst\\Downloads\\invoice.exe"',
              "path": "C:\\Users\\analyst\\Downloads\\invoice.exe"}
SAMPLE = bazaar.Sample.from_api("AgentTesla", {"sha256_hash": "ab" * 32, "file_type": "exe", "file_size": 123456,
                                               "file_name": "invoice.exe", "md5_hash": "m" * 32, "first_seen": "2026-11-01 10:00:00"})


class PackageTests(unittest.TestCase):
    def test_sample_processes(self):
        pids = [p["pid"] for p in package.sample_processes(TRUTH, DETONATION)]
        self.assertEqual(pids, [4100, 4200, 4300, 5000])

    def test_connections(self):
        conns = package.sample_connections(TRUTH, [4100, 4200, 4300])
        self.assertEqual([(c["remote_address"], c["remote_port"], c["pid"]) for c in conns], [("10.66.0.1", 587, 4300)])

    def test_expected_matches_harness_format(self):
        exp = package.build_expected("id1", FAMILY, SAMPLE, TRUTH, DETONATION, 8)
        kinds = [f["type"] for f in exp["facts"]]
        self.assertEqual(kinds.count("process"), 4)
        self.assertIn("connection", kinds)
        parent = next(f for f in exp["facts"] if f["type"] == "parent" and f["name"] == "invoice.exe")
        self.assertEqual(parent["parent_name"], "explorer.exe")
        for fact in exp["facts"]:
            self.assertIn("id", fact)
            self.assertIn("description", fact)
        self.assertEqual(set(exp["findings_review"]), {"true_positive", "false_positive", "inconclusive"})

    def test_parent_that_exited_is_named(self):
        truth = {"processes": [{"pid": 8288, "ppid": 2244, "name": "MSBuild.exe", "created_utc": "2026-11-12T15:00:09Z"}],
                 "connections": []}
        exp = package.build_expected("id1", FAMILY, SAMPLE, truth, {"pids": [2244], "launched_utc": LAUNCH}, 5)
        self.assertIn("started by the sample itself (PID 2244", exp["facts"][0]["description"])

    def test_nothing_running(self):
        exp = package.build_expected("id1", FAMILY, SAMPLE, {"processes": [], "connections": []}, {"pids": []}, 5)
        self.assertEqual(exp["facts"], [])
        self.assertIn("No sample process was running", exp["basis"])

    def test_endpoints(self):
        self.assertEqual(package._split_endpoint("[::1]:80"), ("::1", 80))
        self.assertEqual(package._split_endpoint("*:*"), ("*", 0))
        self.assertFalse(package._is_remote("0.0.0.0"))
        self.assertTrue(package._is_remote("10.66.0.1"))


class FakeVm:
    """Plays the guest: writes detonation.json / groundtruth.json, and a .vmem/.vmss on suspend."""

    def __init__(self, vm_dir: Path, detonation=None):
        self.vm_dir = vm_dir
        self.calls = []
        self.detonation = detonation or DETONATION

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append(name)
            return 0.0 if name == "wait_until_ready" else ""
        return record

    def copy_from_guest(self, vmx, guest_path, host_path):
        self.calls.append("copy_from_guest")
        data = self.detonation if guest_path.endswith("detonation.json") else TRUTH
        Path(host_path).write_text("\ufeff" + json.dumps(data), encoding="utf-8")   # PowerShell may write a BOM

    def suspend(self, vmx):
        self.calls.append("suspend")
        (self.vm_dir / "victim-win10-77.vmem").write_bytes(b"\x00" * 4096)
        (self.vm_dir / "victim-win10-77.vmss").write_bytes(b"state")


class PipelineTests(TempDir):
    def setUp(self):
        super().setUp()
        self.vm_dir = self.tmp / "vms" / "victim-win10"
        self.vm_dir.mkdir(parents=True)
        self.vmx = self.vm_dir / "victim-win10.vmx"
        self.vmx.write_text(SAFE_VMX, encoding="utf-8")
        self.cfg = load_lab_config(write_lab_toml(self.tmp, self.vmx))
        self.cache = bazaar.SampleCache(self.cfg.cache_dir)
        self.cache.add(SAMPLE, b"PK\x03\x04zip")
        self.guest = self.cfg.guests["win10"]

    def test_full_capture_makes_a_package(self):
        vm = FakeVm(self.vm_dir)
        pkg = pipeline.run_capture(self.cfg, vm, self.guest, self.cache, FAMILY, SAMPLE, seconds=1,
                                   log=lambda s: None, sleep=lambda s: None)
        for name in ("memory.vmem", "memory.vmss", "README.md", "expected.json", "metadata.json", "groundtruth.json", "detonation.json"):
            self.assertTrue((pkg / name).is_file(), name)
        self.assertTrue(pkg.name.startswith("win10-agenttesla-abababab-"))
        self.assertLess(vm.calls.index("copy_to_guest"), vm.calls.index("suspend"))
        self.assertEqual(vm.calls[-2:], ["stop", "revert"])                  # the infected VM is thrown away
        meta = json.loads((pkg / "metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["memory"]["size"], 4096)
        self.assertEqual(len(meta["memory"]["sha256"]), 64)
        readme = (pkg / "README.md").read_text(encoding="utf-8")
        self.assertIn(SAMPLE.sha256, readme)
        self.assertIn("invoice.exe", readme)
        self.assertIn("RegAsm.exe", readme)
        self.assertEqual(self.cache.already_run(SAMPLE.sha256, "win10"), pkg.name)

    def test_failed_start_still_reverts(self):
        vm = FakeVm(self.vm_dir, detonation={"status": "error", "error": "SHA-256 mismatch"})
        with self.assertRaises(pipeline.DetonationError):
            pipeline.run_capture(self.cfg, vm, self.guest, self.cache, FAMILY, SAMPLE, seconds=1, log=lambda s: None, sleep=lambda s: None)
        self.assertEqual(vm.calls[-2:], ["stop", "revert"])
        self.assertNotIn("suspend", vm.calls)

    def test_refuses_unisolated_vm(self):
        self.vmx.write_text(SAFE_VMX.replace('"custom"', '"bridged"'), encoding="utf-8")
        vm = FakeVm(self.vm_dir)
        with self.assertRaises(vmware.SafetyError):
            pipeline.run_capture(self.cfg, vm, self.guest, self.cache, FAMILY, SAMPLE, seconds=1, log=lambda s: None, sleep=lambda s: None)
        self.assertEqual(vm.calls, [])                                           # nothing was started

    def test_baseline(self):
        pkg = pipeline.run_capture(self.cfg, FakeVm(self.vm_dir), self.guest, seconds=1, log=lambda s: None, sleep=lambda s: None)
        self.assertIn("-baseline-", pkg.name)
        self.assertEqual(json.loads((pkg / "metadata.json").read_text(encoding="utf-8"))["sample"], None)

    def test_safe_file_name(self):
        self.assertEqual(pipeline.safe_file_name("Order #12 (copy).exe", "ab" * 32, "exe"), "Order_12_copy.exe")
        self.assertEqual(pipeline.safe_file_name("abab" + "ab" * 30 + ".exe", "ab" * 32, "exe"), "invoice_ababab.exe")
        self.assertEqual(pipeline.safe_file_name("", "cd" * 32, "dll"), "invoice_cdcdcd.dll")


class StorageTests(TempDir):
    def make_package(self, name="win10-agenttesla-abababab-20261112-1500"):
        pkg = self.tmp / "work" / name
        pkg.mkdir(parents=True)
        for f in ("memory.vmem", "memory.vmss", "README.md", "expected.json", "groundtruth.json", "detonation.json"):
            (pkg / f).write_text("{}" if f.endswith(".json") else "x", encoding="utf-8")
        meta = {"id": name, "title": "AgentTesla on win10", "run": {"guest": "win10", "captured_utc": "2026-11-12T15:03:10Z", "seconds": 180},
                "sample": {"family": "AgentTesla", "sha256": "ab" * 32}, "memory": {"size": 4 * 2**30}, "os_text": "Windows 10 Pro 22H2"}
        (pkg / "metadata.json").write_text(json.dumps(meta), encoding="utf-8")
        (pkg / "expected.json").write_text(json.dumps({"facts": [{"type": "process"}, {"type": "connection"}]}), encoding="utf-8")
        return pkg

    def test_publish_packs_uploads_commits_and_cleans_up(self):
        repo = self.tmp / "dumps-repo"
        (repo / ".git").mkdir(parents=True)
        cfg = SimpleNamespace(seven_zip="7z", gh="gh", repo="me/memorygraph-dumps", repo_dir=repo, archive_password="infected",
                              volume_size="1900m", keep_local=False)
        calls = []

        def runner(args, timeout, cwd=""):
            calls.append(list(args))
            if args[0] == "7z" and args[1] == "a":
                target = Path(args[args.index("-v1900m") + 1])
                Path(str(target) + ".001").write_bytes(b"7z")
                Path(str(target) + ".002").write_bytes(b"7z")
            if args[:3] == ["gh", "release", "view"]:
                return 1, "release not found"
            if args[:3] == ["git", "diff", "--cached"]:
                return 1, ""
            return 0, ""

        pkg = self.make_package()
        url = storage.Storage(cfg, runner=runner).publish(pkg, "win10")
        self.assertEqual(url, "https://github.com/me/memorygraph-dumps/releases/tag/" + pkg.name)
        seven = next(c for c in calls if c[0] == "7z")
        self.assertIn("-mhe=on", seven)
        self.assertIn("-pinfected", seven)
        create = next(c for c in calls if c[:3] == ["gh", "release", "create"])
        self.assertEqual([Path(a).name for a in create if a.endswith((".001", ".002"))],
                         [pkg.name + ".7z.001", pkg.name + ".7z.002"])
        self.assertIn(["git", "push"], calls)
        target = repo / "packages" / "win10" / pkg.name
        self.assertTrue((target / "README.md").is_file())
        self.assertFalse((target / "memory.vmem").exists())                     # dumps never go into git
        self.assertFalse(pkg.exists())                                           # keep_local = False
        catalog = json.loads((repo / "catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(catalog[0]["sample_processes"], 1)
        self.assertIn(pkg.name, (repo / "CATALOG.md").read_text(encoding="utf-8"))

    def test_existing_release_is_not_uploaded_twice(self):
        repo = self.tmp / "dumps-repo"
        (repo / ".git").mkdir(parents=True)
        cfg = SimpleNamespace(seven_zip="7z", gh="gh", repo="me/r", repo_dir=repo, archive_password="infected", volume_size="1900m", keep_local=True)
        calls = []
        storage.Storage(cfg, runner=lambda a, t, c="": (calls.append(list(a)) or (0, ""))).publish(self.make_package(), "win10")
        self.assertFalse(any(c[0] == "7z" for c in calls))
        self.assertFalse(any(c[:3] == ["gh", "release", "create"] for c in calls))

    def test_pack_needs_memory(self):
        pkg = self.make_package()
        (pkg / "memory.vmem").unlink()
        cfg = SimpleNamespace(seven_zip="7z", archive_password="infected", volume_size="1900m")
        with self.assertRaises(storage.StorageError):
            storage.Storage(cfg, runner=lambda a, t, c="": (0, "")).pack(pkg)


if __name__ == "__main__":
    unittest.main()


class GuestStepTests(TempDir):
    def test_scripts_are_pushed_after_the_revert(self):
        calls = []

        class VM:
            def make_guest_dir(self, vmx, path):
                calls.append(("dir", path))

            def copy_to_guest(self, vmx, host, guest):
                calls.append(("copy", Path(host).name, guest))

        pipeline.push_guest_scripts(VM(), "v.vmx")
        self.assertIn(("dir", "C:\\lab\\out"), calls)
        copies = [c for c in calls if c[0] == "copy"]
        self.assertEqual([c[1] for c in copies], ["lab-json.ps1", "detonate.ps1", "collect.ps1", "net-sampler.ps1"])
        self.assertEqual(copies[2][2], "C:\\lab\\collect.ps1")
        for name in pipeline.GUEST_SCRIPTS:
            self.assertTrue((pipeline.HOST_GUEST_DIR / name).is_file(), name)

    def test_non_zero_exit_is_fine_when_the_result_exists(self):
        class VM:
            def run_powershell(self, vmx, script, args, timeout=0, check=True, log=""):
                assert check is False and log.endswith("c.log")
                return "Guest program exited with non-zero exit code: 1"

            def copy_from_guest(self, vmx, guest, host):
                Path(host).write_text('{"processes": [], "errors": ["x"]}', encoding="utf-8")

        data = pipeline.run_guest_step(VM(), "v.vmx", "c.ps1", "", "g", self.tmp / "t.json", "collect.ps1")
        self.assertEqual(data["errors"], ["x"])

    def test_missing_result_or_fatal_error_is_reported(self):
        class Missing:
            def run_powershell(self, *a, **k):
                return "boom"

            def copy_from_guest(self, vmx, guest, host):
                if guest.endswith(".log"):
                    Path(host).write_text("ParserError: unexpected token", encoding="utf-8")
                    return
                raise vmware.VmrunError("file not found")

        with self.assertRaises(pipeline.DetonationError) as info:
            pipeline.run_guest_step(Missing(), "v.vmx", "c.ps1", "", "g", self.tmp / "t.json", "collect.ps1")
        self.assertIn("ParserError", str(info.exception))     # the guest's own output is shown

        class Fatal(Missing):
            def copy_from_guest(self, vmx, guest, host):  # noqa: F811
                Path(host).write_text('{"fatal": "Access denied"}', encoding="utf-8")

        with self.assertRaises(pipeline.DetonationError) as info:
            pipeline.run_guest_step(Fatal(), "v.vmx", "c.ps1", "", "g", self.tmp / "t.json", "collect.ps1")
        self.assertIn("Access denied", str(info.exception))


class PowershellCommandTests(unittest.TestCase):
    def test_log_redirection_goes_through_cmd(self):
        calls = []
        vm = vmware.Vmrun("vmrun.exe", "u", "p", runner=lambda a, t: (calls.append(list(a)) or (1, "exit code 1")))
        vm.run_powershell("v.vmx", r"C:\lab\collect.ps1", check=False, log=r"C:\lab\out\collect.log")
        self.assertEqual(calls[0][-2], r"C:\Windows\System32\cmd.exe")
        self.assertEqual(calls[0][-1], r"/c C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile "
                                       r"-ExecutionPolicy Bypass -File C:\lab\collect.ps1 > C:\lab\out\collect.log 2>&1")
