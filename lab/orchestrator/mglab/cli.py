"""labctl: fetch samples, run them in the lab VMs, publish the dumps.

    python labctl.py check                      everything in place? (VMs isolated, tools, GitHub, Auth-Key)
    python labctl.py probe                      how many samples MalwareBazaar has per family
    python labctl.py fetch                      download samples (still zipped) into the cache
    python labctl.py baseline --guest win10     clean reference dump of a guest
    python labctl.py run                        every cached sample on every guest its family lists
    python labctl.py run --family AgentTesla --guest win10 --seconds 300
    python labctl.py publish D:\\malware-lab\\work\\<id>      retry the upload of a package kept locally
    python labctl.py get <id> --dest D:\\dumps                download and unpack a published dump
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from .bazaar import BazaarClient, BazaarError, SampleCache, pick_samples, select_samples
from .config import ConfigError, load_families, load_lab_config
from .sources import SourceError, build_sources
from .pipeline import DetonationError, run_capture
from .storage import Storage, StorageError
from .vmware import SafetyError, Vmrun, VmrunError, check_isolation, check_memory_settings

HERE = Path(__file__).resolve().parent.parent


def _guest_ram_gib(vmx) -> float:
    """Guest RAM in GiB, read from the .vmx (memsize is in MB). Defaults to 4 GiB if it can't be read."""
    try:
        for line in Path(vmx).read_text(errors="ignore").splitlines():
            if line.strip().lower().startswith("memsize"):
                return int(line.split('"')[1]) / 1024.0
    except Exception:  # noqa: BLE001
        pass
    return 4.0


def _families(args):
    families = load_families(Path(args.families))
    if args.family:
        wanted = {f.lower() for f in args.family}
        families = [f for f in families if f.name.lower() in wanted]
        if not families:
            raise ConfigError(f"No family named {', '.join(args.family)} in {args.families}")
    return families


def cmd_check(cfg, args) -> int:
    ok = True

    def report(good: bool, text: str):
        nonlocal ok
        ok = ok and good
        print(("  OK    " if good else "  FAIL  ") + text)

    print("VMware")
    report(Path(cfg.vmrun).is_file(), f"vmrun: {cfg.vmrun}")
    for guest in cfg.guests.values():
        if not Path(guest.vmx).is_file():
            report(False, f"{guest.name}: {guest.vmx} not found (terraform apply)")
            continue
        problems = check_isolation(Path(guest.vmx), cfg.lab_vnet)
        report(not problems, f"{guest.name}: isolated on {cfg.lab_vnet}" if not problems else f"{guest.name}: " + "; ".join(problems))
        for note in check_memory_settings(Path(guest.vmx)):
            report(False, f"{guest.name}: {note}")
        if Path(cfg.vmrun).is_file():
            try:
                snaps = Vmrun(cfg.vmrun, cfg.guest_user, cfg.guest_password).snapshots(guest.vmx)
                report(guest.snapshot in snaps, f"{guest.name}: snapshot '{guest.snapshot}'" + ("" if guest.snapshot in snaps else f" missing (has {snaps})"))
            except VmrunError as exc:
                report(False, f"{guest.name}: {exc}")
    print("Tools")
    report(Path(cfg.seven_zip).is_file() or shutil.which(cfg.seven_zip) is not None, f"7-Zip: {cfg.seven_zip}")
    enabled = [s.name for s in build_sources(cfg)]
    report(bool(enabled), f"sample sources enabled: {', '.join(enabled) if enabled else 'none'} "
           f"(wanted: {', '.join(cfg.sources)})")
    if "malwarebazaar" in cfg.sources and "malwarebazaar" not in enabled:
        report(False, f"MalwareBazaar Auth-Key missing: set {cfg.auth_key_env}")
    free = shutil.disk_usage(Path(cfg.work_dir).anchor or ".").free
    rams = [_guest_ram_gib(g.vmx) for g in cfg.guests.values() if Path(g.vmx).is_file()]
    max_ram = max(rams) if rams else 4.0
    need = 2 * max_ram + 2        # the image (~RAM) is copied beside the suspend file, then packed
    report(free > need * 2**30, f"free space for {cfg.work_dir}: {free / 2**30:.0f} GiB "
           f"(need ~{need:.0f} GiB: about 2x the {max_ram:.0f} GiB guest RAM, plus packing headroom)")
    if cfg.storage_mode == "github":
        print("GitHub")
        storage = Storage(cfg)
        try:
            info = storage.check_github()
            report(True, f"gh logged in, {cfg.repo}: {info.strip()}")
            if '"PUBLIC"' in info.upper():
                print("        WARNING: the dumps repository is public. Make it private (Settings > General > Danger Zone).")
        except (StorageError, FileNotFoundError) as exc:
            report(False, f"gh / {cfg.repo}: {exc}")
        report((Path(cfg.repo_dir) / ".git").is_dir(), f"local clone {cfg.repo_dir}")
    print("All good." if ok else "Fix the FAIL lines first.")
    return 0 if ok else 1


def cmd_probe(cfg, args) -> int:
    client = BazaarClient(cfg.auth_key())
    print(f"{'family':16} {'signature':16} {'exe':>5} {'dll':>5}  newest")
    for family in _families(args):
        rows = client.samples_for_signature(family.signature, limit=100)
        types = [str(r.get("file_type", "")).lower() for r in rows]
        newest = rows[0].get("first_seen", "") if rows else "-"
        flag = "" if rows else "   <- no samples: check the signature name"
        print(f"{family.name:16} {family.signature:16} {types.count('exe'):>5} {types.count('dll'):>5}  {newest}{flag}")
    return 0


def cmd_fetch(cfg, args) -> int:
    cache = SampleCache(cfg.cache_dir)
    sources = build_sources(cfg)
    if not sources:
        raise ConfigError(f"no sample sources are enabled (set {cfg.auth_key_env}, or add tokens and list "
                          f"them under [sources] order in lab.toml)")
    print(f"sources: {', '.join(s.name for s in sources)}")
    per_family = args.per_family or cfg.per_family
    for family in _families(args):
        have = cache.samples(family.name)
        need = per_family - len(have)
        if need <= 0:
            print(f"{family.name}: {len(have)} cached")
            continue
        known = cache.known()
        got = 0
        for src in sources:
            if got >= need:
                break
            try:
                found = src.find(family, limit=200)
            except SourceError as exc:
                print(f"{family.name}: {src.name} skipped ({exc})")
                continue
            for sample in select_samples(found, family, need - got, cfg.max_size_mb, known):
                try:
                    archive = src.fetch(sample, cfg.seven_zip)
                except SourceError as exc:
                    print(f"{family.name}: {src.name} could not download {sample.sha256[:12]} ({exc})")
                    continue
                cache.add(sample, archive)
                known.add(sample.sha256)
                got += 1
                size = f"{sample.file_size:,} bytes" if sample.file_size else "size unknown"
                print(f"{family.name}: {sample.sha256} from {src.name} ({sample.file_type}, {size})")
                if got >= need:
                    break
        if got == 0:
            print(f"{family.name}: no new sample from any source "
                  f"({', '.join(family.file_types)}, <= {cfg.max_size_mb} MB)")
    print(f"Cached in {cfg.cache_dir} (password-protected zips; they are only unpacked inside the VM).")
    return 0


def _guests(cfg, args):
    names = args.guest or list(cfg.guests)
    unknown = [n for n in names if n not in cfg.guests]
    if unknown:
        raise ConfigError(f"Unknown guest(s) {unknown}; lab.toml has {list(cfg.guests)}")
    return [cfg.guests[n] for n in names]


def _finish(cfg, pkg: Path, guest: str, args) -> None:
    if cfg.storage_mode == "github" and not args.no_upload:
        print(f"Uploading {pkg.name} ...")
        url = Storage(cfg).publish(pkg, guest)
        print(f"Published: {url}")
    else:
        print(f"Kept locally: {pkg}")


def _vm(cfg) -> Vmrun:
    return Vmrun(cfg.vmrun, cfg.guest_user, cfg.guest_password)


def cmd_baseline(cfg, args) -> int:
    for guest in _guests(cfg, args):
        pkg = run_capture(cfg, _vm(cfg), guest, seconds=args.seconds or 60, allow_unsafe=args.i_know_it_is_not_isolated)
        _finish(cfg, pkg, guest.name, args)
    return 0


def cmd_run(cfg, args) -> int:
    cache = SampleCache(cfg.cache_dir)
    families = _families(args)
    per_family = args.per_family or cfg.per_family

    # Build the ordered worklist first, so we know how many captures there are and can number them.
    # Each one is done strictly one at a time: revert -> detonate -> capture -> revert -> publish -> next.
    worklist = []
    skipped = []
    for guest in _guests(cfg, args):
        for family in families:
            if guest.name not in family.guests:
                continue
            for sample in cache.samples(family.name)[:per_family]:
                previous = cache.already_run(sample.sha256, guest.name)
                if previous and not args.again:
                    skipped.append((family, sample, guest, previous))
                else:
                    worklist.append((guest, family, sample))
    if args.limit:
        worklist = worklist[: args.limit]

    for family, sample, guest, previous in skipped:
        print(f"skip {family.name} {sample.sha256[:12]} on {guest.name}: already captured as {previous} (--again to repeat)")
    total = len(worklist)
    print(f"{total} capture(s) to run" + (f" ({len(skipped)} skipped)" if skipped else "") + ".")

    failures = 0
    done = 0
    for i, (guest, family, sample) in enumerate(worklist, 1):
        print(f"\n===== Sample {i} of {total}: {family.name} {sample.sha256[:12]} on {guest.name} =====")
        try:
            pkg = run_capture(cfg, _vm(cfg), guest, cache, family, sample, seconds=args.seconds,
                              allow_unsafe=args.i_know_it_is_not_isolated)
            _finish(cfg, pkg, guest.name, args)
            done += 1
        except SafetyError:
            raise
        except (DetonationError, VmrunError, StorageError, OSError) as exc:
            failures += 1
            print(f"FAILED {family.name} {sample.sha256[:12]} on {guest.name}: {exc}", file=sys.stderr)
    print(f"\n{done} of {total} dump(s) made, {failures} failed.")
    return 1 if failures else 0


def cmd_publish(cfg, args) -> int:
    pkg = Path(args.package)
    import json
    guest = json.loads((pkg / "metadata.json").read_text(encoding="utf-8"))["run"]["guest"]
    print(Storage(cfg).publish(pkg, guest))
    return 0


def cmd_get(cfg, args) -> int:
    dest = Storage(cfg).fetch(args.id, Path(args.dest))
    print(f"Unpacked to {dest}. Open {dest / 'memory.vmem'} in MemoryGraph (Run analysis).")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="labctl", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=str(HERE / "lab.toml"))
    parser.add_argument("--families", default=str(HERE / "families.toml"))
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check")
    for name in ("probe", "fetch"):
        p = sub.add_parser(name)
        p.add_argument("--family", action="append")
        p.add_argument("--per-family", type=int, default=0)
    for name in ("baseline", "run"):
        p = sub.add_parser(name)
        p.add_argument("--guest", action="append")
        p.add_argument("--seconds", type=int)
        p.add_argument("--no-upload", action="store_true", help="keep the package in work_dir")
        p.add_argument("--i-know-it-is-not-isolated", action="store_true", help=argparse.SUPPRESS)
        if name == "run":
            p.add_argument("--family", action="append")
            p.add_argument("--per-family", type=int, default=0)
            p.add_argument("--limit", type=int, default=0, help="stop after this many dumps")
            p.add_argument("--again", action="store_true", help="also re-run samples already captured on that guest")
    p = sub.add_parser("publish")
    p.add_argument("package")
    p = sub.add_parser("get")
    p.add_argument("id")
    p.add_argument("--dest", default=".")

    args = parser.parse_args(argv)
    try:
        cfg = load_lab_config(Path(args.config))
        handler = {"check": cmd_check, "probe": cmd_probe, "fetch": cmd_fetch, "baseline": cmd_baseline,
                   "run": cmd_run, "publish": cmd_publish, "get": cmd_get}[args.command]
        return handler(cfg, args)
    except SafetyError as exc:
        print(f"STOPPED for safety: {exc}", file=sys.stderr)
        return 2
    except (ConfigError, BazaarError, StorageError, VmrunError, DetonationError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. If a VM was running a sample, revert it: vmrun revertToSnapshot <vmx> ready", file=sys.stderr)
        return 130
