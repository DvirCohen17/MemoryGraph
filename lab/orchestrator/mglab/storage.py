"""Packing, uploading and downloading dump packages.

Layout of the dumps repository (a separate, private GitHub repository):
    git (small, browsable):   CATALOG.md, catalog.json, packages/<guest>/<id>/{README.md, expected.json, metadata.json,
                              groundtruth.json, detonation.json}
    release <id> (big):       <id>.7z.001, <id>.7z.002 ...  AES-256 7z (password "infected", file names hidden too),
                              split under GitHub's 2 GiB per-file limit; holds the same text files + memory.vmem/.vmss
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Callable, List, Sequence, Tuple

TEXT_FILES = ("README.md", "expected.json", "metadata.json", "groundtruth.json", "detonation.json")
MEMORY_FILES = ("memory.vmem", "memory.vmss")

Runner = Callable[[Sequence[str], float, str], Tuple[int, str]]


class StorageError(Exception):
    pass


def _default_runner(args: Sequence[str], timeout: float, cwd: str = "") -> Tuple[int, str]:
    proc = subprocess.run(list(args), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, cwd=cwd or None)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


class Storage:
    def __init__(self, cfg, runner: Runner = _default_runner):
        self.cfg = cfg
        self.run = runner

    def _call(self, args: Sequence[str], timeout: float = 7200, cwd: str = "") -> str:
        code, output = self.run(list(args), timeout, cwd)
        if code != 0:
            raise StorageError(f"{Path(args[0]).name} {' '.join(args[1:3])} failed:\n{output.strip()[-2000:]}")
        return output

    # ------------------------------------------------------------------ pack
    def pack(self, package_dir: Path) -> List[Path]:
        """7z with AES-256 and encrypted file names, split into volumes. Returns the volume files."""
        package_dir = Path(package_dir)
        name = package_dir.name
        out_dir = package_dir.parent / f"{name}.archive"
        if out_dir.exists():
            shutil.rmtree(out_dir)
        out_dir.mkdir(parents=True)
        members = [f for f in (*TEXT_FILES, *MEMORY_FILES) if (package_dir / f).is_file()]
        if "memory.vmem" not in members:
            raise StorageError(f"{package_dir} has no memory.vmem")
        self._call([self.cfg.seven_zip, "a", "-t7z", "-mx=3", "-mhe=on", f"-p{self.cfg.archive_password}",
                    f"-v{self.cfg.volume_size}", str(out_dir / f"{name}.7z"), *members], cwd=str(package_dir))
        volumes = sorted(out_dir.glob(f"{name}.7z.*"))
        if not volumes:
            raise StorageError("7-Zip wrote no archive volumes")
        return volumes

    # ------------------------------------------------------------------ GitHub
    def check_github(self) -> str:
        self._call([self.cfg.gh, "auth", "status"], timeout=60)
        return self._call([self.cfg.gh, "repo", "view", self.cfg.repo, "--json", "nameWithOwner,visibility"], timeout=60)

    def upload(self, package_id: str, volumes: List[Path], notes_file: Path, title: str) -> None:
        self._call([self.cfg.gh, "release", "create", package_id, "--repo", self.cfg.repo, "--title", title,
                    "--notes-file", str(notes_file), *[str(v) for v in volumes]], timeout=6 * 3600)

    def release_exists(self, package_id: str) -> bool:
        code, _ = self.run([self.cfg.gh, "release", "view", package_id, "--repo", self.cfg.repo], 60, "")
        return code == 0

    def commit_text(self, package_dir: Path, guest: str) -> Path:
        """Copy the text files into the local clone of the dumps repo, update the catalog, commit and push."""
        repo = Path(self.cfg.repo_dir)
        if not (repo / ".git").is_dir():
            raise StorageError(f"{repo} is not a git clone of {self.cfg.repo} (run: gh repo clone {self.cfg.repo} \"{repo}\")")
        package_id = Path(package_dir).name
        target = repo / "packages" / guest / package_id
        target.mkdir(parents=True, exist_ok=True)
        for name in TEXT_FILES:
            source = Path(package_dir) / name
            if source.is_file():
                shutil.copy2(source, target / name)
        update_catalog(repo)
        cwd = str(repo)
        self._call(["git", "pull", "--rebase", "--autostash"], timeout=600, cwd=cwd)
        self._call(["git", "add", "-A", "packages", "CATALOG.md", "catalog.json"], timeout=600, cwd=cwd)
        code, _ = self.run(["git", "diff", "--cached", "--quiet"], 60, cwd)
        if code != 0:
            self._call(["git", "commit", "-m", f"Add {package_id}"], timeout=600, cwd=cwd)
            self._call(["git", "push"], timeout=1800, cwd=cwd)
        return target

    def publish(self, package_dir: Path, guest: str) -> str:
        package_dir = Path(package_dir)
        package_id = package_dir.name
        meta = json.loads((package_dir / "metadata.json").read_text(encoding="utf-8"))
        title = meta.get("title") or package_id
        if not self.release_exists(package_id):
            volumes = self.pack(package_dir)
            self.upload(package_id, volumes, package_dir / "README.md", title)
            shutil.rmtree(volumes[0].parent, ignore_errors=True)
        self.commit_text(package_dir, guest)
        if not self.cfg.keep_local:
            shutil.rmtree(package_dir, ignore_errors=True)
        return f"https://github.com/{self.cfg.repo}/releases/tag/{package_id}"

    # ------------------------------------------------------------------ download
    def fetch(self, package_id: str, dest: Path) -> Path:
        dest = Path(dest) / package_id
        dest.mkdir(parents=True, exist_ok=True)
        self._call([self.cfg.gh, "release", "download", package_id, "--repo", self.cfg.repo, "--dir", str(dest),
                    "--pattern", f"{package_id}.7z.*", "--clobber"], timeout=6 * 3600)
        first = dest / f"{package_id}.7z.001"
        if not first.is_file():
            raise StorageError(f"{first} was not downloaded")
        self._call([self.cfg.seven_zip, "x", str(first), f"-p{self.cfg.archive_password}", f"-o{dest}", "-y"], timeout=3600)
        for part in dest.glob(f"{package_id}.7z.*"):
            part.unlink()
        return dest


def update_catalog(repo: Path) -> None:
    """catalog.json + CATALOG.md from packages/*/*/metadata.json."""
    rows = []
    for meta_path in sorted(Path(repo).glob("packages/*/*/metadata.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except ValueError:
            continue
        sample = meta.get("sample") or {}
        expected_path = meta_path.with_name("expected.json")
        procs = 0
        if expected_path.is_file():
            try:
                procs = sum(1 for f in json.loads(expected_path.read_text(encoding="utf-8")).get("facts", []) if f.get("type") == "process")
            except ValueError:
                pass
        rows.append({
            "id": meta.get("id"), "guest": meta.get("run", {}).get("guest"), "os": meta.get("os_text", ""),
            "family": sample.get("family", "baseline (clean)"), "sha256": sample.get("sha256", ""),
            "captured_utc": meta.get("run", {}).get("captured_utc", ""), "seconds": meta.get("run", {}).get("seconds"),
            "memory_bytes": meta.get("memory", {}).get("size", 0), "sample_processes": procs,
            "path": meta_path.parent.relative_to(repo).as_posix(),
        })
    rows.sort(key=lambda r: (r["guest"] or "", r["family"] or "", r["captured_utc"] or ""))
    (Path(repo) / "catalog.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    lines = ["# Memory dump catalog", "",
             "Each package: the text files are in `packages/`, the dump itself is the GitHub release with the same name "
             "(7z, password `infected`). **Contains live malware**: open only in an isolated lab.", "",
             "| Package | Guest | Family | Sample processes | RAM | Captured (UTC) |", "|---|---|---|---|---|---|"]
    for r in rows:
        lines.append(f"| [{r['id']}]({r['path']}/README.md) | {r['guest']} {r['os']} | {r['family']} | {r['sample_processes']} "
                     f"| {r['memory_bytes'] / 2**30:.1f} GiB | {r['captured_utc']} |")
    (Path(repo) / "CATALOG.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
