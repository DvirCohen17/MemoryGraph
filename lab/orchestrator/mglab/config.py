"""lab.toml and families.toml."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List


class ConfigError(Exception):
    pass


@dataclass
class Guest:
    name: str
    vmx: str
    snapshot: str = "ready"


@dataclass
class Family:
    name: str
    signature: str
    guests: List[str]
    file_types: List[str] = field(default_factory=lambda: ["exe"])
    dll_export: str = "DllRegisterServer"
    description: str = ""
    look_for: List[str] = field(default_factory=list)
    malpedia: str = ""   # Malpedia family id, e.g. "win.agent_tesla" (optional)
    triage: str = ""     # Hatching Triage family tag, e.g. "agenttesla" (optional; defaults to the slug)

    @property
    def slug(self) -> str:
        return "".join(ch for ch in self.name.lower() if ch.isalnum())


@dataclass
class LabConfig:
    vmrun: str
    lab_vnet: str
    guest_user: str
    guest_password: str
    guests: Dict[str, Guest]
    run_seconds: int = 180
    work_dir: Path = Path("work")
    cache_dir: Path = Path("samples")
    drop_dir: str = ""
    boot_timeout: int = 600
    auth_key_env: str = "MALWAREBAZAAR_AUTH_KEY"
    malpedia_token_env: str = "MALPEDIA_API_TOKEN"
    triage_token_env: str = "TRIAGE_API_TOKEN"
    sources: List[str] = field(default_factory=lambda: ["malwarebazaar"])
    per_family: int = 1
    max_size_mb: int = 20
    storage_mode: str = "github"
    repo: str = ""
    repo_dir: Path = Path("memorygraph-dumps")
    seven_zip: str = "7z"
    gh: str = "gh"
    archive_password: str = "infected"
    volume_size: str = "1900m"
    keep_local: bool = False

    def auth_key(self) -> str:
        key = os.environ.get(self.auth_key_env, "").strip()
        if not key:
            raise ConfigError(f"Set your MalwareBazaar Auth-Key in the environment variable {self.auth_key_env} "
                              "(free: log in at https://auth.abuse.ch/).")
        return key


def _need(section: dict, key: str, where: str):
    if key not in section or section[key] in ("", None):
        raise ConfigError(f"{where}: '{key}' is missing")
    return section[key]


def load_lab_config(path: Path) -> LabConfig:
    if not path.is_file():
        raise ConfigError(f"{path} not found: copy lab.toml.example to lab.toml and adjust it")
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    vmware = data.get("vmware", {})
    account = data.get("guest_account", {})
    run = data.get("run", {})
    bazaar = data.get("bazaar", {})
    sources_cfg = data.get("sources", {})
    storage = data.get("storage", {})
    guests = {}
    for name, section in (data.get("guests") or {}).items():
        guests[name] = Guest(name=name, vmx=_need(section, "vmx", f"[guests.{name}]"), snapshot=section.get("snapshot", "ready"))
    if not guests:
        raise ConfigError("lab.toml has no [guests.<name>] section")
    mode = storage.get("mode", "github")
    if mode not in ("github", "local"):
        raise ConfigError("[storage] mode must be 'github' or 'local'")
    if mode == "github" and not storage.get("repo"):
        raise ConfigError("[storage] repo is needed for mode = 'github' (for example 'you/memorygraph-dumps')")
    return LabConfig(
        vmrun=_need(vmware, "vmrun", "[vmware]"),
        lab_vnet=vmware.get("lab_vnet", "VMnet9"),
        guest_user=_need(account, "user", "[guest_account]"),
        guest_password=_need(account, "password", "[guest_account]"),
        guests=guests,
        run_seconds=int(run.get("seconds", 180)),
        work_dir=Path(run.get("work_dir", "work")),
        cache_dir=Path(run.get("cache_dir", "samples")),
        drop_dir=run.get("drop_dir", ""),
        boot_timeout=int(run.get("boot_timeout", 600)),
        auth_key_env=bazaar.get("auth_key_env", "MALWAREBAZAAR_AUTH_KEY"),
        malpedia_token_env=sources_cfg.get("malpedia_token_env", "MALPEDIA_API_TOKEN"),
        triage_token_env=sources_cfg.get("triage_token_env", "TRIAGE_API_TOKEN"),
        sources=list(sources_cfg.get("order") or ["malwarebazaar"]),
        per_family=int(bazaar.get("per_family", 1)),
        max_size_mb=int(bazaar.get("max_size_mb", 20)),
        storage_mode=mode,
        repo=storage.get("repo", ""),
        repo_dir=Path(storage.get("repo_dir", "memorygraph-dumps")),
        seven_zip=storage.get("seven_zip", "7z"),
        gh=storage.get("gh", "gh"),
        archive_password=storage.get("archive_password", "infected"),
        volume_size=storage.get("volume_size", "1900m"),
        keep_local=bool(storage.get("keep_local", False)),
    )


def load_families(path: Path) -> List[Family]:
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    families = []
    for i, entry in enumerate(data.get("family", []), 1):
        where = f"family #{i}"
        file_types = [t.lower() for t in entry.get("file_types", ["exe"])]
        bad = [t for t in file_types if t not in ("exe", "dll")]
        if bad:
            raise ConfigError(f"{where}: unsupported file_types {bad} (only exe and dll can be started)")
        families.append(Family(
            name=_need(entry, "name", where),
            signature=_need(entry, "signature", where),
            guests=list(_need(entry, "guests", where)),
            file_types=file_types,
            dll_export=entry.get("dll_export", "DllRegisterServer"),
            description=entry.get("description", ""),
            look_for=list(entry.get("look_for", [])),
            malpedia=entry.get("malpedia", ""),
            triage=entry.get("triage", ""),
        ))
    names = [f.name for f in families]
    if len(set(names)) != len(names):
        raise ConfigError("families.toml: family names must be unique")
    return families
