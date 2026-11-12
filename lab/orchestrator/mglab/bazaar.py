"""MalwareBazaar API client (https://bazaar.abuse.ch/api/) and the local sample cache.

Samples are stored exactly as MalwareBazaar delivers them: a password-protected zip (password
"infected"). They are never unpacked on the host; the lab VM unpacks them itself.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

API_URL = "https://mb-api.abuse.ch/api/v1/"
USER_AGENT = "memorygraph-lab/1.0"


class BazaarError(Exception):
    pass


@dataclass
class Sample:
    sha256: str
    family: str
    signature: str
    file_type: str
    file_name: str
    file_size: int
    first_seen: str
    md5: str = ""
    sha1: str = ""
    tags: tuple = ()
    reporter: str = ""

    @classmethod
    def from_api(cls, family: str, row: dict) -> "Sample":
        return cls(
            sha256=str(row.get("sha256_hash", "")).lower(),
            family=family,
            signature=str(row.get("signature") or ""),
            file_type=str(row.get("file_type") or "").lower(),
            file_name=str(row.get("file_name") or ""),
            file_size=int(row.get("file_size") or 0),
            first_seen=str(row.get("first_seen") or ""),
            md5=str(row.get("md5_hash") or ""),
            sha1=str(row.get("sha1_hash") or ""),
            tags=tuple(row.get("tags") or ()),
            reporter=str(row.get("reporter") or ""),
        )

    @property
    def page(self) -> str:
        return f"https://bazaar.abuse.ch/sample/{self.sha256}/"

    def to_dict(self) -> dict:
        data = dict(self.__dict__)
        data["tags"] = list(self.tags)
        data["page"] = self.page
        return data


Opener = Callable[[urllib.request.Request, float], bytes]


def _default_open(request: urllib.request.Request, timeout: float) -> bytes:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


class BazaarClient:
    def __init__(self, auth_key: str, opener: Optional[Opener] = None, timeout: float = 120.0):
        self.auth_key = auth_key
        self._open = opener or _default_open
        self.timeout = timeout

    def _post(self, form: Dict[str, str]) -> bytes:
        request = urllib.request.Request(
            API_URL,
            data=urllib.parse.urlencode(form).encode("ascii"),
            headers={"Auth-Key": self.auth_key, "User-Agent": USER_AGENT},
            method="POST",
        )
        try:
            return self._open(request, self.timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise BazaarError("MalwareBazaar refused the Auth-Key (check MALWAREBAZAAR_AUTH_KEY)") from exc
            raise BazaarError(f"MalwareBazaar HTTP error {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise BazaarError(f"Cannot reach MalwareBazaar: {exc.reason}") from exc

    def samples_for_signature(self, signature: str, limit: int = 100) -> List[dict]:
        body = self._post({"query": "get_siginfo", "signature": signature, "limit": str(min(max(limit, 1), 1000))})
        try:
            data = json.loads(body)
        except ValueError as exc:
            raise BazaarError("MalwareBazaar returned something that is not JSON") from exc
        status = data.get("query_status")
        if status in ("no_results", "signature_not_found", "illegal_signature"):
            return []
        if status != "ok":
            raise BazaarError(f"MalwareBazaar query failed: {status}")
        return list(data.get("data") or [])

    def download(self, sha256: str) -> bytes:
        body = self._post({"query": "get_file", "sha256_hash": sha256})
        if not body.startswith(b"PK"):
            try:
                status = json.loads(body).get("query_status", "unknown answer")
            except ValueError:
                status = "unknown answer"
            raise BazaarError(f"Download of {sha256} failed: {status}")
        return body


def pick_samples(rows: List[dict], family, count: int, max_size_mb: int, exclude: set) -> List[Sample]:
    """Newest first (MalwareBazaar's order), only file types the lab can start, not too big, not used before."""
    picked = []
    for row in rows:
        sample = Sample.from_api(family.name, row)
        if not sample.sha256 or sample.sha256 in exclude:
            continue
        if sample.file_type not in family.file_types:
            continue
        if sample.file_size and sample.file_size > max_size_mb * 1024 * 1024:
            continue
        picked.append(sample)
        if len(picked) >= count:
            break
    return picked


class SampleCache:
    """cache_dir/<sha256>.zip plus catalog.json describing every cached sample."""

    def __init__(self, cache_dir: Path):
        self.dir = Path(cache_dir)
        self.catalog_path = self.dir / "catalog.json"

    def _load(self) -> Dict[str, dict]:
        if not self.catalog_path.is_file():
            return {}
        return json.loads(self.catalog_path.read_text(encoding="utf-8"))

    def _save(self, catalog: Dict[str, dict]) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.catalog_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(catalog, indent=1, sort_keys=True), encoding="utf-8")
        tmp.replace(self.catalog_path)

    def archive_path(self, sha256: str) -> Path:
        return self.dir / f"{sha256}.zip"

    def add(self, sample: Sample, archive: bytes) -> Path:
        self.dir.mkdir(parents=True, exist_ok=True)
        path = self.archive_path(sample.sha256)
        path.write_bytes(archive)
        catalog = self._load()
        entry = catalog.get(sample.sha256, {})
        entry.update(sample.to_dict())
        catalog[sample.sha256] = entry
        self._save(catalog)
        return path

    def samples(self, family: Optional[str] = None) -> List[Sample]:
        out = []
        for sha, entry in sorted(self._load().items(), key=lambda kv: kv[1].get("first_seen", ""), reverse=True):
            if family and entry.get("family") != family:
                continue
            if not self.archive_path(sha).is_file():
                continue
            fields = {k: entry.get(k) for k in Sample.__dataclass_fields__}
            fields["tags"] = tuple(entry.get("tags") or ())
            fields["file_size"] = int(entry.get("file_size") or 0)
            out.append(Sample(**fields))
        return out

    def known(self) -> set:
        return set(self._load())

    def mark_run(self, sha256: str, guest: str, package_id: str) -> None:
        catalog = self._load()
        entry = catalog.setdefault(sha256, {})
        runs = entry.setdefault("runs", {})
        runs[guest] = package_id
        self._save(catalog)

    def already_run(self, sha256: str, guest: str) -> Optional[str]:
        return (self._load().get(sha256, {}).get("runs") or {}).get(guest)
