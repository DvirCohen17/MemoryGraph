"""Sample sources behind one small interface, so `fetch` can pull from several providers and fill each
family from whichever has samples.

Every source yields `Sample` metadata (`find`) and returns a password-protected ("infected") zip ready
for the cache (`fetch`). MalwareBazaar and Malpedia already hand back such a zip; sources that serve the
raw file are wrapped into one with 7-Zip, so the guest unpacks every sample the same way. The guest
verifies the inner file's SHA-256, so a wrong wrap or a multi-file archive simply fails that one sample
(the run logs it and moves on) - it can never feed the VM the wrong file.

A source that errors (no token, network down, bad response) is skipped with a warning; it never aborts
the fetch, so one flaky provider cannot stop the others.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable, List, Optional

from .bazaar import BazaarClient, BazaarError, Sample

USER_AGENT = "memorygraph-lab/1.0"
Opener = Callable[[urllib.request.Request, float], bytes]
Runner = Callable[[list], "subprocess.CompletedProcess"]


class SourceError(Exception):
    pass


def _default_open(request: urllib.request.Request, timeout: float) -> bytes:
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _default_run(cmd: list) -> "subprocess.CompletedProcess":
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def wrap_infected_zip(raw: bytes, inner_name: str, seven_zip: str,
                      password: str = "infected", runner: Runner = _default_run) -> bytes:
    """Package raw sample bytes into a password-protected zip the guest opens with 7z -p<password>.
    Used for sources that serve the file unzipped, so every cached sample looks like a MalwareBazaar one."""
    safe = "".join(ch for ch in (inner_name or "sample.bin") if ch.isalnum() or ch in "._-") or "sample.bin"
    with tempfile.TemporaryDirectory() as td:
        inner = Path(td) / safe
        inner.write_bytes(raw)
        out = Path(td) / "archive.zip"
        proc = runner([seven_zip, "a", "-tzip", f"-p{password}", "-mx=1", str(out), str(inner)])
        if getattr(proc, "returncode", 1) != 0 or not out.is_file():
            detail = (getattr(proc, "stdout", b"") or b"")
            detail = detail.decode("utf-8", "replace") if isinstance(detail, bytes) else str(detail)
            raise SourceError(f"7-Zip could not package the sample: {detail[:300]}")
        return out.read_bytes()


class Source:
    name = "base"

    def enabled(self) -> bool:
        return True

    def find(self, family, limit: int) -> List[Sample]:
        raise NotImplementedError

    def fetch(self, sample: Sample, seven_zip: str) -> bytes:
        raise NotImplementedError


class MalwareBazaarSource(Source):
    """abuse.ch MalwareBazaar: query by family signature; it already serves an 'infected' zip."""
    name = "malwarebazaar"

    def __init__(self, auth_key: str, opener: Optional[Opener] = None):
        self._key = (auth_key or "").strip()
        self._client = BazaarClient(self._key, opener) if self._key else None

    def enabled(self) -> bool:
        return bool(self._client)

    def find(self, family, limit: int) -> List[Sample]:
        try:
            rows = self._client.samples_for_signature(family.signature, limit=limit)
        except BazaarError as exc:
            raise SourceError(str(exc)) from exc
        return [Sample.from_api(family.name, row) for row in rows]

    def fetch(self, sample: Sample, seven_zip: str) -> bytes:
        try:
            return self._client.download(sample.sha256)   # already a password-"infected" zip
        except BazaarError as exc:
            raise SourceError(str(exc)) from exc


class _TokenSource(Source):
    """Shared HTTP helper for token-authenticated JSON APIs."""
    base = ""
    auth_header = ""   # e.g. "apitoken {token}" or "Bearer {token}"

    def __init__(self, token: str, opener: Optional[Opener] = None, timeout: float = 120.0):
        self._token = (token or "").strip()
        self._open = opener or _default_open
        self.timeout = timeout

    def enabled(self) -> bool:
        return bool(self._token)

    def _get(self, path: str) -> bytes:
        request = urllib.request.Request(
            self.base + path,
            headers={"Authorization": self.auth_header.format(token=self._token), "User-Agent": USER_AGENT},
        )
        try:
            return self._open(request, self.timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise SourceError(f"{self.name} refused the API token") from exc
            if exc.code == 404:
                raise SourceError("not found") from exc
            raise SourceError(f"{self.name} HTTP error {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise SourceError(f"cannot reach {self.name}: {exc.reason}") from exc

    def _get_json(self, path: str):
        try:
            return json.loads(self._get(path))
        except ValueError as exc:
            raise SourceError(f"{self.name} returned something that is not JSON") from exc


class MalpediaSource(_TokenSource):
    """Malpedia (Fraunhofer FKIE): family-labeled samples, served as an 'infected' zip.
    Needs a researcher API token and a per-family Malpedia id (families.toml: malpedia = "win.agent_tesla").
    EXPERIMENTAL: verify once against your token - a source error only skips this provider."""
    name = "malpedia"
    base = "https://malpedia.caad.fkie.fraunhofer.de/api"
    auth_header = "apitoken {token}"

    def find(self, family, limit: int) -> List[Sample]:
        fam = (getattr(family, "malpedia", "") or "").strip()
        if not fam:
            return []
        data = self._get_json(f"/list/samples/{urllib.parse.quote(fam)}")
        rows = data if isinstance(data, list) else (data or {}).get("samples") or []
        out = []
        for row in rows[: max(limit, 0)]:
            sha = str(row.get("sha256") or row.get("sha256_hash") or "").lower()
            if len(sha) != 64:
                continue
            out.append(Sample(sha256=sha, family=family.name, signature=fam,
                              file_type=(family.file_types[0] if family.file_types else "exe"),
                              file_name=f"{sha[:12]}.{family.file_types[0] if family.file_types else 'exe'}",
                              file_size=0, first_seen=str(row.get("version") or ""), tags=("malpedia",)))
        return out

    def fetch(self, sample: Sample, seven_zip: str) -> bytes:
        return self._get(f"/get/sample/{sample.sha256}/zip")   # password-"infected" zip


class TriageSource(_TokenSource):
    """Hatching Triage (tria.ge): family-tagged, serves the raw file (wrapped here into an 'infected' zip).
    Needs an API token; family tag from families.toml (triage = "agenttesla") or the family slug.
    EXPERIMENTAL: verify once against your token - a source error only skips this provider."""
    name = "triage"
    base = "https://tria.ge/api"
    auth_header = "Bearer {token}"

    def find(self, family, limit: int) -> List[Sample]:
        tag = (getattr(family, "triage", "") or family.slug).strip()
        query = urllib.parse.quote(f"family:{tag}")
        data = self._get_json(f"/v0/search?query={query}&limit={max(min(limit, 200), 1)}")
        out = []
        for row in (data or {}).get("data") or []:
            sha = str(row.get("sha256") or "").lower()
            sample_id = str(row.get("id") or "")
            if len(sha) != 64 or not sample_id:
                continue
            s = Sample(sha256=sha, family=family.name, signature=tag,
                       file_type=(family.file_types[0] if family.file_types else "exe"),
                       file_name=str(row.get("filename") or f"{sha[:12]}.bin"),
                       file_size=int(row.get("filesize") or 0), first_seen=str(row.get("submitted") or ""),
                       tags=("triage", sample_id))   # keep the Triage sample id for fetch

            out.append(s)
        return out

    def fetch(self, sample: Sample, seven_zip: str) -> bytes:
        sample_id = next((t for t in sample.tags if t and t != "triage"), "")
        if not sample_id:
            raise SourceError("no Triage sample id recorded for this sample")
        raw = self._get(f"/v0/samples/{sample_id}/sample")
        got = hashlib.sha256(raw).hexdigest()
        if got != sample.sha256:
            raise SourceError(f"downloaded file hashes to {got[:12]}, expected {sample.sha256[:12]}")
        return wrap_infected_zip(raw, sample.file_name or sample.sha256, seven_zip)


class MalShareSource(Source):
    """MalShare (malshare.com): free self-service API key, large recent corpus. It serves the raw file,
    wrapped here into an 'infected' zip. Family match is by MalShare's full-text search on the family
    signature (filenames, sources, YARA hits), so labels are best-effort - the SHA-256 is still verified,
    only the family tag is less authoritative than MalwareBazaar/Malpedia. Auth is a query-string key
    (MalShare's only mechanism)."""
    name = "malshare"
    base = "https://malshare.com/api.php"

    def __init__(self, api_key: str, opener: Optional[Opener] = None, timeout: float = 120.0):
        self._key = (api_key or "").strip()
        self._open = opener or _default_open
        self.timeout = timeout

    def enabled(self) -> bool:
        return bool(self._key)

    def _request(self, params: dict) -> bytes:
        url = self.base + "?" + urllib.parse.urlencode(params)
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            return self._open(request, self.timeout)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise SourceError("MalShare refused the API key") from exc
            raise SourceError(f"MalShare HTTP error {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise SourceError(f"cannot reach MalShare: {exc.reason}") from exc

    def find(self, family, limit: int) -> List[Sample]:
        # MalShare has no family field; its search matches filenames/sources/YARA-hit names. The family
        # *name* (e.g. "Emotet") matches far more than the MalwareBazaar signature (e.g. "Heodo"), so try
        # the name first, then the signature, and union the results.
        terms = []
        for term in (family.name, family.signature):
            term = (term or "").strip()
            if term and term not in terms:
                terms.append(term)
        ext = family.file_types[0] if family.file_types else "exe"
        out, seen = [], set()
        for term in terms:
            body = self._request({"api_key": self._key, "action": "search", "query": term})
            try:
                data = json.loads(body)
            except ValueError as exc:
                raise SourceError("MalShare returned something that is not JSON") from exc
            rows = data if isinstance(data, list) else (data or {}).get("data") or []
            for row in rows:
                sha = str(row.get("sha256") or "").lower()
                if len(sha) != 64 or sha in seen:
                    continue
                seen.add(sha)
                out.append(Sample(sha256=sha, family=family.name, signature=family.signature,
                                  file_type=ext, file_name=f"{sha[:12]}.{ext}",
                                  file_size=int(row.get("size") or 0), first_seen=str(row.get("added") or ""),
                                  tags=("malshare",)))
                if len(out) >= limit:
                    return out
        return out

    def fetch(self, sample: Sample, seven_zip: str) -> bytes:
        raw = self._request({"api_key": self._key, "action": "getfile", "hash": sample.sha256})
        got = hashlib.sha256(raw).hexdigest()   # a "not found" reply is small text and simply fails this check
        if got != sample.sha256:
            raise SourceError(f"downloaded file hashes to {got[:12]}, expected {sample.sha256[:12]}")
        return wrap_infected_zip(raw, sample.file_name or sample.sha256, seven_zip)


_REGISTRY = {
    "malwarebazaar": lambda cfg, opener: MalwareBazaarSource(_env(cfg.auth_key_env), opener),
    "malshare": lambda cfg, opener: MalShareSource(_env(cfg.malshare_key_env), opener),
    "malpedia": lambda cfg, opener: MalpediaSource(_env(cfg.malpedia_token_env), opener),
    "triage": lambda cfg, opener: TriageSource(_env(cfg.triage_token_env), opener),
}


def _env(name: str) -> str:
    import os
    return os.environ.get(name, "").strip()


def build_sources(cfg, opener: Optional[Opener] = None) -> List[Source]:
    """The enabled sources, in cfg.sources order. A source whose credential is missing is left out."""
    out = []
    for name in cfg.sources:
        make = _REGISTRY.get(name)
        if not make:
            raise SourceError(f"unknown source '{name}' in lab.toml (known: {', '.join(_REGISTRY)})")
        src = make(cfg, opener)
        if src.enabled():
            out.append(src)
    return out
