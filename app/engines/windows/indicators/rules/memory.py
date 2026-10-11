"""Memory rules. malfind produces many benign hits (JIT, AV engines), so every region is scored."""
from app.engines.windows.analysis import known_good
from app.analysis.hexview import region_bytes
from app.engines.windows.indicators import baseline
from app.analysis.indicators.base import IndicatorRule, display, lower
from app.engines.windows.indicators.helpers import nt_major
from app.analysis.indicators.scoring import max_severity
from app.util import to_int


def _hex_bytes(region) -> str:
    """Lower-case hex of the stored bytes. (Volatility's dump text ends each line with an ASCII column; parse_hexdump leaves it out,
    where stripping every non-hex character would have turned its letters a-f into extra bytes.)"""
    return region_bytes(region).hex()


def classify_region(region, module_names, legacy: bool = False):
    """Return ``(severity, [reasons])`` for one malfind region."""
    data = _hex_bytes(region)
    reasons = []
    severity = "Medium"
    if data.startswith("4d5a"):
        return "High", ["Region starts with an MZ header (a PE image injected into private memory)"]
    if any(data.startswith(prefix) for prefix in baseline.SHELLCODE_PREFIXES):
        return "High", ["Region starts with a shellcode-like byte sequence"]
    start, end = to_int(region.start), to_int(region.end)
    if legacy and start is not None and end is not None and (start, end - start + 1) in baseline.KNOWN_BENIGN_REGIONS:
        return "Low", [f"Region is {baseline.KNOWN_BENIGN_REGIONS[(start, end - start + 1)]}"]
    if data and set(data[:32]) <= {"0"}:
        return "Low", ["Region begins with empty (zero) bytes: usually reserved/JIT memory"]
    managed = sorted(module_names & baseline.JIT_HOST_MODULES)
    engine = sorted(module_names & baseline.SECURITY_ENGINE_MODULES)
    if engine:
        return "Low", [f"Process hosts a security/emulation engine ({', '.join(engine)}) that legitimately allocates executable memory"]
    if managed:
        return "Low", [f"Process hosts a JIT/runtime ({', '.join(managed[:3])}) that creates executable memory"]
    reasons.append("Private executable memory with non-empty content and no JIT/runtime explanation")
    if "WRITE" not in str(region.protection).upper():
        severity = "Low"
    return severity, reasons


class InjectedMemoryRule(IndicatorRule):
    rule_id = "MEM-001"
    category = "memory"
    name = "Executable private memory (malfind)"
    description = "One lead per process, scored from the region content (MZ header, shellcode bytes, empty/JIT-like pages) instead of one lead per page."

    def evaluate(self, result):
        by_pid = {}
        for region in result.memory_regions:
            by_pid.setdefault(region.pid, []).append(region)
        findings = []
        procs = {p.pid: p for p in result.processes}
        legacy = 0 < nt_major(result) < 6
        # What the process has mapped, not only what its dlllist names: on a real Windows 10 image taskhostw.exe (which runs the .NET NGEN task) had an empty
        # runtime list in dlllist but mscoreei.dll in the memory map, and its executable regions were reported as unexplained.
        mapped = known_good.mapped_images(result)
        good = known_good.for_result(result)
        for pid, regions in by_pid.items():
            proc = procs.get(pid)
            modules = {lower(d.name) for d in proc.dlls} if proc else set()
            modules |= mapped.get(pid, set())
            if proc is not None and good:
                modules |= {m for m in baseline.JIT_HOST_MODULES | baseline.SECURITY_ENGINE_MODULES if good.knows(proc.name, m)}
            scored = [(classify_region(r, modules, legacy), r) for r in regions]
            severity = max_severity(sev for (sev, _why), _r in scored)
            worst = [(why, r) for (sev, why), r in scored if sev == severity]
            reasons = []
            for why, _r in worst:
                for line in why:
                    if line not in reasons:
                        reasons.append(line)
            evidence = [
                f"{r.start}–{r.end} ({r.size}) {r.protection} tag={r.tag or '?'}" for _classified, r in scored[:12]
            ]
            if len(scored) > 12:
                evidence.append(f"... and {len(scored) - 12} more region(s)")
            count_note = f"{len(regions)} executable private region(s) reported by malfind"
            confidence = "High" if severity == "High" else "Medium" if severity == "Medium" else "Low"
            findings.append(self.make(
                title=("Injected PE image in process memory" if severity == "High" and any("MZ" in x for x in reasons)
                       else "Executable private memory reported by malfind"),
                severity=severity, confidence=confidence, process=proc,
                summary="malfind found executable, non-file-backed memory. Many hits are benign (JIT compilers, security engines); the severity reflects what the region contains.",
                reasons=[count_note] + reasons, evidence=evidence, source_plugins=["windows.malfind"]))
            if proc is None:
                findings[-1].process_pid = pid
                findings[-1].process_name = regions[0].process
        return findings
