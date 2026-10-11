"""Windows: things about the image itself that limit what the rules can say (shown with the other analysis warnings)."""
from __future__ import annotations

from typing import List

from app.analysis.indicators.base import plugin_rows_indexed, row_value
from app.engines.windows.indicators.rules.vad import lists_incomplete
from app.models import AnalysisResult
from app.util import parse_time, path_file, to_int


def data_quality_warnings(result: AnalysisResult) -> List[str]:
    out: List[str] = []
    # a core DLL that is mapped but in no loader list: the process's loader lists were only partly readable (paged out)
    partial = {}
    for _i, row in plugin_rows_indexed(result, "windows.ldrmodules"):
        flags = [row_value(row, key, default=None) for key in ("InLoad", "InInit", "InMem")]
        pid = to_int(row_value(row, "Pid", default=None))
        if pid and all(f in (False, 0, "False", "false") for f in flags) and lists_incomplete([path_file(str(row_value(row, "MappedPath") or "")).lower()]):
            partial[pid] = str(row_value(row, "Process") or "")
    if partial:
        names = ", ".join(sorted({n for n in partial.values() if n})[:6])
        out.append(f"The loader lists of {len(partial)} process(es) were only partly readable in this image ({names}); LDR-001 and VAD-001 do not judge them.")
    # processes created after the acquisition started: the image was still being written, so the lists were changing
    captured = parse_time(result.capture_time)
    if captured is not None:
        late = [p for p in result.processes if parse_time(p.create_time) is not None and parse_time(p.create_time) > captured]
        if late:
            out.append(f"{len(late)} process(es) were created after the capture time recorded in the image ({result.capture_time}): the acquisition took a while and "
                       "process lists, handles and memory were still changing while it was written (PT-003 takes this into account).")
    return out
