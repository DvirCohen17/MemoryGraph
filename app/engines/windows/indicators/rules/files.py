"""File-object rules (need the opt-in, large windows.filescan)."""
import re

from app.engines.windows.analysis.fileindex import BENIGN_TEMP_FRAGMENTS
from app.analysis.indicators.base import IndicatorRule, plugin_rows_indexed, row_value
from app.engines.windows.indicators.helpers import is_high_risk_dir
from app.models import EvidenceItem
from app.util import norm_path

_EXEC = (".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".cpl", ".com", ".pif")
_DOC = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".rtf", ".zip", ".mp3", ".mp4")
_STRICT = ("\\users\\public\\", "$recycle.bin\\", "\\recycler\\", "\\windows\\temp\\", "\\windows\\tasks\\", "\\windows\\debug\\")
_MAX_LISTED = 25


class FileObjectRule(IndicatorRule):
    rule_id = "FILE-001"
    category = "file"
    name = "Executable file objects in unusual folders"
    description = ("File objects found in memory (windows.filescan): programs or scripts in Public, Recycle Bin, Windows\\Temp (Medium) or in "
                   "a user's Temp/Downloads (Low), and files with a document extension followed by an executable one ('invoice.pdf.exe', "
                   "Medium). Grouped into at most three findings; the list is evidence of files that existed, not of execution.")

    def evaluate(self, result):
        strict, loose, disguised = [], [], []
        for index, row in plugin_rows_indexed(result, "windows.filescan"):
            path = str(row_value(row, "Name") or "")
            low = norm_path(path)
            if not low:
                continue
            base = low.rsplit("\\", 1)[-1]
            if base.endswith(_EXEC) and any(base[:-len(e)].endswith(d) for e in _EXEC if base.endswith(e) for d in _DOC):
                disguised.append((index, path))
            elif base.endswith(_EXEC) and is_high_risk_dir(path) and not any(f in low + "\\" for f in BENIGN_TEMP_FRAGMENTS):
                (strict if any(s in low + "\\" for s in _STRICT) else loose).append((index, path))
        findings = []
        for items, severity, title in (
            (disguised, "Medium", "{n} file(s) with a document extension followed by an executable extension"),
            (strict, "Medium", "{n} executable file object(s) in Public, Recycle Bin or Windows\\Temp"),
            (loose, "Low", "{n} executable file object(s) in Temp or Downloads"),
        ):
            if not items:
                continue
            shown = items[:_MAX_LISTED]
            findings.append(self.make(
                title=title.format(n=len(items)), severity=severity, confidence="Low" if severity == "Low" else "Medium",
                summary="File objects were found in memory in places where legitimate software rarely keeps programs. A file object only shows that the file was opened, not that it was run.",
                reasons=["Found by windows.filescan (pool scan of file objects)"],
                evidence=[p for _i, p in shown] + ([f"... and {len(items) - _MAX_LISTED} more"] if len(items) > _MAX_LISTED else []),
                source_plugins=["windows.filescan"],
                evidence_items=[EvidenceItem("file", "Name", p, "", "windows.filescan", i) for i, p in shown]))
        return findings
