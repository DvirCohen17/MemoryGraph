"""Computer information: key facts first, the full windows.info table and identities below."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QLabel, QSplitter, QVBoxLayout, QWidget

from app.util import format_time, to_int
from app.windows.widgets import TableModel, make_table, muted, section_title

_FRIENDLY = [
    ("SystemTime", "Memory captured (UTC)"), ("NtMajorVersion", "NT major"), ("NtMinorVersion", "NT minor"),
    ("MajorOperatingSystemVersion", "OS major"), ("MinorOperatingSystemVersion", "OS minor"),
    ("NtBuildLab", "Build"), ("Is64Bit", "64-bit"), ("IsPAE", "PAE"), ("KeNumberProcessors", "Processors"),
    ("MachineType", "Machine type"), ("Major/Minor", "Kernel"),
]


def describe_os(info: dict) -> str:
    major = to_int(info.get("NtMajorVersion"), None)
    minor = to_int(info.get("NtMinorVersion"), None)
    build = ""
    lab = str(info.get("NtBuildLab", "") or "")
    if lab:
        build = lab.split(".")[0]
    names = {(10, 0): "Windows 10 / 11 / Server 2016+", (6, 3): "Windows 8.1 / Server 2012 R2", (6, 2): "Windows 8 / Server 2012",
             (6, 1): "Windows 7 / Server 2008 R2", (6, 0): "Windows Vista / Server 2008", (5, 1): "Windows XP", (5, 2): "Windows XP x64 / Server 2003"}
    base = names.get((major, minor), f"Windows NT {major}.{minor}" if major is not None else "Unknown Windows version")
    return f"{base}" + (f" (build {build})" if build else "")


class SystemInfoView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        info = {str(r.get("Variable", "")): r.get("Value") for r in (result.system_info or []) if isinstance(r, dict)}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        title = QLabel("Computer Information")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("System metadata (windows.info) and the accounts that own processes (windows.getsids)."))

        card = QFrame()
        card.setObjectName("Card")
        grid = QGridLayout(card)
        grid.setContentsMargins(18, 14, 18, 14)
        facts = [
            ("Operating system", info.get("Operating system") or (describe_os(info) if info.get("NtMajorVersion") else "unknown (the operating-system plugin did not run)")),
            ("Memory captured", format_time(result.capture_time) if result.capture_time else "unknown"),
            ("Architecture", "64-bit" if str(info.get("Is64Bit", "")).lower() in ("true", "1") else ("32-bit" if info else "unknown")),
            ("Processors", info.get("KeNumberProcessors", "unknown")),
            ("Memory image", result.dump_path or "unknown"),
            ("Processes / accounts", f"{len(result.processes)} / {len(result.accounts or result.users)}"),
        ] + [(k.title() if k == "analysed" else k, v) for k, v in (getattr(result, "tool_info", None) or {}).items()]
        for i, (key, value) in enumerate(facts):
            label = QLabel(key.upper())
            label.setObjectName("Muted")
            text = QLabel(str(value))
            text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            text.setWordWrap(True)
            grid.addWidget(label, i // 3 * 2, i % 3)
            grid.addWidget(text, i // 3 * 2 + 1, i % 3)
        layout.addWidget(card)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.addWidget(section_title("windows.info"))
        rows = [[r.get("Variable", ""), r.get("Value", "")] for r in (result.system_info or []) if isinstance(r, dict)]
        view, _proxy = make_table(TableModel(["Variable", "Value"], rows), [240, 520])
        left_layout.addWidget(view, 1)
        if not rows:
            left_layout.addWidget(muted("windows.info returned no data."))
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.addWidget(section_title("Accounts that own processes"))
        if result.accounts:
            account_rows = [[a.get("name", ""), a.get("sid", ""), a.get("processes", 0)] for a in result.accounts]
            model = TableModel(["Account", "SID", "Processes"], account_rows,
                               sort_rows=[[str(r[0]).lower(), r[1], r[2]] for r in account_rows])
        else:
            model = TableModel(["Identity"], [[u] for u in result.users] or [["No user identities were normalized."]])
        account_view, _p = make_table(model, [190, 330, 80])
        right_layout.addWidget(account_view, 1)
        splitter.addWidget(right)
        splitter.setSizes([620, 560])
        layout.addWidget(splitter, 1)
