"""Row helpers shared by every engine (Volatility prints the same JSON tree for every operating system)."""
from __future__ import annotations

from typing import Any, Iterable, List


def flatten_rows(rows: Iterable[Any]) -> List[Any]:
    """Flatten Volatility's ``__children`` tree into a list (idempotent, iterative)."""
    out: List[Any] = []
    stack = list(reversed(list(rows or [])))
    while stack:
        row = stack.pop()
        if isinstance(row, dict):
            children = row.get("__children")
            if "__children" in row:
                row = {k: v for k, v in row.items() if k != "__children"}
            out.append(row)
            if isinstance(children, list) and children:
                stack.extend(reversed(children))
        else:
            out.append(row)
    return out
