"""Linux: the back end of the Files view (SKELETON). The view shows a "not implemented yet" page until ``LinuxEngine.view_specs`` marks "Files" available.

Must provide what ``app/engines/windows/analysis/fileindex.py`` provides for Windows: file entries (path, inode / address, flags), a folder tree, search, and the link to dumped files.
"""
from __future__ import annotations

from typing import Iterable, List

from app.engines.linux._todo import todo


def entries_from_rows(rows: Iterable) -> List:
    """File entries from ``linux.pagecache.Files`` / ``linux.lsof`` rows."""
    return todo("entries_from_rows")
