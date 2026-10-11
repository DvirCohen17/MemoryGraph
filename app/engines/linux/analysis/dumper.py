"""Linux: dumping things out of the image (SKELETON). Same method names as ``app/engines/windows/analysis/dumper.py`` where the idea carries over, so the windows work unchanged."""
from __future__ import annotations

from typing import Sequence

from app.engines.linux._todo import todo


class LinuxDumper:
    def __init__(self, dump_path: str, volatility_path: str = "", global_args: Sequence[str] = ()):
        self.dump_path = dump_path
        self.volatility_path = volatility_path
        self.global_args = list(global_args)

    def dump_process(self, pid: int, output_dir: str):
        """The process image / its mappings (``linux.proc.Maps --dump``, ``linux.elfs --dump``)."""
        return todo("LinuxDumper.dump_process")

    def dump_dlls(self, pid: int, output_dir: str):
        """The shared libraries of a process (the window calls them "Libraries")."""
        return todo("LinuxDumper.dump_dlls")

    def dump_handles(self, pid: int, output_dir: str):
        """The files the process has open (``linux.lsof``, ``linux.pagecache.Files --dump``)."""
        return todo("LinuxDumper.dump_handles")

    def dump_malfind_pages(self, pid: int, output_dir: str):
        """Executable anonymous regions (``linux.malfind --dump``)."""
        return todo("LinuxDumper.dump_malfind_pages")

    def dump_all_process_images(self, output_dir: str):
        return todo("LinuxDumper.dump_all_process_images")
