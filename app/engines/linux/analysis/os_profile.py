"""Linux: what kernel this is, and which symbol table it needs (SKELETON)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from app.engines.linux._todo import todo


@dataclass(frozen=True)
class LinuxProfile:
    """The facts the engine needs about the image's kernel (filled from the ``banners.Banners`` row)."""
    kernel: str = ""            # "5.15.0-91-generic"
    distribution: str = ""      # "Ubuntu 22.04"
    architecture: str = ""      # "x86_64" / "aarch64"
    banner: str = ""            # the full "Linux version ..." string (it names the ISF the image needs)

    @property
    def known(self) -> bool:
        """True once the kernel is known. The generic parts of MemoryGraph use ``known``, ``version`` and ``short_name`` of any OS profile."""
        return bool(self.kernel)

    @property
    def version(self):
        """A comparable ``(major, minor)`` of the kernel, like Windows' NT version: plugins can say which kernels they exist for."""
        return todo("LinuxProfile.version")

    @property
    def short_name(self) -> str:
        return todo("LinuxProfile.short_name")


def parse_banner(text: str) -> LinuxProfile:
    """``"Linux version 5.15.0-91-generic (buildd@...) ..."`` -> :class:`LinuxProfile`."""
    return todo("parse_banner")


def from_rows(rows: Iterable) -> LinuxProfile:
    """The profile from the rows of ``banners.Banners``."""
    return todo("from_rows")


def from_result(result) -> LinuxProfile:
    return todo("from_result")


def describe_os(result) -> str:
    """One line for the window header: ``Ubuntu 22.04 (kernel 5.15.0-91-generic, x86_64)``."""
    return todo("describe_os")
