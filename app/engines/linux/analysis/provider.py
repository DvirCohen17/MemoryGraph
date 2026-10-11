"""Linux: the provider that runs the Volatility 3 ``linux.*`` plugins (SKELETON).

It must do what ``app/engines/windows/analysis/real_provider.py`` does, for Linux:
  1. validate the image (``app.analysis.dump.validate_dump``) and find Volatility (``app.analysis.volatility_runner.find_volatility`` / ``check_tool``);
  2. run ``banners.Banners`` first: it reads the kernel banner, which tells which ISF symbol table the other plugins need (see ``os_profile.py``);
  3. run the enabled plugins of ``plugin_registry`` in parallel (``run_plugin`` of the Volatility runner), cached by ``app.analysis.plugin_cache`` and ordered by
     ``app.analysis.plugin_timing.order``;
  4. hand the ``PluginResult`` list to ``app.analysis.pipeline.analyze_plugins(..., engine="linux")`` and return the ``AnalysisResult``.
The front end calls only ``run`` and ``rerun`` and reads the class attributes below.
"""
from __future__ import annotations

import threading
from typing import Callable, Optional, Sequence

from app.engines.linux._todo import todo
from app.engines.linux.analysis import plugin_registry as registry
from app.models import AnalysisResult

Progress = Optional[Callable[[str, int], None]]
PluginEvent = Optional[Callable[[str, str, str], None]]       # (plugin, state, detail)


class LinuxProvider:
    CORE_PLUGINS = registry.names(registry.CORE)
    EXTENDED_PLUGINS = registry.names(registry.EXTENDED)
    OPTIONAL_PLUGINS = registry.names(registry.OPTIONAL)
    REQUIRED_PLUGINS = registry.required_names()

    def __init__(self, settings: Optional[dict] = None):
        self.settings = settings or {}

    def run(self, dump_path: str, progress: Progress = None, plugin_event: PluginEvent = None, cancel: Optional[threading.Event] = None) -> AnalysisResult:
        """Run the enabled plugins on ``dump_path`` and return the normalized, judged :class:`AnalysisResult` (``result.target_os == "linux"``)."""
        return todo("LinuxProvider.run")

    def rerun(self, result: AnalysisResult, names: Optional[Sequence[str]] = None, progress: Progress = None, plugin_event: PluginEvent = None,
              cancel: Optional[threading.Event] = None) -> AnalysisResult:
        """Run ``names`` (default: the plugins of ``result`` that failed) again and rebuild the analysis with the merged plugin results."""
        return todo("LinuxProvider.rerun")
