"""The Linux engine: a SKELETON. Everything the windows and views need from an engine exists here with its signature; the work is still to be written.

Where the work goes (the same layout as ``app/engines/windows``):

    analysis/provider.py          LinuxProvider.run / rerun            run the Volatility 3 ``linux.*`` plugins and return an AnalysisResult
    analysis/plugin_registry.py   PLACEHOLDER plugin list and Settings groups (edit freely)
    analysis/normalizer.py        normalize()                          plugin rows -> processes, connections, memory regions, system info
    analysis/os_profile.py        kernel banner -> distribution / kernel version / architecture; the ISF symbol table the image needs
    analysis/timeline.py          build_timeline() / apply_severity()
    analysis/dumper.py            LinuxDumper                          dump a process, its libraries, its mappings, its open files
    analysis/quality.py           data_quality_warnings()
    analysis/files.py, compare.py the Files view and Compare view back ends (their views show a "not implemented yet" page until these exist)
    indicators/engine.py          IndicatorEngine.evaluate()           run the rules; ``DEFAULT_RULES`` is the list to fill
    indicators/rules/             one module per family of rules (see the docstring there for the families a Linux investigation usually needs)
    indicators/baseline.py        what is normal on Linux (core processes and parents, usual paths, ...)
    indicators/attack.py          ATT&CK mapping of the rules
    data/                         reference data

Until then the Linux choice on the start window works (settings, plugin groups, file filter, window texts) and an analysis stops with a message that names the missing
function (:class:`app.engines.base.EngineNotImplemented`).
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

from app.engines.base import Capabilities, Engine, Terms, ViewSpec
from app.engines.linux._todo import todo

_NOT_YET = "The Linux engine does not provide this view yet (app/engines/linux)."


class LinuxEngine(Engine):
    id = "linux"
    label = "Linux"
    implemented = False                  # the start window says so; the engine functions below raise EngineNotImplemented
    status_note = ("Linux support is a skeleton: you can choose it and set it up, but the Linux engine (app/engines/linux) is not written yet, so an analysis stops with a "
                   "message naming the missing function.")
    capabilities = Capabilities(registry=False, legacy_network_engine=False, process_images=False, known_good=False, file_explorer=False, compare=False, demo=True)
    terms = Terms(
        os_name="Linux", title="Linux Memory Analysis", subtitle="Select a memory dump of a Linux system to begin an investigation.",
        image_placeholder="Select a .lime, .raw, .mem, .vmem or other Linux memory image…",
        image_filter="Memory Images (*.lime *.raw *.mem *.vmem *.bin *.img *.dmp);;All Files (*)",
        module="Library", modules="Libraries", modules_tab="Libraries", dump_modules="Dump libraries", handles="Open files",
        symbols_hint="Volatility 3 needs a symbol table (ISF) that matches the exact kernel of the image (its banner). MemoryGraph never goes online: build or copy the ISF files "
                     "(dwarf2json output, or a Volatility symbol pack) into a folder and add it here.",
        tagline="Linux kernels with a matching symbol table",
    )

    # ------------------------------------------------------------------ what to run
    def plugin_registry(self):
        from app.engines.linux.analysis import plugin_registry
        return plugin_registry

    def default_settings(self) -> Dict[str, Any]:
        return {"enabled_plugins": [], "run_extended_plugins": False, "optional_plugins": [], "symbol_dirs": [], "yara_rules_file": ""}

    def make_provider(self, settings: dict):
        from app.engines.linux.analysis.provider import LinuxProvider
        return LinuxProvider(settings)

    def make_dumper(self, dump_path: str, volatility_path: str = "", global_args: Sequence[str] = ()):
        from app.engines.linux.analysis.dumper import LinuxDumper
        return LinuxDumper(dump_path, volatility_path, list(global_args))

    # ------------------------------------------------------------------ turning plugin rows into a result
    def normalize(self, dump_path: str, plugins: Sequence[Any]):
        from app.engines.linux.analysis.normalizer import normalize
        return normalize(dump_path, plugins)

    def build_timeline(self, result) -> List[Any]:
        from app.engines.linux.analysis.timeline import build_timeline
        return build_timeline(result)

    def apply_timeline_severity(self, result) -> None:
        from app.engines.linux.analysis.timeline import apply_severity
        apply_severity(result)

    def data_quality_warnings(self, result) -> List[str]:
        from app.engines.linux.analysis.quality import data_quality_warnings
        return data_quality_warnings(result)

    def describe_os(self, result) -> str:
        from app.engines.linux.analysis.os_profile import describe_os
        return describe_os(result)

    # ------------------------------------------------------------------ judging it
    def indicator_engine(self, iocs=None):
        from app.engines.linux.indicators.engine import IndicatorEngine
        return IndicatorEngine(iocs=iocs)

    def rule_name(self, rule_id: str) -> str:
        from app.engines.linux.indicators.engine import rule_name
        return rule_name(rule_id)

    def rule_catalog(self) -> Dict[str, Any]:
        from app.engines.linux.indicators.engine import rule_catalog
        return rule_catalog()

    def attack_for(self, rule_id: str) -> List[Any]:
        from app.engines.linux.indicators.attack import attack_for
        return attack_for(rule_id)

    def refresh_image_hash_findings(self, result, iocs=None) -> int:
        return todo("refresh_image_hash_findings")

    def demo_result(self):
        """The demo investigation (made-up data): lets every view be seen before the engine is written. Defined in ``demo.py``; delete that file and ``capabilities.demo`` to remove it."""
        from app.engines.linux import demo
        return demo.build()

    # ------------------------------------------------------------------ small questions the views ask
    def is_risky_path(self, path: str) -> bool:
        from app.engines.linux.indicators.helpers import is_risky_dir
        return is_risky_dir(path)

    def is_trusted_path(self, path: str) -> bool:
        from app.engines.linux.indicators.helpers import is_trusted_dir
        return is_trusted_dir(path)

    # ------------------------------------------------------------------ the window
    def view_specs(self) -> List[ViewSpec]:
        """Like Windows, minus the Registry (Linux has none), and with placeholders where a view needs engine code that does not exist yet."""
        return [
            ViewSpec("Overview"), ViewSpec("Search"), ViewSpec("Process Tree"), ViewSpec("Indications"),
            ViewSpec("Injection", available=False, reason="Linux process-injection chains (linux.malfind, ptrace, /proc/<pid>/mem writers) are not written yet."),
            ViewSpec("Plugin Output"),
            ViewSpec("Files", available=False, reason="The Linux file view (linux.pagecache.Files, linux.lsof, mounts) is not written yet. " + _NOT_YET),
            ViewSpec("Network"), ViewSpec("Timeline"), ViewSpec("Lifetimes"),
            ViewSpec("Compare", available=False, reason="Comparing two Linux investigations is not written yet. " + _NOT_YET),
            ViewSpec("Case Notes"), ViewSpec("Computer Info"),
        ]
