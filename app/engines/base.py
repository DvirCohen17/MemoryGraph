"""The engine interface: everything that is specific to ONE operating system of the memory image.

MemoryGraph has two halves. The **front end** (``app/windows``: the windows, views, tables, settings; ``app/analysis``: the pipeline, the case file, the
Volatility runner, IOC lists, the timing store) works on one result type, :class:`app.models.AnalysisResult`, and does not know which operating system produced it.
An **engine** (``app/engines/<os>``) is everything that turns a memory image of that operating system into an ``AnalysisResult`` and judges it:

* ``analysis/``   which Volatility plugins to run (the plugin registry and its Settings groups), the provider that runs them, the normalizer that turns their rows into
                  processes / connections / modules / memory regions, the OS profile (version detection), the timeline sources, dumping and file reports;
* ``indicators/`` the investigation rules (indications), their baselines of what is normal for that OS, and the ATT&CK mapping;
* ``data/``       reference data (ATT&CK technique descriptions, known-good lists ...).

The front end asks the engine through this class and never imports ``app/engines/<os>/...`` directly (the views that are specific to one operating system, such as the
Windows registry browser, are the only exception and are listed in :meth:`Engine.view_specs`). The Windows engine is complete. The **Linux engine is a skeleton**:
every function exists with its signature and a docstring that says what it must return, and raises :class:`EngineNotImplemented` until it is written.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from app.errors import MemoryGraphError


class EngineNotImplemented(MemoryGraphError):
    """Raised by a part of an engine that has not been written yet. The message names the engine and the function, so the window can say exactly what is missing."""

    def __init__(self, engine: str, function: str):
        super().__init__(f"The {engine} engine does not implement “{function}” yet.\n\nIt is a placeholder in app/engines/{engine.lower()}/ that is waiting to be written; "
                         "the rest of MemoryGraph is ready for it.")
        self.engine = engine
        self.function = function


@dataclass(frozen=True)
class ViewSpec:
    """One entry of the dashboard's navigation. ``available=False`` shows the entry with a page that says why (instead of hiding it), so a missing part is visible."""
    id: str                    # the name the dashboard knows the view by ("Overview", "Process Tree", "Registry", ...)
    available: bool = True
    reason: str = ""           # shown on the placeholder page when not available


@dataclass(frozen=True)
class Capabilities:
    """What the operating system has, so the windows show only what applies (a Linux image has no registry)."""
    registry: bool = False             # a registry browser and registry-based persistence
    legacy_network_engine: bool = False   # Volatility 2 for very old systems (Windows XP / 2003)
    process_images: bool = False       # "Hash all process images"
    known_good: bool = False           # known-good module lists
    file_explorer: bool = False        # Explorer-style file view of the file objects found in memory
    compare: bool = False              # comparing two investigations section by section
    demo: bool = False                 # a built-in demo investigation (made-up data) the start window can open


@dataclass(frozen=True)
class Terms:
    """The words the windows use for things that have another name on this operating system."""
    os_name: str = "Windows"
    title: str = "Windows Memory Analysis"
    subtitle: str = "Select a memory dump to begin an investigation."
    image_placeholder: str = "Select a .raw, .mem, .dmp, .vmem or other memory image…"
    image_filter: str = "Memory Images (*.raw *.mem *.dmp *.vmem *.bin *.lime *.img);;All Files (*)"
    module: str = "DLL"
    modules_tab: str = "Modules"        # the tab of a process window that lists them
    modules: str = "DLLs"
    dump_modules: str = "Dump DLLs"
    handles: str = "Handles"
    symbols_hint: str = ""
    tagline: str = ""


class Engine:
    """Base class of an operating-system engine. Subclasses fill in the attributes and override the methods (the defaults raise :class:`EngineNotImplemented`)."""

    id: str = ""                        # "windows" / "linux": stored in settings and in every saved investigation
    implemented: bool = True            # False for an engine that is only a skeleton: the start window says so
    status_note: str = ""               # shown on the start window when ``implemented`` is False
    label: str = ""
    capabilities: Capabilities = Capabilities()
    terms: Terms = Terms()
    #: the settings keys that belong to this operating system (they are swapped when the user switches; see app.settings.switch_target_os)
    os_settings_keys: Sequence[str] = ("enabled_plugins", "run_extended_plugins", "optional_plugins", "symbol_dirs", "yara_rules_file")

    # ------------------------------------------------------------------ what to run
    def plugin_registry(self):
        """The engine's plugin registry module/object: ``REGISTRY``, ``BUNDLES``, ``names``, ``get``, ``find``, ``optional_choices``, ``bundle_state``, ``apply_bundles``."""
        raise EngineNotImplemented(self.label, "plugin_registry")

    def default_settings(self) -> Dict[str, Any]:
        """The values of ``os_settings_keys`` a fresh profile of this operating system starts with."""
        raise EngineNotImplemented(self.label, "default_settings")

    def make_provider(self, settings: dict):
        """An object with ``run(dump_path, progress, plugin_event, cancel) -> AnalysisResult`` and ``rerun(result, names, progress, plugin_event, cancel)``."""
        raise EngineNotImplemented(self.label, "make_provider")

    def make_dumper(self, dump_path: str, volatility_path: str = "", global_args: Sequence[str] = ()):
        """An object that dumps processes, modules, files and memory regions out of the image (``dump_process``, ``dump_dlls``, ``dump_handles``, ``dump_malfind_pages`` ...)."""
        raise EngineNotImplemented(self.label, "make_dumper")

    # ------------------------------------------------------------------ turning plugin rows into a result
    def normalize(self, dump_path: str, plugins: Sequence[Any]):
        """``list[PluginResult]`` -> :class:`AnalysisResult` (processes, connections, memory regions, system info ...), without indications."""
        raise EngineNotImplemented(self.label, "normalize")

    def build_timeline(self, result) -> List[Any]:
        """The ``TimelineEvent`` list of the result (process starts, connections, module loads, execution history ...)."""
        raise EngineNotImplemented(self.label, "build_timeline")

    def apply_timeline_severity(self, result) -> None:
        """Mark each timeline event with the highest severity of the findings of its process."""
        raise EngineNotImplemented(self.label, "apply_timeline_severity")

    def data_quality_warnings(self, result) -> List[str]:
        """Things about the image that limit what the rules can say (partly readable lists, an acquisition that was still running ...)."""
        raise EngineNotImplemented(self.label, "data_quality_warnings")

    def describe_os(self, result) -> str:
        """One line naming the operating system of the image (``Windows 10 (x64, build 15063)``)."""
        raise EngineNotImplemented(self.label, "describe_os")

    # ------------------------------------------------------------------ judging it
    def indicator_engine(self, iocs=None):
        """An object with ``evaluate(result) -> list[Indication]`` and ``errors``; ``iocs`` is the investigator's own indicator set."""
        raise EngineNotImplemented(self.label, "indicator_engine")

    def rule_name(self, rule_id: str) -> str:
        raise EngineNotImplemented(self.label, "rule_name")

    def rule_catalog(self) -> Dict[str, Any]:
        """``{rule id: rule object}`` with ``name`` and ``description`` (Indications view, case notes)."""
        raise EngineNotImplemented(self.label, "rule_catalog")

    def attack_for(self, rule_id: str) -> List[Any]:
        """The MITRE ATT&CK techniques the rule is commonly associated with (local data, nothing is fetched)."""
        raise EngineNotImplemented(self.label, "attack_for")

    def refresh_image_hash_findings(self, result, iocs=None) -> int:
        """Match the stored process-image hashes against the IOC list (rule IOC-007); returns how many findings that gives."""
        raise EngineNotImplemented(self.label, "refresh_image_hash_findings")

    def demo_result(self):
        """A made-up :class:`AnalysisResult` for the "Show a demo investigation" button (only when ``capabilities.demo``)."""
        raise EngineNotImplemented(self.label, "demo_result")

    # ------------------------------------------------------------------ small questions the views ask
    def is_risky_path(self, path: str) -> bool:
        """A folder code should not normally run from (temporary, downloads, world-writable). The views use it to colour module paths; False when unknown."""
        return False

    def is_trusted_path(self, path: str) -> bool:
        """A folder system files normally live in; False when unknown."""
        return False

    # ------------------------------------------------------------------ the window
    def view_specs(self) -> List[ViewSpec]:
        """The dashboard's navigation, in order."""
        return [ViewSpec(v) for v in ("Overview", "Search", "Process Tree", "Indications", "Plugin Output", "Network", "Timeline", "Lifetimes", "Case Notes", "Computer Info")]

    def __repr__(self) -> str:
        return f"<Engine {self.id}>"
