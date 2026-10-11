"""The Windows engine: Windows memory images (XP / 2003 to Windows 11), complete.

    analysis/     plugin registry and bundles, the provider, normalizer, OS profile (version -> Volatility 2 profile), Volatility 2 for XP network, timeline sources,
                  dumping, file reports, registry tree, process injection chains, known-good lists, comparison
    indicators/   the investigation rules (rules/), the baselines of what is normal on Windows, the ATT&CK mapping, the helpers the rules share
    data/         ATT&CK technique descriptions (local, nothing is fetched)
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

from app.engines.base import Capabilities, Engine, Terms, ViewSpec

_VIEWS = ("Overview", "Search", "Process Tree", "Indications", "Injection", "Plugin Output", "Files", "Registry", "Network", "Timeline", "Lifetimes", "Compare",
          "Case Notes", "Computer Info")


class WindowsEngine(Engine):
    id = "windows"
    label = "Windows"
    capabilities = Capabilities(registry=True, legacy_network_engine=True, process_images=True, known_good=True, file_explorer=True, compare=True)
    terms = Terms(
        os_name="Windows", title="Windows Memory Analysis", subtitle="Select a memory dump of a Windows system to begin an investigation.",
        image_placeholder="Select a .raw, .mem, .dmp, .vmem or other Windows memory image…",
        image_filter="Memory Images (*.raw *.mem *.dmp *.vmem *.bin *.img);;All Files (*)",
        module="DLL", modules="DLLs", dump_modules="Dump DLLs", handles="Handles",
        symbols_hint="Volatility 3 needs the symbol table (ISF) of the image's Windows build, and of tcpip.sys for the network plugins. MemoryGraph never goes online: put the files "
                     "in a folder and add it here (see docs/OFFLINE.md).",
        tagline="XP and 2003 to Windows 11",
    )

    # ------------------------------------------------------------------ what to run
    def plugin_registry(self):
        from app.engines.windows.analysis import plugin_registry
        return plugin_registry

    def default_settings(self) -> Dict[str, Any]:
        return {"enabled_plugins": [], "run_extended_plugins": False, "optional_plugins": [], "symbol_dirs": [], "yara_rules_file": ""}

    def make_provider(self, settings: dict):
        from app.engines.windows.analysis.real_provider import RealProvider
        return RealProvider(settings)

    def make_dumper(self, dump_path: str, volatility_path: str = "", global_args: Sequence[str] = ()):
        from app.engines.windows.analysis.dumper import VolatilityDumper
        return VolatilityDumper(dump_path, volatility_path, list(global_args))

    # ------------------------------------------------------------------ turning plugin rows into a result
    def normalize(self, dump_path: str, plugins: Sequence[Any]):
        from app.engines.windows.analysis.normalizer import normalize
        return normalize(dump_path, plugins)

    def build_timeline(self, result) -> List[Any]:
        from app.engines.windows.analysis.timeline_builder import build_timeline
        return build_timeline(result)

    def apply_timeline_severity(self, result) -> None:
        from app.engines.windows.analysis.timeline_builder import apply_severity
        apply_severity(result)

    def data_quality_warnings(self, result) -> List[str]:
        from app.engines.windows.analysis.quality import data_quality_warnings
        return data_quality_warnings(result)

    def describe_os(self, result) -> str:
        from app.engines.windows.analysis import os_profile
        profile = os_profile.from_result(result)
        return profile.name if profile.known else "Windows (version unknown)"

    # ------------------------------------------------------------------ judging it
    def indicator_engine(self, iocs=None):
        from app.engines.windows.indicators.engine import IndicatorEngine
        return IndicatorEngine(iocs=iocs)

    def rule_name(self, rule_id: str) -> str:
        from app.engines.windows.indicators.engine import rule_name
        return rule_name(rule_id)

    def rule_catalog(self) -> Dict[str, Any]:
        from app.engines.windows.indicators.engine import RULE_CATALOG
        return RULE_CATALOG

    def attack_for(self, rule_id: str) -> List[Any]:
        from app.engines.windows.indicators.attack import attack_for
        return attack_for(rule_id)

    def refresh_image_hash_findings(self, result, iocs=None) -> int:
        from app.engines.windows.analysis.image_hashes import refresh_image_hash_findings
        return refresh_image_hash_findings(result, iocs)

    def demo_result(self):
        """The Windows engine has no demo (its start window offers real images; ``capabilities.demo`` is False)."""
        from app.engines.base import EngineNotImplemented
        raise EngineNotImplemented(self.label, "demo_result")

    # ------------------------------------------------------------------ small questions the views ask
    def is_risky_path(self, path: str) -> bool:
        from app.engines.windows.indicators.helpers import is_high_risk_dir
        return is_high_risk_dir(path)

    def is_trusted_path(self, path: str) -> bool:
        from app.engines.windows.indicators.helpers import is_trusted_dir
        return is_trusted_dir(path)

    def view_specs(self) -> List[ViewSpec]:
        return [ViewSpec(v) for v in _VIEWS]
