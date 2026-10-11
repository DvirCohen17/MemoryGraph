"""What an engine's plugin list is made of (the same for every operating system): plugin specs, Settings bundles and the registry that answers questions about them.

An engine declares its plugins as :class:`PluginSpec` tuples and its Settings groups as :class:`Bundle` tuples, then wraps both in a :class:`PluginRegistry`
(``app/engines/<os>/analysis/plugin_registry.py``). The provider, the Settings window and the documentation read that one object; adding a plugin is one spec.
Groups: ``core`` always runs (unless unticked in Settings; ``required`` ones cannot be unticked), ``extended`` runs together when extended plugins are ticked,
``optional`` runs only when ticked. The settings keys behind them (``enabled_plugins``, ``run_extended_plugins``, ``optional_plugins``) are the same for every engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

CORE, EXTENDED, OPTIONAL = "core", "extended", "optional"
_NT_NAMES = {(5, 1): "XP", (5, 2): "Server 2003", (6, 0): "Vista", (6, 1): "7", (6, 2): "8", (6, 3): "8.1", (10, 0): "10"}


@dataclass(frozen=True)
class PluginSpec:
    name: str
    group: str
    purpose: str
    required: bool = False
    used_by: Tuple[str, ...] = ()           # rule ids / views that read this plugin's rows (documentation, shown in Settings)
    plugin: str = ""                        # Volatility plugin to run when ``name`` is only a label
    args: Tuple[str, ...] = ()              # fixed arguments
    setting_arg: Tuple[str, str] = ()       # (settings key, flag): adds "flag <setting value>"
    needs_setting: str = ""                 # skipped unless this setting is non-empty
    choice: str = ""                        # Settings checkbox id shared by several specs (defaults to ``name``)
    alternatives: Tuple[str, ...] = ()      # other Volatility names of this plugin in other versions (tried when ``plugin`` is not listed)
    warning: str = ""                       # shown next to the Settings checkbox
    min_nt: Tuple[int, int] = (0, 0)        # first OS version (Windows: NT major, minor) the plugin exists for: (6, 0) = Vista; older images skip it with a reason
    max_nt: Tuple[int, int] = (99, 99)      # last OS version it exists for

    @property
    def volatility_plugin(self) -> str:
        return self.plugin or self.name

    @property
    def choice_id(self) -> str:
        return self.choice or self.name

    def inapplicable(self, profile) -> str:
        """Why this plugin makes no sense for the image's OS version (an OS profile with ``known``, ``version`` and ``short_name``), or '' when it does or the OS is unknown."""
        if not profile.known:
            return ""
        if profile.version < self.min_nt:
            return (f"{self.volatility_plugin} needs Windows {_NT_NAMES.get(self.min_nt, 'NT %d.%d' % self.min_nt)} or newer; "
                    f"this image is {profile.short_name}.")
        if profile.version > self.max_nt:
            return f"{self.volatility_plugin} does not exist for {profile.short_name}."
        return ""

    @property
    def volatility_names(self) -> Tuple[str, ...]:
        """Every Volatility name this plugin is known under, preferred one first."""
        return (self.volatility_plugin,) + tuple(a for a in self.alternatives if a != self.volatility_plugin)


@dataclass(frozen=True)
class Bundle:
    """A group of plugins that is ticked as one in Settings. ``members`` are spec names; the settings keys behind them stay what they were
    (``enabled_plugins`` for core plugins, ``run_extended_plugins`` for the extended ones, ``optional_plugins`` for opt-in choices)."""
    id: str
    title: str
    description: str
    members: Tuple[str, ...]
    default: bool = False
    locked: bool = False          # always on (the process list everything else depends on)
    warning: str = ""


class PluginRegistry:
    def __init__(self, specs: Iterable[PluginSpec], bundles: Iterable[Bundle] = ()):
        self.REGISTRY: Tuple[PluginSpec, ...] = tuple(specs)
        self.BUNDLES: Tuple[Bundle, ...] = tuple(bundles)
        self._by_name: Dict[str, PluginSpec] = {spec.name: spec for spec in self.REGISTRY}
        self._bundle_of: Dict[str, Bundle] = {name: bundle for bundle in self.BUNDLES for name in bundle.members}

    # ------------------------------------------------------------------ the plugins
    def plugin_names_used_by(self, rule_id: str) -> List[str]:
        """Result names of the plugin runs whose output the given rule reads."""
        return [spec.name for spec in self.REGISTRY if rule_id in spec.used_by]

    def names(self, group: str) -> List[str]:
        return [spec.name for spec in self.REGISTRY if spec.group == group]

    def get(self, name: str) -> PluginSpec:
        return self._by_name[name]

    def find(self, name: str):
        return self._by_name.get(name)

    def known(self, name: str) -> bool:
        return name in self._by_name

    def required_names(self) -> Tuple[str, ...]:
        return tuple(spec.name for spec in self.REGISTRY if spec.required)

    def optional_choices(self) -> List[Tuple[str, str, str, List[str]]]:
        """[(choice id, label, warning, [spec names])] for the opt-in plugins, in registry order (one entry per Settings checkbox)."""
        order: Dict[str, Tuple[str, str, List[str]]] = {}
        for spec in self.REGISTRY:
            if spec.group != OPTIONAL:
                continue
            label, warning, members = order.setdefault(spec.choice_id, (spec.purpose, spec.warning, []))
            members.append(spec.name)
        return [(cid, label, warning, members) for cid, (label, warning, members) in order.items()]

    # ------------------------------------------------------------------ bundles: what Settings shows
    def bundle_of(self, spec_name: str) -> Bundle:
        return self._bundle_of[spec_name]

    def _member_on(self, spec: PluginSpec, settings: Dict) -> bool:
        if spec.required:
            return True
        if spec.group == CORE:
            enabled = settings.get("enabled_plugins") or [s.name for s in self.REGISTRY if s.group == CORE]
            return spec.name in enabled
        if spec.group == EXTENDED:
            return bool(settings.get("run_extended_plugins"))
        return spec.choice_id in (settings.get("optional_plugins") or [])

    def bundle_state(self, bundle: Bundle, settings: Dict) -> str:
        """``"on"``, ``"off"`` or ``"partial"`` (only some members enabled, for example by an older settings file)."""
        states = [self._member_on(self._by_name[name], settings) for name in bundle.members]
        return "on" if all(states) else "off" if not any(states) else "partial"

    def apply_bundles(self, settings: Dict, choices: Dict[str, str]) -> Dict:
        """Write the Settings checkboxes back into the settings keys. ``choices``: bundle id -> ``"on"`` / ``"off"`` / ``"keep"`` (leave members as they are)."""
        core_all = [s.name for s in self.REGISTRY if s.group == CORE]
        core = set(settings.get("enabled_plugins") or core_all)
        extended = bool(settings.get("run_extended_plugins"))
        optional = set(settings.get("optional_plugins") or [])
        for bundle in self.BUNDLES:
            choice = "on" if bundle.locked else choices.get(bundle.id, "keep")
            if choice == "keep":
                continue
            for name in bundle.members:
                spec = self._by_name[name]
                on = choice == "on" or spec.required
                if spec.group == CORE:
                    (core.add if on else core.discard)(name)
                elif spec.group == EXTENDED:
                    extended = on
                else:
                    (optional.add if on else optional.discard)(spec.choice_id)
        settings["enabled_plugins"] = [] if set(core_all) <= core else [n for n in core_all if n in core]
        settings["run_extended_plugins"] = extended
        settings["optional_plugins"] = [cid for cid, *_ in self.optional_choices() if cid in optional]
        return settings
