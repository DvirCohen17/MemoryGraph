"""Linux: the ATT&CK mapping of the rules (SKELETON). Windows keeps ``ATTACK_BY_RULE`` (rule id -> techniques) and a local data file with each technique's description
(``app/engines/windows/data/attack_techniques.json``): the same shape here, with the Linux techniques (T1055 process injection, T1014 rootkit, T1053.003 cron, ...). Nothing is
fetched from the internet."""
from __future__ import annotations

from typing import List

from app.engines.linux._todo import todo


def attack_for(rule_id: str) -> List:
    """The techniques of a rule, as objects with ``id``, ``name`` and ``info`` (tactics, summary, what to look for)."""
    return []                          # neutral until the Linux rules and their mapping exist (the Indications view shows no technique)


def technique_info(technique_id: str):
    return todo("technique_info")
