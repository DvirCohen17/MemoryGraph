"""Linux: what is NORMAL (SKELETON: empty tables to fill). Everything detection-related that is "knowledge" lives here, not in the rule logic.

Compare ``app/engines/windows/indicators/baseline.py``. Ideas for Linux: the process hierarchy (``systemd`` as PID 1, ``kthreadd`` PID 2 and its children, which processes are
children of ``sshd`` / ``cron`` / ``login``), the directories programs normally run from, the interpreters and the parents they normally have, the processes that normally do not talk
to the internet, the libraries a process normally loads, the kernel modules a distribution normally has.
"""
from __future__ import annotations

CORE_PROCESSES: dict = {}            # name -> {"parents": {...}, "dirs": [...], "single": bool}
INTERPRETERS: set = set()
NORMAL_INTERPRETER_PARENTS: set = set()
NO_NETWORK_EXPECTED: set = set()
HIGH_RISK_DIR_FRAGMENTS: tuple = ()  # /tmp/, /dev/shm/, /var/tmp/, hidden directories under /home ...
TRUSTED_DIR_FRAGMENTS: tuple = ()    # /usr/bin/, /usr/sbin/, /usr/lib/, /bin/, /sbin/, /lib/ ...
