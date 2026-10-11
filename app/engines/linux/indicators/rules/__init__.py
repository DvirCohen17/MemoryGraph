"""Linux rules (SKELETON): one module per family, each a few ``IndicatorRule`` subclasses registered in ``../engine.py``.

Families a Linux investigation usually needs (compare the Windows families in ``app/engines/windows/indicators/rules``):
  process.py       parent / child that does not fit (a shell under a web server, ``kthreadd`` children, PID 1), processes missing from the task list (psscan vs pslist), kernel-thread names
                   on user processes, masquerading (``[kworker/0:1]`` as a user process), deleted binaries (``/proc/<pid>/exe (deleted)``)
  path.py          programs running from /tmp, /dev/shm, /var/tmp or hidden directories
  commandline.py   reverse-shell one-liners (``bash -i >& /dev/tcp``), ``curl | sh``, ``base64 -d`` pipes, ``nc -e``
  memory.py        executable anonymous memory (linux.malfind), memfd / deleted-file mappings, ``LD_PRELOAD`` in the environment
  network.py       listening ports on unexpected processes, connections to public addresses from shells and interpreters
  kernel.py        hidden kernel modules, system call table and IDT changes, tty / keyboard-notifier hooks, network handler hooks
  persistence.py   cron, systemd units, rc scripts, ``authorized_keys``, shell profile files (the Linux counterpart of the registry rules)
  history.py       suspicious entries recovered by linux.bash
  ioc.py           the investigator's own IOC lists: the generic ``app/analysis/ioc.py`` already parses them; only the matching rules are OS specific
"""
