# TEST-50F6D361CC-20260924-154417.raw

* image: `C:\Users\test0\Downloads\TEST-50F6D361CC-20260924-154417.raw` (512 MiB), analysed in 407 s
* OS (windows.info): {'name': 'Windows XP SP3 (x86, NT 5.1, build 2600)', 'family': 'xp', 'nt': '5.1', 'build': 2600, 'service_pack': 3, 'is64': False, 'volatility2_profile': 'WinXPSP3x86'}
* counts: {'processes': 27, 'connections': 19, 'memory_regions': 15, 'findings': 9}

## Plugins

| Plugin | Status | Rows | s | Category | Volatility's own words |
|---|---|---|---|---|---|
| windows.info | Completed | 23 | 25 | OK |  |
| windows.pslist | Completed | 27 | 13 | OK |  |
| windows.psscan | Completed | 27 | 22 | OK |  |
| windows.pstree | Completed | 27 | 15 | OK |  |
| windows.cmdline | Completed | 27 | 14 | OK |  |
| windows.getsids | Completed | 196 | 18 | OK |  |
| windows.netscan | Skipped | 0 | 0 | Skipped by MemoryGraph: not applicable to this Windows | windows.netscan needs Windows Vista or newer; this image is Windows XP SP3. Network connections for this image come from Volatility 2 instead (vol2.connections, vol2.sockets). |
| windows.netstat | Skipped | 0 | 0 | Skipped by MemoryGraph: not applicable to this Windows | windows.netstat needs Windows Vista or newer; this image is Windows XP SP3. Network connections for this image come from Volatility 2 instead (vol2.connections, vol2.sockets). |
| windows.malfind | Completed | 15 | 33 | OK |  |
| windows.dlllist | Completed | 1172 | 16 | OK |  |
| windows.handles | Completed | 5751 | 43 | OK |  |
| windows.modules | Completed | 122 | 12 | OK |  |
| windows.modscan | Completed | 125 | 13 | OK |  |
| windows.ssdt | Completed | 322 | 10 | OK |  |
| windows.callbacks | Completed | 31 | 15 | OK |  |
| windows.svcscan | Completed | 264 | 10 | OK |  |
| windows.driverscan | Completed | 101 | 10 | OK |  |
| windows.registry.userassist | Completed | 39 | 9 | OK |  |
| windows.envars | Completed | 559 | 7 | OK |  |
| windows.mutantscan | Completed | 233 | 8 | OK |  |
| windows.filescan | Completed | 1798 | 17 | OK |  |
| windows.vadinfo | Completed | 2937 | 25 | OK |  |
| windows.ldrmodules | Completed | 1101 | 16 | OK |  |
| windows.psxview | Completed | 50 | 18 | OK |  |
| windows.registry.printkey [Run, machine] | Completed | 15 | 12 | OK |  |
| windows.registry.printkey [RunOnce, machine] | Completed | 12 | 15 | OK |  |
| windows.registry.printkey [Run, user] | Completed | 9 | 15 | OK |  |
| windows.registry.printkey [RunOnce, user] | Completed | 13 | 16 | OK |  |
| windows.registry.printkey [Winlogon] | Completed | 47 | 16 | OK |  |
| windows.registry.printkey [AppInit] | Completed | 19 | 18 | OK |  |
| windows.registry.printkey [IFEO] | Completed | 135 | 20 | OK |  |
| windows.registry.printkey [Run, 32-bit] | Completed | 13 | 17 | OK |  |
| windows.registry.printkey [RunOnce, 32-bit] | Completed | 13 | 16 | OK |  |
| windows.registry.printkey [Explorer Run, machine] | Completed | 13 | 17 | OK |  |
| windows.registry.printkey [Explorer Run, user] | Completed | 13 | 17 | OK |  |
| windows.registry.printkey [Active Setup] | Completed | 253 | 16 | OK |  |
| windows.registry.printkey [Services] | Completed | 5484 | 63 | OK |  |
| windows.registry.scheduled_tasks | Skipped | 0 | 0 | Skipped by MemoryGraph: not applicable to this Windows | windows.registry.scheduled_tasks needs Windows Vista or newer; this image is Windows XP SP3. |
| windows.registry.amcache | Skipped | 0 | 0 | Skipped by MemoryGraph: not applicable to this Windows | windows.registry.amcache needs Windows 7 or newer; this image is Windows XP SP3. |
| windows.malware.hollowprocesses | Completed | 0 | 22 | Completed, 0 rows (possibly incomplete or nothing to report) |  |
| windows.malware.suspicious_threads | Completed | 6 | 21 | OK |  |
| windows.malware.pebmasquerade | Completed | 27 | 8 | OK |  |
| windows.malware.processghosting | Completed | 0 | 15 | Completed, 0 rows (possibly incomplete or nothing to report) |  |
| windows.malware.svcdiff | Skipped | 0 | 0 | Skipped by MemoryGraph: not applicable to this Windows | windows.malware.svcdiff needs Windows 10 or newer; this image is Windows XP SP3. |
| windows.etwpatch | Completed | 0 | 16 | Completed, 0 rows (possibly incomplete or nothing to report) |  |
| windows.driverirp | Completed | 2828 | 13 | OK |  |
| windows.shimcachemem | Completed | 25 | 19 | OK |  |
| vol2.connections | Completed | 0 | 15 | Completed, 0 rows (possibly incomplete or nothing to report) |  |
| vol2.sockets | Completed | 19 | 11 | OK |  |

## MemoryGraph versus the raw Volatility output

| Area | Check | Result | Detail |
|---|---|---|---|
| Processes | same processes as Volatility (pslist ∪ psscan) | **PASS** | Volatility 27, MemoryGraph 27  |
| Processes | process names | **PASS** | 27 compared  |
| Processes | parent PIDs (pslist PPID) | **PASS** | 27 compared  |
| Processes | command lines (windows.cmdline) | **PASS** | 27 compared  |
| Processes | hidden processes (psscan only, not exited) | **PASS** | Volatility [], MemoryGraph []  |
| Modules | DLL lists per process (windows.dlllist) | **PASS** | 26 processes, 1172 rows  |
| Memory | malfind regions (pid + start address) | **PASS** | Volatility 15, MemoryGraph 15  |
| Network | windows.netscan | **INCONCLUSIVE** | Skipped: windows.netscan needs Windows Vista or newer; this image is Windows XP SP3. Network connections for this image come from Volatility 2 instead (vol2.connections, vol2.sockets).  |
| Network | windows.netstat | **INCONCLUSIVE** | Skipped: windows.netstat needs Windows Vista or newer; this image is Windows XP SP3. Network connections for this image come from Volatility 2 instead (vol2.connections, vol2.sockets).  |
| Network | every connection of Volatility 3 / 2 is in MemoryGraph (pid, protocol, local and remote address + port) | **PASS** | from vol2.sockets (19); 19 distinct connections, MemoryGraph 19  |
| Network | connections only in MemoryGraph | **PASS** |   |
| Handles | handle counts per process | **PASS** | 5751 handles, 27 processes  |
| UI | view 'Overview' builds | **PASS** |   |
| UI | view 'Search' builds | **PASS** |   |
| UI | view 'Process Tree' builds | **PASS** |   |
| UI | view 'Indications' builds | **PASS** |   |
| UI | view 'Injection' builds | **PASS** |   |
| UI | view 'Plugin Output' builds | **PASS** |   |
| UI | view 'Files' builds | **PASS** |   |
| UI | view 'Registry' builds | **PASS** |   |
| UI | view 'Network' builds | **PASS** |   |
| UI | view 'Timeline' builds | **PASS** |   |
| UI | view 'Lifetimes' builds | **PASS** |   |
| UI | view 'Compare' builds | **PASS** |   |
| UI | view 'Case Notes' builds | **PASS** |   |
| UI | view 'Computer Info' builds | **PASS** |   |
| UI | Process Tree lists every process | **PASS** | 27 shown, 27 in the result  |
| UI | Network view holds every connection | **PASS** | 19 rows, 19 connections in the result; 19 of 19 connections shown  |
| UI | Indications view shows the findings | **PASS** | 4 tree rows for 9 findings (Low findings are hidden by default)  |
| UI | Plugin Output offers every completed plugin | **PASS** | 40 plugins tried  |
| UI | every process window opens | **PASS** | 27 tried  |

## Expected facts

| Id | Fact | Verified | Result | Detail |
|---|---|---|---|---|
| XP-P1 | Lab12-03.exe (PID 1780) started by explorer.exe (PID 1556) | yes | **PASS** | PID 1780, PPID 1556 |
| XP-P2 | procexp.exe (PID 2016) started by explorer.exe | yes | **PASS** | PID 2016, PPID 1556 |
| XP-P3 | DumpIt.exe (PID 2044) = the acquisition tool, started by explorer.exe | yes | **PASS** | PID 2044, PPID 1556 |
| XP-P4 | services.exe is started by winlogon.exe (normal on XP) | yes | **PASS** | parent is winlogon.exe |
| XP-P5 | lsass.exe is started by winlogon.exe (normal on XP) | yes | **PASS** | parent is winlogon.exe |
| XP-N1 | windows.netscan is skipped on XP (Volatility 3 does not support it), not shown as failed | yes | **PASS** | status Skipped |
| XP-N2 | windows.netstat is skipped on XP | yes | **PASS** | status Skipped |
| XP-F1 | executable file in the Recycle Bin (\RECYCLER\...\Dc23.exe1.0-rc2_signed.exe) | yes | **PASS** | Medium: 1 executable file object(s) in Public, Recycle Bin or Windows\Temp |
| XP-L1 | something is reported about Lab12-03.exe, a Practical Malware Analysis lab sample running from the Desktop | NO | **FAIL** | no finding on this process |
| XP-K1 | CBK-001 for the IoRegisterFsRegistrationChange value 0x1375c085 (no module, listed three times) is reported, as Medium (was High before RW-004). Whether it is a real hook or a windows.callbacks artifact is NOT established | NO | **PASS** | Medium: 1 kernel callback(s) point into user-mode memory |

## Findings (9)

Severity: {'Medium': 3, 'Low': 6}  ·  Rules: {'CBK-001': 2, 'FILE-001': 2, 'DRV-001': 1, 'MEM-001': 4}

| Rule | Sev | Process | Title | Evidence | Verdict |
|---|---|---|---|---|---|
| CBK-001 | Medium | - | 1 kernel callback(s) point into user-mode memory | IoRegisterFsRegistrationChange @ 0x1375c085 | Inconclusive - value 0x1375c085 three times with no module; the Windows 10 image shows the same pattern, so a windows.callbacks artifact is likely but unproven |
| CBK-001 | Medium | - | 1 kernel callback(s) point outside every loaded module | GenericKernelCallback @ 0xf41b53e8 | Unreviewed |
| FILE-001 | Medium | - | 1 executable file object(s) in Public, Recycle Bin or Windows\Temp | \RECYCLER\S-1-5-21-1659004503-412668190-1644491937-500\Dc23.exe1.0-rc2_signed.exe | True Positive - the file object exists in windows.filescan: an executable in the Recycle Bin (a lead; its content was not analysed) |
| DRV-001 | Low | - | 2 driver object(s) found by scan are not in the loaded-module list | drmkaud.sys base=0xf8de5000; DMusic.sys base=0xb2bde000 path=(unreadable name) | Unreviewed |
| FILE-001 | Low | - | 2 executable file object(s) in Temp or Downloads | \DOCUME~1\ADMINI~1\LOCALS~1\Temp\winup.exe; \Documents and Settings\Administrator\Local Settings\Temp\vmware-Administrat | Unreviewed |
| MEM-001 | Low | csrss.exe (612) | Executable private memory reported by malfind | 0x7f6f0000–0x7f7effff (1.0 MB) PAGE_EXECUTE_READWRITE tag=Vad  | Unreviewed |
| MEM-001 | Low | winlogon.exe (640) | Executable private memory reported by malfind | 0x580000–0x59ffff (128.0 KB) PAGE_EXECUTE_READ tag=Vad ; 0x3e750000–0x3e753fff (16.0 KB) PAGE_EXECUTE_READWRITE tag=VadS | Unreviewed |
| MEM-001 | Low | explorer.exe (1556) | Executable private memory reported by malfind | 0x2080000–0x2080fff (4.0 KB) PAGE_EXECUTE_READWRITE tag=VadS | Unreviewed |
| MEM-001 | Low | procexp.exe (2016) | Executable private memory reported by malfind | 0x8d0000–0xbcffff (3.0 MB) PAGE_EXECUTE_READ tag=Vad ; 0x7f6f0000–0x7f7effff (1.0 MB) PAGE_EXECUTE_READ tag=Vad  | Unreviewed |

## Warnings of the analysis

* Not run because they do not exist for this Windows version: windows.netscan, windows.netstat, windows.registry.scheduled_tasks, windows.registry.amcache, windows.malware.svcdiff (see Plugin Output for the reason).
* windows.vadyarascan was skipped: it needs a value for 'yara_rules_file' in Settings (for example the path of your YARA rule file).
