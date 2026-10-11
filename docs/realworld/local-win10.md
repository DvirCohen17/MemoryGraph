# WinDump.mem

* image: `C:\Users\test0\Downloads\WinDump\WinDump.mem` (4,992 MiB), analysed in 2546 s
* OS (windows.info): {'name': 'Windows 10 / Server 2016-2019 (x64, NT 10.0, build 15063)', 'family': '10', 'nt': '10.0', 'build': 15063, 'service_pack': 0, 'is64': True, 'volatility2_profile': ''}
* counts: {'processes': 155, 'connections': 141, 'memory_regions': 19, 'findings': 61}

## Plugins

| Plugin | Status | Rows | s | Category | Volatility's own words |
|---|---|---|---|---|---|
| windows.info | Completed | 20 | 8 | OK |  |
| windows.pslist | Completed | 139 | 9 | OK |  |
| windows.psscan | Completed | 160 | 144 | OK |  |
| windows.pstree | Completed | 139 | 11 | OK |  |
| windows.cmdline | Completed | 139 | 11 | OK |  |
| windows.getsids | Completed | 1662 | 50 | OK |  |
| windows.netscan | Completed | 174 | 70 | OK |  |
| windows.netstat | Completed | 92 | 5 | OK |  |
| windows.malfind | Completed | 19 | 657 | OK |  |
| windows.dlllist | Completed | 5779 | 63 | OK |  |
| windows.handles | Completed | 43472 | 848 | OK |  |
| windows.modules | Completed | 179 | 8 | OK |  |
| windows.modscan | Completed | 247 | 46 | OK |  |
| windows.ssdt | Completed | 669 | 5 | OK |  |
| windows.callbacks | Completed | 184 | 72 | OK |  |
| windows.svcscan | Completed | 1247 | 62 | OK |  |
| windows.driverscan | Completed | 151 | 49 | OK |  |
| windows.registry.userassist | Completed | 83 | 15 | OK |  |
| windows.envars | Completed | 3728 | 8 | OK |  |
| windows.mutantscan | Completed | 788 | 41 | OK |  |
| windows.filescan | Completed | 32613 | 378 | OK |  |
| windows.vadinfo | Completed | 16165 | 590 | OK |  |
| windows.ldrmodules | Completed | 5936 | 93 | OK |  |
| windows.psxview | Completed | 156 | 116 | OK |  |
| windows.registry.printkey [Run, machine] | Completed | 21 | 18 | OK |  |
| windows.registry.printkey [RunOnce, machine] | Completed | 20 | 14 | OK |  |
| windows.registry.printkey [Run, user] | Completed | 20 | 13 | OK |  |
| windows.registry.printkey [RunOnce, user] | Completed | 22 | 14 | OK |  |
| windows.registry.printkey [Winlogon] | Completed | 57 | 15 | OK |  |
| windows.registry.printkey [AppInit] | Completed | 41 | 14 | OK |  |
| windows.registry.printkey [IFEO] | Completed | 129 | 17 | OK |  |
| windows.registry.printkey [Run, 32-bit] | Completed | 21 | 15 | OK |  |
| windows.registry.printkey [RunOnce, 32-bit] | Completed | 20 | 16 | OK |  |
| windows.registry.printkey [Explorer Run, machine] | Completed | 21 | 17 | OK |  |
| windows.registry.printkey [Explorer Run, user] | Completed | 21 | 19 | OK |  |
| windows.registry.printkey [Active Setup] | Completed | 174 | 20 | OK |  |
| windows.registry.printkey [Services] | Completed | 15342 | 271 | OK |  |
| windows.registry.scheduled_tasks | Completed | 232 | 48 | OK |  |
| windows.registry.amcache | Completed | 1230 | 177 | OK |  |
| windows.malware.hollowprocesses | Completed | 1 | 359 | OK |  |
| windows.malware.suspicious_threads | Completed | 1 | 384 | OK |  |
| windows.malware.pebmasquerade | Completed | 139 | 3 | OK |  |
| windows.malware.processghosting | Completed | 0 | 65 | Completed, 0 rows (possibly incomplete or nothing to report) |  |
| windows.malware.svcdiff | Completed | 0 | 57 | Completed, 0 rows (possibly incomplete or nothing to report) |  |
| windows.etwpatch | Completed | 0 | 99 | Completed, 0 rows (possibly incomplete or nothing to report) |  |
| windows.driverirp | Completed | 4255 | 50 | OK |  |
| windows.shimcachemem | Completed | 13 | 4 | OK |  |

## MemoryGraph versus the raw Volatility output

| Area | Check | Result | Detail |
|---|---|---|---|
| Processes | same processes as Volatility (pslist ∪ psscan) | **PASS** | Volatility 155, MemoryGraph 155  |
| Processes | process names | **PASS** | 155 compared  |
| Processes | parent PIDs (pslist PPID) | **PASS** | 139 compared  |
| Processes | command lines (windows.cmdline) | **PASS** | 139 compared  |
| Processes | hidden processes (psscan only, not exited) | **PASS** | Volatility [3828, 6120], MemoryGraph [3828, 6120]  |
| Modules | DLL lists per process (windows.dlllist) | **PASS** | 124 processes, 5779 rows  |
| Memory | malfind regions (pid + start address) | **PASS** | Volatility 19, MemoryGraph 19  |
| Network | every connection of Volatility 3 / 2 is in MemoryGraph (pid, protocol, local and remote address + port) | **PASS** | from windows.netscan (174), windows.netstat (92); 118 distinct connections, MemoryGraph 118  |
| Network | connections only in MemoryGraph | **PASS** |   |
| Handles | handle counts per process | **PASS** | 43472 handles, 125 processes  |
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
| UI | Process Tree lists every process | **PASS** | 155 shown, 155 in the result  |
| UI | Network view holds every connection | **PASS** | 141 rows, 141 connections in the result; 141 of 141 connections shown  |
| UI | Indications view shows the findings | **PASS** | 14 tree rows for 61 findings (Low findings are hidden by default)  |
| UI | Plugin Output offers every completed plugin | **PASS** | 44 plugins tried  |
| UI | every process window opens | **PASS** | 155 tried  |

## Expected facts

| Id | Fact | Verified | Result | Detail |
|---|---|---|---|---|
| W10-P1 | System (PID 4, parent 0) | yes | **PASS** | PID 4, PPID 0 |
| W10-P2 | services.exe is started by wininit.exe | yes | **PASS** | parent is wininit.exe |
| W10-P3 | lsass.exe is started by wininit.exe | yes | **PASS** | parent is wininit.exe |
| W10-P4 | svchost.exe PID 3828 is in psscan and thrdscan but not pslist or csrss, no exit time (psxview raw row) | yes | **PASS** | PID 3828, PPID 716 |
| W10-P5 | taskhostw.exe PID 6120 is in psscan, thrdscan and csrss but not pslist, no exit time | yes | **PASS** | PID 6120, PPID 1568 |
| W10-F1 | reach.exe in \Windows\Temp\2964312081 (file object present in windows.filescan) | yes | **PASS** | Medium: 1 executable file object(s) in Public, Recycle Bin or Windows\Temp |
| W10-F2 | psscan-only process 3828 is reported | yes | **PASS** | Medium: Process present in psscan but not in pslist |
| W10-F3 | hollowprocesses' note for svchost 2756 (no VAD at the image base) is reported | yes | **PASS** | High: Process hollowing suspected: svchost.exe |
| W10-N1 | windows.netscan completes on Windows 10 with Volatility 2.28.2 | yes | **PASS** | status Completed |
| W10-N2 | windows.netstat completes on Windows 10 with Volatility 2.28.2 | yes | **PASS** | status Completed |

## Findings (61)

Severity: {'High': 1, 'Medium': 7, 'Low': 53}  ·  Rules: {'MAL-001': 1, 'CBK-001': 2, 'DRV-002': 1, 'FILE-001': 1, 'MAL-002': 1, 'MEM-001': 7, 'PT-003': 2, 'DRV-001': 1, 'LDR-001': 17, 'MAL-006': 1, 'UA-001': 1, 'VAD-001': 26}

| Rule | Sev | Process | Title | Evidence | Verdict |
|---|---|---|---|---|---|
| MAL-001 | High | svchost.exe (2756) | Process hollowing suspected: svchost.exe | There is no VAD starting at the base address of the process executable (0x7ff791320000) | Inconclusive - relays hollowprocesses' note for svchost 2756 (created at boot); a missing VAD can also mean unreadable page tables |
| CBK-001 | Medium | - | 1 kernel callback(s) point into user-mode memory | IoRegisterFsRegistrationChange @ 0x1f850f21394c | Inconclusive - 0x1f850f21394c is not a kernel address and has no module: probable windows.callbacks artifact, now Medium |
| DRV-002 | Medium | - | 2 driver object(s) are not backed by a loaded module | WudfRd start=0xf802214e0000; ퟀ㮓讅￿Ԙꦡ翹 start=0xf802214b0000 | Unreviewed |
| FILE-001 | Medium | - | 1 executable file object(s) in Public, Recycle Bin or Windows\Temp | \Windows\Temp\2964312081\reach.exe | True Positive - the file object exists; an executable in \Windows\Temp is a lead (content not analysed) |
| MAL-002 | Medium | CompatTelRunne (3672) | 1 thread(s) started in memory that no module backs in CompatTelRunne | TID 1972 Win32Start @ 0x7ff69b425350 <Non-File Backed Region> — This thread started execution in the VAD starting at bas | Unreviewed |
| MEM-001 | Medium | taskhostw.exe (7252) | Executable private memory reported by malfind | 0x7ff66cd00000–0x7ff66cd9ffff (640.0 KB) PAGE_EXECUTE_READWRITE tag=VadS; 0x7ff66ccf0000–0x7ff66ccfffff (64.0 KB) PAGE_E | Inconclusive - taskhostw 7252 RWX regions hold data; it started ngentask.exe when the .NET NGEN scheduled task was created: circumstantial evidence for benign, not proof |
| PT-003 | Medium | svchost.exe (3828) | Process present in psscan but not in pslist | svchost.exe (PID 3828) created 2018-06-21T06:51:27+00:00; Offset 0xd98df8dd2600 | Inconclusive - psscan/thrdscan only, no exit time: an unlinked process, or one caught while being created or terminated |
| PT-003 | Medium | taskhostw.exe (6120) | Process present in psscan but not in pslist | taskhostw.exe (PID 6120) created 2018-06-21T06:50:53+00:00; Offset 0xd98df95cf600 | Inconclusive - psscan/thrdscan only, no exit time: an unlinked process, or one caught while being created or terminated |
| CBK-001 | Low | - | 1 kernel callback value(s) that look like code bytes, not a routine address | GenericKernelCallback @ 0x894808708948 | Inconclusive - 0x894808708948: the bytes are instructions, not a pointer |
| DRV-001 | Low | - | 6 driver object(s) found by scan are not in the loaded-module list | WpdUpFltr.sys base=0xf80221580000 path=\SystemRoot\System32\drivers\WpdUpFltr.sys; USBSTOR.SYS base=0xf802214b0000 path= | Unreviewed |
| LDR-001 | Low | wininit.exe (568) | 2 image(s) mapped in wininit.exe but missing from every loader list | \Windows\System32\wtsapi32.dll (base 0x7ff9a2ca0000); \Windows\System32\winsta.dll (base 0x7ff9a5850000) | Unreviewed |
| LDR-001 | Low | SearchProtocol (1168) | 1 image(s) mapped in SearchProtocol but missing from every loader list | \Windows\System32\linkinfo.dll (base 0x7ff9a14e0000) | Unreviewed |
| LDR-001 | Low | SynTPEnh.exe (2192) | 42 image(s) mapped in SynTPEnh.exe but missing from every loader list | \Windows\System32\SynTPAPI.dll (base 0x59c50000); \Windows\System32\winmmbase.dll (base 0x7ff9973a0000) | Unreviewed |
| LDR-001 | Low | svchost.exe (2764) | 1 image(s) mapped in svchost.exe but missing from every loader list | \Windows\System32\devrtl.dll (base 0x7ff9a20b0000) | Unreviewed |
| LDR-001 | Low | svchost.exe (2988) | 25 image(s) mapped in svchost.exe but missing from every loader list | \Windows\System32\vpnike.dll (base 0x7ff97c800000); \Windows\System32\rascustom.dll (base 0x7ff97c790000) | Unreviewed |
| LDR-001 | Low | svchost.exe (3540) | 55 image(s) mapped in svchost.exe but missing from every loader list | \Windows\System32\wpncore.dll (base 0x7ff99cdc0000); \Windows\System32\Windows.Networking.Connectivity.dll (base 0x7ff99 | Unreviewed |
| LDR-001 | Low | OneDrive.exe (4428) | 5 image(s) mapped in OneDrive.exe but missing from every loader list | \Windows\SysWOW64\Windows.Networking.Connectivity.dll (base 0x6f050000); \Windows\SysWOW64\twinapi.appcore.dll (base 0x6 | Unreviewed |
| LDR-001 | Low | MOM.exe (4444) | 1 image(s) mapped in MOM.exe but missing from every loader list | \Windows\System32\user32.dll (base 0x7ff9a7130000) | Unreviewed |
| LDR-001 | Low | SearchUI.exe (5368) | 135 image(s) mapped in SearchUI.exe but missing from every loader list | \Windows\System32\msvcp110_win.dll (base 0x7ff9a18b0000); \Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\Bi | Unreviewed |
| LDR-001 | Low | svchost.exe (5520) | 1 image(s) mapped in svchost.exe but missing from every loader list | \Windows\System32\svchost.exe (base 0x7ff791320000) | Unreviewed |
| LDR-001 | Low | ngentask.exe (6492) | 1 image(s) mapped in ngentask.exe but missing from every loader list | \Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Management.dll (base 0x | Unreviewed |
| LDR-001 | Low | ShellExperienc (7004) | 2 image(s) mapped in ShellExperienc but missing from every loader list | \Windows\System32\mfcore.dll (base 0x7ff985d20000); \Windows\System32\devobj.dll (base 0x7ff9a49c0000) | Unreviewed |
| LDR-001 | Low | WmiPrvSE.exe (7080) | 18 image(s) mapped in WmiPrvSE.exe but missing from every loader list | \Windows\System32\wbem\cimwin32.dll (base 0x7ff9889c0000); \Windows\System32\wbem\wmiutils.dll (base 0x7ff99b850000) | Unreviewed |
| LDR-001 | Low | svchost.exe (7496) | 37 image(s) mapped in svchost.exe but missing from every loader list | \Windows\System32\accountaccessor.dll (base 0x7ff989f10000); \Windows\System32\cemapi.dll (base 0x7ff989e50000) | Unreviewed |
| LDR-001 | Low | explorer.exe (7688) | 56 image(s) mapped in explorer.exe but missing from every loader list | \Windows\System32\Windows.Media.dll (base 0x7ff9814f0000); \Windows\System32\DDORes.dll (base 0x7ff978590000) | Unreviewed |
| LDR-001 | Low | SkypeHost.exe (9788) | 40 image(s) mapped in SkypeHost.exe but missing from every loader list | \Windows\System32\Windows.Storage.ApplicationData.dll (base 0x7ff9942e0000); \Windows\System32\Windows.Networking.HostNa | Unreviewed |
| LDR-001 | Low | svchost.exe (9888) | 45 image(s) mapped in svchost.exe but missing from every loader list | \Windows\System32\devobj.dll (base 0x7ff9a49c0000); \Windows\System32\wcncsvc.dll (base 0x7ff996c10000) | Unreviewed |
| MAL-006 | Low | - | Driver object with an unreadable name: 5 IRP handler(s) point outside every modu | IRP_MJ_CLEANUP @ 0xd98df58a6540; IRP_MJ_POWER @ 0xd98df55d7260 | Inconclusive - driver object with no readable name (stale object), handlers in pool memory: nothing proven |
| MEM-001 | Low | CCC.exe (880) | Executable private memory reported by malfind | 0x2bb040f0000–0x2bb040fffff (64.0 KB) PAGE_EXECUTE_READWRITE tag=VadS | Unreviewed |
| MEM-001 | Low | ngentask.exe (1336) | Executable private memory reported by malfind | 0x21149e50000–0x21149e5ffff (64.0 KB) PAGE_EXECUTE_READWRITE tag=VadS; 0x7ff5ffc50000–0x7ff5ffc5ffff (64.0 KB) PAGE_EXEC | Unreviewed |
| MEM-001 | Low | MsMpEng.exe (2688) | Executable private memory reported by malfind | 0x1ef80550000–0x1ef8065cfff (1.1 MB) PAGE_EXECUTE_READWRITE tag=VadS; 0x1ef808a0000–0x1ef809acfff (1.1 MB) PAGE_EXECUTE_ | Unreviewed |
| MEM-001 | Low | MOM.exe (4444) | Executable private memory reported by malfind | 0x23ac6580000–0x23ac658ffff (64.0 KB) PAGE_EXECUTE_READWRITE tag=VadS | Unreviewed |
| MEM-001 | Low | SearchUI.exe (5368) | Executable private memory reported by malfind | 0x249e6a40000–0x249e6a5ffff (128.0 KB) PAGE_EXECUTE_READWRITE tag=VadS | Unreviewed |
| MEM-001 | Low | ngentask.exe (6492) | Executable private memory reported by malfind | 0x19e0000–0x19effff (64.0 KB) PAGE_EXECUTE_READWRITE tag=VadS | Unreviewed |
| UA-001 | Low | - | 4 program(s) started from Temp or Downloads (UserAssist) | C:\Users\passmark\Downloads\ProcessMonitor\Procmon.exe  (run count 1, last 2017-08-03T04:42:38+00:00); C:\Users\passmark | Unreviewed |
| VAD-001 | Low | svchost.exe (72) | 3 executable image(s) mapped but not in the module list of svchost.exe | \Windows\System32\devobj.dll; \Windows\System32\userenv.dll | Unreviewed |
| VAD-001 | Low | csrss.exe (468) | 1 executable image(s) mapped but not in the module list of csrss.exe | \Windows\Microsoft.NET\Framework64\v4.0.30319\mscoreei.dll | Unreviewed |
| VAD-001 | Low | wininit.exe (568) | 2 executable image(s) mapped but not in the module list of wininit.exe | \Windows\System32\wtsapi32.dll; \Windows\System32\winsta.dll | Unreviewed |
| VAD-001 | Low | CCC.exe (880) | 154 executable image(s) mapped but not in the module list of CCC.exe | \Program Files (x86)\ATI Technologies\ATI.ACE\Core-Static\CLI.Component.Runtime.dll; \Program Files (x86)\ATI Technologi | Unreviewed |
| VAD-001 | Low | mcbuilder.exe (1048) | 9 executable image(s) mapped but not in the module list of mcbuilder.exe | \Windows\System32\netutils.dll; \Windows\System32\wkscli.dll | Unreviewed |
| VAD-001 | Low | SearchProtocol (1168) | 6 executable image(s) mapped but not in the module list of SearchProtocol | \Windows\System32\edputil.dll; \Windows\System32\cldapi.dll | Unreviewed |
| VAD-001 | Low | SynTPEnh.exe (2192) | 45 executable image(s) mapped but not in the module list of SynTPEnh.exe | \Windows\System32\SynTPAPI.dll; \Windows\System32\winmmbase.dll | Unreviewed |
| VAD-001 | Low | svchost.exe (2748) | 1 executable image(s) mapped but not in the module list of svchost.exe | \Windows\System32\mintdh.dll | Unreviewed |
| VAD-001 | Low | svchost.exe (2764) | 1 executable image(s) mapped but not in the module list of svchost.exe | \Windows\System32\devrtl.dll | Unreviewed |
| VAD-001 | Low | svchost.exe (2988) | 42 executable image(s) mapped but not in the module list of svchost.exe | \Windows\assembly\NativeImages_v4.0.30319_64\System.Xaml\a0964a7cc2b3536bac4b487b94edcb55\System.Xaml.ni.dll; \Windows\a | Unreviewed |
| VAD-001 | Low | svchost.exe (3156) | 1 executable image(s) mapped but not in the module list of svchost.exe | \Windows\System32\clbcatq.dll | Unreviewed |
| VAD-001 | Low | svchost.exe (3540) | 55 executable image(s) mapped but not in the module list of svchost.exe | \Windows\System32\wpncore.dll; \Windows\System32\Windows.Networking.Connectivity.dll | Unreviewed |
| VAD-001 | Low | OneDrive.exe (4428) | 7 executable image(s) mapped but not in the module list of OneDrive.exe | \Windows\SysWOW64\Windows.Networking.Connectivity.dll; \Windows\SysWOW64\twinapi.appcore.dll | Unreviewed |
| VAD-001 | Low | MOM.exe (4444) | 67 executable image(s) mapped but not in the module list of MOM.exe | \Program Files (x86)\ATI Technologies\ATI.ACE\Core-Static\LOG.Foundation.Implementation.dll; \Program Files (x86)\ATI Te | Unreviewed |
| VAD-001 | Low | audiodg.exe (4596) | 1 executable image(s) mapped but not in the module list of audiodg.exe | \Windows\System32\iertutil.dll | Unreviewed |
| VAD-001 | Low | SearchUI.exe (5368) | 140 executable image(s) mapped but not in the module list of SearchUI.exe | \Windows\System32\msvcp110_win.dll; \Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\BingConfigurationClient. | Unreviewed |
| VAD-001 | Low | ngentask.exe (6492) | 1 executable image(s) mapped but not in the module list of ngentask.exe | \Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management\v4.0_4.0.0.0__b03f5f7f11d50a3a\System.Management.dll | Unreviewed |
| VAD-001 | Low | ShellExperienc (7004) | 5 executable image(s) mapped but not in the module list of ShellExperienc | \Windows\System32\Windows.Media.dll; \Windows\System32\mfcore.dll | Unreviewed |
| VAD-001 | Low | WmiPrvSE.exe (7080) | 22 executable image(s) mapped but not in the module list of WmiPrvSE.exe | \Windows\System32\wbem\cimwin32.dll; \Windows\System32\wbem\wmiutils.dll | Unreviewed |
| VAD-001 | Low | RuntimeBroker. (7220) | 1 executable image(s) mapped but not in the module list of RuntimeBroker. | \Windows\System32\thumbcache.dll | Unreviewed |
| VAD-001 | Low | svchost.exe (7496) | 42 executable image(s) mapped but not in the module list of svchost.exe | \Windows\System32\accountaccessor.dll; \Windows\System32\cemapi.dll | Unreviewed |
| VAD-001 | Low | explorer.exe (7688) | 62 executable image(s) mapped but not in the module list of explorer.exe | \Windows\assembly\NativeImages_v4.0.30319_64\mscorlib\ccb48f84a5cca36e9b0205b6a65ee54a\mscorlib.ni.dll; \Windows\System3 | Unreviewed |
| VAD-001 | Low | svchost.exe (7812) | 12 executable image(s) mapped but not in the module list of svchost.exe | \Windows\System32\xmllite.dll; \Windows\System32\samcli.dll | Unreviewed |
| VAD-001 | Low | SkypeHost.exe (9788) | 52 executable image(s) mapped but not in the module list of SkypeHost.exe | \Program Files\WindowsApps\Microsoft.VCLibs.140.00_14.0.25426.0_x64__8wekyb3d8bbwe\vccorlib140_app.dll; \Windows\System3 | Unreviewed |
| VAD-001 | Low | svchost.exe (9888) | 45 executable image(s) mapped but not in the module list of svchost.exe | \Windows\System32\devobj.dll; \Windows\System32\wcncsvc.dll | Unreviewed |
| VAD-001 | Low | remsh.exe (9932) | 62 executable image(s) mapped but not in the module list of remsh.exe | \Windows\System32\winhttp.dll; \Windows\System32\netapi32.dll | Unreviewed |

## Warnings of the analysis

* windows.vadyarascan was skipped: it needs a value for 'yara_rules_file' in Settings (for example the path of your YARA rule file).
