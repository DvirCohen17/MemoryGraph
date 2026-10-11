Volatility 2 (optional)
=======================

MemoryGraph uses Volatility 2 for ONE thing: the network connections of Windows XP / Windows Server 2003 images, which
Volatility 3 cannot read (its network plugins start at Windows Vista). It is also the fallback on Vista / 7 when Volatility 3
cannot load the tcpip symbols without internet (Volatility 2 has its profiles built in).

Put ONE of these here and MemoryGraph finds it by itself (or set the path in Settings -> Volatility 2):

  * the standalone Windows build, e.g.  volatility_2.6_win64_standalone.exe      (no Python needed)
  * the source folder from https://github.com/volatilityfoundation/volatility  (contains vol.py)
    -> this needs Python 2.7 ("py -2" or python2); set its path in Settings if it is not found

INCLUDED HERE: volatility_2.6_win64_standalone.exe (Volatility Foundation, version 2.6, Windows x64, no Python needed), tested on 2026-10-08 on a real Windows XP SP3
image (sockets read in 11 s, merged into the connection list). It is found automatically. Its Windows 10 profiles stop at build 14393: on a newer Windows 10 it runs but its
process IDs are wrong, so MemoryGraph does not use it there.

Volatility 2 is GPL-2.0 licensed (the standalone exe is a separate program under that licence). MemoryGraph runs it as a separate program and never
imports its code. It never connects to the internet: the profile (WinXPSP3x86, Win7SP1x64, ...) is derived from the
image itself, the same way Volatility 3 already identified it.
