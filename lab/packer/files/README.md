# Offline installers for the template

Packer copies this folder into the VM. Download these on any computer and put them here
(they are not in Git: see `lab/.gitignore`).

| File | Needed for | Where to get it |
|---|---|---|
| `7z<version>-x64.msi` (for example `7z2408-x64.msi`) | all | 7-zip.org, "64-bit Windows x64" **.msi** download |
| `ndp48-x86-x64-allos-enu.exe` | Windows 7 only | Microsoft ".NET Framework 4.8 offline installer" |

`provision.ps1` looks for `7z*-x64.msi` and `ndp48*.exe`.

Windows 7 also needs an **older VMware Tools ISO** (10.3.x or 11.x; current Tools need Windows 8.1+).
Set its path as `tools_iso` in `win7.pkrvars.hcl`; it is not put in this folder.
