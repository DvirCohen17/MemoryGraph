# Malware memory-dump lab

Makes practice memory images of Windows machines infected with real malware, each with an answer key
for MemoryGraph. Everything runs on your own Windows PC in VMware Workstation; the dumps are stored
on GitHub so they do not fill your disk.

```
 Packer            Terraform               labctl.py (per sample)                          GitHub (private repo)
 ISO ──► clean ──► linked clone ──► revert "ready" ─► copy zip in ─► run ─► wait ─►       release <id>: dump (7z parts)
 template          + "ready"        (VMware Tools,     (unpacked     3 min   record       git: README / expected.json
 win7/10/11        snapshot          no network)        in the VM)          processes ─►
                                                                            suspend = dump ─► revert (infection gone)
```

> **This runs live malware.** Read the safety section before the first run.

## What you get per sample

| File | What it is |
|---|---|
| `memory.vmem` + `memory.vmss` | The VM's whole RAM, written by VMware from outside the VM (no capture tool inside it, nothing changing while it is written). MemoryGraph and Volatility open `.vmem` directly; keep the `.vmss` next to it. |
| `README.md` | What the malware is, the sample's hashes, how and on which Windows build it ran, what MemoryGraph should find. |
| `expected.json` | The answer key in MemoryGraph's `tools/realworld` format: the sample's processes, parents and connections, recorded inside the VM seconds before the capture. `run_report --expected` scores MemoryGraph with it. |
| `groundtruth.json`, `detonation.json`, `metadata.json` | Everything that was recorded: full process list, netstat, launch details, timings, memory hash. |

Also one **baseline** per guest: the same VM with no malware. Use it in MemoryGraph's *Compare* view and to see
which findings a clean machine already gets.

## Storage: dumps on GitHub, only VMs on your disk

- A **separate private repository** (for example `memorygraph-dumps`) holds the small text files in Git, so you can
  browse every package on GitHub (`CATALOG.md`).
- The dump itself goes into a **GitHub release** with the package's name: a 7-Zip archive with AES-256 encryption,
  password `infected`, file names hidden, split into parts of 1.9 GB. Release files must be under 2 GiB each;
  the total size and the download bandwidth of releases are not limited. Never commit dumps to Git itself
  (100 MB per-file limit, and every clone would download them all).
- After a successful upload the local copy is deleted (`keep_local = false`).
- `python labctl.py get <id>` downloads and unpacks one dump when you want to analyse it.

What still needs local disk: the VMs. Roughly 25–35 GB per template, 5–10 GB per victim (linked clone plus its
"ready" memory snapshot), and about 2.5× the guest RAM while one package is packed. **About 130 GB free** for all
three Windows versions, or start with `guests = ["win10"]`.

## Safety

- The victims are only on **VMnet9**: host-only, *no* host virtual adapter, *no* DHCP, *no* NAT. Your PC is not on that
  network, and nothing on it reaches the internet. The fake-internet VM (INetSim) answers instead.
- Shared folders, clipboard, drag-and-drop and USB are off. Files go in and out only through VMware Tools guest
  operations started from your side.
- `labctl.py` reads each victim's `.vmx` before every run and **refuses to start** if a network adapter is NAT/bridged,
  on another VMnet, or a shared folder / clipboard is enabled.
- Samples stay in MalwareBazaar's password-protected zip on your PC and are only unpacked inside the VM.
- After every capture the VM is powered off and reverted to the clean "ready" snapshot.
- Your PC's antivirus may still flag a `.vmem` (it holds the malware's code in clear). Add an exclusion for the lab
  folder (for example `D:\malware-lab`) only, not more.
- Keep the dumps repository **private**. GitHub allows security-research content, and asks for a clear README disclaimer
  (`dumps-repo-template/README.md` and `SECURITY.md`).
- Never point this at a VM you use for anything else, and never change VMnet9 to NAT or bridged.

## One-time setup

1. **Install** on your PC: VMware Workstation 17, Packer, Terraform 1.4+, Python 3.11+, 7-Zip, GitHub CLI (`gh`).
2. **Lab network.** Workstation: *Edit > Virtual Network Editor > Change Settings > Add Network* → `VMnet9`,
   *Host-only*, **untick** "Connect a host virtual adapter to this network", **untick** "Use local DHCP service",
   subnet `10.66.0.0` / `255.255.255.0`.
3. **ISOs and installers.** Your Windows ISOs (set `iso_url` in `packer/win*.pkrvars.hcl`). Put the 7-Zip x64 MSI
   (and for Windows 7 the .NET 4.8 offline installer) in `packer/files/`; Windows 7 also needs an older VMware Tools
   ISO (see `packer/files/README.md`).
4. **Templates** (about 30–60 min each, from `lab/packer`):
   ```
   packer init .
   packer build -var-file=win10.pkrvars.hcl .
   packer build -var-file=win11.pkrvars.hcl .
   packer build -var-file=win7.pkrvars.hcl .
   ```
   On Windows 10/11 the build **pauses**: switch off *Tamper Protection* in the VM's Windows Security (it cannot be
   scripted), then press Enter. The account is `analyst` / `Lab!Passw0rd` (change it in the answer files, the Packer
   variables and `lab.toml` together).
5. **Fake internet**: see `gateway/README.md` (REMnux or Ubuntu + INetSim at `10.66.0.1`).
6. **Victim VMs** (from `lab/terraform`): copy `terraform.tfvars.example` to `terraform.tfvars`, then
   ```
   terraform init
   terraform apply
   ```
   Each victim is a linked clone, booted once on VMnet9, with the snapshot `ready` taken after logon.
   `terraform destroy` removes them; rebuild them any time.
7. **Dumps repository**:
   ```
   gh auth login
   gh repo create memorygraph-dumps --private --clone
   ```
   Copy `dumps-repo-template/README.md` and `SECURITY.md` into it, commit, push.
8. **MalwareBazaar Auth-Key** (free): log in at https://auth.abuse.ch/, create an Auth-Key, then
   `setx MALWAREBAZAAR_AUTH_KEY "<your key>"` (new terminal afterwards).
9. **Orchestrator** (from `lab/orchestrator`): copy `lab.toml.example` to `lab.toml`, set the paths
   (`terraform output victims` prints the VM paths), then:
   ```
   python labctl.py check
   ```

## Making dumps

```
python labctl.py probe                         # samples per family on MalwareBazaar (fix signature names in families.toml)
python labctl.py fetch                         # 1 sample per family (bazaar.per_family) into the cache
python labctl.py baseline                      # one clean dump per guest
python labctl.py run --guest win10 --limit 1   # try one first
python labctl.py run                           # every cached sample on every guest its family lists
python labctl.py get win10-agenttesla-3f9a1c2e-20261112-1530 --dest D:\dumps
```

`run` options: `--family X` (repeatable), `--guest win10`, `--seconds 300` (longer run before the capture),
`--no-upload` (keep the package locally), `--again` (repeat samples already captured on that guest).
If an upload fails, the package stays in `work_dir`: `python labctl.py publish <folder>` retries it.

The families and what to look for are in `orchestrator/families.toml` (AgentTesla, AsyncRAT, Remcos, RedLine,
Formbook, Quasar, Lumma, XWorm, njRAT, Snake Keylogger, DCRat, NanoCore, Emotet, QakBot, Dridex). Add or remove freely.

## Using a dump with MemoryGraph

1. `python labctl.py get <id> --dest D:\dumps`
2. MemoryGraph: *Run analysis* on `D:\dumps\<id>\memory.vmem`.
3. Score it: `tools\realworld\run_report.bat --dump D:\dumps\<id>\memory.vmem --expected D:\dumps\<id>\expected.json`
4. After you have reviewed MemoryGraph's findings, add your verdicts to `findings_review` in the package's
   `expected.json` in the dumps repository: the answer key gets better with every review.

## Things to know

- **Not every sample does something.** Some check for virtual machines and quit, some need their (long dead) server,
  some need a specific Windows version or language. The README of each package says whether the sample's process
  was still running at capture time. `--seconds 600` helps slow starters.
- **The ground truth is taken from inside the VM** (`collect.ps1`, a few seconds before the capture), so it is
  independent of Volatility. The collector's own `powershell.exe` and `WmiPrvSE.exe` are in the dump; they are
  excluded from the answer key.
- **Clock:** the guests run in UTC.
- **Windows 7**: current samples often need .NET 4.x (install the offline .NET 4.8) and many modern families no longer
  run there; `families.toml` only lists Windows 7 for families that do.
- **DLL samples** run with `rundll32 <file>,<export>` (`dll_export` per family). The right export is not always known.
- This lab has been checked with tests of the orchestrator (`python -m unittest discover -s tests` in `orchestrator/`),
  but the Packer, Terraform and VMware steps can only be tried on a PC with VMware Workstation. Expect to adjust
  details (ISO edition names, VMware Tools versions) on the first build.

## Files

```
lab/
  packer/       windows.pkr.hcl, win7/win10/win11 variables, answer/<os>/autounattend.xml, scripts/ (guest setup)
  guest/        scripts copied into every VM: detonate.ps1, collect.ps1, set-network.ps1, lab-json.ps1
  terraform/    main.tf (linked clones + "ready" snapshot through vmrun), scripts/victim.ps1
  gateway/      fake-internet VM (INetSim)
  orchestrator/ labctl.py, mglab/ (MalwareBazaar, vmrun, packaging, GitHub), families.toml, lab.toml.example, tests/
  dumps-repo-template/  README.md and SECURITY.md for the dumps repository
```
