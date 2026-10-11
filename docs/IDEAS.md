# Ideas for later (nothing here is implemented yet)

> Status of each idea (some are now implemented or partly implemented): see `ROADMAP.md`. The list below is unchanged.

**Triage workflow**
- *Reviewed / false positive* button on a finding, stored in the investigation, hidden afterwards and optionally exported as a baseline.
- Notes and bookmarks per process / event, shown in a "case notes" view and in reports.
- Known-good baseline: analyse a clean dump once and suppress anything that also appears in it.

**Evidence**
- More plugins (opt-in): `windows.svcscan`, `windows.filescan`, registry run keys / `userassist` (persistence), `windows.driverscan`, `modules` vs `modscan` (hidden drivers), `ssdt`, `callbacks`, `vadinfo`, `envars`, `mutantscan`, `windows.vadyarascan` with your own YARA rules.
- Inline decoder for `-EncodedCommand` payloads and a hex/disassembly view for malfind regions.
- Hash dumped files and export the hash list (for offline lookups).
- ATT&CK technique tags on every rule.
- User-supplied IOC lists (IPs, domains, hashes) as an optional extra rule family, kept separate from the built-in behavioural rules.

**Views**
- Process-lifetime lanes (Gantt) next to the timeline.
- Light theme, adjustable font size, saved window layout.

**Engineering**
- Linux image support through the same provider interface.
