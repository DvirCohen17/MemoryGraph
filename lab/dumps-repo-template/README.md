# MemoryGraph memory dumps

> **This repository contains live malware.** Every release is a memory image of a lab VM infected with a
> real malware sample from [MalwareBazaar](https://bazaar.abuse.ch/), for memory-forensics practice and for
> testing [MemoryGraph](https://github.com/DvirCohen17/memorygraph). The archives are 7-Zip, AES-256 encrypted
> with the password `infected`. Open them only inside an isolated analysis environment. Nothing here is meant
> to be run, and it is not attack infrastructure.

- `CATALOG.md`: every dump, its family, guest and size.
- `packages/<guest>/<id>/README.md`: what the malware is, how it was run and what MemoryGraph should find.
- `packages/<guest>/<id>/expected.json`: the answer key (MemoryGraph `tools/realworld` format).
- Release `<id>`: `<id>.7z.001`, `.002` ... (the dump itself, split under GitHub's 2 GiB file limit).

```
gh release download <id> --repo <owner>/<this repo> --dir <id>
7z x <id>\<id>.7z.001 -pinfected -o<id>
```

Report problems or abuse: see `SECURITY.md`.
