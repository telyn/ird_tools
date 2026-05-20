# ISO Rebuild from IRD + JB Folder

## Overview

Add `--build` mode to `ird_tools` to reconstruct a PS3 ISO from an IRD file and a JB-format folder of game files. The IRD provides file layout (sector positions), region boundaries (plain/encrypted), compressed ISO header/footer, and encryption keys. The folder provides the file data.

## Approach

Add `--build`/`-b` mode to the existing `ird_tools` executable. New source files `ird_rebuild.c`/`.h` contain the rebuild logic. Reuses existing IRD loading, GZ decompression, AES-CBC, and MD5 code.

## CLI

```
ird_tools -b <ird_file> <jb_folder> [-o <output.iso>]
```

- `-b` / `--build` — select build mode
- `<ird_file>` — path to .ird file
- `<jb_folder>` — path to JB-format folder tree
- `-o` / `--output` — output ISO path (default: `<ird_file>.iso`, replacing `.ird`)

Flags can appear anywhere before positional args (matching existing pattern).

## Files

| File | Status | Purpose |
|------|--------|---------|
| `ird_rebuild.h` | New | Declarations for rebuild functions |
| `ird_rebuild.c` | New | Rebuild pipeline implementation |
| `main.c` | Modified | Add `-b`/`--build` arg, wire to build handler |
| `Makefile` | Modified | Add `ird_rebuild.c` to SOURCES |

## Rebuild Pipeline

```
1. IRD_load(ird_path)                    — load & decompress IRD in-memory
2. GZ_decompress7(ird->Header) → temp    — decompress ISO header
3. IRD_GetFilesPath(temp_header, ird)    — resolve file paths & sizes
4. IRD_GetRegionBoundaries(temp_header)   — resolve region Start/End sectors
5. fopen(output.iso, "wb")               — open output
6. Write ISO header                      — read sectors 0..first_file_sector from temp header → write to ISO
7. For each FileHashes[i]:
   a. Determine region (plain if region index even, encrypted if odd)
   b. Resolve path: <jb_folder>/<FilePath>
   c. Open source file, fstat size
   d. MD5 compare against FileHashes[i].FileHash → abort on mismatch
   e. fseek ISO to Sector * 0x800
   f. If plain: write file data as-is, pad to sector boundary
   g. If encrypted: for each 0x800 block → AES128-CBC encrypt → write
8. Write ISO footer                     — decompress ird->Footer, write after last file
9. Pad ISO to disc size                 — (last region End + 1) * 0x800
10. Verify region hashes                — MD5 each region, compare RegionHashes[i].RegionHash
11. Cleanup temp files
```

## Encryption

Encrypted regions use AES128-CBC:

- Key: `ird->Data1` decrypted via `dec_d1()` (uses existing hardcoded key/IV from main.c)
- IV per sector: 8 zero bytes + sector LBA as 8-byte big-endian
- Each 0x800-byte block encrypted independently (IV reset per block)

Sector-to-byte mapping: `byte_offset = sector_LBA * 0x800`

## Error Handling

| Condition | Behaviour |
|-----------|-----------|
| IRD load fails | Print error, exit 1 |
| Header/footer decompress fails | Print error, exit 1, delete partial ISO |
| File missing in JB folder | Print file path, exit 1, delete partial ISO |
| File MD5 mismatch | Print file + expected/actual hashes, exit 1, delete partial ISO |
| Region hash mismatch | Print region index + diff, exit 1, delete partial ISO |
| fseek/fwrite fail | Print error, exit 1, delete partial ISO |

## Verification

After full ISO write, verify every region's MD5 against `ird->RegionHashes[i].RegionHash`. This catches sector-level corruption (misaligned writes, wrong padding, bad encryption).
