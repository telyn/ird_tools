# IRD Rebuild Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--build` mode to `ird_tools` to reconstruct a PS3 ISO from an IRD file and JB-format folder.

**Architecture:** Single new C module (`ird_rebuild.c`/`.h`) with one entry point `IRD_rebuild()`. Integrated into existing `ird_tools` binary via new `-b` flag in `main.c`. Reuses existing `IRD_load`, `GZ_decompress7`, `IRD_GetFilesPath`, `IRD_GetRegionBoundaries`, `md5_file`, `aes_cbc_encrypt`.

**Tech Stack:** C99, gcc, zlib, AES-128-CBC

---

### Task 1: Create `ird_rebuild.h`

**Files:**
- Create: `ird_rebuild.h`

- [ ] **Write the header**

```c
#ifndef _IRD_REBUILD_H
#define _IRD_REBUILD_H

#include "ird_build.h"

u8 IRD_rebuild(char *IRD_PATH, char *FOLDER_PATH, char *ISO_OUTPUT, u8 no_verify);

#endif
```

- [ ] **Commit**

```bash
git add ird_rebuild.h && git commit -m "feat: add ird_rebuild.h header"
```

---

### Task 2: Create `ird_rebuild.c` — struct includes, forward decls, helper

**Files:**
- Create: `ird_rebuild.c`

- [ ] **Write includes, forward declarations, and helper constants**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <zlib.h>

#include "ird_rebuild.h"
#include "ird_iso.h"
#include "md5.h"

#if defined (__MSVCRT__)
#define stat _stati64
#endif

#define SECTOR_SIZE 0x800

// forward decls from main.c
void aes_cbc_encrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len);
void dec_d1(unsigned char* d1);

static int region_for_sector(ird_t *ird, u64 sector)
{
    for (int i = 0; i < ird->RegionHashesNumber; i++) {
        if (sector >= (u64)ird->RegionHashes[i].Start && sector <= (u64)ird->RegionHashes[i].End) {
            return i;
        }
    }
    return -1;
}

static int is_encrypted_region(ird_t *ird, u64 sector)
{
    int r = region_for_sector(ird, sector);
    return (r >= 0) && (r % 2 == 1);
}
```

- [ ] **Commit**

```bash
git add ird_rebuild.c && git commit -m "feat: ird_rebuild.c includes and helpers"
```

---

### Task 3: Implement `IRD_rebuild` — load, decompress header, get file paths and regions

- [ ] **Write the first part of IRD_rebuild: load, decompress header, get file paths and boundaries**

```c
u8 IRD_rebuild(char *IRD_PATH, char *FOLDER_PATH, char *ISO_OUTPUT, u8 no_verify)
{
    int ret = FAILED;
    int i;
    ird_t *ird = NULL;
    FILE *f_iso = NULL;
    FILE *f_header = NULL;
    FILE *f_src = NULL;
    char header_path[512];
    char footer_path[512];
    char file_path[1024];

    // 1. Load IRD
    ird = IRD_load(IRD_PATH);
    if (ird == NULL) {
        printf("Error: failed to load IRD %s\n", IRD_PATH);
        goto error;
    }

    // 2. Decompress header
    snprintf(header_path, sizeof(header_path), "%s.header.rebuild", ird->GameId);
    unlink(header_path);
    if (GZ_decompress7((char *)ird->Header, ird->HeaderLength, header_path) != Z_OK) {
        printf("Error: failed to decompress header from IRD\n");
        goto error;
    }

    // 3. Get file paths from ISO header
    print_verbose("IRD_GetFilesPath\n");
    IRD_GetFilesPath(header_path, ird);

    // 4. Get region boundaries
    print_verbose("IRD_GetRegionBoundaries\n");
    if (IRD_GetRegionBoundaries(header_path, ird) == FAILED) {
        printf("Error: failed to get region boundaries\n");
        goto error;
    }
```

The rest of the function will be written in the next task.

- [ ] **Commit**

```bash
git add ird_rebuild.c && git commit -m "feat: IRD_rebuild load and init"
```

---

### Task 4: Implement rebuild — write header, iterate files, write footer, pad ISO

- [ ] **Write the file-writing loop: header, per-file write with encryption, footer, padding**

```c
    // 5. Open output ISO
    f_iso = fopen(ISO_OUTPUT, "wb");
    if (f_iso == NULL) {
        printf("Error: failed to create output ISO %s\n", ISO_OUTPUT);
        goto error;
    }

    // 6. Write header (decompressed, covers sectors 0 to first file's sector)
    {
        f_header = fopen(header_path, "rb");
        if (f_header == NULL) {
            printf("Error: failed to open decompressed header\n");
            goto error;
        }
        u8 buf[SECTOR_SIZE];
        size_t n;
        while ((n = fread(buf, 1, SECTOR_SIZE, f_header)) > 0) {
            if (fwrite(buf, 1, n, f_iso) != n) {
                printf("Error: failed to write header to ISO\n");
                goto error;
            }
        }
        FCLOSE(f_header);
    }

    // 7. For each file in IRD
    // Decrypt Data1 once for per-sector encryption
    // (must work on a copy since dec_d1 modifies in-place)
    u8 disc_key[0x10];
    memcpy(disc_key, ird->Data1, 0x10);
    dec_d1(disc_key);

    for (i = 0; i < (int)ird->FileHashesNumber; i++) {
        u64 sector = ird->FileHashes[i].Sector;
        u64 file_size = ird->FileHashes[i].FileSize;
        int encrypted = is_encrypted_region(ird, sector);

        // 7a. Resolve file path in JB folder
        // FilePath starts with '/' (e.g. "/PS3_GAME/USRDIR/file.dat")
        // so concatenate FOLDER_PATH + FilePath
        snprintf(file_path, sizeof(file_path), "%s%s", FOLDER_PATH, ird->FileHashes[i].FilePath);

        // 7b. Open source file
        f_src = fopen(file_path, "rb");
        if (f_src == NULL) {
            printf("Error: missing file %s\n", file_path);
            goto error;
        }

        // 7c. Verify MD5 if requested
        if (!no_verify) {
            u8 actual_hash[0x10];
            md5_file(file_path, actual_hash);
            if (memcmp(actual_hash, ird->FileHashes[i].FileHash, 0x10) != 0) {
                printf("Error: MD5 mismatch for %s\n", file_path);
                int j;
                printf("  Expected: ");
                for (j = 0; j < 0x10; j++) printf("%02X", ird->FileHashes[i].FileHash[j]);
                printf("\n  Actual:   ");
                for (j = 0; j < 0x10; j++) printf("%02X", actual_hash[j]);
                printf("\n");
                goto error;
            }
        }

        // 7d. Seek to sector position
        u64 iso_offset = sector * SECTOR_SIZE;
        if (fseeko(f_iso, iso_offset, SEEK_SET) != 0) {
            printf("Error: failed to seek to sector %llu in output ISO\n", (unsigned long long)sector);
            goto error;
        }

        // 7e. Write file data in sector blocks
        u64 remaining = file_size;
        u64 current_sector = sector;
        while (remaining > 0) {
            u64 to_read = (remaining < SECTOR_SIZE) ? remaining : SECTOR_SIZE;
            u8 in[SECTOR_SIZE] = {0};
            u8 out[SECTOR_SIZE];

            if (fread(in, 1, to_read, f_src) != to_read) {
                printf("Error: failed to read %llu bytes from %s\n", (unsigned long long)to_read, file_path);
                goto error;
            }

            if (encrypted) {
                u8 iv[0x10] = {0};
                // IV = 8 zero bytes + sector LBA as 8-byte big-endian
                u64 be_sector = ENDIAN_SWAP_64(current_sector);
                memcpy(iv + 8, &be_sector, 8);
                aes_cbc_encrypt(disc_key, iv, in, out, SECTOR_SIZE);
                if (fwrite(out, 1, SECTOR_SIZE, f_iso) != SECTOR_SIZE) {
                    printf("Error: failed to write encrypted sector to ISO\n");
                    goto error;
                }
            } else {
                if (fwrite(in, 1, to_read, f_iso) != to_read) {
                    printf("Error: failed to write sector to ISO\n");
                    goto error;
                }
                // Pad to sector boundary
                if (to_read < SECTOR_SIZE) {
                    u8 zero[SECTOR_SIZE];
                    memset(zero, 0, SECTOR_SIZE - to_read);
                    if (fwrite(zero, 1, SECTOR_SIZE - to_read, f_iso) != SECTOR_SIZE - to_read) {
                        printf("Error: failed to pad sector in ISO\n");
                        goto error;
                    }
                }
            }

            remaining -= to_read;
            current_sector++;
        }

        FCLOSE(f_src);
        print_verbose("Wrote %s at sector %llu\n", ird->FileHashes[i].FilePath, (unsigned long long)sector);
    }

    // 8. Write footer
    {
        snprintf(footer_path, sizeof(footer_path), "%s.footer.rebuild", ird->GameId);
        unlink(footer_path);
        if (GZ_decompress7((char *)ird->Footer, ird->FooterLength, footer_path) != Z_OK) {
            printf("Error: failed to decompress footer from IRD\n");
            goto error;
        }
        FILE *f_ftr = fopen(footer_path, "rb");
        if (f_ftr == NULL) {
            printf("Error: failed to open decompressed footer\n");
            goto error;
        }
        u8 buf[SECTOR_SIZE];
        size_t n;
        while ((n = fread(buf, 1, SECTOR_SIZE, f_ftr)) > 0) {
            if (fwrite(buf, 1, n, f_iso) != n) {
                printf("Error: failed to write footer to ISO\n");
                FCLOSE(f_ftr);
                goto error;
            }
        }
        FCLOSE(f_ftr);
        unlink(footer_path);
    }

    // 9. Pad to full disc size
    {
        u64 disc_sectors = (u64)ird->RegionHashes[ird->RegionHashesNumber - 1].End + 1;
        u64 disc_size = disc_sectors * SECTOR_SIZE;
        u64 current_pos = ftello(f_iso);
        if (current_pos < disc_size) {
            u8 zero[SECTOR_SIZE] = {0};
            while (current_pos < disc_size) {
                u64 to_write = disc_size - current_pos;
                if (to_write > SECTOR_SIZE) to_write = SECTOR_SIZE;
                if (fwrite(zero, 1, to_write, f_iso) != to_write) {
                    printf("Error: failed to pad ISO to full disc size\n");
                    goto error;
                }
                current_pos += to_write;
            }
        }
    }
```

- [ ] **Commit**

```bash
git add ird_rebuild.c && git commit -m "feat: IRD_rebuild file writing loop"
```

---

### Task 5: Implement rebuild — region hash verification, cleanup, return

- [ ] **Write region hash verification, error cleanup, and return**

```c
    // 10. Verify region hashes
    if (!no_verify) {
        u8 region_md5[0x10];
        int r;
        for (r = 0; r < (int)ird->RegionHashesNumber; r++) {
            u64 start_byte = (u64)ird->RegionHashes[r].Start * SECTOR_SIZE;
            u64 end_byte = ((u64)ird->RegionHashes[r].End + 1) * SECTOR_SIZE;
            u64 region_size = end_byte - start_byte;

            // Compute MD5 of region in the output ISO
            md5_context ctx;
            md5_starts(&ctx);

            if (fseeko(f_iso, start_byte, SEEK_SET) != 0) {
                printf("Error: failed to seek for region hash verification\n");
                goto error;
            }

            u64 remaining = region_size;
            u8 buf[SECTOR_SIZE];
            while (remaining > 0) {
                u64 to_read = (remaining < SECTOR_SIZE) ? remaining : SECTOR_SIZE;
                if (fread(buf, 1, to_read, f_iso) != to_read) {
                    printf("Error: failed to read ISO for region hash\n");
                    goto error;
                }
                md5_update(&ctx, buf, to_read);
                remaining -= to_read;
            }

            md5_finish(&ctx, region_md5);

            if (memcmp(region_md5, ird->RegionHashes[r].RegionHash, 0x10) != 0) {
                printf("Error: region %d hash mismatch\n", r + 1);
                int j;
                printf("  Expected: ");
                for (j = 0; j < 0x10; j++) printf("%02X", ird->RegionHashes[r].RegionHash[j]);
                printf("\n  Actual:   ");
                for (j = 0; j < 0x10; j++) printf("%02X", region_md5[j]);
                printf("\n");
                goto error;
            }
            print_verbose("Region %d hash OK\n", r + 1);
        }
    }

    printf("ISO rebuilt successfully: %s\n", ISO_OUTPUT);
    ret = SUCCESS;
    goto cleanup;

error:
    if (f_iso) {
        FCLOSE(f_iso);
        remove(ISO_OUTPUT);
    }
    if (ret == FAILED) {
        printf("Rebuild failed.\n");
    }

cleanup:
    FCLOSE(f_iso);
    FCLOSE(f_header);
    FCLOSE(f_src);
    unlink(header_path);
    unlink(footer_path);
    FREE_IRD(ird);
    return ret;
}
```

- [ ] **Commit**

```bash
git add ird_rebuild.c && git commit -m "feat: IRD_rebuild region verify and cleanup"
```

---

### Task 6: Modify `main.c` — add `-b`/`--build` and `--no-verify` flags, wire to IRD_rebuild

**Files:**
- Modify: `main.c`

- [ ] **Add global variables and task constant**

```c
// Add after the existing globals:
u8 no_verify = 0;
char *output_path = NULL;

// Add to the task enum section:
#define do_build 3
```

- [ ] **Add `-b`/`--build`, `-o`/`--output`, `--no-verify` flag parsing**

Insert in the flag parsing loop in `main()` (after the `-r`/`--rename` block):

```c
        } else
        if( !strcmp(argv[i], "-b") || !strcmp(argv[i], "--build") ) {
            task = do_build;
            a++;
        } else
        if( !strcmp(argv[i], "-o") || !strcmp(argv[i], "--output") ) {
            if (i + 1 < argc) {
                output_path = argv[i + 1];
                i++;
                a += 2;
            }
        } else
        if( !strcmp(argv[i], "--no-verify") ) {
            no_verify = 1;
            a++;
        }
```

- [ ] **Add build handler after the existing `do_task` loop**

Insert after the existing `for(i=a; i<argc; i++)` loop at the end of `main()`:

```c
    if (task == do_build) {
        if (argc - a < 2) {
            printf("Error: --build requires <ird_file> <jb_folder>\n");
            return 1;
        }
        char *ird_path = argv[a];
        char *folder = argv[a + 1];

        char default_output[512];
        if (output_path == NULL) {
            snprintf(default_output, sizeof(default_output), "%s", ird_path);
            int len = strlen(default_output);
            if (len > 4 && strcasecmp(&default_output[len-4], ".ird") == 0) {
                default_output[len-4] = 0;
            }
            strcat(default_output, ".iso");
            output_path = default_output;
        }

        return IRD_rebuild(ird_path, folder, output_path, no_verify) ? 0 : 1;
    }
```

- [ ] **Add include for ird_rebuild.h**

Add near the top with other includes:

```c
#include "ird_rebuild.h"
```

- [ ] **Commit**

```bash
git add main.c && git commit -m "feat: add --build, --no-verify, -o flags to main.c"
```

---

### Task 7: Update Makefile

**Files:**
- Modify: `Makefile`

- [ ] **Add `ird_rebuild.c` to SOURCES**

```makefile
SOURCES= main.c ird_gz.c ird_build.c ird_iso.c md5.c aes.c ird_rebuild.c
```

- [ ] **Commit**

```bash
git add Makefile && git commit -m "build: add ird_rebuild.c to Makefile"
```

---

### Task 8: Build and fix compilation errors

- [ ] **Build and verify**

Run: `make`
Expected: clean compile,produces `ird_tools` executable.

Fix any compilation errors:
- Need `fseeko`/`ftello` — ensure `_FILE_OFFSET_BITS=64` or use `fseek`/`ftell` with careful casting
- The existing code uses `fseek`/`ftell` not `fseeko`/`ftello`. This is a C99 codebase. On some platforms `fseeko` needs `_POSIX_C_SOURCE` or similar. Safer to use `fseek`/`ftell` and cast carefully to 64-bit.

If `fseeko`/`ftello` cause issues, replace with `fseek`/`ftell`:

```c
// Instead of fseeko/ftello, use fseek/ftell with u64 casting
if (fseek(f_iso, (long)iso_offset, SEEK_SET) != 0) {
```

Also need to verify that `ftell` returns a proper 64-bit value (the existing code relies on `_stati64` on MSVC, and on Unix `ftell` is 64-bit already).

- [ ] **Commit after fix**

```bash
git add ird_rebuild.c main.c && git commit -m "fix: compilation fixes"
```

---

### Task 9: Self-review

- [ ] **Check spec coverage against plan**

Review `docs/superpowers/specs/2026-05-20-ird-rebuild-design.md` and verify each requirement maps to a task:
- CLI: -b flag → Task 6
- --no-verify flag → Task 6
- -o flag → Task 6
- default .iso output → Task 6
- Rebuild pipeline → Tasks 3-5
- Encryption → Task 4
- Region hash verification → Task 5
- Error handling (cleanup on fail) → Task 5

- [ ] **Check placeholder scan**
Verify no TBD, TODO, or incomplete code in the plan.

- [ ] **Check type/function name consistency**
Verify: `IRD_rebuild` signature in .h matches .c. Helper names match. Variable names consistent.

- [ ] **Remove line-length overfull files and commit if fixes made**

```bash
git add -A && git commit -m "docs: add rebuild implementation plan"
```
