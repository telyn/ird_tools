#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ird_rebuild.h"
#include "ird_iso.h"
#include "md5.h"

#include <sys/stat.h>

#if defined (__MSVCRT__)
#define stat _stati64
#endif

extern void aes_cbc_encrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len);
extern void dec_d1(unsigned char* d1);

#define SECTOR_SIZE 0x800
#define VERIFY_BUF_SIZE 0x100000

u8 IRD_rebuild(char *IRD_PATH, char *FOLDER_PATH, char *ISO_OUTPUT, u8 no_verify)
{
	int ret = FAILED;
	int i, j;
	ird_t *ird = NULL;
	FILE *iso = NULL;
	FILE *src = NULL;
	FILE *temp = NULL;
	u8 *buf = NULL;
	u8 *sector_buf = NULL;
	u8 *vbuf = NULL;
	u8 dec_key[0x10];
	char header_path[512];
	char footer_path[512];
	char file_path[1024];
	char base[512];
	u8 current_region;
	u8 encrypted;
	u8 actual_hash[0x10];
	u64 sector_lba;
	u64 file_size;
	u64 write_size;
	long footer_size;
	struct stat st;

	strcpy(base, IRD_PATH);
	{
		int l = strlen(base);
		if (l > 4 && base[l-4] == '.') base[l-4] = 0;
	}
	sprintf(header_path, "%s.header.bin", base);
	sprintf(footer_path, "%s.footer.bin", base);

	ird = IRD_load(IRD_PATH);
	if (ird == NULL) {
		printf("Error : IRD_rebuild failed to load IRD\n");
		goto error;
	}

	if (GZ_decompress7((char *)ird->Header, ird->HeaderLength, header_path) != Z_OK) {
		printf("Error : IRD_rebuild failed to decompress header\n");
		goto error;
	}

	if (IRD_GetFilesPath(header_path, ird) == FAILED) {
		printf("Error : IRD_rebuild failed to get file paths\n");
		goto error;
	}

	if (IRD_GetRegionBoundaries(header_path, ird) == FAILED) {
		printf("Error : IRD_rebuild failed to get region boundaries\n");
		goto error;
	}

	iso = fopen(ISO_OUTPUT, "wb");
	if (iso == NULL) {
		printf("Error : IRD_rebuild failed to create output ISO\n");
		goto error;
	}

	temp = fopen(header_path, "rb");
	if (temp == NULL) {
		printf("Error : IRD_rebuild failed to open header file\n");
		goto error;
	}
	stat(header_path, &st);
	buf = (u8 *)malloc(st.st_size);
	if (buf == NULL) {
		printf("Error : IRD_rebuild malloc failed\n");
		FCLOSE(temp);
		goto error;
	}
	if (fread(buf, 1, st.st_size, temp) != (size_t)st.st_size) {
		printf("Error : IRD_rebuild failed to read header file\n");
		FCLOSE(temp);
		FREE(buf);
		goto error;
	}
	if (fwrite(buf, 1, st.st_size, iso) != (size_t)st.st_size) {
		printf("Error : IRD_rebuild failed to write header to ISO\n");
		FCLOSE(temp);
		FREE(buf);
		goto error;
	}
	FCLOSE(temp);
	FREE(buf);

	memcpy(dec_key, ird->Data1, 0x10);
	dec_d1(dec_key);

	sector_buf = (u8 *)malloc(SECTOR_SIZE);
	if (sector_buf == NULL) {
		printf("Error : IRD_rebuild malloc failed\n");
		goto error;
	}

	for (i = 0; i < ird->FileHashesNumber; i++) {
		current_region = 0;
		for (j = 0; j < ird->RegionHashesNumber; j++) {
			if (ird->FileHashes[i].Sector >= ird->RegionHashes[j].Start &&
				ird->FileHashes[i].Sector <= ird->RegionHashes[j].End) {
				current_region = j;
				break;
			}
		}
		encrypted = (current_region % 2 == 1) ? 1 : 0;

		sprintf(file_path, "%s%s", FOLDER_PATH, ird->FileHashes[i].FilePath);

		src = fopen(file_path, "rb");
		if (src == NULL) {
			printf("Error : IRD_rebuild failed to open %s\n", file_path);
			goto error;
		}

		fseek(src, 0, SEEK_END);
		file_size = ftell(src);
		fseek(src, 0, SEEK_SET);

		if (md5_file(file_path, actual_hash) != 0) {
			printf("Error : IRD_rebuild md5_file failed for %s\n", file_path);
			goto error;
		}
		if (memcmp(actual_hash, ird->FileHashes[i].FileHash, 0x10) != 0) {
			if (no_verify) {
				printf("Warning : IRD_rebuild MD5 mismatch for %s\n", file_path);
			} else {
				printf("Error : IRD_rebuild MD5 mismatch for %s\n", file_path);
				printf("  Expected: ");
				for (j = 0; j < 0x10; j++) printf("%02X", ird->FileHashes[i].FileHash[j]);
				printf("\n  Actual:   ");
				for (j = 0; j < 0x10; j++) printf("%02X", actual_hash[j]);
				printf("\n");
				goto error;
			}
		}

		if (fseek(iso, (long)(ird->FileHashes[i].Sector * SECTOR_SIZE), SEEK_SET) != 0) {
			printf("Error : IRD_rebuild seek failed for sector %llu\n", (unsigned long long)ird->FileHashes[i].Sector);
			goto error;
		}

		write_size = file_size;
		sector_lba = ird->FileHashes[i].Sector;

		while (write_size > 0) {
			memset(sector_buf, 0, SECTOR_SIZE);
			if (write_size >= SECTOR_SIZE) {
				if (fread(sector_buf, 1, SECTOR_SIZE, src) != SECTOR_SIZE) {
					printf("Error : IRD_rebuild read failed for %s\n", file_path);
					goto error;
				}
			} else {
				if (fread(sector_buf, 1, write_size, src) != write_size) {
					printf("Error : IRD_rebuild read failed for %s\n", file_path);
					goto error;
				}
			}

			if (encrypted) {
				u8 iv[0x10];
				u8 lba_be[8];
				u64 be_val;
				memset(iv, 0, 8);
				be_val = SWAP_BE(sector_lba);
				memcpy(lba_be, &be_val, 8);
				memcpy(iv + 8, lba_be, 8);

				u8 enc_buf[SECTOR_SIZE];
				aes_cbc_encrypt(dec_key, iv, sector_buf, enc_buf, SECTOR_SIZE);
				if (fwrite(enc_buf, 1, SECTOR_SIZE, iso) != SECTOR_SIZE) {
					printf("Error : IRD_rebuild write failed for sector %llu\n", (unsigned long long)sector_lba);
					goto error;
				}
			} else {
				if (fwrite(sector_buf, 1, SECTOR_SIZE, iso) != SECTOR_SIZE) {
					printf("Error : IRD_rebuild write failed for sector %llu\n", (unsigned long long)sector_lba);
					goto error;
				}
			}

			if (write_size >= SECTOR_SIZE)
				write_size -= SECTOR_SIZE;
			else
				write_size = 0;

			sector_lba++;
		}

		FCLOSE(src);
	}

	if (GZ_decompress7((char *)ird->Footer, ird->FooterLength, footer_path) != Z_OK) {
		printf("Error : IRD_rebuild failed to decompress footer\n");
		goto error;
	}

	temp = fopen(footer_path, "rb");
	if (temp == NULL) {
		printf("Error : IRD_rebuild failed to open footer file\n");
		goto error;
	}
	fseek(temp, 0, SEEK_END);
	footer_size = ftell(temp);
	fseek(temp, 0, SEEK_SET);

	buf = (u8 *)malloc(footer_size);
	if (buf == NULL) {
		printf("Error : IRD_rebuild malloc failed\n");
		FCLOSE(temp);
		goto error;
	}
	if (fread(buf, 1, footer_size, temp) != (size_t)footer_size) {
		printf("Error : IRD_rebuild failed to read footer file\n");
		FCLOSE(temp);
		FREE(buf);
		goto error;
	}
	FCLOSE(temp);

	{
		u64 last_file_end = ird->FileHashes[ird->FileHashesNumber-1].Sector * SECTOR_SIZE +
							ird->FileHashes[ird->FileHashesNumber-1].FileSize;
		last_file_end = (last_file_end + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1);
		if (fseek(iso, (long)last_file_end, SEEK_SET) != 0) {
			printf("Error : IRD_rebuild seek to footer position failed\n");
			FREE(buf);
			goto error;
		}
	}
	if (fwrite(buf, 1, footer_size, iso) != (size_t)footer_size) {
		printf("Error : IRD_rebuild failed to write footer to ISO\n");
		FREE(buf);
		goto error;
	}
	FREE(buf);

	{
		u64 disc_size = (u64)(ird->RegionHashes[ird->RegionHashesNumber-1].End + 1) * SECTOR_SIZE;
		if (fseek(iso, (long)(disc_size - 1), SEEK_SET) != 0) {
			printf("Error : IRD_rebuild seek for padding failed\n");
			goto error;
		}
		if (fwrite("\0", 1, 1, iso) != 1) {
			printf("Error : IRD_rebuild padding write failed\n");
			goto error;
		}
		if (fseek(iso, 0, SEEK_SET) != 0) {
			printf("Error : IRD_rebuild seek to beginning failed\n");
			goto error;
		}
	}

	{
		md5_context md5_ctx;
		u8 region_hash[0x10];

		vbuf = (u8 *)malloc(VERIFY_BUF_SIZE);
		if (vbuf == NULL) {
			printf("Error : IRD_rebuild malloc failed\n");
			goto error;
		}

		for (i = 0; i < ird->RegionHashesNumber; i++) {
			u64 region_start = (u64)ird->RegionHashes[i].Start * SECTOR_SIZE;
			u64 region_size = (u64)(ird->RegionHashes[i].End - ird->RegionHashes[i].Start + 1) * SECTOR_SIZE;
			u64 bytes_remaining = region_size;

			if (fseek(iso, (long)region_start, SEEK_SET) != 0) {
				printf("Error : IRD_rebuild seek for region verification failed\n");
				FREE(vbuf);
				goto error;
			}

			md5_starts(&md5_ctx);
			while (bytes_remaining > 0) {
				size_t to_read = bytes_remaining > VERIFY_BUF_SIZE ? VERIFY_BUF_SIZE : (size_t)bytes_remaining;
				if (fread(vbuf, 1, to_read, iso) != to_read) {
					printf("Error : IRD_rebuild read for region verification failed\n");
					FREE(vbuf);
					goto error;
				}
				md5_update(&md5_ctx, vbuf, to_read);
				bytes_remaining -= to_read;
			}
			md5_finish(&md5_ctx, region_hash);

			if (memcmp(region_hash, ird->RegionHashes[i].RegionHash, 0x10) != 0) {
				if (no_verify) {
					printf("Warning : IRD_rebuild region %d MD5 mismatch\n", i + 1);
				} else {
					printf("Error : IRD_rebuild region %d MD5 mismatch\n", i + 1);
					printf("  Expected: ");
					for (j = 0; j < 0x10; j++) printf("%02X", ird->RegionHashes[i].RegionHash[j]);
					printf("\n  Actual:   ");
					for (j = 0; j < 0x10; j++) printf("%02X", region_hash[j]);
					printf("\n");
					FREE(vbuf);
					goto error;
				}
			}
		}
		FREE(vbuf);
	}

	ret = SUCCESS;
	printf("IRD_rebuild success\n");

error:
	if (ret == FAILED) {
		if (iso != NULL) {
			fclose(iso);
			iso = NULL;
			remove(ISO_OUTPUT);
		}
	}

	FCLOSE(src);
	FCLOSE(iso);
	FCLOSE(temp);
	FREE(buf);
	FREE(sector_buf);
	FREE(vbuf);
	remove(header_path);
	remove(footer_path);
	FREE_IRD(ird);

	return ret;
}
