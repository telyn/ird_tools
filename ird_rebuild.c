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

u8 IRD_rebuild(char *IRD_PATH, char *FOLDER_PATH, char *ISO_OUTPUT, u8 no_verify, u8 encrypt)
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

	if (IRD_GetFilesPath(header_path, ird) != 0) {
		printf("Error : IRD_rebuild failed to get file paths\n");
		goto error;
	}

	if (IRD_GetRegionBoundaries(header_path, ird) == FAILED) {
		printf("Error : IRD_rebuild failed to get region boundaries\n");
		goto error;
	}

	{
		int pup_found = 0;
		for (i = 0; i < ird->FileHashesNumber; i++) {
			if (strstr(ird->FileHashes[i].FilePath, "PS3UPDAT.PUP") != NULL) {
				pup_found = 1;
				sprintf(file_path, "%s%s", FOLDER_PATH, ird->FileHashes[i].FilePath);
				if (stat(file_path, &st) != 0) {
					printf("Error : PS3UPDAT.PUP not found at %s\n", file_path);
					printf("  IRD expects PS3 update version: %.4s\n", ird->UpdateVersion);
					goto error;
				}
				break;
			}
		}
		if (!pup_found) {
			printf("Warning : IRD contains no PS3UPDAT.PUP entry\n");
		}
	}

	iso = fopen(ISO_OUTPUT, "w+b");
	if (iso == NULL) {
		printf("Error : IRD_rebuild failed to create output ISO\n");
		goto error;
	}

	temp = fopen(header_path, "rb");
	if (temp == NULL) {
		printf("Error : IRD_rebuild failed to open header file\n");
		goto error;
	}
	if (stat(header_path, &st) != 0) {
		printf("Error : IRD_rebuild failed to stat header file\n");
		FCLOSE(temp);
		goto error;
	}
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

	if (encrypt) {
		memcpy(dec_key, ird->Data1, 0x10);
		dec_d1(dec_key);
	}

	sector_buf = (u8 *)malloc(SECTOR_SIZE);
	if (sector_buf == NULL) {
		printf("Error : IRD_rebuild malloc failed\n");
		goto error;
	}

	for (i = 0; i < ird->FileHashesNumber; i++) {
		printf("\rfile %d / %d", i + 1, ird->FileHashesNumber);
		fflush(stdout);
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

		if (fseek(src, 0, SEEK_END) != 0) {
			printf("Error : IRD_rebuild fseek failed for %s\n", file_path);
			FCLOSE(src);
			goto error;
		}
		file_size = ftell(src);
		if (fseek(src, 0, SEEK_SET) != 0) {
			printf("Error : IRD_rebuild fseek failed for %s\n", file_path);
			FCLOSE(src);
			goto error;
		}

		{
			u64 expected_size = ird->FileHashes[i].FileSize;

			if (file_size < expected_size) {
				printf("Warning : %s is %llu bytes, IRD expects %llu, will zero-pad\n",
					file_path, (unsigned long long)file_size, (unsigned long long)expected_size);
			} else if (file_size > expected_size) {
				printf("Error : %s is larger than IRD expects (%llu > %llu)\n",
					file_path, (unsigned long long)file_size, (unsigned long long)expected_size);
				FCLOSE(src);
				goto error;
			}
		}

		if (fseek(iso, (long)(ird->FileHashes[i].Sector * SECTOR_SIZE), SEEK_SET) != 0) {
			printf("Error : IRD_rebuild seek failed for sector %llu\n", (unsigned long long)ird->FileHashes[i].Sector);
			FCLOSE(src);
			goto error;
		}

		write_size = ird->FileHashes[i].FileSize;
		sector_lba = ird->FileHashes[i].Sector;
		{
			u64 remaining_source = file_size;
			md5_context md5_ctx;
			md5_starts(&md5_ctx);

			while (write_size > 0) {
				memset(sector_buf, 0, SECTOR_SIZE);
				if (remaining_source > 0) {
					size_t to_read = remaining_source >= SECTOR_SIZE ? SECTOR_SIZE : (size_t)remaining_source;
					if (fread(sector_buf, 1, to_read, src) != to_read) {
						printf("Error : IRD_rebuild read failed for %s\n", file_path);
						FCLOSE(src);
						goto error;
					}
					remaining_source -= to_read;
				}

				{
					size_t hash_size = write_size >= SECTOR_SIZE ? SECTOR_SIZE : (size_t)write_size;
					md5_update(&md5_ctx, sector_buf, hash_size);
				}

				if (encrypted && encrypt) {
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
						FCLOSE(src);
						goto error;
					}
				} else {
					if (fwrite(sector_buf, 1, SECTOR_SIZE, iso) != SECTOR_SIZE) {
						printf("Error : IRD_rebuild write failed for sector %llu\n", (unsigned long long)sector_lba);
						FCLOSE(src);
						goto error;
					}
				}

				if (write_size >= SECTOR_SIZE)
					write_size -= SECTOR_SIZE;
				else
					write_size = 0;

				sector_lba++;
			}
			md5_finish(&md5_ctx, actual_hash);
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
					FCLOSE(src);
					goto error;
				}
			}
		}

		FCLOSE(src);
	}
	printf("\n");

	if (GZ_decompress7((char *)ird->Footer, ird->FooterLength, footer_path) != Z_OK) {
		printf("Error : IRD_rebuild failed to decompress footer\n");
		goto error;
	}

	temp = fopen(footer_path, "rb");
	if (temp == NULL) {
		printf("Error : IRD_rebuild failed to open footer file\n");
		goto error;
	}
	if (fseek(temp, 0, SEEK_END) != 0) {
		printf("Error : IRD_rebuild fseek for footer size failed\n");
		FCLOSE(temp);
		goto error;
	}
	footer_size = ftell(temp);
	if (fseek(temp, 0, SEEK_SET) != 0) {
		printf("Error : IRD_rebuild fseek for footer failed\n");
		FCLOSE(temp);
		goto error;
	}

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

	if (ird->FileHashesNumber == 0) {
		printf("Error : IRD_rebuild no files in IRD\n");
		goto error;
	}

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
			u8 is_encrypted = (i % 2 == 1);
			if (is_encrypted && !encrypt && no_verify) {
				continue;
			}
			if (is_encrypted && !encrypt) {
				printf("Warning : IRD_rebuild region %d is encrypted on the original disc, skipping hash check (use --encrypt)\n", i + 1);
				continue;
			}

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
