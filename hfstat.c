/*
 * Copyright (c) 2011 Vasily Tarasov
 * Copyright (c) 2011 Will Buik
 * Copyright (c) 2011 Erez Zadok
 * Copyright (c) 2011 Geoff Kuenning
 * Copyright (c) 2011 Stony Brook University
 * Copyright (c) 2011 Harvey Mudd College
 * Copyright (c) 2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <time.h>
#include <errno.h>

#define MAXLINE	4096

#include "hashfilelib.h"
#include "liblog.h"

static char *progname;
static int show_files_only;
static int show_files_and_hashes;
static int sql_export_mode;

uint64_t total_files;
uint64_t total_bytes;
uint64_t total_chunks;
uint64_t total_duration;

/*
 * Escapes SQL bulk loader unsafe characters in a string and prints it
 * according to the format string.  The format string MUST contain only
 * one %s.   The list of the characters to escape was obtained from
 * MySQL manual.
 */
static void sql_safe_print(const char *format, const char *str)
{
	char escaped[MAXLINE];
	size_t i;

	for (i = 0; i < (sizeof(escaped) - 2) && *str != '\0'; i++, str++) {
		switch (*str) {
		case '\0':
			escaped[i] = '\\';
			escaped[++i] = '0';
			break;
		case '\t':
			escaped[i] = '\\';
			escaped[++i] = 't';
			break;
		case '\r':
			escaped[i] = '\\';
			escaped[++i] = 'r';
			break;
		case '\n':
			escaped[i] = '\\';
			escaped[++i] = 'n';
			break;
		case '\b':
			escaped[i] = '\\';
			escaped[++i] = 'b';
			break;
		case 26: /* Ctrl+Z */
			escaped[i] = '\\';
			escaped[++i] = 'Z';
			break;
		case '\\':
			escaped[i] = '\\';
			escaped[++i] = '\\';
			break;
		default:
			escaped[i] = *str;
		}
	}
	escaped[i] = '\0';

	printf(format, escaped);
}

/* hash_size is the size of the hash in bytes */
static void print_chunk_info(const uint8_t *hash,
		 int hash_size, uint64_t chunk_size, uint8_t cratio)
{
	int j;

	printf("%.2hhx", hash[0]);
	for (j = 1; j < hash_size; j++)
		printf(":%.2hhx", hash[j]);

	printf("\t<%" PRIu64 ">", chunk_size);
	printf("\t<%" PRIu8 ">", cratio);
	printf("\n");
}

/* hash_size is the size of the hash in bytes */
static void sql_chunk_info(const uint8_t *hash, int hash_size,
				uint64_t chunk_size, uint8_t cratio,
				uint64_t file_id, uint64_t chunk_seqnum)
{
	int j;

	printf("%"PRIu64"\t", file_id);
	printf("%"PRIu64"\t", chunk_seqnum);
	for (j = 0; j < hash_size; j++)
		printf("%.2hhx", hash[j]);
	printf("\t%"PRIu64"\t", chunk_size);
	printf("%"PRIu8"\t", cratio);
	printf("\\N\t\\N\t\\N\t\\N\t\\N\t\\N\t\\N\t\\N\t\\N\t\\N\n");
}

static void print_hashfile_header(struct hashfile_handle *handle)
{
	char buf[MAXLINE];
	time_t start_time;
	time_t end_time;
	time_t run_time;
	int ret;

	printf("Hash file version: %d\n", hashfile_version(handle));
	printf("Root path: %s\n", hashfile_rootpath(handle));
	printf("System id: %s\n", hashfile_sysid(handle) ?
			hashfile_sysid(handle) : "<not supported>");

	start_time = hashfile_start_time(handle);
	printf("Start time: %s", start_time ?
		ctime(&start_time) : "<not supported>\n");
	end_time = hashfile_end_time(handle);
	printf("End time: %s", end_time ?
		ctime(&end_time) : "<not supported>\n");
	run_time = end_time - start_time;
	printf("Total time: %d seconds\n",
		start_time * end_time ? (int)run_time : 0);

	printf("Files hashed: %" PRIu64 "\n", hashfile_numfiles(handle));
	printf("Chunks hashed: %" PRIu64 "\n", hashfile_numchunks(handle));
	printf("Bytes hashed: %" PRIu64 "\n", hashfile_numbytes(handle));

	ret = hashfile_chunking_method_str(handle, buf, MAXLINE);
	if (ret < 0)
		printf("Chunking method not recognized.\n");
	else
		printf("Chunking method: %s", buf);

	ret = hashfile_hashing_method_str(handle, buf, MAXLINE);
	if (ret < 0)
		printf("Hashing method not recognized.\n");
	else
		printf("Hashing method: %s", buf);
}

static void sql_print_time(uint64_t ts)
{
	char tmp[128];
	struct tm *tm;

	tm = localtime((time_t *)&ts);
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", tm);

	printf("%s\t", tmp);
}

static void sql_hashfile_header(struct hashfile_handle *handle)
{
	sql_safe_print("\\N\t\\N\t%s\t", hashfile_rootpath(handle));
	printf("%"PRIu64"\t", hashfile_numfiles(handle));
	printf("%"PRIu64"\t", hashfile_numchunks(handle));
	sql_print_time(hashfile_start_time(handle));
	sql_print_time(hashfile_end_time(handle));
	printf("\\N\t\\N\t\\N\t\\N\t\\N\t\\N\t\\N\t\\N\n");
}

static void update_total_stats(struct hashfile_handle *handle)
{
	total_files += hashfile_numfiles(handle);
	total_bytes += hashfile_numbytes(handle);
	total_chunks += hashfile_numchunks(handle);
	total_duration += (hashfile_end_time(handle) -
				hashfile_start_time(handle));
}

static void print_current_fileinfo(struct hashfile_handle *handle,
							uint8_t *filehash)
{
	uint64_t size, size_kb;
	time_t atm, mtm, ctm;
	char *target_path;
	int j;

	printf("File path: %s\n", hashfile_curfile_path(handle));
	size = hashfile_curfile_size(handle);
	size_kb = size / 1024;
	printf("File size: %"PRIu64 "%s\n", (size_kb > 0) ? size_kb : size,
						(size_kb > 0) ? "KB" : "B");
	printf("FS Blocks: %"PRIu64"\n", hashfile_curfile_blocks(handle));

	printf("Chunks: %" PRIu64 "\n",
				 hashfile_curfile_numchunks(handle));

	/*
	 * Print extended statistics if they are available.
	 * Might be missing for some old hashfiles. 
 	 */
	printf("UID: %"PRIu32"\n", hashfile_curfile_uid(handle));
	printf("GID: %"PRIu32"\n", hashfile_curfile_gid(handle));
	printf("Permission bits: %"PRIo64"\n", hashfile_curfile_perm(handle));

	atm = hashfile_curfile_atime(handle);
	mtm = hashfile_curfile_mtime(handle);
	ctm = hashfile_curfile_ctime(handle);
	printf("Access time: %s", ctime(&atm));
	printf("Modification time: %s", ctime(&mtm));
	printf("Change time: %s", ctime(&ctm));

	printf("Hardlinks: %"PRIu64"\n", hashfile_curfile_hardlinks(handle));
	printf("Device ID: %"PRIu64"\n", hashfile_curfile_deviceid(handle));
	printf("Inode Num: %"PRIu64"\n", hashfile_curfile_inodenum(handle));

	if (filehash) {
		printf("File hash: ");
		for (j = 0; j < hashfile_hash_size(handle) / 8; j++)
			printf("%.2hhx", filehash[j]);
		printf("\n");
	}

	target_path = hashfile_curfile_linkpath(handle);
	if (target_path)
		printf("Target Path: %s\n", target_path);
}

static void sql_current_fileinfo(struct hashfile_handle *handle,
			uint8_t *filehash, uint64_t file_id)
{
	char *link_path;
	int j;

	printf("%"PRIu64"\t", file_id);
	printf("\\N\t");
	sql_safe_print("%s\t", hashfile_curfile_path(handle)
				+ strlen(hashfile_rootpath(handle)));
	printf("%"PRIu64"\t", hashfile_curfile_size(handle));
	printf("%"PRIu64"\t", hashfile_curfile_numchunks(handle));

	sql_print_time(hashfile_curfile_atime(handle));
	sql_print_time(hashfile_curfile_mtime(handle));
	sql_print_time(hashfile_curfile_ctime(handle));
	printf("%"PRIu32"\t", hashfile_curfile_uid(handle));
	printf("%"PRIu32"\t", hashfile_curfile_gid(handle));
	printf("%"PRIo64"\t", hashfile_curfile_perm(handle));
	printf("%"PRIu64"\t", hashfile_curfile_hardlinks(handle));
	printf("%"PRIu64"\t", hashfile_curfile_deviceid(handle));
	printf("%"PRIu64"\t", hashfile_curfile_inodenum(handle));
	link_path = hashfile_curfile_linkpath(handle);
	if (link_path)
		sql_safe_print("%s\t", link_path);
	else
		printf("\\N\t");
	for (j = 0; j < hashfile_hash_size(handle) / 8; j++)
		printf("%.2hhx", filehash[j]);
	printf("\n");
}

static void update_whole_file_hash(uint8_t *hash,
			uint32_t hash_size, uint8_t *xored)
{
	int i;

	for (i = 0; i < hash_size; i++)
		xored[i] = xored[i] ^ hash[i];
}

static void display_hashes_and_comp_whole(struct hashfile_handle *handle,
				uint8_t *whole_file_hash, uint64_t file_id)
{
	const struct chunk_info *ci;
	int hash_size;
	uint64_t chunk_seqnum = 0;

	hash_size = hashfile_hash_size(handle) / 8;
	while (1) {
		ci = hashfile_next_chunk(handle);
		if (!ci)
			break;

		if (sql_export_mode) {
			sql_chunk_info(ci->hash, hash_size, ci->size,
					ci->cratio, file_id, chunk_seqnum);
			/*
 			 * Chunk sequence number is only used during SQL
 			 * export mode to assign a sequence number to a chunk
 			 * in a database.
 			 */
			chunk_seqnum++;
		} else {
			print_chunk_info(ci->hash, hash_size,
						ci->size, ci->cratio);
		}

		update_whole_file_hash(ci->hash, hash_size, whole_file_hash);
	}
}

static void process_hashfile(char *hashfile_name)
{
	struct hashfile_handle *handle;
	uint8_t whole_file_hash[512];
	uint64_t file_id = 0;
	int ret;

	handle = hashfile_open(hashfile_name);
	if (!handle)
		liblog_logen(LOG_FTL, errno, "Error opening hash file!");

	if (sql_export_mode) {
		sql_hashfile_header(handle);
	} else {
		printf("*** Hash file: %s\n", hashfile_name);
		print_hashfile_header(handle);
		update_total_stats(handle);

		if (!show_files_only && !show_files_and_hashes)
			goto out_close;	

		printf("=== Per file statistics ===\n");
	}

	/* Going over the files in a hashfile */
	while (1) {
		ret = hashfile_next_file(handle);
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Cannot get next file from a hashfile!\n");

		/* exit the loop if it was a last file */
		if (ret == 0)
			break;

		if (!show_files_only) {
			bzero(whole_file_hash, sizeof(whole_file_hash));
			display_hashes_and_comp_whole(handle,
					whole_file_hash, file_id);
		}

		if (sql_export_mode) {
			sql_current_fileinfo(handle, whole_file_hash, file_id);
			/*
			 * file_id is used only during SQL export mode to assign
 			 * some ID to a file in a database. Chunks belonging to
 			 * a file are also marked by a corresponding ID.
 			 */
			file_id++;
		} else {
			print_current_fileinfo(handle, show_files_and_hashes ?
							whole_file_hash : NULL);
			printf("\n");
		}
	}

out_close:

	hashfile_close(handle);

	return;
}

static void usage()
{
	printf("%s {-f|-h|-s} <hashfile> ...\n", progname);
	printf("  -f: Display each file stored in the hash file\n");
	printf("  -h: Display each file and hash stored in the hash file\n");
	printf("  -s: Output in SQL export mode, "
				"only single input file is supported\n");
	printf("  All parameters are mutual exclusive\n");
}

int main(int argc, char *argv[])
{
	int opt;
	int i;

	/* Save program name */
	progname = argv[0];

	/* Collecting command line parameters */
	while (1) {
		opt = getopt(argc, argv, "hfs");
		if (opt == -1)
			break;

		switch (opt) {
		case 'h':
			show_files_and_hashes = 1;
			break;
		case 'f':
			show_files_only = 1;
			break;
		case 's':
			sql_export_mode = 1;
			break;
		case '?':
			usage();
			return -1;
		}
	}

	if (optind == argc) {
		liblog_slog(LOG_FTL, "No input files specified!");
		usage();
		return -1;
	}

	if (sql_export_mode + show_files_only + show_files_and_hashes > 1) {
		liblog_slog(LOG_FTL, "-f, -h and -f are mutually exclusive!");
		usage();
		return -1;
	}

	if ((argc - optind > 1) && sql_export_mode) {
		liblog_slog(LOG_FTL, "SQL export mode supports "
					"only single file as an input!");
		usage();
		return -1;
	}

	/* Process hashfiles */
	for (i = optind; i < argc; i++)
		process_hashfile(argv[i]);

	if (!sql_export_mode) {
		printf("*** Totals:\n");
		printf("Total files: %" PRIu64 "\n", total_files);
		printf("Total bytes: %" PRIu64 "\n", total_bytes);
		printf("Total chunks: %" PRIu64 "\n", total_chunks);
		printf("Total time (seconds): %" PRIu64 "\n", total_duration);
	}

	return 0;
}
