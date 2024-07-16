/*
 * Copyright (c) 2011 Vasily Tarasov
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
#define _GNU_SOURCE /* important to keep right basename() version */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include "hashfilelib.h"
#include "liblog.h"

static char *progname;

/* Information about the output file */
static char *out_name;
struct hashfile_handle *out_handle;
static enum chnking_method cmeth;
static struct fixed_chnking_params fxd_params;
static struct var_chnking_params var_params;
static enum hshing_method hmeth;
static int32_t hash_size;

static char *root_path = "/fakeroot";

uint64_t files_processed;

static void add_chunks_to_file(struct hashfile_handle *out_handle,
				struct hashfile_handle *handle)
{
	const struct chunk_info *ci;

	while (1) {
		ci = hashfile_next_chunk(handle);
		if (!ci)
			break;

		hashfile_add_chunk(out_handle, ci);
	}
}

static void process_hashfile(char *hashfile_name)
{
	struct hashfile_handle *handle;
	struct stat stat_buf;
	int ret;

	liblog_slog(LOG_INF, "Processing: %s", hashfile_name);

	handle = hashfile_open(hashfile_name);
	if (!handle)
		liblog_logen(LOG_FTL, errno, "Can't open %s", hashfile_name);

	/* iterating over the files */
	while (1) {
		ret = hashfile_next_file(handle);
		if (ret == 0)
			break;
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Error while processing hashfile!");

		stat_buf.st_size = hashfile_curfile_size(handle);
		stat_buf.st_blocks = hashfile_curfile_blocks(handle);
		stat_buf.st_uid = hashfile_curfile_uid(handle);
		stat_buf.st_gid = hashfile_curfile_gid(handle);
		stat_buf.st_mode = hashfile_curfile_perm(handle);
		stat_buf.st_atime = hashfile_curfile_atime(handle);
		stat_buf.st_mtime = hashfile_curfile_mtime(handle);
		stat_buf.st_ctime = hashfile_curfile_ctime(handle);
		stat_buf.st_nlink = hashfile_curfile_hardlinks(handle);
		stat_buf.st_dev = hashfile_curfile_deviceid(handle);
		stat_buf.st_ino = hashfile_curfile_inodenum(handle);

		ret = hashfile_add_file(out_handle,
			hashfile_curfile_path(handle), &stat_buf,
				hashfile_curfile_linkpath(handle));
		if (ret < 0)
			liblog_logen(LOG_FTL, errno,
				"Error while adding a file!");

		add_chunks_to_file(out_handle, handle);

		files_processed++;
	}

	liblog_slog(LOG_INF, "%"PRIu64" files processed", files_processed);

	hashfile_close(handle);

	return;
}

static int verify_fxd_params(struct fixed_chnking_params *cur_fxd_params)
{

	if (cur_fxd_params->chunk_size != fxd_params.chunk_size)
		return -1;

	return 0;
}

static int verify_var_params(struct var_chnking_params *cur_var_params)
{
	if (cur_var_params->algo != var_params.algo)
		return -1;

	switch(var_params.algo) {
	case RANDOM:
		if (cur_var_params->algo_params.rnd_params.probability !=
			var_params.algo_params.rnd_params.probability)
				return -1;
		break;
 	case SIMPLE_MATCH:
		if (cur_var_params->algo_params.simple_params.bits_to_compare !=
			var_params.algo_params.simple_params.bits_to_compare ||
			cur_var_params->algo_params.simple_params.pattern !=
			var_params.algo_params.simple_params.pattern)
				return -1;
		break;
	case RABIN:
		if (cur_var_params->algo_params.rabin_params.window_size !=
			var_params.algo_params.rabin_params.window_size ||
			cur_var_params->algo_params.rabin_params.prime !=
			var_params.algo_params.rabin_params.prime ||
			cur_var_params->algo_params.rabin_params.module !=
			var_params.algo_params.rabin_params.module ||
			cur_var_params->algo_params.rabin_params.bits_to_compare !=
			var_params.algo_params.rabin_params.bits_to_compare ||
			cur_var_params->algo_params.rabin_params.pattern !=
			var_params.algo_params.rabin_params.pattern)
				return -1;
		break;
	}

	if (cur_var_params->min_csize != var_params.min_csize)
		return -1;

	if (cur_var_params->max_csize != var_params.max_csize)
		return -1;

	return 0;
}

static void verify_input_hashfile(char *hashfile_name)
{
	struct hashfile_handle *handle;
	enum chnking_method cur_cmeth;
	struct fixed_chnking_params cur_fxd_params;
	struct var_chnking_params cur_var_params;
	enum hshing_method cur_hmeth;
	int32_t cur_hash_size;
	int ret;

	liblog_slog(LOG_INF, "Verifying: %s",hashfile_name);

	handle = hashfile_open(hashfile_name);
	if (!handle)
		liblog_logen(LOG_FTL, errno, "Can't open %s", hashfile_name);

	cur_cmeth = hashfile_chunking_method(handle);
	if (cur_cmeth == FIXED)
		ret = hashfile_fxd_chunking_params(handle, &cur_fxd_params);
	else if (cur_cmeth == VARIABLE)
		ret = hashfile_var_chunking_params(handle, &cur_var_params);
	else
		assert(0);

	cur_hmeth = hashfile_hashing_method(handle);
	cur_hash_size = hashfile_hash_size(handle);

	if (!cmeth) {
		/*
		 * It is the very first input hash file.
		 * Just save the parameters.
		 */
		cmeth = cur_cmeth;
		if (cmeth == FIXED)
			fxd_params = cur_fxd_params;
		else if (cmeth == VARIABLE)
			var_params = cur_var_params;
		else
			assert(0);

		hmeth = cur_hmeth;
		hash_size = cur_hash_size;

		hashfile_close(handle);
		return;
	}

	/*
 	 * Verify that current input hash file is compatible
 	 * with previos input hash files.
 	 */
	if (cur_cmeth != cmeth || cur_hmeth != hmeth)
		liblog_sloge(LOG_FTL, "Chunking or hashing methods mismatch!");

	if (cur_hash_size != hash_size)
		liblog_sloge(LOG_FTL, "Hash size mismatch!");

	if (cmeth == FIXED && verify_fxd_params(&cur_fxd_params))
		liblog_sloge(LOG_FTL, "Fixed chunking parameters mismatch!");

	if (cmeth == VARIABLE && verify_var_params(&cur_var_params))
		liblog_sloge(LOG_FTL, "Variable chunking parameters mismatch!");


	hashfile_close(handle);

	return;
}


static void usage()
{
	printf("Usage: ");
	printf("%s -o <output hash file> <input hash files ...>\n", progname);
}

int main(int argc, char *argv[])
{
	int opt;
	int ret;
	int i;

	/* Save program name */
	progname = argv[0];

	/* Collecting command line parameters */
	while (1) {
		opt = getopt(argc, argv, "o:");
		if (opt == -1)
			break;

		switch (opt) {
		case 'o':
			out_name = optarg;
			break;
		case '?':
			liblog_slog(LOG_FTL, "Wrong usage!");
			usage();
			return -1;
		}
	}

	if (!out_name) {
		liblog_slog(LOG_FTL, "Output file is not specified!");
		usage();
		return -1;
	}

	if (optind == argc) {
		liblog_slog(LOG_FTL, "No input files specified!");
		usage();
		return -1;
	}

	/*
	 * First we need to decide on the format of the output hash file:
	 * iterate over all input files, make sure that their format are
	 * compatiable (e.g., same hashing method is used in all input files),
	 * then use input file format as an output file format.
	 */
	for (i = optind; i < argc; i++)
		verify_input_hashfile(argv[i]);

	/*
 	 * Now, open new hash files and set its parameters
 	 */
	out_handle = hashfile_open4write(out_name, cmeth, hmeth,
						hash_size, root_path);
	if (!out_handle)
		liblog_logen(LOG_FTL, errno,
				"Error while opening output hash file!");

	if (cmeth == FIXED)
		ret = hashfile_set_fxd_chnking_params(out_handle, &fxd_params);
	else if (cmeth == VARIABLE)
		ret = hashfile_set_var_chnking_params(out_handle, &var_params);
	else
		assert(0);

	if (ret < 0)
		liblog_logen(LOG_FTL, errno,
			"Error while setting hash file parameters!");

	/* Process input hashfiles */
	for (i = optind; i < argc; i++)
		process_hashfile(argv[i]);

	hashfile_close(out_handle);

	return 0;
}
