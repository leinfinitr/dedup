/*
 * Copyright (c) 2011 Vasily Tarasov
 * Copyright (c) 2011 Amar Mundrankit
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
#define _GNU_SOURCE

#include "config.h"

#if defined(HAVE_OPENSSL_SHA_H) && defined(HAVE_LIBCRYPTO)
	#include <openssl/sha.h>
	/* Solaris libcrypt does not support SHA256 */
	#ifdef SHA256_DIGEST_LENGTH 
		#define SHA256_SUPPORTED 1
	#endif
#endif

#if defined(HAVE_OPENSSL_SHA_H) && defined(HAVE_LIBCRYPTO)
	#include <openssl/md5.h>
	#define MD5_SUPPORTED	1
#endif

#if defined(HAVE_ZLIB_H) && defined(HAVE_LIBZ)
	#include <zlib.h>
	#define ZLIB_SUPPORTED	1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <ftw.h>
#include <sys/stat.h>
#include <assert.h>
#include <inttypes.h>
#include <sys/mman.h>

#include "hashfilelib.h"
#include "liblog.h"
#include "murmurhash3.h"

/* generic */
static char *progname;
static int exit_on_error;
#define GETOPT_OPTIONS "mp:c:C:h:o:udqF:Mez:" /* getopt options string */
#define CHNK_PARAM_DELIMS ":" /* delimiter between parameter-values */
#define CHNK_PARAM_PV_DELIM '=' /* parameter-value delimiter */
#define NFTW_MAX_OPENED_DIRS 100
#define MAX_HASH_SIZE 128	/* in bytes */

/* run's statistics */
uint64_t file_count;
uint64_t byte_count;
uint64_t symlink_count;

/* root path that is being proccessed */
char root_path[4096];
char *root_path_arg;

/* dedup_method forward declaration */
struct dedup_method;

/********************************** FILE IO ***********************************/

static uint64_t window_size;
static uint64_t window_offset;
static unsigned char *window_buffer;

/* Unix Read based File IO */

static uint64_t window_size_read = 4 * 1024 * 1024;
static unsigned char *window_buffer_read;

/*
 * Advances the file window to new_offset using read() calls to fill a buffer.
 * Sets up a buffer to hold the data on the first call.
 */
static int window_advance_read(int fd, uint64_t new_offset)
{
	uint64_t size_cur = 0;
	off_t offset;
	int ret = 0;

	/*
	 * Alocate a buffer to hold the file data. It will exist for the
	 * lifetime of the program, even if called through _mmap function
	 * in case of failover.
	 */
	if (!window_buffer_read) {
		window_buffer_read = malloc(window_size_read);
		if (!window_buffer_read) {
			errno = ENOMEM;
			return -1;
		}
	}

	window_buffer = window_buffer_read;

	/*
	 * If seek fails for new_offset = 0 (we just opened the file),
	 * it is probably a small file on a special file system
	 * that supports reading but does not support seeking.
	 * Allow to continue in this case.
	 */
	offset = lseek(fd, new_offset, SEEK_SET);
	if (offset == (off_t)-1) {
		if (new_offset)
			return -1;
		else
			liblog_slog(LOG_WRN, "Coud not seek to offset 0!"
			"Probably special file system, keep reading...");
	}

	window_offset = new_offset;
	window_size = window_size_read;

	while (size_cur < window_size) {
		ret = read(fd, window_buffer + size_cur, window_size - size_cur);
		if (ret < 0)
			return -1;
		if (!ret)
			break;
		size_cur += ret;
	}

	window_size = size_cur;

	return ret;
}

/* MMap based File IO */

static uint64_t window_size_mmap = 256 * 1024 * 1024;
static unsigned char *window_buffer_mmap;

/*
 * Advances the file window to new_offset using mmap calls to map a buffer.
 * Automatically unmaps the last mmap call.
 */
static int window_advance_mmap(int fd, uint64_t new_offset)
{
	int ret;
	uint64_t file_size;
	long page_size;
	struct stat stat_buf;

	page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size < 0)
		liblog_logen(LOG_FTL, errno, "Failed to get page size!");

	window_buffer = NULL;

	/* Clear out mapping errors on new files */
	if (!new_offset && window_buffer_mmap == MAP_FAILED)
		window_buffer_mmap = NULL;

	/* Go to failover if mapping has failed on this file before */
	if (window_buffer_mmap == MAP_FAILED)
		return window_advance_read(fd, new_offset);

	if (window_buffer_mmap) {
		munmap(window_buffer_mmap, window_size);
		window_buffer_mmap = NULL;
	}

	/* We can only mmap if offset is a multiple of the page size */
	new_offset -= new_offset % page_size;

	/* fstat to get filesize */
	ret = fstat(fd, &stat_buf);
	if (ret < 0)
		return -1;

	file_size = stat_buf.st_size;

	/* If the file is now smaller than new_offset return EOF */
	if (file_size <= new_offset) {
		window_size = 0;
		return 0;
	}

	if (file_size - new_offset <= window_size_mmap) {
		/* EOF */
		window_size = file_size - new_offset;
		ret = 0;
	} else {
		window_size = window_size_mmap;
		ret = 1;
	}

	window_buffer_mmap = mmap(NULL, window_size, PROT_READ,
					MAP_PRIVATE, fd, new_offset);

	/* Go to failover if mapping the file failed */
	if (window_buffer_mmap == MAP_FAILED)
		return window_advance_read(fd, new_offset);

	window_buffer = window_buffer_mmap;
	window_offset = new_offset;
	return ret;
}

/*
 * This function should return -1 and set errno if it fails to read from the
 * file, return 0 on EOF, and return positive integer in case of success.
 * In case of success, window_offset and window_size should be set properly
 * as they are used outside of this function.
 */
static int (*window_advance)(int fd, uint64_t new_offset) = window_advance_read;

/*
 * Advances the window and shows the throughput.
 */
static int window_advance_throughput(int fd, uint64_t new_offset)
{
	static uint64_t prev_offset;
	static uint64_t prev_byte_count;
	static uint64_t prev_file_count;
	static time_t last_printed_time;
	static time_t cur_time;
	static time_t start_time;

	if (!start_time) {
		start_time = time(NULL);
		cur_time = time(NULL);
		last_printed_time = time(NULL);
	}

	if (new_offset) {
		/* this file was read before */
		byte_count += (new_offset - prev_offset);
		cur_time = time(NULL);

		if (cur_time - last_printed_time > 5) {
			liblog_slog(LOG_INF,
			 "InstThroughput: %" PRIu64 " MB/sec %"
							 PRIu64 " files/sec "
			 "AggrThroughput: %" PRIu64 " MB/sec %"
							 PRIu64 " files/sec",
			 (byte_count - prev_byte_count) / 1024 / 1024 /
						(cur_time - last_printed_time),
			 (file_count - prev_file_count) /
					(cur_time - last_printed_time),
			 byte_count / 1024 / 1024 / (cur_time - start_time),
			 file_count / (cur_time - start_time));

			last_printed_time = time(NULL);
			prev_byte_count = byte_count;
			prev_file_count = file_count;
		}
	}

	prev_offset = new_offset;

	return window_advance(fd, new_offset);
}

/************************** FIXED CHUNKING RELATED ****************************/

static char fixed_chnk_help_msg[] = "\tcsize=<csize>\n"
				"\ttails=<on|off>";

struct fixed_chnk_params {
	int csize;
	int tails;
};

static struct fixed_chnk_params fixed_chnk_defaults =
{
	.csize = 4096,
	.tails = 1
};

static int fixed_chnk_init(char *params_str, void **params,
			struct hashfile_handle *handle)
{
	char *token;
	char *param;
	char *value;
	struct fixed_chnk_params *fc_params;
	struct fixed_chnking_params hfile_params;
	int ret;

	fc_params = malloc(sizeof(struct fixed_chnk_params));
	if (!fc_params)
		return -1;

	*fc_params = fixed_chnk_defaults;
	*params = (void *)fc_params;

	if (!params_str)
		goto noparams;

	token = strtok(params_str, CHNK_PARAM_DELIMS);
	do {
		param = token;
		value = strchr(token, CHNK_PARAM_PV_DELIM);
		if (!value)
			goto error;
		*value = '\0';
		value++;

		if (!strcmp(param,"csize"))
			fc_params->csize = atoi(value);
		else if (!strcmp(param, "tails")) {
			if (!strcmp(value, "on"))
				fc_params->tails = 1;
			else if (!strcmp(value, "off"))
				fc_params->tails = 0;
			else
				goto error;
		} else
			goto error;

		token = strtok(NULL, CHNK_PARAM_DELIMS);
	} while (token);

noparams:

	if (fc_params->csize <= 0)
		goto error;

	/* updating the hash file header */
	hfile_params.chunk_size = fc_params->csize;
	ret = hashfile_set_fxd_chnking_params(handle, &hfile_params);
	if (ret < 0)
		goto error;

	return 0;

error:
	free(fc_params);
	return -1;
}

static unsigned char *fixed_chnk_get_next_chunk(void *params,
						unsigned char *buffer,
						uint64_t buffer_size,
						int eof,
						int64_t *chnk_size)
{
	struct fixed_chnk_params *fc_params;

	fc_params = (struct fixed_chnk_params *)params;

	if (buffer_size < fc_params->csize) {
		if (eof && fc_params->tails) {
			/* At EOF, hash the tail */
			*chnk_size = buffer_size;
			return buffer;
		} else {
			/* Need more data, or we don't hash tails */
			*chnk_size = 0;
			return NULL;
		}
	}

	*chnk_size = fc_params->csize;
	return buffer;
}

/************************ VARIABLE CHUNKING RELATED **************************/

/* Internal parameters */
struct var_chnk_params {
	int win_size;
	int match_bits;
	int pattern;
	int min_csize;
	int max_csize;
	int (*match_method)(unsigned char *buf, int size,
				struct var_chnk_params *vc_params);
	int tails;
	uint64_t mask;
	uint64_t polynomial_tables[256];
};

/* Just declarations that make compiler happy */
static int var_chnk_rabin_match(unsigned char *buf, int size,
				 struct var_chnk_params *vc_params);

static char var_chnk_help_msg[] = "\t[:algo=<random|simple|rabin]\n"
"\t[:win_size=<window size>]\n"
"\t[:match_bits=<no of bits to check in the fingerprint>]\n"
"\t[:pattern=<pattern of bits to match>]\n"
"\t[:min_csize=<csize>][:max_csize=<csize>]\n"
"\t[:tails=<on|off>]";

/* Default values for parameters provided by users */
static struct var_chnk_params var_chnk_defaults = {
	.win_size = 48,
	.match_bits = 13,
	.pattern = 0x1fff,
	.min_csize = 2048,
	.max_csize = 16384,
	.match_method = var_chnk_rabin_match,
	.tails = 1
};

/* Rabin fingerprinting constants */
#define PRIME	((uint64_t)1048583)
#define M	((uint64_t)(1 << 30))

/*
 * Calculate (a^p) mod m.
 * This is a naive algorithm, but it is only used once.
 */
static uint64_t pwrmod(uint64_t a, unsigned int p, uint64_t m)
{
	uint64_t result = 1;
	unsigned int i;

	for (i = 0; i < p; i++)
		result = ((result % m) * (a % m)) % m;

	return result;
}

/*
 * Precalculate all values of [t * PRIME^(win_size - 1) mod M] since they
 * will be needed for calculating the value of the rolling polynomial for
 * rabin fingerprinting.
 */
static int var_chnk_compute_table(struct var_chnk_params *vc_params)
{
	uint64_t result;
	int t;

	/*
	 * Verify that PRIME and M are small enough to perform all calculations
	 * in a 64-bit unsigned integer. If (255 * PRIME * M) >= 2^64, then
	 * the calculations might roll over and not be valid.
	 */
	assert((UINT64_MAX / PRIME / M) >= 1);

	result = pwrmod(PRIME, vc_params->win_size - 1, M);

	for (t = 0; t < 256; t++)
		vc_params->polynomial_tables[t] = (t * result) % M;

	return 0;
}

/*
 * Calculate rolling rabin fingerprint:
 *
 * F1 = ((p * (p * (p * t1) + t2) + t3) + t4) % M and then
 * F2 = (p * F1 + t5 - (t1 * (p ^ 3))) % M
 *
 */
static int var_chnk_rabin_match(unsigned char *buf, int size,
				struct var_chnk_params *vc_params)
{
	int i;
	int j;
	int start = 0;
	uint64_t fprt = 0;

	if (size < vc_params->min_csize)
 		return 0;

	if (vc_params->min_csize > vc_params->win_size)
		start = vc_params->min_csize - vc_params->win_size;

	/* calculate original polynomial */
	for (j = 0; j < vc_params->win_size; j++)
		fprt = (PRIME * fprt + buf[start + j]) % M;

	if ((fprt & vc_params->mask) == (vc_params->pattern & vc_params->mask))
		return start + vc_params->win_size;

	/* slide the window */
	for (i = start + 1; i <= size - vc_params->win_size &&
		 	i < vc_params->max_csize - vc_params->win_size; i++) {
		fprt -= vc_params->polynomial_tables[(uint8_t)buf[i - 1]];
		fprt = (fprt * PRIME);
		fprt = (fprt + buf[i + vc_params->win_size - 1]) % M;

		if ((fprt & vc_params->mask) ==
				(vc_params->pattern & vc_params->mask))
			return i + vc_params->win_size;
	}

	/* Check if we need more data */
	if (i + vc_params->win_size == size + 1)
		return 0;

	/* Reached max chunk size, just return it */
	if (i == vc_params->max_csize - vc_params->win_size)
		return vc_params->max_csize;

	/* If we are here, we overran the end of the buffer! */
	assert(0);
	return -1;
}

static int var_chnk_simple_match(unsigned char *buf, int size,
			 	 struct var_chnk_params *vc_params)
{
	int i;
	int bytes_to_look_at = vc_params->match_bits / 8 +
				 ((vc_params->match_bits % 8) ? 1 : 0);
	uint64_t slider;

	if (size < vc_params->min_csize)
		return 0;

	/* We do not support more than 64 bits */
	if (bytes_to_look_at > 8)
		return -1;

	assert(vc_params->min_csize >= bytes_to_look_at);

	for (i = vc_params->min_csize - bytes_to_look_at;
			 i <= size - bytes_to_look_at
				 && i < vc_params->max_csize - bytes_to_look_at;
							 i++) {
		slider = (*(uint64_t *)(buf + i));
		if ((slider & vc_params->mask) ==
				(vc_params->pattern & vc_params->mask))
			return i + bytes_to_look_at;
	}

	/* Check if we need more data */
	if (i + bytes_to_look_at == size + 1)
		return 0;

	/* Reached max chunk size, just return it */
	if (i == vc_params->max_csize - bytes_to_look_at)
		return vc_params->max_csize;

	/* If we are here, we overran the end of the buffer! */
	assert(0);
	return -1;
}

static int var_chnk_random_match(unsigned char *buf_unused, int size,
				 struct var_chnk_params *vc_params)
{
	int i;
	int rnd;

	if (size < vc_params->min_csize)
		return 0;

	for (i = vc_params->min_csize; (i <= size) &&
					(i < vc_params->max_csize); i++) {
		/* rnd will be in the [0;2^match_bits) range */
		rnd = ((double)random() / RAND_MAX) * (vc_params->mask + 1);
		if (rnd == (vc_params->pattern & vc_params->mask))
			return i;
	}

	/* Check if we need more data */
	if (i == size + 1)
		return 0;

	/* Reached max chunk size, just return it */
	if (i == vc_params->max_csize)
		return vc_params->max_csize;

	/* If we are here, we overran the end of the buffer! */
	assert(0);
	return -1;
}

static int var_chnk_init(char *params_str, void **params,
			 struct hashfile_handle *handle)
{
	char *token;
	char *param;
	char *value;
	struct var_chnk_params *vc_params;
	struct var_chnking_params hfile_params;
	int ret;

	vc_params = malloc(sizeof(struct var_chnk_params));
	if (!vc_params)
		return -1;

	*vc_params = var_chnk_defaults;
	*params = (void *)vc_params;
	hfile_params.algo = RABIN;

	if (!params_str)
		goto noparams;

	token = strtok(params_str, CHNK_PARAM_DELIMS);
	do {
		param = token;
		value = strchr(token, CHNK_PARAM_PV_DELIM);
		if (!value)
			goto error;
		*value = '\0';
		value++;

		if (!strcmp(param, "min_csize"))
			vc_params->min_csize = atoi(value);
		else if (!strcmp(param, "max_csize"))
			vc_params->max_csize = atoi(value);
		else if (!strcmp(param, "pattern"))
			vc_params->pattern = strtol(value, NULL, 16);
		else if (!strcmp(param, "win_size"))
			vc_params->win_size = atoi(value);
		else if (!strcmp(param, "match_bits"))
			vc_params->match_bits = atoi(value);
		else if (!strcmp(param, "algo")) {
			if (!strcmp(value, "random")) {
				vc_params->match_method =
					var_chnk_random_match;
				hfile_params.algo = RANDOM;
			} else if (!strcmp(value, "simple")) {
				vc_params->match_method =
					var_chnk_simple_match;
				hfile_params.algo = SIMPLE_MATCH;
			} else if (!strcmp(value, "rabin")) {
				vc_params->match_method =
					var_chnk_rabin_match;
				hfile_params.algo = RABIN;
			} else
				goto error;
		} else if (!strcmp(param, "tails")) {
			if (!strcmp(value, "on"))
				vc_params->tails = 1;
			else if (!strcmp(value, "off"))
				vc_params->tails = 0;
			else
				goto error;
		} else
			goto error;

		token = strtok(NULL, CHNK_PARAM_DELIMS);
	} while (token);

noparams:

	if (vc_params->max_csize < vc_params->min_csize)
		goto error;

	vc_params->mask = (1 << vc_params->match_bits) - 1;

	/* Computing tables for Rabin fingerprints */
	if (vc_params->match_method == var_chnk_rabin_match)
		if (var_chnk_compute_table(vc_params) < 0)
			goto error;

	/* updating the hash file header */
	hfile_params.min_csize = vc_params->min_csize;
	hfile_params.max_csize = vc_params->max_csize;

	switch(hfile_params.algo) {
	case RANDOM:
		hfile_params.algo_params.rnd_params.probability =
							1.0 / vc_params->mask;
		break;
	case SIMPLE_MATCH:
		hfile_params.algo_params.simple_params.pattern =
							vc_params->pattern;
		hfile_params.algo_params.simple_params.bits_to_compare =
							vc_params->match_bits;
		break;
	case RABIN:
		hfile_params.algo_params.rabin_params.window_size =
							vc_params->win_size;
		hfile_params.algo_params.rabin_params.prime =
							PRIME;
		hfile_params.algo_params.rabin_params.module =
							M;
		hfile_params.algo_params.rabin_params.bits_to_compare =
							vc_params->match_bits;
		hfile_params.algo_params.rabin_params.pattern =
							vc_params->pattern;
		break;
	default:
		assert(0);
	}

	ret = hashfile_set_var_chnking_params(handle, &hfile_params);
	if (ret < 0)
		goto error;

	return 0;

error:
	free(vc_params);
	return -1;
}

static unsigned char *var_chnk_get_next_chunk(void *params,
					unsigned char *buffer,
					uint64_t buffer_size,
					int eof,
					int64_t *chnk_size)
{
	struct var_chnk_params *vc_params;

	vc_params = (struct var_chnk_params *)params;

	*chnk_size = vc_params->match_method(buffer, buffer_size, vc_params);
	if (*chnk_size < 0) {
		/* Chunking error */
		*chnk_size = -1;
		return NULL;
	}

	if (!*chnk_size) {
		/* EOF or need more data */
		if (eof && vc_params->tails) {
			*chnk_size = buffer_size;
			return buffer;
		}
		return NULL;
	}

	return buffer;
}

/************************** SHA256 HASHING RELATED ****************************/

#ifdef SHA256_SUPPORTED
static int sha256_compute_hash(unsigned char *buffer, int buffersz,
				 unsigned char *hash)
{
	SHA256(buffer, buffersz, hash);
	return 0;
}
#endif

/**************************** MD5 HASHING RELATED *****************************/

#ifdef MD5_SUPPORTED
static int md5_compute_hash(unsigned char *buffer, int buffersz,
				 unsigned char *hash)
{
	MD5(buffer, buffersz, hash);
	return 0;
}
#endif

/************************** MD5-48BIT HASHING RELATED *************************/

#ifdef MD5_SUPPORTED
static int md5_48bit_compute_hash(unsigned char *buffer, int buffersz,
					 unsigned char *hash)
{
	unsigned char md5full[128 / 8];

	MD5(buffer, buffersz, md5full);

	memcpy(hash, md5full, 48 / 8);

	return 0;
}

static int md5_64bit_compute_hash(unsigned char *buffer, int buffersz,
					 unsigned char *hash)
{
	unsigned char md5full[128 / 8];

	MD5(buffer, buffersz, md5full);

	memcpy(hash, md5full, 64 / 8);

	return 0;
}
#endif

/*************************** MURMUR HASHING RELATED ***************************/

static int murmur_compute_hash(unsigned char *buffer, int buffersz,
					 unsigned char *hash)
{
	#define MURMUR_SEED 0xABCDEF
	MurmurHash3_x64_128(buffer, buffersz, MURMUR_SEED, hash);
	#undef MURMUR_SEED

	return 0;
}


/*************************** NONE COMPRESS RELATED ****************************/

uint8_t none_compute_cratio(unsigned char *buffer, int buffersz)
{
	return 10;
}

/************************* ZLIB-DEF COMPRESS RELATED **************************/

#ifdef ZLIB_SUPPORTED
uint8_t zlib_def_compute_cratio(unsigned char *buffer, int buffersz)
{
	int ret;
	z_stream strm;
	#define COMPRESSED_BUFFER_SIZE (1024 * 1024)
	char compressed[COMPRESSED_BUFFER_SIZE];
	#undef COMPRESSED_BUFFER_SIZE
	unsigned int compressedsz = 0;
	unsigned int cratio;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;

	deflateInit(&strm, Z_DEFAULT_COMPRESSION);
	if (ret != Z_OK)
		return 0;

	strm.avail_in = buffersz;
	strm.next_in = buffer;

	do {
		strm.avail_out = sizeof(compressed);
		strm.next_out = compressed;

		ret = deflate(&strm, Z_FINISH);
		assert(ret != Z_STREAM_ERROR);	/* state not clobbered */

		compressedsz += sizeof(compressed) - strm.avail_out;
	} while (strm.avail_out == 0);

	assert(strm.avail_in == 0);	/* all input should be used */

	(void)deflateEnd(&strm);

	cratio = (buffersz * 10) / compressedsz;

	return cratio < (sizeof(uint8_t) * 255) ? (uint8_t)cratio :  255;
}
#endif	

/************************** GENERIC CHUNKING API ******************************/

#define CHUNKING_METHOD_NAME_MAX_LEN	256

struct chunking_method {
	char name[CHUNKING_METHOD_NAME_MAX_LEN];
	enum chnking_method hashfile_chnk_meth_id;
	int (*init)(char *params_str, void **params,
				 struct hashfile_handle *handle);
	char *help_msg;
	/*
	 * get_next_chunk() returns a pointer to
	 * the buffer with a fresh chunk. This pointer
	 * becomes INVALID after next get_next_chunk() call.
	 * get_next_chunk() returns NULL if an error occured
	 * or more data is needed. If error has happened,
	 * *chnk_size is set to negative value. The parameter
	 * eof indicates that no more data is avalible to
	 * allow get_next_chunk to process the tail of a file
	 * instead of asking for more data.
	 */
	unsigned char *(*get_next_chunk)(void *params, unsigned char *buffer,
					 uint64_t buffer_size, int eof,
					 int64_t *chnk_size);
};

struct chunking_method chnk_methods[] = {
	{
		.name = "fixed",
		.hashfile_chnk_meth_id = FIXED,
		.init = fixed_chnk_init,
		.help_msg = fixed_chnk_help_msg,
		.get_next_chunk = fixed_chnk_get_next_chunk
	},
	{	.name = "variable",
		.hashfile_chnk_meth_id = VARIABLE,
		.init = var_chnk_init,
		.help_msg = var_chnk_help_msg,
		.get_next_chunk = var_chnk_get_next_chunk
	}
};

/*************************** GENERIC HASHING API ******************************/

#define HASHING_METHOD_NAME_MAX_LEN	256

struct hashing_method {
	char name[HASHING_METHOD_NAME_MAX_LEN];
	int hash_size; /* in bits */
	enum hshing_method hashfile_hsh_meth_id;
	int (*compute_hash)(unsigned char *buffer, int buffersz,
					 unsigned char *hash);
};

struct hashing_method hash_methods[] = {
#ifdef SHA256_SUPPORTED
	{
		.name = "sha256",
		.hash_size = 256,
		.hashfile_hsh_meth_id = SHA256_HASH,
		.compute_hash = sha256_compute_hash,
	},
#endif
#ifdef MD5_SUPPORTED
	{
		.name = "md5",
		.hash_size = 128,
		.hashfile_hsh_meth_id = MD5_HASH,
		.compute_hash = md5_compute_hash,
	},
	{
		.name = "md5-48bit",
		.hash_size = 48,
		.hashfile_hsh_meth_id = MD5_48BIT_HASH,
		.compute_hash = md5_48bit_compute_hash,
	},
	{
		.name = "md5-64bit",
		.hash_size = 64,
		.hashfile_hsh_meth_id = MD5_64BIT_HASH,
		.compute_hash = md5_64bit_compute_hash,
	},
#endif
	{
		.name = "murmur",
		.hash_size = 128,
		.hashfile_hsh_meth_id = MURMUR_HASH,
		.compute_hash = murmur_compute_hash,
	}
};

/************************** GENERIC COMPRESS API ******************************/

#define COMPRESS_METHOD_NAME_MAX_LEN	256

struct compress_method {
	char name[COMPRESS_METHOD_NAME_MAX_LEN];
	enum cmpr_method hashfile_compress_meth_id;
	uint8_t (*compute_cratio)(unsigned char *buffer, int buffersz);
};

struct compress_method comp_methods[] = {
#ifdef ZLIB_SUPPORTED
	{
		.name = "zlib-def",
		.hashfile_compress_meth_id = ZLIB_DEF,
		.compute_cratio = zlib_def_compute_cratio,
	},
#endif
	{
		.name = "none",
		.hashfile_compress_meth_id = NONE,
		.compute_cratio = none_compute_cratio,
	}
};

/*************************** DEDUP METHOD STRUCT ******************************/

struct dedup_method {
	struct chunking_method *chnk_method;
	void *chnk_params;
	struct hashing_method *hash_method;
	struct compress_method *comp_method;
	/*
	 * Position of the next chunk in the file to read
	 * for this dedup method.
	 */
	uint64_t offset;
	uint64_t chunk_count;
	struct hashfile_handle *hfhandle;
	struct dedup_method *next;
};

struct dedup_method *dedup_methods;

/********************************* MAIN PART *********************************/

static void usage()
{
	int i;

	printf("Usage:\n");

	printf("%s [-mdqMe] -p <path> {-c <fixed|variable>"
			" [-C <chunking options>]"
			" -h <murmur"
#ifdef MD5_SUPPORTED
			"|md5|md5-64bit|md5-48bit"
#endif
#ifdef SHA256_SUPPORTED
			"|sha256"
#endif
			"> -z <none"
#ifdef ZLIB_SUPPORTED
			"|zlib-def"
#endif
			">  -o <hashfile> | -F <configfile>}\n",
		 	progname);
	printf("-m tells the dedup engine to not to follow any mount "
		"points encountered during the tree walk. If not specified, "
		"mount points within tree will be traversed.\n");
	printf("-d enables debug mode\n");
	printf("-q enables quite mode\n");
	printf("-M use mmap to read files\n");
	printf("-e exit if open returns ENOENT instead of running furher\n");
	printf("-F reads multi-method configuration from <configfile>.\n"
		"Each line of this file behaves like the command line.\n"
		"Global options such as -p, -e, -m, -d, -q, and -F "
		"are ignored. Lines starting with # and empty lines "
		"will be skipped.\n");
	for (i = 0; i < sizeof(chnk_methods) /
				 sizeof(struct chunking_method); i++) {
		printf("%s chunking options:\n%s\n", chnk_methods[i].name,
					 chnk_methods[i].help_msg);
	}
}

static void display_progress(const char *file_name, uint64_t so_far,
				uint64_t size)
{
	liblog_slog(LOG_INF, "Processing file %s: %3lu%%", file_name,
				 size ? (so_far * 100) / size : 0);
}

/*
 * Returns the dedup_method with the lowest offset, or NULL if they all have
 * processed the entire file (this happens if all dedup methods
 * set dedup->offset to UINT64_MAX).
 */
static struct dedup_method *get_next_dedup_method()
{
	struct dedup_method *next_dedup = NULL;
	struct dedup_method *dedup;
	uint64_t lowest_offset = UINT64_MAX;

	for (dedup = dedup_methods; dedup != NULL; dedup = dedup->next) {
		if (dedup->offset < lowest_offset) {
			lowest_offset = dedup->offset;
			next_dedup = dedup;
		}
	}

	return next_dedup;
}

static int is_processable(const char *file_name,
			const struct stat *stat_buf, int flag)
{
	/*
	 * If it is a directory, we don't process it, just print a message
	 * and return.
	 */
	if (S_ISDIR(stat_buf->st_mode)) {
		if (flag == FTW_DNR)
			liblog_slog(LOG_WRN,
				 "Directory is not readable: %s", file_name);
		else
			liblog_slog(LOG_INF,
				"Processing directory: %s", file_name);

		return 0;
	}

	if (!S_ISREG(stat_buf->st_mode) && !S_ISLNK(stat_buf->st_mode)) {
		liblog_slog(LOG_WRN, "Skipping non-regular "
				"and non-symlink file: %s", file_name);
		return 0;
	}

	return 1;
}

/*
 * For all dedup methods reset the offset of file processed.
 * Add new files to corresponding hash files.
 */
static int prepare_dedups_for_new_file(const char *file_name,
			const struct stat *stat_buf, const char *target_path)
{
	struct dedup_method *cur_dedup;
	int ret;

	for (cur_dedup = dedup_methods;
		cur_dedup != NULL; cur_dedup = cur_dedup->next) {

		cur_dedup->offset = 0;

		ret = hashfile_add_file(cur_dedup->hfhandle,
					 file_name, stat_buf, target_path);
		if (ret < 0) {
			liblog_logn(LOG_FTL, errno,
				 "Error adding file to a hash file!");
			return -1;
		}
	}

	return 0;
}

static int process_file(const char *file_name, const struct stat *stat_buf,
			int flag, struct FTW *ftwbuf)
{
	int fd = 0;
	int ret;
	struct chunk_info ci;
	unsigned char hash[MAX_HASH_SIZE];
	unsigned char *chunk;
	uint64_t file_processed_so_far = 0;
	int64_t chunk_size;
	time_t prev_time;
	struct dedup_method *cur_dedup;
	int buffer_eof = 0;
	uint64_t buffer_offset;
	char target_path[MAX_PATH_SIZE];
	int target_path_len;
	int cratio;

	if (!is_processable(file_name, stat_buf, flag))
		return 0;

	liblog_slog(LOG_INF, "Processing file %s", file_name);

	/*
	 * We want to open (or readlink) a file before calling
	 * prepare_dedups_for_new_file(), so that no entry appears
	 * in the hash file if the open call fails.
	 */
	if (S_ISLNK(stat_buf->st_mode)) {
		target_path_len = readlink(file_name,
				target_path, sizeof(target_path));
		if (target_path_len < 0) {
			liblog_logn(LOG_ERR, errno,
				"Could not read symlink's target!");
			if (errno == ENOENT && exit_on_error) {
				/*
				 * It's a clear sign that somebody changes the
				 * file * system while we perform its scan.
				 * Not nice from  their side at all...
				 *
				 * Specifically, it was a problem when scanning
				 * snapshots created by the MacOS Time Machine.
				 * 
				 * If we're in the "exit on error" mode, then
				 * exit immediatelly.
				 */
				return -1;
			}

			/*
			 * We want to continue processing other files, so return 0
			 * so that ntfw keeps working.
			 */
			return 0;

		} else
			target_path[target_path_len] = '\0';
	} else {
		fd = open(file_name, O_RDONLY);
		if (fd < 0) {
			liblog_logn(LOG_ERR, errno,
				"Error opening file %s!", file_name);
			if (errno == ENOENT && exit_on_error) {
				/*
				 * It's a clear sign that somebody changes the
				 * file * system while we perform its scan.
				 * Not nice from  their side at all...
				 *
				 * Specifically, it was a problem when scanning
				 * snapshots created by the MacOS Time Machine.
				 *
				 * If we're in the "exit on error" mode, then
				 * exit immediatelly.
				 */
				return -1;
			}

			/*
			 * We want to continue processing other files, so return 0
			 * so that ntfw keeps working.
			 */
			return 0;
		}
	}

	ret = prepare_dedups_for_new_file(file_name, stat_buf, target_path);
	if (ret < 0)
		return -1;

	file_count++;

	/* Do not calculated hashes for a symlink */
	if (S_ISLNK(stat_buf->st_mode)) {
		symlink_count++;
		goto out;
	}

	ret = window_advance_throughput(fd, 0);
	if (ret < 0) {
		liblog_logen(LOG_FTL, errno, "Error reading the file!");
	} else if (!ret)
		buffer_eof = 1;

	prev_time = time(NULL);

	while ((cur_dedup = get_next_dedup_method())) {
		/*
		 * Calculate the offset between the begining of the file
		 * window and the current dedup method's file cursor.
		 */
		buffer_offset = cur_dedup->offset - window_offset;
		assert(cur_dedup->offset >= window_offset);

		/* Stage 1: chunk */
		if (buffer_offset < window_size)
			chunk = cur_dedup->chnk_method->get_next_chunk(
						cur_dedup->chnk_params,
						window_buffer + buffer_offset,
						window_size - buffer_offset,
						buffer_eof, &chunk_size);
		else if (buffer_offset == window_size) {
			/*
			 * If it happens so, that in previous iteration for
			 * this dedup method we ended right at the end of the
			 * window, we just need to advance the window.
			 */
			chunk = NULL;
			chunk_size = 0;
		} else
			assert(0);

		if (!chunk) {
			/* error, EOF, or need more data */
			if (chunk_size < 0) 
				/* definitely an error */
				liblog_sloge(LOG_FTL,
					 "Error while getting next chunk!");
			if (buffer_eof) {
				/*
				 * Set offset to UINT64_MAX to indicate
				 * to get_next_dedup_method that this method
				 * is finished with the file.
				 */
				cur_dedup->offset = UINT64_MAX;
			} else {
				/* Advance file window and try again */
				ret = window_advance_throughput(fd,
							 cur_dedup->offset);
				if (ret < 0) {
					liblog_logen(LOG_FTL, errno,
						"Error reading the file!");
				} else if (!ret)
					buffer_eof = 1;
			}
			continue;
		}

		/* Maintain dedup method's file cursor. */
		cur_dedup->offset += chunk_size;

		/* Stage 2: hash */
		ret = cur_dedup->hash_method->compute_hash(chunk,
							chunk_size, hash);
		if (ret < 0)
			liblog_sloge(LOG_FTL, "Could not compute hash!");

		/* Stage 3: compute compress ratio */
		cratio = cur_dedup->comp_method->compute_cratio(chunk,
								chunk_size);
		if (cratio < 0)
			liblog_sloge(LOG_FTL, "Could not compute"
							" compress ratio!");

		/* Write the hash to hashfile */
		ci.size = chunk_size;
		ci.hash = hash;
		ci.cratio = cratio;
		ret = hashfile_add_chunk(cur_dedup->hfhandle, &ci);
		if (ret < 0)
			liblog_sloge(LOG_FTL, "Could not add hash to a file!");

		/* updating statistics */
		cur_dedup->chunk_count++;
		file_processed_so_far = cur_dedup->offset;

		/* Display progress every 5 seconds */
		if (time(NULL) - prev_time > 5) {
			display_progress(file_name, file_processed_so_far,
					 stat_buf->st_size);
			prev_time = time(NULL);
		}
	}

	close(fd);

out:

	liblog_slog(LOG_INF, "Done!");

	return 0;
}

/*
 * Initialize a dedup_method from supplied parameters.
 * On error, returns -1 and logs the message.
 */
int init_dedup_method(struct dedup_method *dedup,
			char *chnk_method_str, char *chnk_method_params_str,
			char *hash_method_str, char *comp_method_str,
			char *hashfile_name)
{
	int i;
	int ret;

	if (!chnk_method_str) {
		liblog_slog(LOG_FTL, "Specify chunking method (-c argument)!");
		return -1;
	}

	for (i = 0; i < sizeof(chnk_methods) /
				 sizeof(struct chunking_method); i++) {
		if (!strcmp(chnk_methods[i].name, chnk_method_str)) {
			dedup->chnk_method = &chnk_methods[i];
			break;
		}
	}

	if (!dedup->chnk_method) {
		liblog_slog(LOG_FTL, "Chunking method \'%s\' "
				"is not supported!", chnk_method_str);
		return -1;
	}

	if (!hash_method_str) {
		liblog_slog(LOG_FTL, "Specify hashing method (-h argument)!");
		return -1;
	}

	for (i = 0; i < sizeof(hash_methods) /
			sizeof(struct hashing_method); i++) {
		if (!strcmp(hash_methods[i].name, hash_method_str)) {
			dedup->hash_method = &hash_methods[i];
			break;
		}
	}

	if (!dedup->hash_method) {
		 liblog_slog(LOG_FTL, "Hashing method \'%s\' "
				"is not supported!", hash_method_str);
		return -1;
	}

	if (!comp_method_str) {
		liblog_slog(LOG_FTL, "Specify compress method (-z argument)!");
		return -1;
	}

	for (i = 0; i < sizeof(comp_methods) /
			sizeof(struct compress_method); i++) {
		if (!strcmp(comp_methods[i].name, comp_method_str)) {
			dedup->comp_method = &comp_methods[i];
			break;
		}
	}

	if (!dedup->comp_method) {
		 liblog_slog(LOG_FTL, "Compress method \'%s\' "
				"is not supported!", comp_method_str);
		return -1;
	}

	if (!hashfile_name) {
		liblog_slog(LOG_FTL, "Specify hash file (-o argument)!");
		return -1;
	}

	dedup->hfhandle = hashfile_open4write(hashfile_name,
		dedup->chnk_method->hashfile_chnk_meth_id,
		dedup->hash_method->hashfile_hsh_meth_id,
		dedup->hash_method->hash_size, root_path);
	if (!dedup->hfhandle) {
		liblog_logn(LOG_FTL, errno,
				"Could not create hash file!");
		return -1;
	}

	ret = dedup->chnk_method->init(chnk_method_params_str,
						&dedup->chnk_params,
						dedup->hfhandle);
	if (ret < 0) {
		liblog_slog(LOG_FTL, "Error while initializing chunking!");
		liblog_slog(LOG_FTL, "Make sure that chunking parameters "
				"(-C argument) are well-formed.");
		liblog_slog(LOG_FTL, "%s chunking params:\n%s",
			dedup->chnk_method->name,
			dedup->chnk_method->help_msg);
		return -1;
	}

	return 0;
}

/* Reads a configuration from the command line. Returns -1 on error. */
int config_dedup_method(int argc, char **argv)
{
	struct dedup_method *dedup;
	char *chnk_method_str = NULL;
	char *chnk_method_params_str = NULL;
	char *hash_method_str = NULL;
	char *comp_method_str = NULL;
	char *hashfile_name = NULL;
	int opt;

	optind = 1;
	opterr = 0;

	/* Process dedup method command line parameters */
	while (1) {
		opt = getopt(argc, argv, GETOPT_OPTIONS);
		if (opt == -1)
			break;

		switch(opt) {
		case 'c':
			chnk_method_str = optarg;
			break;
		case 'C':
			chnk_method_params_str = optarg;
			break;
		case 'h':
			hash_method_str = optarg;
			break;
		case 'z':
			comp_method_str = optarg;
			break;
		case 'o':
			hashfile_name = optarg;
			break;
		case '?':
			liblog_slog(LOG_FTL, "Unrecognized parameter %c!",
								(char)optopt);
			return -1;
		default:
			/* Ignore global command line parameters */
			break;
		}
	}

	/*
	 * Allocate a new dedup_method and add it to the list. If
	 * init_dedup_method fails it will leave a broken dedup_method
	 * at the head of the list, but the program will terminate anyways.
	 */
	dedup = calloc(sizeof(struct dedup_method), 1);
	if (!dedup) {
		liblog_slog(LOG_FTL, "Failed to allocate dedup_method!");
		return -1;
	}

	dedup->next = dedup_methods;
	dedup_methods = dedup;

	return init_dedup_method(dedup, chnk_method_str,
			chnk_method_params_str, hash_method_str,
			comp_method_str, hashfile_name);
}

/*
 * Parses a command line from a configuration file into an argv array
 * and calls config_dedup_method. Returns -1 on error. This does not handle
 * quoted spaces or any escaped characters like the command line usallly does.
 */
int parse_config_line(char *line) {
	int argc = 1;
	char *argv[48];

	argv[0] = progname;
	argv[argc] = strtok(line, " \t\r\n");
	while (argv[argc]) {
		argc++;
		if (argc >= (sizeof(argv) / sizeof(char *))) {
			liblog_slog(LOG_FTL, "Too many parameters!");
			return -1;
		}
		argv[argc] = strtok(NULL, " \t\r\n");
	}

	return config_dedup_method(argc, argv);
}

/* Load deduplication methods from a configuration file. */
int load_config_file(char *config_file_str)
{
	FILE *f;
	char line_buffer[1024];
	int ret = 0;
	int lineno = 0;

	f = fopen(config_file_str, "r");
	if (!f) {
		liblog_logn(LOG_FTL, errno, "Error opening configuration file!");
		return -1;
	}

	while (fgets(line_buffer, sizeof(line_buffer), f)) {
		lineno++;

		if (!strlen(line_buffer) || line_buffer[0] == '#')
			continue;

		if (parse_config_line(line_buffer)) {
			liblog_slog(LOG_FTL,
				"Error parsing line %d of configuration!",
				lineno);
			ret = -1;
			break;
		}
	}

	/* Check if there was an error or we just hit EOF */
	if (ferror(f)) {
		liblog_logn(LOG_FTL, ferror(f),
					"Error reading configuration file.");
		ret = -1;
	}

	fclose(f);

	/*
	 * This can happen, if config file is empty
	 * or contains only comments.
	 */
	if (!dedup_methods) {
		liblog_slog(LOG_FTL, "No deduplication methods specified.");
		ret = -1;
	}

	return ret;
}

/* Output information about a dedup_method to the log. */
void log_dedup_method(struct dedup_method *dedup)
{
	liblog_slog(LOG_DBG, "Chunking method: %s", dedup->chnk_method->name);
	liblog_slog(LOG_DBG,"Hashing method: %s", dedup->hash_method->name);
}

/*
 * main() parses global parameters
 * and calls appropriate initialization
 * routines. It then calls process_file()
 * for each file in the directory.
 */
int main(int argc, char *argv[])
{
	int opt;
	int ret, nftw_ret;
	int flags = 0, do_not_follow_mounts = 0;
	struct dedup_method *cur_dedup;
	char *config_file_str = NULL;

	progname = argv[0];
	opterr = 0;

	/* Process global command line parameters */
	while (1) {
		opt = getopt(argc, argv, GETOPT_OPTIONS);
		if (opt == -1)
			break;

		switch(opt) {
		case 'p':
			root_path_arg = optarg;
			break;
		case 'm':
			do_not_follow_mounts = 1;
			break;
		case 'd':
			liblog_set_log_level(LOG_DBG);
			break;
		case 'q':
			liblog_set_log_level(LOG_ERR);
			break;
		case 'u':
			usage();
			return 0;
		case 'F':
			config_file_str = optarg;
			break;
		case 'M':
			window_advance = window_advance_mmap;
			break;
		case 'e':
			exit_on_error = 1;
			break;
		case '?':
			liblog_slog(LOG_FTL, "Unrecognized parameter %c!",
						(char)optopt);
			usage();
			return -1;
		default:
			/* Ignore deduplication method parameters */
			break;
		}
	}

	/* Validating parameters */
	if (!root_path_arg)
		liblog_sloge(LOG_FTL, "Specify the name of the "
			"file or directory to process (-p argument)!");

	/* Converting relative/symbolic root path to absolute */
	if (!realpath(root_path_arg, root_path))
		liblog_logen(LOG_FTL, errno,
				"Could not canonicalize root path!");

	if (config_file_str) {
		/* Read dedup_methods from config file */
		ret = load_config_file(config_file_str);
	} else {
		/* Use single dedup_method from command line */
		ret = config_dedup_method(argc, argv);
	}

	if (ret < 0) {
		/*
		 * The functions above already print
		 * appropriate error messages.
		 */
		return -1;
	}

	/* Printing out some job information */
	liblog_slog(LOG_DBG, "Job information:");
	liblog_slog(LOG_DBG, "Path: %s", root_path);
	if (config_file_str)
		liblog_slog(LOG_DBG, "Configuration file: %s", config_file_str);
	for (cur_dedup = dedup_methods; cur_dedup != NULL;
				cur_dedup = cur_dedup->next)
		log_dedup_method(cur_dedup);

	/*
	 * traversing the directory.
	 *
	 * Notice, that we check nftw return value AFTER writing the header.
	 * It is done to have a close-to-consistent header even in the event
	 * of failing in the middle of the nftw().
	 */

	/*
	 * Do not follow symlinks.  Instead, when we see a symlink,
	 * we record the target path (not the content).
	 */
	flags = FTW_PHYS;

	if (do_not_follow_mounts)
		flags |= FTW_MOUNT;

	nftw_ret = nftw(root_path, process_file, NFTW_MAX_OPENED_DIRS, flags);
	if (nftw_ret)
		liblog_logn(LOG_FTL, errno,
			 "Failed traversing the directory!");

	printf("Number of files processed: %" PRIu64 "\n", file_count);
	printf("Number of symlinks processed: %" PRIu64 "\n", symlink_count);

	for (cur_dedup = dedup_methods; cur_dedup != NULL;
				cur_dedup = cur_dedup->next) {
		hashfile_close(cur_dedup->hfhandle);

		printf("Deduplication method: %s %s \n",
			cur_dedup->chnk_method->name,
			cur_dedup->hash_method->name);
		printf("Number of chunks processed: %" PRIu64 "\n",
							cur_dedup->chunk_count);
	}

	if (nftw_ret)
		return -1;

	return 0;
}
