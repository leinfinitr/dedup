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
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <libgen.h>
#include <openssl/md5.h>
#include <assert.h>

#define MAXLINE	4096

#include "hashfilelib.h"
#include "fstree.h"

static char *progname;

int empty_fstree;

uint64_t files_processed;

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

static char *get_fstreefile_name(char *hashfile_name)
{
	char *fstreefile_name;
	int len;

	len = strlen(hashfile_name);
	/* 1 for '\0' and 4 for ".fst" */
	fstreefile_name = malloc(len + 1 + 4);
	if (!fstreefile_name) {
		perror("Could not allocate memory for file name!\n");
		exit(-1);
	}

	strcpy(fstreefile_name, hashfile_name);
	strcpy(fstreefile_name + len, ".fst");
	return fstreefile_name;
}

/*
 * We have no information about the directories
 * in the hash file (except of a name).
 * Just fill dir node in fstree with
 * something fake information.
 */
static void fill_dir_info(struct dir *dir, uint64_t name)
{
	struct ugperm ugp;

	ugp.uid = 0;
	ugp.gid = 0;
	/* XXX: looks like rwx is too large */
	ugp.rwx[0] = 0;
	ugp.rwx[1] = 0;
	ugp.rwx[2] = 0;

	dir->name = name;
	dir->ugperm = ugp;
	dir->mtime = 0;
	dir->atime = 0;
	dir->ctime = 0;

	dir->parent = NULL;
	dir->first_childdir = NULL;
	dir->childdirnum = 0;
	dir->first_childfile = NULL;
	dir->childfilenum = 0;
	dir->sibling = NULL;
}

static struct file *lookup_create_file(const char *path, struct fstree *fst)
{
	char *next_dash;
	int is_file;
	unsigned char md5_hash[16];
	uint64_t curname;
	int comp_len;
	struct dir *curparent;
	struct dir *dir_child;
	struct file *file_child;

	if (!fst->root_dir) {
		fst->root_dir = allocate_dir(fst);
		fill_dir_info(fst->root_dir, 0xdeadbeef);
	}

	curparent = fst->root_dir;

repeat:
	/*
	 * path enters this function in a form: "/some/path/file"
	 * (root is already truncated). As we iterate, the path
	 * points to:
	 * 1) /path/file
	 * 2) /file
	 * in order.
	 */

	next_dash = strchr(path + 1, '/');

	if (!next_dash) {
		is_file = 1;
		comp_len = strlen(path + 1);
	} else {
		is_file = 0;
		comp_len = (uint64_t)next_dash - (uint64_t)path - 1;
	}

	MD5((const unsigned char *)(path + 1), comp_len, md5_hash);
	curname = (*((uint64_t *)md5_hash));

	if (!is_file) { /* locate or create a directory */
		/* try to find the directory first */
		dir_child = curparent->first_childdir;
		while (dir_child) {
			if (dir_child->name == curname)
				break;

			dir_child = dir_child->sibling;
		}

		/* create dir if it was not found */
		if (!dir_child) {
			dir_child = allocate_dir(fst);

			fill_dir_info(dir_child, curname);

			dir_child->parent = curparent;
			dir_child->sibling = curparent->first_childdir;
			curparent->first_childdir = dir_child;
			curparent->childdirnum++;
		}

		/*
		 * at this point we have a dir_child, that becomes a new parent
		 */
		curparent = dir_child;
		path += comp_len + 1;
		goto repeat;
	} else {  /* create a file */
		file_child = allocate_file(fst);
		/*
		 * we only fill the fields that can be filled here,
		 * the remaining ones will be filled by the caller.
		 */
		file_child->name = curname;
		file_child->parent = curparent;

		file_child->sibling = curparent->first_childfile;
		curparent->first_childfile = file_child;
		curparent->childfilenum++;

		return file_child;
	}

	assert(0);
	return NULL;
}

static struct file *create_file_in_fstree(struct hashfile_handle *handle,
						struct fstree *fst)
{
	const char *path = hashfile_curfile_path(handle);
	const char *rootpath = hashfile_rootpath(handle);
	int rootlen;

	rootlen = strlen(rootpath);

	if (strncmp(path, rootpath, rootlen)) {
		perror("File path out of the root path scope!");
		exit(-1);
	}

	path += rootlen;
	return lookup_create_file(path, fst);
}

static uint64_t extract_64bit_hash(const struct chunk_info *ci)
{
	uint64_t hash;
	int len_to_copy;

	hash = 0;

	len_to_copy = (ci->size > sizeof(uint64_t)) ?
				sizeof(uint64_t) : ci->size;

	memcpy(&hash, ci->hash, len_to_copy);

	return hash;
}

static void add_chunks_to_file(struct hashfile_handle *handle,
				struct fstree *fst, struct file *f)
{
	struct log_chunk *lch;
	struct log_chunk *prev_lch = NULL;
	const struct chunk_info *ci;
	uint64_t offset;

	offset = 0;
	while (1) {
		ci = hashfile_next_chunk(handle);
		if (!ci)
			break;

		lch = allocate_chunk(fst);
		if (!lch)
			exit(-1);

		lch->phys_id = extract_64bit_hash(ci);
		lch->size = (uint16_t)ci->size;
		lch->offset = offset;
		if (!prev_lch)
			f->first_log_chunk = lch;
		else
			prev_lch->next = lch;

		offset += lch->size;
		prev_lch = lch;
	}
}

static void fill_file_info(struct hashfile_handle *handle, struct file *file)
{
	char *ptr;
	char *path;
	int i;

	path = (char *)hashfile_curfile_path(handle);
	path = basename(path);

	ptr = strrchr(path, '.');
	if (ptr) {
		strncpy(file->extension, ptr + 1, MAX_EXT_LEN);
		file->extension[MAX_EXT_LEN - 1] = '\0';
	} else
		file->extension[0] = '\0';

	/* XXX: hack - our profiles use coma as separator,
		replace them with _ for now */
	for (i = 0; file->extension[i] != '\0'; i++)
		if (file->extension[i] == ',')
			file->extension[i] = '_';

	file->size = hashfile_curfile_size(handle);
	file->mtime =  hashfile_curfile_mtime(handle);
	file->atime = hashfile_curfile_atime(handle);
	file->ctime = hashfile_curfile_mtime(handle);

	file->filestate = FST_NEW;
}

static void process_hashfile(char *hashfile_name)
{
	struct hashfile_handle *handle;
	char *fstreefile_name;
	int fstreefile_fd;
	struct fstree fst;
	struct file *f;
	int ret;

	handle = hashfile_open(hashfile_name);
	if (!handle) {
		perror("Error opening hash file.");
		exit(-1);
	}

	print_hashfile_header(handle);

	ret = create_fstree(&fst);
	if (ret) {
		perror("Error while creating fstree.");
		exit(-1);
	}

	fst.num_files = hashfile_numfiles(handle);
	fst.num_hashes = hashfile_numchunks(handle);
	/*
         * All fstree objects have hash size of 64 bit.
	 * This simplifies our life a little.
	 */
	fst.hash_size = 64;

	/* iterating over the files */
	while (1) {

		if (files_processed % 10000 == 0)
			printf("Files processed: %"PRIu64"/%"PRIu64"\n",
				files_processed, hashfile_numfiles(handle));

		ret = hashfile_next_file(handle);
		if (ret == 0)
			break;
		if (ret < 0) {
			fprintf(stderr, "Error processing hash file.");
			exit(-1);
		}

		/* fstrees do not support symlinks, ommit them */
		if (hashfile_curfile_linkpath(handle))
			continue;

		/* this functions can'f fail, the exit() on errors */
		f = create_file_in_fstree(handle, &fst);
		fill_file_info(handle, f);
		if (!empty_fstree)
			add_chunks_to_file(handle, &fst, f);

		files_processed++;
	}

	printf("Files processed: %"PRIu64"/%"PRIu64"\n",
		files_processed, hashfile_numfiles(handle));

	/* saving fstree */
	fstreefile_name = get_fstreefile_name(hashfile_name);
	fstreefile_fd = open(fstreefile_name, O_WRONLY | O_CREAT | O_TRUNC,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fstreefile_fd < 0) {
		fprintf(stderr, "Could not open %s file!", fstreefile_name);
		exit(-1);
	}

	ret = save_fstree(&fst, fstreefile_fd);
	if (ret) {
		perror("Could not save fstree!");
		exit(-1);
	}

	/* cleanup */
	free(fstreefile_name);
	fstreefile_name = NULL;
	close(fstreefile_fd);

	hashfile_close(handle);

	return;
}

static void usage()
{
	printf("./%s [-e] <hash files>\n", progname);
	printf("<hash files> The hash files generated by dedup binary.\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	int opt;
	int i;

	/* Save program name */
	progname = argv[0];

	/* Collecting command line parameters */
	while (1) {
		opt = getopt(argc, argv, "e");
		if (opt == -1)
			break;

		switch (opt) {
		case 'e':
			empty_fstree = 1;
			break;
		case '?':
			usage();
		}
	}

	if (optind == argc) {
		fprintf(stderr, "No input files specified!\n");
		usage();
		return -1;
	}

	/* Process hashfiles */
	for (i = optind; i < argc; i++) {
		printf("Processing: %s\n", argv[i]);
		process_hashfile(argv[i]);
	}

	return 0;
}
