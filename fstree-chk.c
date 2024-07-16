/*
 * Copyright (c) 2011 Will Buik
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include "fstree.h"

static void stat_node(struct dir *dir, uint64_t *dircount,
		      uint64_t *filecount)
{
	(*dircount) += dir->childdirnum;
	(*filecount) += dir->childfilenum;

	dir = dir->first_childdir;

	while (dir) {
		stat_node(dir, dircount, filecount);
		dir = dir->sibling;
	}
}

static void get_file_stats(struct fstree *fst)
{
	uint64_t dircount = 0;
	uint64_t filecount = 0;

	stat_node(fst->root_dir, &dircount, &filecount);

	fprintf(stderr, "\tTotal Directories: %"PRIu64"\n", dircount);
	fprintf(stderr, "\tTotal Files:       %"PRIu64"\n", filecount);
	fprintf(stderr, "\tDir Slab Size:     %"PRIu64" bytes\n",
					fst->dir_slab.length_inuse);
	fprintf(stderr, "\tFile Slab Size:    %"PRIu64" bytes\n",
					fst->file_slab.length_inuse);
	fprintf(stderr, "\tChunk Slab Size:   %"PRIu64" bytes\n",
					fst->chunk_slab.length_inuse);
}

static int check_file(char *path)
{
	struct fstree fst;
	int ret = 0;
	int fd;

	fprintf(stderr, "*** Checking file %s ***\n", path);

	if (!strcmp(path, "-"))
		fd = STDIN_FILENO;
	else
		fd = open(path, O_RDONLY);

	if (fd < 0) {
		perror("\tFailed to open file");
		return -1;
	}

	ret = load_fstree(&fst, fd);
	if (ret < 0) {
		perror("\tFailed to load fs tree");
		goto out;
	}

	ret = check_fstree(&fst);
	if (ret < 0)
		fprintf(stderr, "\tIntegrity check failed!\n");
	else
		fprintf(stderr, "\tFile passed integrity check.\n");

	get_file_stats(&fst);

	destroy_fstree(&fst);

out:
	if (fd != STDIN_FILENO)
		close(fd);

	if (ret < 0)
		return -1;
	else
		return 0;
}

int main(int argc, char *argv[])
{
	int i;
	int ret = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <tree file> ...\n", argv[0]);
		fprintf(stderr, "Returns non-zero if the integrity check of "
			"any file fails.\n");
		return -1;
	}

	for (i = 1; i < argc; i++)
		ret = ret | check_file(argv[i]);

	return ret;
}
