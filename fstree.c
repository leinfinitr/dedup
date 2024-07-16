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

#include <inttypes.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>

#include "fstree.h"

/* OS-X defines only MAP_ANON not MAP_ANONYMOUS */
#ifndef MAP_ANONYMOUS
# define MAP_ANONYMOUS MAP_ANON
#endif /* not MAP_ANONYMOUS */

/************************ Slab and slice allocation *************************/

static int allocate_slab(struct slab *slab)
{
	void *base;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS;

	if (slab->length <= 0 || slab->slice_width <= 0 ||
					 slab->length < slab->slice_width) {
		errno = EINVAL;
		return -1;
	}

	if (slab->base)
		flags |= MAP_FIXED;

	base = mmap(slab->base, slab->length,
		    PROT_READ | PROT_WRITE, flags, 0, 0);
	if (base == MAP_FAILED)
		return -1;

	/*
	 * If the slab belongs in a particular location,
	 * verify mmap actually put it in the right place.
	 */
	if (slab->base && base != slab->base) {
		munmap(slab->base, slab->length);
		errno = EINVAL;
		return -1;
	} else
		slab->base = base;

	slab->length_inuse = 0;
	slab->first_free = slab->base;

	return 0;
}

static void free_slab(struct slab *slab)
{
	slab->length_inuse = 0;
	munmap(slab->base, slab->length);
}

static void *allocate_slice(struct slab *slab)
{
	void *slice = slab->first_free;

	/*
	 * Find first free slice in the slab.
	 * Empty slice is indicated by first four bytes beeing zero.
	 * Notice, that anonymous mmappings are initialized to zero by the
	 * kernel.
	 */
	while (*(uint64_t *)slice || *(uint64_t *)((uint64_t *)slice + 1)) {
		slice += slab->slice_width;
		if (slice + slab->slice_width > slab->base + slab->length) {
			/* Reached end of slab without finding an open slot */
			errno = ENOMEM;
			return NULL;
		}
	}

	/*
	 * If this slice is allocated beyond the current region marked in use,
	 * extend the in use region so it will be properly serialized to disk.
	 */
	if (slice - slab->base + slab->slice_width > slab->length_inuse)
		slab->length_inuse = slice - slab->base + slab->slice_width;

	/*
	 * Update the pointer to the first_free slice.  This slice might not
	 * might not be free, but everything before it is gaurenteed to be
	 * in use.
	 */
	slab->first_free = slice + slab->slice_width;

	return slice;
}

static void free_slice(struct slab *slab, void *slice)
{
	if (!slice)
		return;

	/* Sanity checks, make sure slice is in slab, slice starts on boundry */
	assert(slice >= slab->base && slice < (slab->base + slab->length));
	assert((((uint64_t)slice - (uint64_t)FILE_SLAB_BASE)
					 % slab->slice_width) == 0);

	/* If this slice is before the first_free slice, reset first_free */
	if (slice < slab->first_free)
		slab->first_free = slice;

	memset(slice, 0, slab->slice_width);
}

/**************************** File tree allocators ****************************/

/*
 * MAP_FIXED will let you clobber a previously mapped chunk of memory with a
 * new one without any indication or error.  To ensure that does not happen,
 * only permit fstree creation if map_busy is 0.  The function create_fstree
 * sets this to 1, destroy_fstree sets it back to 0.
 */
static int map_busy;

int create_fstree(struct fstree *fst)
{
	int ret;

	/* Make sure we will not clobber a previously mapped fstree */
	if (map_busy) {
		errno = EADDRINUSE;
		return -1;
	}

	fst->root_dir = NULL;
	fst->fstree_size = 0;
	fst->num_files = 0;
	fst->num_dirs = 0;
	fst->num_hashes = 0;
	fst->hash_size = 0;

	/* Allocate all the slabs */
	fst->file_slab.base = FILE_SLAB_BASE;
	fst->file_slab.length = DEFAULT_SLAB_SIZE;
	fst->file_slab.slice_width = sizeof(struct file);

	fst->dir_slab.base = DIR_SLAB_BASE;
	fst->dir_slab.length = DEFAULT_SLAB_SIZE;
	fst->dir_slab.slice_width = sizeof(struct dir);

	fst->chunk_slab.base = CHUNK_SLAB_BASE;
	fst->chunk_slab.length = DEFAULT_SLAB_SIZE;
	fst->chunk_slab.slice_width = sizeof(struct log_chunk);

	ret = allocate_slab(&fst->file_slab);
	if (ret < 0)
		goto out_file;

	ret = allocate_slab(&fst->dir_slab);
	if (ret < 0)
		goto out_dir;

	ret = allocate_slab(&fst->chunk_slab);
	if (ret < 0)
		goto out_chunk;

	map_busy = 1;
	return 0;

out_chunk:
	free_slab(&fst->dir_slab);
out_dir:
	free_slab(&fst->file_slab);
out_file:
	return -1;
}

void destroy_fstree(struct fstree *fst)
{
	free_slab(&fst->chunk_slab);
	free_slab(&fst->dir_slab);
	free_slab(&fst->file_slab);
	map_busy = 0;
}

struct file *allocate_file(struct fstree *fst)
{
	return allocate_slice(&fst->file_slab);
}

void free_file(struct fstree *fst, struct file *ptr)
{
	free_slice(&fst->file_slab, ptr);
}

struct dir *allocate_dir(struct fstree *fst)
{
	return allocate_slice(&fst->dir_slab);
}

void free_dir(struct fstree *fst, struct dir *ptr)
{
	free_slice(&fst->dir_slab, ptr);
}

struct log_chunk *allocate_chunk(struct fstree *fst)
{
	return allocate_slice(&fst->chunk_slab);
}

void free_chunk(struct fstree *fst, struct log_chunk *ptr)
{
	free_slice(&fst->chunk_slab, ptr);
}

/************************** File tree serialization ***************************/

static int large_io_blocksize = 4 * 1024 * 1024;

/*
 * Read a large length of data into a buffer. Returns -1 on failure. If 
 * EOF is reached before readling the full length of data set errno
 * to ENODATA. On success return 0.
 */
static int large_read(int fd, char *buffer, uint64_t length)
{
	size_t read_size = large_io_blocksize;
	ssize_t last_read;

	while (length > 0) {
		if (length < read_size)
			read_size = length;
		last_read = read(fd, buffer, read_size);
		if (last_read <= 0) {
			if (!last_read)
				errno = ENODATA;
			return -1;
		}
		buffer += last_read;
		length -= last_read;
	}

	return 0;
}

/*
 * Writes a large length of data into a file.
 * Returns -1 on failure, 0 on success.
 */
static int large_write(int fd, char *buffer, uint64_t length)
{
	size_t write_size = large_io_blocksize;
	ssize_t last_write;

	while (length > 0) {
		if (length < write_size)
			write_size = length;
		last_write = write(fd, buffer, write_size);
		if (last_write < 0)
			return -1;
		buffer += last_write;
		length -= last_write;
	}

	return 0;
}

/*
 * Write a fstree to fd, starts writing from fd's cursor.
 * Returns 0 on success, sets errno and returns -1 if the operation fails.
 */
int save_fstree(struct fstree *fst, int fd)
{
	int ret;
	struct fstree_fileheader header;

	/* Generate header */
	header.magic = FS_TREE_MAGIC;
	header.header_size = sizeof(header);
	header.file_slab_size = fst->file_slab.length_inuse;
	header.dir_slab_size = fst->dir_slab.length_inuse;
	header.chunk_slab_size = fst->chunk_slab.length_inuse;
	header.root_dir = fst->root_dir;
	header.fstree_size = fst->fstree_size;
	header.num_files = fst->num_files;
	header.num_dirs = fst->num_dirs;
	header.num_hashes = fst->num_hashes;
	header.hash_size = fst->hash_size;

	/* Write header, file slab, dir slab, and chunk slab to file */
	ret = large_write(fd, (char *)&header, sizeof(header));
	if (ret < 0)
		return -1;
	ret = large_write(fd, fst->file_slab.base, header.file_slab_size);
	if (ret < 0)
		return -1;
	ret = large_write(fd, fst->dir_slab.base, header.dir_slab_size);
	if (ret < 0)
		return -1;
	ret = large_write(fd, fst->chunk_slab.base, header.chunk_slab_size);
	if (ret < 0)
		return -1;

	return 0;
}

/*
 * Load a fstree to fd, starts reading from fd's cursor.
 * Returns 0 on success, sets errno and returns -1 if the operation fails.
 * errno == EINVAL indicates that the fstree file was not valid.
 */
int load_fstree(struct fstree *fst, int fd)
{
	int ret;
	struct fstree_fileheader header;

	/* Read and verify header */
	ret = large_read(fd, (char *)&header, sizeof(header));
	if (ret < 0)
		return -1;

	if (header.magic != FS_TREE_MAGIC ||
	    header.header_size != sizeof(header)) {
		errno = EINVAL;
		return -1;
	}

	if (header.file_slab_size > DEFAULT_SLAB_SIZE ||
	    header.dir_slab_size > DEFAULT_SLAB_SIZE ||
	    header.chunk_slab_size > DEFAULT_SLAB_SIZE) {
		errno = E2BIG;
		return -1;
	}

	/* Create an empty fstree and populate its data */
	ret = create_fstree(fst);
	if (ret < 0)
		return -1;

	fst->root_dir = header.root_dir;
	fst->fstree_size = header.fstree_size;
	fst->num_files = header.num_files;
	fst->num_dirs = header.num_dirs;
	fst->num_hashes = header.num_hashes;
	fst->hash_size = header.hash_size;

	fst->file_slab.length_inuse = header.file_slab_size;
	ret = large_read(fd, fst->file_slab.base, header.file_slab_size);
	if (ret < 0)
		return -1;

	fst->dir_slab.length_inuse = header.dir_slab_size;
	ret = large_read(fd, fst->dir_slab.base, header.dir_slab_size);
	if (ret < 0)
		return -1;

	fst->chunk_slab.length_inuse = header.chunk_slab_size;
	ret = large_read(fd, fst->chunk_slab.base, header.chunk_slab_size);
	if (ret < 0)
		return -1;

	return 0;
}

/************************** File tree serialization ***************************/

static int walk_subtree(struct dir *rootdir, int (*perform)(void *, int, int))
{
	static int level = 0;
	struct file *f;
	struct dir *d;
	int ret;

	ret = perform(rootdir, OBJ_TYPE_DIR, level);
	if (ret == WTR_ERROR)
		return -1;

	level++;
	f = rootdir->first_childfile;
	while (f) {
		ret = perform(f, OBJ_TYPE_FILE, level);
		if (ret == WTR_ERROR)
			return -1;

		f = f->sibling;
	}

	d = rootdir->first_childdir;
	while (d) {
		ret = walk_subtree(d, perform);
			if (ret < 0)
				return -1;
		d = d->sibling;
	}

	level--;

	return 0;
}

int walk_fstree(struct fstree *fst, int (*perform)(void *, int, int))
{
	if (!fst->root_dir)
		return	0;

	return walk_subtree(fst->root_dir, perform);
}

/****************************** Error checker *********************************/

/* Linked list of pointers used to detect loops */
struct ptr_list {
	void *ptr;
	struct ptr_list *next;
};

static struct ptr_list *dir_list;

/* Returns -1 if ptr is neither NULL nor in the slab */
static int verify_ptr(void *ptr, struct slab *slab)
{
	if (!ptr)
		return 0;

	if (ptr < slab->base || ptr >= slab->base + slab->length)
		return -1;

	return 0;
}

static int verify_chunks(struct fstree *fst, struct file *file)
{
	struct log_chunk *chunk;
	uint64_t chunk_count = 0;
	uint64_t chunk_size_sum = 0;
	int ret;
	
	chunk = file->first_log_chunk;
	while (chunk) {
		ret = verify_ptr(chunk, &fst->chunk_slab);
		if (ret < 0) {
			fprintf(stderr, "Bad pointer to the next chunk!\n");
			return -1;
		}

		if (chunk->offset != chunk_size_sum) {
			fprintf(stderr, "Bad chunk offset!\n");
			return -1;
		}

		if (!chunk->size) {
			fprintf(stderr, "Chunk of a zero size!\n");
			return -1;
		}

		/*
		 * Some files may have too many chunks to feasibly check
		 * for cycles in the chunk list, but a decent heuristic
		 * is to assume there is a cycle if there are ever more
		 * chunks than bytes in the file.
		 */
		if (chunk_count > file->size) {
			fprintf(stderr, "Probable cycle in chunk list\n");
			return -1;
		}

		chunk_size_sum += chunk->size;
		chunk_count++;

		chunk = chunk->next;
	}

	if (chunk_size_sum != file->size) {
		fprintf(stderr, "Chunk sizes sum does not match file size\n");
		return -1;
	}

	return 0;
}

/* Returns -1 if an issue is detected in files of a dir */
static int verify_files(struct fstree *fst, struct dir *parent)
{
	int ret;
	uint32_t i = 0;
	struct file *file = parent->first_childfile;

	while (file && i <= parent->childfilenum) {
		ret = verify_ptr(file, &fst->file_slab);
		if (ret < 0) {
			fprintf(stderr, "Bad pointer to the next file\n");
			return -1;
		}

		if (file->parent != parent) {
			fprintf(stderr, "File parent does not match\n");
			return -1;
		}

		ret = verify_ptr(file->first_log_chunk, &fst->chunk_slab);
		if (ret < 0) {
			fprintf(stderr, "Bad pointer to first chunk\n");
			return -1;
		}

		if (file->first_log_chunk) {
			ret = verify_chunks(fst, file);
			if (ret < 0)
				return -1;
		}

		file = file->sibling;
		i++;
	}

	if (i != parent->childfilenum) {
		fprintf(stderr, "Actual number of files does "
				"not match parent's childfilenum\n");
		return -1;
	}

	return 0;
}

/* Returns -1 if an issue is detected in subdirs of a dir */
static int verify_dirs(struct fstree *fst, struct dir *root)
{
	int ret;
	uint32_t i = 0;
	struct dir *dirchild = root->first_childdir;
	struct ptr_list dir_list_entry;
	struct ptr_list *dir_list_cur = dir_list;

	/* Check if directory is on the dir_list */
	while (dir_list_cur) {
		if (dir_list_cur->ptr == root) {
			fprintf(stderr, "Loop detected in directory tree\n");
			return -1;
		}

		dir_list_cur = dir_list_cur->next;
	}

	/* Add directory to the dir_list */
	dir_list_entry.ptr = root;
	dir_list_entry.next = dir_list;
	dir_list = &dir_list_entry;

	while (dirchild) {
		ret = verify_ptr(dirchild, &fst->dir_slab);
		if (ret < 0) {
			fprintf(stderr, "Bad pointer to the next dir\n");
			return -1;
		}

		if (dirchild->parent != root) {
			fprintf(stderr, "Dir parent does not match\n");
			return -1;
		}

		ret = verify_files(fst, dirchild);
		if (ret < 0)
			return -1;

		ret = verify_dirs(fst, dirchild);
		if (ret < 0)
			return -1;

		dirchild = dirchild->sibling;
		i++;
	}

	if (i != root->childdirnum) {
		fprintf(stderr, "Actual number of subdirs does "
				"not match parent's dirfilenum\n");
		return -1;
	}

	/* Pop directory off dir_list */
	dir_list = dir_list->next;

	return 0;
}

/*
 * Runs basic sanity checks on a fstree.
 * If the tree is in good condition, returns 0, otherwise returns -1.
 * Messages are written to stderr regarding the nature of the problems.
 */
int check_fstree(struct fstree *fst)
{
	int ret;

	dir_list = NULL;

	ret = verify_ptr(fst->root_dir, &fst->dir_slab);
	if (ret < 0) {
		fprintf(stderr, "Root directory pointer is invalid: %p\n",
			fst->root_dir);
		return -1;
	}

	if (!fst->root_dir) {
		fprintf(stderr, "Root directory pointer is not set\n");
		return -1;
	}

	ret = verify_files(fst, fst->root_dir);
	if (ret < 0)
		return -1;

	ret = verify_dirs(fst, fst->root_dir);
	if (ret < 0)
		return -1;

	return 0;
}

enum file_states get_file_state(char state)
{
	switch (state) {
	case 'N': return FST_NEW_PREV;
	case 'M': return FST_MUTABLE_PREV;
	case 'I': return FST_IMMUTABLE_PREV;
	case 'D': return FST_DELETED_PREV;
	}

	return FST_ERROR;
}

char *print_state(enum file_states state)
{
	switch(state) {
	case FST_NEW:
			 return "N";
	case FST_NEW_PREV:
			 return "NP";
	case FST_MUTABLE:
			 return "M";
	case FST_MUTABLE_PREV:
			 return "MP";
	case FST_IMMUTABLE:
			 return "I";
	case FST_IMMUTABLE_PREV:
			 return "IP";
	case FST_DELETED:
			 return "D";
	case FST_DELETED_PREV:
			 return "DP";
	case FST_IGNORE:
			 return "IGN";
	case FST_ERROR: return "E";
	}

	return "E";
}

void switch_file_state_prev(struct file *file)
{
	switch (file->filestate) {
	case FST_NEW:
			file->filestate = FST_NEW_PREV;
			break;
	case FST_DELETED:
			file->filestate = FST_DELETED_PREV;
			break;
	case FST_MUTABLE:
			file->filestate = FST_MUTABLE_PREV;
			break;
	case FST_IMMUTABLE:
			file->filestate = FST_IMMUTABLE_PREV;
			break;
	default:
			file->filestate = FST_IGNORE;
	}
}

 // TODO
void fill_rwx(char rwx[3], mode_t perm)
{
	rwx[0] = 0;
	rwx[1] = 0;
	rwx[2] = 0;
}
