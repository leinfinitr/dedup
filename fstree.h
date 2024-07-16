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

#ifndef _FSTREE_H
#define _FSTREE_H

#include <inttypes.h>
#include <stdlib.h>
#include <stddef.h>

#define MIN(a, b)	((a) < (b) ? (a) : (b))
#define FALSE	0
#define TRUE	1

#define MAX_EXT_LEN	7

#define UINT8_T_SIZE_IN_BITS		8

#define container_of(ptr, type, member) ({                      \
	const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
	(type *)( (char *)__mptr - offsetof(type,member) );})

/* FS Tree Types */

struct ugperm {
	uint16_t uid;
	uint16_t gid;
	char rwx[3];
};

struct dir {
	uint64_t name;
	struct ugperm ugperm;
	time_t mtime;
	time_t atime;
	time_t ctime;
	struct dir *parent;

	struct dir *first_childdir;
	uint32_t childdirnum;

	struct file *first_childfile;
	uint32_t childfilenum;

	struct dir *sibling;
};

struct log_chunk {
	uint64_t phys_id; /* a la fingerprint */
	uint16_t size;
	uint64_t offset;
	struct log_chunk *next;
};

enum file_states {
	FST_NEW = 1,
	FST_DELETED = 2,
	FST_MUTABLE = 3,
	FST_IMMUTABLE = 4,
	FST_NEW_PREV = 5,
	FST_DELETED_PREV = 6,
	FST_MUTABLE_PREV = 7,
	FST_IMMUTABLE_PREV = 8,
	FST_IGNORE = 9,
	FST_ERROR = 10,
};

struct file {
	uint64_t name;
	char extension[MAX_EXT_LEN];
	struct ugperm ugperm;
	uint64_t size;
	time_t mtime;
	time_t atime;
	time_t ctime;

	struct dir *parent;

	struct file *sibling;

	struct log_chunk *first_log_chunk;

	enum file_states filestate;
};

/* FS Tree memory management */

#define FILE_SLAB_BASE ((void *)0x0000001000000000)
#define DIR_SLAB_BASE  ((void *)0x0000002000000000)
#define CHUNK_SLAB_BASE  ((void *)0x0000003000000000)
#define DEFAULT_SLAB_SIZE (8ULL * 1024ULL * 1024ULL * 1024ULL)

struct slab {
	void *base;
	uint64_t length;
	uint64_t slice_width;
	uint64_t length_inuse;
	void *first_free;
};

struct fstree {
	struct slab file_slab;
	struct slab dir_slab;
	struct slab chunk_slab;
	struct dir *root_dir;
	uint64_t fstree_size;
	uint64_t num_files;
	uint64_t num_dirs;
	uint64_t num_hashes;
	uint8_t hash_size; /* MUST BE 64, ALWAYS (TEMPORARY FIX) */
};

/* FS Tree Serialization Types */

#define FS_TREE_MAGIC 0x89ABCDEF

struct fstree_fileheader {
	uint32_t magic;
	uint16_t header_size;
	uint64_t file_slab_size;
	uint64_t dir_slab_size;
	uint64_t chunk_slab_size;
	struct dir *root_dir;
	uint64_t fstree_size;
	uint64_t num_files;
	uint64_t num_dirs;
	uint64_t num_hashes;
	uint8_t hash_size;
} __attribute__((packed));

/* FS Tree Interface Functions */

int create_fstree(struct fstree *fstree);
void destroy_fstree(struct fstree *fstree);

struct file *allocate_file(struct fstree *fstree);
void free_file(struct fstree *fstree, struct file *ptr);
struct dir *allocate_dir(struct fstree *fstree);
void free_dir(struct fstree *fstree, struct dir *ptr);
struct log_chunk *allocate_chunk(struct fstree *fstree);
void free_chunk(struct fstree *fstree, struct log_chunk *ptr);

int save_fstree(struct fstree *fstree, int fd);
int load_fstree(struct fstree *fstree, int fd);

int walk_fstree(struct fstree *fstree, int (*perform)(void *, int, int));

#define OBJ_TYPE_DIR	1
#define OBJ_TYPE_FILE	2

#define WTR_ERROR	-1

int check_fstree(struct fstree *fstree);

enum file_states get_file_state(char state);
char *print_state(enum file_states state);
void switch_file_state_prev(struct file *file);
void fill_rwx(char rwx[3], mode_t perm);

#endif /* _FSTREE_H */
