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

#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <stddef.h>

#include "fstree-mutate.h"
#include "fsdistro.h"

#if DEBUG_DEVIATION
#define MODIFICATION		1
#define DELETION		2

struct chunks_with_1_dup {
	uint64_t			chunk_id;
	uint8_t				count;
	struct chunks_with_1_dup 	*next;
};

struct chunks_with_1_dup *watch_chunks;
int chunks_placed_so_far = 0;

struct deviation {
	uint64_t	uniq_chunk_increase;
	uint64_t	uniq_chunk_decrease;
	uint64_t	chunk_1_dup_increase;
	uint64_t	chunk_1_dup_decrease;
	uint64_t	chunk_2_dup_increase;
	uint64_t	chunk_2_dup_decrease;
	uint64_t	num_files_not_deleted;
	uint64_t	num_files_not_modified;
} distro_dev;
#endif

struct fstree fst;
struct mutation_profile *profile;
uint64_t new_files, mod_files, del_files, unmod_files, error_files, total_files;
uint64_t new_files_prev, mod_files_prev, del_files_prev, unmod_files_prev;
uint64_t failed_mod, ignored_files, chunk_count_mismatch;
uint64_t num_uniq_chunks_added, num_uniq_chunks_removed;
uint64_t num_chunks_1_dup_added, num_chunks_1_dup_removed;
struct remembered_hashes more_than_2_dup_hashes;
static uint64_t processed_files;

uint64_t files_not_deleted_coz_distro_unmatch;
uint8_t hash_search_finished;

#define dup_count_1_or_2(count)			\
			((count) == DUP_COUNT_1 || (count) == DUP_COUNT_2)
#define dup_count_neither_1_nor_2(count)	\
			((count) != DUP_COUNT_1 && (count) != DUP_COUNT_2)

#if DEBUG_DEVIATION
void watch_chunk(uint64_t chunk_id)
{
	struct chunks_with_1_dup *current;

	for (current = watch_chunks; current; current = current->next) {
		if (chunk_id == current->chunk_id) {
			current->count++;
			return;
		}
	}

	current = (struct chunks_with_1_dup *)malloc(sizeof(*current));
	if (!current)
		return;

	current->chunk_id = chunk_id;
	current->count = 0;
	current->next = watch_chunks;
	watch_chunks = current;
	chunks_placed_so_far++;
}

void check_1_duplicate(struct file *file, int level)
{
	struct log_chunk *chunk;
	struct rb_root *root;
	struct chunk_hash_info *chunk_info;
	uint8_t flag = 0;
	uint64_t chunk_id;
	uint64_t chunk_count = 0, chunks_1_dup = 0, uniq_chunks = 0;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {
		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);

		chunk_count++;
		if (!chunk_info)
			continue;

		switch (chunk_info->dup_count) {
		case 1:
			uniq_chunks++;
			break;
		case 2:
#if DEBUG_CHUNKS
			printf("***%"PRIx64"(%"PRIx64")***", (uint64_t)chunk,
							 chunk->phys_id);
#endif
			watch_chunk(chunk_id);
			chunks_1_dup++;
			flag = 1;
			break;
		}
	}

	if (flag == 1) {
		//print_file_details(file);
		printf("Level: %d Ext: %s File: %"PRIx64" State: %s Total Chunks: %"PRIu64
			" UC: %"PRIu64" 1DC: %"PRIu64"\n", level, file->extension, (uint64_t)file,
			print_state(file->filestate), chunk_count, uniq_chunks,
			chunks_1_dup);
		printf("-------------------------------------------\n");
	}

}

void record_deviation(struct hash_matrix_details *entry, uint8_t type,
							 uint32_t num_files)
{
	distro_dev.uniq_chunk_increase += (entry->num_uniq_chunks * num_files);
	distro_dev.chunk_1_dup_increase += (entry->num_chunks_1_dup * num_files);
	distro_dev.chunk_2_dup_increase += (entry->num_chunks_2_dup * num_files);

	if (type == MODIFICATION) {
		distro_dev.uniq_chunk_decrease +=
		 (entry->file_details.mod_info.num_uniq_chunks_new * num_files);
		distro_dev.chunk_1_dup_decrease +=
		 (entry->file_details.mod_info.num_chunks_1_dup_new * num_files);
		distro_dev.chunk_2_dup_decrease +=
		 (entry->file_details.mod_info.num_chunks_2_dup_new * num_files);
		distro_dev.num_files_not_modified += num_files;
	}

	if (type == DELETION)
		distro_dev.num_files_not_deleted += num_files;
}
#endif

void print_file_details(struct file *file)
{
	printf("%s %"PRIx64": ", print_state(file->filestate), (uint64_t)file);

#if DEBUG_CHUNKS
	struct log_chunk *chunk;
	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next)
		printf("%"PRIx64"(%"PRIx64") ", (uint64_t)chunk,
							 chunk->phys_id);
#endif
	printf("\n");
}

void print_mod_details(struct file *file, struct hash_matrix_details *file_char,
			struct hash_matrix_details *entry)
{
	print_file_details(file);
	printf("Current File Char: CC: %"PRIu64" UC: %"PRIu64" 1DC: %"PRIu64
		" 2DC: %"PRIu64"\n", file_char->chunk_count,
		file_char->num_uniq_chunks, file_char->num_chunks_1_dup,
		file_char->num_chunks_2_dup);
	print_mod_files_entry(entry);
	printf("-----------------------------\n");
}

void print_chunk_info(struct log_chunk *chunk)
{
	printf("Modifying chunk: %"PRIx64" Next: %"PRIx64" ID: %"PRIx64"\n",
		 (uint64_t)chunk, (uint64_t)chunk->next, chunk->phys_id);
}

/* Returns a uint64 that will not conflict with the name of any child */
static uint64_t next_free_name(struct dir *dir)
{
	uint64_t free_name = 1;
	struct file *childfile;
	struct dir *childdir;

	childdir = dir->first_childdir;
	while (childdir) {
		if (childdir->name >= free_name)
			free_name = childdir->name + 1;

		childdir = childdir->sibling;
	}

	childfile = dir->first_childfile;
	while (childfile) {
		if (childfile->name >= free_name)
			free_name = childfile->name + 1;

		childfile = childfile->sibling;
	}

	return free_name;
}

/************************** NEW FILES CREATION ******************************/

static struct file *recreate_deleted_file(struct hash_matrix_details *entry)
{
	/* keep absolute number of deleted files to be recreated */
	if (profile->st_switch_prob[PR_DN] == 0)
		return NULL;

	if (entry->file_details.new_info.num_nodes == 0)
		return NULL;

	/* If we can recreate some files at this point, we do that */
	struct file_list *current, *node;
	uint32_t num;
	int j;
	struct file *ret_file;

	num = random() % entry->file_details.new_info.num_nodes;
	current = entry->file_details.new_info.head;

	for (j = 0; j < num; j++, current = current->next) ;

	if (current->next == NULL)
		node = entry->file_details.new_info.head;
	else
		node = current->next;

	if (node->file->filestate != FST_DELETED_PREV) {
	# if 0
		print_file_details(node->file);
		print_new_files_matrix_entry(entry);
		exit(1);
	#endif
		ret_file = NULL;
	} else {
		profile->st_switch_prob[PR_DN]--;
		ret_file = node->file;
	}

	if (current->next == NULL)
		entry->file_details.new_info.head = node->next;
	else
		current->next = node->next;

	free(node);
	entry->file_details.new_info.num_nodes--;

	if (ret_file)
		print_file_details(ret_file);
	return ret_file;
}

static int add_file_to_new_files_matrix(struct file *file,
					struct hash_matrix_details *entry)
{
	struct file_list *node;

	node = (struct file_list *)malloc(sizeof(*node));
	if (!node)
		return -1;

	node->file = file;
	node->flags = 0;
	node->next = NULL;

	if (entry->file_details.new_info.head)
		node->next = entry->file_details.new_info.head;

	entry->file_details.new_info.head = node;

	entry->file_details.new_info.num_nodes++;

	return 0;
}

static int place_file_in_new_files_matrix(struct file *file, int level)
{
	int i, ret;
	struct hash_matrix_details *entry;

	for (i = 0; i < profile->new_files_matrix.num_entries; i++) {
		entry = &profile->new_files_matrix.entries[i];
		if (!strcmp(file->extension, entry->extension) &&
		    file->filestate == FST_DELETED_PREV &&
		    entry->depth == level) {
			ret = add_file_to_new_files_matrix(file, entry);
			if (ret)
				return -1;
		}
	}

	return 0;
}

static void set_new_dir_in_fst(struct dir *new_dir, struct dir *parent)
{
	new_dir->name = next_free_name(parent);
	new_dir->ugperm.uid = parent->ugperm.uid;
	new_dir->ugperm.gid = parent->ugperm.gid;
	fill_rwx(new_dir->ugperm.rwx, (mode_t)0777);
	new_dir->parent = parent;
	new_dir->first_childdir = NULL;
	new_dir->childdirnum = 0;
	new_dir->first_childfile = NULL;
	new_dir->childfilenum = 0;

	new_dir->sibling = parent->first_childdir;
	parent->first_childdir = new_dir;
	parent->childdirnum++;

	new_dir->mtime = time(NULL);
	new_dir->ctime = new_dir->mtime;
	new_dir->atime = new_dir->mtime;
}

/* We set the chunks in the file in simple manner.  All uniq chunks within
 * file are at the start of the file, followed by chunks with 1 duplicates,
 * followed by chunks with 2 duplicates and then chunks with more number of
 * duplicates.
 */
static uint64_t get_appropriate_chunk_id(uint64_t chunk_num,
				struct hash_matrix_details *entry,
				struct dup_chunk_distro_ext *distro)
{
	if (chunk_num < entry->num_uniq_chunks)
		return get_uniq_chunk_id();

	if (chunk_num >= entry->num_uniq_chunks &&
	    chunk_num < (entry->num_uniq_chunks + entry->num_chunks_1_dup))
		return find_available_chunk_id_ext(DUP_COUNT_1,
							NEW_FILES, distro);

	if (chunk_num >= entry->num_chunks_1_dup &&
	    chunk_num < (entry->num_uniq_chunks +
			 entry->num_chunks_1_dup + entry->num_chunks_2_dup))
		return find_available_chunk_id_ext(DUP_COUNT_2,
							NEW_FILES, distro);

	return find_available_chunk_id_ext(DUP_COUNT_ANY, NEW_FILES, distro);
}

static int set_new_file_chunks(struct file *file,
				struct hash_matrix_details *entry)
{
	uint64_t created_chunks = 0;
	int i;
	struct log_chunk *chunk;
	struct log_chunk **tail = &file->first_log_chunk;
	uint64_t offset = 0;
	struct dup_chunk_distro_ext *new_files_distro;

	new_files_distro = &profile->prev_snapshot_hash_distro;

	/* Create Unique Chunks */
	for (i = 0; i < entry->chunk_count; i++) {
		chunk = allocate_chunk(&fst);
		if (!chunk)
			return -1;

		chunk->phys_id = get_appropriate_chunk_id(i, entry,
						 new_files_distro);
		if (!chunk->phys_id)
			return -1;

		chunk->offset = offset;
		chunk->next = NULL;
		chunk->size = profile->avg_chunk_size;

		*tail = chunk;
		tail = &chunk->next;
		offset += chunk->size;

		created_chunks++;
	}

	return 0;
}

static int set_new_files_in_dir(struct dir *pwd,
				struct hash_matrix_details *entry)
{
	int i;
	struct file *new_file;
	int ret;

	for (i = 0; i < entry->num_files; i++) {

		new_file = recreate_deleted_file(entry);
		if (!new_file) {
			new_file = allocate_file(&fst);
			if (!new_file)
				return -1;

			new_file->name = next_free_name(pwd);
			strncpy(new_file->extension, entry->extension,
								 MAX_EXT_LEN);
			new_file->parent = pwd;
			new_file->sibling = pwd->first_childfile;
			pwd->first_childfile = new_file;
			pwd->childfilenum++;
		}

		new_file->filestate = FST_NEW;
		new_file->ugperm.uid = pwd->ugperm.uid;
		new_file->ugperm.gid = pwd->ugperm.gid;
		fill_rwx(new_file->ugperm.rwx, (mode_t)0777);
		new_file->size = entry->chunk_count * profile->avg_chunk_size;

		new_file->mtime = time(NULL);
		new_file->ctime = new_file->mtime;
		new_file->atime = new_file->mtime;

		new_file->first_log_chunk = NULL;
		ret = set_new_file_chunks(new_file, entry);
		if (ret)
			return -1;

		fst.num_files++;
		fst.fstree_size += new_file->size;
		print_file_details(new_file);
	}

	printf("Successfully created %6"PRIu64" files\n", entry->num_files);
	return 0;
}

/* File System Depth at which particular file is newly created is present in
 * matrix.  We maintain the depth so that later iterations of fstree-mutate
 * for deleted, modified files still finds the files with required depth.
 *
 * Matrix is arranged in descending order of depth.  so matrix[0] contains
 * the highest depth.  We create directories from root till this depth
 * and then add files at each level.
 *
 * All files and directories are created with permissions of root directory
 * in the fstree object.
 */
static int create_required_new_files(struct hash_matrix *matrix)
{
	struct dir *new_dir, *parent, *pwd;
	uint8_t depth, current_depth;
	int i, j;
	int ret;
	struct hash_matrix_details *matrix_row;

	parent = fst.root_dir;
	depth = matrix->entries[0].depth;
	for (i = 0; i < depth - 1; i++) {
		new_dir = allocate_dir(&fst);
		if (!new_dir)
			return -1;

		set_new_dir_in_fst(new_dir, parent);
		parent = new_dir;
		fst.num_dirs++;
	}

	/* Last new_dir is innermost, we start creating files
	 * in that and travers up to the root
	 */
	pwd = new_dir;
	current_depth = depth;

	for (i = 0; i < matrix->num_entries; i++) {
		matrix_row = &matrix->entries[i];

		/* Move up if depth changes */
		if (current_depth != matrix_row->depth) {
			assert(pwd != fst.root_dir);

			for (j = 0;
				 j < (current_depth - matrix_row->depth); j++)
				pwd = pwd->parent;

			current_depth = matrix_row->depth;
		}

		ret = set_new_files_in_dir(pwd, matrix_row);
		if (ret)
			return -1;
	}

	return 0;
}

/************************** Deleting Required Files ***************************/
static int add_file_to_be_deleted_to_matrix(struct file *file,
					struct hash_matrix_details *entry)
{
	struct file_list *node;

	node = (struct file_list *)malloc(sizeof(*node));
	if (!node)
		return -1;

	node->file = file;
	node->flags = 0;
	node->next = NULL;

	if (entry->file_details.del_info.head)
		node->next = entry->file_details.del_info.head;

	entry->file_details.del_info.head = node;

	entry->file_details.del_info.num_nodes++;

	return 0;
}

/* This function needs to be lot of intelligent to correctly identify the file.
 * Simple match with these 5 - 6 properties would not suffice
 */
static int match_deletion_characteristics(struct hash_matrix_details *entry,
					  struct hash_matrix_details *file_char)
{
	if (file_char->depth == entry->depth &&
	    !strcmp(file_char->extension, entry->extension) &&
	    file_char->chunk_count == entry->chunk_count &&
	    file_char->num_uniq_chunks == entry->num_uniq_chunks &&
	    file_char->num_chunks_1_dup == entry->num_chunks_1_dup &&
	    file_char->num_chunks_2_dup == entry->num_chunks_2_dup &&
	    file_char->file_details.del_info.prev_state ==
				entry->file_details.del_info.prev_state)
		return TRUE;

	return FALSE;
}

static int place_deleted_file_in_matrix(struct file *file,
					struct hash_matrix_details *file_char)
{
	int i, ret;
	struct hash_matrix_details *entry;
	uint8_t match;

	for (i = 0; i < profile->del_files_matrix.num_entries; i++) {
		entry = &profile->del_files_matrix.entries[i];
		match = match_deletion_characteristics(entry, file_char);
		if (match) {
			ret = add_file_to_be_deleted_to_matrix(file, entry);
			if (ret)
				return -1;
			return 0;
		}
	}

	/* Not necessary that every file should fall in the matrix */
	return 0;
}

static int extract_deletion_characteristics(void *object, int type, int level)
{
	struct file *file;
	struct log_chunk *chunk;
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;
	int ret;
	struct hash_matrix_details file_char;

	if (type == OBJ_TYPE_DIR)
		return 0;

	file = (struct file *)object;
	/* Already modified file not selected for deletion */
	if (file->filestate != FST_NEW_PREV &&
	    file->filestate != FST_MUTABLE_PREV &&
	    file->filestate != FST_IMMUTABLE_PREV)
		return 0;

	file_char.depth = level;
	strncpy(file_char.extension, file->extension, MAX_EXT_LEN);
	file_char.chunk_count = file_char.num_chunks_1_dup = 0;
	file_char.num_uniq_chunks = file_char.num_chunks_2_dup = 0;
	file_char.file_details.del_info.prev_state = file->filestate;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {

		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);
		if (!chunk_info) {
			printf("Hash Not Found: %"PRIx64" Chunk: %"PRIx64
				" File: %"PRIx64"\n", chunk_id, (uint64_t)chunk,
				(uint64_t)file);
			print_file_details(file);
			return -1;
		}

		file_char.chunk_count++;

		switch (chunk_info->dup_count) {
		case 1:
			file_char.num_uniq_chunks++;
			break;
		case 2:
			file_char.num_chunks_1_dup++;
			break;
		case 3:
			file_char.num_chunks_2_dup++;
			break;
		}
	}

	/* Place the file appropriately in deleted file matrix */
	ret = place_deleted_file_in_matrix(file, &file_char);
	if (ret) {
		printf("Failed to place file in matrix\n");
		return -1;
	}

	processed_files++;
	//printf("\rExtracting Deletion Characteristics: %3d completed.",
	//			(int)(100 * processed_files / fst.num_files));

	return 0;
}

static int update_del_files_distro(struct chunk_hash_info *chunk_info)
{
	struct dup_chunk_distro *distro;
	struct dup_chunk_details *entry;
	int i;

	distro = &profile->del_files_dup_chunk_distro;

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];
		if (entry->dup_count == chunk_info->dup_count) {
			assert(entry->num_chunks - 1 >= 0);
			entry->num_chunks--;
			return 0;
		}
	}

	printf("Strange !! We did not find dup_count for this chunk\n");
	return 0;
}

static int remove_file_contents(struct file *file)
{
	struct log_chunk *chunk, *saved;
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;
	int ret;

	print_file_details(file);
	for (chunk = file->first_log_chunk; chunk;) {

		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);
		if (!chunk_info)
			return -1;

		saved = chunk->next;
		//free_chunk(&fst, chunk);
		chunk = saved;

		/* Decrement number of chunks from distro */
		ret = update_del_files_distro(chunk_info);
		if (ret)
			return -1;
		#if 0
		chunk_info->dup_count--;
		if (!chunk_info->dup_count)
			rb_erase(&chunk_info->node, root);
		#endif
	}

	return 0;
}

static struct file_list *search_del_sequential(struct hash_matrix_details *entry,
					   struct file_list **current)
{
	struct file_list *node, *track;

	for (node = entry->file_details.del_info.head, track = NULL;
				 node; track = node, node = node->next)
		if (node->file->filestate == FST_NEW_PREV ||
		    node->file->filestate == FST_MUTABLE_PREV ||
		    node->file->filestate == FST_IMMUTABLE_PREV)
			break;

	if (track == NULL)
		for (track = entry->file_details.del_info.head;
				track->next; track = track->next);

	*current = track;
	return node;
}

static int delete_files(struct hash_matrix_details *entry)
{
	uint32_t i, j;
	int ret;
	struct file_list *current, *node;
	uint32_t num;
	uint32_t deleted_file_count = 0;

	if (entry->num_files > entry->file_details.del_info.num_nodes) {
		printf("Ignore Delete case: \n");
		print_mod_files_entry(entry);
		entry->file_details.del_info.status = PROCESS_IN_PASS_2;
#if DEBUG_DEVIATION
		record_deviation(entry, DELETION, entry->num_files);
#endif
		return 0;
	}

	for (i = 0; i < entry->num_files; i++) {

		num = random() % entry->file_details.del_info.num_nodes;

		/* Delete 'num + 1' file entry from list */
		current = entry->file_details.del_info.head;
		for (j = 0; j < num; j++, current = current->next) ;

		/* It is possible that one file is in multiple rows,
		 * So, if we have already mutated its state, then
		 * look for next one
		 */

		if (current->next == NULL)
			node = entry->file_details.del_info.head;
		else
			node = current->next;

		if (node->file->filestate != FST_NEW_PREV &&
		    node->file->filestate != FST_MUTABLE_PREV &&
		    node->file->filestate != FST_IMMUTABLE_PREV) {
			node = search_del_sequential(entry, &current);
			if (!node || !current) {
				printf("Ignore Delete case:\n");
				print_mod_files_entry(entry);
				entry->file_details.del_info.status =
							PARTIALLY_PROCESSED;
				entry->num_files -= deleted_file_count;
#if DEBUG_DEVIATION
				record_deviation(entry, DELETION,
						 entry->num_files);
#endif
				return 0;
			}
		}

		/* Sheer randomness.  If we get last node, we modify
		 * head.  Just like that.
		 */
		if (current->next == NULL)
			entry->file_details.del_info.head = node->next;
		else
			current->next = node->next;

		processed_files++;
		node->file->filestate = FST_DELETED;
		/* Remove chunks from FSTree and Hash Table, but we don't
		 * remove file as it is required in case of deleted files
		 * re-created case*/
		ret = remove_file_contents(node->file);
		if (ret)
			return -1;

		free(node);
		deleted_file_count++;
		entry->file_details.del_info.num_nodes--;
	}

	entry->file_details.del_info.status = PROCESSED;
	return 0;
}

static int delete_all_files_sequentially(struct hash_matrix_details *entry)
{
	int ret;
	struct file_list *current, *saved;

	for (current = entry->file_details.del_info.head; current; ) {

		if (current->file->filestate == FST_NEW_PREV ||
		    current->file->filestate == FST_MUTABLE_PREV ||
		    current->file->filestate == FST_IMMUTABLE_PREV) {

			ret = remove_file_contents(current->file);
			if (ret)
				return -1;
			processed_files++;
			current->file->filestate = FST_DELETED;
		}

		saved = current->next;
		free(current);
		current = saved;
		entry->file_details.del_info.num_nodes--;
		entry->num_files--;
	}

	assert(entry->file_details.mod_info.num_nodes == 0);

	return 0;
}

static int delete_required_files()
{
	int ret;
	int i;
	struct hash_matrix_details *entry;
	struct file_list *current, *saved;

	processed_files = 0;
	ret = walk_fstree(&fst, extract_deletion_characteristics);
	if (ret < 0)
		return -1;

	printf("\n");

	print_del_files_hash_matrix(&profile->del_files_matrix);

	/* Now just delete required number of files as indicated by num_files
	 * filed in matrix.  We randomly select those many number of files.
	 *
	 * Ideally, difference between expected number of files to be
	 * deleted and potential number of files found matching the deletion
	 * criteria should be very small.  Adding more dimensions to the
	 * matrix would achieve that.  But, still, this is better than
	 * selecting file absolutely randomly.
	 *
	 * We mark the file FST_DELETED and then do not create those files
	 * during fscreate.  This way we get some names saved for the
	 * case of deleted file recreated case.
	 */
	processed_files = 0;

	/* Deal with trivial search first, i.e., num_files >= num_nodes */
	for (i = 0; i < profile->del_files_matrix.num_entries; i++) {
		entry = &profile->del_files_matrix.entries[i];
		if (entry->num_files >= entry->file_details.del_info.num_nodes &&
		    entry->file_details.del_info.num_nodes > 0) {
			ret = delete_all_files_sequentially(entry);
			if (ret)
				return -1;
			entry->file_details.del_info.status = PARTIALLY_PROCESSED;
#if DEBUG_DEVIATION
			record_deviation(entry, DELETION, entry->num_files);
#endif
			printf("Successfully Deleted %6"PRIu64" files\n",
					entry->file_details.del_info.num_nodes);
		}
	}

	for (i = 0; i < profile->del_files_matrix.num_entries; i++) {
		entry = &profile->del_files_matrix.entries[i];
		if (entry->file_details.del_info.status == NOT_PROCESSED) {
			ret = delete_files(entry);
			if (ret)
				return -1;

			/* Free out rest of the nodes */
			for (current = entry->file_details.del_info.head; current; ) {
				saved = current->next;
				free(current);
				current = saved;
				entry->file_details.del_info.num_nodes--;
			}

			assert(entry->file_details.del_info.num_nodes == 0);
			printf("Successfully Deleted %6"PRIu64" files\n",
								 entry->num_files);
		}
	}

	return 0;
}

/************************ Delete Required Files: Pass 2 ************************/
static uint8_t match_matrix_pass_2(struct hash_matrix_details *file_char,
				   struct hash_matrix_details **ret_entry)
{
	int i;
	struct hash_matrix_details *entry;

	for (i = 0; i < profile->del_files_matrix.num_entries; i++) {
		entry = &profile->del_files_matrix.entries[i];
		if ((entry->file_details.del_info.status == PROCESS_IN_PASS_2 ||
		     entry->file_details.del_info.status == PARTIALLY_PROCESSED) &&
		    entry->num_files > 0				     &&
		    file_char->depth == entry->depth			     &&
		    !strcmp(file_char->extension, entry->extension) 	     &&
		    file_char->chunk_count == entry->chunk_count 	     &&
		    file_char->file_details.del_info.prev_state ==
				     entry->file_details.del_info.prev_state) {
			*ret_entry = entry;
			return TRUE;
		}
	}

	return FALSE;
}

static uint8_t match_distro(struct chunk_hash_info *chunk_info)
{
	struct dup_chunk_distro *distro;
	struct dup_chunk_details *entry;
	int i;

	distro = &profile->del_files_dup_chunk_distro;

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];
		if (entry->dup_count == chunk_info->dup_count) {
			if (entry->num_chunks > 0)
				return TRUE;
			else {
				printf("Exhausted chunks of %"PRIu32
					" duplicates\n", entry->dup_count);
				files_not_deleted_coz_distro_unmatch++;
				return FALSE;
			}
		}
	}

	return FALSE;
}

static uint8_t match_deletion_distro(struct file *file)
{
	struct log_chunk *chunk;
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {

		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);
		if (!chunk_info) {
			printf("Hash Not Found: %"PRIx64" Chunk: %"PRIx64
				" File: %"PRIx64"\n", chunk_id, (uint64_t)chunk,
				(uint64_t)file);
			print_file_details(file);
			return -1;
		}

		/* Even if one is not allowed, we cannot use this file */
		if (!match_distro(chunk_info))
			return FALSE;
	}

	return TRUE;
}

static int pass_2_deletion(void *object, int type, int level)
{
	struct file *file;
	struct log_chunk *chunk;
	int ret;
	struct hash_matrix_details file_char;
	struct hash_matrix_details *entry;
	uint8_t match_found_in_matrix = FALSE;
	uint8_t distro_preserved = FALSE;
#if DEBUG_DEVIATION
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;
#endif

	if (type == OBJ_TYPE_DIR)
		return 0;

	file = (struct file *)object;
	/* Already modified file not selected for deletion */
	if (file->filestate != FST_NEW_PREV &&
	    file->filestate != FST_MUTABLE_PREV &&
	    file->filestate != FST_IMMUTABLE_PREV)
		return 0;

	file_char.depth = level;
	strncpy(file_char.extension, file->extension, MAX_EXT_LEN);
	file_char.chunk_count = file_char.num_chunks_1_dup = 0;
	file_char.num_uniq_chunks = file_char.num_chunks_2_dup = 0;
	file_char.file_details.del_info.prev_state = file->filestate;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {
		file_char.chunk_count++;
#if DEBUG_DEVIATION
		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);

		switch (chunk_info->dup_count) {
		case 1:	file_char.num_uniq_chunks++;
			break;
		case 2: file_char.num_chunks_1_dup++;
			break;
		case 3: file_char.num_chunks_2_dup++;
			break;
		}
#endif
	}

	/* Find if this file can possibly placed in one of the rows of matrix.
	 * Match will be liberal, unique, 1DC and 2DC not matched.
	 */
	match_found_in_matrix = match_matrix_pass_2(&file_char, &entry);

	if (!match_found_in_matrix)
		return 0;

	//distro_preserved = match_deletion_distro(file);
	distro_preserved = TRUE;

	if (!distro_preserved)
		return 0;

	/* Deleting this file should be safe now */
	processed_files++;
	ret = remove_file_contents(file);
	if (ret)
		return -1;

	file->filestate = FST_DELETED;
	entry->num_files--;
#if DEBUG_DEVIATION
	distro_dev.num_files_not_deleted--;
	distro_dev.uniq_chunk_increase -= file_char.num_uniq_chunks;
	distro_dev.chunk_1_dup_increase -= file_char.num_chunks_1_dup;
	distro_dev.chunk_2_dup_increase -= file_char.num_chunks_2_dup;
#endif
	return 0;
}

static int delete_required_files_pass_2()
{
	int ret;

#if DEBUG_DEVIATION
	printf("We failed to delete %"PRIu64" files during pass 1\n",
					distro_dev.num_files_not_deleted);
#endif
	processed_files = 0;
	ret = walk_fstree(&fst, pass_2_deletion);
	if (ret < 0)
		return -1;

	printf("We managed to delete %"PRIu64" extra files in second pass\n",
							processed_files);
	printf("We failed to delete %"PRIu64" extra files in second pass"
		" due to unmatched distro.\n",
		 files_not_deleted_coz_distro_unmatch);
	return 0;
}


/************************** Modifying Required Files ***************************/

static int add_file_to_be_modified_to_matrix(struct file *file,
					struct hash_matrix_details *entry)
{
	struct file_list *node;

	node = (struct file_list *)malloc(sizeof(*node));
	if (!node)
		return -1;

	node->file = file;
	node->flags = 0;
	node->next = NULL;

	if (entry->file_details.mod_info.head)
		node->next = entry->file_details.mod_info.head;

	entry->file_details.mod_info.head = node;

	entry->file_details.mod_info.num_nodes++;

	return 0;
}

/* This function needs to be lot of intelligent to correctly identify the file.
 * Simple match with these 5 - 6 properties would not suffice
 */
static int match_modification_characteristics(struct hash_matrix_details *entry,
					  struct hash_matrix_details *file_char)
{
	if (file_char->depth == entry->depth &&
	    !strcmp(file_char->extension, entry->extension) &&
	    file_char->chunk_count == entry->chunk_count &&
	    file_char->num_uniq_chunks == entry->num_uniq_chunks &&
	    file_char->num_chunks_1_dup == entry->num_chunks_1_dup &&
	    file_char->num_chunks_2_dup == entry->num_chunks_2_dup &&
	    file_char->file_details.del_info.prev_state ==
				entry->file_details.del_info.prev_state)
		return TRUE;

	return FALSE;
}


static int place_modified_file_in_matrix(struct file *file,
					struct hash_matrix_details *file_char)
{
	int i, ret;
	struct hash_matrix_details *entry;
	uint8_t match;

	for (i = 0; i < profile->mod_files_matrix.num_entries; i++) {
		entry = &profile->mod_files_matrix.entries[i];
		match = match_modification_characteristics(entry, file_char);
		if (match) {
			ret = add_file_to_be_modified_to_matrix(file, entry);
			if (ret)
				return -1;

			/* We still continue to place same file in multiple
			 * rows of matrix.  This is not the case with deleted
			 * files, because matrix for modified files also has
			 * dimensions about how to modify file which is not
			 * the case for deleted files.  Thus, 1 file with
			 * 1 chunk at depth 4 might need to be modified
			 * to have 2 chunks and 1 file with 1 chunk at depth
			 * 4 might need to be modified to have 3 chunks.
			 */
		}
	}

	/* Not necessary that every file should fall in the matrix */
	return 0;
}

static int extract_modification_characteristics(void *object, int type, int level)
{
	struct file *file;
	struct log_chunk *chunk;
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;
	int ret;
	struct hash_matrix_details file_char;

	if (type == OBJ_TYPE_DIR)
		return 0;

	file = (struct file *)object;

	if (file->filestate != FST_NEW_PREV &&
	    file->filestate != FST_MUTABLE_PREV &&
	    file->filestate != FST_IMMUTABLE_PREV)
		return 0;

	/* All *_new properties and pattern is about how to modify file and
	 * has nothing to do with identifying file
	 */
	file_char.depth = level;
	strncpy(file_char.extension, file->extension, MAX_EXT_LEN);
	file_char.chunk_count = file_char.num_chunks_1_dup = 0;
	file_char.num_uniq_chunks = file_char.num_chunks_2_dup = 0;
	file_char.file_details.mod_info.prev_state = file->filestate;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {

		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);
		if (!chunk_info) {
			printf("Hash Not Found: %"PRIx64" Chunk: %"PRIx64
				" File: %"PRIx64"\n", chunk_id, (uint64_t)chunk,
				(uint64_t)file);
			return -1;
		}

		file_char.chunk_count++;

		switch (chunk_info->dup_count) {
		case 1:
			file_char.num_uniq_chunks++;
			break;
		case 2:
			file_char.num_chunks_1_dup++;
			break;
		case 3:
			file_char.num_chunks_2_dup++;
			break;
		}
	}

	/* Place the file appropriately in deleted file matrix */
	ret = place_modified_file_in_matrix(file, &file_char);
	if (ret) {
		printf("Failed to place file in matrix\n");
		return -1;
	}

	processed_files++;
	//printf("\rExtracting Modification Characteristics: %3d completed.",
	//			(int)(100 * processed_files / fst.num_files));

	return 0;
}

static int match_complete(struct hash_matrix_details *entry,
			  struct hash_matrix_details *file_char)
{
	if (entry->file_details.mod_info.chunk_count_new ==
					 file_char->chunk_count &&
	    entry->file_details.mod_info.num_uniq_chunks_new ==
					 file_char->num_uniq_chunks &&
	    entry->file_details.mod_info.num_chunks_1_dup_new ==
					 file_char->num_chunks_1_dup &&
	    entry->file_details.mod_info.num_chunks_2_dup_new ==
					 file_char->num_chunks_2_dup) {
		printf("***************************\n");
		return TRUE;
	}

	return FALSE;
}

static int modification_same_size(struct log_chunk *chunk,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	uint64_t chunk_id;
	struct rb_root *root;
	struct chunk_hash_info *chunk_info;
	struct dup_chunk_distro_ext *distro;

	/* find its dup_count */
	chunk_id = htole64(chunk->phys_id);
	root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
	chunk_info = search_hash_rbtree(root, chunk_id);
	if (!chunk_info)
		return -1;

	if (chunk_info->dup_count == DUP_COUNT_1)
		file_char->num_chunks_1_dup--;
	if (chunk_info->dup_count == DUP_COUNT_2)
		file_char->num_chunks_2_dup--;
	else
		remember_chunk(chunk_id);

	/* Now delete that chunk and replace it with one
	 * chunk as suggested by *_new values */
	#if 0
	chunk_info->dup_count--;
	if (!chunk_info->dup_count) {
		//printf("Deleting chunk id: %"PRIx64"\n", chunk_id);
		rb_erase(&chunk_info->node, root);
	}
	#endif
	/* This is the distro from which we are going to get our destination
	 * hashes
	 */
	distro = &profile->prev_snapshot_hash_distro;

	/* Add Unique Chunk */
	if (file_char->num_uniq_chunks <
			entry->file_details.mod_info.num_uniq_chunks_new) {
		chunk->phys_id = get_uniq_chunk_id();
		//print_chunk_info(chunk);
		file_char->num_uniq_chunks++;
	} else if (file_char->num_chunks_1_dup <
			entry->file_details.mod_info.num_chunks_1_dup_new) {
		chunk->phys_id = find_available_chunk_id_ext(DUP_COUNT_1,
							     MOD_FILES, distro);
		//print_chunk_info(chunk);
		file_char->num_chunks_1_dup++;
	} else if (file_char->num_chunks_2_dup <
			entry->file_details.mod_info.num_chunks_2_dup_new) {
		chunk->phys_id = find_available_chunk_id_ext(DUP_COUNT_2,
							     MOD_FILES, distro);
		//print_chunk_info(chunk);
		file_char->num_chunks_2_dup++;
	} else {
		chunk->phys_id = find_available_chunk_id_ext(DUP_COUNT_ANY,
							     MOD_FILES, distro);
		//print_chunk_info(chunk);
	}

	return 0;
}

static int modification_increase_size(struct log_chunk **ref_chunk,
				enum mod_position which,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	struct dup_chunk_distro_ext *distro;
	struct log_chunk *chunk;

	chunk = allocate_chunk(&fst);
	if (!chunk)
		return -1;

	/* Connect it into the file chunk sequence */
	if (*ref_chunk == NULL) {
		*ref_chunk = chunk;
		chunk->next = NULL;
	} else if (which == BEFORE_REF_CHUNK) {
		memcpy((void *)chunk, (void *)(*ref_chunk), sizeof(*chunk));
		(*ref_chunk)->next = chunk;
		chunk = (*ref_chunk);
	} else {
		chunk->next = (*ref_chunk)->next;
		(*ref_chunk)->next = chunk;
	}

	chunk->size = profile->avg_chunk_size;
	file_char->chunk_count++;

	/* This is the distro from which we are going to get our destination
	 * hashes
	 */
	distro = &profile->prev_snapshot_hash_distro;

	/* Add Unique Chunk */
	if (file_char->num_uniq_chunks <
			entry->file_details.mod_info.num_uniq_chunks_new) {
		chunk->phys_id = get_uniq_chunk_id();
		//print_chunk_info(chunk);
		file_char->num_uniq_chunks++;
	} else if (file_char->num_chunks_1_dup <
			entry->file_details.mod_info.num_chunks_1_dup_new) {
		chunk->phys_id = find_available_chunk_id_ext(DUP_COUNT_1,
							     MOD_FILES, distro);
		//print_chunk_info(chunk);
		file_char->num_chunks_1_dup++;
	} else if (file_char->num_chunks_2_dup <
			entry->file_details.mod_info.num_chunks_2_dup_new) {
		chunk->phys_id = find_available_chunk_id_ext(DUP_COUNT_2,
							     MOD_FILES, distro);
		//print_chunk_info(chunk);
		file_char->num_chunks_2_dup++;
	} else {
		chunk->phys_id = find_available_chunk_id_ext(DUP_COUNT_ANY,
							     MOD_FILES, distro);
		//print_chunk_info(chunk);
	}

	return 0;
}

static int modification_decrease_size(struct log_chunk **ref_chunk,
				struct log_chunk *prev,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	struct log_chunk *save;
	uint64_t chunk_id;
	struct rb_root *root;
	struct chunk_hash_info *chunk_info;

	/* find its dup_count */
	chunk_id = htole64((*ref_chunk)->phys_id);
	root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
	chunk_info = search_hash_rbtree(root, chunk_id);
	if (!chunk_info)
		return -1;

	if (chunk_info->dup_count == DUP_COUNT_1)
		file_char->num_chunks_1_dup--;
	if (chunk_info->dup_count == DUP_COUNT_2)
		file_char->num_chunks_2_dup--;
	else
		remember_chunk(chunk_id);

	#if 0
	/* Now delete that chunk */
	chunk_info->dup_count--;
	if (!chunk_info->dup_count) {
		//printf("Deleting chunk id: %"PRIx64"\n", chunk_id);
		rb_erase(&chunk_info->node, root);
	}
	#endif

	file_char->chunk_count--;

	if (prev) {
		prev->next = (*ref_chunk)->next;
		free_chunk(&fst, *ref_chunk);
	} else {
		save = *ref_chunk;
		*ref_chunk = (*ref_chunk)->next;
		free_chunk(&fst, save);
	}

	return 0;
}

static void display_error_message(struct file *file, char *location,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	printf("Modification operation failed at %s of file\n", location);
	printf("Current status: CC: %"PRIu64" UC: %"PRIu64" 1DC: %"PRIu64
		" 2DC: %"PRIu64"\n", file_char->chunk_count,
		file_char->num_uniq_chunks, file_char->num_chunks_1_dup,
		file_char->num_chunks_2_dup);
	printf("Expected:  CC: %"PRIu64" UC: %"PRIu64" 1DC: %"PRIu64
		" 2DC: %"PRIu64"\n",
		entry->file_details.mod_info.chunk_count_new,
		entry->file_details.mod_info.num_uniq_chunks_new,
		entry->file_details.mod_info.num_chunks_1_dup_new,
		entry->file_details.mod_info.num_chunks_2_dup_new);
}

static int modify_starting_chunk(struct file *file,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	enum mod_size state;

	state = get_modification_state(file_char, entry);

	//printf("Modifying chunk at start: ");
	//print_chunk_info(file->first_log_chunk);

	switch (state) {
	case SAME_FILE_SIZE:
		/* Same size case: Just some internal modification */

		/* Get first chunk and remove it.  We will add new
		 * chunk at that place */
		return modification_same_size(file->first_log_chunk,
						entry, file_char);

	case INCREASE_FILE_SIZE:
		/* Increase size case: Add one chunk at start*/
		return modification_increase_size(&file->first_log_chunk,
					BEFORE_REF_CHUNK, entry, file_char);

	case DECREASE_FILE_SIZE:
		/* Decrease size case: Remove one chunk at start*/
		print_file_details(file);
		return modification_decrease_size(&file->first_log_chunk, NULL,
							entry, file_char);

	default:
		return -1;
	}
}

static int modify_center_chunk(struct file *file,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	struct log_chunk *chunk = NULL, *prev = NULL;
	int i;
	enum mod_pattern pattern;
	enum mod_size state;
	int mid_chunk_num;

	state = get_modification_state(file_char, entry);
	pattern = entry->file_details.mod_info.pattern;

	switch (state) {
	case SAME_FILE_SIZE:
		/* Same size case: Just some internal modification */

		/* Special Case */
		if (file_char->chunk_count < 3)
			return modification_same_size(file->first_log_chunk,
						 entry, file_char);

		/* Search the middle chunk for modification */
		mid_chunk_num = file_char->chunk_count / 2;
		if (file_char->chunk_count % 2)
			mid_chunk_num += 1;

		for (i = 0, chunk = file->first_log_chunk;
				i < mid_chunk_num - 1; i++, chunk = chunk->next);

		//printf("Modifying chunk at Center: ");
		//print_chunk_info(chunk);
		return modification_same_size(chunk, entry, file_char);

	case INCREASE_FILE_SIZE:
		/* Increase size case: Add one chunk at Center
		 */
		mid_chunk_num = file_char->chunk_count / 2;
		if (file_char->chunk_count % 2)
			mid_chunk_num += 1;

		for (i = 0, chunk = file->first_log_chunk;
				i < mid_chunk_num; i++, chunk = chunk->next);

		if (!chunk)
			return modification_increase_size(&file->first_log_chunk,
					 AFTER_REF_CHUNK, entry, file_char);
		//printf("Modifying chunk at Center: ");
		//print_chunk_info(chunk);
		return modification_increase_size(&chunk, BEFORE_REF_CHUNK,
							 entry, file_char);

	case DECREASE_FILE_SIZE:
		/* Search the middle chunk for modification */
		for (i = 0, prev = NULL, chunk = file->first_log_chunk;
				i < (file_char->chunk_count / 2);
				i++, prev = chunk, chunk = chunk->next);

		//printf("Modifying chunk at Center: ");
		//print_chunk_info(chunk);
		print_file_details(file);
		if (!prev)
			return modification_decrease_size(&file->first_log_chunk,
							 prev, entry, file_char);

		return modification_decrease_size(&chunk, prev,
							 entry, file_char);

	default:
		return -1;
	}
}

static int modify_end_chunk(struct file *file,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	struct log_chunk *chunk, *prev;
	int i;
	enum mod_size state;

	state = get_modification_state(file_char, entry);

	/* Search the last chunk for modification */
	for (i = 0, chunk = file->first_log_chunk;
				i < (file_char->chunk_count - 1);
				i++, prev = chunk, chunk = chunk->next);

	//printf("Modifying chunk at End: ");
	//print_chunk_info(chunk);

	switch (state) {
	case SAME_FILE_SIZE:
		/* Same size case: Just some internal modification */
		return modification_same_size(chunk, entry, file_char);

	case INCREASE_FILE_SIZE:
		/* Increase size case: Add one chunk at end*/
		return modification_increase_size(&chunk, AFTER_REF_CHUNK,
							 entry, file_char);
	case DECREASE_FILE_SIZE:
		/* Search the last but one chunk for deletion*/
		for (i = 0, prev = NULL, chunk = file->first_log_chunk;
				i < (file_char->chunk_count - 1);
				i++, prev = chunk, chunk = chunk->next);

		//printf("Modifying chunk at End: ");
		//print_chunk_info(chunk);
		print_file_details(file);
		if (!prev)
			return modification_decrease_size(&file->first_log_chunk,
							 prev, entry, file_char);

		return modification_decrease_size(&chunk, prev,
							 entry, file_char);
	default:
		return -1;
	}
}

static int replacement_possible(struct hash_matrix_details *file_char,
				struct hash_matrix_details *entry)
{
	if (file_char->num_uniq_chunks <
	    entry->file_details.mod_info.num_uniq_chunks_new ||
	    file_char->num_chunks_1_dup <
	    entry->file_details.mod_info.num_chunks_1_dup_new ||
	    file_char->num_chunks_2_dup <
	    entry->file_details.mod_info.num_chunks_2_dup_new)
		return TRUE;

	return FALSE;
}

static int match_same_size(struct file *file, struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	struct log_chunk *chunk;
	int i;
	int skip_chunk_num;
	uint64_t chunk_id;
	struct rb_root *root;
	struct chunk_hash_info *chunk_info;
	struct dup_chunk_distro_ext *distro;
	enum mod_size state;
	enum mod_pattern pattern;
	uint8_t skip_middle_chunk = 0, skip_start_chunk = 0, skip_end_chunk = 0;
	uint64_t zeroed_chunks = 0;

	if (file_char->chunk_count == 0)
		return 0;

	/* We need to make some intelligent decisions based on how this
	 * function is called as this function is called with size increase
	 * and decrease case as well
	 */
	state = get_modification_state(file_char, entry);
	/* This is the distro from which we are going to get our destination
	 * hashes
	 */
	distro = &profile->prev_snapshot_hash_distro;

	pattern = entry->file_details.mod_info.pattern;
	if (pattern == MODIFY_CENTER || pattern == MODIFY_END ||
	    pattern == MODIFY_CENTER_AND_END)
		skip_start_chunk = 1;

	if (pattern == MODIFY_START || pattern == MODIFY_START_AND_CENTER)
		skip_end_chunk = 1;

	if (pattern == MODIFY_START || pattern == MODIFY_END ||
	    pattern == MODIFY_START_AND_END) {
		skip_middle_chunk = 1;
		skip_chunk_num = file_char->chunk_count / 2;
		if (file_char->chunk_count % 2)
			skip_chunk_num += 1;
	}

	/* Same size case: Just some internal modification
	 * Delete required 1 DC and add required 1 UC, delete
	 * operation would just set chunk_id to 0 and add operation
	 * would put new chunk id there as we want to retain the
	 * size to be same.  When searching for chunk with given
	 * dup to del, ignore search failure of new chunks added
	 * during modification
	 */
	for (i = 1, chunk = file->first_log_chunk; i <= file_char->chunk_count;
				i++, chunk = chunk->next) {

		if (i == 1 && skip_start_chunk)
			continue;

		if (i == skip_chunk_num && skip_middle_chunk)
			continue;

		if (i == file_char->chunk_count && skip_end_chunk)
			break;

		/* find its dup_count */
		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);
		if (!chunk_info) {
			/* We might end up into same size  match after
			 * adding some chunks in between, so neglect if
			 * chunk not found
			 */
			continue;
		}

		/* Remove Extras */
		if (chunk_info->dup_count == DUP_COUNT_1 &&
		    file_char->num_chunks_1_dup >
		    entry->file_details.mod_info.num_chunks_1_dup_new) {
			chunk->phys_id = 0;
			file_char->num_chunks_1_dup--;
			zeroed_chunks++;
		} else if (chunk_info->dup_count == DUP_COUNT_2 &&
		    file_char->num_chunks_2_dup >
		    entry->file_details.mod_info.num_chunks_2_dup_new) {
			chunk->phys_id = 0;
			file_char->num_chunks_2_dup--;
			zeroed_chunks++;
		} else {
			/* What is other dup_count?  We need to match
			 * it with resultuant distribution.
			 */
			if (chunk_info->dup_count != DUP_COUNT_1 &&
			    chunk_info->dup_count != DUP_COUNT_2 &&
			    replacement_possible(file_char, entry)) {
				/* Make a note of chunk, as we might need
				 * it later.  eg. CCo = 26, UCo = 1DCo = 0
				 * 2DCo = 22, 4 chunks with DC > 2.  CCn = 25
				 * UCn = 22 1DCn = 2DCn = 0, then ideally,
				 * we shd replace all 2DCo chunks with UCn
				 * chunks, but we can't retain that intelligence.
				 * So, we keep a note of these 4 chunks as - if
				 * we scan chunks and get those chunks with
				 * DC > 2 initially, we would probably replace
				 * them.  So, just make a note of them and
				 * use them for DUP_COUNT_ANY search.
				 */
				remember_chunk(chunk->phys_id);
				chunk->phys_id = 0;
				zeroed_chunks++;
			}
		}

		if (chunk->phys_id)
			continue;

		/* Add missing */
		if (file_char->num_uniq_chunks <
		    entry->file_details.mod_info.num_uniq_chunks_new) {
			chunk->phys_id = get_uniq_chunk_id();
			file_char->num_uniq_chunks++;
			zeroed_chunks--;
		} else if (file_char->num_chunks_1_dup <
		    entry->file_details.mod_info.num_chunks_1_dup_new) {
			chunk->phys_id =
			   find_available_chunk_id_ext(DUP_COUNT_1,
							MOD_FILES, distro);
			file_char->num_chunks_1_dup++;
			zeroed_chunks--;
		} else if (file_char->num_chunks_2_dup <
		    entry->file_details.mod_info.num_chunks_2_dup_new) {
			chunk->phys_id =
			   find_available_chunk_id_ext(DUP_COUNT_2,
							MOD_FILES, distro);
			file_char->num_chunks_2_dup++;
			zeroed_chunks--;
		} else {
			if ((int64_t)(file_char->chunk_count -
				entry->file_details.mod_info.chunk_count_new)
				< (int64_t)zeroed_chunks) {
				chunk->phys_id =
				  find_available_chunk_id_ext(DUP_COUNT_ANY,
							      MOD_FILES, distro);
				zeroed_chunks--;
			}
		}
	}

	print_mod_details(file, file_char, entry);
	return 0;
}

static int match_increase_size(struct file *file,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	struct log_chunk *mid_chunk, *end_chunk;
	int i;
	int ret;
	uint32_t diff, count;
	enum mod_pattern pattern;

	/* Increase size case: We need to maintain the middle chunk correctly
	 * as we have correctly modified it.  Thus, following cases arise:
	 *
	 * 1. diff = expected size - current size
	 * pattern = SCE or SC		1. add diff / 2 before start
	 *				2. add diff / 2 after end
	 * pattern = CE	or E		1. add diff after end
	 * pattern = SC	or S		1. add diff before start
	 * pattern = C			1. add diff / 2 before central chunk
	 *				2. add diff / 2 after central chunk
	 *
	 * This is the point where we have dealt with first,
	 * last and middle chunk already.  So, ignore them.
	 */

	diff = entry->file_details.mod_info.chunk_count_new -
							 file_char->chunk_count;
	assert(diff > 0);

	pattern = entry->file_details.mod_info.pattern;

	/* Search last chunk */
	for (i = 0, end_chunk = file->first_log_chunk;
				i < (file_char->chunk_count - 1);
				i++, end_chunk = end_chunk->next);

	/* Search central chunk */
	for (i = 0, mid_chunk = file->first_log_chunk;
				i < (file_char->chunk_count / 2);
				i++, mid_chunk = mid_chunk->next);

	switch (pattern) {
	case MODIFY_START_CENTER_AND_END:
	case MODIFY_START_AND_END:
		/* Add chunks before start */
		count = diff / 2;
		for (i = 0; i < count; i++) {
			ret = modification_increase_size(&file->first_log_chunk,
					BEFORE_REF_CHUNK, entry, file_char);
			if (ret)
				return -1;
		}

		/* Add chunks at end */
		for (i = 0; i < diff - count; i++) {
			ret = modification_increase_size(&end_chunk,
					AFTER_REF_CHUNK, entry, file_char);
			if (ret)
				return -1;
		}

		break;

	case MODIFY_CENTER_AND_END:
	case MODIFY_END:
		/* Add chunks at end */
		for (i = 0; i < diff; i++) {
			ret = modification_increase_size(&end_chunk,
					AFTER_REF_CHUNK, entry, file_char);
			if (ret)
				return -1;
		}

		break;

	case MODIFY_START_AND_CENTER:
	case MODIFY_START:
		/* Add chunks before start */
		for (i = 0; i < diff; i++) {
			ret = modification_increase_size(&file->first_log_chunk,
					BEFORE_REF_CHUNK, entry, file_char);
			if (ret)
				return -1;
		}

		break;

	case MODIFY_CENTER:
		/* Add chunks before middle chunk*/
		count = diff / 2;
		for (i = 0; i < count; i++) {
			ret = modification_increase_size(&mid_chunk,
					BEFORE_REF_CHUNK, entry, file_char);
			if (ret)
				return -1;
		}

		/* Add chunks after middle chunk*/
		for (i = 0; i < diff - count; i++) {
			ret = modification_increase_size(&mid_chunk,
					AFTER_REF_CHUNK, entry, file_char);
			if (ret)
				return -1;
		}

		break;

	default:
		return -1;
	}

	assert(entry->file_details.mod_info.chunk_count_new ==
						file_char->chunk_count);
	print_mod_details(file, file_char, entry);
	return 0;
}

/* Delete 'diff' number of chunks with dup counts other than unique, 1 or 2
 * from given half of file.  We won't bother if we find those many chunks
 * in the given half.
 */
static int delete_chunks(struct file *file, int diff, uint8_t del_dup_count,
				struct log_chunk **start_chunk, int scan_length,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	int deleted_chunks = 0;
	int i;
	struct log_chunk *chunk, *prev, *saved;
	uint64_t chunk_id;
	struct rb_root *root;
	struct chunk_hash_info *chunk_info;

	printf("start_from: %"PRIx64" scan_length: %d type: %d\n",
			 (uint64_t)*start_chunk, scan_length, del_dup_count);
	print_mod_details(file, file_char, entry);
	for (i = 0, prev = NULL, chunk = *start_chunk; i < scan_length &&
				   deleted_chunks < diff && chunk; i++) {
		/* find its dup_count */
		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);
		if (!chunk_info) {
			printf("Hash Not Found: %"PRIx64" Chunk: %"PRIx64
				" File: %"PRIx64"\n", chunk_id, (uint64_t)chunk,
				(uint64_t)file);
			prev = chunk;
			chunk = chunk->next;
			continue;
		}

		switch (del_dup_count) {
		case DUP_COUNT_1_OR_2:
			if (dup_count_1_or_2(chunk_info->dup_count)) {
				if (chunk_info->dup_count == DUP_COUNT_1 &&
				    file_char->num_chunks_1_dup >
				    entry->file_details.mod_info.num_chunks_1_dup_new)
					file_char->num_chunks_1_dup--;
				else if (chunk_info->dup_count == DUP_COUNT_2 &&
				    file_char->num_chunks_2_dup >
				    entry->file_details.mod_info.num_chunks_2_dup_new)
					file_char->num_chunks_2_dup--;

				if (prev)
					prev->next = chunk->next;
				else
					*start_chunk = chunk->next;

 				saved = chunk->next;
				free_chunk(&fst, chunk);
				chunk = saved;
				deleted_chunks++;
				file_char->chunk_count--;
			} else {
				prev = chunk;
				chunk = chunk->next;
			}
			break;

		case DUP_COUNT_NEITHER_1_NOR_2:
			if (dup_count_neither_1_nor_2(chunk_info->dup_count)) {
				if (prev)
					prev->next = chunk->next;
				else {
					*start_chunk = chunk->next;
				}

				saved = chunk->next;
				free_chunk(&fst, chunk);
				chunk = saved;
				deleted_chunks++;
				file_char->chunk_count--;
			} else {
				prev = chunk;
				chunk = chunk->next;
			}
			break;
		}
	}

	printf("Could delete %d chunks\n", deleted_chunks);
	return (diff - deleted_chunks);
}

static int remove_chunks(struct file *file, int diff,
			struct log_chunk **start_from, int scan_length,
			struct hash_matrix_details *entry,
			struct hash_matrix_details *file_char)
{
	int ret;

	ret = delete_chunks(file, diff, DUP_COUNT_1_OR_2, start_from,
					scan_length, entry, file_char);
	if (ret < 0)
		return -1;

	if (ret > 0) {
		printf("Could not find %d chunks of duplicate counts 1 or 2\n",
			ret);
		ret = delete_chunks(file, ret, DUP_COUNT_NEITHER_1_NOR_2,
				    start_from, scan_length, entry, file_char);
		if (ret < 0)
			return -1;

		if (ret > 0) {
			print_mod_details(file, file_char, entry);
			printf("Could not delete %d chunks: ", ret);
		}
	}

	return ret;
}

struct log_chunk **get_mid_chunk(struct file *file,
				struct hash_matrix_details *file_char)
{
	int i;
	struct log_chunk *chunk, *prev;
	/* Search central chunk */
	for (i = 0, prev = NULL, chunk = file->first_log_chunk;
				i < (file_char->chunk_count / 2);
				i++, prev = chunk, chunk = chunk->next);

	if (!prev)
		return &file->first_log_chunk;
	else
		return &prev->next;
}

static int match_decrease_size(struct file *file,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	struct log_chunk **start_from;
	int ret;
	uint32_t diff, count, scan_length;
	enum mod_pattern pattern;

	/* Decrease size case: We need to maintain the middle chunk correctly
	 * as we have correctly modified it.  Thus, following cases arise:
	 * We only remove chunks with dup_count 1 and 2 and then later to
	 * match more we remove chunks that does not have diff count 1 or 2.
	 *
	 * 1. diff = current size - expected size
	 * pattern = SCE or SC or C	1. remove diff / 2 chunks between start and center
	 *				2. remove diff / 2 chunks between end and center
	 * pattern = CE	or E		1. remove diff chunks between end and center
	 * pattern = SC	or S		1. remove diff chunks between start and center
	 *
	 * This is the point where we have dealt with first,
	 * last and middle chunk already.  So, ignore them.
	 */

	pattern = entry->file_details.mod_info.pattern;
	diff = file_char->chunk_count -
				 entry->file_details.mod_info.chunk_count_new;
	assert(diff > 0);

	switch (pattern) {
	case MODIFY_START_CENTER_AND_END:
		/* Whole Scan: Situation is SCE is to be modified and we still
		 * have to reduce count, so just scan whole length */
		start_from = &file->first_log_chunk;
		scan_length = file_char->chunk_count;
		count = diff;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		break;

	case MODIFY_START_AND_END:
		/* First Half Scan: Middle chunk excluded, first chunk included */
		start_from = &file->first_log_chunk;
		scan_length = file_char->chunk_count / 2;
		count = diff / 2;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		/* Second Half Scan: Middle chunk excluded, end chunk included */
		start_from = &(*get_mid_chunk(file, file_char))->next;
		scan_length = (file_char->chunk_count + count) - ret
							       - scan_length - 1;
		count = diff - count + ret;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		break;

	case MODIFY_CENTER:
		/* Whole Scan: first chunk excluded, Last chunk excluded */
		start_from = &file->first_log_chunk->next;
		scan_length = file_char->chunk_count - 2;
		count = diff;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		break;

	case MODIFY_CENTER_AND_END:
		/* Whole Scan: Start from chunk after start and go till end*/
		start_from = &file->first_log_chunk->next;
		scan_length = file_char->chunk_count - 1;
		count = diff;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		break;

	case MODIFY_END:
		/* First Half Scan: Middle chunk excluded, first chunk included */
		start_from = &file->first_log_chunk->next;
		scan_length = file_char->chunk_count / 2;
		count = diff / 2;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		/* Second Half Scan: Middle chunk excluded, end chunk included */
		start_from = &(*get_mid_chunk(file, file_char))->next;
		scan_length = (file_char->chunk_count + count) - ret
							       - scan_length - 1;
		count = diff - count + ret;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		break;

	case MODIFY_START_AND_CENTER:
		/* First Half Scan: Middle chunk included, first chunk included */
		start_from = &file->first_log_chunk;
		scan_length = file_char->chunk_count - 1;
		count = diff;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		break;

	case MODIFY_START:
		/* First Half Scan: Middle chunk excluded, first chunk included */
		start_from = &file->first_log_chunk;
		scan_length = (file_char->chunk_count / 2);
		count = diff;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		/* Second Half Scan: Middle chunk excluded, end chunk included */
		start_from = &(*get_mid_chunk(file, file_char))->next;
		scan_length = (file_char->chunk_count + count) - ret
							       - scan_length;
		count = diff - count + ret;
		ret = remove_chunks(file, count, start_from, scan_length,
					 entry, file_char);
		if (ret < 0)
			return -1;

		break;

	default:
		return -1;
	}

	return 0;
}

static void delete_zero_chunks(struct file *file,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	struct log_chunk *chunk, *saved, *prev = NULL;

	for (chunk = file->first_log_chunk; chunk && file_char->chunk_count >
			 entry->file_details.mod_info.chunk_count_new ; ) {
		if (!chunk->phys_id) {
			if (prev)
				prev->next = chunk->next;
			else
				file->first_log_chunk = chunk->next;
			saved = chunk->next;
			free_chunk(&fst, chunk);
			file_char->chunk_count--;
			chunk = saved;
		} else {
			prev = chunk;
			chunk = chunk->next;
		}
	}

	print_mod_details(file, file_char, entry);
}

static int match_remaining_modification(struct file *file,
				struct hash_matrix_details *entry,
				struct hash_matrix_details *file_char)
{
	int ret;
	enum mod_size state;

	if (entry->file_details.mod_info.pattern == MODIFY_MTIME_ONLY)
		return 0;

	state = get_modification_state(file_char, entry);

	switch (state) {
	case SAME_FILE_SIZE:
		return match_same_size(file, entry, file_char);
	case INCREASE_FILE_SIZE:
		/* First try to remove any extraneous and replace it
		 * with whatever you can.  Then we will add the difference.
		 */
		ret = match_same_size(file, entry, file_char);
		if (ret)
			return -1;

		if (match_complete(entry, file_char))
			return 0;

		delete_zero_chunks(file, entry, file_char);

		if (match_complete(entry, file_char))
			return 0;

		return match_increase_size(file, entry, file_char);
	case DECREASE_FILE_SIZE:
		/* First try to remove any extraneous and replace it
		 * with whatever you can.  Then we will add the difference.
		 */
		ret = match_same_size(file, entry, file_char);
		if (ret)
			return -1;

		if (match_complete(entry, file_char))
			return 0;

		delete_zero_chunks(file, entry, file_char);

		if (match_complete(entry, file_char))
			return 0;

		/* What if we match the size correctly by deleting
		 * zero chunks but few modifications are still pending.
		 * We can't go to decrease size as we achieved the
		 * correct size.  We should call the same size again
		 * How about efficiency then?  It is same as we are
		 * going to call either of same size or decrease size
		 * One round of file chunks is anyways there.  We cannot
		 * increase size so only 2 cases considered.
		 */
		state = get_modification_state(file_char, entry);
		if (state == SAME_FILE_SIZE)
			return match_same_size(file, entry, file_char);
		else
			return match_decrease_size(file, entry, file_char);
	default:
		return -1;
	}
}

static int modify_file_contents(struct file *file,
				struct hash_matrix_details *file_char,
				struct hash_matrix_details *entry)
{
	int ret;
	enum mod_size state;

	/* Modify the file first */
	file->filestate = FST_MUTABLE;
	file->mtime = time(NULL);
	file->ctime = file->mtime;
	file->atime = file->mtime;

	/* Allocate memory for hashes to remember, e.g. hashes with DC > 2 */
	ret = allocate_space_for_spl_hashes(file_char, &more_than_2_dup_hashes);
	if (ret)
		return -1;
	//printf("%s ", get_pattern(entry->file_details.mod_info.pattern));
	//print_file_details(file);
	print_mod_details(file, file_char, entry);
	/* Key point to understand here is- once we achieve target chunk
	 * count we will never be increase or decrease it any further
	 * All functions of modification, will take care to maintain that
	 * target chunk count
	 */
	switch (entry->file_details.mod_info.pattern) {
	case MODIFY_MTIME_ONLY:
		/* TODO: If we decide to deal with tail processing
		 * probably we need to add a chunk of size less than
		 * avg_chunk_size
		 */
		return 0;
	case MODIFY_START:
		ret = modify_starting_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "START", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		break;
	case MODIFY_END:
		ret = modify_end_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "END", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		break;
	case MODIFY_CENTER:
		ret = modify_center_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "CENTER", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		break;
	case MODIFY_START_AND_END:
		ret = modify_starting_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "START", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		ret = modify_end_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "END", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		break;
	case MODIFY_START_AND_CENTER:
		ret = modify_starting_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "START", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		ret = modify_center_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "CENTER", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		break;
	case MODIFY_CENTER_AND_END:
		ret = modify_center_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "CENTER", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		ret = modify_end_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "END", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		break;
	case MODIFY_START_CENTER_AND_END:
		ret = modify_starting_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "START", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		ret = modify_center_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "CENTER", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		ret = modify_end_chunk(file, entry, file_char);
		if (ret) {
			display_error_message(file, "END", entry, file_char);
			return -1;
		}
		print_mod_details(file, file_char, entry);
		break;
	default:
		return -1;
	}

	if (match_complete(entry, file_char))
		return 0;

	printf("Requires more mod\n");
	ret = match_remaining_modification(file, entry, file_char);
	if (ret) {
		display_error_message(file, "REMAINING", entry, file_char);
		return -1;
	}

	if (!match_complete(entry, file_char)) {
		printf("Could not successfully match modification\n");
		failed_mod++;
		/* Though we fail the modification, make sure that total
		 * chunk count matches correctly, so that file will still
		 * be selected for mutation in later iteration.
		 */
		state = get_modification_state(file_char, entry);
		if (state != SAME_FILE_SIZE)
			chunk_count_mismatch++;
	}
	print_mod_details(file, file_char, entry);

	return 0;
}

static struct file_list *search_mod_sequential(struct hash_matrix_details *entry,
					   struct file_list **current)
{
	struct file_list *node, *track;

	for (node = entry->file_details.mod_info.head, track = NULL;
				 node; track = node, node = node->next)
		if (node->file->filestate == FST_NEW_PREV ||
		    node->file->filestate == FST_MUTABLE_PREV ||
		    node->file->filestate == FST_IMMUTABLE_PREV)
			break;

	if (track == NULL)
		for (track = entry->file_details.mod_info.head;
				track->next; track = track->next);

	*current = track;
	return node;
}

static int update_mod_distro_counts(struct chunk_hash_info *chunk_info)
{
	struct dup_chunk_distro *distro;
	struct dup_chunk_details *entry;
	int i;

	distro = &profile->mod_files_dup_chunk_distro_sid1;

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];
		if (entry->dup_count == chunk_info->dup_count) {
			assert(entry->num_chunks - 1 >= 0);
			entry->num_chunks--;
			return 0;
		}
	}

	printf("Strange !! We did not find dup_count for this chunk\n");
	return 0;
}

static int update_modified_files_distro(struct file *file)
{
	struct log_chunk *chunk;
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;
	int ret;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {
		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);
		if (!chunk_info)
			return -1;

		/* Decrement number of chunks from distro */
		ret = update_mod_distro_counts(chunk_info);
		if (ret)
			return -1;
	}

	return 0;
}

static int modify_random_files(struct hash_matrix_details *entry)
{
	uint32_t i, j;
	int ret;
	struct file_list *current, *node;
	uint32_t num;
	uint32_t modified_file_count = 0;
	struct hash_matrix_details file_char;

	if (entry->num_files > entry->file_details.mod_info.num_nodes) {
		printf("Ignore Modify case: \n");
		print_mod_files_entry(entry);
		entry->file_details.mod_info.status = PROCESS_IN_PASS_2;
#if DEBUG_DEVIATION
		record_deviation(entry, MODIFICATION, entry->num_files);
#endif
		return 0;
	}

	for (i = 0; i < entry->num_files; i++) {

		num = random() % entry->file_details.mod_info.num_nodes;

		/* Modify 'num + 1' file entry from list */
		current = entry->file_details.mod_info.head;
		for (j = 0; j < num; j++, current = current->next) ;

		/* It is possible that one file is in multiple rows,
		 * So, if we have already mutated its state, then
		 * look for next one
		 */

		if (current->next == NULL)
			node = entry->file_details.mod_info.head;
		else
			node = current->next;

		if (node->file->filestate != FST_NEW_PREV &&
		    node->file->filestate != FST_MUTABLE_PREV &&
		    node->file->filestate != FST_IMMUTABLE_PREV) {
			node = search_mod_sequential(entry, &current);
			if (!node || !current) {
				printf("Ignore Modify case:\n");
				print_mod_files_entry(entry);
				entry->file_details.mod_info.status =
							 PARTIALLY_PROCESSED;
				entry->num_files -= modified_file_count;
#if DEBUG_DEVIATION
				record_deviation(entry, MODIFICATION,
						 entry->num_files);
#endif
				return 0;
			}
		}

		/* Sheer randomness.  If we get last node, we modify
		 * head.  Just like that.
		 */
		if (current->next == NULL)
			entry->file_details.mod_info.head = node->next;
		else
			current->next = node->next;

		/* Modify file contents as per indicated by *_new values*/
		ret = update_modified_files_distro(node->file);
		if (ret)
			return -1;

		file_char.chunk_count = entry->chunk_count;
		file_char.num_uniq_chunks = 0;
		/* Across the snapshots the numbers will propogate one column */
		file_char.num_chunks_1_dup = entry->num_uniq_chunks;
		file_char.num_chunks_2_dup = entry->num_chunks_1_dup;

		ret = modify_file_contents(node->file, &file_char, entry);
		if (ret)
			return -1;

		free(node);
		modified_file_count++;
		entry->file_details.mod_info.num_nodes--;
	}

	return 0;
}

static int modify_all_files_sequentially(struct hash_matrix_details *entry)
{
	int ret;
	struct file_list *current, *saved;
	struct hash_matrix_details file_char;

	for (current = entry->file_details.mod_info.head; current; ) {

		/* When we are putting same file in multiple matrix rows, it
		 * is possible that a file get modified with earlier row and
		 * it is the same file found in next row of matrix.  We can't
		 * try selecting different file as num_files = num_nodes
		 * So just ignore such file.
		 */
		if (current->file->filestate == FST_NEW_PREV ||
		    current->file->filestate == FST_MUTABLE_PREV ||
		    current->file->filestate == FST_IMMUTABLE_PREV) {

			/* Modify file contents as per indicated by *_new values*/
			ret = update_modified_files_distro(current->file);
			if (ret)
				return -1;

			file_char.chunk_count = entry->chunk_count;
			file_char.num_uniq_chunks = 0;
			/* Across the snapshots the numbers will propogate one column */
			file_char.num_chunks_1_dup = entry->num_uniq_chunks;
			file_char.num_chunks_2_dup = entry->num_chunks_1_dup;

			ret = modify_file_contents(current->file, &file_char, entry);
			if (ret)
				return -1;
			processed_files++;
		}

		saved = current->next;
		free(current);
		current = saved;
		entry->file_details.mod_info.num_nodes--;
		entry->num_files--;
	}

	assert(entry->file_details.mod_info.num_nodes == 0);

	return 0;
}

static int modify_required_files()
{
	int ret;
	int i;
	struct hash_matrix_details *entry;
	struct file_list *current, *saved;

	processed_files = 0;
	ret = walk_fstree(&fst, extract_modification_characteristics);
	if (ret < 0)
		return -1;

	printf("\n");

	print_mod_files_hash_matrix(&profile->mod_files_matrix);

	/* Now just modify required number of files as indicated by num_files
	 * filed in matrix.  We randomly select those many number of files.
	 *
	 * Ideally, difference between expected number of files to be
	 * deleted and potential number of files found matching the deletion
	 * criteria should be very small.  Adding more dimensions to the
	 * matrix would achieve that.  But, still, this is better than
	 * selecting file absolutely randomly.
	 *
	 * We mark the file FST_MUTABLE
	 */
	processed_files = 0;

	/* Deal with trivial search first, i.e., num_files >= num_nodes */
	for (i = 0; i < profile->mod_files_matrix.num_entries; i++) {
		entry = &profile->mod_files_matrix.entries[i];
		if (entry->num_files >= entry->file_details.mod_info.num_nodes &&
		    entry->file_details.mod_info.num_nodes > 0) {
			ret = modify_all_files_sequentially(entry);
			if (ret)
				return -1;
			entry->file_details.mod_info.status = PARTIALLY_PROCESSED;
#if DEBUG_DEVIATION
			record_deviation(entry, MODIFICATION, entry->num_files);
#endif
		}
	}

	for (i = 0; i < profile->mod_files_matrix.num_entries; i++) {
		entry = &profile->mod_files_matrix.entries[i];
		if (entry->file_details.mod_info.status == NOT_PROCESSED) {
			ret = modify_random_files(entry);
			if (ret)
				return -1;

			/* Free out rest of the nodes */
			for (current = entry->file_details.mod_info.head; current; ) {
				saved = current->next;
				free(current);
				current = saved;
				entry->file_details.mod_info.num_nodes--;
			}

			assert(entry->file_details.mod_info.num_nodes == 0);
			printf("Successfully Modified %6"PRIu64" files\n",
							 entry->num_files);
		}
	}

	return 0;
}

/************************ Modify Required Files: Pass 2 ************************/
static uint8_t match_mod_matrix_pass_2(struct hash_matrix_details *file_char,
				   struct hash_matrix_details **ret_entry)
{
	int i;
	struct hash_matrix_details *entry;

	for (i = 0; i < profile->mod_files_matrix.num_entries; i++) {
		entry = &profile->mod_files_matrix.entries[i];
		if ((entry->file_details.mod_info.status == PROCESS_IN_PASS_2 ||
		     entry->file_details.mod_info.status == PARTIALLY_PROCESSED) &&
		    entry->num_files > 0				     &&
		    file_char->depth == entry->depth			     &&
		    !strcmp(file_char->extension, entry->extension) 	     &&
		    file_char->chunk_count == entry->chunk_count 	     &&
		    file_char->file_details.mod_info.prev_state ==
				     entry->file_details.mod_info.prev_state) {
			*ret_entry = entry;
			return TRUE;
		}
	}

	return FALSE;
}

static uint8_t match_mod_distro(struct chunk_hash_info *chunk_info)
{
	struct dup_chunk_distro *distro;
	struct dup_chunk_details *entry;
	int i;

	distro = &profile->mod_files_dup_chunk_distro_sid1;

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];
		if (entry->dup_count == chunk_info->dup_count &&
		    entry->num_chunks > 0)
			return TRUE;
	}

	return FALSE;
}

static uint8_t match_modification_distro(struct file *file)
{
	struct log_chunk *chunk;
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {

		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);
		if (!chunk_info) {
			printf("Hash Not Found: %"PRIx64" Chunk: %"PRIx64
				" File: %"PRIx64"\n", chunk_id, (uint64_t)chunk,
				(uint64_t)file);
			print_file_details(file);
			return -1;
		}

		/* Even if one is not allowed, we cannot use this file */
		if (!match_mod_distro(chunk_info))
			return FALSE;
	}

	return TRUE;
}

static int pass_2_modification(void *object, int type, int level)
{
	struct file *file;
	struct log_chunk *chunk;
	int ret;
	struct hash_matrix_details file_char;
	struct hash_matrix_details *entry;
	uint8_t match_found_in_matrix = FALSE;
	uint8_t distro_preserved = FALSE;
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;

	if (type == OBJ_TYPE_DIR)
		return 0;

	file = (struct file *)object;
	/* Already modified file not selected for deletion */
	if (file->filestate != FST_NEW_PREV &&
	    file->filestate != FST_MUTABLE_PREV &&
	    file->filestate != FST_IMMUTABLE_PREV)
		return 0;

	file_char.depth = level;
	strncpy(file_char.extension, file->extension, MAX_EXT_LEN);
	file_char.chunk_count = file_char.num_chunks_1_dup = 0;
	file_char.num_uniq_chunks = file_char.num_chunks_2_dup = 0;
	file_char.file_details.mod_info.prev_state = file->filestate;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {
		file_char.chunk_count++;
		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);

		switch (chunk_info->dup_count) {
		case 1:	file_char.num_uniq_chunks++;
			break;
		case 2: file_char.num_chunks_1_dup++;
			break;
		case 3: file_char.num_chunks_2_dup++;
			break;
		}
	}

	/* Find if this file can possibly placed in one of the rows of matrix.
	 * Match will be liberal, unique, 1DC and 2DC not matched.
	 */
	match_found_in_matrix = match_mod_matrix_pass_2(&file_char, &entry);

	if (!match_found_in_matrix)
		return 0;

	//distro_preserved = match_modification_distro(file);
	distro_preserved = TRUE;

	if (!distro_preserved)
		return 0;

	/* Modifying this file should be safe now */
	processed_files++;
	file_char.num_chunks_2_dup = file_char.num_chunks_1_dup;
	file_char.num_chunks_1_dup = file_char.num_uniq_chunks;
	file_char.num_uniq_chunks = 0;
	ret = modify_file_contents(file, &file_char, entry);
	if (ret)
		return -1;

	entry->num_files--;
#if DEBUG_DEVIATION
	distro_dev.num_files_not_modified--;
	distro_dev.uniq_chunk_increase -= file_char.num_uniq_chunks;
	distro_dev.chunk_1_dup_increase -= file_char.num_chunks_1_dup;
	distro_dev.chunk_2_dup_increase -= file_char.num_chunks_2_dup;
#endif
	return 0;
}

static int modify_required_files_pass_2()
{
	int ret;

#if DEBUG_DEVIATION
	printf("We failed to modify %"PRIu64" files during pass 1\n",
					distro_dev.num_files_not_modified);
#endif
	processed_files = 0;
	ret = walk_fstree(&fst, pass_2_modification);
	if (ret < 0)
		return -1;

	printf("We managed to modify %"PRIu64" extra files in second pass\n",
							processed_files);
	return 0;
}


/******************* Marking Rest of the files Immutable ********************/
static int mark_files_immutable(void *object, int type, int level)
{
	struct file *file;
	int ret;

	if (type == OBJ_TYPE_DIR)
		return 0;

	file = (struct file *)object;

	if (file->filestate == FST_NEW_PREV ||
	    file->filestate == FST_MUTABLE_PREV ||
	    file->filestate == FST_IMMUTABLE_PREV) {
		processed_files++;
		file->filestate = FST_IMMUTABLE;
	}

	/* Classify deleted files: These files are eventually utilized
	 * for re-creation */
	if (file->filestate == FST_DELETED_PREV) {
		ret = place_file_in_new_files_matrix(file, level);
		if (ret)
			return -1;
	}

	return 0;
}

static int count_files(void *object, int type, int level)
{
	struct file *file;

	if (type == OBJ_TYPE_DIR)
		return 0;

	file = (struct file *)object;

#if DEBUG_DEVIATION
	if (file->filestate == FST_NEW ||
	    file->filestate == FST_MUTABLE ||
	    file->filestate == FST_IMMUTABLE)
		check_1_duplicate(file, level);
	//print_file_details(file);
#endif

	switch (file->filestate) {
	case FST_NEW: new_files++; break;
	case FST_NEW_PREV: new_files_prev++; break;
	case FST_MUTABLE: mod_files++; break;
	case FST_MUTABLE_PREV: mod_files_prev++; break;
	case FST_IMMUTABLE: unmod_files++; break;
	case FST_IMMUTABLE_PREV: unmod_files_prev++; break;
	case FST_DELETED: del_files++; break;
	case FST_DELETED_PREV: del_files_prev++; break;
	case FST_IGNORE: ignored_files++; break;
	default: error_files++; break;
	}

	total_files++;

	return 0;
}


/************************* Reading Mutation Profile **************************/
static void load_profile(char *profile_file)
{
	FILE *profile_fp;
	int prob_val;
	int i, ret;

	profile_fp = fopen(profile_file, "r");
	if (!profile_fp) {
		printf("Failed to open file: %s\n", profile_file);
		exit(1);
	}

	fscanf(profile_fp, "%"PRIu32"\n", &profile->avg_chunk_size);

	/* figuring out number the number files
		 to switch for this specific fstree */
	for (i = PR_N; i < PR_MAX; i++) {
		fscanf(profile_fp, "%d\n", &prob_val);

		/* Build a cumulative distribution */
		switch (i) {
		case PR_N:
		case PR_NM:
		case PR_MM:
		case PR_IM:
		case PR_DN:
			profile->st_switch_prob[i] = prob_val;
			break;
		case PR_NI:
		case PR_MI:
		case PR_II:
			profile->st_switch_prob[i] =
				profile->st_switch_prob[i - 1] + prob_val;
			break;
		case PR_ND:
		case PR_MD:
		case PR_ID:
			profile->st_switch_prob[i] = MOD_VAL;
			break;
		}
	}

	ret = read_new_files_hash_matrix(&profile->new_files_matrix, profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	ret = read_dup_chunk_distro(&profile->new_files_dup_chunk_distro,
								profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	ret = read_del_files_hash_matrix(&profile->del_files_matrix, profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	ret = read_dup_chunk_distro(&profile->del_files_dup_chunk_distro,
								profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	ret = read_mod_files_hash_matrix(&profile->mod_files_matrix, profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	ret = read_dup_chunk_distro(&profile->mod_files_dup_chunk_distro_sid1,
								profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	ret = read_dup_chunk_distro(&profile->mod_files_dup_chunk_distro_sid2,
								profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	ret = read_dup_chunk_distro(&profile->intra_snapshot_uniq_chunk_distro,
								 profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	ret = read_dup_chunk_distro_ext(&profile->prev_snapshot_hash_distro,
								 profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	ret = read_dup_chunk_distro_ext(&profile->del_files_common_hash_distro,
								 profile_fp);
	if (ret) {
		printf("Error reading profile file: %s\n", profile_file);
		exit(1);
	}

	fclose(profile_fp);
}

/***************************** Main Program Logic *****************************/
static void rand_init()
{
	srand(time(NULL));
	srand48(time(NULL));
}

static void file_statistics()
{
	int ret;
#if DEBUG_DEVIATION
	struct chunks_with_1_dup *current;
	uint64_t ctr = 0;
#endif

	new_files = new_files_prev = mod_files = mod_files_prev = 0;
	del_files = del_files_prev = unmod_files = unmod_files_prev = 0;
	total_files = error_files = ignored_files = 0;

	ret = walk_fstree(&fst, count_files);
	if (ret) {
		printf("Failed to mark files immutable");
		exit(1);
	}

	printf("New Files: %"PRIu64", New files prev: %"PRIu64"\n"
		"Mod Files: %"PRIu64", Mod Files Prev: %"PRIu64"\n"
		"UnMod Files: %"PRIu64", UnMod Files Prev: %"PRIu64"\n"
		"Del Files: %"PRIu64", Del Files Prev: %"PRIu64"\n"
		"Error Files: %"PRIu64", Total Files: %"PRIu64"\n"
		"Ignored Files: %"PRIu64" Failed Mod: %"PRIu64"\n"
		"Files Mutated with chunk count mismatch: %"PRIu64"\n",
		new_files, new_files_prev, mod_files, mod_files_prev,
		unmod_files, unmod_files_prev, del_files, del_files_prev,
		error_files, total_files, ignored_files, failed_mod,
		chunk_count_mismatch);

#if DEBUG_DEVIATION
	for (current = watch_chunks; current; current = current->next) {
		if (current->count == 1)
			ctr++;
	}

	printf("Chunks with 1 duplicate: %"PRIu64"\n", ctr);
	printf("UC[+]: %"PRIu64" UC[-]: %"PRIu64" 1DC[+]: %"PRIu64
		" 1DC[-]: %"PRIu64" 2DC[+]: %"PRIu64" 2DC[-]: %"PRIu64"\n",
		distro_dev.uniq_chunk_increase, distro_dev.uniq_chunk_decrease,
		distro_dev.chunk_1_dup_increase, distro_dev.chunk_1_dup_decrease,
		distro_dev.chunk_2_dup_increase, distro_dev.chunk_2_dup_decrease);
	printf("Num Files not deleted: %"PRIu64"\n", distro_dev.num_files_not_deleted);
	printf("Num Files not modified: %"PRIu64"\n", distro_dev.num_files_not_modified);
#endif
}

static char *usage_str = "-i <input file> -p <profile file> [-o <output file>]";
static char *usage_desc =
"-i: read fstree from <input file>\n"
"-o: instead of overwritting <input file>, write to a new  <output file>\n"
"-p: Profile to use for mutation of file system.\n";

static void usage(char *progname)
{
	fprintf(stderr, "Usage: %s %s\n%s", progname, usage_str, usage_desc);
}

static int build_chunk_dist_switch_states(void *object, int type, int level)
{
	struct file *f;

	if (type == OBJ_TYPE_DIR)
		return 0;

	f = (struct file *)object;

	/*
	 * Switch file state to its *_PREV equivalent. Essentially, what
	 * *_PREV indicates is that given file has not yet been mutated to its
	 * destination stat.
	 */
	switch_file_state_prev(f);
	if (f->filestate != FST_NEW_PREV &&
	    f->filestate != FST_MUTABLE_PREV &&
	    f->filestate != FST_IMMUTABLE_PREV)
		return 0;

	return add_chunks_to_hash_table(object, type, level);
}

int main(int argc, char **argv)
{
	char *input_file = NULL, *output_file = NULL;
	char *profile_file = NULL;
	int ret;
	int opt;
	int fd;

	while (1) {
		opt = getopt(argc, argv, "i:o:p:");
		if (opt == -1)
			break;

		switch (opt) {
		case 'i':
			input_file = optarg;
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'p':
			profile_file = optarg;
			break;
		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (!input_file) {
		fprintf(stderr, "Input file was not specified!");
		usage(argv[0]);
		return -1;
	}

	if (!output_file)
		output_file = input_file;

	if (!strcmp(input_file, "-"))
		fd = STDIN_FILENO;
	else
		fd = open(input_file, O_RDONLY);

	if (fd < 0) {
		perror("Failed to open input file");
		return -1;
	}

	ret = load_fstree(&fst, fd);
	if (ret < 0) {
		perror("Failed to load fs tree from input file");
		close(fd);
		return -1;
	}
	close(fd);

	rand_init();
	profile = (struct mutation_profile *)
				calloc(1, sizeof(*profile));
	if (!profile) {
		perror("Failed to allocate file distro object.");
		return -1;
	}

	/* will exit in case of error */
	load_profile(profile_file);

	/*
	 * Create a table where a given hash
	 * and its duplicate count is determined.
	 */
	init_chunk_hash_table(hash_table, HASH_TABLE_SIZE);
	ret = walk_fstree(&fst, build_chunk_dist_switch_states);
	if (ret < 0) {
		perror("Failed to build chunk distribution");
		return -1;
	}

	ret = build_intra_snapshot_uniq_hash_distro(
				&profile->intra_snapshot_uniq_chunk_distro);
	if (ret < 0) {
		perror("Failed to set unique hashes.");
		return -1;
	}

	/* Scan through all files in file system tree to extract their
	 * properties like number of uniq chunks, number of chunks with
	 * 1 duplicates and so on.  Place the file in the matrix
	 * for deleted files as potential file for deletion
	 */
	printf("Deletion - Pass 1\n");
	ret = delete_required_files();
	if (ret < 0) {
		printf("Failed to delete required files\n");
		return -1;
	}

	printf("Deletion - Pass 1 Finished.  Collecting hashes\n");
	ret = setup_prev_snapshot_hashes(&profile->prev_snapshot_hash_distro,
					 &profile->del_files_common_hash_distro);
	if (ret < 0) {
		perror("Failed to set hashes from previous snapshot.");
		return -1;
	}
	/* Let us first modify files, so we don't delete
	 * a file for modification
	 */
	printf("Hashes Collected.  Modification - Pass 1\n");
	ret = modify_required_files();
	if (ret < 0) {
		perror("Failed to modify required files");
		return -1;
	}

	printf("Modification - Pass 1 finished.  Deletion - Pass 2\n");
	ret = delete_required_files_pass_2();
	if (ret < 0) {
		printf("Failed to delete required files in pass 2\n");
		return -1;
	}

	printf("Deletion - Pass 2 finished.  Modification - Pass 2\n");
	ret = modify_required_files_pass_2();
	if (ret < 0) {
		printf("Failed to modify required files in pass 2\n");
		return -1;
	}

	printf("Modification - Pass 2 finished.  Marking rest immutable\n");
	processed_files = 0;
	/* Any *_PREV should now be marked as FST_IMMUTABLE */
	ret = walk_fstree(&fst, mark_files_immutable);
	if (ret) {
		perror("Failed to mark files immutable");
		return -1;
	}

	printf("Files marked immutable.  Creating new files\n");
	/* Now add new files */
	ret = create_required_new_files(&profile->new_files_matrix);
	if (ret) {
		perror("Failed to create required new files\n");
		return -1;
	}

	/* TODO: We are not done yet. Free up any files with status
	 * FST_DELETED_PREV, But, we cannot use walk_fstree and delete
	 * files with given state as the list operation would screw up
	 * Currently, we would just not create any file with state
	 * FST_DELETED_PREV */
#if 0
	ret = walk_fstree(&fst, cleanup);
	if (ret) {
		perror("Failed to mark files immutable");
		return -1;
	}
#endif
	printf("Files created.  Collecting statistics\n");
	file_statistics();

	/* write out modified tree data */
	if (!strcmp(output_file, "-"))
		fd = STDOUT_FILENO;
	else
		fd = open(output_file, O_WRONLY | O_TRUNC | O_CREAT,
			  S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP
				  | S_IROTH | S_IWOTH);
	if (fd < 0) {
		perror("Failed to open output file for writing");
		return -1;
	}
	ret = save_fstree(&fst, fd);
	if (ret < 0) {
		perror("Failed to save fs tree to output file");
		close(fd);
		return -1;
	}
	close(fd);

	return 0;
}
