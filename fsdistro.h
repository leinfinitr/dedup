#ifndef _FSDISTRO_H
#define _FSDISTRO_H

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "fstree.h"
#include "rbtree.h"

#define DUP_COUNT_ANY			0
#define DUP_COUNT_1			1
#define DUP_COUNT_2			2
#define DUP_COUNT_1_OR_2		3
#define DUP_COUNT_NEITHER_1_NOR_2	4

#define MAXLINE		512

#define NULL_EXTENSION	"(null)"

#define NEW_FILES		1
#define MOD_FILES		2

/* Hash Table to put a given hash of the chunk in bucket */
#define HASH_TABLE_SIZE		65536
extern struct rb_root hash_table[HASH_TABLE_SIZE];
#define HASH_SIZE_BYTES		(sizeof(uint64_t))

enum mod_pattern {
	PATTERN_ERROR = 0,
	MODIFY_MTIME_ONLY = 1,
	MODIFY_START = 2,
	MODIFY_END = 3,
	MODIFY_CENTER = 4,
	MODIFY_START_AND_END = 5,
	MODIFY_START_AND_CENTER = 6,
	MODIFY_CENTER_AND_END = 7,
	MODIFY_START_CENTER_AND_END = 8,
};

enum mod_position {
	BEFORE_REF_CHUNK = 1,
	AFTER_REF_CHUNK = 2,
	SAME_REF_CHUNK = 3,
};

enum mod_size {
	SIZE_ERROR = 0,
	INCREASE_FILE_SIZE = 1,
	DECREASE_FILE_SIZE = 2,
	SAME_FILE_SIZE = 3,
};

enum processing_status {
	PROCESSED		= 0,
	NOT_PROCESSED		= 1,
	PARTIALLY_PROCESSED	= 2,
	PROCESS_IN_PASS_2 	= 3,
};

#define HASH_WITH_1_DUP_FOUND		1
#define HASH_WITH_2_DUP_FOUND		2
#define HASH_WITH_GREATER_DUP_FOUND	3

struct chunk_hash_info {
	uint64_t	chunk_hash;
	uint32_t	dup_count;
	uint8_t		flags;
	struct rb_node	node;
};

struct file_list {
	struct file		*file;
	uint8_t			flags;
	struct file_list	*next;
};

struct new_files_details {
	uint64_t		num_nodes;
	struct file_list	*head;
};

struct del_files_details {
	enum file_states 	prev_state;
	uint64_t		num_nodes;
	enum processing_status	status;
	struct file_list	*head;
};

struct mod_files_details {
	enum file_states 	prev_state;
	uint64_t		chunk_count_new;
	uint64_t		num_uniq_chunks_new;
	uint64_t		num_chunks_1_dup_new;
	uint64_t		num_chunks_2_dup_new;
	enum mod_pattern	pattern;
	uint64_t		num_nodes;
	uint8_t			processed;
	enum processing_status	status;
	struct file_list	*head;
};

struct hash_matrix_details {
	uint8_t			depth;
	char			extension[MAX_EXT_LEN];
	uint64_t		chunk_count;
	uint64_t		num_uniq_chunks;
	uint64_t		num_chunks_1_dup;
	uint64_t		num_chunks_2_dup;
	uint64_t		num_files;
	union {
		struct new_files_details	new_info;
		struct del_files_details 	del_info;
		struct mod_files_details 	mod_info;
	} file_details;
};

struct uniq_count {
	uint64_t	num_hashes;
	uint64_t	*hashes;
	uint64_t	num_filled;
	uint64_t	next_available;
};

struct hash_matrix {
	uint32_t			num_entries;
	struct hash_matrix_details	*entries;
};

struct remembered_hashes {
	uint64_t	*hashes;
	uint64_t	total_hashes;
	uint64_t	used_slots;
	uint64_t	free_slots;
	uint64_t	available;
};

struct dup_chunk_details {
	/* number of duplicates */
	uint32_t	dup_count;
	/* number of chunks that have corresponding number of duplicates */
	uint64_t	num_chunks;
	/* All hashes from previous snapshot with number of duplicates
	 * equal to 'dup_count */
	uint8_t		*hashes;
	uint64_t	first_free_index;
	uint64_t	num_available;
};

struct dup_chunk_distro {
	uint32_t			num_entries;
	struct dup_chunk_details	*entries;
};

/* Extended Version */
struct dup_chunk_details_ext {
	/* number of duplicates */
	uint32_t	dup_count;
	/* Distinct among num_chunks */
	uint64_t	distinct_chunks;
	uint64_t	all_chunks;
	/* All hashes from previous snapshot with number of duplicates
	 * equal to 'dup_count */
	uint8_t		*all_hashes;
	uint8_t		*distinct_hashes;
	uint64_t	first_free_index;
	uint64_t	num_available;
};

struct dup_chunk_distro_ext {
	uint32_t			num_entries;
	struct dup_chunk_details_ext	*entries;
};

struct duplicate_distro_node {
	uint32_t			dup_count;
	uint64_t			hash_count;
	struct duplicate_distro_node	*next;
};

int read_dup_chunk_distro(struct dup_chunk_distro *dup_distro, FILE *fp);
void print_dup_chunk_distro(struct dup_chunk_distro *dup_distro);
int read_new_files_hash_matrix(struct hash_matrix *matrix, FILE *fp);
void print_new_files_hash_matrix(struct hash_matrix *matrix);
int read_del_files_hash_matrix(struct hash_matrix *matrix, FILE *fp);
void print_del_files_hash_matrix(struct hash_matrix *matrix);
int read_mod_files_hash_matrix(struct hash_matrix *matrix, FILE *fp);
void print_mod_files_hash_matrix(struct hash_matrix *matrix);
#if 0
int set_hashes_files(struct dup_chunk_distro *distro);
#endif
int build_intra_snapshot_uniq_hash_distro(struct dup_chunk_distro *distro);
int set_hashes_files(uint8_t hashes_for);
uint64_t find_available_chunk_id(uint8_t dup_count,
				struct dup_chunk_distro *distro);
uint64_t get_uniq_chunk_id();
int insert_hash_rbtree(struct rb_root *root,
				 struct chunk_hash_info *hash);
struct chunk_hash_info *search_hash_rbtree(struct rb_root *root,
						 uint64_t chunk_phys_id);
enum mod_pattern set_pattern(char *pattern);
char *get_pattern(enum mod_pattern pattern);
enum mod_size get_modification_state(struct hash_matrix_details *file_char,
				     struct hash_matrix_details *entry);
void print_mod_files_entry(struct hash_matrix_details *entry);
void print_new_files_matrix_entry(struct hash_matrix_details *entry);
int allocate_space_for_spl_hashes(struct hash_matrix_details *file_char,
					struct remembered_hashes *hash_set);
void remember_chunk(uint64_t chunk_id);
int read_uniq_count_hashes(struct uniq_count *uniq_count_hashes, FILE *fp);
void init_chunk_hash_table(struct rb_root *hash_table, uint32_t size);
int add_chunks_to_hash_table(void *object, int type, int level);
int traverse_hash_table(void);
int setup_prev_snapshot_hashes(struct dup_chunk_distro_ext *all_distro,
			       struct dup_chunk_distro_ext *del_distro);
int read_dup_chunk_distro_ext(struct dup_chunk_distro_ext *dup_distro, FILE *fp);
uint64_t find_available_chunk_id_ext(uint8_t dup_count, uint8_t hash_for,
				struct dup_chunk_distro_ext *distro);
#endif /* _FSDISTRO_H */
