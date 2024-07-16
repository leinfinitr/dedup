#ifndef _FSTREE_MUTATE_H
#define _FSTREE_MUTATE_H

#include <inttypes.h>

#include "fsdistro.h"

#define PR_N	1

#define PR_NM	2
#define PR_NI	3
#define PR_ND	4

#define PR_MM	5
#define PR_MI	6
#define PR_MD	7

#define PR_IM	8
#define PR_II	9
#define PR_ID	10

#define PR_DN	11

#define PR_MAX	(PR_DN + 1)

/* Instead of dealing % probabilities, we scaled it 100 times so that
 * smaller probabilities get better representation.
 */
#define MOD_VAL	10000

/*
#define PAGE_SIZE		4096

#define NUM_HASH_ENTRIES	\
		((PAGE_SIZE / sizeof(struct chunk_hash_info)) - 1)

struct node {
	struct hash_info	hash_array[NUM_HASH_ENTRIES];
	uint16_t		next_free_entry_index;
	struct node		*next;
};

union page {
	uint8_t		data[PAGE_SIZE];
	struct node	list_node;
};
*/

struct mutation_profile {
	uint32_t			avg_chunk_size;
	/* how many switches to perform for this specific tree
		based on the probabilities in the profile
			and number of files in the fstree */
	uint64_t			st_switch_prob[PR_MAX];
	struct hash_matrix		new_files_matrix;
	struct dup_chunk_distro		new_files_dup_chunk_distro;
	struct hash_matrix		del_files_matrix;
	struct dup_chunk_distro 	del_files_dup_chunk_distro;
	struct hash_matrix		mod_files_matrix;
	struct dup_chunk_distro 	mod_files_dup_chunk_distro_sid1;
	struct dup_chunk_distro		mod_files_dup_chunk_distro_sid2;
	struct dup_chunk_distro 	intra_snapshot_uniq_chunk_distro;
	struct dup_chunk_distro_ext	prev_snapshot_hash_distro;
	struct dup_chunk_distro_ext	del_files_common_hash_distro;
};

#endif /*_FSTREE_MUTATE_H */
