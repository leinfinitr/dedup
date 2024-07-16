#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "fsdistro.h"
#include "fstree-mutate.h"

static struct rb_root uniq_chunk_hash_table[HASH_TABLE_SIZE];
static struct rb_root distinct_hash_table[HASH_TABLE_SIZE];
static uint64_t duplicate_uniq_chunk_id_generated;

uint64_t num_files_analyzed = 0;
int read_dup_chunk_distro(struct dup_chunk_distro *dup_distro, FILE *fp)
{
	int i;
	struct dup_chunk_details *entry;

	fscanf(fp, "%"PRIu32"\n", &dup_distro->num_entries);

	dup_distro->entries = (struct dup_chunk_details *)
				malloc(sizeof(*entry) * dup_distro->num_entries);
	if (!dup_distro->entries) {
		printf("Failed to allocate space for duplicate distribution\n");
		exit(1);
	}

	for (i = 0; i < dup_distro->num_entries; i++) {
		entry = &dup_distro->entries[i];
		fscanf(fp, "%"PRIu32",%"PRIu64"\n",
			&entry->dup_count, &entry->num_chunks);
	}

	return 0;
}

void print_dup_chunk_distro(struct dup_chunk_distro *dup_distro)
{
	int i;
	struct dup_chunk_details *entry;

	for (i = 0; i < dup_distro->num_entries; i++) {
		entry = &dup_distro->entries[i];
		printf("%"PRIu32" -> %"PRIu64"\n",
			entry->dup_count, entry->num_chunks);
	}
}

int read_dup_chunk_distro_ext(struct dup_chunk_distro_ext *dup_distro, FILE *fp)
{
	int i;
	struct dup_chunk_details_ext *entry;

	fscanf(fp, "%"PRIu32"\n", &dup_distro->num_entries);

	dup_distro->entries = (struct dup_chunk_details_ext *)
				malloc(sizeof(*entry) * dup_distro->num_entries);
	if (!dup_distro->entries) {
		printf("Failed to allocate space for duplicate distribution\n");
		exit(1);
	}

	for (i = 0; i < dup_distro->num_entries; i++) {
		entry = &dup_distro->entries[i];
		fscanf(fp, "%"PRIu32",%"PRIu64",%"PRIu64"\n",
			&entry->dup_count, &entry->distinct_chunks,
			&entry->all_chunks);
	}

	return 0;
}

void print_dup_chunk_distro_ext(struct dup_chunk_distro_ext *dup_distro)
{
	int i;
	struct dup_chunk_details_ext *entry;

	for (i = 0; i < dup_distro->num_entries; i++) {
		entry = &dup_distro->entries[i];
		printf("%"PRIu32" -> %"PRIu64" -> %"PRIu64"\n",
			entry->dup_count, entry->distinct_chunks,
			entry->all_chunks);
	}
}

int parse_new_file_matrix_line(char *line, struct hash_matrix_details *entry)
{
	char *token;

	/* First token is depth */
	token = strtok(line, ",");
	if (!token)
		return -1;

	sscanf(token, "%"SCNu8, &entry->depth);

	/* Next: Extension */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	if (!strcmp(token, NULL_EXTENSION))
		entry->extension[0] = '\0';
	else {
		strncpy(entry->extension, token, 6);
		entry->extension[6] = '\0';
	}

	/* Next: chunk_count */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->chunk_count);

	/* Next: No Unique Chunks*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_uniq_chunks);

	/* Next: No Chunks with 1 Duplicate*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_chunks_1_dup);

	/* Next: No Chunks with 2 Duplicate*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_chunks_2_dup);

	/* Next: No of Files*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_files);

	return 0;
}

int read_new_files_hash_matrix(struct hash_matrix *matrix, FILE *fp)
{
	int i;
	int ret;
	struct hash_matrix_details *entry;
	char line[MAXLINE];

	fscanf(fp, "%"PRIu32"\n", &matrix->num_entries);

	matrix->entries = (struct hash_matrix_details *)
				malloc(sizeof(*entry) * matrix->num_entries);
	if (!matrix->entries) {
		printf("Failed to allocate space for hash matrix\n");
		exit(1);
	}

	for (i = 0; i < matrix->num_entries; i++) {
		entry = &matrix->entries[i];

		/* Parsing business as extension is of variable length */
		if (!fgets(line, MAXLINE, fp)) {
			printf("Failed to read the profile file\n");
			exit(1);
		}

		ret = parse_new_file_matrix_line(line, entry);
		if (ret) {
			printf("Failed to read the profile file\n");
			exit(1);
		}
	}

	return 0;
}

void print_new_files_matrix_entry(struct hash_matrix_details *entry)
{
	printf("Depth: %2"SCNu8" Ext: %6s CC: %6"PRIu64" UC: %6"PRIu64
			" 1DC: %6"PRIu64" 2DC: %6"PRIu64" #Files: %6"PRIu64
			" #Found: %6"PRIu64"\n", entry->depth,
			entry->extension, entry->chunk_count,
			entry->num_uniq_chunks, entry->num_chunks_1_dup,
			entry->num_chunks_2_dup, entry->num_files,
			entry->file_details.new_info.num_nodes);
}

void print_new_files_hash_matrix(struct hash_matrix *matrix)
{
	int i;
	struct hash_matrix_details *entry;

	for (i = 0; i < matrix->num_entries; i++) {
		entry = &matrix->entries[i];
		print_new_files_matrix_entry(entry);
	}
}

int parse_del_file_matrix_line(char *line, struct hash_matrix_details *entry)
{
	char *token;
	char state;

	/* First token is depth */
	token = strtok(line, ",");
	if (!token)
		return -1;

	sscanf(token, "%"SCNu8, &entry->depth);

	/* Next: Extension */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	if (!strcmp(token, NULL_EXTENSION))
		entry->extension[0] = '\0';
	else {
		strncpy(entry->extension, token, 6);
		entry->extension[6] = '\0';
	}

	/* Next: Previous state */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%c", &state);
	entry->file_details.del_info.prev_state = get_file_state(state);

	/* Next: chunk_count */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->chunk_count);

	/* Next: No Unique Chunks*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_uniq_chunks);

	/* Next: No Chunks with 1 Duplicate*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_chunks_1_dup);

	/* Next: No Chunks with 2 Duplicate*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_chunks_2_dup);

	/* Next: No of Files*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_files);

	return 0;
}

int read_del_files_hash_matrix(struct hash_matrix *matrix, FILE *fp)
{
	int i;
	int ret;
	struct hash_matrix_details *entry;
	char line[MAXLINE];

	fscanf(fp, "%"PRIu32"\n", &matrix->num_entries);

	matrix->entries = (struct hash_matrix_details *)
				malloc(sizeof(*entry) * matrix->num_entries);
	if (!matrix->entries) {
		printf("Failed to allocate space for hash matrix\n");
		exit(1);
	}

	for (i = 0; i < matrix->num_entries; i++) {
		entry = &matrix->entries[i];
		entry->file_details.del_info.num_nodes = 0;
		entry->file_details.del_info.head = NULL;
		entry->file_details.del_info.status = NOT_PROCESSED;

		if (!fgets(line, MAXLINE, fp)) {
			printf("Failed to read the profile file\n");
			exit(1);
		}

		ret = parse_del_file_matrix_line(line, entry);
		if (ret) {
			printf("Failed to read the profile file\n");
			exit(1);
		}

	}

	return 0;
}

void print_del_files_hash_matrix(struct hash_matrix *matrix)
{
	int i;
	struct hash_matrix_details *entry;

	for (i = 0; i < matrix->num_entries; i++) {
		entry = &matrix->entries[i];
		printf("Depth: %2"SCNu8" Ext: %6s Prev State: %2s CC: %6"PRIu64
			" UC: %6"PRIu64" 1DC: %6"PRIu64" 2DC: %6"PRIu64
			" Expected #: %6"PRIu64" Found #: %6"PRIu64"\n",
			entry->depth, entry->extension,
			print_state(entry->file_details.del_info.prev_state),
			entry->chunk_count, entry->num_uniq_chunks,
			entry->num_chunks_1_dup, entry->num_chunks_2_dup,
			entry->num_files,
			entry->file_details.del_info.num_nodes);
	}
}

enum mod_pattern set_pattern(char *pattern)
{
	if (!strcmp(pattern, "Z"))
		return MODIFY_MTIME_ONLY;
	if (!strcmp(pattern, "S"))
		return MODIFY_START;
	if (!strcmp(pattern, "E"))
		return MODIFY_END;
	if (!strcmp(pattern, "C"))
		return MODIFY_CENTER;
	if (!strcmp(pattern, "SE"))
		return MODIFY_START_AND_END;
	if (!strcmp(pattern, "SC"))
		return MODIFY_START_AND_CENTER;
	if (!strcmp(pattern, "CE"))
		return MODIFY_CENTER_AND_END;
	if (!strcmp(pattern, "SCE"))
		return MODIFY_START_CENTER_AND_END;

	return PATTERN_ERROR;
}

char *get_pattern(enum mod_pattern pattern)
{
	switch (pattern) {
	case MODIFY_MTIME_ONLY			: return "Z";
	case MODIFY_START			: return "S";
	case MODIFY_END				: return "E";
	case MODIFY_CENTER			: return "C";
	case MODIFY_START_AND_END		: return "SE";
	case MODIFY_START_AND_CENTER		: return "SC";
	case MODIFY_CENTER_AND_END		: return "CE";
	case MODIFY_START_CENTER_AND_END	: return "SCE";
	default					: return "Err";
	}
}

enum mod_size get_modification_state(struct hash_matrix_details *file_char,
				     struct hash_matrix_details *entry)
{
	if (file_char->chunk_count ==
		 entry->file_details.mod_info.chunk_count_new)
		return SAME_FILE_SIZE;

	if (file_char->chunk_count <
		 entry->file_details.mod_info.chunk_count_new)
		return INCREASE_FILE_SIZE;

	if (file_char->chunk_count >
		 entry->file_details.mod_info.chunk_count_new)
		return DECREASE_FILE_SIZE;

	return SIZE_ERROR;
}


int parse_mod_file_matrix_line(char *line, struct hash_matrix_details *entry)
{
	char *token;
	char state;

	/* First token is depth */
	token = strtok(line, ",");
	if (!token)
		return -1;

	sscanf(token, "%"SCNu8, &entry->depth);

	/* Next: Extension */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	if (!strcmp(token, NULL_EXTENSION))
		entry->extension[0] = '\0';
	else {
		strncpy(entry->extension, token, 6);
		entry->extension[6] = '\0';
	}

	/* Next: Previous state */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%c", &state);
	entry->file_details.mod_info.prev_state = get_file_state(state);

	/* Next: chunk_count Old */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->chunk_count);

	/* Next: No Unique Chunks Old*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_uniq_chunks);

	/* Next: No Chunks with 1 Duplicate Old*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_chunks_1_dup);

	/* Next: No Chunks with 2 Duplicate Old*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_chunks_2_dup);

	/* Next: chunk_count New */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->file_details.mod_info.chunk_count_new);

	/* Next: No Unique Chunks New */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64,
			 &entry->file_details.mod_info.num_uniq_chunks_new);

	/* Next: No Chunks with 1 Duplicate New*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64,
			 &entry->file_details.mod_info.num_chunks_1_dup_new);

	/* Next: No Chunks with 2 Duplicate New */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64,
			 &entry->file_details.mod_info.num_chunks_2_dup_new);

	/* Next: Pattern of modification */
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	entry->file_details.mod_info.pattern = set_pattern(token);

	/* Next: No of Files*/
	token = strtok(NULL, ",");
	if (!token)
		return -1;

	sscanf(token, "%"PRIu64, &entry->num_files);

	return 0;
}

int read_mod_files_hash_matrix(struct hash_matrix *matrix, FILE *fp)
{
	int i;
	int ret;
	struct hash_matrix_details *entry;
	char line[MAXLINE];

	fscanf(fp, "%"PRIu32"\n", &matrix->num_entries);

	matrix->entries = (struct hash_matrix_details *)
				malloc(sizeof(*entry) * matrix->num_entries);
	if (!matrix->entries) {
		printf("Failed to allocate space for hash matrix\n");
		exit(1);
	}

	for (i = 0; i < matrix->num_entries; i++) {
		entry = &matrix->entries[i];
		entry->file_details.mod_info.num_nodes = 0;
		entry->file_details.mod_info.head = NULL;
		entry->file_details.mod_info.processed = FALSE;
		entry->file_details.mod_info.status = NOT_PROCESSED;

		if (!fgets(line, MAXLINE, fp)) {
			printf("Failed to read the profile file\n");
			exit(1);
		}

		ret = parse_mod_file_matrix_line(line, entry);
		if (ret) {
			printf("Failed to read the profile file\n");
			exit(1);
		}
	}

	return 0;
}

void print_mod_files_entry(struct hash_matrix_details *entry)
{
	printf("Depth: %2"SCNu8" Ext: %6s Prev State: %2s CC(Old): %4"
			PRIu64" UC(Old): %4"PRIu64" 1DC(Old): %4"PRIu64
			" 2DC(Old): %4"PRIu64" CC(New): %4"PRIu64" UC(New): "
			"%4"PRIu64" 1DC(New): %4"PRIu64" 2DC(New): %4"PRIu64
			" Pattern: %3s Expected #: %4"PRIu64" Found #: %6"
			PRIu64"\n", entry->depth, entry->extension,
			print_state(entry->file_details.del_info.prev_state),
			entry->chunk_count, entry->num_uniq_chunks,
			entry->num_chunks_1_dup, entry->num_chunks_2_dup,
			entry->file_details.mod_info.chunk_count_new,
			entry->file_details.mod_info.num_uniq_chunks_new,
			entry->file_details.mod_info.num_chunks_1_dup_new,
			entry->file_details.mod_info.num_chunks_2_dup_new,
			get_pattern(entry->file_details.mod_info.pattern),
			entry->num_files, entry->file_details.mod_info.num_nodes);
}

void print_mod_files_hash_matrix(struct hash_matrix *matrix)
{
	int i;

	for (i = 0; i < matrix->num_entries; i++)
		print_mod_files_entry(&matrix->entries[i]);
}

uint64_t get_unique_chunk_id()
{
	uint64_t chunk_id;
	struct chunk_hash_info *chunk_info, *uniq_chunk_info;
	struct rb_root *root, *uniq_root;
	int ret;

	while (TRUE) {
		chunk_id = (uint64_t)mrand48();
		if (chunk_id)
			break;
	}

	while (TRUE) {
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		uniq_root = &uniq_chunk_hash_table[(chunk_id) % HASH_TABLE_SIZE];

		chunk_info = search_hash_rbtree(root, chunk_id);
		uniq_chunk_info = search_hash_rbtree(uniq_root, chunk_id);

		if (uniq_chunk_info)
			duplicate_uniq_chunk_id_generated++;

		if (!chunk_info && !uniq_chunk_info)
			break;

		chunk_id++;
	}

	uniq_chunk_info = (struct chunk_hash_info *)malloc(sizeof(*chunk_info));
	if (!uniq_chunk_info)
		return -1;

	uniq_chunk_info->chunk_hash = chunk_id;
	uniq_chunk_info->dup_count = 1;
	uniq_chunk_info->flags = 0;

	ret = insert_hash_rbtree(uniq_root, uniq_chunk_info);
	if (!ret)
		return -1;

	return chunk_id;
}

int set_uniq_hashes(struct dup_chunk_details *entry)
{
	int i;
	uint64_t chunk_id;

	for (i = 0; i < entry->num_chunks; i++) {
		chunk_id = get_unique_chunk_id();
		memcpy(&entry->hashes[entry->first_free_index],
			(uint8_t *)&chunk_id, sizeof(uint64_t));
		entry->first_free_index += sizeof(uint64_t);
		entry->num_available++;
	}

	return 0;
}

int build_intra_snapshot_uniq_hash_distro(struct dup_chunk_distro *distro)
{
	int i, j;
	struct dup_chunk_details *entry;
	int ret;
	uint64_t data_size_to_copy_in_bytes;

	init_chunk_hash_table(uniq_chunk_hash_table, HASH_TABLE_SIZE);

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];

		entry->hashes = (uint8_t *)
			malloc(entry->num_chunks * entry->dup_count
						 * sizeof(uint64_t));
		if (!entry->hashes)
			return -1;

		entry->first_free_index = 0;
		entry->num_available = 0;

		ret = set_uniq_hashes(entry);
		if (ret)
			return -1;

		/* If duplicate count is greater than 1, copy the hashes */
		data_size_to_copy_in_bytes =
				 entry->num_available * sizeof(uint64_t);
		for (j = 0; j < (entry->dup_count - 1); j++) {
			memcpy(&entry->hashes[entry->first_free_index],
				entry->hashes, data_size_to_copy_in_bytes);
			entry->first_free_index += data_size_to_copy_in_bytes;
			entry->num_available +=
				(data_size_to_copy_in_bytes / sizeof(uint64_t));
		}

		assert(entry->num_available ==
					 entry->num_chunks * entry->dup_count);

		/* Reset it for distribution */
		entry->first_free_index = 0;
	}

	printf("Duplicate uniq chunk IDs generated: %"PRIu64"\n",
			duplicate_uniq_chunk_id_generated);
	return 0;
}

void remember_chunk(uint64_t chunk_id)
{
	extern struct remembered_hashes more_than_2_dup_hashes;
	struct remembered_hashes *hash_set;

	hash_set = &more_than_2_dup_hashes;

	if (hash_set->free_slots == 0)
		return;

	hash_set->hashes[hash_set->used_slots] = chunk_id;
	hash_set->used_slots++;
	hash_set->free_slots--;
}

int allocate_space_for_spl_hashes(struct hash_matrix_details *file_char,
					struct remembered_hashes *hash_set)
{
	if (hash_set->hashes)
		free(hash_set->hashes);

	hash_set->used_slots = 0;
	hash_set->free_slots = 0;
	hash_set->hashes = NULL;
	hash_set->available = 0;

	hash_set->total_hashes = file_char->chunk_count -
				 file_char->num_chunks_1_dup -
				 file_char->num_chunks_2_dup;

	if (hash_set->total_hashes == 0)
		return 0;
	hash_set->hashes = (uint64_t *)
			malloc(hash_set->total_hashes * sizeof(uint64_t));
	if (!hash_set->hashes)
		return -1;
	hash_set->used_slots = 0;
	hash_set->free_slots = hash_set->total_hashes;

	return 0;
}

int allocate_hash_space_ext(struct dup_chunk_distro_ext *distro)
{
	int i;
	struct dup_chunk_details_ext *entry;

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];

		entry->distinct_hashes = (uint8_t *)
			malloc(entry->distinct_chunks * HASH_SIZE_BYTES);
		if (!entry->distinct_hashes)
			return -1;

		entry->first_free_index = 0;
		entry->num_available = 0;
	}

	return 0;
}

/* Scan current entry and make sure that hash we are copying does not
 * already exist
 */
static int hash_not_selected_already(uint64_t chunk_id)
{
	struct chunk_hash_info *chunk_info = NULL;
	struct rb_root *root;

	root = &distinct_hash_table[(chunk_id) % HASH_TABLE_SIZE];
	chunk_info = search_hash_rbtree(root, chunk_id);
	if (chunk_info)
		return FALSE;

	return TRUE;
}

static void select_hash_ext(struct chunk_hash_info *chunk_info,
		     struct dup_chunk_distro_ext *distro, enum file_states state)
{
	struct dup_chunk_details_ext *entry;
	int i;
	struct chunk_hash_info *distinct_chunk_info = NULL;
	struct rb_root *root;
	uint64_t chunk_id;
	int ret;

	if (distro->num_entries == 0)
		return;

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];
		if (entry->dup_count == chunk_info->dup_count &&
		    entry->num_available < entry->distinct_chunks &&
		    hash_not_selected_already(chunk_info->chunk_hash)) {
			assert(chunk_info->chunk_hash);
			memcpy(&entry->distinct_hashes[entry->first_free_index],
				(uint8_t *)&chunk_info->chunk_hash,
				 HASH_SIZE_BYTES);
			entry->first_free_index += HASH_SIZE_BYTES;
			entry->num_available++;
#if DEBUG_CHUNKS
			printf("Selecting hash %"PRIx64" of dup_count %d from "
				"%s file\n", chunk_info->chunk_hash,
				chunk_info->dup_count, print_state(state));
#endif
			distinct_chunk_info = (struct chunk_hash_info *)
						malloc(sizeof(*chunk_info));
			if (!distinct_chunk_info) {
				printf("Could not allocate memory\n");
				exit(1);
			}

			chunk_id = chunk_info->chunk_hash;
			distinct_chunk_info->chunk_hash = chunk_id;
			distinct_chunk_info->dup_count = 1;
			distinct_chunk_info->flags = 0;
			root = &distinct_hash_table[(chunk_id) % HASH_TABLE_SIZE];

			ret = insert_hash_rbtree(root, distinct_chunk_info);
			if (!ret) {
				printf("Could not place hash in RBTree\n");
				exit(1);
			}

			break;
		}
	}
}

int hash_search_finish_ext(struct dup_chunk_distro_ext *del_distro,
			   struct dup_chunk_distro_ext *all_distro)
{
	struct dup_chunk_details_ext *entry;
	int i;
	extern uint8_t hash_search_finished;

	for (i = 0; i < del_distro->num_entries; i++) {
		entry = &del_distro->entries[i];
		if (entry->num_available < entry->distinct_chunks)
			return FALSE;
	}

	for (i = 0; i < all_distro->num_entries; i++) {
		entry = &all_distro->entries[i];
		if (entry->num_available < entry->distinct_chunks)
			return FALSE;
	}

	hash_search_finished = TRUE;
	printf("Hash Search finished\n");
	return TRUE;
}

int select_prev_hashes(void *object, int type, int level)
{
	extern uint8_t hash_search_finished;
	extern struct mutation_profile *profile;

	if (hash_search_finished)
		return 0;

	if (type == OBJ_TYPE_DIR)
		return 0;

	struct dup_chunk_distro_ext *all_distro, *del_distro;
	struct log_chunk *chunk;
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;
	struct file *file;

	all_distro = &profile->prev_snapshot_hash_distro,
	del_distro = &profile->del_files_common_hash_distro;
	file = (struct file *)object;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {

		chunk_id = htole64(chunk->phys_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);

		if (!chunk_info)
			continue;

		if (file->filestate == FST_DELETED)
			select_hash_ext(chunk_info, del_distro,
							 file->filestate);

		if (file->filestate == FST_IMMUTABLE    ||
		    file->filestate == FST_NEW_PREV     ||
		    file->filestate == FST_MUTABLE_PREV ||
		    file->filestate == FST_IMMUTABLE_PREV)
			select_hash_ext(chunk_info, all_distro,
							 file->filestate);

		if (hash_search_finish_ext(del_distro, all_distro))
			break;
	}

	num_files_analyzed++;
	return 0;
}

/* Set up an entry with dup_count closer to the one we could not find
 * We are currently copying 1 hash from entry before or after whichever
 * difference is smaller.  This will affect the distribution of duplicates
 * such that only one hash will now have extra duplicates.  Not a big deal
 */
static void set_dummy_hash_ext(int index, struct dup_chunk_details_ext *entry,
				struct dup_chunk_distro_ext *distro)
{
	struct dup_chunk_details_ext *before, *after, *copy_from;

	if (index)
		before = &distro->entries[index - 1];
	else
		before = NULL;

	if (index < distro->num_entries)
		after = &distro->entries[index + 1];
	else
		after = NULL;

	if (!after->num_available)
		after = NULL;

	if (before && after) {
		if (entry->dup_count - before->dup_count <=
			after->dup_count - entry->dup_count)
			copy_from = before;
		else
			copy_from = after;
	} else {
		if (!after)
			copy_from = before;
		else
			copy_from = after;
	}

	assert(copy_from);

	memcpy(entry->distinct_hashes, copy_from->distinct_hashes,
							 HASH_SIZE_BYTES);
	entry->first_free_index += HASH_SIZE_BYTES;
	entry->num_available++;
}

static int replicate_hashes(struct dup_chunk_distro_ext *distro,
						 uint8_t set_dummy)
{
	int i, j;
	struct dup_chunk_details_ext *entry;
	uint32_t quotient, remainder;
	uint8_t *dest;

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];
		entry->all_hashes = (uint8_t *)
				malloc(entry->all_chunks * HASH_SIZE_BYTES);
		if (!entry->all_hashes)
			return -1;

		/* Ensure that num_available is never zero. */
		if (entry->num_available == 0) {
			if (set_dummy) {
				printf("Could not find hashes with %"PRIu32
					" duplicates at all. Setting dummy\n",
					entry->dup_count);
				set_dummy_hash_ext(i, entry, distro);
			} else
				continue;
		}

		quotient = entry->all_chunks / entry->num_available;
		remainder = entry->all_chunks % entry->num_available;

		for (j = 0; j < quotient; j++) {
			dest = entry->all_hashes +
			 	j * HASH_SIZE_BYTES * entry->num_available;
			memcpy(dest, entry->distinct_hashes,
				HASH_SIZE_BYTES * entry->num_available);
		}

		if (remainder) {
			dest = entry->all_hashes +
				quotient * HASH_SIZE_BYTES * entry->num_available;
			memcpy(dest, entry->distinct_hashes,
						 HASH_SIZE_BYTES * remainder);
		}
		entry->num_available = entry->all_chunks;
	}

	return 0;
}

static struct dup_chunk_details_ext *
		   get_source_entry_ext(struct dup_chunk_details_ext *dest,
					struct dup_chunk_distro_ext *distro)
{
	int i;
	struct dup_chunk_details_ext *entry;

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];
		if (entry->dup_count == dest->dup_count)
			return entry;
	}

	return NULL;
}

static uint8_t check_hashes(uint8_t *hashes, uint64_t num_hashes,
			    uint32_t dup_count)
{
	int i;
	uint64_t *ptr;

	for (ptr = (uint64_t *)hashes, i = 0; i < num_hashes; i++, ptr++) {
		if (*ptr == 0) {
			printf("Entry with dup_count %"PRIu32" has "
				"chunk id of 0. Index: %d\n", dup_count, i);
			return FALSE;
		}
	}

	return TRUE;
}

int setup_prev_snapshot_hashes(struct dup_chunk_distro_ext *all_distro,
			       struct dup_chunk_distro_ext *del_distro)
{
	int i, ret;
	struct dup_chunk_details_ext *src_entry, *dst_entry, *entry;
	extern uint8_t hash_search_finished;
	extern struct fstree fst;

	if (all_distro->num_entries == 0 && del_distro->num_entries == 0)
		return 0;

	hash_search_finished = FALSE;
	ret = allocate_hash_space_ext(all_distro);
	if (ret) {
		printf("Failed to allocate hash space\n");
		return -1;
	}

	ret = allocate_hash_space_ext(del_distro);
	if (ret) {
		printf("Failed to allocate hash space\n");
		return -1;
	}

	init_chunk_hash_table(distinct_hash_table, HASH_TABLE_SIZE);

	ret = walk_fstree(&fst, select_prev_hashes);
	if (ret)
		return -1;

	for (i = 0; i < all_distro->num_entries; i++) {
		entry = &all_distro->entries[i];
		assert(check_hashes(entry->distinct_hashes,
				    entry->num_available, entry->dup_count));
	}

	for (i = 0; i < del_distro->num_entries; i++) {
		entry = &del_distro->entries[i];
		assert(check_hashes(entry->distinct_hashes,
				    entry->num_available, entry->dup_count));
	}

	ret = replicate_hashes(del_distro, FALSE);
	if (ret) {
		printf("Failed to replicated deleted files hashes\n");
		return -1;
	}

	for (i = 0; i < del_distro->num_entries; i++) {
		entry = &del_distro->entries[i];
		assert(check_hashes(entry->all_hashes,
				    entry->num_available, entry->dup_count));
	}

	ret = replicate_hashes(all_distro, TRUE);
	if (ret) {
		printf("Failed to replicated deleted files hashes\n");
		return -1;
	}

	for (i = 0; i < all_distro->num_entries; i++) {
		entry = &all_distro->entries[i];
		assert(check_hashes(entry->all_hashes,
				    entry->num_available, entry->dup_count));
	}

	/* Now we have to copy deleted hashes into actual distro */
	for (i = 0; i < all_distro->num_entries; i++) {
		dst_entry = &all_distro->entries[i];
		src_entry = get_source_entry_ext(dst_entry, del_distro);
		if (!src_entry)
			continue;

		if (!src_entry->num_available)
			continue;

		assert(src_entry->num_available <= dst_entry->num_available);
		printf(" Dst Dup_count: %"PRIu32" Src Dup_count: %"PRIu32
			" Dst # hashes: %"PRIu64" Src # hashes: %"PRIu64"\n",
			dst_entry->dup_count, src_entry->dup_count,
			dst_entry->all_chunks, src_entry->all_chunks);
		memcpy(dst_entry->all_hashes, src_entry->all_hashes,
			  src_entry->num_available * HASH_SIZE_BYTES);
		free(src_entry->all_hashes);
		free(src_entry->distinct_hashes);
		free(dst_entry->distinct_hashes);
	}

	for (i = 0; i < all_distro->num_entries; i++) {
		entry = &all_distro->entries[i];
		assert(check_hashes(entry->all_hashes,
				    entry->num_available, entry->dup_count));
	}

	return 0;
}

uint64_t get_uniq_chunk_id()
{
	extern struct mutation_profile *profile;
	struct dup_chunk_distro *distro;
	int i;
	int start_index;
	struct dup_chunk_details *entry;
	uint64_t chunk_id;
	uint64_t index;
	static uint32_t dup_count = 0;
	static uint64_t count = 0;

	distro = &profile->intra_snapshot_uniq_chunk_distro;

	/* We first emit chunk IDs with dup_count > 1 to ensure
	 * duplicates are correctly introduced in FST.  Then, we
	 * emit unique chunks with 1 duplicate only.
	 */
	start_index = (distro->entries[0].dup_count == 1 ? 1 : 0);
	for (i = start_index; i < distro->num_entries; i++) {
		entry = &distro->entries[i];

		if (entry->first_free_index >= entry->num_available)
			continue;

		if (dup_count != entry->dup_count) {
			printf("Emitting unique chunks with duplicate count: %"
				PRIu32" For duplicate count %"PRIu32
				" Emitted Hash count: %"PRIu64"\n",
				entry->dup_count, dup_count, count);
			dup_count = entry->dup_count;
			count = 0;
		}
		index = entry->first_free_index * sizeof(uint64_t);
		memcpy((uint8_t *)&chunk_id, &entry->hashes[index],
							 sizeof(uint64_t));
		entry->first_free_index++;
		count++;
		return chunk_id;
	}

	if (distro->entries[0].dup_count != 1) {
		printf("Exhausted with unique hashes !!\n");
		return -1;
	}

	entry = &distro->entries[0];
	if (entry->first_free_index >= entry->num_available) {
		printf("Exhausted with unique hashes !!\n");
		return -1;
	}

	index = entry->first_free_index * sizeof(uint64_t);
	memcpy((uint8_t *)&chunk_id, &entry->hashes[index],
						 sizeof(uint64_t));
	entry->first_free_index++;
	return chunk_id;
}

static uint64_t available_chunk_id_ext(struct dup_chunk_details_ext *entry)
{
	uint64_t index;
	uint64_t chunk_id = 0;
	extern struct fstree fst;

	assert(entry->num_available >= 0 &&
	       entry->num_available <= entry->all_chunks);

	index = (entry->all_chunks - entry->num_available) * HASH_SIZE_BYTES;

	/* Goes in little endian anyways */
	memcpy((uint8_t *)&chunk_id,
			&entry->all_hashes[index], HASH_SIZE_BYTES);

	entry->num_available--;

	/* Wrap it up */
	if (entry->num_available == 0)
		entry->num_available = entry->all_chunks;

	assert(chunk_id);

	return chunk_id;
}

static int check_if_distro_matches(struct dup_chunk_distro *distro,
				   struct dup_chunk_details_ext *ref_entry)
{
	struct dup_chunk_details *entry;
	int i;

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];
		if (entry->dup_count == ref_entry->dup_count) {
			if (entry->num_chunks > 0) {
				entry->num_chunks--;
				return TRUE;
			} else
				return FALSE;
		}
	}

	return FALSE;
}

uint64_t find_available_chunk_id_ext(uint8_t dup_count, uint8_t hash_for,
				struct dup_chunk_distro_ext *distro)
{
	int i;
	struct dup_chunk_details_ext *entry;
	struct dup_chunk_distro *ref_distro;
	uint8_t distro_match = FALSE;
	extern struct mutation_profile *profile;

	if (dup_count == DUP_COUNT_1 || dup_count == DUP_COUNT_2) {
		for (i = 0; i < distro->num_entries; i++) {
			entry = &distro->entries[i];
			if (entry->dup_count == dup_count)
				return available_chunk_id_ext(entry);
		}
	}

	if (hash_for == NEW_FILES)
		ref_distro = &profile->new_files_dup_chunk_distro;
	else if (hash_for == MOD_FILES)
		ref_distro = &profile->mod_files_dup_chunk_distro_sid2;
	else {
		printf("Invalid argument hash_for: %d\n", hash_for);
		exit(1);
	}

	for (i = 0; i < distro->num_entries; i++) {
		entry = &distro->entries[i];
		if (entry->dup_count != DUP_COUNT_1 &&
		    entry->dup_count != DUP_COUNT_2 &&
		    entry->num_available > 0) {
			distro_match =
				 check_if_distro_matches(ref_distro, entry);
			if (distro_match)
				return available_chunk_id_ext(entry);
		}
	}

	/* Check if we have remembered something */
	extern struct remembered_hashes more_than_2_dup_hashes;
	struct remembered_hashes *hash_set;
	uint64_t index;

	hash_set = &more_than_2_dup_hashes;

	if (hash_set->total_hashes) {
		index = (hash_set->available + 1) % hash_set->total_hashes;
		hash_set->available++;
		return hash_set->hashes[index];
	}
	/* Special chunk id reserved to indicate error */
	return 0;
}
