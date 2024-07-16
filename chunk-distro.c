#include <assert.h>

#include "fstree.h"
#include "fsdistro.h"

struct rb_root hash_table[HASH_TABLE_SIZE];
static struct duplicate_distro_node *fst_dup_chunk_distro;

/******************* BUILDING CHUNK DISTRIBUTION *********************/
struct chunk_hash_info *search_hash_rbtree(struct rb_root *root,
						 uint64_t chunk_phys_id)
{
	struct rb_node *node = root->rb_node;

	while (node) {
		struct chunk_hash_info *data =
			 container_of(node, struct chunk_hash_info, node);

		if (le64toh(chunk_phys_id) < le64toh(data->chunk_hash))
			node = node->rb_left;
	      	else if (le64toh(chunk_phys_id) > le64toh(data->chunk_hash))
			node = node->rb_right;
	      	else
			return data;
      }

      return NULL;
}

int insert_hash_rbtree(struct rb_root *root,
				 struct chunk_hash_info *hash)
{
  	struct rb_node **new = &(root->rb_node), *parent = NULL;

 	while (*new) {
 		struct chunk_hash_info *this =
			 container_of(*new, struct chunk_hash_info, node);

	       	parent = *new;
 		if (le64toh(hash->chunk_hash) < le64toh(this->chunk_hash))
 			new = &((*new)->rb_left);
 		else if (le64toh(hash->chunk_hash) > le64toh(this->chunk_hash))
 			new = &((*new)->rb_right);
 		else
 			return FALSE;
 	}

 	rb_link_node(&hash->node, parent, new);
 	rb_insert_color(&hash->node, root);

	return TRUE;
}

int add_chunks_to_hash_table(void *object, int type, int level)
{
	struct file *file;
	struct log_chunk *chunk;
	struct chunk_hash_info *chunk_info;
	struct rb_root *root;
	uint64_t chunk_id;
	int ret;

	if (type == OBJ_TYPE_DIR)
		return 0;

	file = (struct file *)object;

	for (chunk = file->first_log_chunk; chunk; chunk = chunk->next) {

		chunk_id = htole64(chunk->phys_id);
		assert(chunk_id);
		root = &hash_table[(chunk_id) % HASH_TABLE_SIZE];
		chunk_info = search_hash_rbtree(root, chunk_id);
		if (chunk_info) {
			chunk_info->dup_count++;
			continue;
		}

		chunk_info =
			 (struct chunk_hash_info *)malloc(sizeof(*chunk_info));
		if (!chunk_info)
			return -1;

		chunk_info->chunk_hash = chunk_id;
		chunk_info->dup_count = 1;
		chunk_info->flags = 0;

		ret = insert_hash_rbtree(root, chunk_info);
		if (!ret)
			return -1;
	}

	return 0;
}

void init_chunk_hash_table(struct rb_root *hash_table, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
		hash_table[i].rb_node = NULL;
}

static struct duplicate_distro_node *dup_count_exists(uint64_t dup_count)
{
	struct duplicate_distro_node *current;

	for (current = fst_dup_chunk_distro; current; current = current->next) {
		if (dup_count == current->dup_count)
			return current;
	}

	return NULL;
}

static struct duplicate_distro_node *get_distro_node()
{
	struct duplicate_distro_node *node;

	node = (struct duplicate_distro_node *)malloc(sizeof(*node));
	if (!node) {
		printf("Failed to allocate memory\n");
		exit(1);
	}

	node->dup_count = 0;
	node->hash_count = 0;
	node->next = NULL;
	return node;
}

static void add_node_in_linked_list(struct duplicate_distro_node *node)
{
	struct duplicate_distro_node *current, *prev;

	if (fst_dup_chunk_distro == NULL) {
		fst_dup_chunk_distro = node;
		return;
	}

	for (current = fst_dup_chunk_distro, prev = NULL; current;
				prev = current, current = current->next) {
		if (node->dup_count < current->dup_count) {
			if (prev == NULL) {
				node->next = fst_dup_chunk_distro;
				fst_dup_chunk_distro = node;
			} else {
				node->next = prev->next;
				prev->next = node;
			}
			return;
		}
	}

	if (current == NULL)
		prev->next = node;
}

/* In-Order traversal on RBTree to find out hash distribution.
 * Recursive function.
 */
static void inorder_traversal_rbtree(struct rb_node *node)
{
	if (node) {
		struct duplicate_distro_node *distro_node;
		struct chunk_hash_info *data =
			 container_of(node, struct chunk_hash_info, node);

		if ((distro_node = dup_count_exists(data->dup_count)) != NULL)
			distro_node->hash_count++;
		else {
			distro_node = get_distro_node();
			distro_node->dup_count = data->dup_count;
			distro_node->hash_count++;
			add_node_in_linked_list(distro_node);
			printf("Added node for %"PRIu32" Duplicates\n",
							data->dup_count);
		}
		inorder_traversal_rbtree(node->rb_left);
		inorder_traversal_rbtree(node->rb_right);
	}
}

int traverse_hash_table(void)
{
	int i;
	struct duplicate_distro_node *current;

	for (i = 0; i < HASH_TABLE_SIZE; i++)
		inorder_traversal_rbtree(hash_table[i].rb_node);

	printf("dup_count,hash_count\n");
	for (current = fst_dup_chunk_distro; current; current = current->next)
		printf("%"PRIu32",%"PRIu64"\n",
				current->dup_count, current->hash_count);

	return 0;
}
