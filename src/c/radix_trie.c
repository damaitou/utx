#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "radix_trie.h"

#ifdef __cplusplus
extern "C" {
#endif

unsigned long node_number = 0;

void trie_stats() {
    printf("node_number=%lu\n", node_number);
}
 
struct trie_node *create_trie_node(unsigned char value)
{
	struct trie_node * node = calloc(1, sizeof(struct trie_node));
	node->value = value;
    ++node_number;
	return node;
}
 
int search(struct trie_node *root, const unsigned char *word)
{
	struct trie_node *n = NULL;
	const unsigned char *p = NULL;
	
	if (root == NULL) {
		return 0;
	}
	
	while (*word != 0) {
		p = word++;
		n = root;
		while (*p != 0) {
            unsigned char hi = *p >> 4;
            unsigned char low = *p & 0x0F;

			n = n->node[hi];
			if (n == NULL) {
				break;
			}
			else if (n->exist == 1) {
				return 1;
			}

            n = n->node[low];
			if (n == NULL) {
				break;
			}
			else if (n->exist == 1) {
				return 1;
			}

			p++;
		}
	}
		
	return 0;
}

int search_buf(struct trie_node *root, const unsigned char *word, int len)
{
    struct trie_node *n = NULL;
    const unsigned char *p = NULL;

    if (root == NULL) {
        return 0;
    }

    const unsigned char *wordhead = word;
    while (word - wordhead < len) {
        p = word++;
        n = root;
        while (*p != 0) {
            unsigned char hi = *p >> 4;
            unsigned char low = *p & 0x0F;

			n = n->node[hi];
			if (n == NULL) {
				break;
			}
			else if (n->exist == 1) {
				return 1;
			}

            n = n->node[low];
			if (n == NULL) {
				break;
			}
			else if (n->exist == 1) {
				return 1;
			}

            p++;
        }
    }

    return 0;
}

void insert(struct trie_node *root, const unsigned char *word) 
{
    struct trie_node *n;
    while (*word != 0) {
        unsigned char hi = *word >> 4;
        unsigned char low = *word & 0x0F;

        n = root->node[hi];
        if (n == NULL) {
            n = create_trie_node(hi);
            root->node[hi] = n;
        }
        root = n;

        n = root->node[low];
        if (n == NULL) {
            n = create_trie_node(low);
            root->node[low] = n;
        }
        root = n;

        word++;
    }
    root->exist = 1;
}

void destroy_trie_tree(struct trie_node *root) 
{
    int i;
    if (root == NULL) {
        return;
    }
    for (i = 0; i < WORD_NUM; i++) {
        destroy_trie_tree(root->node[i]);
    }
    free(root);
}


void update_trie_tree(struct trie_node **root, const char *filename)
{
    char word[1024];
    FILE *fp;
    char *p;

    if (*root != NULL) {
        destroy_trie_tree(*root);
    }

    *root = calloc(sizeof(**root),1);

    fp = fopen(filename, "r");
    if (fp == NULL) {
        printf("file can't open %s\n", filename);
        return;
    }

    while (fgets(word, sizeof(word), fp)) {
        p = word;

        while (*p != 0) {
            if (*p == '\r' || *p == '\n' || *p == ' ') {
                *p = 0;
                break;
            }
            p++;
        }
        insert(*root, (unsigned char *)word);
    }
}

unsigned long long trie_new()
{
    /*
    struct trie_node *root = (struct trie_node *)calloc(sizeof(*root),1);
    printf("trie_new(), return %llu\n", (unsigned long long)root);
    return (unsigned long long)root;
    */
    struct trie_head *head = (struct trie_head *)calloc(sizeof(struct trie_head),1);
    head->ref_count = 1;
    head->node_number = 0;
    head->root = (struct trie_node *)calloc(sizeof(struct trie_node),1);

    return (unsigned long long)head;
}

void trie_insert(unsigned long long handle, const unsigned char * word)
{
    /*
    struct trie_node *root = (struct trie_node *)handle;
    insert(root, word);
    */
    struct trie_head *head = (struct trie_head *)handle;
    insert(head->root, word);
}

int trie_match(unsigned long long handle, const unsigned char * buf, int len)
{
    /*
    struct trie_node *root = (struct trie_node *)handle;
    return search_buf(root, buf, len);
    */
    struct trie_head *head = (struct trie_head *)handle;
    return search_buf(head->root, buf, len);
}

void trie_clone(unsigned long long handle) {
    struct trie_head *head = (struct trie_head *)handle;
    head->ref_count += 1;
    printf("trie_clone(), handle=%llu, ref_count=%u\n", (unsigned long long)handle, head->ref_count);
}

void trie_drop(unsigned long long handle)
{
    /*
    struct trie_node *root = (struct trie_node *)handle;
    destroy_trie_tree(root);
    */
    struct trie_head *head = (struct trie_head *)handle;
    head->ref_count -= 1;
    printf("trie_drop(), handle=%llu, ref_count=%u\n", (unsigned long long)handle, head->ref_count);
    if (head->ref_count == 0) {
        printf("trie_drop(), really dropping...\n");
        destroy_trie_tree(head->root);
        free(head);
    }
}

#ifdef __cplusplus
}
#endif

