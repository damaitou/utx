#ifndef _RADIX_TRIE_H_INCLUDED_
#define _RADIX_TRIE_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif
 
#define WORD_NUM 16
struct trie_node {
	struct trie_node *node[WORD_NUM];
	unsigned char value:4, exist:1;
};

struct trie_head {
    unsigned int node_number;
    unsigned int ref_count;
    struct trie_node *root;
};
 
struct trie_node *create_trie_node(unsigned char value);
void insert(struct trie_node *root, const unsigned char *word);
int search(struct trie_node *root, const unsigned char *word); /* return 1 表示存在， return 0表示不存在 */
int search_buf(struct trie_node *root, const unsigned char *word, int len);
void destroy_trie_tree(struct trie_node *root);
void update_trie_tree(struct trie_node **root, const char *filename);

extern unsigned long node_number;
extern unsigned long long trie_new();
extern void trie_insert(unsigned long long handle, const unsigned char * word);
extern int trie_match(unsigned long long handle, const unsigned char * buf, int len);
extern void trie_clone(unsigned long long handle);
extern void trie_drop(unsigned long long handle);
extern void trie_stats();
 
#ifdef __cplusplus
}
#endif

#endif

