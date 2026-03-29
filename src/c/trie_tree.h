#ifndef _TRIE_TREE_H_INCLUDED_
#define _TRIE_TREE_H_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif
 
#define WORD_NUM          256
struct trie_node {
	struct trie_node *node[WORD_NUM];
	int value;
	int exist;
};
 
struct trie_node *create_trie_node(int value);
void insert(struct trie_node *root, const unsigned char *word);
/* return 1 表示存在， return 0表示不存在 */
int search(struct trie_node *root, const unsigned char *word);
int search_buf(struct trie_node *root, const unsigned char *word, int len);
void destroy_trie_tree(struct trie_node *root);
void update_trie_tree(struct trie_node **root, const char *filename);

extern unsigned long node_number;
extern unsigned long long trie_new();
extern void trie_insert(unsigned long long handle, const unsigned char * word);
extern int trie_match(unsigned long long handle, const unsigned char * buf, int len);
extern void trie_drop(unsigned long long handle);
extern void trie_stats();
 
#ifdef __cplusplus
}
#endif

#endif

