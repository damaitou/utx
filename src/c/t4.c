
#include "radix_trie.h"
//#include "trie_tree.h"
#include <stdio.h>
#include <stdlib.h>

void f1()
{
    printf("sizeof(trie_node)=%u\n", sizeof(struct trie_node));
    struct trie_node *root = (struct trie_node *)calloc(sizeof(*root),1);

    insert(root, "cdefg");
    insert(root, "妈的");
    insert(root, "脏话");
    insert(root, "连篇");

    printf("node_number=%u\n", node_number);

    printf("found abcdefghixyz=%d\n",search(root, "abcdefghixyz"));
    printf("found 去你妈的=%d\n",search(root, "去你妈的"));
    printf("found 我不说脏话=%d\n",search(root, "我不说脏话"));
    printf("found 绝密机密=%d\n",search(root, "绝密机密"));
}

void f2()
{
    unsigned long long h = trie_new();
    trie_insert(h, "cdefg");
    trie_insert(h, "妈的");
    trie_insert(h, "脏话");
    trie_insert(h, "连篇");
    trie_clone(h);
    printf("found abcdefghixyz=%d\n",trie_match(h, "abcdefghixyz", 12));
    printf("found 去你妈的=%d\n",trie_match(h, "去你妈的", strlen("去你妈的")));
    printf("found 我不说脏话=%d\n",trie_match(h, "我不说脏话", strlen("我不说脏话")));
    printf("found 绝密机密=%d\n",trie_match(h, "绝密机密", strlen("绝密机密")));

    trie_drop(h);
    trie_drop(h);
}

int main()
{
    f2();
}
