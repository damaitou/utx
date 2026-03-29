#include <stdio.h>
#include <magic.h>
#include <string.h>

unsigned long long file_magic_init() {
    struct magic_set *magic = magic_open(MAGIC_CHECK|MAGIC_MIME_TYPE);
    magic_load(magic,NULL);
    return (unsigned long long)magic;
}

const char * file_magic(unsigned long long handle, const char *file, int *len) {
    const char *magic = magic_file((struct magic_set*)handle, file);
    *len = strlen(magic);
    return magic;
}

/*
int main(void) {
  //struct magic_set *magic = magic_open(MAGIC_MIME|MAGIC_CHECK);
  struct magic_set *magic = magic_open(MAGIC_CHECK|MAGIC_MIME_TYPE);
  magic_load(magic,NULL);

  printf("Output1: '%s'\n",magic_file(magic,"a.out"));
  printf("Output1: '%s'\n",magic_file(magic,"magic.c"));
  printf("Output1: '%s'\n",magic_file(magic,"/home/damaitou/dev/kernel/linux-3.16.77.tar.xz"));
  printf("Output1: '%s'\n",magic_file(magic,"/home/damaitou/utx/etc/tx_for_fpull.json"));
  printf("Output1: '%s'\n",magic_file(magic,"/home/damaitou/dev/rust/utx/magic/sourcecode.zip"));

  return 0;
}
*/

