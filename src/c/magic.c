#include <stdio.h>
#include <magic.h>

int main(void) {
  //struct magic_set *magic = magic_open(MAGIC_MIME|MAGIC_CHECK);
  struct magic_set *magic = magic_open(MAGIC_CHECK|MAGIC_MIME_TYPE);
  magic_load(magic,NULL);

  printf("Output1: '%s'\n",magic_file(magic,"/home/damaitou/utx/data/tx3/test1/2.txt.badfiletype"));
  printf("Output1: '%s'\n",magic_file(magic,"magic"));
  printf("Output1: '%s'\n",magic_file(magic,"magic.c"));
  printf("Output1: '%s'\n",magic_file(magic,"filesample/1.html"));
  printf("Output1: '%s'\n",magic_file(magic,"filesample/f1"));
  printf("Output1: '%s'\n",magic_file(magic,"filesample/offer.docx"));
  printf("Output1: '%s'\n",magic_file(magic,"/home/damaitou/dev/kernel/linux-3.16.77.tar.xz"));
  printf("Output1: '%s'\n",magic_file(magic,"/home/damaitou/utx/etc/tx_for_fpull.json"));
  printf("Output1: '%s'\n",magic_file(magic,"/home/damaitou/dev/rust/utx/magic/sourcecode.zip"));
  printf("Output1: '%s'\n",magic_file(magic,"filesample/test-docx.docx"));

  return 0;
}

