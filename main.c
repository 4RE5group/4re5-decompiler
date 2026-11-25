#include "types/binary_types.h"
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: 4re5-decompiler path/to/executable\n");
    return 1;
  }
  int fd = open(argv[1], O_RDONLY);
  if (fd < 0) {
    perror(argv[1]);
    return 1;
  }
  int result = detect_type(fd);
  close(fd);
  return result;
}
