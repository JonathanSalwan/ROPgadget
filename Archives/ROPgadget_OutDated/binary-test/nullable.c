#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int force_read(char *b, int fd, int s) {
  int r = 0;
  while (r < s) {
    int t = read(fd, b, s-r);
    if (t == -1) {
      perror("wut file error");
      exit(1);
    } else if (t == 0) {
      fprintf(stderr, "wut %d\n", r);
      exit(1);
    }
    r += t;
  }
  return r;
}

void vuln(int fd, int size) {
  char buff[32] = {0};
  printf("read %d bytes\n", force_read(buff, fd, size));
  return;
}

int main(int argc, char **argv) {
  int fd, size;
  struct stat buf;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s filename\n", argv[0]);
    return 1;
  }
  fd = open(argv[1], O_RDONLY);

  fstat(fd, &buf);
  size = buf.st_size;

  vuln(fd, size);

  return (0);
}
