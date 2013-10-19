#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <libkallsyms/kallsyms_in_memory.h>

static size_t
get_file_length(const char *file_name)
{
  struct stat st;

  if (stat(file_name, &st) < 0) {
    return 0;
  }

  return st.st_size;
}

static bool
do_get_kallsyms(const char *file_name, size_t len)
{
  int fd;
  unsigned long* mem;
  kallsyms *info;

  fd = open(file_name, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "file open failed \"%s\"(%d)\n", strerror(errno), errno);
    return false;
  }

  mem = (unsigned long*)mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
  if(mem == MAP_FAILED)
  {
    fprintf(stderr, "mmap error \"%s\"(%d)\n", strerror(errno), errno);
    close(fd);
    return false;
  }

  info = kallsyms_in_memory_init(mem, len);
  if (info) {
    kallsyms_in_memory_print_all(info);
  }

  if (munmap(mem, len)) {
    fprintf(stderr, "munmap error \"%s\"(%d)\n", strerror(errno), errno);
  }

  if (close(fd)) {
    fprintf(stderr, "close error \"%s\"(%d)\n", strerror(errno), errno);
  }

  return info != NULL;
}

int main(int argc, char** argv)
{
  char *file_name;
  size_t len;

  kallsyms_in_memory_set_verbose(true);

  if (argc !=2 ) {
    fprintf(stderr, "Usage: %s FILENAME\n", argv[0]);
    return 2;
  }

  file_name = argv[1];

  len = get_file_length(file_name);
  if (len == 0) {
    fprintf(stderr, "Can't get file size\n");
  }

  if (!do_get_kallsyms(file_name, len)) {
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}

/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
