/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** Allan Wirth - http://allanwirth.com/
** http://shell-storm.org
** 2012-11-11
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "ropgadget.h"

#define MKSTEMP_TEMPLATE "/tmp/ropgadget_XXXXXX"

static void make_temporary_file(char **name, int *fd) {
  char *tname;
  int tfd;

  tname = xmalloc(strlen(MKSTEMP_TEMPLATE)+1);
  strcpy(tname, MKSTEMP_TEMPLATE);

  tfd = mkstemp(tname);

  *name = tname;
  *fd = tfd;
}

static void write_source_file(char *str, int fd)
{
  int i;

  if (syntaxins == INTEL)
    xwrite(fd, ".intel_syntax noprefix\n", 23);

  for (i = 0; str[i] != '\0'; i++)
    if (str[i] == ';')
      xwrite(fd, "\n", 1);
    else
      xwrite(fd, &str[i], 1);

  xwrite(fd, "\n", 1);
}

#define AS_PHDR(X, t) (containerType == CONTAINER_ELF32?((t)(a.aspElf_Header32 X)):((t)(a.aspElf_Header64 X)))
#define AS_SHDR(X, t) (containerType == CONTAINER_ELF32?((t)(b.aspElf_Shdr32 X)):((t)(b.aspElf_Shdr64 X)))
void x86_build_code(char *str)
{
  char *args[] = {"as", NULL, NULL, "-o", NULL, NULL};
  int sfd, bfd;
  char *sname, *bname;
  struct stat sts;
  Offset   offset = 0;
  Address    size = 0;
  int         status;
  void        *map;
  pid_t       pid;
  int         fd;
  unsigned char *opcode;
  char *ptrNameSection = NULL;
  int x;
  union {
    Elf32_Ehdr  *aspElf_Header32;
    Elf64_Ehdr  *aspElf_Header64;
  } a;
  union {
    Elf32_Shdr  *aspElf_Shdr32;
    Elf64_Shdr  *aspElf_Shdr64;
  } b;

  make_temporary_file(&sname, &sfd);
  make_temporary_file(&bname, &bfd);

  if(containerType == CONTAINER_ELF32)
    args[1] = "--32";
  else
    args[1] = "--64";

  args[2] = sname;
  args[4] = bname;

  write_source_file(str, sfd);

  xclose(bfd);
  xclose(sfd);

  pid = fork();
  if (pid == 0)
    {
      execvp(args[0], args);
      exit(EXIT_SUCCESS);
    }
  waitpid(pid, &status, 0);

  if (stat(bname, &sts) == -1)
    exit(EXIT_FAILURE);

  fd = xopen(bname, O_RDONLY, 0644);
  map = xmmap(0, sts.st_size, PROT_READ, MAP_SHARED, fd, 0);

  AS_PHDR( = map, void *);
  AS_SHDR( = (void*)(AS_PHDR(+0, char*) + AS_PHDR(->e_shoff, size_t)), void *);

  AS_SHDR( += AS_PHDR(->e_shstrndx, size_t), void *);

  ptrNameSection = (char *)filemode.data + AS_SHDR(->sh_offset, size_t);

  AS_SHDR( -= AS_PHDR(->e_shstrndx, size_t), void *);

  for (x = 0; x != AS_PHDR(->e_shnum, int); x++, AS_SHDR(++, size_t))
    if (!strcmp((char *)(ptrNameSection + AS_SHDR(->sh_name, size_t)), ".text"))
      {
        offset = AS_SHDR(->sh_offset, Offset);
        size = AS_SHDR(->sh_size, Address);
      }

  asm_mode.size = size;
  opcode = xmalloc((size * sizeof(char)) + 1);
  asm_mode.argument = str;
  memcpy((char *)opcode, (char *)map + offset, asm_mode.size);
  opcode_mode.flag = 1;
  opcode_mode.size = asm_mode.size;
  opcode_mode.opcode = opcode;

  xclose(fd);

  unlink(bname);
  unlink(sname);

  free(bname);
  free(sname);
}
#undef AS_PHDR
#undef AS_SHDR
