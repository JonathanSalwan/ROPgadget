/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
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

#define SFILE_WRITE "/tmp/ropgadget_asm.s"
#define BFILE_WRITE "/tmp/ropgadget_asm"

static void del_files(void)
{
  unlink(SFILE_WRITE);
  unlink(BFILE_WRITE);
}

static void write_source_file(char *str)
{
  int fd;
  int i;

  fd = xopen(SFILE_WRITE, O_WRONLY | O_CREAT | O_APPEND, 0755);
  if (syntaxins == INTEL)
    write(fd, ".intel_syntax noprefix\n", 23);

  for (i = 0; str[i] != '\0'; i++)
    if (str[i] == ';')
      write(fd, "\n", 1);
    else
      write(fd, &str[i], 1);

  write(fd, "\n", 1);
  xclose(fd);
}

Elf32_Off return_info_text(int flag, void *map, Elf32_Ehdr *ElfH, Elf32_Shdr *ElfS)
{
  char *ptrNameSection;
  int x;

  for (x = 0; x != ElfH->e_shnum; x++, ElfS++)
    if (ElfS->sh_type == SHT_STRTAB && ElfS->sh_addr == 0)
      {
        ptrNameSection = (char *)map + ElfS->sh_offset;
        break;
      }

  ElfS -= x;

  for (x = 0; x != ElfH->e_shnum; x++, ElfS++)
    if (!strcmp((char *)(ptrNameSection + ElfS->sh_name), ".text"))
      return flag == 0 ? ElfS->sh_offset : ElfS->sh_size;

  return 0;
}

void build_code(char *str)
{
  char *args[] = {"as", "--32", SFILE_WRITE, "-o", BFILE_WRITE, NULL};
  Elf32_Ehdr  *aspElf_Header;
  Elf32_Shdr  *aspElf_Shdr;
  Elf32_Off   offset;
  struct stat sts;
  uint32_t    size;
  int         status;
  void        *map;
  pid_t       pid;
  int         fd;

  del_files();
  write_source_file(str);
  pid = fork();
  if (pid == 0)
    {
      execvp(args[0], args);
      exit(EXIT_SUCCESS);
    }
  waitpid(pid, &status, 0);

  if (stat(BFILE_WRITE, &sts) == -1)
    exit(EXIT_FAILURE);

  fd = xopen(BFILE_WRITE, O_RDONLY, 0644);
  map = xmmap(0, sts.st_size, PROT_READ, MAP_SHARED, fd, 0);

  aspElf_Header = map;
  aspElf_Shdr = (Elf32_Shdr *)((char *)map + aspElf_Header->e_shoff);

  offset = return_info_text(0, map, aspElf_Header, aspElf_Shdr);
  size = return_info_text(1, map, aspElf_Header, aspElf_Shdr);

  asm_mode.size = size;
  asm_mode.opcode = xmalloc((size * sizeof(char)) + 1);
  asm_mode.argument = str;
  memcpy((char *)asm_mode.opcode, (char *)map + offset, asm_mode.size);
  opcode_mode.flag = 1;
  opcode_mode.size = asm_mode.size;
  opcode_mode.opcode = asm_mode.opcode;

  xclose(fd);
  del_files();
}
