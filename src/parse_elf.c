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

#define MAGIC_ELF         "\x7F\x45\x4C\x46"

#define SYSV     (filemode.data[EI_OSABI] == ELFOSABI_SYSV)
#define LINUX    (filemode.data[EI_OSABI] == ELFOSABI_LINUX)
#define FREEBSD  (filemode.data[EI_OSABI] == ELFOSABI_FREEBSD)
#define ELF_F    (filemode.data[EI_CLASS] == ELFCLASS32)
#define ELF_F64  (filemode.data[EI_CLASS] == ELFCLASS64)
#define PROC8632 (pElf32_Header->e_machine == EM_386)
#define PROC8664 (pElf64_Header->e_machine == EM_X86_64)

void process_filemode(char *file)
{
  int fd;
  unsigned char *data;
  struct stat filestat;

  fd = xopen(file, O_RDONLY, 0644);
  stat(file, &filestat);
  filemode.size = (size_t)filestat.st_size;
  filemode.file = file;

  data = xmmap(0, filemode.size, PROT_READ, MAP_SHARED, fd, 0);
  filemode.data = data;
  close(fd);

  if (strncmp((char *)data, MAGIC_ELF, 4))
    {
      fprintf(stderr, "%sError%s: No elf format\n", RED, ENDC);
      exit(EXIT_FAILURE);
    }

  /* supported: - Linux/x86-32bits */
  /* supported: - FreeBSD/x86-32bits */
  if (ELF_F && (SYSV || LINUX || FREEBSD))
    {
      containerType = CONTAINER_ELF32;
      pElf32_Header = (Elf32_Ehdr *)data;
      pElf32_Phdr = (Elf32_Phdr *)(filemode.data + pElf32_Header->e_phoff);
      if (PROC8632)
        return;
    }
  else if (ELF_F64 && (SYSV || LINUX || FREEBSD))
    {
      containerType = CONTAINER_ELF64;
      pElf64_Header = (Elf64_Ehdr *)data;
      pElf64_Phdr = (Elf64_Phdr *)(filemode.data + pElf64_Header->e_phoff);
      if (PROC8664)
        return;
    }
  fprintf(stderr, "%sError%s: Architecture isn't supported\n", RED, ENDC);
  exit(EXIT_FAILURE);
}
