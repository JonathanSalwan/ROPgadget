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

static const char * const flag_const[] = {
  "---", "--x",
  "-w-", "-wx",
  "r--", "r-x",
  "rw-", "rwx",
  "Err"
};

const char *get_flags(Elf32_Word flags)
{
  if (flags > 7) flags = 8;
  return flag_const[flags];
}

/* returns section offset by name */
Elf32_Off get_offset_section(char *name)
{
  t_list_section *tmp;

  tmp = list_section;
  while(tmp)
    {
      if (!strcmp(tmp->name_section, name))
        return (tmp->offset);
      tmp = tmp->next;
    }
  return (0);
}

char *get_seg(Elf32_Word seg)
{
  if (seg == 0)
    return ("NULL");
  else if (seg == 1)
    return ("LOAD");
  else if (seg == 2)
    return ("DYNAMIC");
  else if (seg == 3)
    return ("INTERP");
  else if (seg == 4)
    return ("NOTE");
  else if (seg == 5)
    return ("SHLIB");
  else if (seg == 6)
    return ("PHDR");
  else if (seg == 7)
    return ("TLS");
  else if (seg == 8)
    return ("NUM");
  else if (seg == 0x60000000)
    return ("LOOS");
  else if (seg == 0x6fffffff)
    return ("HIOS");
  else if (seg == 0x70000000)
    return ("LOPROC");
  else if (seg == 0x7fffffff)
    return ("HIPROC");
  else if (seg == 0x6474e550)
    return ("EH_FRAME");
  else if (seg == 0x6474e551)
    return ("STACK");
  else if (seg == 0x6474e552)
    return ("RELRO");
  else if (seg == 0x65041580)
    return ("PAX_FLAGS");
  else
    return ("ERROR");
}

/* returns section size by name */
size_t get_size_section(char *name)
{
  t_list_section *tmp;

  tmp = list_section;
  while(tmp)
    {
      if (!strcmp(tmp->name_section, name))
        return (tmp->size);
      tmp = tmp->next;
    }
  return (0);
}

/* returns section addr by name */
Elf32_Addr get_addr_section(char *name)
{
  t_list_section *tmp;

  tmp = list_section;
  while(tmp)
    {
      if (!strcmp(tmp->name_section, name))
        return (tmp->addr);
      tmp = tmp->next;
    }
  return (0);
}

/* returns section offset by name */
int get_entsize_section(char *name)
{
  t_list_section *tmp;

  tmp = list_section;
  while(tmp)
    {
      if (!strcmp(tmp->name_section, name))
        return (tmp->entsize);
      tmp = tmp->next;
    }
  return (0);
}

void check_elf_format(unsigned char *data)
{
  if (strncmp((const char *)data, MAGIC_ELF, 4))
    {
      fprintf(stderr, "%sError%s: No elf format\n", RED, ENDC);
      exit(EXIT_FAILURE);
    }
}

#define SYSV     pElf_Header->e_ident[EI_OSABI] == ELFOSABI_SYSV
#define LINUX    pElf_Header->e_ident[EI_OSABI] == ELFOSABI_LINUX
#define FREEBSD  pElf_Header->e_ident[EI_OSABI] == ELFOSABI_FREEBSD
#define ELF_F    pElf_Header->e_ident[EI_CLASS] == ELFCLASS32
#define PROC8632 pElf_Header->e_machine == EM_386

void check_arch_supported(void)
{

  /* supported: - Linux/x86-32bits */
  /* supported: - FreeBSD/x86-32bits */
  if (ELF_F && (SYSV || LINUX || FREEBSD) && PROC8632)
    return ;
  else
    {
      fprintf(stderr, "%sError%s: Architecture isn't supported\n", RED, ENDC);
      exit(EXIT_FAILURE);
    }
}
