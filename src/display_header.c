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

void display_elf_header(void)
{
  fprintf(stdout, "%sELF Header\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  fprintf(stdout, "entry        %s" ADDR_FORMAT "%s\n",	      RED, EHDR(->e_entry, Address), ENDC);
  fprintf(stdout, "phoff        %s" ADDR_FORMAT "%s\n",        RED, EHDR(->e_phoff, Address), ENDC);
  fprintf(stdout, "shoff        %s" ADDR_FORMAT "%s\n",        RED, EHDR(->e_shoff, Address), ENDC);
  fprintf(stdout, "flags        %s" ADDR_FORMAT "%s\n",        RED, EHDR(->e_flags, Size), ENDC);
  fprintf(stdout, "ehsize       %s" ADDR_FORMAT " (%2$d)%s\n",   RED, EHDR(->e_ehsize, Size), ENDC);
  fprintf(stdout, "phentsize    %s" ADDR_FORMAT " (%2$d)%s\n",   RED, EHDR(->e_phentsize, Size), ENDC);
  fprintf(stdout, "phnum        %s" ADDR_FORMAT " (%2$d)%s\n",   RED, EHDR(->e_phnum, Size), ENDC);
  fprintf(stdout, "shentsize    %s" ADDR_FORMAT " (%2$d)%s\n",   RED, EHDR(->e_shentsize, Size), ENDC);
  fprintf(stdout, "shnum        %s" ADDR_FORMAT " (%2$d)%s\n",   RED, EHDR(->e_shnum, Size), ENDC);
  fprintf(stdout, "shstrndx     %s" ADDR_FORMAT " (%2$d)%s\n\n\n", RED, EHDR(->e_shstrndx, Size), ENDC);
}

void display_symtab(void)
{
  t_list_symbols *tmp;
  int i;

  i = 0;
  tmp = list_symbols;
  fprintf(stdout, "%sSymbols Table\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  if (tmp == NULL)
    fprintf(stderr, "%s/!\\ no symbols in %s%s\n", RED, filemode.file, ENDC);
  else
    {
      fprintf(stderr, "%sidx  addr\tsize\t   name%s\n", GREEN, ENDC);
      while (tmp != NULL)
        {
          if (*tmp->name != '\0')
            {
              fprintf(stdout, "%s%.3x   %s" ADDR_FORMAT "\t" SIZE_FORMAT "   %s%s\n", GREEN, i, RED, tmp->st_value, tmp->st_size, ENDC, tmp->name);
              i++;
            }
          tmp = tmp->back;
        }
    }
  fprintf(stdout, "\n\n");
}

void display_program_header()
{
  Size x;

  fprintf(stdout, "%sProgram Header\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  for (x = 0; x != EHDR(->e_phnum, Size); x++, PHDR(++, void *))
    {
      fprintf(stdout, "%s%s%s\n", YELLOW, get_seg(PHDR(->p_type, Elf64_Word)), ENDC);
      fprintf(stdout, "\toffset %s" ADDR_FORMAT "%s ",  RED, PHDR(->p_offset, Offset), ENDC);
      fprintf(stdout, "vaddr %s" ADDR_FORMAT "%s ",  RED, PHDR(->p_vaddr, Address), ENDC);
      fprintf(stdout, "paddr %s" ADDR_FORMAT "%s\n", RED, PHDR(->p_paddr, Address), ENDC);
      fprintf(stdout, "\tfilesz %s" SIZE_FORMAT "%s ",  RED, PHDR(->p_filesz, Address), ENDC);
      fprintf(stdout, "memsz %s" SIZE_FORMAT "%s ",  RED, PHDR(->p_memsz, Address), ENDC);
      fprintf(stdout, "flags %s%s%s\n",   RED, get_flags(PHDR(->p_flags, Size)), ENDC);
    }
  PHDR( -= x, void *);
  fprintf(stdout, "\n\n");
}

#define SHDR(X, t) (containerType == CONTAINER_ELF32?((t)(a.pElf32_Shdr X)):((t)(a.pElf64_Shdr X)))
void display_section_header(void)
{
  union {
    Elf32_Shdr *pElf32_Shdr;
    Elf64_Shdr *pElf64_Shdr;
  } a;

  if (containerType == CONTAINER_ELF32)
    a.pElf32_Shdr = (Elf32_Shdr *)(filemode.data + pElf32_Header->e_shoff);
  else
    a.pElf64_Shdr = (Elf64_Shdr *)(filemode.data + pElf64_Header->e_shoff);

  char *ptrNameSection = NULL;
  Size x;

  for(x = 0; x != EHDR(->e_shnum, Size); x++, SHDR(++, void *))
    {
      if (SHDR(->sh_type, Elf64_Word) == SHT_STRTAB && SHDR(->sh_addr, Address) == 0)
        {
          ptrNameSection =  (char *)pMapElf + SHDR(->sh_offset, ssize_t);
          break;
        }
    }
  SHDR( -= x, void *);

  fprintf(stdout, "%sSection Header\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  fprintf(stdout, "%sidx\taddr\t\tsize\t\tsection%s\n", GREEN, ENDC);
  for (x = 0; x != EHDR(->e_shnum, Size); x++, SHDR(++, void *))
    {
      fprintf(stdout, "%s%.2d%s\t", GREEN, x, ENDC);
      fprintf(stdout, "%s" ADDR_FORMAT "\t", RED, SHDR(->sh_addr, Address));
      fprintf(stdout, SIZE_FORMAT "\t%s", SHDR(->sh_size, Size), ENDC);
      fprintf(stdout, "%s\n", (char *)(ptrNameSection + SHDR(->sh_name, ssize_t)));
    }
  SHDR( -= x, void *);
  fprintf(stdout, "\n\n");
}
#undef SHDR
