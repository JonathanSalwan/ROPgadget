/*
** RopGadget - Release v3.0
** Jonathan Salwan - http://shell-storm.org - http://twitter.com/shell_storm
** 2011-08-01
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
*/

#include "ropgadget.h"

/* function for add a new element in linked list | save a exec maps */
static t_maps_exec *add_maps_exec(t_maps_exec *old_element, Elf32_Addr addr_start, Elf32_Addr addr_end)
{
  t_maps_exec *new_element;

  new_element = malloc(sizeof(t_maps_exec));
  if (new_element == NULL)
    exit(-1);
  new_element->addr_start = addr_start;
  new_element->addr_end   = addr_end;
  new_element->next       = old_element;

  return (new_element);
}

/* free linked list */
void free_add_maps_exec(t_maps_exec *element)
{
  t_maps_exec *tmp;

  while(element)
    {
      tmp = element;
      element = element->next;
      free(tmp);
    }
}

/* check if flag have a EXEC BIT */
static int check_exec_flag(Elf32_Word flag)
{
  if (flag == 1 || flag == 3 || flag == 5 || flag == 7)
    return (TRUE);
  else
    return (FALSE);
}

/* display elf header */
static void display_elf_header(void)
{
  fprintf(stdout, "%sELF Header\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  fprintf(stdout, "entry        %s0x%.8x%s\n",	      RED, pElf_Header->e_entry, ENDC);
  fprintf(stdout, "phoff        %s0x%.8x%s\n",        RED, pElf_Header->e_phoff, ENDC);
  fprintf(stdout, "shoff        %s0x%.8x%s\n",        RED, pElf_Header->e_shoff, ENDC);
  fprintf(stdout, "flags        %s0x%.8x%s\n",        RED, pElf_Header->e_flags, ENDC);
  fprintf(stdout, "ehsize       %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_ehsize, pElf_Header->e_ehsize, ENDC);
  fprintf(stdout, "phentsize    %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_phentsize, pElf_Header->e_phentsize, ENDC);
  fprintf(stdout, "phnum        %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_phnum, pElf_Header->e_phnum,ENDC);
  fprintf(stdout, "shentsize    %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_shentsize, pElf_Header->e_shentsize, ENDC);
  fprintf(stdout, "shnum        %s0x%.8x (%d)%s\n",   RED, pElf_Header->e_shnum, pElf_Header->e_shnum,ENDC);
  fprintf(stdout, "shstrndx     %s0x%.8x (%d)%s\n\n", RED, pElf_Header->e_shstrndx,  pElf_Header->e_shstrndx,ENDC);
}

/* display program header */
static t_maps_exec *display_program_header(void)
{
  int  x = 0;
  t_maps_exec *maps_exec;

  maps_exec = NULL;
  fprintf(stdout, "\n%sProgram Header\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  while (x != pElf_Header->e_phnum)
    {
      fprintf(stdout, "%s%s%s\n", YELLOW, get_seg(pElf32_Phdr->p_type), ENDC);
      fprintf(stdout, "\toffset ");
      fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_offset, ENDC);
      fprintf(stdout, "vaddr ");
      fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_vaddr, ENDC);
      fprintf(stdout, "paddr ");
      fprintf(stdout, "%s0x%.8x%s\n", RED, pElf32_Phdr->p_paddr, ENDC);
      fprintf(stdout, "\tfilesz ");
      fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_filesz, ENDC);
      fprintf(stdout, "memsz ");
      fprintf(stdout, "%s0x%.8x%s ",  RED, pElf32_Phdr->p_memsz, ENDC);
      fprintf(stdout, "flags ");
      fprintf(stdout, "%s%s%s\n",   RED, get_flags(pElf32_Phdr->p_flags), ENDC);
      if (check_exec_flag(pElf32_Phdr->p_flags) == TRUE)
        maps_exec = add_maps_exec(maps_exec, pElf32_Phdr->p_vaddr, (Elf32_Addr)(pElf32_Phdr->p_vaddr + pElf32_Phdr->p_memsz));
      x++;
      pElf32_Phdr++;
    }
  pElf32_Phdr -= x;

  return (maps_exec);
}

/* display section header */
static void display_section_header(void)
{
  int  x = 0;
  char *ptrNameSection;

  while(x != pElf_Header->e_shnum)
    {
      if (pElf32_Shdr->sh_type == SHT_STRTAB && pElf32_Shdr->sh_addr == 0)
        {
          ptrNameSection =  (char *)pMapElf + pElf32_Shdr->sh_offset;
          break;
        }
      x++;
      pElf32_Shdr++;
    }
  pElf32_Shdr -= x;
  x = 0;

  fprintf(stdout, "\n\n%sSection Header\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  fprintf(stdout, "%sidx\taddr\t\tsize\t\tsection%s\n", GREEN, ENDC);
  while (x != pElf_Header->e_shnum)
  {
    fprintf(stdout, "%s%.2d%s\t", GREEN, x, ENDC);
    fprintf(stdout, "%s0x%.8x\t", RED, pElf32_Shdr->sh_addr);
    fprintf(stdout, "0x%.8x\t%s", pElf32_Shdr->sh_size, ENDC);
    fprintf(stdout, "%s\n", (char *)(ptrNameSection + pElf32_Shdr->sh_name));
    if (!strcmp((char *)(ptrNameSection + pElf32_Shdr->sh_name), ".data")) /* for the ropmaker */
      Addr_sData = pElf32_Shdr->sh_addr;
    x++;
    pElf32_Shdr++;
  }
  pElf32_Shdr -= x;
  fprintf(stdout, "\n\n");
}

t_maps_exec *display_info_header(void)
{
  t_maps_exec *maps_exec;

  display_elf_header();
  maps_exec = display_program_header();
  display_section_header();

  return (maps_exec);
}
