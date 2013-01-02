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

/* does something to the phdr/header struct with a given type, based on 32 or 64 bits */
/* Joshua 7:20 - Achan replied, "It is true! I have sinned against the LORD, the God of Israel." */
#define EHDR(b, X, t)    (b->container == CONTAINER_ELF32?((t)((Elf32_Ehdr*)b->data) X):((t)((Elf64_Ehdr*)b->data) X))
#define PHDR(b, X, t)    (b->container == CONTAINER_ELF32?((t)((Elf32_Phdr*)b->phdr) X):((t)((Elf64_Phdr*)b->phdr) X))
#define SHDR(a, b, X, t) (b->container == CONTAINER_ELF32?((t)((Elf32_Shdr*)a) X)      :((t)((Elf64_Shdr*)a) X))
#define ARTH_PHDR(b,n,op)(b->container == CONTAINER_ELF32?(b->phdr op sizeof(Elf32_Phdr)*(n)):(b->phdr op sizeof(Elf64_Phdr)*(n)))
#define ARTH_SHDR(a,b,n,op)(b->container == CONTAINER_ELF32?(a op sizeof(Elf32_Shdr)*(n)):(a op sizeof(Elf64_Shdr)*(n)))
#define INC_PHDR(b, n) ARTH_PHDR(b, n, +=)
#define INC_SHDR(a, b, n) ARTH_SHDR(a, b, n, +=)
#define DEC_PHDR(b, n) ARTH_PHDR(b, n, -=)
#define DEC_SHDR(a, b, n) ARTH_SHDR(a, b, n, -=)

#define SYSV(d)     (d[EI_OSABI] == ELFOSABI_SYSV)
#define LINUX(d)    (d[EI_OSABI] == ELFOSABI_LINUX)
#define FREEBSD(d)  (d[EI_OSABI] == ELFOSABI_FREEBSD)
#define ELF_F(d)    (d[EI_CLASS] == ELFCLASS32)
#define ELF_F64(d)  (d[EI_CLASS] == ELFCLASS64)
#define PROC8632(b) (EHDR(b,->e_machine, int) == (int)EM_386)
#define PROC8664(b) (EHDR(b,->e_machine, int) == (int)EM_X86_64)

static void save_sections(t_binary *bin)
{
  Size  x = 0;
  char *ptrNameSection = NULL;
  Size shnum;
  unsigned char *shdr;

  shdr = bin->data+ EHDR(bin, ->e_shoff, size_t);
  shnum = EHDR(bin, ->e_shnum, Size);

  INC_SHDR(shdr, bin, EHDR(bin, ->e_shstrndx, size_t));
  ptrNameSection = (char *)(bin->data + SHDR(shdr, bin, ->sh_offset, size_t));
  DEC_SHDR(shdr, bin, EHDR(bin, ->e_shstrndx, size_t));

  for ( x = 0; x != shnum; x++, INC_SHDR(shdr, bin, 1))
  {
    char *name = ptrNameSection + SHDR(shdr, bin, ->sh_name, size_t);
    if (SHDR(shdr, bin, ->sh_flags, int) & (SHF_ALLOC|SHF_WRITE) &&
        SHDR(shdr, bin, ->sh_size, Size) > bin->writable_size)
      {
        bin->writable_offset = SHDR(shdr, bin, ->sh_addr, Address);
        bin->writable_size = SHDR(shdr, bin, ->sh_size, Size);
      }
    if (SHDR(shdr, bin, ->sh_flags, int) & (SHF_ALLOC|SHF_WRITE|SHF_EXECINSTR) &&
        SHDR(shdr, bin, ->sh_size, Size) > bin->writable_exec_size)
      {
        bin->writable_exec_offset = SHDR(shdr, bin, ->sh_addr, Address);
        bin->writable_exec_size = SHDR(shdr, bin, ->sh_size, Size);
      }
    if (!strcmp(name, ".text"))
      {
        bin->exec_offset = SHDR(shdr, bin, ->sh_addr, Address);
        bin->exec_size = SHDR(shdr, bin, ->sh_size, Size);
      }
  }

  if (bin->writable_offset % 0x100 == 0x00 && bin->writable_size > 0)
    {
      bin->writable_offset++;
      bin->writable_size--;
    }
  if (bin->writable_exec_offset % 0x100 == 0x00 && bin->writable_exec_size > 0)
    {
      bin->writable_exec_offset++;
      bin->writable_exec_size--;
    }
}

/* function for add a new element in linked list | save a read/exec map */
static t_map *add_map(t_map *old_element, Address addr_start, Address addr_end)
{
  t_map *new_element;

  new_element = xmalloc(sizeof(t_map));
  new_element->addr_start = addr_start;
  new_element->addr_end   = addr_end;
  new_element->next       = old_element;

  return (new_element);
}

/* free linked list */
static void free_add_map(t_map *element)
{
  t_map *tmp;

  while(element)
    {
      tmp = element;
      element = element->next;
      free(tmp);
    }
}

/* check if flag have a READ BIT */
static int check_read_flag(Elf64_Word flag)
{
  return (flag > 3);
}

/* check if flag have a EXEC BIT */
static int check_exec_flag(Elf64_Word flag)
{
  return (flag%2 == 1);
}

/* return linked list with maps read/exec segment */
static void make_maps(t_binary *bin, int read)
{
  Elf64_Half  x;
  t_map *map;
  Elf64_Half phnum;

  map = NULL;
  phnum = EHDR(bin, ->e_phnum, Elf64_Half);

  for (x = 0; x != phnum; x++, INC_PHDR(bin, 1))
    if (read?check_read_flag(PHDR(bin, ->p_flags, Elf64_Word)):check_exec_flag(PHDR(bin, ->p_flags, Elf64_Word)))
      map = add_map(map, PHDR(bin, ->p_vaddr, Address), PHDR(bin, ->p_vaddr, Address) + PHDR(bin, ->p_memsz, Address));

  DEC_PHDR(bin, phnum);

  if (read)
    bin->maps_read = map;
  else
    bin->maps_exec = map;
}

void free_binary(t_binary *bin)
{
  if (bin == NULL) return;

  if (bin->file != NULL)
    free(bin->file);

  if (bin->data != NULL)
    munmap(bin->data, bin->size);

  if (bin->maps_read != NULL)
    free_add_map(bin->maps_read);

  if (bin->maps_exec != NULL)
    free_add_map(bin->maps_exec);

  free(bin);
}

t_binary *process_binary(char *file)
{
  int fd;
  unsigned char *data;
  struct stat filestat;
  t_binary *output = NULL;

  fd = xopen(file, O_RDONLY, 0644);
  if (stat(file, &filestat)) goto fail;

  data = xmmap(0, (size_t)filestat.st_size, PROT_READ, MAP_SHARED, fd, 0);
  close(fd);

  if (strncmp((char *)data, MAGIC_ELF, 4))
    goto fail;

  output = xmalloc(sizeof(t_binary));
  memset(output, 0, sizeof(t_binary));

  output->file = xmalloc(strlen(file)+1);
  strcpy(output->file, file);
  output->size = (size_t)filestat.st_size;
  output->data = data;
  /* supported: - Linux/x86-32bits */
  /* supported: - FreeBSD/x86-32bits */
  if (ELF_F(data) && (SYSV(data) || LINUX(data) || FREEBSD(data)))
    {
      output->container = CONTAINER_ELF32;
      if (!PROC8632(output))
        goto fail;
      output->processor = PROCESSOR_X8632;
    }
  else if (ELF_F64(data) && (SYSV(data) || LINUX(data) || FREEBSD(data)))
    {
      output->container = CONTAINER_ELF64;
      if (!PROC8664(output))
        goto fail;
      output->processor = PROCESSOR_X8664;
    }
  else
    goto fail;

  output->phdr = output->data + EHDR(output, ->e_phoff, Size);

  make_maps(output, 0);
  make_maps(output, 1);

  save_sections(output);

  output->base_addr = (PHDR(output, ->p_vaddr, Address) - PHDR(output, ->p_offset, Address));
  output->end_addr = output->base_addr + output->size;

  return output;

fail:
  free_binary(output);
  fprintf(stderr, "%sError%s: Architecture isn't supported or file does not exist\n", RED, ENDC);
  return NULL;
}

