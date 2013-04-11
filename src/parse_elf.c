/*
** RopGadget
** Allan Wirth - http://allanwirth.com/
** Jonathan Salwan - http://twitter.com/JonathanSalwan
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
#define DYN(a, b, X, t)  (b->container == CONTAINER_ELF32?(t)(a.dyn32 X)               :(t)(a.dyn64 X))
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

static void save_depends(t_binary *bin, void *dyns)
{
  union {
    Elf32_Dyn *dyn32;
    Elf64_Dyn *dyn64;
  } a;
  char *strtab = NULL;
  size_t i;

  DYN(a, bin, = dyns, void *);

  for (i = 0; DYN(a, bin, [i].d_tag, Elf64_Sxword) != DT_NULL; i++)
    {
      if (DYN(a, bin, [i].d_tag, Elf64_Sxword) == DT_STRTAB)
        {
          strtab = (char*)(DYN(a, bin, [i].d_un.d_val, Address) - bin->load_diff + bin->data);
          break;
        }
    }
  for (i = 0; DYN(a, bin, [i].d_tag, Elf64_Sxword) != DT_NULL; i++)
    {
      Elf64_Sxword type = DYN(a, bin, [i].d_tag, Elf64_Sxword);
      if (type == DT_NEEDED)
        bin->depends = add_dep(bin->depends, strtab + DYN(a, bin, [i].d_un.d_ptr, Address));
    }
}

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
    int flags = SHDR(shdr, bin, ->sh_flags, int);

    Address addr = SHDR(shdr, bin, ->sh_addr, Address);
    Size size = SHDR(shdr, bin, ->sh_size, Size);
    Size offset = SHDR(shdr, bin, ->sh_offset, Size);
    if (flags & SHF_ALLOC && flags & SHF_WRITE) /* .data, etc. */
      {
        if (addr == bin->writable_offset + bin->writable_size)
          bin->writable_size += size;
        else if (size > bin->writable_size)
          {
            bin->writable_offset = addr;
            bin->writable_size = size;
          }
      }
    if (flags & SHF_ALLOC && flags & SHF_WRITE && flags & SHF_EXECINSTR) /* .got, etc. */
      {
        if (addr == bin->writable_exec_offset + bin->writable_exec_size)
          bin->writable_exec_size += size;
        else if (size > bin->writable_exec_size)
          {
            bin->writable_exec_offset = addr;
            bin->writable_exec_size = size;
          }
      }
    if (!strcmp(name, ".text"))
      {
        bin->exec_offset = offset;
        bin->exec_size = size;
      }
    else if (!strcmp(name, ".dynamic"))
      {
        save_depends(bin, bin->data + offset);
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
    {
      if (read?check_read_flag(PHDR(bin, ->p_flags, Elf64_Word)):check_exec_flag(PHDR(bin, ->p_flags, Elf64_Word)))
        map = add_map(map, PHDR(bin, ->p_vaddr, Address), PHDR(bin, ->p_offset, Address), PHDR(bin, ->p_filesz, Size));
      if (!read && PHDR(bin, ->p_type == PT_LOAD, int) && !bin->load_diff_set)
        {
          bin->load_diff = PHDR(bin, ->p_vaddr, Address) - PHDR(bin, ->p_offset, Offset);
          bin->load_diff_set = TRUE;
        }
    }

  DEC_PHDR(bin, phnum);

  if (read)
    bin->maps_read = map;
  else
    bin->maps_exec = map;
}

static int is_elf(unsigned char *data)
{
  return !strncmp((char *)data, MAGIC_ELF, 4);
}

int process_elf(t_binary *output)
{
  unsigned char *data = output->data;

  if (!is_elf(output->data))
    return FALSE;

  /* supported: - Linux/x86-32bits */
  /* supported: - FreeBSD/x86-32bits */
  if (ELF_F(data) && (SYSV(data) || LINUX(data) || FREEBSD(data)))
    {
      output->container = CONTAINER_ELF32;
      output->processor = PROCESSOR_X8632;
      if (!PROC8632(output))
        return FALSE;
    }
  else if (ELF_F64(data) && (SYSV(data) || LINUX(data) || FREEBSD(data)))
    {
      output->container = CONTAINER_ELF64;
      output->processor = PROCESSOR_X8664;
      if (!PROC8664(output))
        return FALSE;
    }
  else
    return FALSE;

  if (EHDR(output, ->e_type, uint16_t) == ET_DYN)
    output->object = OBJECT_SHARED;
  else
    output->object = OBJECT_EXECUTABLE;

  output->abi = ABI_LINUX;

  output->phdr = output->data + EHDR(output, ->e_phoff, Size);

  make_maps(output, 0);
  make_maps(output, 1);

  save_sections(output);

  return TRUE;
}
