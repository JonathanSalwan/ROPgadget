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

#define SHDR(X, t) (containerType == CONTAINER_ELF32?((t)(a.pElf32_Shdr X)):((t)(a.pElf64_Shdr X)))
void save_section(void)
{
  Size  x = 0;
  char *ptrNameSection = NULL;
  Size shnum;
  union {
    Elf32_Shdr *pElf32_Shdr;
    Elf64_Shdr *pElf64_Shdr;
  } a;

  if (containerType == CONTAINER_ELF32)
    a.pElf32_Shdr = (Elf32_Shdr *)(filemode.data + pElf32_Header->e_shoff);
  else
    a.pElf64_Shdr = (Elf64_Shdr *)(filemode.data + pElf64_Header->e_shoff);

  shnum = (containerType == CONTAINER_ELF32?pElf32_Header->e_shnum:pElf64_Header->e_shnum);

  SHDR( += (containerType == CONTAINER_ELF32?pElf32_Header->e_shstrndx:pElf64_Header->e_shstrndx), void *);

  ptrNameSection = (char *)filemode.data + SHDR(->sh_offset, size_t);

  SHDR( -= (containerType == CONTAINER_ELF32?pElf32_Header->e_shstrndx:pElf64_Header->e_shstrndx), void *);

  for ( x = 0; x != shnum; x++, SHDR(++, void *))
  {
    char *name = ptrNameSection + SHDR(->sh_name, size_t);
    printf("%s, %d, %d\n", name, x, shnum);
    if (!strcmp(name, ".data"))
      Addr_sData = SHDR(->sh_addr, Address);
    else if (!strcmp(name, ".got"))
      {
        Addr_sGot = SHDR(->sh_addr, Address);
        importsc_mode.gotsize = SHDR(->sh_size, size_t);
      }
    else if (!strcmp(name, ".gotplt"))
      importsc_mode.gotpltsize = SHDR(->sh_size, size_t);
  }

  if (Addr_sData % 0x100 == 0x00)
    Addr_sData++;
  if (Addr_sGot % 0x100 == 0x00)
    Addr_sGot++;
}
#undef SHDR
