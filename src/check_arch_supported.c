/*
** RopGadget - Release v3.3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-02-19
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

#include <stdio.h>
#include "ropgadget.h"

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
