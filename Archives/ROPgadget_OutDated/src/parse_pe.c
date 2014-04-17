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
#include "pe.h"


#define IMAGE_SCN_MEM_EXECUTE     (DWORD)0x20000000
#define IMAGE_SCN_MEM_READ        (DWORD)0x40000000
#define IMAGE_SCN_MEM_WRITE       (DWORD)0x80000000

static void save_sections(t_binary *output, PE_FILE *pef)
{
  WORD i;

  for(i = 0; i < pef->num_sections; i++) {
    IMAGE_SECTION_HEADER *h = pef->sections_ptr[i];
    if (h->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
      output->maps_exec = add_map(output->maps_exec,
          h->VirtualAddress, h->PointerToRawData, h->SizeOfRawData);
    }
    if (h->Characteristics & IMAGE_SCN_MEM_READ) {
      output->maps_read = add_map(output->maps_read,
          h->VirtualAddress, h->PointerToRawData, h->SizeOfRawData);
    }
    if (h->Characteristics & IMAGE_SCN_MEM_WRITE &&
        h->SizeOfRawData > output->writable_size) {
      output->writable_size = h->SizeOfRawData;
      output->writable_offset = h->VirtualAddress;
    }
    if (h->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
        h->Characteristics & IMAGE_SCN_MEM_WRITE &&
        h->SizeOfRawData > output->writable_exec_size) {
      output->writable_exec_offset = h->VirtualAddress;
      output->writable_exec_size = h->SizeOfRawData;
    }
    if (h->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
        output->exec_offset == 0) {
      output->exec_offset = h->PointerToRawData;
      output->exec_size = h->SizeOfRawData;
    }
  }
}

int process_pe(t_binary *output, int fd)
{
  int fd2;
  PE_FILE pef;
  FILE *h;
  int res = FALSE;

  if ((fd2 = dup(fd)) == -1)
    goto ret;

  if (lseek(fd2, 0, SEEK_SET) == (off_t)-1 ||
      (h = fdopen(fd2, "r")) == NULL)
    goto cleanup_fd;

  if (!pe_init(&pef, h))
    goto cleanup_fh;

  if (!is_pe(&pef) ||
      !pe_get_sections(&pef))
    goto cleanup_pef;

  output->container = CONTAINER_PE;

  if (pef.architecture == PE32)
    output->processor = PROCESSOR_X8632;
  else if (pef.architecture == PE64)
    output->processor = PROCESSOR_X8664;
  else
    goto cleanup_pef;

  if (pef.isdll)
    output->object = OBJECT_SHARED;
  else
    output->object = OBJECT_EXECUTABLE;

  output->abi = ABI_WINNT;

  save_sections(output, &pef);

  res = TRUE;

cleanup_pef:
  pef.handle = NULL; /* prevent libpe from fclosing */
  pe_deinit(&pef);

cleanup_fh:
  fclose(h);

cleanup_fd:
  close(fd2);

ret:
  return res;
}
