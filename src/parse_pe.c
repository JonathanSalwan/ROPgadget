/*
** RopGadgetX - Release v1.0.0
** Allan Wirth - http://allanwirth.com/
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** 2012-1-4
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

cleanup_pef:
  pe_deinit(&pef);

cleanup_fh:
  fclose(h);

cleanup_fd:
  close(fd2);

ret:
  return res;
}
