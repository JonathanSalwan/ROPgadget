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

/* function for add a new element in linked list | save a read/exec map */
t_map *add_map(t_map *old_element, Address addr_start, Address offset, Size size)
{
  t_map *new_element;

  new_element = xmalloc(sizeof(t_map));
  new_element->addr_start = addr_start;
  new_element->size       = size;
  new_element->offset     = offset;
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

t_depend *add_dep(t_depend *next, char *dep)
{
  t_depend *d;
  d = xmalloc(sizeof(t_depend));
  d->name = xstrdup(dep);
  d->next = next;

  return d;
}

static void free_depends(t_depend *dep)
{
  t_depend *tmp;

  while (dep)
    {
      tmp = dep;
      if (tmp->name)
        free(tmp->name);
      dep = dep->next;
      free(tmp);
    }
}

t_binary *process_binary(char *file)
{
  int fd;
  struct stat filestat;
  int parsed;

  t_binary *output = NULL;
  fd = xopen(file, O_RDONLY, 0644);
  if (stat(file, &filestat))
    {
      eprintf("%sError%s: File does not exist\n", RED, ENDC);
      return NULL;
    }

  output = xmalloc(sizeof(t_binary));
  memset(output, 0, sizeof(t_binary));

  output->file = xstrdup(file);
  output->size = (size_t)filestat.st_size;
  output->data = xmmap(0, output->size, PROT_READ, MAP_SHARED, fd, 0);

  parsed = (process_elf(output) || process_pe(output, fd));

  close(fd);

  if (!parsed)
    {
      free_binary(output);
      eprintf("%sError%s: Architecture isn't supported\n", RED, ENDC);
      return NULL;
    }

  return output;
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

  if (bin->depends != NULL)
    free_depends(bin->depends);

  free(bin);
}
