/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-18
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

unsigned char *save_bin_data(char *binary, unsigned int size)
{
  unsigned char *data;
  int fd;

  fd = open(binary, O_RDONLY);
  pMapElf = mmap(0, size, PROT_READ, MAP_SHARED, fd, 0);
  if (fd == -1)
    {
      perror("open");
      exit(EXIT_FAILURE);
    }
  data = malloc(size * sizeof(char));
  if (data == NULL)
    {
      perror("malloc");
      exit(EXIT_FAILURE);
    }
  read(fd, data, size);
  close(fd);

  return (data);
}
