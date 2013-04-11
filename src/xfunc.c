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

void *xmalloc(size_t size)
{
  char *p;

  p = malloc(size);
  if (p == NULL)
    {
      perror("malloc");
      exit(EXIT_FAILURE);
    }
  return (p);
}

int xopen(const char *pathname, int flags, mode_t mode)
{
  int fd;

  fd = open(pathname, flags, mode);
  if (fd == -1)
    {
      perror("open");
      exit(EXIT_FAILURE);
    }
  return (fd);
}

void *xmmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
  void *p;

  p = mmap(addr, len, prot, flags, fildes, off);
  if (p == MAP_FAILED)
    {
      perror("mmap");
      exit(EXIT_FAILURE);
    }

  return (p);
}

ssize_t xread(int fd, void *buf, size_t count)
{
  ssize_t ret;

  ret = read(fd, buf, count);
  if (ret == -1)
    {
      perror("read");
      exit(EXIT_FAILURE);
    }
  return (ret);
}

ssize_t xwrite(int fd, const void *buf, size_t count)
{
  ssize_t ret;

  ret = write(fd, buf, count);
  if (ret == -1)
    {
      perror("write");
      exit(EXIT_FAILURE);
    }
  return ret;
}

int xclose(int fd)
{
  int ret;

  ret = close(fd);
  if (ret == -1)
    {
      perror("close");
      exit(EXIT_FAILURE);
    }
  return (ret);
}

char *xstrdup(const char *a)
{
  char *r;

  r = strdup(a);
  if (r == NULL)
    {
      perror("strdup");
      exit(EXIT_FAILURE);
    }
  return r;
}
