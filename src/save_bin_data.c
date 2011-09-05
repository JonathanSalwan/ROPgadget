/*
** RopGadget - Release v3.1
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-09-05
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
