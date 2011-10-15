/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-16
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

void check_d_mode(char **argv)
{
  struct stat filestat;
  unsigned char *data;
  unsigned int size;
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-d"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              pOption.dfile = argv[i + 1];
              if((stat(pOption.dfile, &filestat)) == -1)
                {
                  perror("stat");
                  exit(EXIT_FAILURE);
                }
              size = filestat.st_size;
              data = save_bin_data(pOption.dfile, size);
              display_data(data, size);
              free(data);
              exit(EXIT_SUCCESS);
            }
          else
            {
              fprintf(stderr, "Syntax: -d <binaire>\n");
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
