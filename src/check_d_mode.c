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
