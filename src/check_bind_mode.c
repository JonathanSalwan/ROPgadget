/*
** RopGadget - Release v3.3.4
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-06-25
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

void check_bind_mode(char **argv)
{
  int i = 0;

  memset(bind_mode.port, 0x00, sizeof(bind_mode.port));
  strcpy(bind_mode.port, "1337"); /* set a default port */
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-bind"))
        bind_mode.flag = 1;
      if (!strcmp(argv[i], "-port"))
        {
          if (argv[i + 1] == NULL)
            {
              fprintf(stderr, "%sSyntax%s: -port <port>\n", RED, ENDC);
              fprintf(stderr, "%sEx%s:     -port 8080\n", RED, ENDC);
              exit(EXIT_FAILURE);
            }
          if (atoi(argv[i + 1]) < 1000 || atoi(argv[i + 1]) > 9999)
            {
              fprintf(stderr, "%sError port%s: need to set port between 1000 and 9999 (For stack padding)\n", RED, ENDC);
              exit(EXIT_FAILURE);
            }
          strncpy(bind_mode.port, argv[i + 1], 4);
        }
      i++;
    }
}
