/*
** RopGadget - Release v3.4.0
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-06-26
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

void check_limit_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-limit"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              limitmode.flag = 1;
              limitmode.value = atoi(argv[i + 1]);
              if (limitmode.value < 0 || limitmode.value > 0xfffe)
                {
                  fprintf(stderr, "%sError%s: limit value\n", RED, ENDC);
                  exit(EXIT_FAILURE);
                }
            }
          else
            {
              fprintf(stderr, "%sSyntax%s: -limit <value>\n", RED, ENDC);
              fprintf(stderr, "%sEx%s:     -limit 100\n", RED, ENDC);
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
