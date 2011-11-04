/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-11-02
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

void display_symtab(void)
{
  t_list_symbols *tmp;
  int i;

  i = 0;
  flag_symtab = 1;
  tmp = list_symbols;
  fprintf(stdout, "%sSymbols Table\n", YELLOW);
  fprintf(stdout, "============================================================%s\n\n", ENDC);
  if (tmp == NULL)
    fprintf(stderr, "%s/!\\ no symbols in %s%s\n", RED, filemode.file, ENDC);
  else
    {
      fprintf(stderr, "%sidx  addr\tsize\t   name%s\n", GREEN, ENDC);
      while (tmp != NULL)
        {
          if (*tmp->name != '\0')
            {
              fprintf(stdout, "%s%.3x   %s%.8x\t%.8x   %s%s\n", GREEN, i, RED, tmp->st_value, tmp->st_size, ENDC, tmp->name);
              i++;
            }
          tmp = tmp->back;
        }
    }
  fprintf(stdout, "\n\n");
}

void check_symtab_mode(char **argv)
{
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-symtab") && flag_symtab == 0)
        display_symtab();
      i++;
    }
}
