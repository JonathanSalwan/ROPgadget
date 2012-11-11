/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-11-11
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

static t_filter_linked *add_element_filter(t_filter_linked *old_element, char *word)
{
  t_filter_linked *new_element;

  new_element = xmalloc(sizeof(t_filter_linked));
  new_element->word = word;
  new_element->next = old_element;

  return (new_element);
}

void check_filtre_mode(char **argv)
{
  int i = 0;

  filter_mode.flag = 0;
  filter_linked = NULL;
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-filter"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              filter_mode.argument = argv[i + 1];
              filter_mode.flag = 1;
              filter_linked = add_element_filter(filter_linked, filter_mode.argument);
            }
          else
            {
              fprintf(stderr, "%sSyntax%s: -filtre <word>\n", RED, ENDC);
              fprintf(stderr, "%sEx%s:     -filter \"dec %%edx\"\n", RED, ENDC);
              fprintf(stderr, "        -filter \"pop %%eax\" -filter \"dec\"\n");
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
