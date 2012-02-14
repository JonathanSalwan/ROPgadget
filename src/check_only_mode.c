/*
** RopGadget - Release v3.3.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2012-02-14
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

static t_only_linked *add_element_only(t_only_linked *old_element, char *word)
{
  t_only_linked *new_element;

  new_element = xmalloc(sizeof(t_only_linked));
  new_element->word = word;
  new_element->next = old_element;

  return (new_element);
}

void check_only_mode(char **argv)
{
  int i = 0;

  only_mode.flag = 0;
  only_linked = NULL;
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-only"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              only_mode.argument = argv[i + 1];
              only_mode.flag = 1;
              only_linked = add_element_only(only_linked, only_mode.argument);
            }
          else
            {
              fprintf(stderr, "%sSyntax%s: -only <keyword>\n", RED, ENDC);
              fprintf(stderr, "%sEx%s:     -only \"dec %%edx\"\n", RED, ENDC);
              fprintf(stderr, "        -only \"pop %%eax\" -only \"dec\"\n");
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
