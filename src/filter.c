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

int filter(char *instruction, t_filter_mode *mode)
{
  t_word_linked *tmp;

  if (mode->flag == 0)
    return -1;

  /* every substring in instruction against every filter. */
  for (tmp = mode->linked; tmp != NULL; tmp = tmp->next)
    if (strstr(instruction, tmp->word))
      return 1;

  return 0;
}

t_word_linked *add_element_word(t_word_linked *old_element, char *word)
{
  t_word_linked *new_element;

  new_element = xmalloc(sizeof(t_word_linked));
  new_element->word = word;
  new_element->next = old_element;

  return new_element;
}
