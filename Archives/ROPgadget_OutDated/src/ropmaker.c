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

/*
** match() is used in search_instruction() for match any reg:
** ex => %e?x match with %eax, %ebx, %ecx, %edx
*/
int match(const char *gadget, const char *instruction)
{
  size_t n = strlen(instruction);

  if (strlen(gadget) < n)
    return FALSE;

  return match2((unsigned char *)gadget, (unsigned char *)instruction, n);
}
/*
** same as match but only check first n bytes
** We use this because s1 (data) might have null bytes in it that don't
** indicate the end of the string
*/
int match2(const unsigned char *s1, const unsigned char *s2, size_t n)
{
  size_t i;
  unsigned char c;

  for (i = 0; i < n; i++)
    {
      c = s2[i];
      if (c != '?' && c != '#' && c != s1[i])
        return FALSE;
    }

  return TRUE;
}

/* check if instruction was match and return addr */
t_asm *search_instruction(t_asm *pGadgets, char *instruction)
{
  char  *p;
  int   i;
  t_asm *best = NULL;

  for (i = 0; pGadgets[i].instruction != NULL; i++)
    for (p = pGadgets[i].instruction; *p != 0; p++)
      if (match(p, instruction) && pGadgets[i].flag == 1 &&
          (best == NULL || pGadgets[i].size < best->size))
        best = &pGadgets[i];

  return best;
}
