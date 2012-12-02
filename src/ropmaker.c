/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** Allan Wirth - http://allanwirth.com/
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

/*
** match() is used in search_instruction() for match any reg:
** ex => %e?x match with %eax, %ebx, %ecx, %edx
*/
int match(const char *s1, const char *s2, size_t n)
{
  size_t i;

  if (strlen(s1) < n)
    return 1;

  for (i = 0; s1[i] != '\0' && s2[i] != '\0' && i < n; i++)
    if ((unsigned char)s1[i] != (unsigned char)s2[i] && !(s2[i] == '?' || s2[i] == '#'))
      return 1;

  return 0;
}
/*
** same as match but only check first n bytes
*/
int match2(const unsigned char *s1, const unsigned char *s2, size_t n)
{
  size_t i;
  unsigned char c;

  for (i = 0; i < n; i++)
    {
      c = s2[i];
      if (c != '?' && c != '#' && c != s1[i])
        return 1;
    }

  return 0;
}

/* check if instruction was match and return addr */
Address search_instruction(t_asm *pGadgets, char *instruction)
{
  char  *p;
  int   i;

  for (i = 0; pGadgets[i].instruction != NULL; i++)
    for (p = pGadgets[i].instruction; *p != 0; p++)
      if (!match(p, instruction, strlen(instruction)) && pGadgets[i].flag == 1)
        return pGadgets[i].addr;

  return 0;
}

/* returns the gadget since addr */
char *get_gadget_since_addr(t_asm *pGadgets, Address addr)
{
  int i;

  for (i = 0; pGadgets[i].instruction != NULL; i++)
    if (pGadgets[i].addr == addr && pGadgets[i].flag == 1)
      return pGadgets[i].instruction;

  return "Error";
}

/* returns the gadget since addr with att syntax (just for parsing in makecode ) */
char *get_gadget_since_addr_att(t_asm *pGadgets, Address addr)
{
  int i;

  for (i = 0; pGadgets[i].instruction != NULL; i++)
    if (pGadgets[i].addr == addr && pGadgets[i].flag == 1)
      return pGadgets[i].instruction;

  return "Error";
}
