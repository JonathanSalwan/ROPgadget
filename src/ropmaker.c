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

/*
** match() is used in search_instruction() for match any reg:
** ex => %e?x match with %eax, %ebx, %ecx, %edx
*/
int match(const char *s1, const char *s2, size_t n)
{
  int i = 0;

  if (strlen(s1) < n)
    return (1);
  start:
  while (s1[i] != '\0' && s2[i] != '\0' && n != 0)
    {
      if (s2[i] == '?' || s2[i] == '#')
        {
          i++;
          n--;
          goto start;
        }
      if ((unsigned char)s1[i] != (unsigned char)s2[i])
        return (1);
      i++;
      n--;
    }
  return (0);
}

int match2(const char *s1, const char *s2, size_t n)
{
  int i = 0;

  start:
  while (n != 0)
    {
      if (s2[i] == '?' || s2[i] == '#')
        {
          i++;
          n--;
          goto start;
        }
      if ((unsigned char)s1[i] != (unsigned char)s2[i])
        return (1);
      i++;
      n--;
    }
  return (0);
}

/* check if instruction was found */
int check_gadget_if_exist(char *instruction)
{
  int i = 0;

  while (pGadgets[i].instruction != NULL)
    {
      if (!strcmp(pGadgets[i].instruction, instruction) && pGadgets[i].flag == 1)
        return (TRUE);
      i++;
    }
  return (FALSE);
}

/* check if instruction was match and return addr */
Elf32_Addr search_instruction(char *instruction)
{
  char  *p;
  int   i = 0;

  while (pGadgets[i].instruction != NULL)
    {
      p = pGadgets[i].instruction;
      while (*p != 0)
        {
          if (!match(p, instruction, strlen(instruction)) && pGadgets[i].flag == 1)
            return (pGadgets[i].addr);
          p++;
        }
      i++;
    }
  return (0);
}

/* returns the gadget since addr */
char *get_gadget_since_addr(Elf32_Addr addr)
{
  int i = 0;

  while (pGadgets[i].instruction != NULL)
    {
      if (pGadgets[i].addr == addr && pGadgets[i].flag == 1)
        {
          if (syntaxins.type == INTEL)
            return (pGadgets[i].instruction_intel);
          else
            return (pGadgets[i].instruction);
        }
      i++;
    }
  return ("Error");
}

/* returns the gadget since addr with att syntax (just for parsing in makecode ) */
char *get_gadget_since_addr_att(Elf32_Addr addr)
{
  int i = 0;

  while (pGadgets[i].instruction != NULL)
    {
      if (pGadgets[i].addr == addr && pGadgets[i].flag == 1)
        return (pGadgets[i].instruction);
      i++;
    }
  return ("Error");
}

void ropmaker(void)
{
  if (importsc_mode.flag == 0)
    {
      combo_ropmaker1();
      combo_ropmaker2();
    }
  else if (importsc_mode.flag == 1)
    combo_ropmaker_importsc();
}
