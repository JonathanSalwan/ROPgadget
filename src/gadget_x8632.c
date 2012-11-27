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
#include "x8632.h"

static void gadget_x8632(unsigned char *data, unsigned int cpt, Elf32_Addr offset, int i)
{
  char *varopins  = NULL;
  char *syntax = NULL;

  syntax = (syntaxins == INTEL)?tab_x8632[i].instruction_intel:tab_x8632[i].instruction;

  if (importsc_mode.flag == 1)
    save_octet(data, (Elf32_Addr)(cpt + offset));

  if(!match2((const char *)data, tab_x8632[i].value, tab_x8632[i].size))
    {
      /* no '?' & no '#' */
      if (!check_interrogation(syntax))
        {
          fprintf(stdout, "%s0x%.8x%s: %s%s%s\n", RED, (cpt + offset), ENDC, GREEN, syntax, ENDC);
          tab_x8632[i].flag = 1;
        }
      /* if '?' or '#' */
      else
        {
          varopins = ret_instruction((pMapElf + cpt), syntax, tab_x8632[i].value, tab_x8632[i].size);
          if (!check_if_varop_was_printed(varopins))
            {
              fprintf(stdout, "%s0x%.8x%s: %s%s%s\n", RED, (cpt + offset), ENDC, GREEN, varopins, ENDC);
              pVarop = add_element(pVarop, varopins, (cpt + offset));
            }
          else
            NbGadFound--;
          free(varopins);
        }

      tab_x8632[i].addr = (Elf32_Addr)(cpt + offset);
      NbGadFound++;
      NbTotalGadFound++;
    }
}

void x8632(unsigned char *data, unsigned int size_data, t_map *maps_exec, t_map *maps_read)
{
  int i;
  unsigned int cpt   = 0;
  Elf32_Addr  offset;
  char *real_string;
  char *inst_tmp;

  pGadgets = tab_x8632;
  NbTotalGadFound = 0;
  NbGadFound = 0;
  pVarop = NULL;
  importsc_mode.poctet = NULL;
  offset = (pElf32_Phdr->p_vaddr - pElf32_Phdr->p_offset); /* base addr */
  cpt = set_cpt_if_mapmode(cpt); /* mapmode */

  /* If we're in simple gadget mode, precompute which instructions to search */
  if (opcode_mode.flag != 1 && stringmode.flag != 1)
    {
      for (i = 0; i < (int)NB_GADGET; i++)
        {
          inst_tmp = (syntaxins == INTEL)?pGadgets[i].instruction_intel:pGadgets[i].instruction;
          if (!(filter(inst_tmp, &filter_mode) <=0 && filter(inst_tmp, &only_mode)))
            pGadgets[i].flag = -1;
        }
    }


  while(cpt < size_data && (int)NbGadFound != limitmode.value && (int)NbTotalGadFound != limitmode.value && !check_end_mapmode(cpt))
    {
      if (check_maps(stringmode.flag?maps_read:maps_exec, (Elf32_Addr)(cpt + offset)))
        continue;
      /* opcode mode */
      if (opcode_mode.flag)
        {
          if(!search_opcode((const char *)data, (char *)opcode_mode.opcode, opcode_mode.size))
            {
              fprintf(stdout, "%s0x%.8x%s: \"%s", RED, (cpt + offset), ENDC, GREEN);
              print_opcode();
              fprintf(stdout, "%s\"\n", ENDC);
              NbTotalGadFound++;
            }
        }
      /* string mode */
      else if (stringmode.flag)
        {
          if(!match2((const char *)data, (char *)stringmode.string, strlen(stringmode.string)))
            {
              real_string = real_string_stringmode(stringmode.string, data);
              fprintf(stdout, "%s0x%.8x%s: \"%s", RED, (cpt + offset), ENDC, GREEN);
              print_real_string(real_string);
              fprintf(stdout, "%s\"\n", ENDC);
              NbTotalGadFound++;
              free(real_string);
            }
        }
      /* simple gadget mode */
      else
        {
          for (i = 0; i < (int)NB_GADGET; i++)
            {
              if (pGadgets[i].flag != 0)
                continue;
              gadget_x8632(data, cpt, offset, i);
            }
        }

      cpt++;
      data++;
    }
}
