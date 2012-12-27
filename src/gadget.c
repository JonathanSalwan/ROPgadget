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

static void check_gadget(unsigned char *data, unsigned int cpt, Address offset, t_asm *asm, unsigned int *NbGadFound, unsigned int *NbTotalGadFound, t_list_inst **pVarop)
{
  char *varopins;
  char *syntax;

  if (importsc_mode.flag == 1)
    save_octet(data, (Address)(cpt + offset));

  /* if this doesn't match the current data pointer return */
  if(!match2(data, (unsigned char *)asm->value, asm->size))
    return;

  syntax = (syntaxins == INTEL)?asm->instruction_intel:asm->instruction;

  /* no '?' & no '#' */
  if (!check_interrogation(syntax))
    {
      fprintf(stdout, "%s" ADDR_FORMAT "%s: %s%s%s\n", RED, ADDR_WIDTH, (cpt + offset), ENDC, GREEN, syntax, ENDC);
      asm->flag = 1;
    }
  /* if '?' or '#' */
  else
    {
      varopins = ret_instruction(data, syntax, asm->value, asm->size);
      if (!check_if_varop_was_printed(varopins, *pVarop))
        {
          fprintf(stdout, "%s" ADDR_FORMAT "%s: %s%s%s\n", RED, ADDR_WIDTH, (cpt + offset), ENDC, GREEN, varopins, ENDC);
          *pVarop = add_element(*pVarop, varopins, (cpt + offset));
        }
      else
        *NbGadFound -= 1;
      free(varopins);
    }

  asm->addr = (Address)(cpt + offset);
  *NbGadFound += 1;
  *NbTotalGadFound += 1;
}

void find_all_gadgets(unsigned char *data, unsigned int size_data, t_map *maps_exec, t_map *maps_read, t_asm *gadgets, unsigned int *NbGadFound, unsigned int *NbTotalGadFound)
{
  int i;
  unsigned int cpt   = 0;
  Address  offset;
  char *real_string;
  char *inst_tmp;
  size_t stringlen = 0;
  t_list_inst *pVarop = NULL;

  importsc_mode.poctet = NULL;
  offset = (PHDR(->p_vaddr, Address) - PHDR(->p_offset, Offset)); /* base addr */
  cpt = set_cpt_if_mapmode(cpt); /* mapmode */

  /* If we're in simple gadget mode, precompute which instructions to search */
  if (opcode_mode.flag != 1 && stringmode.flag != 1)
    {
      for (i = 0; gadgets[i].size; i++)
        {
          inst_tmp = (syntaxins == INTEL)?gadgets[i].instruction_intel:gadgets[i].instruction;
          if (!(filter(inst_tmp, &filter_mode) <=0 && filter(inst_tmp, &only_mode)))
            gadgets[i].flag = -1;
        }
    }
  else if (stringmode.flag)
    {
      stringlen = strlen(stringmode.string);
    }


  for(; cpt < size_data && (int)*NbGadFound != limitmode.value && (int)*NbTotalGadFound != limitmode.value && !check_end_mapmode(cpt); cpt++, data++)
    {
      /* check if our address is NOT in the list of maps */
      if (!check_maps(stringmode.flag?maps_read:maps_exec, (Address)(cpt + offset)))
        continue;
      /* opcode mode */
      if (opcode_mode.flag)
        {
          if(!strncmp((char *)data, (char *)opcode_mode.opcode, opcode_mode.size))
            {
              fprintf(stdout, "%s" ADDR_FORMAT "%s: \"%s", RED, ADDR_WIDTH, (cpt + offset), ENDC, GREEN);
              print_opcode();
              fprintf(stdout, "%s\"\n", ENDC);
              *NbTotalGadFound += 1;
            }
        }
      /* string mode */
      else if (stringmode.flag)
        {
          if(match2(data, (unsigned char *)stringmode.string, stringlen))
            {
              real_string = real_string_stringmode(stringmode.string, data);
              fprintf(stdout, "%s" ADDR_FORMAT "%s: \"%s", RED, ADDR_WIDTH, (cpt + offset), ENDC, GREEN);
              print_real_string(real_string);
              fprintf(stdout, "%s\"\n", ENDC);
              *NbTotalGadFound += 1;
              free(real_string);
            }
        }
      /* simple gadget mode */
      else
        {
          for (i = 0; gadgets[i].size; i++)
            {
              if (gadgets[i].flag != 0)
                continue;
              check_gadget(data, cpt, offset, &gadgets[i], NbGadFound, NbTotalGadFound, &pVarop);
            }
        }
    }

  free_list_inst(pVarop);
}
