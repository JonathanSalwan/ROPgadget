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

static void check_gadget(unsigned char *data, Address v_addr, t_asm *asm,
                         unsigned int *NbGadFound, unsigned int *NbTotalGadFound,
                         t_list_inst **pVarop)
{
  char *varopins;
  char *syntax;

  /* if this doesn't match the current data pointer return */
  if(!match2(data, (unsigned char *)asm->value, asm->size))
    return;

  syntax = DISPLAY_SYNTAX(asm);

  (void)varopins;
  (void)pVarop;

  /* no '?' & no '#' */
  /*
  ** TODO: Fix this bug when the opcode in gadget is '#' or '?'
  **       See: github issue https://github.com/JonathanSalwan/ROPgadget/issues/13
  **
  ** if (!check_interrogation(syntax))
  **  {
  */
      uprintf("%s" ADDR_FORMAT "%s: %s%s%s\n", RED, ADDR_WIDTH, v_addr, ENDC, GREEN, syntax, ENDC);
      asm->flag = 1;
  /*
  **  }
  */

  /* if '?' or '#' */
  /*
  ** TODO: Fix this bug when the opcode in gadget is '#' or '?'
  **       See: github issue https://github.com/JonathanSalwan/ROPgadget/issues/13
  ** else
  **   {
  **     varopins = ret_instruction(data, syntax, asm->value, asm->size);
  **     if (!check_if_varop_was_printed(varopins, *pVarop))
  **       {
  **         uprintf("%s" ADDR_FORMAT "%s: %s%s%s\n", RED, ADDR_WIDTH, v_addr, ENDC, GREEN, varopins, ENDC);
  **         *pVarop = add_element(*pVarop, varopins, NULL);
  **       }
  **     else
  **       *NbGadFound -= 1;
  **     free(varopins);
  **   }
  */

  asm->addr = v_addr;
  *NbGadFound += 1;
  *NbTotalGadFound += 1;
}

static void find_all_gadgets(t_binary *bin, t_asm *gadgets, unsigned int *NbGadFound,
                             unsigned int *NbTotalGadFound)
{
  int i;
  unsigned char *real_string;
  char *inst_tmp;
  size_t stringlen = 0;
  t_list_inst *pVarop = NULL;

  size_t max_gadget_size = 0, different = 0, max_difference=40, j;
  char* all_endings = NULL;
  unsigned char** endings = NULL;

  /* If we're in simple gadget mode, precompute which instructions to search */
  if (opcode_mode.flag != 1 && stringmode.flag != 1)
    {
      all_endings = xmalloc(max_difference);
      for (i = 0; gadgets[i].size; i++)
        {
          inst_tmp = DISPLAY_SYNTAX(&gadgets[i]);
          if (!(filter(inst_tmp, &filter_mode) <=0 && filter(inst_tmp, &only_mode)))
            gadgets[i].flag = -1;

         // Find the maximum number of op-codes in a gadget
         if(gadgets[i].size > max_gadget_size)
           max_gadget_size = gadgets[i].size;

         // Store all the possible last byte instruction
         for(j = 0; j < different; j++)	{
           if(all_endings[j] == gadgets[i].value[gadgets[i].size-1])
             break;
         }

         // Need to allocate more space
         if(different >= max_difference)  {
           max_difference *= 2;
           char* tmp = xmalloc(max_difference);
           for(j = 0; j < different; j++)
             tmp[j] = all_endings[j];
           free(all_endings);
           all_endings = tmp;
         }

         // New possible ending
         if(j >= different && different < max_difference)  {
           all_endings[different++] = gadgets[i].value[gadgets[i].size-1];
         }
        }
      free(all_endings);

      // Allocate the new array to store which last-byte instruction is possible
      // compared to the length of the gadget.
      // endings[n][0] = number of endings in gadgets of length n
      // endings[n][1->] = All possible endings in gadget of length n
      endings = xmalloc( (max_gadget_size+1)*sizeof(unsigned char*));
      for(i = 0; i <= (int)max_gadget_size; i++)  {
        endings[i] = xmalloc(different+2);
        endings[i][0] = 0;	// The number of bytes that follows
      }

      // Go through all gadgets and find which last-byte instruction is possible
      // on each possible length
      for (i = 0; gadgets[i].size; i++)  {
        int n = gadgets[i].size;
        int insert = 1;  // Insert into the list
        for(j = 1; j <= (size_t)endings[n][0]; j++)  {
          if(gadgets[i].value[n-1] == (char)endings[n][j])  {
            insert = 0;  // Already exist in array
            break;
          }
        }
        if(insert)  {
          // New possible ending for gadgets of length n
          endings[n][++endings[n][0]] = gadgets[i].value[n-1];
        }
      }
    }
  else if (stringmode.flag)
    {
      stringlen = strlen(stringmode.string);
    }


  for (t_map *map = stringmode.flag?bin->maps_read:bin->maps_exec; map; map = map->next)  {
    for (size_t cpt = 0; cpt < map->size; cpt++)
      {
        unsigned char *data = bin->data + map->offset + cpt;
        Address v_addr = map->addr_start + cpt;

        if (mapmode.flag && !(v_addr >= mapmode.addr_start &&
            v_addr <= mapmode.addr_end))
          continue;

        /* opcode mode */
        if (opcode_mode.flag)
          {
            if(!memcmp((char *)data, (char *)opcode_mode.opcode, opcode_mode.size))
              {
                uprintf("%s" ADDR_FORMAT "%s: \"%s", RED, ADDR_WIDTH, v_addr, ENDC, GREEN);
                print_opcode();
                uprintf("%s\"\n", ENDC);
                *NbTotalGadFound += 1;
              }
          }
        /* string mode */
        else if (stringmode.flag)
          {
            if(match2(data, (unsigned char *)stringmode.string, stringlen))
              {
                real_string = real_string_stringmode(stringmode.string, data);
                uprintf("%s" ADDR_FORMAT "%s: \"%s", RED, ADDR_WIDTH, v_addr, ENDC, GREEN);
                print_real_string(real_string);
                uprintf("%s\"\n", ENDC);
                *NbTotalGadFound += 1;
                free(real_string);
              }
          }
        /* simple gadget mode */
        else
          {
            // Check if "data" is a possible gadget
            int check = 0;	// Not a possible gadget
            for(i = 1; i <= (int)max_gadget_size; i++)	{
              for(j = 1; j <= endings[i][0]; j++)	{
                if(data[i-1] == endings[i][j])	{
                  check = 1;	// Possible gadget
                  break;
                }
              }
            }
            if(check)	{
              for (i = 0; gadgets[i].size; i++)
              {
                if (gadgets[i].flag != 0)
                  continue;
                check_gadget(data, v_addr, &gadgets[i], NbGadFound, NbTotalGadFound, &pVarop);
              }
            }
          }


        if (*NbGadFound >= limitmode.value || *NbTotalGadFound >= limitmode.value)
          goto done;
      }
  }

done:
  free_list_inst(pVarop);
  if (endings != NULL)  {
    for(i = 0; i <= (int)max_gadget_size; i++)  {
      free(endings[i]);
    }
    free(endings);
  }
}

void search_gadgets(t_binary *bin)
{
  unsigned int NbGadFound = 0;
  unsigned int NbTotalGadFound = 0;

  uprintf("%sGadgets information\n", YELLOW);
  uprintf("============================================================%s\n", ENDC);

  /* Linux/x86-32bits & FreeBSD/x86-32bits*/
  if (bin->processor == PROCESSOR_X8632)
    find_all_gadgets(bin, tab_x8632, &NbGadFound, &NbTotalGadFound);
  else if (bin->processor == PROCESSOR_X8664)
    find_all_gadgets(bin, tab_x8664, &NbGadFound, &NbTotalGadFound);
  else
    {
      eprintf("Gadget searching not supported for this architecture.\n");
      return;
    }

  if (opcode_mode.flag == 1)
    uprintf("\nTotal opcodes found: %s%u%s\n", YELLOW, NbTotalGadFound, ENDC);
  else if (stringmode.flag == 1)
    uprintf("\nTotal strings found: %s%u%s\n", YELLOW, NbTotalGadFound, ENDC);
  else
    uprintf("\nUnique gadgets found: %s%u%s\n", YELLOW, NbGadFound, ENDC);
}
