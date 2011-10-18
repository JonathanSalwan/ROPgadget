/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-18
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

/* function "-d  Dump Hexadecimal" */
void display_data(unsigned char *data, unsigned int size_data)
{
  unsigned int cpt = 0;
  int i = 0;

  while(cpt < size_data)
    {
      fprintf(stdout, "%.8x   ", cpt);
      while (i < 16 && cpt < size_data)
        {
          if (i == 4 || i == 8 || i == 12)
            printf(" ");
          fprintf(stdout, "%.2X ", data[cpt++]);
          i++;
        }
      cpt = cpt - 16;
      i = 0;
      fprintf(stdout, " [");
      while (i < 16 && cpt < size_data)
        {
          if(data[cpt] >= 32 && data[cpt] <= 126)
            fprintf(stdout, "%c", data[cpt]);
          else
              fprintf(stdout, ".");
          cpt++;
          i++;
        }
      fprintf(stdout, "]\n");
      i = 0;
    }
}
