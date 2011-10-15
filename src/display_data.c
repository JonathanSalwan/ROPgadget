/*
** RopGadget - Dev v3.3
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-16
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
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
