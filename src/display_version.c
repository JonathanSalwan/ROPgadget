/*
** RopGadget - Release v3.1
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-09-05
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

void display_version(void)
{
  fprintf(stdout, "RopGadget - Release v3.1 (2011-09-05)\n");
  fprintf(stdout, "Jonathan Salwan - twitter @JonathanSalwan\n");
  fprintf(stdout, "http://www.shell-storm.org\n");

  exit(EXIT_SUCCESS);
}
