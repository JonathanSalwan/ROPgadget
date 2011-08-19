/*
** RopGadget - Release v3.0
** Jonathan Salwan - http://shell-storm.org - http://twitter.com/shell_storm
** 2011-08-01
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
  fprintf(stdout, "RopGadget - Release v3.0 (2011-08-01)\n");
  fprintf(stdout, "Jonathan Salwan - twitter @shell_storm\n");
  fprintf(stdout, "http://www.shell-storm.org\n");

  exit(EXIT_SUCCESS);
}
