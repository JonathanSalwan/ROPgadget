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

#define MKSTEMP_TEMPLATE "/tmp/ropgadget_XXXXXX"

static void make_temporary_file(char **name, int *fd)
{
  char *tname;
  int tfd;

  tname = xstrdup(MKSTEMP_TEMPLATE);

  tfd = mkstemp(tname);

  *name = tname;
  *fd = tfd;
}

static void write_source_file(char *str, int fd)
{
  int i;

  if (syntaxins == INTEL)
    xwrite(fd, ".intel_syntax noprefix\n", 23);

  for (i = 0; str[i] != '\0'; i++)
    if (str[i] == ';')
      xwrite(fd, "\n", 1);
    else
      xwrite(fd, &str[i], 1);

  xwrite(fd, "\n", 1);
}

void x86_build_code(char *str, e_processor proc)
{
  char *args[] = {"as", NULL, NULL, "-o", NULL, NULL};
  int sfd, bfd;
  char *sname, *bname;
  pid_t       pid;
  t_binary *output;

  make_temporary_file(&sname, &sfd);
  make_temporary_file(&bname, &bfd);

  args[1] = (proc == PROCESSOR_X8632)?"--32":"--64";

  args[2] = sname;
  args[4] = bname;

  write_source_file(str, sfd);

  xclose(bfd);
  xclose(sfd);

  pid = fork();
  if (pid == 0)
    {
      execvp(args[0], args);
      exit(EXIT_SUCCESS);
    }
  waitpid(pid, NULL, 0);

  output = process_binary(bname);

  opcode_mode.opcode = xmalloc(output->exec_size * sizeof(char));
  memcpy(opcode_mode.opcode, output->data + output->exec_offset, output->exec_size);
  opcode_mode.flag = 1;
  opcode_mode.size = output->exec_size;

  free_binary(output);

  unlink(bname);
  unlink(sname);

  free(bname);
  free(sname);
}
