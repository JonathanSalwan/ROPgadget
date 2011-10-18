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

#define SFILE_WRITE "/tmp/ropgadget_asm.s"
#define BFILE_WRITE "/tmp/ropgadget_asm"

static int return_size(char *data)
{
  while (strcmp(data, ".text"))
    data++;
  while (*data != 0x00 && *(data + 1) != 0x00)
    data++;
  while (*data != 0x34)
    data++;

  return (*(data + 0x4));
}

static void del_files(void)
{
  unlink(SFILE_WRITE);
  unlink(BFILE_WRITE);
}

static void write_source_file(char *str)
{
  int fd;
  int i;

  i = 0;

  fd = open(SFILE_WRITE, O_WRONLY | O_CREAT | O_APPEND, 0755);
  while (str[i] != '\0')
    {
      if (str[i] == ';')
        write(fd, "\n", 1);
      else
        write(fd, &str[i], 1);
      i++;
    }
  write(fd, "\n", 1);
  close(fd);
}

static char *write_bin_file(int size)
{
  char *data;
  int fd;

  data = malloc(size * sizeof(char));
  fd = open(BFILE_WRITE, O_RDONLY);
  read(fd, data, size);
  close(fd);

  return (data);
}

static void make_opcode_with_nasm(char *str)
{
  pid_t pid;
  struct stat sts;
  int status;
  char *data;
  char *args[] = {"as", "--32", SFILE_WRITE, "-o", BFILE_WRITE, NULL};

  del_files();
  write_source_file(str);
  pid = fork();
  if (pid == 0)
    {
      execvp(args[0], args);
      exit(EXIT_SUCCESS);
    }
  waitpid(pid, &status, 0);

  if (stat(BFILE_WRITE, &sts) == -1)
    exit(EXIT_FAILURE);

  data = write_bin_file(sts.st_size);
  asm_mode.size = return_size(data);
  asm_mode.opcode = malloc(asm_mode.size * sizeof(char));
  asm_mode.argument = str;
  memcpy((char *)asm_mode.opcode, data + 0x34, asm_mode.size);
  opcode_mode.flag = 1;
  opcode_mode.size = asm_mode.size;
  opcode_mode.opcode = asm_mode.opcode;

  free(data);
  del_files();
}

void check_asm_mode(char **argv)
{
  int i = 0;

  asm_mode.flag = 0;
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-asm"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              asm_mode.argument = argv[i + 1];
              asm_mode.flag = 1;
              make_opcode_with_nasm(argv[i + 1]);
            }
          else
            {
              fprintf(stderr, "Syntax: -asm <instructions>\n\n");
              fprintf(stderr, "Ex: -asm \"xor %%ebx, %%eax\"\n");
              fprintf(stderr, "Ex: -asm \"int \\$0x80\"\n");
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
