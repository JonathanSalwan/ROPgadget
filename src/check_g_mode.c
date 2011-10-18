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

static void save_section_header(void)
{
  int  x = 0;
  char *ptrNameSection;

  while(x != pElf_Header->e_shnum)
    {
      if (pElf32_Shdr->sh_type == SHT_STRTAB && pElf32_Shdr->sh_addr == 0)
        {
          ptrNameSection =  (char *)pMapElf + pElf32_Shdr->sh_offset;
          break;
        }
      x++;
      pElf32_Shdr++;
    }
  pElf32_Shdr -= x;
  x = 0;

  while (x != pElf_Header->e_shnum)
  {
    if (!strcmp((char *)(ptrNameSection + pElf32_Shdr->sh_name), ".data"))    /* for the ropmaker */
      Addr_sData = pElf32_Shdr->sh_addr;
    if (!strcmp((char *)(ptrNameSection + pElf32_Shdr->sh_name), ".got"))     /* for the ropmaker */
      {
        Addr_sGot = pElf32_Shdr->sh_addr;
        importsc_mode.gotsize = pElf32_Shdr->sh_size;
      }
    if (!strcmp((char *)(ptrNameSection + pElf32_Shdr->sh_name), ".got.plt")) /* for the ropmaker */
      importsc_mode.gotpltsize = pElf32_Shdr->sh_size;
    x++;
    pElf32_Shdr++;
  }
  pElf32_Shdr -= x;
}

static void set_all_flag(void)
{
  flag_sectheader         = 0;
  flag_progheader         = 0;
  flag_elfheader          = 0;
  syntaxcode.flag_pysyn   = 1;  /* python syntax by default */
  syntaxcode.flag_csyn    = 0;
  syntaxcode.flag_phpsyn  = 0;
  syntaxcode.flag_perlsyn = 0;
  limitmode.flag          = 0;
  limitmode.value         = -1; /* default unlimited */
  opcode_mode.flag        = 0;
  stringmode.flag         = 0;
  bind_mode.flag          = 0;
}

static void check_all_flag(char **argv)
{
  check_allheader_mode(argv);
  check_elfheader_mode(argv);
  check_progheader_mode(argv);
  check_sectheader_mode(argv);
  check_bind_mode(argv);
  check_filtre_mode(argv);
  check_only_mode(argv);
  check_opcode_mode(argv);
  check_asm_mode(argv);
  check_importsc_mode(argv);
  check_syntax_mode(argv);
  check_limit_mode(argv);
  check_string_mode(argv);
}

void check_g_mode(char **argv)
{
  struct stat filestat;
  unsigned char *data;
  unsigned int size;
  int i = 0;

  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-g"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              pOption.gfile = argv[i + 1];
              if((stat(pOption.gfile, &filestat)) == -1)
                {
                  perror("stat");
                  exit(EXIT_FAILURE);
                }
              set_all_flag();
              size = filestat.st_size;
              data = save_bin_data(pOption.gfile, size);
              pElf_Header = (Elf32_Ehdr *)data;
              pElf32_Shdr = (Elf32_Shdr *)((char *)data + pElf_Header->e_shoff);
              pElf32_Phdr = (Elf32_Phdr *)((char *)data + pElf_Header->e_phoff);

              if (check_elf_format(data) == -1)
                no_elf_format();
              if (check_arch_supported() == -1)
                no_arch_supported();

              save_section_header();
              check_all_flag(argv);
              search_gadgets(data, size); /* let's go */
              free(data);
              exit(EXIT_SUCCESS);
            }
          else
            {
              fprintf(stderr, "Syntax: -g <binaire>\n");
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
