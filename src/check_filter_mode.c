/*
** RopGadget - Release v3.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** http://shell-storm.org
** 2011-10-10
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

static t_filter_linked *add_element_filter(t_filter_linked *old_element, char *word)
{
  t_filter_linked *new_element;

  new_element = malloc(sizeof(t_filter_linked));
  if (new_element == NULL)
    exit(EXIT_FAILURE);
  new_element->word = word;
  new_element->next = old_element;

  return (new_element);
}

void check_filtre_mode(char **argv)
{
  int i = 0;

  filter_mode.flag = 0;
  filter_linked = NULL;
  while (argv[i] != NULL)
    {
      if (!strcmp(argv[i], "-filter"))
        {
          if (argv[i + 1] != NULL && argv[i + 1][0] != '\0')
            {
              filter_mode.argument = argv[i + 1];
              filter_mode.flag = 1;
              filter_linked = add_element_filter(filter_linked, filter_mode.argument);
            }
          else
            {
              fprintf(stderr, "Syntax: -filtre <word>\n\n");
              fprintf(stderr, "Ex: -filter \"dec %%edx\"\n");
              fprintf(stderr, "    -filter \"pop %%eax\" -filter \"dec\"\n");
              exit(EXIT_FAILURE);
            }
        }
      i++;
    }
}
