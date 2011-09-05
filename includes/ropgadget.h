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

#ifndef	 ROPgadget_H
#define	 ROPgadget_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>

/* colors */
#define BLUE        "\033[94m"
#define GREEN       "\033[92m"
#define YELLOW      "\033[93m"
#define RED         "\033[91m"
#define ENDC        "\033[0m"

#define MAGIC_ELF         "\x7F\x45\x4C\x46"
#define TRUE              0
#define FALSE             1

/* gadgets series */
typedef struct s_asm
{
  int         flag;
  Elf32_Addr  addr;
  char        *instruction;
  char        *value;
} t_asm;

/* Linked list for phdr map with exec bit */
typedef struct s_maps_exec
{
  Elf32_Addr 		addr_start;
  Elf32_Addr 		addr_end;
  struct s_maps_exec 	*next;
} t_maps_exec;

/* Ropmaker */
typedef struct s_ropmaker
{
  char        *instruction;
} t_ropmaker;

/* Liked list for makecode */
typedef struct s_makecode
{
  char 			*instruction;
  Elf32_Addr		addr;
  struct s_makecode 	*next;
} t_makecode;

typedef struct  s_bind_mode
{
  char  port[8];
  int   flag;
} t_bind_mode;

Elf32_Ehdr          	*pElf_Header;
Elf32_Phdr          	*pElf32_Phdr;
Elf32_Shdr          	*pElf32_Shdr;
Elf32_Shdr          	*pElf32_HeaderSection;
Elf32_Shdr          	*pElf32_StringSection;
Elf32_Addr  		Addr_sData;
void                	*pMapElf;
t_asm               	*pGadgets;
t_bind_mode             bind_mode;

/* core */
char           		*get_flags(Elf32_Word);
char           		*get_seg(Elf32_Word);
void           		syntax(char *);
void           		display_version(void);
void           		display_data(unsigned char *, unsigned int);
void           		search_gadgets(unsigned char *, unsigned int);
unsigned char  		*save_bin_data(char *, unsigned int);
int            		check_elf_format(unsigned char *);
int            		check_arch_supported(void);
void           		no_elf_format(void);
void           		no_arch_supported(void);
void           		how_many_found();
int 			check_exec_maps(t_maps_exec *, Elf32_Addr);
void                    free_add_maps_exec(t_maps_exec *);
t_maps_exec   		*display_info_header(void);

/* ropmaker */
int 			check_gadget_if_exist(char *);
void                    ropmaker(void);
void      		combo_ropmaker1(void);
void      		combo_ropmaker2(void);
char 			*get_gadget_since_addr(Elf32_Addr);
Elf32_Addr 		search_instruction(char *);
int                     match(const char *, const char *, size_t);

/* makecode */
t_makecode              *add_element(t_makecode *, char *, Elf32_Addr);
void			makecode(t_makecode *);
void                    check_bind_mode(char **);

/* x86-32bits */
void 			gadget_x8632(unsigned char *, unsigned int, Elf32_Addr, int, t_maps_exec *);
void 			x8632(unsigned char *, unsigned int, t_maps_exec *);

#endif

