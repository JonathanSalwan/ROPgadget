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

#ifndef	 ROPgadget_H
#define	 ROPgadget_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <wchar.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <wait.h>
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
  size_t      size;
} t_asm;

/* Linked list for phdr map with exec bit */
typedef struct s_maps_exec
{
  Elf32_Addr 		addr_start;
  Elf32_Addr 		addr_end;
  struct s_maps_exec 	*next;
} t_maps_exec;

/* Linked list for phdr map with read bit */
typedef struct s_maps_read
{
  Elf32_Addr 		addr_start;
  Elf32_Addr 		addr_end;
  struct s_maps_read 	*next;
} t_maps_read;

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

/* Liked list for variable opcode */
typedef struct s_varop
{
  char 			*instruction;
  Elf32_Addr            addr;
  struct s_varop 	*next;
} t_varop;

typedef struct  s_bind_mode
{
  char  port[8];
  int   flag;
} t_bind_mode;

typedef struct s_filter_mode
{
  char  *argument;
  int   flag;
} t_filter_mode;

typedef struct s_filter_linked
{
  char    *word;
  struct  s_filter_linked  *next;
} t_filter_linked;

typedef struct s_only_mode
{
  char  *argument;
  int   flag;
} t_only_mode;

typedef struct s_only_linked
{
  char    *word;
  struct  s_only_linked  *next;
} t_only_linked;

typedef struct s_opcode
{
  char *argument;
  unsigned char *opcode;
  int  size;
  int  flag;
} t_opcode;

typedef struct s_stringmode
{
  char *string;
  size_t size;
  int  flag;
} t_stringmode;

typedef struct s_asm_mode
{
  char *argument;
  unsigned char *opcode;
  int  size;
  int  flag;
} t_asm_mode;

typedef struct s_char_importsc
{
  unsigned char octet;
  Elf32_Addr addr;
  struct s_char_importsc *next;
  struct s_char_importsc *back;
} t_char_importsc;

typedef struct s_importsc
{
  char *argument;
  unsigned char *opcode;
  int  size;
  int  flag;
  int  gotsize;
  int  gotpltsize;
  t_char_importsc *poctet;
} t_importsc;

typedef struct s_option
{
  char *gfile;
  char *dfile;
} t_option;

typedef struct s_syntaxcode
{
  int flag_pysyn;
  int flag_csyn;
  int flag_phpsyn;
  int flag_perlsyn;
} t_syntaxcode;

typedef struct s_limitmode
{
  int flag;
  int value;
} t_limitmode;

/* globals vars */
Elf32_Ehdr          	*pElf_Header;
Elf32_Phdr          	*pElf32_Phdr;
Elf32_Shdr          	*pElf32_Shdr;
Elf32_Shdr          	*pElf32_HeaderSection;
Elf32_Shdr          	*pElf32_StringSection;
Elf32_Addr  		Addr_sData;
Elf32_Addr              Addr_sGot;

void                	*pMapElf;
t_asm               	*pGadgets;
t_filter_linked         *filter_linked;
t_only_linked           *only_linked;
unsigned int            NbGadFound;
unsigned int            NbTotalGadFound;
t_varop                 *pVarop;
int			flag_sectheader;
int			flag_progheader;
int			flag_elfheader;

/* flag options */
t_option                pOption;	/*  -g or -d 	   */
t_opcode                opcode_mode;	/*  -opcode 	   */
t_stringmode            stringmode;     /*  -string        */
t_asm_mode              asm_mode;	/*  -asm 	   */
t_importsc              importsc_mode;	/*  -importsc 	   */
t_bind_mode             bind_mode;	/*  -bind & -port  */
t_filter_mode           filter_mode;	/*  -filter 	   */
t_only_mode             only_mode;	/*  -only 	   */
t_limitmode             limitmode;      /*  -limit         */
t_syntaxcode            syntaxcode;     /*  -pysyn -csyn -phpsyn -perlsyn */

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
int 			check_exec_maps(t_maps_exec *, Elf32_Addr);
void                    free_add_maps_exec(t_maps_exec *);
void                    display_program_header(void);
void                    display_section_header(void);
void                    display_elf_header(void);
t_maps_exec   		*return_maps_exec(void);
t_maps_read   		*return_maps_read(void);
char                    *real_string_stringmode(char *, unsigned char *);
void                    print_real_string(char *str);
int 			check_read_maps(t_maps_read *, Elf32_Addr);
void                    free_add_maps_read(t_maps_read *);
void                    free_var_opcode(t_varop *element);
void                    check_g_mode(char **);
void                    check_d_mode(char **);
void                    check_v_mode(char **);
void                    check_filtre_mode(char **);
void                    check_opcode_mode(char **);
void                    check_string_mode(char **);
void                    check_asm_mode(char **);
void                    check_importsc_mode(char **);
void                    check_elfheader_mode(char **);
void                    check_progheader_mode(char **);
void                    check_sectheader_mode(char **);
void                    check_allheader_mode(char **);
void                    check_syntax_mode(char **);
void                    check_limit_mode(char **);
void                    how_many_found(void);
t_varop 		*add_element_varop(t_varop *, char *, Elf32_Addr);
void 			free_var_opcode(t_varop *);
int 			check_interrogation(char *);
int 			calc_pos_charany(char *, int);
char 			*ret_instruction_interrogation(Elf32_Addr, char *, char *, int);
char 			*ret_instruction_diese(Elf32_Addr, char *, char *, int);
int			check_if_varop_was_printed(char *);
int 			interrogation_or_diese(char *);
int 			no_filtered(char *);
void 			print_opcode(void);
void                    save_octet(unsigned char *, Elf32_Addr);
int 			search_opcode(const char *, const char *, size_t);
void 			check_only_mode(char **);
int 			onlymode(char *);
int                     size_opcode(char *);

/* ropmaker */
int 			check_gadget_if_exist(char *);
void                    ropmaker(void);
void      		combo_ropmaker1(void);
void      		combo_ropmaker2(void);
void                    combo_ropmaker_importsc(void);
char 			*get_gadget_since_addr(Elf32_Addr);
Elf32_Addr 		search_instruction(char *);
int                     match(const char *, const char *, size_t);
int                     match2(const char *, const char *, size_t);

/* makecode */
t_makecode              *add_element(t_makecode *, char *, Elf32_Addr);
void			makecode(t_makecode *);
void                    makecode_importsc(t_makecode *, int, char *);
void                    check_bind_mode(char **);

/* x86-32bits */
void 			gadget_x8632(unsigned char *, unsigned int, Elf32_Addr, int, t_maps_exec *);
void 			x8632(unsigned char *, unsigned int, t_maps_exec *, t_maps_read *);

/* xfunc */
void                    *xmalloc(size_t);
int                     xopen(const char *, int, mode_t);
void                    *xmmap(void *, size_t, int, int, int, off_t);
ssize_t                 xread(int, void *, size_t);
int                     xclose(int);

#endif

