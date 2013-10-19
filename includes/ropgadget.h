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

#ifndef	 ROPgadget_H
#define	 ROPgadget_H

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <wchar.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <wait.h>
#include <fcntl.h>
#include <elf.h>
#include <stdio.h>

#define ROPGADGET_VERSION "Ropgadget v4.0.3"

/* colors */
#define _BLUE        "\033[94m"
#define _GREEN       "\033[92m"
#define _YELLOW      "\033[93m"
#define _RED         "\033[91m"
#define _ENDC        "\033[0m"

#define TRUE              1
#define FALSE             0

/* type definitions for easing transition */
typedef Elf64_Addr Address;
typedef Elf64_Off Offset;
typedef uint64_t Size;
#define ADDR_FORMAT "0x%.*"PRIx64
#define SIZE_FORMAT "%.*"PRIu64

#define ADDR_WIDTH ((binary->processor == PROCESSOR_X8632)?8:16)
#define SIZE_WIDTH ADDR_WIDTH

/* These are for the Reverse Polish Notation used to define shellcodes (CR = combo ropmaker) */
#define CR_AND "&"
#define CR_OR "|"
#define CR_OPT "?"

/* enum and struct typedefs */
#include "ropgadget_types.h"

/* global variables */
#include "ropgadget_globals.h"

/* function forward declarations */
#include "ropgadget_funcs.h"

/* globals vars */
t_binary                *binary;

/* flag options */
t_opcode                opcode_mode;	/*  -opcode 	                  */
t_stringmode            stringmode;     /*  -string                       */
t_stringmode            asm_mode;	/*  -asm 	                  */
t_opcode                importsc_mode;	/*  -importsc 	                  */
t_bind_mode             bind_mode;	/*  -bind & -port                 */
t_filter_mode           filter_mode;	/*  -filter 	                  */
t_filter_mode           only_mode;	/*  -only 	                  */
t_limitmode             limitmode;      /*  -limit                        */
t_mapmode               mapmode;        /*  -map                          */
e_syntaxcode            syntaxcode;     /*  -pysyn -csyn -phpsyn -perlsyn */
e_syntax                syntaxins;      /*  -intel -att                   */
char                    **target_argv;  /*  non-default target            */

/* color variables */
char                    *BLUE;
char                    *RED;
char                    *YELLOW;
char                    *GREEN;
char                    *ENDC;

/* core */
void           		syntax(char *);
void                    version(void);
void           		search_gadgets(t_binary *);

/* maps */
void                    map_parse(char *);

/* stringmode */
unsigned char           *real_string_stringmode(char *, unsigned char *);
void                    print_real_string(unsigned char *str);

/* filemode */
t_binary                *process_binary(char *);
void                    free_binary(t_binary *);
t_map                   *add_map(t_map *, Address, Address, Size);
t_depend                *add_dep(t_depend *, char *);
int                     process_elf(t_binary *);
int                     process_pe(t_binary *, int);

/* word mode */
t_word_linked           *add_element_word(t_word_linked *, char *);
int 			filter(char *, t_filter_mode *);

/* opcode/importsc */
void                    make_opcode(char *, t_opcode *op);
void 			print_opcode(void);

/* argv */
char                    **get_argv(void);
void                    free_argv(char **argv);

/* varop */
int 			check_interrogation(const char *);
char 			*ret_instruction(const unsigned char *, const char *, const char *, size_t);
int			check_if_varop_was_printed(const char *, const t_list_inst *pVarop);
char                    getreg(const char *, int i);
char                    *get_reg(const char *, int);
t_list_inst             *add_element(t_list_inst *, char *, t_asm *);
void 			free_list_inst(t_list_inst *);

/* ropmaker */
t_asm  	                *search_instruction(t_asm *, char *);
int                     match(const char *, const char *);
int                     match2(const unsigned char *, const unsigned char *, size_t);

/* pop info */
#define how_many_pop(g) how_many_pop_x(g, NULL, TOTAL)
#define how_many_pop_before(g, i) how_many_pop_x(g, i, BEFORE)
#define how_many_pop_after(g, i) how_many_pop_x(g, i, AFTER)
size_t how_many_pop_x(const char *gadget, const char *pop_reg, enum e_where w);



/* combo_ropmaker */
int                     combo_ropmaker(char **, t_asm *, t_gadget **);
void                    sc_print_pre_init(void);
void                    sc_print_init(void);
void                    sc_print_end(void);
void                    sc_print_comment(const char *);

void                    sc_print_sect_addr(int offset, int data, size_t bytes);

/* makecode: Mid-level payload generation */
void                    sc_print_sect_addr_pop(const t_gadget *, int, int, size_t);
void                    sc_print_number_pop(const t_gadget *, Size, const char *, size_t);
void                    sc_print_raw_pop(const t_gadget *, const char *, size_t, size_t);
void                    sc_print_str_pop(const t_gadget *, const char *, size_t);
void                    sc_print_solo_inst(const t_gadget *, size_t);

/* makecode: High-level payload generation */
void                    sc_print_raw_string(const char *, size_t, const t_rop_writer *, int, int, size_t);
void                    sc_print_string(const char *, const t_rop_writer *, int, int, size_t);
void                    sc_print_vector(const int *, const t_rop_writer *, int, int, size_t);
size_t                  sc_print_argv(const char * const *, const t_rop_writer *, int, int, size_t, int *, int *);

/* xfunc */
void                    *xmalloc(size_t);
int                     xopen(const char *, int, mode_t);
void                    *xmmap(void *, size_t, int, int, int, off_t);
ssize_t                 xread(int, void *, size_t);
ssize_t                 xwrite(int, const void *, size_t);
char                    *xstrdup(const char *);
int                     xclose(int);

/* common makecodes */
void                    x86_makecode_importsc(t_gadget *, size_t);
void                    x86_makecode(t_gadget *, size_t);
void                    x86_ropmaker(size_t);
void                    x86_build_code(char *, e_processor);

/* x86-32bits */
extern t_asm            tab_x8632[];
extern char             *tab_x8632_ropmaker[];
extern char             *tab_x8632_importsc[];

/* x86-64bits */
extern t_asm		tab_x8664[];
extern char             *tab_x8664_ropmaker[];
extern char             *tab_x8664_importsc[];

#endif
