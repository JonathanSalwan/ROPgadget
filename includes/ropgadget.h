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

#define ROPGADGET_VERSION "Ropgadget v4.0.2"

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

/* Simple macro for checking which syntax to display an asm in */
#define DISPLAY_SYNTAX(a) ((syntaxins==INTEL)?((a)->instruction_intel):((a)->instruction))

/* output control marcros */
/* user */
#define uprintf(...) fprintf(stderr, __VA_ARGS__)
/* output / payload */
#define oprintf(...) fprintf(stdout, __VA_ARGS__)
/* error */
#define eprintf(...) fprintf(stderr, __VA_ARGS__)
/* help */
#define hprintf(...) fprintf(stdout, __VA_ARGS__)

/* enum and struct typedefs */
#include "ropgadget_types.h"

/* global variables */
#include "ropgadget_globals.h"

/* function forward declarations */
#include "ropgadget_funcs.h"

#endif
