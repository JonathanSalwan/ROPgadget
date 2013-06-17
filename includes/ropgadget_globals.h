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

#ifndef	 ROPgadget_globals_H
#define	 ROPgadget_globals_H

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

#endif
