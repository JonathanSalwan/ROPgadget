##
## RopGadget - Release v3.4.2
## Jonathan Salwan - http://twitter.com/JonathanSalwan
## http://shell-storm.org
## 2012-11-11
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##

DEBUG   = no
RM      = rm -f
INCLUDE = ./includes
SRC_DIR = ./src
NAME    = ROPgadget

ifeq ($(DEBUG),yes)
    CFLAGS   	= -g3 -ggdb -Wextra -Wall -D _BSD_SOURCE -I$(INCLUDE)
    CC 		= gcc
else
    CFLAGS    	= -W -Wall -Wextra -ansi -pedantic -D _BSD_SOURCE -I$(INCLUDE) -O2 -ggdb
    CC 		= gcc
endif

SRC     = 	$(SRC_DIR)/main.c \
          	$(SRC_DIR)/syntax.c \
          	$(SRC_DIR)/search_gadgets.c \
	  	$(SRC_DIR)/opcode.c \
          	$(SRC_DIR)/gadget.c \
		$(SRC_DIR)/save_octet.c \
	        $(SRC_DIR)/save_section.c \
          	$(SRC_DIR)/ropmaker.c \
		$(SRC_DIR)/maps.c \
		$(SRC_DIR)/real_string_stringmode.c \
	  	$(SRC_DIR)/varop.c \
	  	$(SRC_DIR)/filter.c \
		$(SRC_DIR)/parse_elf.c \
		$(SRC_DIR)/makecode.c \
	        $(SRC_DIR)/combo_ropmaker.c \
	        $(SRC_DIR)/target.c \
		$(SRC_DIR)/xfunc.c \
	  	$(SRC_DIR)/x8632/makecode.c \
          	$(SRC_DIR)/x8632/combo_ropmaker.c \
          	$(SRC_DIR)/x8632/gadgets.c \
	  	$(SRC_DIR)/x8632/asm.c \
	        $(SRC_DIR)/x8664/gadgets.c \
	        $(SRC_DIR)/x8664/combo_ropmaker.c \
	        $(SRC_DIR)/x8664/makecode.c

OBJ      = $(SRC:.c=.o)

all:     $(NAME)

$(NAME): $(OBJ)
	 $(CC) $(CFLAGS) -o $(NAME) $(OBJ)

install:
	 install -D -m 755 ./$(NAME) /usr/bin/$(NAME)

clean:
	 $(RM) $(OBJ) $(NAME) 

cleanall: clean
	$(RM) $(SRC_DIR)/x8664/gadgets.c

fclean:  clean
	 $(RM) $(NAME)

re:	 fclean all

.PHONY:  re fclean clean install all

$(SRC_DIR)/x8664/gadgets.c: script/makex64gadgets.py
	$< > $@
