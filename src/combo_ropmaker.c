/*
** RopGadget - Release v3.4.2
** Jonathan Salwan - http://twitter.com/JonathanSalwan
** Allan Wirth - http://allanwirth.com/
** http://shell-storm.org
** 2012-11-11
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

typedef struct s_stack {
  struct s_stack *next;
  int val;
} t_stack;

static void push_stack(int v, t_stack **stack) {
  t_stack *n = xmalloc(sizeof(t_stack));
  n->next = *stack;
  n->val = v;
  *stack = n;
}

static int pop_stack(t_stack **stack) {
  t_stack *n;
  int t;

  if (*stack == NULL) return -1;

  n = *stack;
  t = n->val;
  *stack = n->next;
  free(n);
  return t;
}

static void free_stack(t_stack **stack) {
  while (pop_stack(stack) != -1) ;
}


int combo_ropmaker(char **ropsh, t_asm *table, t_list_inst **list_ins)
{
  int i;
  t_asm *res = NULL;
  t_stack *stack = NULL;

  *list_ins = NULL;

  /* check if combo n is possible */
  for (i = 0; ropsh[i]; i++) {
    if (!strcmp(ropsh[i], CR_AND)) {
      push_stack(pop_stack(&stack) && pop_stack(&stack), &stack);
    } else if (!strcmp(ropsh[i], CR_OR)) {
      push_stack(pop_stack(&stack) || pop_stack(&stack), &stack);
    } else {
      res = search_instruction(table, ropsh[i]);
      push_stack(!!res, &stack);
      if (res) {
        fprintf(stdout, "\t- %s" ADDR_FORMAT "%s => %s%s%s\n", GREEN, ADDR_WIDTH, res->addr,
            ENDC, GREEN, DISPLAY_SYNTAX(res), ENDC);
        *list_ins = add_element(*list_ins, res->instruction, res);
      } else {
        fprintf(stdout, "\t- %s..........%s => %s%s%s\n", RED, ENDC, RED, ropsh[i], ENDC);
      }
    }
  }

  fprintf(stdout, "\t- %s" ADDR_FORMAT "%s => %s.data Addr%s\n", GREEN, ADDR_WIDTH, (Address)Addr_sData, ENDC, GREEN, ENDC);

  i = pop_stack(&stack);

  if (i == 1) {
    fprintf(stdout, "[%s+%s] Combo was found!\n", GREEN, ENDC);
  } else {
    fprintf(stderr, "[%s-%s] Combo was not found.\n", RED, ENDC);
  }

  free_stack(&stack);
  return (i == 1);
}
