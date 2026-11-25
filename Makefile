NAME		= 4re5-decompiler-gui

CORE_CFILES	= types/elf.c types/type_detector.c arch/x86/x86.c
GUI_CFILES	= gui/app.c gui/model.c
CFILES		= $(CORE_CFILES) $(GUI_CFILES)
OFILES		= $(CFILES:.c=.o)
DFILES		= $(CFILES:.c=.d)
CFLAGS		= -Wall -Wextra -Werror -g3 -MMD -MP
GTK_CFLAGS	= $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS	= $(shell pkg-config --libs gtk+-3.0)

all: $(NAME)

$(NAME): $(OFILES)
	$(CC) $(CFLAGS) $(GTK_CFLAGS) $^ $(GTK_LIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(if $(findstring gui/,$<),$(GTK_CFLAGS),) -c $< -o $@

clean:
	rm -rf $(OFILES) $(DFILES)

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONY: all clean fclean re
-include $(DFILES)
