NAME		= 4re5-decompiler
CFILES		=	main.c \
				types/elf.c \
				types/type_detector.c \
				arch/x86/x86.c
OFILES		= $(CFILES:.c=.o)
DFILES		= $(CFILES:.c=.d)
CFLAGS		= -Wall -Wextra -Werror -g3 -MMD -MP

all: $(NAME)

$(NAME): $(OFILES)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -rf $(OFILES) $(DFILES)

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONY: all, clean, fclean, re
-include: $(DFILES)