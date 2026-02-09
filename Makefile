NAME		= 4re5-decompiler
CFILES		=	main.c \
				types/elf.c \
				types/type_detector.c \
				arch/x86/x86.c
OFILES		= $(CFILES:.c=.o)
#CFLAGS		= -Wall -Wextra -Werror -g3

all: $(NAME)

$(NAME): $(OFILES)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

clean:
	rm -rf $(OFILES)

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONY: all, clean, fclean, re