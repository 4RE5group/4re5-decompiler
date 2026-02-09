#include "types/binary_types.h"

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

void	print_error(const char *message)
{
	printf("\033[31mERROR\033[0m: %s\n", message);
	exit(1);
}

int	main(int argc, char **argv)
{
	int		fd;

	if (argc != 2)
		print_error("Usage: 4re5-decompiler path/to/executable");
	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		print_error("Could not find or open file");

	if (detect_type(fd))
		print_error("Could not decompile given file");

	close(fd);
	return 0;
}