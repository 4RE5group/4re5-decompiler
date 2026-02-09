#ifndef BINARY_TYPES_H
#define BINARY_TYPES_H

#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/* cpu architectures */
#include "../arch/x86/x86.h"

int	detect_type(int fd);

#endif