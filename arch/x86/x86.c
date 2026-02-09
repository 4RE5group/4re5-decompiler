#include "x86.h"

#include <stdbool.h>

//static inline void decode_modrm(unsigned char byte):
//    unsigned char mod = (byte >> 6) & 3;
//    unsigned char reg = (byte >> 3) & 7;
//    unsigned char rm  = byte & 7;
//    return mod, reg, rm

char	*get_mnemonic(unsigned char byte, bool two_byte)
{
	if (!two_byte)
	{
		/* Arithmetic & logic */
		if (byte <= 0x05) return "add";
		else if (byte >= 0x08 && byte <= 0x0D) return "or";
		else if (byte >= 0x10 && byte <= 0x15) return "adc";
		else if (byte >= 0x18 && byte <= 0x1D) return "sbb";
		else if (byte >= 0x20 && byte <= 0x25) return "and";
		else if (byte >= 0x28 && byte <= 0x2D) return "sub";
		else if (byte >= 0x30 && byte <= 0x35) return "xor";
		else if (byte >= 0x38 && byte <= 0x3D) return "cmp";

		/* INC / DEC */
		else if (byte >= 0x40 && byte <= 0x47) return "inc";
		else if (byte >= 0x48 && byte <= 0x4F) return "dec";

		/* PUSH / POP */
		else if (byte >= 0x50 && byte <= 0x57) return "push";
		else if (byte >= 0x58 && byte <= 0x5F) return "pop";

		/* MOV */
		else if (byte >= 0x88 && byte <= 0x8B) return "mov";
		else if (byte >= 0xB0 && byte <= 0xBF) return "mov";
		else if (byte == 0xC6 || byte == 0xC7) return "mov";

		/* XCHG */
		else if (byte == 0x86 || byte == 0x87) return "xchg";
		else if (byte >= 0x90 && byte <= 0x97) return "xchg";

		/* TEST */
		else if (byte == 0x84 || byte == 0x85) return "test";
		else if (byte == 0xA8 || byte == 0xA9) return "test";

		/* JMP / CALL / RET */
		else if (byte == 0xE8) return "call";
		else if (byte == 0xE9 || byte == 0xEB) return "jmp";
		else if (byte >= 0x70 && byte <= 0x7F) return "jcc";
		else if (byte == 0xC3 || byte == 0xC2) return "ret";

		/* INT */
		else if (byte == 0xCD) return "int";

		/* NOP */
		else if (byte == 0x90) return "nop";

		/* LEA */
		else if (byte == 0x8D) return "lea";

		/* PUSHF / POPF */
		else if (byte == 0x9C) return "pushf";
		else if (byte == 0x9D) return "popf";

		/* Unknown */
		else return "db";
	}
	else
	{
		if (byte >= 0x80 && byte <= 0x8F) return "jcc";
		else if (byte == 0xAF) return "imul";
		else if (byte == 0xBE) return "movsx";
		else if (byte == 0xB6) return "movzx";
		else if (byte == 0x1F) return "nop";
		else if (byte == 0x31) return "rdtsc";
		else if (byte == 0xA2) return "cpuid";
		else return "db";
	}
}


size_t	x86_decode(char	*bytes, size_t size, x86_instruction *instr)
{
	size_t	i = 0;

	// prefixes
	while (i < size && i < 4 && (bytes[i] == 0x66 || bytes[i] == 0x67 ||
		 bytes[i] == 0xF0 || bytes[i] == 0xF2 || bytes[i] == 0xF3))
	{
		instr->PREFIXES[i] = bytes[i];
		i++;
	}

	// opcodes
	instr->OPCODES[0] = bytes[i++];
	if (instr->OPCODES[0] == 0x0F)
	{
    	instr->OPCODES[1] = bytes[i++];
		instr->MNEMONIC = get_mnemonic(instr->OPCODES[1], 1);
	}
	else
		instr->MNEMONIC = get_mnemonic(instr->OPCODES[0], 0);
	
	return i;
}

void x86_disasm(char *bytes, size_t size)
{
    size_t i = 0;

    while (i < size)
    {
        x86_instruction ins = {0};

        size_t len = x86_decode(bytes + i, size - i, &ins);
        if (len == 0)
        {
            printf("db 0x%02x\n", (unsigned char)bytes[i]);
            i++;
            continue;
        }

        printf("%s %s\n", ins.MNEMONIC, ins.OPERANDS);
        i += len;
    }
}