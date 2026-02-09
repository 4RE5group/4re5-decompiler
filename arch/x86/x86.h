#ifndef X86_H
#define X86_H

#include <stdint.h>
#include <stddef.h>

typedef struct x86_instruction
{
    uint8_t		PREFIXES[4];
    int			PREFIXES_COUNT;
    uint8_t		OPCODES[3];
    int			OPCODE_SIZE;
    int			HAS_MODRM;
    uint8_t		MODRM;
    int			HAS_SIB;
    uint8_t		SIB;
    int32_t		DISPLACEMENT;
    int			DISP_SIZE;
    uint32_t	IMMEDIATE;
    int			IMM_SIZE;
    size_t		INSTR_SIZE;
    const char	*MNEMONIC;
    char		OPERANDS[64];
}   x86_instruction;


/* functions */
void x86_disasm(char *bytes, size_t size);

#endif