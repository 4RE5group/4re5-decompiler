#ifndef X86_H
#define X86_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
	uint8_t mod;
	uint8_t reg;
	uint8_t rm;
}   modrm_t;

typedef enum {
	OP_NONE,
	OP_SIMPLE,
	OP_GROUP
}   opcode_kind;

typedef struct {
	uint16_t opcode;
	opcode_kind kind;
	bool has_modrm;
	const char *mnemonic;
	const char *group[8];
}   opcode_desc;


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
void x86_disasm(uint8_t *bytes, size_t size);

#endif