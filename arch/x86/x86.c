#include "x86.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static inline modrm_t parse_modrm(uint8_t byte)
{
	modrm_t m;
	m.mod = (byte >> 6) & 0x3;
	m.reg = (byte >> 3) & 0x7;
	m.rm  = byte & 0x7;
	return m;
}

static const char *grp1[8] = {
	"add","or","adc","sbb","and","sub","xor","cmp"
};

static const char *grp2[8] = {
	"rol","ror","rcl","rcr","shl","shr",NULL,"sar"
};

static const char *grp3[8] = {
	"test",NULL,"not","neg","mul","imul","div","idiv"
};

static const char *grp5[8] = {
	"inc","dec","call","callf","jmp","jmpf","push",NULL
};


static const char *reg8[8]  = {"al","cl","dl","bl","ah","ch","dh","bh"};
static const char *reg16[8] = {"ax","cx","dx","bx","sp","bp","si","di"};
static const char *reg32[8] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"};


static opcode_desc opcode_table[] = {
	/* --- ADD --- */
	{0x0000, OP_SIMPLE, true,  "add", {NULL}},
	{0x0001, OP_SIMPLE, true,  "add", {NULL}},
	{0x0002, OP_SIMPLE, true,  "add", {NULL}},
	{0x0003, OP_SIMPLE, true,  "add", {NULL}},
	{0x0004, OP_SIMPLE, false, "add", {NULL}},
	{0x0005, OP_SIMPLE, false, "add", {NULL}},

	/* --- OR --- */
	{0x0008, OP_SIMPLE, true,  "or", {NULL}},
	{0x0009, OP_SIMPLE, true,  "or", {NULL}},
	{0x000A, OP_SIMPLE, true,  "or", {NULL}},
	{0x000B, OP_SIMPLE, true,  "or", {NULL}},
	{0x000C, OP_SIMPLE, false, "or", {NULL}},
	{0x000D, OP_SIMPLE, false, "or", {NULL}},

	/* --- ADC --- */
	{0x0010, OP_SIMPLE, true, "adc", {NULL}},
	{0x0011, OP_SIMPLE, true, "adc", {NULL}},
	{0x0012, OP_SIMPLE, true, "adc", {NULL}},
	{0x0013, OP_SIMPLE, true, "adc", {NULL}},
	{0x0014, OP_SIMPLE, true, "adc", {NULL}},
	{0x0015, OP_SIMPLE, true, "adc", {NULL}},

	/* --- SBB --- */
	{0x0018, OP_SIMPLE, true, "sbb", {NULL}},
	{0x0019, OP_SIMPLE, true, "sbb", {NULL}},
	{0x001A, OP_SIMPLE, true, "sbb", {NULL}},
	{0x001B, OP_SIMPLE, true, "sbb", {NULL}},
	{0x001C, OP_SIMPLE, true, "sbb", {NULL}},
	{0x001D, OP_SIMPLE, true, "sbb", {NULL}},

	/* --- AND --- */
	{0x0020, OP_SIMPLE, true, "and", {NULL}},
	{0x0021, OP_SIMPLE, true, "and", {NULL}},
	{0x0022, OP_SIMPLE, true, "and", {NULL}},
	{0x0023, OP_SIMPLE, true, "and", {NULL}},
	{0x0024, OP_SIMPLE, true, "and", {NULL}},
	{0x0025, OP_SIMPLE, true, "and", {NULL}},

	/* --- SUB --- */
	{0x0028, OP_SIMPLE, true, "sub", {NULL}},
	{0x0029, OP_SIMPLE, true, "sub", {NULL}},
	{0x002A, OP_SIMPLE, true, "sub", {NULL}},
	{0x002B, OP_SIMPLE, true, "sub", {NULL}},
	{0x002C, OP_SIMPLE, true, "sub", {NULL}},
	{0x002D, OP_SIMPLE, true, "sub", {NULL}},

	/* --- XOR --- */
	{0x0030, OP_SIMPLE, true, "xor", {NULL}},
	{0x0031, OP_SIMPLE, true, "xor", {NULL}},
	{0x0032, OP_SIMPLE, true, "xor", {NULL}},
	{0x0033, OP_SIMPLE, true, "xor", {NULL}},
	{0x0034, OP_SIMPLE, true, "xor", {NULL}},
	{0x0035, OP_SIMPLE, true, "xor", {NULL}},

	/* --- CMP --- */
	{0x0038, OP_SIMPLE, true, "cmp", {NULL}},
	{0x0039, OP_SIMPLE, true, "cmp", {NULL}},
	{0x003A, OP_SIMPLE, true, "cmp", {NULL}},
	{0x003B, OP_SIMPLE, true, "cmp", {NULL}},
	{0x003C, OP_SIMPLE, true, "cmp", {NULL}},
	{0x003D, OP_SIMPLE, true, "cmp", {NULL}},

	/* --- INC --- */
	{0x0040, OP_SIMPLE, false, "inc", {NULL}},
	{0x0041, OP_SIMPLE, false, "inc", {NULL}},
	{0x0042, OP_SIMPLE, false, "inc", {NULL}},
	{0x0043, OP_SIMPLE, false, "inc", {NULL}},
	{0x0044, OP_SIMPLE, false, "inc", {NULL}},
	{0x0045, OP_SIMPLE, false, "inc", {NULL}},
	{0x0046, OP_SIMPLE, false, "inc", {NULL}},
	{0x0047, OP_SIMPLE, false, "inc", {NULL}},

	/* --- DEC --- */
	{0x0048, OP_SIMPLE, false, "dec", {NULL}},
	{0x0049, OP_SIMPLE, false, "dec", {NULL}},
	{0x004A, OP_SIMPLE, false, "dec", {NULL}},
	{0x004B, OP_SIMPLE, false, "dec", {NULL}},
	{0x004C, OP_SIMPLE, false, "dec", {NULL}},
	{0x004D, OP_SIMPLE, false, "dec", {NULL}},
	{0x004E, OP_SIMPLE, false, "dec", {NULL}},
	{0x004F, OP_SIMPLE, false, "dec", {NULL}},

	/* --- PUSH / POP --- */
	{0x0050, OP_SIMPLE, false, "push", {NULL}},
	{0x0058, OP_SIMPLE, false, "pop", {NULL}},

	/* --- MOV --- */
	{0x0088, OP_SIMPLE, true,  "mov", {NULL}},
	{0x0089, OP_SIMPLE, true,  "mov", {NULL}},
	{0x008A, OP_SIMPLE, true,  "mov", {NULL}},
	{0x008B, OP_SIMPLE, true,  "mov", {NULL}},

	/* --- System IO --- */
	{0x00CD, OP_SIMPLE, false, "int", {NULL}},

	/* mov r32, imm32 */
	{0x00B0, OP_SIMPLE, false, "mov", {NULL}},
	{0x00B1, OP_SIMPLE, false, "mov", {NULL}},
	{0x00B2, OP_SIMPLE, false, "mov", {NULL}},
	{0x00B3, OP_SIMPLE, false, "mov", {NULL}},
	{0x00B4, OP_SIMPLE, false, "mov", {NULL}},
	{0x00B5, OP_SIMPLE, false, "mov", {NULL}},
	{0x00B6, OP_SIMPLE, false, "mov", {NULL}},
	{0x00B7, OP_SIMPLE, false, "mov", {NULL}},
	{0x00B8, OP_SIMPLE, false, "mov", {NULL}},
	{0x00B9, OP_SIMPLE, false, "mov", {NULL}},
	{0x00BA, OP_SIMPLE, false, "mov", {NULL}},
	{0x00BB, OP_SIMPLE, false, "mov", {NULL}},
	{0x00BC, OP_SIMPLE, false, "mov", {NULL}},
	{0x00BD, OP_SIMPLE, false, "mov", {NULL}},
	{0x00BE, OP_SIMPLE, false, "mov", {NULL}},
	{0x00BF, OP_SIMPLE, false, "mov", {NULL}},

	/* --- TEST --- */
	{0x0084, OP_SIMPLE, true,  "test", {NULL}},
	{0x0085, OP_SIMPLE, true,  "test", {NULL}},
	{0x00A8, OP_SIMPLE, false, "test", {NULL}},
	{0x00A9, OP_SIMPLE, false, "test", {NULL}},

	/* --- XCHG --- */
	{0x0086, OP_SIMPLE, true,  "xchg", {NULL}},
	{0x0087, OP_SIMPLE, true,  "xchg", {NULL}},
	{0x0090, OP_SIMPLE, false, "nop", {NULL}},

	/* --- CONTROL FLOW --- */
	{0x00E8, OP_SIMPLE, false, "call", {NULL}},
	{0x00E9, OP_SIMPLE, false, "jmp", {NULL}},
	{0x00EB, OP_SIMPLE, false, "jmp", {NULL}},
	{0x00C2, OP_SIMPLE, false, "ret", {NULL}},
	{0x00C3, OP_SIMPLE, false, "ret", {NULL}},

	/* --- CONDITIONAL JUMPS (short) --- */
	{0x0070, OP_SIMPLE, false, "jo", {NULL}},
	{0x0071, OP_SIMPLE, false, "jno", {NULL}},
	{0x0072, OP_SIMPLE, false, "jb", {NULL}},
	{0x0073, OP_SIMPLE, false, "jnb", {NULL}},
	{0x0074, OP_SIMPLE, false, "je", {NULL}},
	{0x0075, OP_SIMPLE, false, "jne", {NULL}},
	{0x0076, OP_SIMPLE, false, "jbe", {NULL}},
	{0x0077, OP_SIMPLE, false, "ja", {NULL}},
	{0x0078, OP_SIMPLE, false, "js", {NULL}},
	{0x0079, OP_SIMPLE, false, "jns", {NULL}},
	{0x007A, OP_SIMPLE, false, "jp", {NULL}},
	{0x007B, OP_SIMPLE, false, "jnp", {NULL}},
	{0x007C, OP_SIMPLE, false, "jl", {NULL}},
	{0x007D, OP_SIMPLE, false, "jge", {NULL}},
	{0x007E, OP_SIMPLE, false, "jle", {NULL}},
	{0x007F, OP_SIMPLE, false, "jg", {NULL}},

	/* --- GROUPS --- */
	{0x0080, OP_GROUP, true, NULL, {(const char *)grp1}},
	{0x0081, OP_GROUP, true, NULL, {(const char *)grp1}},
	{0x0083, OP_GROUP, true, NULL, {(const char *)grp1}},
	{0x00D0, OP_GROUP, true, NULL, {(const char *)grp2}},
	{0x00D1, OP_GROUP, true, NULL, {(const char *)grp2}},
	{0x00F6, OP_GROUP, true, NULL, {(const char *)grp3}},
	{0x00F7, OP_GROUP, true, NULL, {(const char *)grp3}},
	{0x00FF, OP_GROUP, true, NULL, {(const char *)grp5}},

	/* --- TWO BYTE (0F) --- */
	{0x0FAF, OP_SIMPLE, true, "imul", {NULL}},
	{0x0FB6, OP_SIMPLE, true, "movzx", {NULL}},
	{0x0FB7, OP_SIMPLE, true, "movzx", {NULL}},
	{0x0FBE, OP_SIMPLE, true, "movsx", {NULL}},
	{0x0FBF, OP_SIMPLE, true, "movsx", {NULL}},

	/* --- SENTINEL --- */
	{0, OP_NONE, false, NULL, {NULL}}
};


static size_t read_imm(uint8_t *b, size_t size, uint32_t *out, int bytes)
{
	if (size < (size_t)bytes)
		return 0;
	*out = 0;
	for (int i = 0; i < bytes; i++)
		*out |= b[i] << (i * 8);
	return bytes;
}


static size_t format_rm32(
	char *out,
	uint8_t *bytes,
	size_t size,
	modrm_t m
)
{
	size_t i = 0;

	if (m.mod == 3)
	{
		sprintf(out, "%s", reg32[m.rm]);
		return 0;
	}

	/* memory */
	if (m.mod == 0 && m.rm == 5)
	{
		uint32_t disp;
		i += read_imm(bytes, size, &disp, 4);
		sprintf(out, "[0x%x]", disp);
		return i;
	}

	sprintf(out, "[%s", reg32[m.rm]);

	if (m.mod == 1)
	{
		int8_t d = bytes[i++];
		sprintf(out + strlen(out), "%+d]", d);
	}
	else if (m.mod == 2)
	{
		uint32_t d;
		i += read_imm(bytes + i, size - i, &d, 4);
		sprintf(out + strlen(out), "+0x%x]", d);
	}
	else
		strcat(out, "]");

	return i;
}

/* --- NEW HELPERS --- */

static size_t format_rm8(char *out, uint8_t *bytes, size_t size, modrm_t m)
{
	size_t i = 0;

	if (m.mod == 3)
	{
		sprintf(out, "%s", reg8[m.rm]);
		return 0;
	}

	if (m.mod == 0 && m.rm == 5)
	{
		uint32_t disp;
		i += read_imm(bytes, size, &disp, 4);
		sprintf(out, "[0x%x]", disp);
		return i;
	}

	sprintf(out, "[%s", reg32[m.rm]);

	if (m.mod == 1)
	{
		int8_t d = bytes[i++];
		sprintf(out + strlen(out), "%+d]", d);
	}
	else if (m.mod == 2)
	{
		uint32_t d;
		i += read_imm(bytes + i, size - i, &d, 4);
		sprintf(out + strlen(out), "+0x%x]", d);
	}
	else
		strcat(out, "]");

	return i;
}

static size_t format_rm16(char *out, uint8_t *bytes, size_t size, modrm_t m)
{
	size_t i = 0;

	if (m.mod == 3)
	{
		sprintf(out, "%s", reg16[m.rm]);
		return 0;
	}

	if (m.mod == 0 && m.rm == 6)
	{
		uint32_t disp;
		i += read_imm(bytes, size, &disp, 2);
		sprintf(out, "[0x%x]", disp);
		return i;
	}

	sprintf(out, "[%s", reg16[m.rm]);

	if (m.mod == 1)
	{
		int8_t d = bytes[i++];
		sprintf(out + strlen(out), "%+d]", d);
	}
	else if (m.mod == 2)
	{
		uint32_t d;
		i += read_imm(bytes + i, size - i, &d, 2);
		sprintf(out + strlen(out), "+0x%x]", d);
	}
	else
		strcat(out, "]");

	return i;
}



static opcode_desc *find_opcode(uint16_t opcode)
{
	for (int i = 0; opcode_table[i].kind != OP_NONE; i++)
	{
		if (opcode_table[i].opcode == opcode)
			return &opcode_table[i];
	}
	return NULL;
}

const char	*get_mnemonic(uint16_t opcode, uint8_t modrm_byte)
{
	opcode_desc	*desc;

	desc = find_opcode(opcode);
	if (!desc)
		return "db";

	if (desc->kind == OP_SIMPLE)
		return desc->mnemonic;
	else if (desc->kind == OP_GROUP)
	{
		modrm_t m = parse_modrm(modrm_byte);
		const char *mn = desc->group[m.reg];
		return mn?mn:"db";
	}

	return "db";
}

static size_t format_operands(
	x86_instruction *ins,
	uint8_t *bytes,
	size_t size,
	uint8_t opcode,
	uint8_t modrm_byte,
	int has_modrm
)
{
	size_t i = 0;
	char op1[64] = {0};
	char op2[64] = {0};

	int is_16 = 0;
	for (int p = 0; p < ins->PREFIXES_COUNT; p++)
		if (ins->PREFIXES[p] == 0x66)
			is_16 = 1;

	if (has_modrm)
	{
		modrm_t m = parse_modrm(modrm_byte);

		/* 8-bit */
		if (opcode == 0x00 || opcode == 0x02 || opcode == 0x88 || opcode == 0x8A)
		{
			if (opcode == 0x00 || opcode == 0x88)
			{
				i += format_rm8(op1, bytes + i, size - i, m);
				sprintf(op2, "%s", reg8[m.reg]);
			}
			else
			{
				sprintf(op1, "%s", reg8[m.reg]);
				i += format_rm8(op2, bytes + i, size - i, m);
			}
		}
		/* 16-bit */
		else if (is_16)
		{
			if (opcode == 0x01 || opcode == 0x29 || opcode == 0x89)
			{
				i += format_rm16(op1, bytes + i, size - i, m);
				sprintf(op2, "%s", reg16[m.reg]);
			}
			else if (opcode == 0x03 || opcode == 0x2B || opcode == 0x8B)
			{
				sprintf(op1, "%s", reg16[m.reg]);
				i += format_rm16(op2, bytes + i, size - i, m);
			}
		}
		else
		{
			/* r/m32, r32 */
			if (opcode == 0x01 || opcode == 0x29 || opcode == 0x89)
			{
				i += format_rm32(op1, bytes + i, size - i, m);
				sprintf(op2, "%s", reg32[m.reg]);
			}
			/* r32, r/m32 */
			else if (opcode == 0x03 || opcode == 0x2B || opcode == 0x8B)
			{
				sprintf(op1, "%s", reg32[m.reg]);
				i += format_rm32(op2, bytes + i, size - i, m);
			}
			/* GROUP */
			else
			{
				i += format_rm32(op1, bytes + i, size - i, m);

				if (opcode == 0x80 || opcode == 0x83)
				{
					uint32_t imm;
					i += read_imm(bytes + i, size - i, &imm, 1);
					sprintf(op2, "0x%x", imm);
				}
				else if (opcode == 0x81)
				{
					uint32_t imm;
					i += read_imm(bytes + i, size - i, &imm, 4);
					sprintf(op2, "0x%x", imm);
				}
			}
		}
	}
	else
	{
		/* mov r8, imm8 */
		if ((opcode & 0xF8) == 0xB0)
		{
			uint32_t imm;
			i += read_imm(bytes + i, size - i, &imm, 1);
			sprintf(op1, "%s", reg8[opcode & 7]);
			sprintf(op2, "0x%x", imm);
		}
		/* mov r16, imm16 */
		else if (is_16 && (opcode & 0xF8) == 0xB8)
		{
			uint32_t imm;
			i += read_imm(bytes + i, size - i, &imm, 2);
			sprintf(op1, "%s", reg16[opcode & 7]);
			sprintf(op2, "0x%x", imm);
		}
		/* mov reg, imm32 */
		if ((opcode & 0xF8) == 0xB8)
		{
			uint32_t imm;
			i += read_imm(bytes + i, size - i, &imm, 4);
			sprintf(op1, "%s", reg32[opcode & 7]);
			sprintf(op2, "0x%x", imm);
		}
		/* int imm32 */
		else if (opcode == 0xCD)
		{
			uint32_t imm;
			i += read_imm(bytes + i, size - i, &imm, 1);
			sprintf(op1, "0x%x", imm);
		}
		/* call / jmp rel32 */
		else if (opcode == 0xE8 || opcode == 0xE9)
		{
			int32_t rel;
			i += read_imm(bytes + i, size - i, (uint32_t *)&rel, 4);
			sprintf(op1, "0x%x", rel);
		}
	}

	if (op1[0] && op2[0])
		sprintf(ins->OPERANDS, "%s, %s", op1, op2);
	else if (op1[0])
		sprintf(ins->OPERANDS, "%s", op1);
	else
		ins->OPERANDS[0] = 0;

	return i;
}


size_t x86_decode(uint8_t *bytes, size_t size, x86_instruction *instr)
{
	size_t i = 0;

	/* prefixes */
	while (i < size && i < 4 &&
	      (bytes[i] == 0x66 || bytes[i] == 0x67 ||
	       bytes[i] == 0xF0 || bytes[i] == 0xF2 ||
	       bytes[i] == 0xF3))
	{
		instr->PREFIXES[instr->PREFIXES_COUNT++] = bytes[i++];
	}

	/* opcode */
	uint16_t opcode = bytes[i++];
	instr->OPCODES[0] = opcode;

	if (opcode == 0x0F)
	{
		uint8_t second = bytes[i++];
		instr->OPCODES[1] = second;
		opcode = (0x0F << 8) | second;
	}

	opcode_desc *desc = find_opcode(opcode);
	if (!desc)
	{
		instr->MNEMONIC = "db";
		return 1;
	}

	uint8_t modrm = 0;
	if (desc->has_modrm)
	{
		modrm = bytes[i++];
		instr->MODRM = modrm;
	}

	instr->MNEMONIC = get_mnemonic(opcode, modrm);
	i += format_operands(
		instr,
		bytes + i,
		size - i,
		opcode,
		modrm,
		desc->has_modrm
	);
	return i;
}


void x86_disasm(uint8_t *bytes, size_t size)
{
    size_t i = 0;

    while (i < size)
    {
		size_t	start_i = i;
        x86_instruction ins = {0};

        size_t len = x86_decode(bytes + i, size - i, &ins);
        if (len == 0)
        {
            printf("db 0x%02x\n", (unsigned char)bytes[i]);
            i++;
            continue;
        }
		
        i += len;
		int j = i - start_i;
		while (j > 0)
		{
			printf("%.2x ", bytes[i - j]);
			j--;
		}
		j = 10 - (i - start_i);
		while (j-- > 0)
			printf("   ");
		printf("    ");
		printf("%s %s\n", ins.MNEMONIC, ins.OPERANDS);
    }
}