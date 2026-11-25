#include "binary_types.h"

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>

static uint16_t read16(const unsigned char *p, int swap) {
  uint16_t value = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
  return swap ? (uint16_t)((value >> 8) | (value << 8)) : value;
}

static uint32_t read32(const unsigned char *p, int swap) {
  uint32_t value = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                   ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
  if (!swap)
    return value;
  return ((value & 0xff) << 24) | ((value & 0xff00) << 8) |
         ((value >> 8) & 0xff00) | ((value >> 24) & 0xff);
}

static uint64_t read64(const unsigned char *p, int swap) {
  uint64_t value = 0;
  for (int i = 0; i < 8; i++)
    value |= (uint64_t)p[i] << (i * 8);
  if (!swap)
    return value;
  uint64_t result = 0;
  for (int i = 0; i < 8; i++)
    result |= ((value >> (i * 8)) & 0xff) << ((7 - i) * 8);
  return result;
}

static const char *section_flags(uint64_t flags) {
  static char result[8];
  int i = 0;
  if (flags & SHF_WRITE)
    result[i++] = 'W';
  if (flags & SHF_ALLOC)
    result[i++] = 'A';
  if (flags & SHF_EXECINSTR)
    result[i++] = 'X';
  result[i] = 0;
  return result;
}

static int valid_range(size_t file_size, uint64_t offset, uint64_t size) {
  return offset <= file_size && size <= file_size - offset;
}

int detect_type(int fd) {
  struct stat info;
  if (fstat(fd, &info) < 0 || info.st_size < EI_NIDENT)
    return 1;
  size_t file_size = (size_t)info.st_size;
  unsigned char *file = malloc(file_size);
  if (!file)
    return 1;
  if (pread(fd, file, file_size, 0) != (ssize_t)file_size) {
    free(file);
    return 1;
  }
  if (memcmp(file, ELFMAG, SELFMAG) != 0) {
    free(file);
    return 1;
  }
  int is64 = file[EI_CLASS] == ELFCLASS64;
  int swap = file[EI_DATA] == ELFDATA2MSB;
  if ((!is64 && file[EI_CLASS] != ELFCLASS32) || file[EI_DATA] == ELFDATANONE) {
    free(file);
    return 1;
  }
  uint64_t section_offset, section_size, section_count, string_index,
      entry_size, entry;
  uint64_t entry_point;
  if (is64) {
    if (file_size < sizeof(Elf64_Ehdr)) {
      free(file);
      return 1;
    }
    Elf64_Ehdr *header = (Elf64_Ehdr *)file;
    section_offset = read64((unsigned char *)&header->e_shoff, swap);
    section_size = read16((unsigned char *)&header->e_shentsize, swap);
    section_count = read16((unsigned char *)&header->e_shnum, swap);
    string_index = read16((unsigned char *)&header->e_shstrndx, swap);
    entry_size = read16((unsigned char *)&header->e_ehsize, swap);
    entry_point = read64((unsigned char *)&header->e_entry, swap);
    entry = read16((unsigned char *)&header->e_machine, swap);
  } else {
    if (file_size < sizeof(Elf32_Ehdr)) {
      free(file);
      return 1;
    }
    Elf32_Ehdr *header = (Elf32_Ehdr *)file;
    section_offset = read32((unsigned char *)&header->e_shoff, swap);
    section_size = read16((unsigned char *)&header->e_shentsize, swap);
    section_count = read16((unsigned char *)&header->e_shnum, swap);
    string_index = read16((unsigned char *)&header->e_shstrndx, swap);
    entry_size = read16((unsigned char *)&header->e_ehsize, swap);
    entry_point = read32((unsigned char *)&header->e_entry, swap);
    entry = read16((unsigned char *)&header->e_machine, swap);
  }
  if (entry != EM_386 && entry != EM_X86_64) {
    free(file);
    return 1;
  }
  if (!section_size || !section_count ||
      !valid_range(file_size, section_offset, section_size * section_count) ||
      string_index >= section_count) {
    free(file);
    return 1;
  }
  uint64_t names_offset, names_size;
  if (is64) {
    unsigned char *sh = file + section_offset + string_index * section_size;
    names_offset = read64(sh + 24, swap);
    names_size = read64(sh + 32, swap);
  } else {
    unsigned char *sh = file + section_offset + string_index * section_size;
    names_offset = read32(sh + 16, swap);
    names_size = read32(sh + 20, swap);
  }
  if (!valid_range(file_size, names_offset, names_size)) {
    free(file);
    return 1;
  }
  const char *names = (const char *)(file + names_offset);
  printf("ELF|%s|%s|%llx|%llx|%llx\n", is64 ? "64" : "32", swap ? "MSB" : "LSB",
         (unsigned long long)entry_point, (unsigned long long)entry,
         (unsigned long long)entry_size);
  printf("ELF_HEADER|Class|ELF%s\n", is64 ? "64" : "32");
  printf("ELF_HEADER|Data|%s endian\n", swap ? "Big" : "Little");
  printf("ELF_HEADER|Machine|%s (0x%llx)\n", is64 ? "x86-64" : "i386",
         (unsigned long long)entry);
  printf("ELF_HEADER|Entry point|0x%llx\n", (unsigned long long)entry_point);
  printf("ELF_HEADER|Section table|offset 0x%llx, %llu entries\n",
         (unsigned long long)section_offset, (unsigned long long)section_count);
  for (uint64_t i = 0; i < section_count; i++) {
    unsigned char *sh = file + section_offset + i * section_size;
    uint64_t name_index = read32(sh, swap), address, offset, size, flags;
    if (is64) {
      flags = read64(sh + 8, swap);
      address = read64(sh + 16, swap);
      offset = read64(sh + 24, swap);
      size = read64(sh + 32, swap);
    } else {
      flags = read32(sh + 8, swap);
      address = read32(sh + 12, swap);
      offset = read32(sh + 16, swap);
      size = read32(sh + 20, swap);
    }
    const char *name =
        name_index < names_size ? names + name_index : "<invalid>";
    printf("SECTION|%s|%llx|%llx|%llx|%s\n", name, (unsigned long long)address,
           (unsigned long long)offset, (unsigned long long)size,
           section_flags(flags));
    if ((flags & SHF_EXECINSTR) && size && valid_range(file_size, offset, size))
      x86_disasm(file + offset, size, address, is64);
  }
  /* Export symbols as structured records for the GUI and future analysis
   * passes. Both normal and dynamic symbol tables are handled here. */
  for (uint64_t i = 0; i < section_count; i++) {
    unsigned char *sh = file + section_offset + i * section_size;
    uint32_t type = read32(sh + 4, swap);
    uint64_t sym_offset, sym_size, sym_entry, link;
    if (is64) {
      sym_offset = read64(sh + 24, swap);
      sym_size = read64(sh + 32, swap);
      sym_entry = read64(sh + 56, swap);
      link = read32(sh + 40, swap);
    } else {
      sym_offset = read32(sh + 16, swap);
      sym_size = read32(sh + 20, swap);
      sym_entry = read32(sh + 36, swap);
      link = read32(sh + 24, swap);
    }
    if ((type != SHT_SYMTAB && type != SHT_DYNSYM) || !sym_entry ||
        !valid_range(file_size, sym_offset, sym_size) || link >= section_count)
      continue;
    unsigned char *str_sh = file + section_offset + link * section_size;
    uint64_t str_offset =
        is64 ? read64(str_sh + 24, swap) : read32(str_sh + 16, swap);
    uint64_t str_size =
        is64 ? read64(str_sh + 32, swap) : read32(str_sh + 20, swap);
    if (!valid_range(file_size, str_offset, str_size))
      continue;
    const char *strings = (const char *)(file + str_offset);
    for (uint64_t pos = 0; pos + sym_entry <= sym_size; pos += sym_entry) {
      unsigned char *symbol = file + sym_offset + pos;
      uint32_t name_index = read32(symbol, swap);
      uint64_t value, symbol_size;
      unsigned char info;
      uint16_t section_index;
      if (is64) {
        info = symbol[4];
        section_index = read16(symbol + 6, swap);
        value = read64(symbol + 8, swap);
        symbol_size = read64(symbol + 16, swap);
      } else {
        value = read32(symbol + 4, swap);
        symbol_size = read32(symbol + 8, swap);
        info = symbol[12];
        section_index = read16(symbol + 14, swap);
      }
      if (!name_index || name_index >= str_size)
        continue;
      const char *name = strings + name_index;
      if (!*name)
        continue;
      printf("SYMBOL|%s|%llx|%llx|%u|%u|%u\n", name, (unsigned long long)value,
             (unsigned long long)symbol_size, ELF64_ST_BIND(info),
             ELF64_ST_TYPE(info), section_index);
      if (section_index < section_count && value) {
        unsigned char *target =
            file + section_offset + section_index * section_size;
        uint64_t target_flags =
            is64 ? read64(target + 8, swap) : read32(target + 8, swap);
        if (target_flags & SHF_EXECINSTR)
          printf("FUNCTION|%s|%llx|%llx|%u\n", name, (unsigned long long)value,
                 (unsigned long long)symbol_size, section_index);
      }
    }
  }
  free(file);
  return 0;
}
