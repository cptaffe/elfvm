
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

// header
typedef struct {
	struct {
		uint32_t mag;
		uint8_t cls;
		uint8_t data;
		uint8_t version;
		uint8_t osabi;
		uint8_t abiversion;
		uint8_t pad[7];
	} ident;
	uint16_t type;
	uint16_t machine;
	uint32_t version;
	uint64_t entry;
	uint64_t phoff;
	uint64_t shoff;
	uint32_t flags;
	uint16_t ehsize;
	uint16_t phentsize;
	uint16_t phnum;
	uint16_t shentsize;
	uint16_t shnum;
	uint16_t shstri;
} elfhdr;

static const uint32_t elfhdr_magic = 0x7f | 'E' << 0x8 | 'L' << 0x10 | 'F' << 0x18;

// section header
typedef struct {
	uint32_t name; // offset in section name table
	uint32_t type; // section type
	uint64_t flags; // attributes
	uint64_t addr; // addr of the section (if allocated)
	uint64_t off; // offset of section contents in file
	uint64_t size; // size of the section
	uint32_t link; // section index of an associated section
	uint32_t info; // extra info
	uint64_t addr_align; // required alignment (power of 2)
	uint64_t entry_size; // size of each entry (for fixed size entries)
} elfsechdr;

// symbol table entry
typedef struct {
	uint32_t name; // offset in symbol string table
	uint8_t info; // symbol table & scope
	uint8_t other; // reserved, zero
	uint16_t shi; // index of definition, or specifier
	uint64_t value; // value of the symbol
	uint64_t size; // size associated with symbol
} elfsym;

// elf relocatable
typedef struct {
	uint64_t offset;
	uint64_t info; // symbol table index & relocation type
} elfrel;

typedef struct {
	uint64_t offset;
	uint64_t info; // symbol table index & relocation type
	uint64_t addend; // constant addend to computer value at field
} elfrela;

// program header
typedef struct {
	uint32_t type;
	uint32_t flags;
	uint64_t offset;
	uint64_t vaddr;
	uint64_t paddr;
	uint64_t fsize;
	uint64_t msize;
	uint64_t align;
} elfphdr;

int main(int argc, char *argv[]) {
	char *f;
	if (argc != 2) {
		printf("%s file\n", argv[0]);
		return 1;
	} else {
		f = argv[1];
	}

	int fd = open(f, O_RDONLY, S_IREAD);
	elfhdr hdr;
	read(fd, &hdr, sizeof(elfhdr));

	if (hdr.ident.mag == elfhdr_magic) {
		printf("elf!\n");
	}
}
