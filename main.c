
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> // read
#include <fcntl.h> // open
#include <string.h>
#include <stdbool.h>

// Magic marker for elf files.
uint8_t headerIdentMagic[4] = { 0x7f, 'E', 'L', 'F' };

typedef struct {
	uint8_t mag[4],
		class,
		data,
		version,
		OSABI,
		ABIVersion,
		padding[6],
		size;
} ElfHeaderIdent;

enum {
	// Class
	ElfHeaderIdentClass32Bit = 1,
	ElfHeaderIdentClass64Bit,

	// Data
	ElfHeaderIdentDataLittleEndian = 1,
	ElfHeaderIdentDataBigEndian,

	// Version
	ElfHeaderIdentVersionCurrent = 1,

	// OS ABI
	ElfHeaderIdentOSABISystemV = 0,
	ElfHeaderIdentOSABIHPUX = 1,
	ElfHeaderIdentOSABIEmbedded = 0xff,
};

typedef struct {
	ElfHeaderIdent ident;
	uint16_t type, machine;
	uint32_t version;
	uint64_t entry, programHeaderOffset, sectionHeaderOffset;
	uint32_t flags;
	uint16_t size, programHeaderEntrySize, programHeaderEntryNum,
		sectionHeaderEntrySize, sectionHeaderEntryNum,
		sectionNameStringTableIndex;
} ElfHeader;

enum {
	// Type
	ElfHeaderTypeNone = 0,
	ElfHeaderTypeRelocatable,
	ElfHeaderTypeExecutable,
	ElfHeaderTypeDynamic,
	ElfHeaderTypeCore,
	ElfHeaderTypeOS_low = 0xfe00,
	ElfHeaderTypeOS_high = 0xfeff,
	ElfHeaderTypeProcessor_low = 0xff00,
	ElfHeaderTypeProcessor_high = 0xffff,

	// Version
	ElfHeaderVersionCurrent = 1,


};

const char *toStringElfHeaderIdentClass(uint8_t class) {
	const char *classes[] = {
		[ElfHeaderIdentClass32Bit] = "32 bit",
		[ElfHeaderIdentClass64Bit] = "64 bit"
	};
	if (class < sizeof(classes)) {
		return classes[class];
	} else {
		return NULL;
	}
}

const char *toStringElfHeaderIdentData(uint8_t data) {
	const char *datas[] = {
		[ElfHeaderIdentDataLittleEndian] = "little endian",
		[ElfHeaderIdentDataBigEndian] = "big endian"
	};
	if (data < sizeof(datas)) {
		return datas[data];
	} else {
		return NULL;
	}
}

const char *toStringElfHeaderIdentVersion(uint8_t version) {
	const char *versions[] = {
		[ElfHeaderIdentVersionCurrent] = "current"
	};
	if (version < sizeof(versions)) {
		return versions[version];
	} else {
		return NULL;
	}
}

const char *toStringElfHeaderIdentOSABI(uint8_t abi) {
	const char *abis[] = {
		[ElfHeaderIdentOSABISystemV] = "System V",
		[ElfHeaderIdentOSABIHPUX] = "HP UX"
	};
	if (abi < sizeof(abis)) {
		return abis[abi];
	} else {
		if (abi == ElfHeaderIdentOSABIEmbedded) {
			return "embedded";
		} else {
			return NULL;
		}
	}
}

const char *toStringElfHeaderType(uint16_t type) {
	const char *types[] = {
		[ElfHeaderTypeNone] = "none",
		[ElfHeaderTypeRelocatable] = "relocatable",
		[ElfHeaderTypeExecutable] = "executable",
		[ElfHeaderTypeDynamic] = "dynamic",
		[ElfHeaderTypeCore] = "core",
	};
	if (type  < sizeof(types)) {
		return types[type];
	} else {
		if (type >= ElfHeaderTypeOS_low && type <= ElfHeaderTypeOS_high) {
			return "reserved for OS specific";
		} else if (type >= ElfHeaderTypeProcessor_low && type <= ElfHeaderTypeProcessor_high) {
			return "reserved for processor specific";
		} else {
			return NULL;
		}
	}
}

const char *toStringElfHeaderVersion(uint8_t version) {
	const char *versions[] = {
		[ElfHeaderVersionCurrent] = "current"
	};
	if (version < sizeof(versions)) {
		return versions[version];
	} else {
		return NULL;
	}
}

char *toStringElfHeader(ElfHeader *hdr) {
	char *str;
	asprintf(&str,
		"hdr: {\n"
		"  ident: {\n"
		"    class:      '%s',\n"
		"    data:       '%s',\n"
		"    version:    '%s',\n"
		"    OSABI:      '%s',\n"
		"    ABIVersion: '%d',\n"
		"\n"
		"    // does this mean anything?\n"
		"    size: '%d'\n"
		"\n"
		"  },\n"
		"  type: '%s',\n"
		"\n"
		"  // processor specific\n"
		"  machine: '%#x',\n"
		"\n"
		"  version:             '%s',\n"
		"  entry:               '%#llx',\n"
		"  programHeaderOffset: '%#llx',\n"
		"  sectionHeaderOffset: '%#llx',\n"
		"\n"
		"  // processor specific\n"
		"  flags: '%#x',\n"
		"\n"
		"  size:                        '%#x',\n"
		"  programHeaderEntrySize:      '%#x',\n"
		"  programHeaderEntryNum:       '%#x',\n"
		"  sectionHeaderEntrySize:      '%#x',\n"
		"  sectionHeaderEntryNum:       '%#x',\n"
		"  sectionNameStringTableIndex: '%#x'\n"
		"}\n",
		toStringElfHeaderIdentClass(hdr->ident.class),
		toStringElfHeaderIdentData(hdr->ident.data),
		toStringElfHeaderIdentVersion(hdr->ident.version),
		toStringElfHeaderIdentOSABI(hdr->ident.OSABI),
		hdr->ident.ABIVersion,
		hdr->ident.size,
		toStringElfHeaderType(hdr->type),
		hdr->machine,
		toStringElfHeaderVersion(hdr->version),
		hdr->entry,
		hdr->programHeaderOffset,
		hdr->sectionHeaderOffset,
		hdr->flags,
		hdr->size,
		hdr->programHeaderEntrySize,
		hdr->programHeaderEntryNum,
		hdr->sectionHeaderEntrySize,
		hdr->sectionHeaderEntryNum,
		hdr->sectionNameStringTableIndex
	);
	return str;
}

bool elfHeader(ElfHeader *hdr) {
	return memcmp(headerIdentMagic, hdr, sizeof(headerIdentMagic)) == 0;
}

int main(int argc, char *argv[]) {
	char *f;
	if (argc != 2) {
		printf("%s file\n", argv[0]);
		return 1;
	} else {
		f = argv[1];
	}

	ElfHeader *hdr = calloc(sizeof(ElfHeader), 1);
	int fd = open(f, O_RDONLY, S_IREAD);
	int len = read(fd, hdr, sizeof(ElfHeader));
	if (elfHeader(hdr)) {
		char *str = toStringElfHeader(hdr);
		printf("%s", str);
		free(str);
	}
	free(hdr);
}
