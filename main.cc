
#include <iostream>
#include <string>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

class Stringable {
public:
	virtual std::string toString() = 0;
};

namespace elf {

	// Memory structure as stored
	struct HeaderMem {
		HeaderMem(int fd) {
			read(fd, static_cast<void *>(this), sizeof(HeaderMem));
		}
		struct Ident {
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
		uint16_t shstrndx;
	};

	struct SectionHeaderMem {
		uint32_t name;
		uint32_t type;
		uint64_t flags;
		uint64_t addr;
		uint64_t off;
		uint64_t size;
		uint32_t link;
		uint32_t info;
		uint64_t addr_align;
		uint64_t entry_size;
	};

	class Header : public Stringable {
	public:
		Header(HeaderMem m) : mem(m), ident(m.ident), type(m.type), version(m.version) {}

		bool confirm() {
			return ident.confirm();
		}

		virtual std::string toString() {
			char *str;
			size_t len = asprintf(&str,
				"hdr: {\n"
				"  ident: %s\n"
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
				"}",
				ident.toString().c_str(),
				type.toString().c_str(),
				mem.machine,
				version.toString().c_str(),
				mem.entry,
				mem.phoff,
				mem.shoff,
				mem.flags,
				mem.ehsize,
				mem.phentsize,
				mem.phnum,
				mem.shentsize,
				mem.shnum,
				mem.shstrndx
			);
			std::string st(str);
			free(str);
			return st;
		}
	private:
		HeaderMem mem;

		class Ident : public Stringable {
		public:
			Ident(HeaderMem::Ident i) : mag(i.mag), cls(i.cls), data(i.data), version(i.version), abi(i.osabi), abi_version(i.abiversion) {}

			bool confirm() {
				return mag.confirm();
			}

			virtual std::string toString() {
				char *str;
				size_t len = asprintf(&str,
					"{\n"
					"    class:      '%s',\n"
					"    data:       '%s',\n"
					"    version:    '%s',\n"
					"    OSABI:      '%s',\n"
					"    ABIVersion: '%s',\n"
					"  },",
					cls.toString().c_str(),
					data.toString().c_str(),
					version.toString().c_str(),
					abi.toString().c_str(),
					abi_version.toString().c_str()
				);
				std::string st(str);
				free(str);
				return st;
			}
		private:
			class Magic : public Stringable {
			public:
				Magic(uint32_t mg) : mag(mg) {}
				bool confirm() {
					return mag == kMagic;
				}

				virtual std::string toString() {
					if (confirm()) {
						return "elf";
					} else {
						return "not elf";
					}
				}
			private:
				static const uint32_t kMagic =
					0x7f | 'E' << 0x8 | 'L' << 0x10 | 'F' << 0x18;

				uint32_t mag;
			} mag;

			class Class : public Stringable {
			public:
				Class(uint8_t c) : cls(c) {}

				virtual std::string toString() {
					std::string classes[] = {
						[kBit32] = "32 bit",
						[kBit64] = "64 bit"
					};
					if (cls < (sizeof(classes) / sizeof(std::string))) {
						return classes[cls];
					} else {
						return "";
					}
				}
			private:
				enum {
					kBit32 = 1,
					kBit64,
				};
				uint8_t cls;
			} cls;

			class Data : public Stringable {
			public:
				Data(uint8_t d) : data(d) {}

				virtual std::string toString() {
					std::string datas[] = {
						[kLittleEndian] = "little endian",
						[kBigEndian] = "big endian"
					};
					if (data < (sizeof(datas) / sizeof(std::string))) {
						return datas[data];
					} else {
						return "";
					}
				}
			private:
				enum {
					kLittleEndian = 1,
					kBigEndian
				};
				uint8_t data;
			} data;

			class Version : public Stringable {
			public:
				Version(uint8_t v) : version(v) {}

				virtual std::string toString() {
					std::string versions[] = {
						[kCurrent] = "current"
					};
					if (version < (sizeof(versions) / sizeof(std::string))) {
						return versions[version];
					} else {
						return "";
					}
				}
			private:
				enum {
					kCurrent
				};
				uint8_t version;
			} version;

			class OSABI : public Stringable {
			public:
				OSABI(uint8_t a) : abi(a) {}

				virtual std::string toString() {
					std::string abis[] = {
						[kSystemV] = "System V",
						[kHPUX] = "HP UX"
					};
					if (abi < (sizeof(abis) / sizeof(std::string))) {
						return abis[abi];
					} else {
						if (abi == kEmbedded) {
							return "embedded";
						} else {
							return "";
						}
					}
				}
			private:
				enum {
					kSystemV,
					kHPUX,
					kEmbedded = 0xff
				};
				uint8_t abi;
			} abi;

			class ABIVersion : public Stringable {
			public:
				ABIVersion(uint8_t v) : version(v) {}

				virtual std::string toString() {
					char *str;
					asprintf(&str, "%d", version);
					std::string st(str);
					return st;
				}
			private:
				uint8_t version;
			} abi_version;
		} ident;

		class Type : public Stringable {
		public:
			Type(uint16_t t) : type(t) {}

			virtual std::string toString() {
				std::string types[] = {
					[kNone] = "none",
					[kRelocatable] = "relocatable",
					[kExecutable] = "executable",
					[kDynamic] = "dynamic",
					[kCore] = "core",
				};
				if (type  < (sizeof(types) / sizeof(std::string))) {
					return types[type];
				} else {
					if (type >= kOS_low && type <= kOS_high) {
						return "reserved for OS specific";
					} else if (type >= kProcessor_low && type <= kProcessor_high) {
						return "reserved for processor specific";
					} else {
						return "";
					}
				}
			}
		private:
			enum {
				// Type
				kNone = 0,
				kRelocatable,
				kExecutable,
				kDynamic,
				kCore,
				kOS_low = 0xfe00,
				kOS_high = 0xfeff,
				kProcessor_low = 0xff00,
				kProcessor_high = 0xffff
			};
			uint16_t type;
		} type;

		class Version : public Stringable {
		public:
			Version(uint32_t v) : version(v) {}

			virtual std::string toString() {
				std::string versions[] = {
					[kCurrent] = "current"
				};
				if (version < (sizeof(versions) / sizeof(std::string))) {
					return versions[version];
				} else {
					return "";
				}
			}
		private:
			enum {
				kCurrent
			};
			uint32_t version;
		} version;
	};
}

int main(int argc, char *argv[]) {
	char *f;
	if (argc != 2) {
		printf("%s file\n", argv[0]);
		return 1;
	} else {
		f = argv[1];
	}

	int fd = open(f, O_RDONLY, S_IREAD);
	elf::Header hdr(fd); // read header from fd.
	printf("%s: %s\n", hdr.toString().c_str(), (hdr.confirm()) ? "elf" : "not elf");
}
