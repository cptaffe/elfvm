
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
	class Header : public Stringable {
	public:
		Header(int fd) : ident(fd), type(fd), version(fd) {
			read(fd, static_cast<void *>(&entry), sizeof(entry));
			read(fd, static_cast<void *>(&programHeaderOffset), sizeof(programHeaderOffset));
			read(fd, static_cast<void *>(&sectionHeaderOffset), sizeof(sectionHeaderOffset));
			read(fd, static_cast<void *>(&flags), sizeof(flags));
			read(fd, static_cast<void *>(&size), sizeof(size));
			read(fd, static_cast<void *>(&programHeaderEntrySize), sizeof(programHeaderEntrySize));
			read(fd, static_cast<void *>(&programHeaderEntryNum), sizeof(programHeaderEntryNum));
			read(fd, static_cast<void *>(&sectionHeaderEntrySize), sizeof(sectionHeaderEntrySize));
			read(fd, static_cast<void *>(&sectionHeaderEntryNum), sizeof(sectionHeaderEntryNum));
			read(fd, static_cast<void *>(&sectionNameStringTableIndex), sizeof(sectionNameStringTableIndex));
		}

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
				"}\n",
				ident.toString().c_str(),
				type.toString().c_str(),
				machine,
				version.toString().c_str(),
				entry,
				programHeaderOffset,
				sectionHeaderOffset,
				flags,
				size,
				programHeaderEntrySize,
				programHeaderEntryNum,
				sectionHeaderEntrySize,
				sectionHeaderEntryNum,
				sectionNameStringTableIndex
			);
			std::string st(str);
			free(str);
			return st;
		}
	private:
		class Ident : public Stringable {
		public:
			Ident(int fd) : mag(fd), cls(fd), data(fd), version(fd), abi(fd), abi_version(fd) {
				read(fd, static_cast<void *>(&padding), sizeof(padding));
			}

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
				Magic(int fd) {
					read(fd, static_cast<void *>(&mag), sizeof(mag));
				}
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
				Class(int fd) {
					read(fd, static_cast<void *>(&cls), sizeof(cls));
				}

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
				Data(int fd) {
					read(fd, static_cast<void *>(&data), sizeof(data));
				}

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
				Version(int fd) {
					read(fd, static_cast<void *>(&version), sizeof(version));
				}

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
				OSABI(int fd) {
					read(fd, static_cast<void *>(&abi), sizeof(abi));
				}

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
				ABIVersion(int fd) {
					read(fd, static_cast<void *>(&version), sizeof(version));
				}

				virtual std::string toString() {
					char *str;
					asprintf(&str, "%d", version);
					std::string st(str);
					return st;
				}
			private:
				uint8_t version;
			} abi_version;

			// padding bytes
			uint8_t padding[7];
		} ident;

		class Type : public Stringable {
		public:
			Type(int fd) {
				read(fd, static_cast<void *>(&type), sizeof(type));
			}

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

		uint16_t machine;

		class Version : public Stringable {
		public:
			Version(int fd) {
				read(fd, static_cast<void *>(&version), sizeof(version));
			}

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

		uint64_t entry, programHeaderOffset, sectionHeaderOffset;
		uint32_t flags;
		uint16_t size, programHeaderEntrySize, programHeaderEntryNum,
			sectionHeaderEntrySize, sectionHeaderEntryNum,
			sectionNameStringTableIndex;
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
	elf::Header hdr(fd);
	printf("%s: %s\n", hdr.toString().c_str(), (hdr.confirm()) ? "elf" : "not elf");
}
