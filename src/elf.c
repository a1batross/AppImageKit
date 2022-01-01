#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <elf.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ELFDATANATIVE ELFDATA2LSB
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ELFDATANATIVE ELFDATA2MSB
#else
#error "Unknown machine endian"
#endif

#define bswap_16(value) \
	((((value) & 0xff) << 8) | ((value) >> 8))

#define bswap_32(value) \
	(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
	(uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define bswap_64(value) \
	(((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) << 32) | \
	(uint64_t)bswap_32((uint32_t)((value) >> 32)))

static Elf64_Ehdr ehdr;

static uint16_t
file16_to_cpu(uint16_t val) {
	if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_16(val);
	return val;
}

static uint32_t
file32_to_cpu(uint32_t val)
{
	if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_32(val);
	return val;
}

static uint64_t
file64_to_cpu(uint64_t val)
{
	if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
		val = bswap_64(val);
	return val;
}

static off_t
read_elf32(const char *fname, FILE* fd)
{
	Elf32_Ehdr ehdr32;
	Elf32_Shdr shdr32;
	off_t last_shdr_offset;
	ssize_t ret;
	off_t  sht_end, last_section_end;

	fseeko(fd, 0, SEEK_SET);
	ret = fread(&ehdr32, 1, sizeof(ehdr32), fd);
	if (ret < 0 || (size_t)ret != sizeof(ehdr32)) {
		fprintf(stderr, "Read of ELF header from %s failed: %s\n",
			fname, strerror(errno));
		return -1;
	}

	ehdr.e_shoff		= file32_to_cpu(ehdr32.e_shoff);
	ehdr.e_shentsize	= file16_to_cpu(ehdr32.e_shentsize);
	ehdr.e_shnum		= file16_to_cpu(ehdr32.e_shnum);

	last_shdr_offset = ehdr.e_shoff + (ehdr.e_shentsize * (ehdr.e_shnum - 1));
	fseeko(fd, last_shdr_offset, SEEK_SET);
	ret = fread(&shdr32, 1, sizeof(shdr32), fd);
	if (ret < 0 || (size_t)ret != sizeof(shdr32)) {
		fprintf(stderr, "Read of ELF section header from %s failed: %s\n",
			fname, strerror(errno));
		return -1;
	}

	/* ELF ends either with the table of section headers (SHT) or with a section. */
	sht_end = ehdr.e_shoff + (ehdr.e_shentsize * ehdr.e_shnum);
	last_section_end = file64_to_cpu(shdr32.sh_offset) + file64_to_cpu(shdr32.sh_size);
	return sht_end > last_section_end ? sht_end : last_section_end;
}

static off_t
read_elf64(const char *fname, FILE* fd)
{
	Elf64_Ehdr ehdr64;
	Elf64_Shdr shdr64;
	off_t last_shdr_offset;
	off_t ret;
	off_t sht_end, last_section_end;

	fseeko(fd, 0, SEEK_SET);
	ret = fread(&ehdr64, 1, sizeof(ehdr64), fd);
	if (ret < 0 || (size_t)ret != sizeof(ehdr64)) {
		fprintf(stderr, "Read of ELF header from %s failed: %s\n",
			fname, strerror(errno));
		return -1;
	}

	ehdr.e_shoff		= file64_to_cpu(ehdr64.e_shoff);
	ehdr.e_shentsize	= file16_to_cpu(ehdr64.e_shentsize);
	ehdr.e_shnum		= file16_to_cpu(ehdr64.e_shnum);

	last_shdr_offset = ehdr.e_shoff + (ehdr.e_shentsize * (ehdr.e_shnum - 1));
	fseeko(fd, last_shdr_offset, SEEK_SET);
	ret = fread(&shdr64, 1, sizeof(shdr64), fd);
	if (ret < 0 || ret != sizeof(shdr64)) {
		fprintf(stderr, "Read of ELF section header from %s failed: %s\n",
			fname, strerror(errno));
		return -1;
	}

	/* ELF ends either with the table of section headers (SHT) or with a section. */
	sht_end = ehdr.e_shoff + (ehdr.e_shentsize * ehdr.e_shnum);
	last_section_end = file64_to_cpu(shdr64.sh_offset) + file64_to_cpu(shdr64.sh_size);
	return sht_end > last_section_end ? sht_end : last_section_end;
}

ssize_t
get_elf_size(const char *fname)
{
	ssize_t ret;
	FILE* fd;
	off_t size = -1;

	fd = fopen(fname, "rb");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open %s: %s\n",
			fname, strerror(errno));
		return -1;
	}

	ret = fread(ehdr.e_ident, 1, EI_NIDENT, fd);
	if (ret != EI_NIDENT) {
		fprintf(stderr, "Read of e_ident from %s failed: %s\n",
			fname, strerror(errno));
		return -1;
	}
	if ((ehdr.e_ident[EI_DATA] != ELFDATA2LSB) &&
		(ehdr.e_ident[EI_DATA] != ELFDATA2MSB)) {
		fprintf(stderr, "Unknown ELF data order %u\n",
			ehdr.e_ident[EI_DATA]);
		return -1;
	}

	if (ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
		size = read_elf32(fname, fd);
	} else if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
		size = read_elf64(fname, fd);
	} else {
		fprintf(stderr, "Unknown ELF class %u\n", ehdr.e_ident[EI_CLASS]);
		return -1;
	}

	fclose(fd);
	return size;
}
