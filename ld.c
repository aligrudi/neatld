#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>

#define MAXSECS		(1 << 10)
#define MAXOBJS		(1 << 7)
#define MAXSYMS		(1 << 12)
#define PAGE_SIZE	(1 << 12)
#define GOT_PAD		16
#define MAXFILES	(1 << 10)

#define ALIGN(x,a)		__ALIGN_MASK(x,(typeof(x))(a)-1)
#define __ALIGN_MASK(x,mask)	(((x)+(mask))&~(mask))

struct obj {
	char *mem;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	Elf64_Sym *syms;
	int nsyms;
	char *symstr;
	char *shstr;
};

struct secmap {
	Elf64_Shdr *o_shdr;
	Elf64_Phdr *phdr;
	struct obj *obj;
};

struct bss_sym {
	Elf64_Sym *sym;
	int off;
};

struct outelf {
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr[MAXSECS];
	int nph;
	struct secmap secs[MAXSECS];
	int nsecs;
	struct obj objs[MAXOBJS];
	int nobjs;
	unsigned long faddr;
	unsigned long vaddr;

	/* bss section */
	struct bss_sym bss_syms[MAXSYMS];
	int nbss_syms;
	unsigned long bss_addr;
	int bss_len;

	/* got/plt section */
	Elf64_Sym *got_syms[MAXSYMS];
	int ngot_syms;
	unsigned long got_addr;
	unsigned long got_faddr;
};

static Elf64_Sym *obj_find(struct obj *obj, char *name)
{
	int i;
	for (i = 0; i < obj->nsyms; i++) {
		Elf64_Sym *sym = &obj->syms[i];
		if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL ||
				sym->st_shndx == SHN_UNDEF)
			continue;
		if (!strcmp(name, obj->symstr + sym->st_name))
			return sym;
	}
	return NULL;
}

static void obj_init(struct obj *obj, char *mem)
{
	int i;
	obj->mem = mem;
	obj->ehdr = (void *) mem;
	obj->shdr = (void *) (mem + obj->ehdr->e_shoff);
	obj->shstr = mem + obj->shdr[obj->ehdr->e_shstrndx].sh_offset;
	for (i = 0; i < obj->ehdr->e_shnum; i++) {
		if (obj->shdr[i].sh_type != SHT_SYMTAB)
			continue;
		obj->symstr = mem + obj->shdr[obj->shdr[i].sh_link].sh_offset;
		obj->syms = (void *) (mem + obj->shdr[i].sh_offset);
		obj->nsyms = obj->shdr[i].sh_size / sizeof(*obj->syms);
	}
}

static void outelf_init(struct outelf *oe)
{
	memset(oe, 0, sizeof(*oe));
	oe->ehdr.e_ident[0] = 0x7f;
	oe->ehdr.e_ident[1] = 'E';
	oe->ehdr.e_ident[2] = 'L';
	oe->ehdr.e_ident[3] = 'F';
	oe->ehdr.e_ident[4] = ELFCLASS64;
	oe->ehdr.e_ident[5] = ELFDATA2LSB;
	oe->ehdr.e_ident[6] = EV_CURRENT;
	oe->ehdr.e_ident[7] = ELFOSABI_LINUX;
	oe->ehdr.e_type = ET_EXEC;
	oe->ehdr.e_machine = EM_X86_64;
	oe->ehdr.e_version = EV_CURRENT;
	oe->ehdr.e_shstrndx = SHN_UNDEF;
	oe->ehdr.e_ehsize = sizeof(oe->ehdr);
	oe->faddr = sizeof(oe->ehdr);
	oe->ehdr.e_phentsize = sizeof(oe->phdr[0]);
	oe->ehdr.e_shentsize = sizeof(Elf64_Shdr);
	oe->vaddr = 0x800000l + oe->faddr;
}

static struct secmap *outelf_mapping(struct outelf *oe, Elf64_Shdr *shdr)
{
	int i;
	for (i = 0; i < oe->nsecs; i++)
		if (oe->secs[i].o_shdr == shdr)
			return &oe->secs[i];
	return NULL;
}

static int outelf_find(struct outelf *oe, char *name,
			struct obj **sym_obj, Elf64_Sym **sym_sym)
{
	int s_idx, s_off;
	int i;
	for (i = 0; i < oe->nobjs; i++) {
		struct obj *obj = &oe->objs[i];
		Elf64_Sym *sym;
		if ((sym = obj_find(obj, name))) {
			*sym_obj = obj;
			*sym_sym = sym;
			return 0;
		}
	}
	return 1;
}

static unsigned long bss_addr(struct outelf *oe, Elf64_Sym *sym)
{
	int i;
	for (i = 0; i < oe->nbss_syms; i++)
		if (oe->bss_syms[i].sym == sym)
			return oe->bss_addr + oe->bss_syms[i].off;
}

static unsigned long symval(struct outelf *oe, struct obj *obj, Elf64_Sym *sym)
{
	struct secmap *sec;
	char *name = obj ? obj->symstr + sym->st_name : NULL;
	int s_idx, s_off;
	switch (ELF64_ST_TYPE(sym->st_info)) {
	case STT_SECTION:
		if ((sec = outelf_mapping(oe, &obj->shdr[sym->st_shndx])))
			return sec->phdr->p_vaddr;
		break;
	case STT_NOTYPE:
	case STT_OBJECT:
	case STT_FUNC:
		if (name && *name && sym->st_shndx == SHN_UNDEF)
			outelf_find(oe, name, &obj, &sym);
		if (sym->st_shndx == SHN_COMMON)
			return bss_addr(oe, sym);
		s_idx = sym->st_shndx;
		s_off = sym->st_value;
		sec = outelf_mapping(oe, &obj->shdr[s_idx]);
		if ((sec = outelf_mapping(oe, &obj->shdr[s_idx])))
			return sec->phdr->p_vaddr + s_off;
	}
	return 0;
}

static void die(char *msg)
{
	write(1, msg, strlen(msg));
	exit(1);
}

static unsigned long outelf_addr(struct outelf *oe, char *name)
{
	struct obj *obj;
	Elf64_Sym *sym;
	int s_idx, s_off;
	struct secmap *sec;
	if (outelf_find(oe, name, &obj, &sym))
		die("unknown symbol!\n");
	return symval(oe, obj, sym);
}

static void alloc_bss(struct outelf *oe, Elf64_Sym *sym)
{
	int n = oe->nbss_syms++;
	int off = ALIGN(oe->bss_len, sym->st_value);
	oe->bss_syms[n].sym = sym;
	oe->bss_syms[n].off = off + sym->st_size;
	oe->bss_len += off + sym->st_size;
}

static void got_offset(struct outelf *oe, struct obj *obj, Elf64_Sym *sym)
{
	char *name = obj->symstr + sym->st_name;
	int n;
	int i;
	if (name && *name && sym->st_shndx == SHN_UNDEF)
		outelf_find(oe, name, &obj, &sym);
	for (i = 0; i < oe->ngot_syms; i++)
		if (oe->got_syms[i] == sym)
			return i * 8;
	n = oe->ngot_syms++;
	oe->got_syms[n] = sym;
	return n * 8;
}

static void outelf_reloc_sec(struct outelf *oe, int o_idx, int s_idx)
{
	struct obj *obj = &oe->objs[o_idx];
	Elf64_Shdr *rel_shdr = &obj->shdr[s_idx];
	Elf64_Rela *rel = (void *) obj->mem + obj->shdr[s_idx].sh_offset;
	Elf64_Shdr *other_shdr = &obj->shdr[rel_shdr->sh_info];
	void *other = (void *) obj->mem + other_shdr->sh_offset;
	int nrel = rel_shdr->sh_size / sizeof(*rel);
	unsigned long addr;
	int i;
	for (i = 0; i < nrel; i++) {
		int sym_idx = ELF64_R_SYM(rel[i].r_info);
		Elf64_Sym *sym = &obj->syms[sym_idx];
		unsigned long val = symval(oe, obj, sym) + rel[i].r_addend;
		unsigned long *dst = other + rel[i].r_offset;
		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE:
			break;
		case R_X86_64_32:
		case R_X86_64_32S:
			*(unsigned int *) dst = val;
			break;
		case R_X86_64_64:
			*dst = val;
			break;
		case R_X86_64_PC32:
		case R_X86_64_PLT32:
			addr = outelf_mapping(oe, other_shdr)->phdr->p_vaddr +
				rel[i].r_offset;
			*(unsigned int *) dst += val - addr;
			break;
		case R_X86_64_GOTPCREL:
			addr = outelf_mapping(oe, other_shdr)->phdr->p_vaddr +
				rel[i].r_offset;
			val = got_offset(oe, obj, sym) + oe->got_addr +
				rel[i].r_addend;
			*(unsigned int *) dst += val - addr;
			break;
		default:
			die("unknown relocation type\n");
		}
	}
}

static void outelf_reloc(struct outelf *oe)
{
	int i, j;
	int len = oe->ngot_syms * 8 + GOT_PAD;
	oe->got_addr = ALIGN(oe->vaddr, PAGE_SIZE) + oe->faddr % PAGE_SIZE;
	oe->got_faddr = oe->faddr;
	oe->vaddr = oe->vaddr + len;
	oe->faddr = oe->faddr + len;

	for (i = 0; i < oe->nobjs; i++) {
		struct obj *obj = &oe->objs[i];
		for (j = 0; j < obj->ehdr->e_shnum; j++)
			if (obj->shdr[j].sh_type == SHT_RELA)
				outelf_reloc_sec(oe, i, j);
	}
}

static void alloc_bss(struct outelf *oe, Elf64_Sym *sym)
{
	int n = oe->nbss_syms++;
	int off = ALIGN(oe->bss_len, sym->st_value);
	oe->bss_syms[n].sym = sym;
	oe->bss_syms[n].off = off + sym->st_size;
	oe->bss_len += off + sym->st_size;
}

static void outelf_bss(struct outelf *oe)
{
	int i, j;
	Elf64_Phdr *phdr = &oe->phdr[oe->nph++];
	for (i = 0; i < oe->nobjs; i++) {
		struct obj *obj = &oe->objs[i];
		for (j = 0; j < obj->nsyms; j++)
			if (obj->syms[j].st_shndx == SHN_COMMON)
				alloc_bss(oe, &obj->syms[j]);
	}
	oe->bss_addr = oe->vaddr;
	oe->vaddr = oe->vaddr + oe->bss_len;

	phdr->p_type = PT_LOAD;
	phdr->p_flags = PF_R | PF_W;
	phdr->p_vaddr = oe->bss_addr;
	phdr->p_paddr = oe->bss_addr;
	phdr->p_offset = oe->faddr;
	phdr->p_filesz = 0;
	phdr->p_memsz = oe->bss_len;
	phdr->p_align = PAGE_SIZE;
}

static int outelf_putgot(struct outelf *oe, char *buf)
{
	Elf64_Phdr *phdr = &oe->phdr[oe->nph++];
	unsigned long *got = (void *) buf;
	struct obj *obj;
	int len = 8 * oe->ngot_syms;
	int i;
	for (i = 0; i < oe->ngot_syms; i++)
		got[i] = symval(oe, NULL, oe->got_syms[i]);
	memset(buf + len, 0, GOT_PAD);
	phdr->p_type = PT_LOAD;
	phdr->p_flags = PF_R | PF_W;
	phdr->p_vaddr = oe->got_addr;
	phdr->p_paddr = oe->got_addr;
	phdr->p_offset = oe->got_faddr;
	phdr->p_filesz = len;
	phdr->p_memsz = len;
	phdr->p_align = PAGE_SIZE;
	return len + GOT_PAD;
}

static void outelf_write(struct outelf *oe, int fd)
{
	int i;
	char buf[1 << 14];
	int got_len;
	oe->ehdr.e_entry = outelf_addr(oe, "_start");
	got_len = outelf_putgot(oe, buf);

	oe->ehdr.e_phnum = oe->nph;
	oe->ehdr.e_phoff = oe->faddr;
	oe->ehdr.e_shnum = 0;
	oe->ehdr.e_shoff = 0;
	write(fd, &oe->ehdr, sizeof(oe->ehdr));
	for (i = 0; i < oe->nsecs; i++) {
		struct secmap *sec = &oe->secs[i];
		char *buf = sec->obj->mem + sec->o_shdr->sh_offset;
		int len = sec->o_shdr->sh_size;
		lseek(fd, sec->phdr->p_offset, SEEK_SET);
		write(fd, buf, len);
	}
	lseek(fd, oe->got_faddr, SEEK_SET);
	write(fd, buf, got_len);
	lseek(fd, oe->faddr, SEEK_SET);
	write(fd, &oe->phdr, oe->nph * sizeof(oe->phdr[0]));
}

static void outelf_link(struct outelf *oe, char *mem)
{
	Elf64_Ehdr *ehdr = (void *) mem;
	Elf64_Shdr *shdr = (void *) (mem + ehdr->e_shoff);
	struct obj *obj;
	int i;
	if (ehdr->e_type != ET_REL)
		return;
	obj = &oe->objs[oe->nobjs++];
	obj_init(obj, mem);
	for (i = 0; i < ehdr->e_shnum; i++) {
		struct secmap *sec;
		if (!(shdr[i].sh_flags & 0x7))
			continue;
		sec = &oe->secs[oe->nsecs++];
		sec->o_shdr = &shdr[i];
		sec->phdr = &oe->phdr[oe->nph++];
		sec->obj = obj;
		sec->phdr->p_type = PT_LOAD;
		sec->phdr->p_flags = PF_R | PF_W | PF_X;
		sec->phdr->p_vaddr = oe->vaddr;
		sec->phdr->p_paddr = sec->phdr->p_vaddr;
		sec->phdr->p_offset = oe->faddr;
		sec->phdr->p_filesz = shdr[i].sh_size;
		sec->phdr->p_memsz = shdr[i].sh_size;
		sec->phdr->p_align = PAGE_SIZE;
		oe->faddr = sec->phdr->p_offset + sec->phdr->p_filesz;
		oe->vaddr = sec->phdr->p_vaddr + sec->phdr->p_memsz;
	}
}

struct arhdr {
	char ar_name[16];
	char ar_date[12];
	char ar_uid[6];
	char ar_gid[6];
	char ar_mode[8];
	char ar_size[10];
	char ar_fmag[2];
};

static int get_be32(unsigned char *s)
{
	return s[3] | (s[2] << 8) | (s[1] << 16) | (s[0] << 32);
}

static int sym_undef(struct outelf *oe, char *name)
{
	int i, j;
	int undef = 0;
	for (i = 0; i < oe->nobjs; i++) {
		struct obj *obj = &oe->objs[i];
		for (j = 0; j < obj->nsyms; j++) {
			Elf64_Sym *sym = &obj->syms[j];
			if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL)
				continue;
			if (strcmp(name, obj->symstr + sym->st_name))
				continue;
			if (sym->st_shndx != SHN_UNDEF)
				return 0;
			undef = 1;
		}
	}
	return undef;
}

static void outelf_ar_link(struct outelf *oe, unsigned char *ar, int base)
{
	unsigned char *ar_index;
	unsigned char *ar_name;
	int nsyms = get_be32(ar);
	int i;
	ar_index = ar + 4;
	ar_name = ar_index + nsyms * 4;
	for (i = 0; i < nsyms; i++) {
		int off = get_be32(ar_index + i * 4) + sizeof(struct arhdr);
		if (sym_undef(oe, ar_name))
			outelf_link(oe, ar - base + off);
		ar_name = strchr(ar_name, '\0') + 1;
	}
}

static int startswith(char *s, char *r)
{
	return !strncmp(s, r, strlen(r));
}

static void link_archive(struct outelf *oe, char *ar)
{
	char *beg = ar;
	int i;

	/* skip magic */
	ar += 8;
	for(;;) {
		struct arhdr *hdr = (void *) ar;
		int size;
		ar += sizeof(*hdr);
		hdr->ar_size[sizeof(hdr->ar_size) - 1] = '\0';
		size = atoi(hdr->ar_size);
		size = (size + 1) & ~1;
		if (startswith(hdr->ar_name, "/ ")) {
			outelf_ar_link(oe, ar, ar - beg);
			return;
		} else if (startswith(hdr->ar_name, "// ") ||
				startswith(hdr->ar_name, "__.SYMDEF ") ||
				startswith(hdr->ar_name, "__.SYMDEF/ ") ||
				startswith(hdr->ar_name, "ARFILENAMES/ ")) {
			/* skip symbol table or archive names */
		} else {
			outelf_link(oe, ar);
		}
		ar += size;
	}
}

static long filesize(int fd)
{
	struct stat stat;
	fstat(fd, &stat);
	return stat.st_size;
}

static char *fileread(char *path)
{
	int fd = open(path, O_RDONLY);
	int size = filesize(fd);
	char *buf = malloc(size);
	read(fd, buf, size);
	close(fd);
	return buf;
}

static int is_ar(char *path)
{
	int len = strlen(path);
	return len > 2 && path[len - 2] == '.' && path[len - 1] == 'a';
}

int main(int argc, char **argv)
{
	char out[1 << 10] = "a.out";
	char *buf;
	struct outelf oe;
	char *mem[MAXFILES];
	int nmem;
	int fd;
	int i = 0;
	if (argc < 2)
		die("no object given\n");
	outelf_init(&oe);

	while (++i < argc) {
		if (!strcmp("-o", argv[i])) {
			strcpy(out, argv[++i]);
			continue;
		}
		buf = fileread(argv[i]);
		mem[nmem++] = buf;
		if (!buf)
			die("cannot open object\n");
		if (is_ar(argv[i]))
			link_archive(&oe, buf);
		else
			outelf_link(&oe, buf);
	}
	fd = open(out, O_WRONLY | O_TRUNC | O_CREAT, 0700);
	outelf_bss(&oe);
	outelf_reloc(&oe);
	outelf_write(&oe, fd);
	close(fd);
	for (i = 0; i < nmem; i++)
		free(mem[i]);
	return 0;
}
