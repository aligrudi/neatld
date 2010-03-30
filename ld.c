#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAXSECS		(1 << 10)
#define MAXOBJS		(1 << 7)
#define PAGESIZE	(1 << 12)

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
};

static int obj_find(struct obj *obj, char *name, int *s_idx, int *s_off)
{
	int i;
	for (i = 0; i < obj->nsyms; i++) {
		Elf64_Sym *sym = &obj->syms[i];
		if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL ||
				sym->st_shndx == SHN_UNDEF)
			continue;
		if (!strcmp(name, obj->symstr + sym->st_name)) {
			*s_idx = sym->st_shndx;
			*s_off = sym->st_value;
			return 0;
		}
	}
	return 1;
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

static unsigned long outelf_find(struct outelf *oe, char *name)
{
	int s_idx, s_off;
	int i;
	for (i = 0; i < oe->nobjs; i++) {
		struct obj *obj = &oe->objs[i];
		if (!obj_find(obj, name, &s_idx, &s_off)) {
			struct secmap *sec;
			if ((sec = outelf_mapping(oe, &obj->shdr[s_idx])))
				return sec->phdr->p_vaddr + s_off;
		}
	}
	return 0;
}

static unsigned long symval(struct outelf *oe, struct obj *obj, Elf64_Sym *sym)
{
	struct secmap *sec;
	char *name = obj->symstr + sym->st_name;
	switch (ELF64_ST_TYPE(sym->st_info)) {
	case STT_SECTION:
		if ((sec = outelf_mapping(oe, &obj->shdr[sym->st_shndx])))
			return sec->phdr->p_vaddr;
		break;
	case STT_NOTYPE:
	case STT_OBJECT:
	case STT_FUNC:
		if (name && *name)
			return outelf_find(oe, name);
		break;
	}
	return 0;
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
		unsigned long val = symval(oe, obj, sym);
		char *name = obj->symstr + sym->st_name;
		unsigned long *dst = other + rel[i].r_offset;
		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_32:
			*(unsigned int *) dst = val + rel[i].r_addend;
			break;
		case R_X86_64_64:
			*dst = val + rel[i].r_addend;
			break;
		case R_X86_64_PC32:
			addr = outelf_mapping(oe, other_shdr)->phdr->p_vaddr +
				rel[i].r_offset;
			*(unsigned int *) dst = val - addr + rel[i].r_addend - 4;
			break;
		}
	}
}

static void outelf_reloc(struct outelf *oe)
{
	int i, j;
	for (i = 0; i < oe->nobjs; i++) {
		struct obj *obj = &oe->objs[i];
		for (j = 0; j < obj->ehdr->e_shnum; j++)
			if (obj->shdr[j].sh_type == SHT_RELA)
				outelf_reloc_sec(oe, i, j);
	}
}

static void outelf_write(struct outelf *oe, int fd)
{
	int i;
	oe->ehdr.e_entry = outelf_find(oe, "_start");

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
	lseek(fd, oe->faddr, SEEK_SET);
	write(fd, &oe->phdr, oe->nph * sizeof(oe->phdr[0]));
}

static void outelf_link(struct outelf *oe, char *mem)
{
	Elf64_Ehdr *ehdr = (void *) mem;
	Elf64_Shdr *shdr = (void *) (mem + ehdr->e_shoff);
	struct obj *obj = &oe->objs[oe->nobjs++];
	int i;
	if (ehdr->e_type != ET_REL)
		return;
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
		sec->phdr->p_paddr = oe->vaddr;
		sec->phdr->p_offset = oe->faddr;
		sec->phdr->p_filesz = shdr[i].sh_size;
		sec->phdr->p_memsz = shdr[i].sh_size;
		sec->phdr->p_align = PAGESIZE;
		oe->faddr += shdr[i].sh_size;
		oe->vaddr += shdr[i].sh_size;
	}
}

static void outelf_free(struct outelf *oe)
{
	int i;
	for (i = 0; i < oe->nobjs; i++)
		free(oe->objs[i].mem);
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

static void die(char *msg)
{
	write(1, msg, strlen(msg));
	exit(1);
}

int main(int argc, char **argv)
{
	char out[1 << 10] = "a.out";
	char *buf;
	struct outelf oe;
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
		if (!buf)
			die("cannot open object\n");
		outelf_link(&oe, buf);
	}
	fd = open(out, O_WRONLY | O_TRUNC | O_CREAT, 0700);
	outelf_reloc(&oe);
	outelf_write(&oe, fd);
	close(fd);
	outelf_free(&oe);
	return 0;
}
