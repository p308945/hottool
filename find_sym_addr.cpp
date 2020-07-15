#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "find_sym_addr.h"
#include "crossprocess.h"
#include <unistd.h>
#include <linux/limits.h>

//#define DEBUG_PHDR_INFO 0
//#define DEBUG_SHDR_INFO 0

bool find_elf_addr(pid_t pid, const char* elfname, const char *perms_prot_flags, unsigned long &start, unsigned long &end)
{
	FILE* fp;
	char maps[4096], mapbuf[4096], perms[32], libpath[4096];
	char* libname;
	unsigned long file_offset, inode, dev_major, dev_minor;
	sprintf(maps, "/proc/%d/maps", pid);
	fp = fopen(maps, "rb");
	if (!fp)
	{
		fprintf(stderr, "Failed to open %s: %s\n", maps, strerror(errno));
		return 0;
	}
	while (fgets(mapbuf, sizeof(mapbuf), fp))
	{
		sscanf(mapbuf, "%lx-%lx %s %lx %lx:%lx %lu %s", &start, &end, perms, &file_offset, &dev_major, &dev_minor, &inode, libpath);
		libname = strrchr(libpath, '/');
		if (libname)
		{
			libname++;
		}
		else
		{
			continue;
		}
		if (!strncmp(perms, perms_prot_flags, 4) && strstr(libname, elfname))
		{
			fclose(fp);
			return true;
		}
	}
	fclose(fp);
	return false;
}

bool find_so_func_addr_by_mem(int pid, const std::string &soname, const std::string &funname, void *&funcaddr_plt, void *&funcaddr)
{
	unsigned long startaddr;
	unsigned long endaddr;

	if (!find_elf_addr(pid, soname.c_str(), "r-xp", startaddr, endaddr))
	{
		fprintf(stderr, "%s %d find %s addr error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	Elf64_Ehdr targetso;
	int ret = cross_proc_read(pid, (char *)startaddr, (char *)&targetso, sizeof(targetso));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d get %s elf header data error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}
	if (targetso.e_ident[EI_MAG0] != ELFMAG0 ||
			targetso.e_ident[EI_MAG1] != ELFMAG1 ||
			targetso.e_ident[EI_MAG2] != ELFMAG2 ||
			targetso.e_ident[EI_MAG3] != ELFMAG3)
	{
		fprintf(stderr, "%s %d %s elf header magic error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	fprintf(stderr, "%s %d %p read head ok startaddr:%lu, e_she_shoff:%lu, e_shnum:%d, e_shentsize:%d, e_shstrndx:%d\n", __FUNCTION__, __LINE__, startaddr, targetso.e_shoff, targetso.e_shnum, targetso.e_shentsize, targetso.e_shstrndx);

	Elf64_Shdr sections[targetso.e_shnum];
	ret = cross_proc_read(pid, (char *)(startaddr + targetso.e_shoff), (char *)&sections, sizeof(sections));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d get %s section header data error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	Elf64_Shdr &shsection = sections[targetso.e_shstrndx];
	fprintf(stderr, "%s %d %s section strtable offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), shsection.sh_offset, shsection.sh_size);
	char shsectionname[shsection.sh_size];
	ret = cross_proc_read(pid, (char *)(startaddr + shsection.sh_offset), shsectionname, sizeof(shsectionname));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d get %s section header name error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	int pltindex = -1;
	int dynsymindex = -1;
	int dynstrindex = -1;
	int relapltindex = -1;
	for (int i = 0; i < targetso.e_shnum; ++i)
	{
		Elf64_Shdr &s = sections[i];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".plt")
		{
			pltindex = i;
			continue;
		}
		if (name == ".dynsym")
		{
			dynsymindex = i;
			continue;
		}
		if (name == ".dynstr")
		{
			dynstrindex = i;
			continue;
		}
		if (name == ".rela.plt")
		{
			relapltindex = i;
			continue;
		}
	}
    if (pltindex < 0)
	{
        fprintf(stderr, "%s %d not find .plt %s\n", __FUNCTION__, __LINE__, soname.c_str());
        return false;
    }
    if (dynsymindex < 0)
	{
        fprintf(stderr, "%s %d not find .dynsym %s\n", __FUNCTION__, __LINE__, soname.c_str());
        return false;
    }
    if (dynstrindex < 0)
	{
        fprintf(stderr, "%s %d not find .dynstr %s\n", __FUNCTION__, __LINE__, soname.c_str());
        return false;
    }
    if (relapltindex < 0)
	{
        fprintf(stderr, "%s %d not find .rel.plt %s\n", __FUNCTION__, __LINE__, soname.c_str());
        return false;
    }

	Elf64_Shdr pltsection = sections[pltindex];
    fprintf(stderr, "%s %d %s ok get plt section header offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), pltsection.sh_offset, pltsection.sh_size);

	Elf64_Shdr dynsymsection = sections[dynsymindex];
    fprintf(stderr, "%s %d %s ok get dynsym section header offset:%ld, size:%ld", __FUNCTION__, __LINE__, soname.c_str(), dynsymsection.sh_offset, dynsymsection.sh_size);

	Elf64_Sym sym[dynsymsection.sh_size / sizeof(Elf64_Sym)];
	ret = cross_proc_read(pid, (char *)(startaddr + dynsymsection.sh_offset), (char *)&sym, sizeof(sym));
	if (ret != 0)
	{
        fprintf(stderr, "%s %d %s get dynsym error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	Elf64_Shdr dynstrsection = sections[dynstrindex];

    fprintf(stderr, "%s %d %s ok get dynstr section header offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), __FUNCTION__, __LINE__, dynstrsection.sh_offset, dynstrsection.sh_size);
	char dynstr[dynstrsection.sh_size];
	ret = cross_proc_read(pid, (char *)(startaddr + dynstrsection.sh_offset), dynstr, sizeof(dynstr));
	if (ret != 0)
	{
        fprintf(stderr, "%s %d %s get dynstr error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	int symfuncindex = -1;
	for (int i = 0; i < (int)(dynsymsection.sh_size / sizeof(Elf64_Sym)); ++i)
	{
		Elf64_Sym &s = sym[i];
		std::string name = &dynstr[s.st_name];
		if (name == funname)
		{
			symfuncindex = i;
			break;
		}
	}

	if (symfuncindex < 0)
	{
		fprintf(stderr, "%s %d %s %s not found in .dynsym\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str());
		return false;
	}

	Elf64_Sym &targetsym = sym[symfuncindex];
	if (targetsym.st_shndx != SHN_UNDEF && targetsym.st_value != 0 && targetsym.st_size != 0)
	{
		Elf64_Shdr &s = sections[targetsym.st_shndx];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".text")
		{
			void *func = (void *)(startaddr + targetsym.st_value);
			fprintf(stderr, "%s %d %s %s target text func addr %p\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str(), func);
			funcaddr_plt = 0;
			funcaddr = func;
			return true;
		}
		else
		{
			fprintf(stderr, "%s %d %s %s target not text %s\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str(), name.c_str());
		}
	}

	Elf64_Shdr &relapltsection = sections[relapltindex];
	fprintf(stderr, "%s %d %s ok get relapltsection section header offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), __FUNCTION__, __LINE__, relapltsection.sh_offset, relapltsection.sh_size);

	Elf64_Rela rela[relapltsection.sh_size / sizeof(Elf64_Rela)];
	ret = cross_proc_read(pid, (char *)(startaddr + relapltsection.sh_offset), (char *)&rela, sizeof(rela));
	if (ret != 0)
	{
        fprintf(stderr, "%s %d %s get rela error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	int relafuncindex = -1;
	for (int i = 0; i < (int)(relapltsection.sh_size / sizeof(Elf64_Rela)); ++i)
	{
		Elf64_Rela &r = rela[i];
		if ((int)ELF64_R_SYM(r.r_info) == symfuncindex)
		{
			relafuncindex = i;
			break;
		}
	}

	if (relafuncindex < 0)
	{
        fprintf(stderr, "%s %d %s %s not found in .rela.plt\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str());
		return false;
	}

	Elf64_Rela &relafunc = rela[relafuncindex];
    fprintf(stderr, "%s %d %s %s found in .rela.plt relafuncindex:%d, offset:%ld", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str(), relafuncindex, relafunc.r_offset);

	void *func;

	ret = cross_proc_read(pid, (char *)(startaddr + relafunc.r_offset), (char *)&func, sizeof(func));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d %s %s get relafunc error\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str());
		return false;
	}

	funcaddr_plt = (void *)(startaddr + relafunc.r_offset);
	funcaddr = func;

	fprintf(stderr, "%s %d %s %s succ get got:%p, func:%p\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str(), funcaddr_plt, func);

	return true;

}

bool find_so_func_addr_by_file(int pid, const std::string &sopath, const std::string &funname, void *&funcaddr_plt, void *&funcaddr, int sofd)
{
	int pos = sopath.find_last_of("/");
	std::string soname = sopath;
	if (-1 != pos)
	{
		soname = sopath.substr(pos + 1);
	}

	uint64_t sobeginvalue, soendvalue;
	if (!find_elf_addr(pid, soname.c_str(), "r-xp", sobeginvalue, soendvalue))
	{
		fprintf(stderr, "%s %d find %s addr error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	fprintf(stderr, "%s %d find %s addr succ sobeginvalue %lx, soendvalue %lx\n", __FUNCTION__, __LINE__, soname.c_str(), sobeginvalue, soendvalue);

	Elf64_Ehdr targetso;
	int ret = cross_proc_read(pid, (char *)sobeginvalue, (char *)&targetso, sizeof(targetso));

	if (ret != 0)
	{
		fprintf(stderr, "%s %d %s cross_proc_read error addr:%lx, size:%lx\n", __FUNCTION__, __LINE__, soname.c_str(), sobeginvalue, sizeof(targetso));
		return false;
	}

    if (targetso.e_ident[EI_MAG0] != ELFMAG0 ||
        targetso.e_ident[EI_MAG1] != ELFMAG1 ||
        targetso.e_ident[EI_MAG2] != ELFMAG2 ||
        targetso.e_ident[EI_MAG3] != ELFMAG3)
	{
        fprintf(stderr, "%s %d not valid elf header /proc/%d/maps %lu\n", __FUNCTION__, __LINE__, pid, sobeginvalue);
        return false;
    }

    fprintf(stderr, "%s %d read head ok %lx, e_shoff:%lu, e_shnum:%d, e_shentsize:%d, e_shstrndx:%d\n", __FUNCTION__, __LINE__, sobeginvalue, targetso.e_shoff, targetso.e_shnum, targetso.e_shentsize, targetso.e_shstrndx);

	struct stat st;
	ret = fstat(sofd, &st);
	if (ret < 0)
	{
        fprintf(stderr, "%s %d fstat fail %s %d\n", __FUNCTION__, __LINE__, sopath.c_str(), sofd);
        return false;
	}

	int sofilelen = st.st_size;

	char *sofileaddr = (char *)mmap(NULL, sofilelen, PROT_READ, MAP_PRIVATE, sofd, 0);

	if (sofileaddr == MAP_FAILED)
	{
		fprintf(stderr, "%s %d mmap fail %s %d\n", __FUNCTION__, __LINE__, sopath.c_str(), sofd);
		return false;
	}

	if (memcmp(sofileaddr, &targetso, sizeof(targetso)) != 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d mmap diff %s %d\n", __FUNCTION__, __LINE__, sopath.c_str(), sofd);
		return false;
	}

	Elf64_Shdr sections[targetso.e_shnum];
	memcpy(&sections, sofileaddr + targetso.e_shoff, sizeof(sections));

	Elf64_Shdr &shsection = sections[targetso.e_shstrndx];

	fprintf(stderr, "%s %d section header string table offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, shsection.sh_offset, shsection.sh_size);

	char shsectionname[shsection.sh_size];
	memcpy(shsectionname, sofileaddr + shsection.sh_offset, sizeof(shsectionname));

	int pltindex = -1;
	int dynsymindex = -1;
	int dynstrindex = -1;
	int relapltindex = -1;
	for (int i = 0; i < targetso.e_shnum; ++i)
	{
		Elf64_Shdr &s = sections[i];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".plt")
		{
			pltindex = i;
			continue;
		}
		if (name == ".dynsym")
		{
			dynsymindex = i;
			continue;
		}
		if (name == ".dynstr")
		{
			dynstrindex = i;
			continue;
		}
		if (name == ".rela.plt")
		{
			relapltindex = i;
			continue;
		}
	}

	if (pltindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find .plt %s\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	if (dynsymindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find .dynsym %s\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	if (dynstrindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find .dynstr %s\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	if (relapltindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find .rel.plt %s\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	Elf64_Shdr &pltsection = sections[pltindex];
	fprintf(stderr, "%s %d pltindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, pltindex, pltsection.sh_offset, pltsection.sh_size);

	Elf64_Shdr &dynsymsection = sections[dynsymindex];
    Elf64_Sym sym[dynsymsection.sh_size / sizeof(Elf64_Sym)];
    memcpy(&sym, sofileaddr + dynsymsection.sh_offset, sizeof(sym));
	fprintf(stderr, "%s %d dynsymindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, dynsymindex, dynsymsection.sh_offset, dynsymsection.sh_size);

	Elf64_Shdr &dynstrsection = sections[dynstrindex];
    char dynstr[dynstrsection.sh_size];
    memcpy(dynstr, sofileaddr + dynstrsection.sh_offset, sizeof(dynstr));

	fprintf(stderr, "%s %d dynstrindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, dynstrindex, dynstrsection.sh_offset, dynstrsection.sh_size);

	int symfuncindex = -1;
	for (int i = 0; i < (int)(dynsymsection.sh_size / sizeof(Elf64_Sym)); ++i)
	{
		Elf64_Sym &s = sym[i];
		std::string name = &dynstr[s.st_name];
		if (name == funname)
		{
			symfuncindex = i;
			break;
		}
	}
	if (symfuncindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find in dynsym %s %s\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str());
		return false;
	}

	Elf64_Sym &targetsym = sym[symfuncindex];
	if (targetsym.st_shndx != SHN_UNDEF && targetsym.st_value != 0 && targetsym.st_size != 0)
	{
		Elf64_Shdr &s = sections[targetsym.st_shndx];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".text")
		{
			munmap(sofileaddr, sofilelen);
			void *func = (void *)(sobeginvalue + targetsym.st_value);
			fprintf(stderr, "%s %d find func succ %s %s %p\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str(), func);
			funcaddr_plt = 0;
			funcaddr = func;
			return true;
		}
		else
		{
			fprintf(stderr, "%s %d %s %s target not text %s\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str(), name.c_str());
		}

	}

	Elf64_Shdr &relapltsection = sections[relapltindex];

	fprintf(stderr, "%s %d relapltindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, relapltindex, relapltsection.sh_offset, relapltsection.sh_size);

	Elf64_Rela rela[relapltsection.sh_size / sizeof(Elf64_Rela)];

	memcpy(&rela, sofileaddr + relapltsection.sh_offset, sizeof(rela));

	int relafuncindex = -1;
	for (int i = 0; i < (int)(relapltsection.sh_size / sizeof(Elf64_Rela)); ++i)
	{
		Elf64_Rela &r = rela[i];
		if ((int)ELF64_R_SYM(r.r_info) == symfuncindex)
		{
			relafuncindex = i;
			break;
		}
	}

	if (relafuncindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find in dynsym %s %s\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str());
		return false;
	}

	Elf64_Rela &relafunc = rela[relafuncindex];
	fprintf(stderr, "%s %d %s %s relafuncindex: %d, relafun offset:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str(), relafuncindex, relafunc.r_offset);

	void *func;
	ret = cross_proc_read(pid, (char *)(sobeginvalue + relafunc.r_offset), (char *)&func, sizeof(func));
	if (0 != ret)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d cross_proc_read error %lx %d\n", __FUNCTION__, __LINE__, sobeginvalue + relafunc.r_offset, ret);
		return false;
	}

	funcaddr_plt = (void *)(sobeginvalue + relafunc.r_offset);
	funcaddr = func;

	fprintf(stderr, "%s %d %s %s find succ in plt %lx, old func: %p\n", __FUNCTION__, __LINE__, soname.c_str(), funname.c_str(), funcaddr_plt, func);
	
	munmap(sofileaddr, sofilelen);
	return true;
}

bool find_elf_fun_addr_by_file(int pid, const std::string &elfpath, const std::string &funcname, void *&funcaddr_plt, void *&funcaddr, int elffd)
{
	int pos = elfpath.find_last_of("/");
	std::string elfname = elfpath;
	if (-1 != pos)
	{
		elfname = elfpath.substr(pos + 1);
	}

	uint64_t elfbeginvalue, elfendvalue;
	if (!find_elf_addr(pid, elfname.c_str(), "r-xp", elfbeginvalue, elfendvalue))
	{
		fprintf(stderr, "%s %d find %s addr error\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	fprintf(stderr, "%s %d find %s addr succ elfbeginvalue %lx, elfendvalue %lx\n", __FUNCTION__, __LINE__, elfname.c_str(), elfbeginvalue, elfendvalue);

	Elf64_Ehdr targetelf;
	int ret = cross_proc_read(pid, (char *)elfbeginvalue, (char *)&targetelf, sizeof(targetelf));

	if (ret != 0)
	{
		fprintf(stderr, "%s %d %s cross_proc_read error addr:%lx, size:%lx\n", __FUNCTION__, __LINE__, elfname.c_str(), elfbeginvalue, sizeof(targetelf));
		return false;
	}

    if (targetelf.e_ident[EI_MAG0] != ELFMAG0 ||
        targetelf.e_ident[EI_MAG1] != ELFMAG1 ||
        targetelf.e_ident[EI_MAG2] != ELFMAG2 ||
        targetelf.e_ident[EI_MAG3] != ELFMAG3)
	{
        fprintf(stderr, "%s %d not valid elf header /proc/%d/maps %lu\n", __FUNCTION__, __LINE__, pid, elfbeginvalue);
        return false;
    }

    fprintf(stderr, "%s %d read head ok %lx, e_shoff:%lu, e_shnum:%d, e_shentsize:%d, e_shstrndx:%d\n", __FUNCTION__, __LINE__, elfbeginvalue, targetelf.e_shoff, targetelf.e_shnum, targetelf.e_shentsize, targetelf.e_shstrndx);

	struct stat st;
	ret = fstat(elffd, &st);
	if (ret < 0)
	{
        fprintf(stderr, "%s %d fstat fail %s %d\n", __FUNCTION__, __LINE__, elfpath.c_str(), elffd);
        return false;
	}

	int elffilelen = st.st_size;

	char *elffileaddr = (char *)mmap(NULL, elffilelen, PROT_READ, MAP_PRIVATE, elffd, 0);

	if (elffileaddr == MAP_FAILED)
	{
		fprintf(stderr, "%s %d mmap fail %s %d\n", __FUNCTION__, __LINE__, elfpath.c_str(), elffd);
		return false;
	}

	if (memcmp(elffileaddr, &targetelf, sizeof(targetelf)) != 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d mmap diff %s %d\n", __FUNCTION__, __LINE__, elfpath.c_str(), elffd);
		return false;
	}

	Elf64_Shdr sections[targetelf.e_shnum];
	memcpy(&sections, elffileaddr + targetelf.e_shoff, sizeof(sections));

	Elf64_Shdr &shsection = sections[targetelf.e_shstrndx];

	fprintf(stderr, "%s %d section header string table offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, shsection.sh_offset, shsection.sh_size);

	char shsectionname[shsection.sh_size];
	memcpy(shsectionname, elffileaddr + shsection.sh_offset, sizeof(shsectionname));

	int pltindex = -1;
	int dynsymindex = -1;
	int dynstrindex = -1;
	int relapltindex = -1;
	for (int i = 0; i < targetelf.e_shnum; ++i)
	{
		Elf64_Shdr &s = sections[i];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".plt")
		{
			pltindex = i;
			continue;
		}
		if (name == ".dynsym")
		{
			dynsymindex = i;
			continue;
		}
		if (name == ".dynstr")
		{
			dynstrindex = i;
			continue;
		}
		if (name == ".rela.plt")
		{
			relapltindex = i;
			continue;
		}
	}

	if (pltindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .plt %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	if (dynsymindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .dynsym %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	if (dynstrindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .dynstr %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	if (relapltindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .rel.plt %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	Elf64_Shdr &pltsection = sections[pltindex];
	fprintf(stderr, "%s %d pltindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, pltindex, pltsection.sh_offset, pltsection.sh_size);

	Elf64_Shdr &dynsymsection = sections[dynsymindex];
    Elf64_Sym sym[dynsymsection.sh_size / sizeof(Elf64_Sym)];
    memcpy(&sym, elffileaddr + dynsymsection.sh_offset, sizeof(sym));
	fprintf(stderr, "%s %d dynsymindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, dynsymindex, dynsymsection.sh_offset, dynsymsection.sh_size);

	Elf64_Shdr &dynstrsection = sections[dynstrindex];
    char dynstr[dynstrsection.sh_size];
    memcpy(dynstr, elffileaddr + dynstrsection.sh_offset, sizeof(dynstr));

	fprintf(stderr, "%s %d dynstrindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, dynstrindex, dynstrsection.sh_offset, dynstrsection.sh_size);

	int symfuncindex = -1;
	for (int i = 0; i < (int)(dynsymsection.sh_size / sizeof(Elf64_Sym)); ++i)
	{
		Elf64_Sym &s = sym[i];
		std::string name = &dynstr[s.st_name];
		if (name == funcname)
		{
			symfuncindex = i;
			break;
		}
	}
	if (symfuncindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find in dynsym %s %s\n", __FUNCTION__, __LINE__, elfname.c_str(), funcname.c_str());
		return false;
	}

	Elf64_Sym &targetsym = sym[symfuncindex];
	if (targetsym.st_shndx != SHN_UNDEF && targetsym.st_value != 0 && targetsym.st_size != 0)
	{
		Elf64_Shdr &s = sections[targetsym.st_shndx];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".text")
		{
			munmap(elffileaddr, elffilelen);
			void *func = (void *)(targetsym.st_value);
			fprintf(stderr, "%s %d find func succ %s %s %p\n", __FUNCTION__, __LINE__, elfname.c_str(), funcname.c_str(), func);
			funcaddr_plt = 0;
			funcaddr = func;
			return true;
		}
		else
		{
			fprintf(stderr, "%s %d %s %s target not text %s\n", __FUNCTION__, __LINE__, elfname.c_str(), funcname.c_str(), name.c_str());
		}

	}

	Elf64_Shdr &relapltsection = sections[relapltindex];

	fprintf(stderr, "%s %d relapltindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, relapltindex, relapltsection.sh_offset, relapltsection.sh_size);

	Elf64_Rela rela[relapltsection.sh_size / sizeof(Elf64_Rela)];

	memcpy(&rela, elffileaddr + relapltsection.sh_offset, sizeof(rela));

	int relafuncindex = -1;
	for (int i = 0; i < (int)(relapltsection.sh_size / sizeof(Elf64_Rela)); ++i)
	{
		Elf64_Rela &r = rela[i];
		if ((int)ELF64_R_SYM(r.r_info) == symfuncindex)
		{
			relafuncindex = i;
			break;
		}
	}

	if (relafuncindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find in dynsym %s %s\n", __FUNCTION__, __LINE__, elfname.c_str(), funcname.c_str());
		return false;
	}

	Elf64_Rela &relafunc = rela[relafuncindex];
	fprintf(stderr, "%s %d %s %s relafuncindex: %d, relafun offset:%ld\n", __FUNCTION__, __LINE__, elfname.c_str(), funcname.c_str(), relafuncindex, relafunc.r_offset);

	void *func;
	ret = cross_proc_read(pid, (char *)(relafunc.r_offset), (char *)&func, sizeof(func));
	if (0 != ret)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d cross_proc_read error %lx %d\n", __FUNCTION__, __LINE__, elfbeginvalue + relafunc.r_offset, ret);
		return false;
	}

	funcaddr_plt = (void *)(uint64_t)relafunc.r_offset;
	funcaddr = func;

	fprintf(stderr, "%s %d %s %s find succ in plt %lx, old func: %p\n", __FUNCTION__, __LINE__, elfname.c_str(), funcname.c_str(), funcaddr_plt, func);
	
	munmap(elffileaddr, elffilelen);
	return true;
}

bool find_so_variable_addr_by_mem(int pid, const std::string &soname, const std::string &variablename, void *&variableaddr_got, void *&variableaddr)
{
	unsigned long startaddr;
	unsigned long endaddr;
	if (!find_elf_addr(pid, soname.c_str(), "r-xp", startaddr, endaddr))
	{
		fprintf(stderr, "%s %d find %s addr error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	Elf64_Ehdr targetso;
	int ret = cross_proc_read(pid, (char *)startaddr, (char *)&targetso, sizeof(targetso));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d get %s elf header data error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}
	if (targetso.e_ident[EI_MAG0] != ELFMAG0 ||
			targetso.e_ident[EI_MAG1] != ELFMAG1 ||
			targetso.e_ident[EI_MAG2] != ELFMAG2 ||
			targetso.e_ident[EI_MAG3] != ELFMAG3)
	{
		fprintf(stderr, "%s %d %s elf header magic error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	fprintf(stderr, "%s %d %p read head ok startaddr:%lu, e_she_shoff:%lu, e_shnum:%d, e_shentsize:%d, e_shstrndx:%d\n", __FUNCTION__, __LINE__, startaddr, targetso.e_shoff, targetso.e_shnum, targetso.e_shentsize, targetso.e_shstrndx);

	Elf64_Shdr sections[targetso.e_shnum];
	ret = cross_proc_read(pid, (char *)(startaddr + targetso.e_shoff), (char *)&sections, sizeof(sections));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d get %s section header data error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	Elf64_Shdr &shsection = sections[targetso.e_shstrndx];
	fprintf(stderr, "%s %d %s section strtable offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), shsection.sh_offset, shsection.sh_size);
	char shsectionname[shsection.sh_size];
	ret = cross_proc_read(pid, (char *)(startaddr + shsection.sh_offset), shsectionname, sizeof(shsectionname));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d get %s section header name error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	int gotindex = -1;
	int dynsymindex = -1;
	int dynstrindex = -1;
	int reladynindex = -1;
	for (int i = 0; i < targetso.e_shnum; ++i)
	{
		Elf64_Shdr &s = sections[i];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".got")
		{
			gotindex = i;
			continue;
		}
		if (name == ".dynsym")
		{
			dynsymindex = i;
			continue;
		}
		if (name == ".dynstr")
		{
			dynstrindex = i;
			continue;
		}
		if (name == ".rela.dyn")
		{
			reladynindex = i;
			continue;
		}
	}
    if (gotindex < 0)
	{
        fprintf(stderr, "%s %d not find .got %s\n", __FUNCTION__, __LINE__, soname.c_str());
        return false;
    }
    if (dynsymindex < 0)
	{
        fprintf(stderr, "%s %d not find .dynsym %s\n", __FUNCTION__, __LINE__, soname.c_str());
        return false;
    }
    if (dynstrindex < 0)
	{
        fprintf(stderr, "%s %d not find .dynstr %s\n", __FUNCTION__, __LINE__, soname.c_str());
        return false;
    }
    if (reladynindex < 0)
	{
        fprintf(stderr, "%s %d not find .rel.dyn %s\n", __FUNCTION__, __LINE__, soname.c_str());
        return false;
    }

	Elf64_Shdr gotsection = sections[gotindex];
    fprintf(stderr, "%s %d %s ok get got section header offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), gotsection.sh_offset, gotsection.sh_size);

	Elf64_Shdr dynsymsection = sections[dynsymindex];
    fprintf(stderr, "%s %d %s ok get dynsym section header offset:%ld, size:%ld", __FUNCTION__, __LINE__, soname.c_str(), dynsymsection.sh_offset, dynsymsection.sh_size);

	Elf64_Sym sym[dynsymsection.sh_size / sizeof(Elf64_Sym)];
	ret = cross_proc_read(pid, (char *)(startaddr + dynsymsection.sh_offset), (char *)&sym, sizeof(sym));
	if (ret != 0)
	{
        fprintf(stderr, "%s %d %s get dynsym error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	Elf64_Shdr dynstrsection = sections[dynstrindex];

    fprintf(stderr, "%s %d %s ok get dynstr section header offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), __FUNCTION__, __LINE__, dynstrsection.sh_offset, dynstrsection.sh_size);
	char dynstr[dynstrsection.sh_size];
	ret = cross_proc_read(pid, (char *)(startaddr + dynstrsection.sh_offset), dynstr, sizeof(dynstr));
	if (ret != 0)
	{
        fprintf(stderr, "%s %d %s get dynstr error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	int symvarindex = -1;
	for (int i = 0; i < (int)(dynsymsection.sh_size / sizeof(Elf64_Sym)); ++i)
	{
		Elf64_Sym &s = sym[i];
		std::string name = &dynstr[s.st_name];
		if (name == variablename)
		{
			symvarindex = i;
			break;
		}
	}

	if (symvarindex < 0)
	{
		fprintf(stderr, "%s %d %s %s not found in .dynsym\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str());
		return false;
	}

	Elf64_Sym &targetsym = sym[symvarindex];
	if (targetsym.st_shndx != SHN_UNDEF && targetsym.st_value != 0 && targetsym.st_size != 0)
	{
		Elf64_Shdr &s = sections[targetsym.st_shndx];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".data" || name == ".bss" || name == ".rodata")
		{
			void *variable = (void *)(startaddr + targetsym.st_value);
			fprintf(stderr, "%s %d %s %s target data variable addr %p\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str(), variable);
			variableaddr_got = 0;
			variableaddr = variable;
			return true;
		}
		else
		{
			fprintf(stderr, "%s %d %s %s target not data %s\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str(), name.c_str());
		}
	}

	Elf64_Shdr &reladynsection = sections[reladynindex];
	fprintf(stderr, "%s %d %s ok get reladynsection section header offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), __FUNCTION__, __LINE__, reladynsection.sh_offset, reladynsection.sh_size);

	Elf64_Rela rela[reladynsection.sh_size / sizeof(Elf64_Rela)];
	ret = cross_proc_read(pid, (char *)(startaddr + reladynsection.sh_offset), (char *)&rela, sizeof(rela));
	if (ret != 0)
	{
        fprintf(stderr, "%s %d %s get rela error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	int relavarindex = -1;
	for (int i = 0; i < (int)(reladynsection.sh_size / sizeof(Elf64_Rela)); ++i)
	{
		Elf64_Rela &r = rela[i];
		if ((int)ELF64_R_SYM(r.r_info) == symvarindex)
		{
			relavarindex = i;
			break;
		}
	}

	if (relavarindex < 0)
	{
        fprintf(stderr, "%s %d %s %s not found in .rela.dyn\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str());
		return false;
	}

	Elf64_Rela &relavar = rela[relavarindex];
    fprintf(stderr, "%s %d %s %s found in .rela.dyn relafuncindex:%d, offset:%ld", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str(), relavarindex, relavar.r_offset);

	void *variable;

	ret = cross_proc_read(pid, (char *)(startaddr + relavar.r_offset), (char *)&variable, sizeof(variable));
	if (ret != 0)
	{
		fprintf(stderr, "%s %d %s %s get reladyn error\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str());
		return false;
	}

	variableaddr_got = (void *)(startaddr + relavar.r_offset);
	variableaddr = variable;

	fprintf(stderr, "%s %d %s %s succ get got:%p, variableaddr:%p\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str(), variableaddr_got, variableaddr);

	return true;
}

bool find_so_variable_addr_by_file(int pid, const std::string &sopath, const std::string &variablename, void *&variableaddr_got, void *&variableaddr, int sofd)
{
	int pos = sopath.find_last_of("/");
	std::string soname = sopath;
	if (-1 != pos)
	{
		soname = sopath.substr(pos + 1);
	}

	uint64_t sobeginvalue, soendvalue;
	if (!find_elf_addr(pid, soname.c_str(), "r-xp", sobeginvalue, soendvalue))
	{
		fprintf(stderr, "%s %d find %s addr error\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	fprintf(stderr, "%s %d find %s addr succ sobeginvalue %lx, soendvalue %lx\n", __FUNCTION__, __LINE__, soname.c_str(), sobeginvalue, soendvalue);

	Elf64_Ehdr targetso;
	int ret = cross_proc_read(pid, (char *)sobeginvalue, (char *)&targetso, sizeof(targetso));

	if (ret != 0)
	{
		fprintf(stderr, "%s %d %s cross_proc_read error addr:%lx, size:%lx\n", __FUNCTION__, __LINE__, soname.c_str(), sobeginvalue, sizeof(targetso));
		return false;
	}

    if (targetso.e_ident[EI_MAG0] != ELFMAG0 ||
        targetso.e_ident[EI_MAG1] != ELFMAG1 ||
        targetso.e_ident[EI_MAG2] != ELFMAG2 ||
        targetso.e_ident[EI_MAG3] != ELFMAG3)
	{
        fprintf(stderr, "%s %d not valid elf header /proc/%d/maps %lu\n", __FUNCTION__, __LINE__, pid, sobeginvalue);
        return false;
    }

    fprintf(stderr, "%s %d read head ok %lx, e_shoff:%lu, e_shnum:%d, e_shentsize:%d, e_shstrndx:%d\n", __FUNCTION__, __LINE__, sobeginvalue, targetso.e_shoff, targetso.e_shnum, targetso.e_shentsize, targetso.e_shstrndx);

	struct stat st;
	ret = fstat(sofd, &st);
	if (ret < 0)
	{
        fprintf(stderr, "%s %d fstat fail %s %d\n", __FUNCTION__, __LINE__, sopath.c_str(), sofd);
        return false;
	}

	int sofilelen = st.st_size;

	char *sofileaddr = (char *)mmap(NULL, sofilelen, PROT_READ, MAP_PRIVATE, sofd, 0);

	if (sofileaddr == MAP_FAILED)
	{
		fprintf(stderr, "%s %d mmap fail %s %d\n", __FUNCTION__, __LINE__, sopath.c_str(), sofd);
		return false;
	}

	if (memcmp(sofileaddr, &targetso, sizeof(targetso)) != 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d mmap diff %s %d\n", __FUNCTION__, __LINE__, sopath.c_str(), sofd);
		return false;
	}

	Elf64_Shdr sections[targetso.e_shnum];
	memcpy(&sections, sofileaddr + targetso.e_shoff, sizeof(sections));

	Elf64_Shdr &shsection = sections[targetso.e_shstrndx];

	fprintf(stderr, "%s %d section header string table offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, shsection.sh_offset, shsection.sh_size);

	char shsectionname[shsection.sh_size];
	memcpy(shsectionname, sofileaddr + shsection.sh_offset, sizeof(shsectionname));

	int gotindex = -1;
	int dynsymindex = -1;
	int dynstrindex = -1;
	int reladynindex = -1;
	for (int i = 0; i < targetso.e_shnum; ++i)
	{
		Elf64_Shdr &s = sections[i];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".got")
		{
			gotindex = i;
			continue;
		}
		if (name == ".dynsym")
		{
			dynsymindex = i;
			continue;
		}
		if (name == ".dynstr")
		{
			dynstrindex = i;
			continue;
		}
		if (name == ".rela.dyn")
		{
			reladynindex = i;
			continue;
		}
	}

	if (gotindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find .got %s\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	if (dynsymindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find .dynsym %s\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	if (dynstrindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find .dynstr %s\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	if (reladynindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find .rel.got %s\n", __FUNCTION__, __LINE__, soname.c_str());
		return false;
	}

	Elf64_Shdr &gotsection = sections[gotindex];
	fprintf(stderr, "%s %d gotindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, gotindex, gotsection.sh_offset, gotsection.sh_size);

	Elf64_Shdr &dynsymsection = sections[dynsymindex];
    Elf64_Sym sym[dynsymsection.sh_size / sizeof(Elf64_Sym)];
    memcpy(&sym, sofileaddr + dynsymsection.sh_offset, sizeof(sym));
	fprintf(stderr, "%s %d dynsymindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, dynsymindex, dynsymsection.sh_offset, dynsymsection.sh_size);

	Elf64_Shdr &dynstrsection = sections[dynstrindex];
    char dynstr[dynstrsection.sh_size];
    memcpy(dynstr, sofileaddr + dynstrsection.sh_offset, sizeof(dynstr));

	fprintf(stderr, "%s %d dynstrindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, dynstrindex, dynstrsection.sh_offset, dynstrsection.sh_size);

	int symvarindex = -1;
	for (int i = 0; i < (int)(dynsymsection.sh_size / sizeof(Elf64_Sym)); ++i)
	{
		Elf64_Sym &s = sym[i];
		std::string name = &dynstr[s.st_name];
		if (name == variablename)
		{
			symvarindex = i;
			break;
		}
	}
	if (symvarindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find in dynsym %s %s\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str());
		return false;
	}

	Elf64_Sym &targetsym = sym[symvarindex];
	if (targetsym.st_shndx != SHN_UNDEF && targetsym.st_value != 0 && targetsym.st_size != 0)
	{
		Elf64_Shdr &s = sections[targetsym.st_shndx];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".data" || name == ".bss" || name == ".rodata")
		{
			munmap(sofileaddr, sofilelen);
			void *variable = (void *)(sobeginvalue + targetsym.st_value);
			fprintf(stderr, "%s %d find variable succ %s %s %p\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str(), variable);
			variableaddr_got = 0;
			variableaddr = variable;
			return true;
		}
		else
		{
			fprintf(stderr, "%s %d %s %s target not data %s\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str(), name.c_str());
		}

	}

	Elf64_Shdr &reladynsection = sections[reladynindex];

	fprintf(stderr, "%s %d reladynindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, reladynindex, reladynsection.sh_offset, reladynsection.sh_size);

	Elf64_Rela rela[reladynsection.sh_size / sizeof(Elf64_Rela)];

	memcpy(&rela, sofileaddr + reladynsection.sh_offset, sizeof(rela));

	int relavarindex = -1;
	for (int i = 0; i < (int)(reladynsection.sh_size / sizeof(Elf64_Rela)); ++i)
	{
		Elf64_Rela &r = rela[i];
		if ((int)ELF64_R_SYM(r.r_info) == symvarindex)
		{
			relavarindex = i;
			break;
		}
	}

	if (relavarindex < 0)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d not find in dynsym %s %s\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str());
		return false;
	}

	Elf64_Rela &relavar = rela[relavarindex];
	fprintf(stderr, "%s %d %s %s relaavrindex: %d, relafun offset:%ld\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str(), relavarindex, relavar.r_offset);

	void *variable;
	ret = cross_proc_read(pid, (char *)(sobeginvalue + relavar.r_offset), (char *)&variable, sizeof(variable));
	if (0 != ret)
	{
		munmap(sofileaddr, sofilelen);
		fprintf(stderr, "%s %d cross_proc_read error %lx %d\n", __FUNCTION__, __LINE__, sobeginvalue + relavar.r_offset, ret);
		return false;
	}

	variableaddr_got = (void *)(sobeginvalue + relavar.r_offset);
	variableaddr = variable;

	fprintf(stderr, "%s %d %s %s find succ in got %lx, old addr: %p\n", __FUNCTION__, __LINE__, soname.c_str(), variablename.c_str(), variableaddr_got, variableaddr);
	
	munmap(sofileaddr, sofilelen);
	return true;
}

bool find_elf_variable_addr_by_file(int pid, const std::string &elfpath, const std::string &variablename, void *&variableaddr_got, void *&variableaddr, int elffd)
{
	int pos = elfpath.find_last_of("/");
	std::string elfname = elfpath;
	if (-1 != pos)
	{
		elfname = elfpath.substr(pos + 1);
	}

	uint64_t elfbeginvalue, elfendvalue;
	if (!find_elf_addr(pid, elfname.c_str(), "r-xp", elfbeginvalue, elfendvalue))
	{
		fprintf(stderr, "%s %d find %s addr error\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	fprintf(stderr, "%s %d find %s addr succ elfbeginvalue %lx, elfendvalue %lx\n", __FUNCTION__, __LINE__, elfname.c_str(), elfbeginvalue, elfendvalue);

	Elf64_Ehdr targetelf;
	int ret = cross_proc_read(pid, (char *)elfbeginvalue, (char *)&targetelf, sizeof(targetelf));

	if (ret != 0)
	{
		fprintf(stderr, "%s %d %s cross_proc_read error addr:%lx, size:%lx\n", __FUNCTION__, __LINE__, elfname.c_str(), elfbeginvalue, sizeof(targetelf));
		return false;
	}

    if (targetelf.e_ident[EI_MAG0] != ELFMAG0 ||
        targetelf.e_ident[EI_MAG1] != ELFMAG1 ||
        targetelf.e_ident[EI_MAG2] != ELFMAG2 ||
        targetelf.e_ident[EI_MAG3] != ELFMAG3)
	{
        fprintf(stderr, "%s %d not valid elf header /proc/%d/maps %lu\n", __FUNCTION__, __LINE__, pid, elfbeginvalue);
        return false;
    }

    fprintf(stderr, "%s %d read head ok %lx, e_shoff:%lu, e_shnum:%d, e_shentsize:%d, e_shstrndx:%d\n", __FUNCTION__, __LINE__, elfbeginvalue, targetelf.e_shoff, targetelf.e_shnum, targetelf.e_shentsize, targetelf.e_shstrndx);

	struct stat st;
	ret = fstat(elffd, &st);
	if (ret < 0)
	{
        fprintf(stderr, "%s %d fstat fail %s %d\n", __FUNCTION__, __LINE__, elfpath.c_str(), elffd);
        return false;
	}

	int elffilelen = st.st_size;

	char *elffileaddr = (char *)mmap(NULL, elffilelen, PROT_READ, MAP_PRIVATE, elffd, 0);

	if (elffileaddr == MAP_FAILED)
	{
		fprintf(stderr, "%s %d mmap fail %s %d\n", __FUNCTION__, __LINE__, elfpath.c_str(), elffd);
		return false;
	}

	if (memcmp(elffileaddr, &targetelf, sizeof(targetelf)) != 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d mmap diff %s %d\n", __FUNCTION__, __LINE__, elfpath.c_str(), elffd);
		return false;
	}

	Elf64_Shdr sections[targetelf.e_shnum];
	memcpy(&sections, elffileaddr + targetelf.e_shoff, sizeof(sections));

	Elf64_Shdr &shsection = sections[targetelf.e_shstrndx];

	fprintf(stderr, "%s %d section header string table offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, shsection.sh_offset, shsection.sh_size);

	char shsectionname[shsection.sh_size];
	memcpy(shsectionname, elffileaddr + shsection.sh_offset, sizeof(shsectionname));

	int gotindex = -1;
	int dynsymindex = -1;
	int dynstrindex = -1;
	int reladynindex = -1;
	for (int i = 0; i < targetelf.e_shnum; ++i)
	{
		Elf64_Shdr &s = sections[i];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".got")
		{
			gotindex = i;
			continue;
		}
		if (name == ".dynsym")
		{
			dynsymindex = i;
			continue;
		}
		if (name == ".dynstr")
		{
			dynstrindex = i;
			continue;
		}
		if (name == ".rela.dyn")
		{
			reladynindex = i;
			continue;
		}
	}

	if (gotindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .got %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	if (dynsymindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .dynsym %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	if (dynstrindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .dynstr %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	if (reladynindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .rel.dyn %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	Elf64_Shdr &pltsection = sections[gotindex];
	fprintf(stderr, "%s %d gotindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, gotindex, pltsection.sh_offset, pltsection.sh_size);

	Elf64_Shdr &dynsymsection = sections[dynsymindex];
    Elf64_Sym sym[dynsymsection.sh_size / sizeof(Elf64_Sym)];
    memcpy(&sym, elffileaddr + dynsymsection.sh_offset, sizeof(sym));
	fprintf(stderr, "%s %d dynsymindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, dynsymindex, dynsymsection.sh_offset, dynsymsection.sh_size);

	Elf64_Shdr &dynstrsection = sections[dynstrindex];
    char dynstr[dynstrsection.sh_size];
    memcpy(dynstr, elffileaddr + dynstrsection.sh_offset, sizeof(dynstr));

	fprintf(stderr, "%s %d dynstrindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, dynstrindex, dynstrsection.sh_offset, dynstrsection.sh_size);

	int symvarindex = -1;
	for (int i = 0; i < (int)(dynsymsection.sh_size / sizeof(Elf64_Sym)); ++i)
	{
		Elf64_Sym &s = sym[i];
		std::string name = &dynstr[s.st_name];
		if (name == variablename)
		{
			symvarindex = i;
			break;
		}
	}
	if (symvarindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find in dynsym %s %s\n", __FUNCTION__, __LINE__, elfname.c_str(), variablename.c_str());
		return false;
	}

	Elf64_Sym &targetsym = sym[symvarindex];
	if (targetsym.st_shndx != SHN_UNDEF && targetsym.st_value != 0 && targetsym.st_size != 0)
	{
		Elf64_Shdr &s = sections[targetsym.st_shndx];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".data" || name == ".bss" || name == ".rodata")
		{
			munmap(elffileaddr, elffilelen);
			void *variable = (void *)(targetsym.st_value);
			fprintf(stderr, "%s %d find variable succ %s %s %p\n", __FUNCTION__, __LINE__, elfname.c_str(), variablename.c_str(), variable);
			variableaddr_got = 0;
			variableaddr = variable;
			return true;
		}
		else
		{
			fprintf(stderr, "%s %d %s %s target not data %s\n", __FUNCTION__, __LINE__, elfname.c_str(), variablename.c_str(), name.c_str());
		}

	}

	Elf64_Shdr &reladynsection = sections[reladynindex];

	fprintf(stderr, "%s %d reladynindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, reladynindex, reladynsection.sh_offset, reladynsection.sh_size);

	Elf64_Rela rela[reladynsection.sh_size / sizeof(Elf64_Rela)];

	memcpy(&rela, elffileaddr + reladynsection.sh_offset, sizeof(rela));

	int relavarindex = -1;
	for (int i = 0; i < (int)(reladynsection.sh_size / sizeof(Elf64_Rela)); ++i)
	{
		Elf64_Rela &r = rela[i];
		if ((int)ELF64_R_SYM(r.r_info) == symvarindex)
		{
			relavarindex = i;
			break;
		}
	}

	if (relavarindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find in dynsym %s %s\n", __FUNCTION__, __LINE__, elfname.c_str(), variablename.c_str());
		return false;
	}

	Elf64_Rela &relafunc = rela[relavarindex];
	fprintf(stderr, "%s %d %s %s relavarindex: %d, relafun offset:%ld\n", __FUNCTION__, __LINE__, elfname.c_str(), variablename.c_str(), relavarindex, relafunc.r_offset);

	void *variable;
	ret = cross_proc_read(pid, (char *)(relafunc.r_offset), (char *)&variable, sizeof(variable));
	if (0 != ret)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d cross_proc_read error %lx %d\n", __FUNCTION__, __LINE__, elfbeginvalue + relafunc.r_offset, ret);
		return false;
	}

	variableaddr_got = (void *)(uint64_t)relafunc.r_offset;
	variableaddr = variable;

	fprintf(stderr, "%s %d %s %s find succ in got %lx, old addr: %p\n", __FUNCTION__, __LINE__, elfname.c_str(), variablename.c_str(), variableaddr_got, variableaddr);
	
	munmap(elffileaddr, elffilelen);
	return true;
}

bool find_elf_local_sym_addr_by_file(const std::string &elfpath, const std::string &symname, void *&symaddr, int elffd)
{
	int pos = elfpath.find_last_of("/");
	std::string elfname = elfpath;
	if (-1 != pos)
	{
		elfname = elfpath.substr(pos + 1);
	}

	struct stat st;
	int ret = fstat(elffd, &st);
	if (ret < 0)
	{
        fprintf(stderr, "%s %d fstat fail %s %d\n", __FUNCTION__, __LINE__, elfpath.c_str(), elffd);
        return false;
	}

	int elffilelen = st.st_size;

	char *elffileaddr = (char *)mmap(NULL, elffilelen, PROT_READ, MAP_PRIVATE, elffd, 0);

	if (elffileaddr == MAP_FAILED)
	{
		fprintf(stderr, "%s %d mmap fail %s %d\n", __FUNCTION__, __LINE__, elfpath.c_str(), elffd);
		return false;
	}

	Elf64_Ehdr targetelf;
	memcpy(&targetelf, elffileaddr, sizeof(targetelf));
	if (targetelf.e_ident[EI_MAG0] != ELFMAG0 ||
			targetelf.e_ident[EI_MAG1] != ELFMAG1 ||
			targetelf.e_ident[EI_MAG2] != ELFMAG2 ||
			targetelf.e_ident[EI_MAG3] != ELFMAG3)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not valid elf header %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	Elf64_Shdr sections[targetelf.e_shnum];
	memcpy(&sections, elffileaddr + targetelf.e_shoff, sizeof(sections));

	Elf64_Shdr &shsection = sections[targetelf.e_shstrndx];

	fprintf(stderr, "%s %d section header string table offset:%ld, size:%ld\n", __FUNCTION__, __LINE__, shsection.sh_offset, shsection.sh_size);

	char shsectionname[shsection.sh_size];
	memcpy(shsectionname, elffileaddr + shsection.sh_offset, sizeof(shsectionname));

	int symindex = -1;
	int strindex = -1;
	for (int i = 0; i < targetelf.e_shnum; ++i)
	{
		Elf64_Shdr &s = sections[i];
		std::string name = &shsectionname[s.sh_name];
		if (name == ".symtab")
		{
			symindex = i;
			continue;
		}
		if (name == ".strtab")
		{
			strindex = i;
			continue;
		}
	}

	if (symindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .symtab %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	if (strindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find .strtab %s\n", __FUNCTION__, __LINE__, elfname.c_str());
		return false;
	}

	Elf64_Shdr &symsection = sections[symindex];
    Elf64_Sym sym[symsection.sh_size / sizeof(Elf64_Sym)];
    memcpy(&sym, elffileaddr + symsection.sh_offset, sizeof(sym));
	fprintf(stderr, "%s %d symindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, symindex, symsection.sh_offset, symsection.sh_size);

	Elf64_Shdr &strsection = sections[strindex];
    char str[strsection.sh_size];
    memcpy(str, elffileaddr + strsection.sh_offset, sizeof(str));

	fprintf(stderr, "%s %d strindex:%d, sh_offset:%ld, sh_size:%ld \n", __FUNCTION__, __LINE__, strindex, strsection.sh_offset, strsection.sh_size);

	int symfindindex = -1;
	for (int i = 0; i < (int)(symsection.sh_size / sizeof(Elf64_Sym)); ++i)
	{
		Elf64_Sym &s = sym[i];
		std::string name = &str[s.st_name];
		if (name == symname)
		{
			symfindindex = i;
			break;
		}
	}
	if (symfindindex < 0)
	{
		munmap(elffileaddr, elffilelen);
		fprintf(stderr, "%s %d not find in sym %s %s\n", __FUNCTION__, __LINE__, elfname.c_str(), symname.c_str());
		return false;
	}

	Elf64_Sym &targetsym = sym[symfindindex];
	if (targetsym.st_shndx != SHN_UNDEF && targetsym.st_value != 0 && targetsym.st_size != 0)
	{
		Elf64_Shdr &s = sections[targetsym.st_shndx];
		std::string name = &shsectionname[s.sh_name];
//		if (name == ".data" || name == ".bss" || name == ".rodata" || name == ".text")
		{
			munmap(elffileaddr, elffilelen);
			void *addr = (void *)(targetsym.st_value);
			fprintf(stderr, "%s %d find sym succ %s %s %s %p\n", __FUNCTION__, __LINE__, elfname.c_str(), symname.c_str(), name.c_str(), addr);
			symaddr = addr;
			return true;
		}
	}
	fprintf(stderr, "%s %d find sym fail %s %s\n", __FUNCTION__, __LINE__, elfname.c_str(), symname.c_str());
	munmap(elffileaddr, elffilelen);
	return false;
}
