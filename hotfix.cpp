#include "crossprocess.h"
#include "find_sym_addr.h"
#include "hook.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

void usage()
{
	printf("1 ./hottool hotfix 1 pid elfname symname soname newsymname\n");
	printf("2 ./hottool hotfix 2 pid srcsoname srcsymname dstsoname dtssymname\n");
}

int hottool_hotfix(pid_t pid, int argc, char *argv[], void *&back_got_plt, void *&back_addr)
{
	std::string typestr = argv[2];
	if (typestr == "1" || typestr == "2")
	{
		void *old_funcaddr = NULL;
		void *func_gotplt = NULL;

		int fd = open(argv[4], O_RDONLY);

		if (typestr == "1")
		{
			if (!find_elf_fun_addr_by_file(pid, argv[4], argv[5], func_gotplt, old_funcaddr, fd))
			{
				close(fd);
				fprintf(stderr, "%s %d, %s %s find_elf_fun_addr_by_file error %d\n", __FUNCTION__, __LINE__, argv[4], argv[5], errno);
				return -1;
			}
		}
		else if (typestr == "2")
		{
			if (!find_so_func_addr_by_mem(pid, argv[4], argv[5], func_gotplt, old_funcaddr))
			{
				close(fd);
				fprintf(stderr, "%s %d, %s %s find_so_func_addr_by_mem error %d\n", __FUNCTION__, __LINE__, argv[4], argv[5], errno);
				return -1;
			}
		}
		close(fd);
		fprintf(stderr, "%s %d, %s %s find_elf_fun_addr_by_file succ %p %p\n", __FUNCTION__, __LINE__, argv[4], argv[5], old_funcaddr, func_gotplt);

		uint64_t handle;
		if (!cross_dlopen(pid, argv[6], handle))
		{
			fprintf(stderr, "%s %d, %s cross_dlopen error %d\n", __FUNCTION__, __LINE__, argv[6], errno);
			return -1;
		}
		fprintf(stderr, "%s %d, %s cross_dlopen succ %lu\n", __FUNCTION__, __LINE__, argv[6], handle);

		void *new_gotplt = 0;
		void *new_funcaddr = 0;
		if (!find_so_func_addr_by_mem(pid, argv[6], argv[7], new_gotplt, new_funcaddr))
		{
			cross_dlclose(pid, argv[5], handle);
			fprintf(stderr, "%s %d, %s %s find_so_func_addr_by_mem error %d\n", __FUNCTION__, __LINE__, argv[6], argv[7], errno);
			return -1;
		}
		fprintf(stderr, "%s %d, %s %s find_so_func_addr_by_mem succ %p\n", __FUNCTION__, __LINE__, argv[6], argv[7], new_funcaddr);

		if (NULL == func_gotplt)
		{
			char backupcode[16] = {0};
			if (!hotfix_func64(pid, old_funcaddr, new_funcaddr, backupcode, sizeof(backupcode)))
			{
				cross_dlclose(pid, argv[5], handle);
				fprintf(stderr, "%s %d, hotfix_func64 error %p %p\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr);
				return -1;
			}
			fprintf(stderr, "%s %d, hotfix_func64 succ %p %p\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr);
		}
		else
		{
			uint64_t backupcode;
			if (!hotfix_gotplt(pid, func_gotplt, new_funcaddr, backupcode))
			{
				cross_dlclose(pid, argv[5], handle);
				fprintf(stderr, "%s %d, hotfix_gotplt error %p %p %p %lx\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr, func_gotplt, backupcode);
				return -1;
			}
			fprintf(stderr, "%s %d, hotfix_gotplt succ %p %p %p %lx\n", __FUNCTION__, __LINE__, old_funcaddr, new_funcaddr, func_gotplt, backupcode);
		}
	}
	else
	{
		usage();
		return -1;
	}

		//printf("8 ./hottool hotfix 1 pid elfname symname soname newsymname\n");
	fprintf(stderr, "%s %d, replace succ type: %s, pid :%s, srcelfname:%s, srcsymname:%s, dstelfname:%s, dstsymname:%s\n", __FUNCTION__, __LINE__, argv[2], argv[3], argv[4], argv[5], argv[6], argv[7]);
	return 0;

}

int main(int argc, char *argv[])
{
	printf("%s %d main:%p, printf:%p\n", __FUNCTION__, __LINE__, main, printf);
	if (argc < 3)
	{
		usage();
		return -1;
	}

	bool init_hook_flag = false;
	std::string optstr = argv[1];
	std::string pidstr = argv[3];
	pid_t pid;
	if (pidstr == "self")
	{
		pid = getpid();
	}
	else
	{
		pid = atoi(pidstr.c_str());
		init_hook_env(pid);
		init_hook_flag = true;
	}

	if (optstr == "hotfix")
	{
	//	printf("./hotfix replace 1 pid elfname symname soname newsymname\n");
		void *back_got_plt = NULL;
		void *back_addr = NULL;
		int ret = hottool_hotfix(pid, argc, argv, back_got_plt, back_addr);
		if (0 != ret)
		{
			fprintf(stderr, "%s %d, hotfix failed type: %s, pid :%s, filename:%s, symname:%s\n", __FUNCTION__, __LINE__, argv[2], argv[3], argv[4], argv[5]);
			return ret;
		}

		fprintf(stderr, "%s %d, hotfix succ type: %s, pid :%s, filename:%s, symname:%s, back_got_plt:%p, back_addr:%p\n", __FUNCTION__, __LINE__, argv[2], argv[3], argv[4], argv[5], back_got_plt, back_addr);

	}

	if (init_hook_flag)
	{
		fini_hook_env(pid);
	}

	return 0;
}
