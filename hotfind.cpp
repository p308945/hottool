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
	printf("1 ./hottool find 1 pid soname funcname\n");
	printf("2 ./hottool find 2 pid sopath funcname\n");
	printf("3 ./hottool find 3 pid elfname funcname\n");
	printf("4 ./hottool find 4 pid soname variablename\n");
	printf("5 ./hottool find 5 pid sopath variablename\n");
	printf("6 ./hottool find 6 pid elfname variablename\n");
	printf("7 ./hottool find 7 pid(holder pos ignore) elfname symname\n");
}

int hottool_find(pid_t pid, int argc, char *argv[], void *&got_plt, void *&addr)
{
	std::string typestr = argv[2];
	if (typestr == "1")
	{
		if (!find_so_func_addr_by_mem(pid, argv[4], argv[5], got_plt, addr))
		{
			fprintf(stderr, "%s %d, %s %s find_so_func_addr_by_mem error %d\n", __FUNCTION__, __LINE__, argv[4], argv[5], errno);
			return -1;
		}
	}
	else if (typestr == "2")
	{
		int fd = open(argv[4], O_RDWR);
		if (-1 == fd)
		{
			fprintf(stderr, "%s %d, %s open error \n", __FUNCTION__, __LINE__, argv[4]);
			return -1;
		}
		if (!find_so_func_addr_by_file(pid, argv[4], argv[5], got_plt, addr, fd))
		{
			close(fd);
			fprintf(stderr, "%s %d, %s %s find_so_func_addr_by_file error %d\n", __FUNCTION__, __LINE__, argv[4], argv[5], errno);
			return -1;
		}
		close(fd);
	}
	else if (typestr == "3")
	{
		int fd = open(argv[4], O_RDONLY);
		if (-1 == fd)
		{
			fprintf(stderr, "%s %d, %s open error %d\n", __FUNCTION__, __LINE__, argv[4], errno);
			return -1;
		}

		if (!find_elf_fun_addr_by_file(pid, argv[4], argv[5], got_plt, addr, fd))
		{
			close(fd);
			fprintf(stderr, "%s %d, %s %s find_elf_fun_addr_by_file error %d\n", __FUNCTION__, __LINE__, argv[4], argv[5], errno);
			return -1;
		}

		close(fd);
	}
	else if (typestr == "4")
	{
		if (!find_so_variable_addr_by_mem(pid, argv[4], argv[5], got_plt, addr))
		{
			fprintf(stderr, "%s %d, %s %s find_so_variable_addr_by_mem error %d\n", __FUNCTION__, __LINE__, argv[4], argv[5], errno);
			return -1;
		}
	}
	else if (typestr == "5")
	{
		int fd = open(argv[4], O_RDWR);
		if (-1 == fd)
		{
			fprintf(stderr, "%s %d, %s open error \n", __FUNCTION__, __LINE__, argv[4]);
			return -1;
		}
		if (!find_so_variable_addr_by_file(pid, argv[4], argv[5], got_plt, addr, fd))
		{
			close(fd);
			fprintf(stderr, "%s %d, %s %s find_so_variable_addr_by_file error %d\n", __FUNCTION__, __LINE__, argv[4], argv[5], errno);
			return -1;
		}
		close(fd);
	}
	else if (typestr == "6")
	{
		int fd = open(argv[4], O_RDONLY);
		if (-1 == fd)
		{
			fprintf(stderr, "%s %d, %s open error %d\n", __FUNCTION__, __LINE__, argv[4], errno);
			return -1;
		}

		if (!find_elf_variable_addr_by_file(pid, argv[4], argv[5], got_plt, addr, fd))
		{
			close(fd);
			fprintf(stderr, "%s %d, %s %s find_elf_variable_addr_by_file error %d\n", __FUNCTION__, __LINE__, argv[4], argv[5], errno);
			return -1;
		}
		close(fd);
	}
	else if (typestr == "7")
	{
		int fd = open(argv[4], O_RDONLY);
		if (-1 == fd)
		{
			fprintf(stderr, "%s %d, %s open error %d\n", __FUNCTION__, __LINE__, argv[4], errno);
			return -1;
		}

		if (!find_elf_local_sym_addr_by_file(argv[4], argv[5], addr, fd))
		{
			close(fd);
			fprintf(stderr, "%s %d, %s %s find_elf_local_sym_addr_by_file error %d\n", __FUNCTION__, __LINE__, argv[4], argv[5], errno);
			return -1;
		}
		close(fd);
	}
	else
	{
		usage();
		return -1;
	}

	fprintf(stderr, "%s %d, find type: %s, pid :%s, filename:%s, symname:%s, got_plt:%p, addr:%p\n", __FUNCTION__, __LINE__, argv[2], argv[3], argv[4], argv[5], got_plt, addr);
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

	if (optstr == "find")
	{
		void *got_plt = NULL;
		void *addr = NULL;
		int ret = hottool_find(pid, argc, argv, got_plt, addr);
		if (0 != ret)
		{
			fprintf(stderr, "%s %d, find failed type: %s, pid :%s, filename:%s, symname:%s\n", __FUNCTION__, __LINE__, argv[2], argv[3], argv[4], argv[5]);
			return ret;
		}

		fprintf(stderr, "%s %d, find succ type: %s, pid :%s, filename:%s, symname:%s, got_plt:%p, addr:%p\n", __FUNCTION__, __LINE__, argv[2], argv[3], argv[4], argv[5], got_plt, addr);
	}
	else
	{
		usage();
		return -1;
	}

	if (init_hook_flag)
	{
		fini_hook_env(pid);
	}

	return 0;
}
