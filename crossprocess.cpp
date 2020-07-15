#include "crossprocess.h"
#include <sys/ptrace.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>

static int cross_proc_readv(pid_t pid, char *remoteaddr, char *localaddr, size_t len)
{
	struct iovec local[1] = {};
	struct iovec remote[1] = {};

	local[0].iov_base = localaddr;
	local[0].iov_len = len;

	remote[0].iov_base = remoteaddr;
	remote[0].iov_len = len;

	ssize_t nread = process_vm_readv(pid, local, 1, remote, 1, 0);

	if (nread != len)
	{
		return errno;
	}
	return 0;
}

static int cross_proc_readmem(pid_t pid, char *remoteaddr, char *localaddr, size_t len)
{
	char file[PATH_MAX] = {0};
	sprintf(file, "/proc/%d/mem", pid);
	int fd = open(file, O_RDWR);
	if (fd < 0)
	{
		return errno;
	}
	int ret = pread(fd, localaddr, len, (off_t)remoteaddr);
	if (ret < 0)
	{
		return errno;
	}

	close(fd);
	return 0;
}

static int cross_proc_readptrace(pid_t pid, char *remoteaddr, char *localaddr, size_t len)
{
	char *dest = localaddr;
	char *src = remoteaddr;
	long word;
	while (len >= sizeof(word))
	{
		errno = 0;
		word = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
		if (errno != 0)
		{
			return errno;
		}
		*(long *)dest = word;
		src += sizeof(word);
		dest += sizeof(word);
		len -= sizeof(word);
	}

	if (len > 0)
	{
		word = 0;
		char *data = (char *)&word;
		word = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
		if (errno != 0)
		{
			return errno;
		}
		while (len--)
		{
			*(dest++) = *(src++);
		}
	}
	return 0;
}

int cross_proc_read(pid_t pid, char *remoteaddr, char *localaddr, size_t len)
{
	int ret = 0;
	ret = cross_proc_readv(pid, remoteaddr, localaddr, len);
	if (0 == ret)
	{
		return ret;
	}
	ret = cross_proc_readmem(pid, remoteaddr, localaddr, len);
	if (0 == ret)
	{
		return ret;
	}
	ret = cross_proc_readptrace(pid, remoteaddr, localaddr, len);
	if (0 == ret)
	{
		return ret;
	}
	fprintf(stderr, "%s %d cross read error %d\n", __FUNCTION__, __LINE__, ret);
	return ret;
}

static int cross_proc_writev(pid_t pid, char *remoteaddr, char *localaddr, size_t len)
{
	struct iovec local[1] = {};
	struct iovec remote[1] = {};

	local[0].iov_base = localaddr;
	local[0].iov_len = len;

	remote[0].iov_base = remoteaddr;
	remote[0].iov_len = len;

	ssize_t nwrite = process_vm_writev(pid, local, 1, remote, 1, 0);

	if (nwrite != len)
	{
		return errno;
	}
	return 0;
}

static int cross_proc_writemem(pid_t pid, char *remoteaddr, char *localaddr, size_t len)
{
	char file[PATH_MAX] = {0};
	sprintf(file, "/proc/%d/mem", pid);
	int fd = open(file, O_RDWR);
	if (fd < 0)
	{
		return errno;
	}
	int ret = pwrite(fd, localaddr, len, (off_t)remoteaddr);
	if (ret < 0)
	{
		return errno;
	}

	close(fd);
	return 0;
}

static int cross_proc_writeptrace(pid_t pid, char *remoteaddr, char *localaddr, size_t len)
{
	char *src = localaddr;
	char *dest = remoteaddr;
	long word;
	while (len >= sizeof(word))
	{
		errno = 0;
		word = ptrace(PTRACE_POKETEXT, pid, dest, *(long *)src);
		if (errno != 0)
		{
			return errno;
		}
		src += sizeof(word);
		dest += sizeof(word);
		len -= sizeof(word);
	}

	if (len > 0)
	{
		word = 0;
		word = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
		char *data = (char *)&word;
		while (len--)
		{
			*(data++) = *(src++);
		}
		ptrace(PTRACE_POKETEXT, pid, dest, word);
		if (errno != 0)
		{
			return errno;
		}
	}
	return 0;
}

int cross_proc_write(pid_t pid, char *remoteaddr, char *localaddr, size_t len)
{
	int ret = 0;
	ret = cross_proc_writev(pid, remoteaddr, localaddr, len);
	if (0 == ret)
	{
		return ret;
	}
	ret = cross_proc_writemem(pid, remoteaddr, localaddr, len);
	if (0 == ret)
	{
		return ret;
	}
	ret = cross_proc_writeptrace(pid, remoteaddr, localaddr, len);
	if (0 == ret)
	{
		return ret;
	}
	fprintf(stderr, "%s %d cross write error %d\n", __FUNCTION__, __LINE__, ret);
	return ret;
}
