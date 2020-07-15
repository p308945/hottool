#ifndef __GET_PROCESS_BASE_ADDR__H__
#define __GET_PROCESS_BASE_ADDR__H__

#include <unistd.h>
#include <stdio.h>

bool get_elf_text_base_addr(const char* findname, unsigned long &start)
{
	FILE* fp;
	char maps[4096], mapbuf[4096], perms[32], libpath[4096];
	char* elfname;
	unsigned long file_offset, inode, dev_major, dev_minor;
	sprintf(maps, "/proc/%d/maps", pid);
	fp = fopen(maps, "rb");
	fp = fopen(maps, openflags.c_str());
	if (!fp)
	{
		return false;
	}
	unsigned long end;
	while (fgets(mapbuf, sizeof(mapbuf), fp))
	{
		sscanf(mapbuf, "%lx-%lx %s %lx %lx:%lx %lu %s", &start, &end, perms, &file_offset, &dev_major, &dev_minor, &inode, libpath);
		elfname = strrchr(libpath, '/');
		if (elfname)
		{
			elfname++;
		}
		else
		{
			continue;
		}
		if (!strncmp(perms, "r-xp", 4) && strstr(elfname, findname))
		{
			fclose(fp);
			return true;
		}
	}
	fclose(fp);
	return false;
}

bool get_elf_data_base_addr(const char* findname, unsigned long &start)
{
	FILE* fp;
	char maps[4096], mapbuf[4096], perms[32], libpath[4096];
	char* elfname;
	unsigned long file_offset, inode, dev_major, dev_minor;
	sprintf(maps, "/proc/%d/maps", pid);
	fp = fopen(maps, "rb");
	fp = fopen(maps, openflags.c_str());
	if (!fp)
	{
		return false;
	}
	unsigned long end;
	while (fgets(mapbuf, sizeof(mapbuf), fp))
	{
		sscanf(mapbuf, "%lx-%lx %s %lx %lx:%lx %lu %s", &start, &end, perms, &file_offset, &dev_major, &dev_minor, &inode, libpath);
		elfname = strrchr(libpath, '/');
		if (elfname)
		{
			elfname++;
		}
		else
		{
			continue;
		}
		if (!strncmp(perms, "rw-p", 4) && strstr(elfname, findname))
		{
			fclose(fp);
			return true;
		}
	}
	fclose(fp);
	return false;
}

#endif
