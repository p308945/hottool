#ifndef __CROSSPROCESS_H_
#define __CROSSPROCESS_H_

#include <sys/uio.h>

int cross_proc_read(pid_t pid, char *remoteaddr, char *localaddr, size_t len);
int cross_proc_write(pid_t pid, char *remoteaddr, char *localaddr, size_t len);

#endif
