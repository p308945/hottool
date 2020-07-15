#ifndef __HOOK_H_
#define __HOOK_H_

#include <string>
#include <unistd.h>
#include <stdint.h>

bool init_hook_env(pid_t pid);
bool fini_hook_env(int pid);

bool cross_dlopen(pid_t pid, const std::string &sopath, uint64_t &handle);

bool cross_dlclose(pid_t pid, const std::string &sopath, uint64_t handle);

bool hotfix_func(pid_t pid, void *old_funcaddr, void *new_funcaddr, uint64_t &backupcode);

bool hotfix_func64(pid_t pid, void *old_funcaddr, void *new_funcaddr, char *backupcode, int len);

bool hotfix_gotplt(pid_t pid, void *gotplt, void *new_funcaddr, uint64_t &backupcode);

#endif
