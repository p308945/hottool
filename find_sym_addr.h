#ifndef __FIND_SYM_ADDR_H__
#define __FIND_SYM_ADDR_H__

#include <string>

bool find_elf_addr(pid_t pid, const char* elfname, const char *perms_prot_flags, unsigned long &start, unsigned long &end);

bool find_so_func_addr_by_mem(int pid, const std::string &soname, const std::string &funname, void *&funcaddr_plt, void *&funcaddr);

bool find_so_func_addr_by_file(int pid, const std::string &sopath, const std::string &funname, void *&funcaddr_plt, void *&funcaddr, int sofd);

bool find_elf_fun_addr_by_file(int pid, const std::string &elfpath, const std::string &funcname, void *&funcaddr_plt, void *&funcaddr, int elffd);

bool find_so_variable_addr_by_mem(int pid, const std::string &soname, const std::string &variablename, void *&variableaddr_got, void *&variableaddr);

bool find_so_variable_addr_by_file(int pid, const std::string &sopath, const std::string &variablename, void *&variableaddr_got, void *&variableaddr, int sofd);

bool find_elf_variable_addr_by_file(int pid, const std::string &elfpath, const std::string &variablename, void *&variableaddr_got, void *&variableaddr, int elffd);

bool find_elf_local_sym_addr_by_file(const std::string &elfpath, const std::string &symname, void *&symaddr, int elffd);

#endif
