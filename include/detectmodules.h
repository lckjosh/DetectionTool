#ifndef DETECTMODULES_H
#define DETECTMODULES_H

#include "main.h"

int scan_modules(void);
const char *find_hidden_module_name(unsigned long addr);
struct module *get_module_from_addr(unsigned long addr);

#endif