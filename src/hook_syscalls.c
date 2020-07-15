#include "main.h"
#include "detectmodules.h"

extern unsigned long *addr_syscall_table;         /* Syscall Table */
extern int (*core_kern_text)(unsigned long addr); /* Core Kernel Text */

int scan_sys_call_table(void)
{
    unsigned int sys_num = 0;
    unsigned long addr;
    unsigned char test[12];
    int no_of_syscall_hooks = 0;
    const char *mod_name;
    struct module *mod;

    // scan sys_call_table
    printk(KERN_INFO "detection tool: Scanning sys_call_table...\n");
    for (sys_num = 0; sys_num < NR_syscalls; sys_num++)
    {
        addr = addr_syscall_table[sys_num];
        if (!core_kern_text(addr))
        {
            mutex_lock(&module_mutex);
            mod = get_module_from_addr(addr);
            if (mod)
            {
                printk(KERN_ALERT "detection tool: syscall [%d] hook by module [%s] detected!\n", sys_num, mod->name);
            }
            else
            {
                mod_name = find_hidden_module_name(addr);
                if (mod_name)
                    printk(KERN_ALERT "detection tool: syscall [%d] hook by module [%s] detected!\n", sys_num, mod_name);

                else
                    printk(KERN_ALERT "detection tool: syscall [%d] hook by a hidden module detected!\n", sys_num);
            }
            mutex_unlock(&module_mutex);
            no_of_syscall_hooks++;
        }
        // detect inline hook with mov and jmp
        else
        {
            memcpy(test, (void *)addr, 12);
            if (test[0] == 0x48 && test[1] == 0xb8 && test[10] == 0xff && test[11] == 0xe0)
            {
                mutex_lock(&module_mutex);
                mod = get_module_from_addr(addr);
                if (mod)
                {
                    printk(KERN_ALERT "detection tool: syscall [%d] hook by module [%s] detected!\n", sys_num, mod->name);
                }
                else
                {
                    mod_name = find_hidden_module_name(addr);
                    if (mod_name)
                        printk(KERN_ALERT "detection tool: syscall [%d] hook by module [%s] detected!\n", sys_num, mod_name);

                    else
                        printk(KERN_ALERT "detection tool: syscall [%d] hook by a hidden module detected!\n", sys_num);
                }
                mutex_unlock(&module_mutex);
                no_of_syscall_hooks++;
            }
        }
    }
    if (no_of_syscall_hooks)
        printk(KERN_ALERT "detection tool: %d hooked system calls detected!\n", no_of_syscall_hooks);
    else
        printk(KERN_INFO "detection tool: No hooked system calls detected.\n");

    return no_of_syscall_hooks;
}