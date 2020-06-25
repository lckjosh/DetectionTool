#include "main.h"

extern unsigned long *addr_syscall_table; /* Syscall Table */
extern int (*core_kern_text)(unsigned long addr); /* Core Kernel Text */

int scan_sys_call_table(void)
{
    unsigned int sys_num = 0;
    unsigned long addr;
    unsigned char test[12];
    int no_of_syscall_hooks = 0;

    // scan sys_call_table
    printk(KERN_INFO "detection tool: Scanning sys_call_table...\n");
    for (sys_num = 0; sys_num < NR_syscalls; sys_num++)
    {
        addr = addr_syscall_table[sys_num];
        if (!core_kern_text(addr))
        {
            printk(KERN_ALERT "detection tool: Hook detected! (syscall %d)\n", sys_num);
            no_of_syscall_hooks++;
        }
        // detect inline hook with mov and jmp
        else
        {
            memcpy(test, (void *)addr, 12);
            if (test[0] == 0x48 && test[1] == 0xb8 && test[10] == 0xff && test[11] == 0xe0)
            {
                printk(KERN_ALERT "detection tool: Hook detected! (syscall %d)\n", sys_num);
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