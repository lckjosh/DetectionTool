#include "main.h"
#include "detectmodules.h"

extern int (*core_kern_text)(unsigned long addr); /* Core Kernel Text */

int scan_fops(void)
{
    unsigned long addr;
    unsigned char test[12];
    struct file *fp;
    int no_of_fops_hooks = 0;
    char path[6];
    const char *mod_name;
    struct module *mod;

    // scan fops hooks
    printk(KERN_INFO "detection tool: [*] Scanning fops of /, /proc and /sys...\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
#define SCAN_FOPS(NAME)                                                                                                         \
    sprintf(path, "/%s", #NAME);                                                                                                \
    fp = filp_open(path, O_RDONLY, S_IRUSR);                                                                                    \
    if (IS_ERR(fp))                                                                                                             \
        printk(KERN_ERR "detection tool: [*] Failed to open %s!\n", path);                                                      \
    if (IS_ERR(fp->f_op))                                                                                                       \
        printk(KERN_WARNING "detection tool: [WARNING] %s has no fops!\n", path);                                               \
                                                                                                                                \
    addr = (unsigned long)fp->f_op->iterate_shared;                                                                             \
    if (!core_kern_text(addr))                                                                                                  \
    {                                                                                                                           \
        mutex_lock(&module_mutex);                                                                                              \
        mod = get_module_from_addr(addr);                                                                                       \
        if (mod)                                                                                                                \
        {                                                                                                                       \
            printk(KERN_ALERT "detection tool: [WARNING] [%s] fops hook by module [%s] detected!\n", path, mod->name);          \
        }                                                                                                                       \
        else                                                                                                                    \
        {                                                                                                                       \
            mod_name = find_hidden_module_name(addr);                                                                           \
            if (mod_name)                                                                                                       \
                printk(KERN_ALERT "detection tool: [WARNING] [%s] fops hook by module [%s] detected!\n", path, mod_name);       \
            else                                                                                                                \
                printk(KERN_ALERT "detection tool: [WARNING] [%s] fops hook by a hidden module detected!\n", path);             \
        }                                                                                                                       \
        mutex_unlock(&module_mutex);                                                                                            \
        no_of_fops_hooks++;                                                                                                     \
    }                                                                                                                           \
    else                                                                                                                        \
    {                                                                                                                           \
        memcpy(test, (void *)addr, 12);                                                                                         \
        if ((test[0] == 0x48 && test[1] == 0xb8 && test[10] == 0xff && test[11] == 0xe0) || test[0] == 0xe9 || test[0] == 0xcc) \
        {                                                                                                                       \
            printk(KERN_ALERT "detection tool: [WARNING] [%s] fops hook by a kernel module detected!\n", path);                 \
            no_of_fops_hooks++;                                                                                                 \
        }                                                                                                                       \
    }                                                                                                                           \
    filp_close(fp, 0);
#else
#define SCAN_FOPS(NAME)                                                                                                         \
    sprintf(path, "/%s", #NAME);                                                                                                \
    fp = filp_open(path, O_RDONLY, S_IRUSR);                                                                                    \
    if (IS_ERR(fp))                                                                                                             \
        printk(KERN_ERR "detection tool: [*] Failed to open %s!\n", path);                                                      \
    if (IS_ERR(fp->f_op))                                                                                                       \
        printk(KERN_WARNING "detection tool: [WARNING] %s has no fops!\n", path);                                               \
                                                                                                                                \
    addr = (unsigned long)fp->f_op->iterate;                                                                                    \
    if (!core_kern_text(addr))                                                                                                  \
    {                                                                                                                           \
        mutex_lock(&module_mutex);                                                                                              \
        mod = get_module_from_addr(addr);                                                                                       \
        if (mod)                                                                                                                \
        {                                                                                                                       \
            printk(KERN_ALERT "detection tool: [WARNING] [%s] fops hook by module [%s] detected!\n", path, mod->name);          \
        }                                                                                                                       \
        else                                                                                                                    \
        {                                                                                                                       \
            mod_name = find_hidden_module_name(addr);                                                                           \
            if (mod_name)                                                                                                       \
                printk(KERN_ALERT "detection tool: [WARNING] [%s] fops hook by module [%s] detected!\n", path, mod_name);       \
            else                                                                                                                \
                printk(KERN_ALERT "detection tool: [WARNING] [%s] fops hook by a hidden module detected!\n", path);             \
        }                                                                                                                       \
        mutex_unlock(&module_mutex);                                                                                            \
        no_of_fops_hooks++;                                                                                                     \
    }                                                                                                                           \
    else                                                                                                                        \
    {                                                                                                                           \
        memcpy(test, (void *)addr, 12);                                                                                         \
        if ((test[0] == 0x48 && test[1] == 0xb8 && test[10] == 0xff && test[11] == 0xe0) || test[0] == 0xe9 || test[0] == 0xcc) \
        {                                                                                                                       \
            printk(KERN_ALERT "detection tool: [WARNING] [%s] fops hook by a kernel module detected!\n", path);                 \
            no_of_fops_hooks++;                                                                                                 \
        }                                                                                                                       \
    }                                                                                                                           \
    filp_close(fp, 0);
#endif

    SCAN_FOPS()
    SCAN_FOPS(proc)
    SCAN_FOPS(sys)

    if (no_of_fops_hooks)
        printk(KERN_ALERT "detection tool: [WARNING] %d hooked fops detected!\n", no_of_fops_hooks);
    else
        printk(KERN_INFO "detection tool: [OK] No hooked fops detected.\n");

    return no_of_fops_hooks;
}