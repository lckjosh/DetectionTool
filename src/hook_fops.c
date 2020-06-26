#include "main.h"

extern int (*core_kern_text)(unsigned long addr); /* Core Kernel Text */

int scan_fops(void)
{
    unsigned long addr;
    unsigned char test[12];
    struct file *fp;
    int no_of_fops_hooks = 0;
    char path[6];

    // scan fops hooks
    printk(KERN_INFO "detection tool: Scanning fops of /, /proc and /sys...\n");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
#define SCAN_FOPS(NAME)                                                                 \
    sprintf(path, "/%s", #NAME);                                                        \
    fp = filp_open(path, O_RDONLY, S_IRUSR);                                            \
    if (IS_ERR(fp))                                                                     \
        printk(KERN_ERR "detection tool: Failed to open %s!\n", path);                  \
    if (IS_ERR(fp->f_op))                                                               \
        printk(KERN_WARNING "detection tool: %s has no fops!\n", path);                 \
                                                                                        \
    addr = (unsigned long)fp->f_op->iterate_shared;                                     \
    if (!core_kern_text(addr))                                                          \
    {                                                                                   \
        printk(KERN_ALERT "detection tool: %s fops hook detected!\n", path);            \
        no_of_fops_hooks++;                                                             \
    }                                                                                   \
    else                                                                                \
    {                                                                                   \
        memcpy(test, (void *)addr, 12);                                                 \
        if (test[0] == 0x48 && test[1] == 0xb8 && test[10] == 0xff && test[11] == 0xe0) \
        {                                                                               \
            printk(KERN_ALERT "detection tool: %s fops hook detected!\n", path);        \
            no_of_fops_hooks++;                                                         \
        }                                                                               \
    }                                                                                   \
    filp_close(fp, 0);
#else
#define SCAN_FOPS(NAME)                                                                 \
    sprintf(path, "/%s", #NAME);                                                        \
    fp = filp_open(path, O_RDONLY, S_IRUSR);                                            \
    if (IS_ERR(fp))                                                                     \
        printk(KERN_ERR "detection tool: Failed to open %s!\n", path);                  \
    if (IS_ERR(fp->f_op))                                                               \
        printk(KERN_WARNING "detection tool: %s has no fops!\n", path);                 \
                                                                                        \
    addr = (unsigned long)fp->f_op->iterate;                                            \
    if (!core_kern_text(addr))                                                          \
    {                                                                                   \
        printk(KERN_ALERT "detection tool: %s fops hook detected!\n", path);            \
        no_of_fops_hooks++;                                                             \
    }                                                                                   \
    else                                                                                \
    {                                                                                   \
        memcpy(test, (void *)addr, 12);                                                 \
        if (test[0] == 0x48 && test[1] == 0xb8 && test[10] == 0xff && test[11] == 0xe0) \
        {                                                                               \
            printk(KERN_ALERT "detection tool: %s fops hook detected!\n", path);        \
            no_of_fops_hooks++;                                                         \
        }                                                                               \
    }                                                                                   \
    filp_close(fp, 0);
#endif

    SCAN_FOPS()
    SCAN_FOPS(proc)
    SCAN_FOPS(sys)

    if (no_of_fops_hooks)
        printk(KERN_ALERT "detection tool: %d hooked fops detected!\n", no_of_fops_hooks);
    else
        printk(KERN_INFO "detection tool: No hooked fops detected.\n");

    return no_of_fops_hooks;
}