#include "main.h"

extern int (*core_kern_text)(unsigned long addr); /* Core Kernel Text */

int scan_networks(void)
{
    unsigned long addr;
    unsigned char test[12];
    struct file *fp;
    int no_of_net_hooks = 0;
    char path[15];
    struct tcp_seq_afinfo *tcp_afinfo;
    struct udp_seq_afinfo *udp_afinfo;

    // scan network hooks
    printk(KERN_INFO "detection tool: Scanning for network function hooks...\n");

#define SCAN_PROC_NET(NAME)                                                             \
    sprintf(path, "/proc/net/%s", #NAME);                                               \
    fp = filp_open(path, O_RDONLY, 0);                                                  \
    if (IS_ERR(fp))                                                                     \
        printk(KERN_ERR "detection tool: Failed to open %s!\n", path);                  \
    if (IS_ERR(fp->f_path.dentry->d_inode))                                             \
        printk(KERN_WARNING "detection tool: %s has no afinfo!\n", path);               \
                                                                                        \
    /* tcp */                                                                           \
    if (!strncmp("tcp", #NAME, 3))                                                      \
    {                                                                                   \
        tcp_afinfo = PDE_DATA(fp->f_path.dentry->d_inode);                              \
        addr = (unsigned long)tcp_afinfo->seq_ops.show;                                 \
    }                                                                                   \
    /* udp */                                                                           \
    else                                                                                \
    {                                                                                   \
        udp_afinfo = PDE_DATA(fp->f_path.dentry->d_inode);                              \
        addr = (unsigned long)udp_afinfo->seq_ops.show;                                 \
    }                                                                                   \
                                                                                        \
    if (!core_kern_text(addr))                                                          \
    {                                                                                   \
        printk(KERN_ALERT "detection tool: %s function hook detected!\n", path);        \
        no_of_net_hooks++;                                                              \
    }                                                                                   \
    else                                                                                \
    {                                                                                   \
        memcpy(test, (void *)addr, 12);                                                 \
        if (test[0] == 0x48 && test[1] == 0xb8 && test[10] == 0xff && test[11] == 0xe0) \
        {                                                                               \
            printk(KERN_ALERT "detection tool: %s function hook detected!\n", path);    \
            no_of_net_hooks++;                                                          \
        }                                                                               \
    }                                                                                   \
    filp_close(fp, 0);

    SCAN_PROC_NET(tcp)
    SCAN_PROC_NET(tcp6)
    SCAN_PROC_NET(udp)
    SCAN_PROC_NET(udp6)

    if (no_of_net_hooks)
        printk(KERN_ALERT "detection tool: %d hooked network functions detected!\n", no_of_net_hooks);
    else
        printk(KERN_INFO "detection tool: No hooked network functions detected.\n");
    
    return no_of_net_hooks;
}