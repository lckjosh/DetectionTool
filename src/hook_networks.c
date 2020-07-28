#include "main.h"
#include "hook_networks.h"
#include "detectmodules.h"

extern int (*core_kern_text)(unsigned long addr); /* Core Kernel Text */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
struct net_entry net[4] = {
    {"tcp", NULL},
    {"tcp6", NULL},
    {"udp", NULL},
    {"udp6", NULL}};

struct proc_dir_entry *find_subdir(struct rb_root *tree, const char *str)
{
    struct rb_node *node = rb_first(tree);
    struct proc_dir_entry *e = NULL;

    while (node)
    {
        e = rb_entry(node, struct proc_dir_entry, subdir_node);
        if (strcmp(e->name, str) == 0)
            return e;
        node = rb_next(node);
    }

    return NULL;
}

int scan_networks(void)
{
    int i;
    unsigned long addr;
    unsigned char test[12];
    const struct seq_operations *seq_ops;
    int no_of_net_hooks = 0;
    const char *mod_name;
    struct module *mod;

    for (i = 0; i < 4; i++)
    {
        net[i].entry = find_subdir(&init_net.proc_net->subdir, net[i].name);
        if (!net[i].entry)
            continue;

        seq_ops = net[i].entry->seq_ops;
        addr = (unsigned long)seq_ops->show;

        if (!core_kern_text(addr))
        {
            mutex_lock(&module_mutex);
            mod = get_module_from_addr(addr);
            if (mod)
            {
                printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by module [%s] detected!\n", net[i].name, mod->name);
            }
            else
            {
                mod_name = find_hidden_module_name(addr);
                if (mod_name)
                    printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by module [%s] detected!\n", net[i].name, mod_name);
                else
                    printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by a hidden module detected!\n", net[i].name);
            }
            mutex_unlock(&module_mutex);
            no_of_net_hooks++;
        }
        else
        {
            memcpy(test, (void *)addr, 12);
            if ((test[0] == 0x48 && test[1] == 0xb8 && test[10] == 0xff && test[11] == 0xe0) || test[0] == 0xe9 || test[0] == 0xcc)
            {
                mutex_lock(&module_mutex);
                mod = get_module_from_addr(addr);
                if (mod)
                {
                    printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by module [%s] detected!\n", net[i].name, mod->name);
                }
                else
                {
                    mod_name = find_hidden_module_name(addr);
                    if (mod_name)
                        printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by module [%s] detected!\n", net[i].name, mod_name);
                    else
                        printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by a hidden module detected!\n", net[i].name);
                }
                mutex_unlock(&module_mutex);
                no_of_net_hooks++;
            }
        }
    }
    if (no_of_net_hooks)
        printk(KERN_ALERT "detection tool: [WARNING] %d hooked network functions detected!\n", no_of_net_hooks);
    else
        printk(KERN_INFO "detection tool: [OK] No hooked network functions detected.\n");

    return no_of_net_hooks;
}

#else
int scan_networks(void)
{
    unsigned long addr;
    unsigned char test[12];
    struct file *fp;
    int no_of_net_hooks = 0;
    char path[15];
    struct tcp_seq_afinfo *tcp_afinfo;
    struct udp_seq_afinfo *udp_afinfo;
    const char *mod_name;
    struct module *mod;

    // scan network hooks
    printk(KERN_INFO "detection tool: [*] Scanning for network function hooks...\n");

#define SCAN_PROC_NET(NAME)                                                                                                        \
    sprintf(path, "/proc/net/%s", #NAME);                                                                                          \
    fp = filp_open(path, O_RDONLY, 0);                                                                                             \
    if (IS_ERR(fp))                                                                                                                \
        printk(KERN_ERR "detection tool: [*] Failed to open %s!\n", path);                                                         \
    if (IS_ERR(fp->f_path.dentry->d_inode))                                                                                        \
        printk(KERN_WARNING "detection tool: [*] %s has no afinfo!\n", path);                                                      \
                                                                                                                                   \
    /* tcp */                                                                                                                      \
    if (!strncmp("tcp", #NAME, 3))                                                                                                 \
    {                                                                                                                              \
        tcp_afinfo = PDE_DATA(fp->f_path.dentry->d_inode);                                                                         \
        addr = (unsigned long)tcp_afinfo->seq_ops.show;                                                                            \
    }                                                                                                                              \
    /* udp */                                                                                                                      \
    else                                                                                                                           \
    {                                                                                                                              \
        udp_afinfo = PDE_DATA(fp->f_path.dentry->d_inode);                                                                         \
        addr = (unsigned long)udp_afinfo->seq_ops.show;                                                                            \
    }                                                                                                                              \
                                                                                                                                   \
    if (!core_kern_text(addr))                                                                                                     \
    {                                                                                                                              \
        mutex_lock(&module_mutex);                                                                                                 \
        mod = get_module_from_addr(addr);                                                                                          \
        if (mod)                                                                                                                   \
        {                                                                                                                          \
            printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by module [%s] detected!\n", #NAME, mod->name);        \
        }                                                                                                                          \
        else                                                                                                                       \
        {                                                                                                                          \
            mod_name = find_hidden_module_name(addr);                                                                              \
            if (mod_name)                                                                                                          \
                printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by module [%s] detected!\n", #NAME, mod_name);     \
            else                                                                                                                   \
                printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by a hidden module detected!\n", #NAME);           \
        }                                                                                                                          \
        mutex_unlock(&module_mutex);                                                                                               \
        no_of_net_hooks++;                                                                                                         \
    }                                                                                                                              \
    else                                                                                                                           \
    {                                                                                                                              \
        memcpy(test, (void *)addr, 12);                                                                                            \
        if ((test[0] == 0x48 && test[1] == 0xb8 && test[10] == 0xff && test[11] == 0xe0) || test[0] == 0xe9 || test[0] == 0xcc)    \
        {                                                                                                                          \
            mutex_lock(&module_mutex);                                                                                             \
            mod = get_module_from_addr(addr);                                                                                      \
            if (mod)                                                                                                               \
            {                                                                                                                      \
                printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by module [%s] detected!\n", #NAME, mod->name);    \
            }                                                                                                                      \
            else                                                                                                                   \
            {                                                                                                                      \
                mod_name = find_hidden_module_name(addr);                                                                          \
                if (mod_name)                                                                                                      \
                    printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by module [%s] detected!\n", #NAME, mod_name); \
                else                                                                                                               \
                    printk(KERN_ALERT "detection tool: [WARNING] [%s] function hook by a hidden module detected!\n", #NAME);       \
            }                                                                                                                      \
            mutex_unlock(&module_mutex);                                                                                           \
            no_of_net_hooks++;                                                                                                     \
        }                                                                                                                          \
    }                                                                                                                              \
    filp_close(fp, 0);

    SCAN_PROC_NET(tcp)
    SCAN_PROC_NET(tcp6)
    SCAN_PROC_NET(udp)
    SCAN_PROC_NET(udp6)

    if (no_of_net_hooks)
        printk(KERN_ALERT "detection tool: [WARNING] %d hooked network functions detected!\n", no_of_net_hooks);
    else
        printk(KERN_INFO "detection tool: [OK] No hooked network functions detected.\n");

    return no_of_net_hooks;
}

#endif