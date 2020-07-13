#include "main.h"
#include <net/net_namespace.h> /* init_net */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#include <linux/proc_fs.h>
#else
typedef int (*proc_write_t)(struct file *, char *, size_t);
#endif

struct proc_dir_entry
{
    atomic_t in_use;
    refcount_t refcnt;
    struct list_head pde_openers;
    spinlock_t pde_unload_lock;
    struct completion *pde_unload_completion;
    const struct inode_operations *proc_iops;
    const struct file_operations *proc_fops;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 29)
    const struct dentry_operations *proc_dops;
#endif
    union
    {
        const struct seq_operations *seq_ops;
        int (*single_show)(struct seq_file *, void *);
    };
    proc_write_t write;
    void *data;
    unsigned int state_size;
    unsigned int low_ino;
    nlink_t nlink;
    kuid_t uid;
    kgid_t gid;
    loff_t size;
    struct proc_dir_entry *parent;
    struct rb_root subdir;
    struct rb_node subdir_node;
    char *name;
    umode_t mode;
    u8 namelen;
    char inline_name[];
};

struct net_entry
{
    const char *name;
    struct proc_dir_entry *entry;
};

int scan_networks(void);