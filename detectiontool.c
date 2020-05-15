#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joshua Lim, Fai Yew");

// name of the detection tool's proc filesystem entry
// permissions of detection tool's proc filesystem entry
#define TOOL_PROCFS_ENTRYNAME  "detectiontool"
#define TOOL_PROCFS_ENTRYPERM  0666

// commands
#define DETECTPID_CMD 	 "detectpid"
#define DETECTFILE_CMD 	 "detectfile"

//for 4.X
//copied from /fs/proc/internal.h 
struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	void *data;
	atomic_t count;		/* use count */
	atomic_t in_use;	/* number of callers into module in progress; */
			/* negative -> it's going away RSN */
	struct completion *pde_unload_completion;
	struct list_head pde_openers;	/* who did ->open, but not ->release */
	spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
	u8 namelen;
	char name[];
};

// prototypes
static int 	tool_procfs_entry_init(void);
static ssize_t 	tool_procfs_write(struct file *,const char __user *,size_t,loff_t*);
static ssize_t  tool_procfs_read(struct file *,char __user *,size_t,loff_t *); 

static struct proc_dir_entry *tool_procfs_entry,*procfs_root;

// handlers for the read and write operations from/to tool's
// proc filesystem entry

static struct file_operations tool_procfs_fops = 
{
	.write = tool_procfs_write,
	.read  = tool_procfs_read
};

/*
create a proc filesystem entry for the rootkit
*/
static int tool_procfs_entry_init(void)
{
	tool_procfs_entry = proc_create(TOOL_PROCFS_ENTRYNAME,
					   TOOL_PROCFS_ENTRYPERM,
				   	   NULL,
					   &tool_procfs_fops);

	if (tool_procfs_entry == NULL)
		return 0;

	procfs_root = tool_procfs_entry->parent;

	return 1;
}

static ssize_t tool_procfs_write(struct file *fp,
				    const char __user *buf,
				    size_t count,
				    loff_t *offp)
{
	if (strcmp(buf,DETECTPID_CMD) == 0)
	{
		// detect hidden pids
	}

	else if(strcmp(buf,DETECTFILE_CMD) == 0)
	{
        // detect hidden files
	}

	return count;
}


static ssize_t tool_procfs_read(struct file *fp,
				   char __user *buf,
				   size_t count,
				   loff_t *offset)
{
	const char tools_cmds[] = 
				"#######################\n"
				"Detection Tool Commands\n"
				"#######################\n\n"
				"\t* [-p] -->> to detect hidden PIDs on the system\n"
				"\t* [-f] -->> to detect hidden files on the system\n"
				"\x00";

	if (copy_to_user(buf,tools_cmds,strlen(tools_cmds)))
		return -EFAULT;

	if (*offset != 0)
		return 0;

	*offset += 1;
	return (ssize_t)strlen(tools_cmds);
}

static int tool_init(void)
{
	if (!tool_procfs_entry_init())
		return -1;

	return 0;
}

static void tool_exit(void)
{

	remove_proc_entry(TOOL_PROCFS_ENTRYNAME,procfs_root);

}

module_init(tool_init);
module_exit(tool_exit);