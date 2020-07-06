#include "main.h"
#include "hook_syscalls.h"
#include "hook_fops.h"
#include "hook_networks.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joshua Lim, Fai Yew");

// name of the detection tool's proc filesystem entry
// permissions of detection tool's proc filesystem entry
#define TOOL_PROCFS_ENTRYNAME "detectiontool"
#define TOOL_PROCFS_ENTRYPERM 0666

// commands
#define DETECTPID_CMD "detectpid"
#define DETECTINODE_CMD "detectinode"
#define DETECTPORTS_CMD "detectports"
#define DETECTHOOKS_CMD "detecthooks"
#define DETECTMODULES_CMD "detectmods"

// declarations
unsigned long *addr_syscall_table;
int (*core_kern_text)(unsigned long addr);

// prototypes
static int tool_procfs_entry_init(void);
static ssize_t tool_procfs_write(struct file *, const char __user *, size_t, loff_t *);
static ssize_t tool_procfs_read(struct file *, char __user *, size_t, loff_t *);
static void hook_detection(void);
static void analyze_modules(void);
static struct proc_dir_entry *tool_procfs_entry;

// handlers for the read and write operations from/to tool's
// proc filesystem entry
static struct file_operations tool_procfs_fops =
	{
		.write = tool_procfs_write,
		.read = tool_procfs_read};

// create a proc filesystem entry for the detection tool
static int tool_procfs_entry_init(void)
{
	tool_procfs_entry = proc_create(TOOL_PROCFS_ENTRYNAME,
									TOOL_PROCFS_ENTRYPERM,
									NULL,
									&tool_procfs_fops);

	if (tool_procfs_entry == NULL)
		return 0;

	return 1;
}

static ssize_t tool_procfs_write(struct file *fp,
								 const char __user *ubuf,
								 size_t count,
								 loff_t *offp)
{
	char buf[16];
	memset(buf, 0x0, 16);

	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;

	if (strcmp(buf, DETECTPID_CMD) == 0)
	{
		// detect hidden pids (Userspace)
		printk(KERN_INFO "detection tool: Detect hidden pids (-p) has been invoked by the user.\n");
		memset(buf, 0x0, 16);
	}

	else if (strcmp(buf, DETECTINODE_CMD) == 0)
	{
		// detect hidden files (Userspace)
		printk(KERN_INFO "detection tool: Detect hidden inode scan (-f) has been invoked by the user.\n");
		memset(buf, 0x0, 16);
	}

	else if (strcmp(buf, DETECTPORTS_CMD) == 0)
	{
		// detect hidden network ports (Userspace)
		printk(KERN_INFO "detection tool: Detect hidden network ports scan (-n) has been invoked by the user.\n");
		memset(buf, 0x0, 16);
	}

	else if (strcmp(buf, DETECTHOOKS_CMD) == 0)
	{
		// detect hooked functions
		printk(KERN_INFO "detection tool: Detect hooked function scan (-s) has been invoked by the user.\n");
		memset(buf, 0x0, 16);
		hook_detection();
	}
	else if (strcmp(buf, DETECTMODULES_CMD) == 0)
	{
		// detect hidden modules
		printk(KERN_INFO "detection tool: Detect hidden module scan (-m) has been invoked by the user.\n");
		memset(buf, 0x0, 16);
		analyze_modules();
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
		"\t* [-f partition-to-scan] -->> to detect hidden files on the system\n"
		"\t* [-s] -->> to detect hooked functions\n"
		"\t* [-m] -->> to detect hidden modules\n"
		"\x00";

	if (copy_to_user(buf, tools_cmds, strlen(tools_cmds)))
		return -EFAULT;

	if (*offset != 0)
		return 0;

	*offset += 1;
	return (ssize_t)strlen(tools_cmds);
}

// detect hooks
static void hook_detection(void)
{
	int hooked_functions = scan_sys_call_table() + scan_fops() + scan_networks();
	// print summary
	if (hooked_functions)
		printk(KERN_ALERT "detection tool: Scanning complete. A total of %d hooked functions on your system was detected.\n", hooked_functions);
	else
		printk(KERN_INFO "detection tool: Scanning complete. No hooked functions on your system were detected.\n");
}

// detect hidden modules
static void analyze_modules(void)
{
	struct kset *mod_kset;
	struct kobject *cur, *tmp;
	struct module_kobject *kobj;
	int modulesFound = 0;

	printk(KERN_INFO "detection tool: Scanning Modules...\n");

	mod_kset = (void *)kallsyms_lookup_name("module_kset");
	if (!mod_kset)
		return;

	list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry)
	{
		if (!kobject_name(tmp))
			break;

		kobj = container_of(tmp, struct module_kobject, kobj);

		if (kobj && kobj->mod && kobj->mod->name)
		{
			mutex_lock(&module_mutex);
			if (!find_module(kobj->mod->name))
			{
				printk(KERN_ALERT "detection tool: Module [%s] hidden.\n", kobj->mod->name);
				modulesFound++;
			}
			mutex_unlock(&module_mutex);
		}
	}

	if (modulesFound)
		printk(KERN_ALERT "detection tool: Scanning complete. A total of %d hidden modules on your system was detected.\n", modulesFound);
	else
		printk(KERN_INFO "detection tool: Scanning complete. No hidden modules on your system were detected.\n");
}

static int tool_init(void)
{
	if (!tool_procfs_entry_init())
		return -1;

	addr_syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	core_kern_text = (void *)kallsyms_lookup_name("core_kernel_text");

	if (!addr_syscall_table)
	{
		printk(KERN_INFO "detection tool: Failed - Address of syscalls table not found\n");
		return -ECANCELED;
	}
	if (!core_kern_text)
	{
		printk(KERN_INFO "detection tool: Failed - Core Kernel Text not found\n");
		return -ECANCELED;
	}

	printk(KERN_INFO "detection tool: Init OK\n");
	printk(KERN_INFO "detection tool: It is recommended to run \"sudo ./client -f\" the first time this LKM is loaded into the kernel.\n");

	return 0;
}

static void tool_exit(void)
{
	proc_remove(tool_procfs_entry);
	printk(KERN_INFO "detection tool: Exiting\n");
}

module_init(tool_init);
module_exit(tool_exit);