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