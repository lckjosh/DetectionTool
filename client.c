#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <math.h>

// client program for detection tool
// adapted from LilyOfTheValley rootkit

// Usage:
// ./client [-p] [-f]

// [-p] detect hidden PIDs
// [-f] detect hidden files


#define DETECTPID_CMD 	"detectpid"
#define DETECTFILE_CMD	"detectfile"

#define PROCFS_ENTRYNAME 	"/proc/detectiontool"

#define BUF_SIZE 16

#define usage_err_msg "[Usage] ./client [-p] [-f]\n \
                        [-p] detect hidden PIDs\n \
                        [-f] detect hidden files"

#define OPTS_STR "+:p:f"
