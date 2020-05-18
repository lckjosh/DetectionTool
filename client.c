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

#define DETECTPID_CMD "detectpid"
#define DETECTFILE_CMD "detectfile"

#define PROCFS_ENTRYNAME "/proc/detectiontool"

#define BUF_SIZE 16

#define usage_err_msg "[Usage] ./client [-p] [-f]\n \
                        [-p] detect hidden PIDs\n \
                        [-f] detect hidden files"

#define OPTS_STR "+:p:f"

#define __err(msg, prnt_func, err_code) \
    do                                  \
    {                                   \
        prnt_func(msg);                 \
        return err_code;                \
    } while (0)

#define usage_err(errmsg, opt) \
    do                         \
    {                          \
        printf(errmsg, opt);   \
        printf(usage_err_msg); \
        return -1;             \
    } while (0)

int main(int argc, char **argv)
{
    int opt, fd;
    fd = open(PROCFS_ENTRYNAME, O_RDWR);

    if (fd < 0)
        __err("[__ERROR_1__]", perror, -1);

    while ((opt = getopt(argc, argv, OPTS_STR)) != -1)
    {
        switch (opt)
        {
        case 'p':
            // detect hidden pids
            break;
        case 'f':
            // detect hidden files
            break;
        case '?':
            usage_err("[__ERROR__]unrecognized option [%c]\n", opt);
            break;
        case ':':
            usage_err("[__ERROR__]missing argument to [%c] option\n", opt);
        }
    }
}