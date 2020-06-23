#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <math.h>

#include <sys/stat.h>
#include <getopt.h>
#include <string.h>

#include "detectpids.c"
#include "detectinodes.c"

// client program for detection tool
// adapted from LilyOfTheValley rootkit

// Usage:
// ./client [-p] [-f]

// [-p] detect hidden PIDs
// [-f] detect hidden files

#define DETECTPID_CMD "detectpid"
#define DETECTINODE_CMD "detectinode"
#define DETECTHOOKS_CMD "detecthooks"
#define DETECTMODULES_CMD "detectmods"

#define PROCFS_ENTRYNAME "/proc/detectiontool"

#define BUF_SIZE 16

#define usage_err_msg "[Usage] ./client [-p] [-f <filesystem-mounted-at-root-directory> ] [-s] [-m]\n\
\t[-p] detect hidden PIDs\n\
\t[-f <filesystem-mounted-at-root-directory> ] detect hidden files (./client -f /dev/sda1)\n\
\t[-s] detect hooked functions\n\
\t[-m] detect hidden modules\n"

#define hidden_proc_found_msg "There are hidden processes found on your system.\n\
There may be a rootkit installed on your system that is hiding these processes.\n"

#define hidden_proc_notfound_msg "There are no hidden processes found on your system.\n\
A rootkit may still be present on your system but is not hiding any process at the moment.\n"

#define OPTS_STR ":pf:sm"

#define __err(msg, prnt_func, err_code) \
   do                                   \
   {                                    \
      prnt_func(msg);                   \
      return err_code;                  \
   } while (0)

#define usage_err()          \
   do                        \
   {                         \
      printf(usage_err_msg); \
      return -1;             \
   } while (0)

int main(int argc, char **argv)
{
   if (argc < 2)
      usage_err();

   char cmd_buf[BUF_SIZE];
   int opt, fd;
   fd = open(PROCFS_ENTRYNAME, O_RDWR);

   if (fd < 0)
      __err("[__ERROR_1__]", perror, -1);

   while ((opt = getopt(argc, argv, OPTS_STR)) != -1)
   {
      switch (opt)
      {
      case 'p':
         // detect hidden processes
         if (getuid() != 0)
         {
            printf("You must be root to perform this function!\n");
            exit(1);
         }
         // Log to LKM
         memset(cmd_buf, 0x0, BUF_SIZE);
         sprintf(cmd_buf, DETECTPID_CMD);
         if (write(fd, cmd_buf, strlen(cmd_buf)) < 0)
         {
            __err("[__ERROR_2__]", perror, -1);
         }

         checkallquick();

         if (found_HP)
            printf(hidden_proc_found_msg);
         else
            printf(hidden_proc_notfound_msg);
         break;
      case 'f':
         // detect hidden inodes
         if (getuid() != 0)
         {
            printf("You must be root to perform this function!\n");
            exit(1);
         }
         // Log to LKM
         memset(cmd_buf, 0x0, BUF_SIZE);
         sprintf(cmd_buf, DETECTINODE_CMD);
         if (write(fd, cmd_buf, strlen(cmd_buf)) < 0)
         {
            __err("[__ERROR_2__]", perror, -1);
         }
         // int status = system("./hidden-inode-detector.py /dev/sda1 / /");
         int status = hideinodedetector(optarg, sizeof(optarg));
         if (status != 0)
         {
            printf("client.c: Python script (hidden-inode-detector.py) failed to execute completely due to a raised exception.\n");
            break;
         }
         break;
      case 's':
         // detect hooked functions
         memset(cmd_buf, 0x0, BUF_SIZE);
         sprintf(cmd_buf, DETECTHOOKS_CMD);
         if (write(fd, cmd_buf, strlen(cmd_buf)) < 0)
            __err("[__ERROR_2__]", perror, -1);
         printf("Scanning for hooked functions. Run \"dmesg\" to view results.\n");
         break;
      case 'm':
         // detect hidden modules
         memset(cmd_buf, 0x0, BUF_SIZE);
         sprintf(cmd_buf, DETECTMODULES_CMD);
         if (write(fd, cmd_buf, strlen(cmd_buf)) < 0)
            __err("[__ERROR_2__]", perror, -1);
         printf("Scanning for hidden modules. Run \"dmesg\" to view results.\n");
         break;
      case '?':
         printf("unknown option: %c\n", optopt);
         usage_err();
         break;
      case ':':
         usage_err();
      }
   }
}