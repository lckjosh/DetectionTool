#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <math.h>
// Needed for unistd.h to declare getpgid() and others
#define _XOPEN_SOURCE 500

// Needed for sched.h to declare sched_getaffinity()
#define _GNU_SOURCE

#include <sys/stat.h>
#include <wait.h>
#include <sys/resource.h>
#include <errno.h>
#include <dirent.h>
#include <sched.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <ctype.h>
#include <time.h>

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

#define usage_err_msg "[Usage] ./client [-p] [-f]\n	\
[-p] detect hidden PIDs\n	\
[-f] detect hidden files\n"

#define OPTS_STR "pf"

#define __err(msg, prnt_func, err_code) \
    do                                  \
    {                                   \
        prnt_func(msg);                 \
        return err_code;                \
    } while (0)

#define usage_err() \
    do                         \
    {                          \
        printf(usage_err_msg); \
        return -1;             \
    } while (0)

// prototypes
void checkallquick(void);

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
            checkallquick();
            break;
        case 'f':
            // detect hidden files
            break;
        case '?':
            usage_err();
            break;
        case ':':
            usage_err();
        }
    }
}

/*
 *  Compare the various system calls against each other,
 *  and with fs function in /proc, finally check ps output
 */
void checkallquick(void) 
{

   int ret;
   int syspids;
   struct timespec tp;
   struct sched_param param;
   cpu_set_t mask;
   int found=0;
   int found_killbefore=0;
   int found_killafter=0;
   char directory[100], *pathpt;
   struct stat buffer;
   int statusproc, statusdir, backtodir ;
   char curdir[PATH_MAX] ;
   DIR *dir_fd;

   msgln(unlog, 0, "[*]Searching for Hidden processes through  comparison of results of system calls, proc, dir and ps\n") ;

   // get the path where Unhide is ran from.
   if (NULL == (pathpt = getcwd(curdir, PATH_MAX))) 
   {
      warnln(verbose, unlog, "Can't get current directory, test aborted.") ;
      return;
    }

   sprintf(directory,"/proc/");

   for ( syspids = 1; syspids <= maxpid; syspids++ ) 
   {
      // avoid ourselves
      if (syspids == mypid) 
      {
         continue;
      }
      // printf("syspid = %d\n", syspids); //DEBUG

      found=0;
      found_killbefore=0;
      found_killafter=0;

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killbefore=1;

      errno= 0 ;
      ret = getpriority(PRIO_PROCESS, syspids);
      if (errno == 0) found++;

      errno= 0 ;
      ret = getpgid(syspids);
      if (errno == 0) found++;

      errno= 0 ;
      ret = getsid(syspids);
      if (errno == 0) found++;

      errno= 0 ;
      ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
      if (ret == 0) found++;

      errno= 0 ;
      ret = sched_getparam(syspids, &param);
      if (errno == 0) found++;

      errno= 0 ;
      ret = sched_getscheduler(syspids);
      if (errno == 0) found++;

      errno=0;
      ret = sched_rr_get_interval(syspids, &tp);
      if (errno == 0) found++;

      sprintf(&directory[6],"%d",syspids);

      statusproc = stat(directory, &buffer) ;
      if (statusproc == 0) 
      {
         found++;
      }

      statusdir = chdir(directory) ;
      if (statusdir == 0) 
      {
         found++;
         if (-1 == (backtodir = chdir(curdir))) 
         {
            warnln(verbose, unlog, "Can't go back to unhide directory, test aborted.") ;
            return;
         }
      }

      dir_fd = opendir(directory) ;
      if (NULL != dir_fd) 
      {
         found++;
         closedir(dir_fd);
      }

      // Avoid checkps call if nobody sees anything
      if ((0 != found) || (0 != found_killbefore)) 
      {
         if(checkps(syspids,PS_PROC | PS_THREAD)) 
         {
            found++;
         }
      }

      errno=0;
      ret = kill(syspids, 0);
      if (errno == 0) found_killafter=1;


      /* these should all agree, except if a process went or came in the middle */
      if (found_killbefore == found_killafter) 
      {
         if ( ! ((found_killbefore == 0 && found == 0) ||
                 (found_killbefore == 1 && found == 11)) ) 
         {
            printbadpid(syspids);
         }
      } /* else: unreliable */
      else 
      {
         errno = 0 ;
         warnln(verbose, unlog, "syscall comparison test skipped for PID %d.", syspids) ;
      }
   }
}