// Needed for unistd.h to declare getpgid() and others
// #define _XOPEN_SOURCE 500

// Needed for sched.h to declare sched_getaffinity()
// #define _GNU_SOURCE

// Masks for the checks to do in checkps
// =====================================
#define PS_PROC 0x00000001
#define PS_THREAD 0x00000002

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wait.h>
#include <sys/resource.h>
#include <errno.h>
#include <dirent.h>
#include <sched.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <ctype.h>
#include <time.h>

#include "detectpids.h"

// defauly sysctl kernel.pid_max
int maxpid = 32768;

// our own PID
pid_t mypid;

// flag for hidden process
int found_HP = 0;

/*
 *  Get the maximum number of process on this system. 
 */
void get_max_pid(int *newmaxpid)
{
    char path[] = "/proc/sys/kernel/pid_max";
    pid_t tmppid = 0;
    FILE *fd = fopen(path, "r");
    if (!fd)
    {
        printf("Cannot read current maximum PID. Using default value %d", *newmaxpid);
        return;
    }

    if ((fscanf(fd, "%d", &tmppid) != 1) || tmppid < 1)
    {
        printf("Warning : Cannot get current maximum PID, error parsing %s format. Using default value %d", path, *newmaxpid);
        return;
    }
    else
    {
        *newmaxpid = tmppid;
    }
    fclose(fd);
}

/*
 *  Verify if ps see a given pid. 
 */
int checkps(int tmppid, int checks)
{

    int ok = 0;
    char pids[30];

    char compare[100];
    char command[60];

    FILE *fich_tmp;

    // printf("in --> checkps\n");   // DEBUG

    // The compare string is the same for all test
    sprintf(compare, "%i\n", tmppid);

    if (PS_PROC == (checks & PS_PROC))
    {
        sprintf(command, COMMAND, tmppid);

        fich_tmp = popen(command, "r");
        if (fich_tmp == NULL)
        {
            printf("Couldn't run command: %s while ps checking pid %d", command, tmppid);
            return (0);
        }

        {
            char *tmp_pids = pids;

            if (NULL != fgets(pids, 30, fich_tmp))
            {
                pids[29] = 0;

                //          printf("pids = %s\n", pids);   // DEBUG
                while (*tmp_pids == ' ' && tmp_pids <= pids + 29)
                {
                    tmp_pids++;
                }

                if (strncmp(tmp_pids, compare, 30) == 0)
                {
                    ok = 1;
                }
            }
        }

        if (NULL != fich_tmp)
            pclose(fich_tmp);

        if (1 == ok)
            return (ok); // pid is found, no need to go further
    }

    if (PS_THREAD == (checks & PS_THREAD))
    {
        FILE *fich_thread;

        fich_thread = popen(THREADS, "r");
        if (NULL == fich_thread)
        {
            printf("Couldn't run command: %s while ps checking pid %d", THREADS, tmppid);
            return (0);
        }

        while ((NULL != fgets(pids, 30, fich_thread)) && ok == 0)
        {
            char *tmp_pids = pids;

            pids[29] = 0;

            while (*tmp_pids == ' ' && tmp_pids <= pids + 29)
            {
                tmp_pids++;
            }

            if (strncmp(tmp_pids, compare, 30) == 0)
            {
                ok = 1;
            }
        }
        if (fich_thread != NULL)
            pclose(fich_thread);

        if (1 == ok)
            return (ok); // thread is found, no need to go further
    }

    if (PS_MORE == (checks & PS_MORE))
    {

        FILE *fich_session;

        sprintf(command, SESSION, tmppid);

        fich_session = popen(command, "r");
        if (fich_session == NULL)
        {
            printf("Couldn't run command: %s while ps checking pid %d", command, tmppid);
            return (0);
        }

        while ((NULL != fgets(pids, 30, fich_session)) && ok == 0)
        {
            char *tmp_pids = pids;

            pids[29] = 0;

            while (*tmp_pids == ' ' && tmp_pids <= pids + 29)
            {
                tmp_pids++;
            }

            if (strncmp(tmp_pids, compare, 30) == 0)
            {
                ok = 1;
            }
        }

        pclose(fich_session);

        if (1 == ok)
            return (ok); // session is found, no need to go further

        FILE *fich_pgid;

        fich_pgid = popen(PGID, "r");
        if (NULL == fich_pgid)
        {
            printf("Couldn't run command: %s while ps checking pid %d", PGID, tmppid);
            return (0);
        }

        while ((NULL != fgets(pids, 30, fich_pgid)) && ok == 0)
        {
            char *tmp_pids = pids;

            pids[29] = 0;

            while (*tmp_pids == ' ' && tmp_pids <= pids + 29)
            {
                tmp_pids++;
            }

            if (strncmp(tmp_pids, compare, 30) == 0)
            {
                ok = 1;
            }
        }

        pclose(fich_pgid);
    }
    return ok;
}

/*
 *  Display hidden process and possibly some information on it. 
 */
void printbadpid(int tmppid)
{
    // Set text colour to red
    printf("\x1b[1;31m");

    int statuscmd;
    char cmd[100];
    struct stat buffer;
    FILE *cmdfile;
    char cmdcont[1000], fmtstart[128];
    int cmdok = 0, cmdok2 = 0;

    found_HP = 1;
    sprintf(fmtstart, "[WARNING] Found HIDDEN PID: %i", tmppid);
    printf("%s", fmtstart);

    sprintf(cmd, "/proc/%i/cmdline", tmppid);

    statuscmd = stat(cmd, &buffer);
    // statuscmd = 0 ;  // DEBUG

    if (statuscmd == 0)
    {
        cmdfile = fopen(cmd, "r");
        if (cmdfile != NULL)
        {
            while ((NULL != fgets(cmdcont, 1000, cmdfile)) && 0 == cmdok)
            {
                cmdok++;
                printf("\tCmdline: \"%s\"", cmdcont);
            }
            fclose(cmdfile);
        }
    }
    if (0 == cmdok)
    {
        printf("\tCmdline: \"<none>\"");
    }

    { // try to readlink the exe
        ssize_t length;

        sprintf(cmd, "/proc/%i/exe", tmppid);
        statuscmd = lstat(cmd, &buffer);
        //    printf("%s",cmd) ; //DEBUG
        //      printf("\tstatuscmd : %d\n",statuscmd) ; //DEBUG
        if (statuscmd == 0)
        {
            length = readlink(cmd, cmdcont, 1000);
            //         printf("\tLength : %0d\n",(int)length) ; //DEBUG
            if (-1 != length)
            {
                cmdcont[length] = 0; // terminate the string
                cmdok++;
                printf("\tExecutable: \"%s\"", cmdcont);
            }
            else
            {
                printf("\tExecutable: \"<nonexistant>\"");
            }
        }
        else
        {
            printf("\tExecutable: \"<no link>\"");
        }
    }
    { // read internal command name
        sprintf(cmd, "/proc/%i/comm", tmppid);
        statuscmd = stat(cmd, &buffer);
        if (statuscmd == 0)
        {
            cmdfile = fopen(cmd, "r");
            if (cmdfile != NULL)
            {
                //       printf("\tCmdFile : %s\n",cmd) ; //DEBUG
                while ((NULL != fgets(cmdcont, 1000, cmdfile)) && 0 == cmdok2)
                {
                    cmdok2++;
                    //               printf("\tLastChar : %x\n",cmdcont[strlen(cmdcont)]) ; //DEBUG
                    if (cmdcont[strlen(cmdcont) - 1] == '\n')
                    {
                        cmdcont[strlen(cmdcont) - 1] = 0; // get rid of newline
                    }
                    if (0 == cmdok) // it is a kthreed : add brackets
                    {
                        printf("\tCommand: \"[%s]\"", cmdcont);
                    }
                    else
                    {
                        printf("\tCommand: \"%s\"", cmdcont);
                    }
                }
                fclose(cmdfile);
            }
            else
            {
                printf("\tCommand: \"can't read file\"");
            }
        }
        else
        {
            printf("\t\"<none>  ... maybe a transitory process\"");
        }
    }
    // try to print some useful info about the hidden process
    // does not work well for kernel processes/threads and deamons
    {
        FILE *fich_tmp;

        sprintf(cmd, "/proc/%i/environ", tmppid);
        statuscmd = stat(cmd, &buffer);
        if (statuscmd == 0)
        {
            sprintf(cmd, "cat /proc/%i/environ | tr \"\\0\" \"\\n\" | grep -w 'USER'", tmppid);
            //      printf(cmd) ;
            fich_tmp = popen(cmd, "r");
            if (fich_tmp == NULL)
            {
                printf("\tCouldn't read USER for pid %d", tmppid);
            }

            if (NULL != fgets(cmdcont, 30, fich_tmp))
            {
                cmdcont[strlen(cmdcont) - 1] = 0; // get rid of newline
                printf("\t$%s", cmdcont);
            }
            else
            {
                printf("\t$USER=%s", cmdcont);
            }
            pclose(fich_tmp);

            sprintf(cmd, "cat /proc/%i/environ | tr \"\\0\" \"\\n\" | grep -w 'PWD'", tmppid);
            //      printf(cmd) ;
            fich_tmp = popen(cmd, "r");
            if (fich_tmp == NULL)
            {
                printf("\tCouldn't read PWD for pid %d", tmppid);
            }

            if (NULL != fgets(cmdcont, 30, fich_tmp))
            {
                cmdcont[strlen(cmdcont) - 1] = 0; // get rid of newline
                printf("\t$%s", cmdcont);
            }
            else
            {
                printf("\t$PWD=%s", cmdcont);
            }
            pclose(fich_tmp);

            //      printf("Done !\n");
        }
    }

    // Set text colour back to normal
    printf("\x1b[1;32m");
    printf("\n");
}

/*
 *  Compare the various system calls against each other,
 *  and with fs function in /proc, finally check ps output
 */
void checkpids(void)
{

    int ret;
    int syspids;
    struct timespec tp;
    struct sched_param param;
    cpu_set_t mask;
    int found = 0;
    int found_killbefore = 0;
    int found_killafter = 0;
    char directory[100], *pathpt;
    struct stat buffer;
    int statusproc, statusdir, backtodir;
    char curdir[PATH_MAX];
    DIR *dir_fd;

    printf("[*] Searching for hidden processes through the comparison of the results of system calls, proc, dir and ps...\n");

    // get the path where Unhide is ran from.
    if (NULL == (pathpt = getcwd(curdir, PATH_MAX)))
    {
        printf("Can't get current directory, test aborted.");
        return;
    }

    sprintf(directory, "/proc/");

    get_max_pid(&maxpid);
    mypid = getpid();

    for (syspids = 1; syspids <= maxpid; syspids++)
    {
        // avoid ourselves
        if (syspids == mypid)
        {
            continue;
        }
        // printf("syspid = %d\n", syspids); //DEBUG

        found = 0;
        found_killbefore = 0;
        found_killafter = 0;

        errno = 0;
        ret = kill(syspids, 0);
        if (errno == 0)
            found_killbefore = 1;

        errno = 0;
        ret = getpriority(PRIO_PROCESS, syspids);
        if (errno == 0)
            found++;

        errno = 0;
        ret = getpgid(syspids);
        if (errno == 0)
            found++;

        errno = 0;
        ret = getsid(syspids);
        if (errno == 0)
            found++;

        errno = 0;
        ret = sched_getaffinity(syspids, sizeof(cpu_set_t), &mask);
        if (ret == 0)
            found++;

        errno = 0;
        ret = sched_getparam(syspids, &param);
        if (errno == 0)
            found++;

        errno = 0;
        ret = sched_getscheduler(syspids);
        if (errno == 0)
            found++;

        errno = 0;
        ret = sched_rr_get_interval(syspids, &tp);
        if (errno == 0)
            found++;

        sprintf(&directory[6], "%d", syspids);

        statusproc = stat(directory, &buffer);
        if (statusproc == 0)
        {
            found++;
        }

        statusdir = chdir(directory);
        if (statusdir == 0)
        {
            found++;
            if (-1 == (backtodir = chdir(curdir)))
            {
                printf("Can't go back to unhide directory, test aborted.");
                return;
            }
        }

        dir_fd = opendir(directory);
        if (NULL != dir_fd)
        {
            found++;
            closedir(dir_fd);
        }

        // Avoid checkps call if nobody sees anything
        if ((0 != found) || (0 != found_killbefore))
        {
            if (checkps(syspids, PS_PROC | PS_THREAD))
            {
                found++;
            }
        }

        errno = 0;
        ret = kill(syspids, 0);
        if (errno == 0)
            found_killafter = 1;

        /* these should all agree, except if a process went or came in the middle */
        if (found_killbefore == found_killafter)
        {
            if (!((found_killbefore == 0 && found == 0) ||
                  (found_killbefore == 1 && found == 11)))
            {
                printbadpid(syspids);
            }
        } /* else: unreliable */
        else
        {
            errno = 0;
            printf("syscall comparison test skipped for PID %d.", syspids);
        }
    }
}
