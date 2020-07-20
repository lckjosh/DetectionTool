#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <math.h>
#include <sys/stat.h>
#include <getopt.h>

#include "client.h"

#include "detectpids.c"
#include "detectinodes.c"
#include "detectports.c"

int main(int argc, char **argv)
{
    if (argc < 2)
        usage_err();

    char cmd_buf[BUF_SIZE];
    int opt, fd;

    FILE *dmesg_cmd_tmp;
    char dmesg_cmd_buf[200];

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

            checkpids();

            if (found_HP)
            {
                rk_warning_red_msg(hidden_proc_found_msg);
            }
            else
            {
                rk_ok_green_msg(hidden_proc_notfound_msg);
            }
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
        case 'n':
            // detect hidden network ports
            if (getuid() != 0)
            {
                printf("You must be root to perform this function!\n");
                exit(1);
            }
            // Log to LKM
            memset(cmd_buf, 0x0, BUF_SIZE);
            sprintf(cmd_buf, DETECTPORTS_CMD);
            if (write(fd, cmd_buf, strlen(cmd_buf)) < 0)
            {
                __err("[__ERROR_2__]", perror, -1);
            }

            checknetworkports();

            if (hidden_found)
            {
                rk_warning_red_msg(hidden_port_found_msg);
            }
            else
            {
                rk_ok_green_msg(hidden_port_notfound_msg);
            }
            break;
        case 's':
            // detect hooked functions
            memset(cmd_buf, 0x0, BUF_SIZE);
            sprintf(cmd_buf, DETECTHOOKS_CMD);
            if (write(fd, cmd_buf, strlen(cmd_buf)) < 0)
                __err("[__ERROR_2__]", perror, -1);
            // printf("Scanning for hooked functions. Run \"dmesg\" to view results.\n");
            dmesg_cmd_buf[0] = 0;
            if (NULL != (dmesg_cmd_tmp = popen(HOOKED_FUNCTION_OUTPUT_DMESG_CMD, "r")))
            {
                while (NULL != fgets(dmesg_cmd_buf, 200, dmesg_cmd_tmp))
                {
                    if (strncmp("[WARNING]", dmesg_cmd_buf, 9) == 0)
                    {
                        rk_warning_red_msg(dmesg_cmd_buf);
                    }
                    else if (strncmp("[OK]", dmesg_cmd_buf, 4) == 0)
                    {
                        rk_ok_green_msg(dmesg_cmd_buf);
                    }
                    else
                    {
                        printf("%s", dmesg_cmd_buf);
                    }
                    dmesg_cmd_buf[0] = 0;
                }
                pclose(dmesg_cmd_tmp);
            }
            else
            {
                printf("Error: client.c could not run dmesg command to view output, Run \'dmesg\' to view results");
            }
            break;
        case 'm':
            // detect hidden modules
            memset(cmd_buf, 0x0, BUF_SIZE);
            sprintf(cmd_buf, DETECTMODULES_CMD);
            if (write(fd, cmd_buf, strlen(cmd_buf)) < 0)
                __err("[__ERROR_2__]", perror, -1);
            // printf("Scanning for hidden modules. Run \"dmesg\" to view results.\n");
            dmesg_cmd_buf[0] = 0;
            if (NULL != (dmesg_cmd_tmp = popen(HIDDEN_MODULE_OUTPUT_DMESG_CMD, "r")))
            {
                while (NULL != fgets(dmesg_cmd_buf, 200, dmesg_cmd_tmp))
                {
                    if (strncmp("[WARNING]", dmesg_cmd_buf, 9) == 0)
                    {
                        rk_warning_red_msg(dmesg_cmd_buf);
                    }
                    else if (strncmp("[OK]", dmesg_cmd_buf, 4) == 0)
                    {
                        rk_ok_green_msg(dmesg_cmd_buf);
                    }
                    else
                    {
                        printf("%s", dmesg_cmd_buf);
                    }
                    dmesg_cmd_buf[0] = 0;
                }
                pclose(dmesg_cmd_tmp);
            }
            else
            {
                printf("Error: client.c could not run dmesg command to view output, Run \'dmesg\' to view results");
            }

            break;
        case '?':
            printf("Error: Unknown option: -%c\n", optopt);
            usage_err();
            break;
        case ':':
            printf("Error: Option -%c requires an argument.\n", optopt);
            usage_err();
            break;
        case 'h':
            usage_err();
        }
    }
}
