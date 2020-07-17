#include <stdio.h>
#include <argp.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "detectports.h"

// flag for finding hidden ports
int hidden_found = 0;

// which checker to use
char checker[10] = "ss";

char output_buffer[200];

/* thx aramosf@unsec.net for the nice regexp! */

// Linux
char tcp4command1[] = "netstat -t4an | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'";
char tcp6command1[] = "netstat -t6an | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'";
char udp4command1[] = "netstat -u4an | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'";
char udp6command1[] = "netstat -u6an | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'";

// Alternative commands, needs iproute2
char tcp4command2[] = "ss -t4an sport = :%d | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'";
char tcp6command2[] = "ss -t6an sport = :%d | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'";
char udp4command2[] = "ss -u4an sport = :%d | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'";
char udp6command2[] = "ss -u6an sport = :%d | sed -e '/[\\.:][0-9]/!d' -e 's/.*[\\.:]\\([0-9]*\\) .*[\\.:].*/\\1/'";

/* Print a port*/
void print_port(enum Proto proto, int port)
{
    output_buffer[0] = 0; //Clear output buffer
    if (TCP == proto)
    {
        sprintf(output_buffer, "[WARNING] Possible hidden TCP port that does not appear in %s: %i \n", checker, port);
        rk_warning_red_msg(output_buffer);
    }
    if (TCP6 == proto)
    {
        sprintf(output_buffer, "[WARNING] Possible hidden TCP6 port that does not appear in %s: %i \n", checker, port);
        rk_warning_red_msg(output_buffer);
    }
    if (UDP == proto)
    {
        sprintf(output_buffer, "[WARNING] Possible hidden UDP port that does not appear in %s: %i \n", checker, port);
        rk_warning_red_msg(output_buffer);
    }
    if (UDP6 == proto)
    {
        sprintf(output_buffer, "[WARNING] Possible hidden UDP6 port that does not appear in %s: %i \n", checker, port);
        rk_warning_red_msg(output_buffer);
    }
}

/*
 * Check if port is seen by netstat.
 *
 * If not, report it and optionnally run lsof and/or fuser
 * to show more info.
 */
int checkoneport(int port, char command[])
{
    int ok = 0;
    char ports[30];
    char compare[100];

    FILE *fich_tmp;

    if (NULL != (fich_tmp = popen(command, "r")))
    {
        sprintf(compare, "%i\n", port);
        while ((NULL != fgets(ports, 30, fich_tmp)) && ok == 0)
        {
            if (strcmp(ports, compare) == 0)
            {
                ok = 1;
            }
        }
        pclose(fich_tmp);
    }
    else
    {
        printf("Couldn't execute command : %s while checking port %d", command, port);
    }
    return (ok);
}

/*
 * Check all TCP ports one by one.
 */
static void print_hidden_TCP_ports_1_by_1(enum Proto proto)
{
    int i;
    char tcpcommand[512];

    for (i = 1; i <= 65535; i++)
    {
        int socket_desc;
        struct sockaddr_in address;

        if (-1 != (socket_desc = socket(AF_INET, SOCK_STREAM, 0)))
        {
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = INADDR_ANY;
            address.sin_port = htons(i);
            errno = 0;
            if (-1 != bind(socket_desc, (struct sockaddr *)&address, sizeof(address)))
            {
                listen(socket_desc, 1);
                if (EADDRINUSE == errno) // port is listened by another process
                {
                    // use ss
                    if (strcmp("ss", checker) == 0)
                        sprintf(tcpcommand, tcp4command2, i);

                    // use netstat
                    else
                        strncpy(tcpcommand, tcp4command1, 512);

                    if (0 == checkoneport(i, tcpcommand))
                    {
                        // test again
                        listen(socket_desc, 1);
                        if (EADDRINUSE == errno) // port is still listened by another process
                        {
                            hidden_found = 1;
                            print_port(proto, i);
                        }
                    }
                    close(socket_desc);
                }
                else
                {
                    close(socket_desc);
                }
            }
            else
            {
                if (EADDRINUSE == errno) //port is in use by another process
                {
                    // use ss
                    if (strcmp("ss", checker) == 0)
                        sprintf(tcpcommand, tcp4command2, i);

                    // use netstat
                    else
                        strncpy(tcpcommand, tcp4command1, 512);

                    if (0 == checkoneport(i, tcpcommand))
                    {
                        // test again
                        if (-1 == bind(socket_desc, (struct sockaddr *)&address, sizeof(address)))
                        {
                            if (EADDRINUSE == errno) // port is still used by another process
                            {
                                hidden_found = 1;
                                print_port(proto, i);
                            }
                            else
                            {
                                printf("Can't bind to socket while checking port %d", i);
                            }
                            close(socket_desc);
                        }
                    }
                    else
                    {
                        close(socket_desc);
                    }
                }
            }
        }
        else
        {
            printf("Can't create socket while checking port %d/tcp", i);
        }
    }
}

/*
 * Check all UDP ports one by one.
 */
static void print_hidden_UDP_ports_1_by_1(enum Proto proto)
{
    int u;
    char udpcommand[512];

    for (u = 1; u <= 65535; u++)
    {
        int socket_desc;
        struct sockaddr_in address;

        if (-1 != (socket_desc = socket(AF_INET, SOCK_DGRAM, 0)))
        {
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = INADDR_ANY;
            address.sin_port = htons(u);
            errno = 0;
            if (0 != bind(socket_desc, (struct sockaddr *)&address, sizeof(address)))
            {
                if (EADDRINUSE == errno) //port is in use by another process
                {
                    // use ss
                    if (strcmp("ss", checker) == 0)
                        sprintf(udpcommand, udp4command2, u);

                    // use netstat
                    else
                        strncpy(udpcommand, udp4command1, 512);

                    if (0 == checkoneport(u, udpcommand))
                    {
                        // test again
                        if (0 != bind(socket_desc, (struct sockaddr *)&address, sizeof(address))) // port is still in use by another process
                        {
                            if (EADDRINUSE == errno) //port is in use by another process
                            {
                                hidden_found = 1;
                                print_port(proto, u);
                            }
                        }
                    }
                    close(socket_desc);
                }
                else // other error
                {
                    close(socket_desc);
                    printf("Can't bind to socket while checking port %d", u);
                }
            }
            else // port is available
            {
                close(socket_desc);
            }
        }
        else
        {
            printf("Can't create socket while checking port %d/udp", u);
        }
    }
}

/*
 * Check all TCP6 ports one by one.
 */
static void print_hidden_TCP6_ports_1_by_1(enum Proto proto)
{
    int i;
    char tcpcommand[512];
    int flag = 1; // turn on IPV6_V6ONLY flag to only check IPv6 sockets later because flag is off by recent kernel versions by default

    for (i = 1; i <= 65535; i++)
    {
        int socket_desc;
        struct sockaddr_in6 address;

        if (-1 != (socket_desc = socket(AF_INET6, SOCK_STREAM, 0)))
        {
            address.sin6_family = AF_INET6;
            address.sin6_addr = in6addr_any;
            address.sin6_port = htons(i);
            setsockopt(socket_desc, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&flag, sizeof(flag));
            errno = 0;
            if (-1 != bind(socket_desc, (struct sockaddr *)&address, sizeof(address)))
            {
                listen(socket_desc, 1);
                if (EADDRINUSE == errno) // port is listened by another process
                {
                    // use ss
                    if (strcmp("ss", checker) == 0)
                        sprintf(tcpcommand, tcp6command2, i);

                    // use netstat
                    else
                        strncpy(tcpcommand, tcp6command1, 512);

                    if (0 == checkoneport(i, tcpcommand))
                    {
                        // test again
                        listen(socket_desc, 1);
                        if (EADDRINUSE == errno) // port is still listened by another process
                        {
                            hidden_found = 1;
                            print_port(proto, i);
                        }
                    }
                    close(socket_desc);
                }
                else
                {
                    close(socket_desc);
                }
            }
            else
            {
                if (EADDRINUSE == errno) //port is in use by another process
                {
                    // use ss
                    if (strcmp("ss", checker) == 0)
                        sprintf(tcpcommand, tcp6command2, i);

                    // use netstat
                    else
                        strncpy(tcpcommand, tcp6command1, 512);

                    if (0 == checkoneport(i, tcpcommand))
                    {
                        // test again
                        if (-1 == bind(socket_desc, (struct sockaddr *)&address, sizeof(address)))
                        {
                            if (EADDRINUSE == errno) // port is still used by another process
                            {
                                hidden_found = 1;
                                print_port(proto, i);
                            }
                            else
                            {
                                printf("Can't bind to socket while checking port %d", i);
                            }
                            close(socket_desc);
                        }
                    }
                    else
                    {
                        close(socket_desc);
                    }
                }
            }
        }
        else
        {
            printf("Can't create socket while checking port %d/tcp6", i);
        }
    }
}

/*
 * Check all UDP6 ports one by one.
 */
static void print_hidden_UDP6_ports_1_by_1(enum Proto proto)
{
    int u;
    char udpcommand[512];
    int flag = 1; // turn on IPV6_V6ONLY flag to only check IPv6 sockets later because flag is off by recent kernel versions by default

    for (u = 1; u <= 65535; u++)
    {
        int socket_desc;
        struct sockaddr_in6 address;

        if (-1 != (socket_desc = socket(AF_INET6, SOCK_DGRAM, 0)))
        {
            address.sin6_family = AF_INET6;
            address.sin6_addr = in6addr_any;
            address.sin6_port = htons(u);
            setsockopt(socket_desc, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&flag, sizeof(flag));
            errno = 0;
            if (0 != bind(socket_desc, (struct sockaddr *)&address, sizeof(address)))
            {
                if (EADDRINUSE == errno) //port is in use by another process
                {
                    // use ss
                    if (strcmp("ss", checker) == 0)
                        sprintf(udpcommand, udp6command2, u);

                    // use netstat
                    else
                        strncpy(udpcommand, udp6command1, 512);

                    if (0 == checkoneport(u, udpcommand))
                    {
                        // test again
                        if (0 != bind(socket_desc, (struct sockaddr *)&address, sizeof(address))) // port is still in use by another process
                        {
                            if (EADDRINUSE == errno) //port is in use by another process
                            {
                                hidden_found = 1;
                                print_port(proto, u);
                            }
                        }
                    }
                    close(socket_desc);
                }
                else // other error
                {
                    close(socket_desc);
                    printf("Can't bind to socket while checking port %d", u);
                }
            }
            else // port is available
            {
                close(socket_desc);
            }
        }
        else
        {
            printf("Can't create socket while checking port %d/udp6", u);
        }
    }
}

/*
 * Look for TCP and UDP ports that are hidden to netstat.
 */
void checknetworkports(void)
{
    printf("[*] Searching for ports hidden in netstat/ss command...\n");
    // using ss
    strncpy(checker, "ss", 10);
    print_hidden_TCP_ports_1_by_1(TCP);
    print_hidden_TCP6_ports_1_by_1(TCP6);
    print_hidden_UDP_ports_1_by_1(UDP);
    print_hidden_UDP6_ports_1_by_1(UDP6);

    //using netstat
    strncpy(checker, "netstat", 10);
    print_hidden_TCP_ports_1_by_1(TCP);
    print_hidden_TCP6_ports_1_by_1(TCP6);
    print_hidden_UDP_ports_1_by_1(UDP);
    print_hidden_UDP6_ports_1_by_1(UDP6);
}
