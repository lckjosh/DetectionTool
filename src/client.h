#define DETECTPID_CMD "detectpid"
#define DETECTINODE_CMD "detectinode"
#define DETECTPORTS_CMD "detectports"
#define DETECTHOOKS_CMD "detecthooks"
#define DETECTMODULES_CMD "detectmods"

#define PROCFS_ENTRYNAME "/proc/detectiontool"

#define BUF_SIZE 16

#define usage_err_msg "[Usage] ./client [-p] [-f partition-to-scan] [-s] [-m]\n\
\t[-p] detect hidden PIDs\n\
\t[-f partition-to-scan] detect hidden files (./client -f /dev/sda1)\n\
\t[-n] detect hidden network ports\n\
\t[-s] detect hooked functions\n\
\t[-m] detect hidden modules\n"

#define hidden_proc_found_msg "[WARNING] There are hidden processes found on your system.\n\
[WARNING] There may be a rootkit installed on your system that is hiding these processes.\n"

#define hidden_proc_notfound_msg "[OK] There are no hidden processes found on your system.\n\
[OK] A rootkit may still be present on your system but is not hiding any process at the moment.\n"

#define hidden_port_found_msg "[WARNING] There are hidden ports found on your system.\n\
[WARNING] There may be a rootkit installed on your system that is hiding these ports.\n"

#define hidden_port_notfound_msg "[OK] There are no hidden ports found on your system.\n\
[OK] A rootkit may still be present on your system but is not hiding any ports at the moment.\n"

#define OPTS_STR ":pf:nsmh"

#define __err(msg, prnt_func, err_code) \
    do                                  \
    {                                   \
        prnt_func(msg);                 \
        return err_code;                \
    } while (0)

#define usage_err()            \
    do                         \
    {                          \
        printf(usage_err_msg); \
        return -1;             \
    } while (0)

//Makes text bold red
#define rk_warning_red_msg(msg) \
    printf("\x1b[1;31m"         \
           "%s"                 \
           "\x1b[0m",           \
           msg);

//Make text bold green
#define rk_ok_green_msg(msg) \
    printf("\x1b[1;32m"      \
           "%s"              \
           "\x1b[0m",        \
           msg);

#define HOOKED_FUNCTION_OUTPUT_DMESG_CMD "dmesg | grep \"detection tool\" | awk -F\':\' \'{ print $2}\' | awk \'{if ($0 ~ /-s/) {chunk=\"\"} else {chunk=chunk $0 RS}} END {printf \"%s\", chunk}\' | sed \'s/^ *//g\'"
#define HIDDEN_MODULE_OUTPUT_DMESG_CMD "dmesg | grep \"detection tool\" | awk -F\':\' \'{ print $2}\' | awk \'{if ($0 ~ /-m/) {chunk=\"\"} else {chunk=chunk $0 RS}} END {printf \"%s\", chunk}\' | sed \'s/^ *//g\'"
