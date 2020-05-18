// External commands
// =================
// we are looking only for real process not thread and only one by one
#define COMMAND "ps --no-header -p %i o pid"
// we are looking for session ID one by one
#define SESSION "ps --no-header -s %i o sess"
// We are looking for group ID one by one
// but ps can't select by pgid
#define PGID "ps --no-header -eL o pgid"
// We are looking for all processes even threads
#define THREADS "ps --no-header -eL o lwp"
// for sysinfo scanning, fall back to old command, as --no-header seems to create
// an extra process/thread
// #define SYS_COMMAND "ps -eL o lwp"
#define SYS_COMMAND "ps --no-header -eL o lwp"
// an extra process/thread
#define REVERSE "ps --no-header -eL o lwp,cmd"

// Masks for the checks to do in checkps
// =====================================
#define PS_PROC         0x00000001
#define PS_THREAD       0x00000002
#define PS_MORE         0x00000004