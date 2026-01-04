/*
 * Fsh - The Friendly Shell v3.3.3
 * Features: 500+ CMD Translations | Persian UTF-8 | Pipe | &&/& | Enhanced Safety
 */

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <strings.h>
#include <termios.h>
#include <glob.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>

#define FSH_MAX_INPUT 4096
#define FSH_MAX_ARGS 128
#define FSH_MAX_HISTORY 1000
#define FSH_MAX_BIN_CMDS 10000
#define FSH_MAX_ALIASES 100
#define FSH_MAX_PIPE_CMDS 10

#define COLOR_RED     "\033[1;31m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"
#define COLOR_MAGENTA "\033[1;35m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_WHITE   "\033[1;37m"
#define COLOR_RESET   "\033[0m"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-truncation"

// STRUCTURES
typedef struct {
    const char* windows_cmd;
    const char* linux_cmd;
    const char* description;
} CmdMapping;

typedef struct {
    const char* persian;
    char english;
} KeyMapping;

typedef struct {
    const char* name;
    int (*func)(char** args);
} BuiltinCommand;

typedef struct {
    char** commands;
    int count;
    int capacity;
    int current_index;
} CommandHistory;

typedef struct {
    char** commands;
    int count;
    int capacity;
} SystemCommands;

typedef struct {
    char* name;
    char* value;
} Alias;

typedef struct {
    char* cmd;
    int background;
} CommandChain;

// CRITICAL: FORWARD DECLARATIONS - ALL functions must be declared before use
static void sigchld_handler(int sig);
static const BuiltinCommand* find_builtin(const char* cmd);
static int builtin_type(char** args);
static void enable_raw_mode(void);
static void disable_raw_mode(void);
static const char* history_up(void);
static const char* history_down(void);
static void reset_history_position(void);
static void init_history(void);
static void save_history(void);
static void add_to_history(const char* command);
static void scan_directory(const char* path, SystemCommands* cmd_list);
static int is_utf8_start_byte(unsigned char c);
static int utf8_char_length(unsigned char c);
static int contains_persian(const char* input);
static void persian_to_english_layout(char* input);
static void cleanup_system_commands(void);
static void init_command_database(void);
static int levenshtein_distance(const char* s1, const char* s2);
static const char* find_best_suggestion(const char* input);
static const char* translate_cmd(const char* input);
static int is_dangerous_command(char** args);
static int confirm_dangerous_command(char** args);
static void exec_pipe_commands(char*** pipe_args, int pipe_count);
static char* read_input_with_history(void);
static void execute_single_command(char* cmd_line);
static void execute_piped_commands(char* cmd_line);
static int execute_command_line(char* input);
static void print_banner(void);

// Built-in implementations
int builtin_cd(char** args);
int builtin_pwd(char** args);
int builtin_exit(char** args);
int builtin_export(char** args);
int builtin_history(char** args);
int builtin_alias(char** args);
int builtin_unalias(char** args);
int builtin_clear(char** args);
int builtin_stats(char** args);
int builtin_echo(char** args);
int builtin_set(char** args);
int builtin_unset(char** args);
int builtin_umask(char** args);
int builtin_jobs(char** args);
int builtin_kill(char** args);
int builtin_type(char** args);

// GLOBALS
static CommandHistory history = {0};
static SystemCommands bin_cmds = {0};
static SystemCommands sbin_cmds = {0};
static SystemCommands all_cmds = {0};
static Alias aliases[FSH_MAX_ALIASES] = {0};
static int alias_count = 0;
static struct termios orig_termios;
static int raw_mode_enabled = 0;
static int last_exit_status = 0;

typedef struct {
    time_t start_time;
    int commands_executed;
    int commands_translated;
    int persian_converted;
    int typos_corrected;
    int pipes_executed;
    int background_jobs;
    int windows_cmds_used;
    int dangerous_commands_blocked;
} SessionStats;

static SessionStats stats = {0};


int builtin_type(char** args) {
    if (!args[1]) {
        printf("Usage: type command\n");
        return 1;
    }
    const BuiltinCommand* builtin = find_builtin(args[1]);
    if (builtin) {
        printf("%s is a shell builtin\n", args[1]);
    } else {
        printf("%s is an external command\n", args[1]);
    }
    return 0;
}

static char distro_name[64] = "FarazOS";
static void detect_distro_name(void) {
    FILE* f = fopen("/etc/os-release", "r");
    if (!f) return;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "NAME=", 12) == 0) { // you can replace with PRETTY_NAME=
            char* val = line + 12;
            // Remove leading quote if present
            if (*val == '\"') val++;
            // Remove trailing quote and newline if present
            size_t len = strlen(val);
            while (len > 0 && (val[len-1] == '\\n' || val[len-1] == '\"')) {
                val[--len] = '\\0';
            }
            strncpy(distro_name, val, sizeof(distro_name)-1);
            distro_name[sizeof(distro_name)-1] = '\\0';
            break;
        }
    }
    fclose(f);
}

// 500+ Windows CMD translations
static const CmdMapping cmd_mappings[] = {
    // Basic Commands
    {"dir", "ls -lh --color=auto", "List directory contents"},
    {"ls", "ls --color=auto", "List files"},
    {"copy", "cp -i", "Copy files"},
    {"xcopy", "cp -r", "Copy directories"},
    {"del", "rm -i", "Delete files"},
    {"erase", "rm -i", "Delete files"},
    {"move", "mv -i", "Move/rename files"},
    {"ren", "mv", "Rename files"},
    {"rename", "mv", "Rename files"},
    {"type", "cat", "Display file content"},
    {"more", "less", "View file page by page"},
    {"cls", "clear", "Clear screen"},
    {"cd", "cd", "Change directory"},
    {"chdir", "cd", "Change directory"},
    {"mkdir", "mkdir -p", "Make directory"},
    {"md", "mkdir -p", "Make directory"},
    {"rmdir", "rmdir", "Remove empty directory"},
    {"rd", "rmdir", "Remove empty directory"},
    {"pushd", "pushd", "Push directory to stack"},
    {"popd", "popd", "Pop directory from stack"},
    {"dirs", "dirs", "Show directory stack"},
    
    // File Attributes & Permissions
    {"attrib", "chmod", "Change file attributes"},
    {"cacls", "setfacl", "Change ACLs"},
    {"icacls", "setfacl", "Change ACLs"},
    {"takeown", "chown", "Take ownership"},
    {"icacls /grant", "setfacl -m u", "Grant permissions"},
    {"icacls /deny", "setfacl -m u", "Deny permissions"},
    {"icacls /remove", "setfacl -x", "Remove permissions"},
    {"icacls /reset", "setfacl -b", "Reset ACLs"},
    
    // Disk & Filesystem (EXPANDED)
    {"chkdsk", "fsck", "Check disk"},
    {"chkdsk /f", "fsck -f", "Fix filesystem errors"},
    {"chkdsk /r", "fsck -c", "Check bad sectors"},
    {"chkdsk /x", "umount && fsck", "Force unmount and check"},
    {"diskpart", "fdisk || gdisk || parted", "Disk partition tool"},
    {"diskpart /s", "fdisk <", "Scripted partition"},
    {"format", "mkfs", "Format disk"},
    {"format /fs:ntfs", "mkfs.ntfs", "Format NTFS"},
    {"format /fs:fat32", "mkfs.vfat -F 32", "Format FAT32"},
    {"format /q", "mkfs -f", "Quick format"},
    {"defrag", "e4defrag", "Defragment disk"},
    {"defrag /c", "e4defrag /dev/sd*", "Defrag all volumes"},
    {"defrag /a", "e4defrag -c", "Analyze only"},
    {"compact", "btrfs filesystem defragment -czstd", "Compact files"},
    {"compact /c", "chattr +c", "Compress files"},
    {"compact /u", "chattr -c", "Uncompress files"},
    {"cipher", "cryptsetup", "Encrypt files"},
    {"cipher /e", "cryptsetup luksFormat", "Encrypt drive"},
    {"cipher /d", "cryptsetup luksRemove", "Decrypt drive"},
    {"vssadmin", "btrfs subvolume", "Volume shadow copy"},
    {"vssadmin create", "btrfs subvolume snapshot", "Create shadow copy"},
    {"vssadmin list", "btrfs subvolume list", "List snapshots"},
    {"vssadmin delete", "btrfs subvolume delete", "Delete snapshot"},
    {"subst", "mount --bind", "Substitute path"},
    {"subst /d", "umount", "Delete substitution"},
    
    // System Information (EXPANDED)
    {"ver", "uname -a", "Show version"},
    {"systeminfo", "neofetch || screenfetch || inxi -F", "System information"},
    {"wmic", "lshw || hwinfo", "Hardware info"},
    {"wmic cpu", "lscpu", "CPU info"},
    {"wmic memory", "free -h", "Memory info"},
    {"wmic diskdrive", "lsblk -d", "Disk info"},
    {"wmic process", "ps aux", "Process info"},
    {"msinfo32", "inxi -F", "System information"},
    {"dxdiag", "glxinfo || vulkaninfo", "DirectX diagnostics"},
    {"driverquery", "lsmod", "List drivers"},
    {"driverquery /v", "modinfo", "Driver details"},
    {"perfmon", "htop || atop", "Performance monitor"},
    {"resmon", "atop", "Resource monitor"},
    {"taskmgr", "htop", "Task manager"},
    {"msconfig", "systemctl", "System configuration"},
    {"control", "systemctl", "Control panel"},
    {"appwiz.cpl", "dpkg -l || rpm -qa", "Add/remove programs"},
    {"compmgmt.msc", "sudo -i", "Computer management"},
    {"devmgmt.msc", "ls /dev", "Device manager"},
    {"diskmgmt.msc", "lsblk", "Disk management"},
    {"fsmgmt.msc", "df -h", "Shared folders"},
    {"gpedit.msc", "visudo", "Group policy"},
    {"lusrmgr.msc", "vipw", "Local users"},
    {"secpol.msc", "visudo", "Security policy"},
    {"credwiz", "pass", "Credential wizard"},
    {"certmgr.msc", "update-ca-certificates", "Certificate manager"},
    {"eventvwr", "journalctl -p err", "Event viewer"},
    {"wevtutil", "journalctl", "Event utility"},
    {"eventquery.vbs", "journalctl --since", "Query events"},
    {"eventcreate", "logger", "Create event"},
    {"eventtriggers", "systemd-path", "Event triggers"},
    {"sharedoc", "hostname -i", "Shared folders"},
    
    // Process Management (EXPANDED)
    {"tasklist", "ps aux", "List processes"},
    {"tasklist /v", "ps auxf", "Detailed processes"},
    {"tasklist /fi", "ps aux | grep", "Filter processes"},
    {"tasklist /fo", "ps -o", "Formatted output"},
    {"taskkill", "kill", "Kill process"},
    {"taskkill /f", "kill -9", "Force kill process"},
    {"taskkill /t", "kill -9 -", "Kill process tree"},
    {"taskkill /im", "pkill -f", "Kill by image name"},
    {"taskkill /pid", "kill", "Kill by PID"},
    {"start", "nohup", "Start process"},
    {"start /min", "nohup &", "Start minimized"},
    {"start /max", "nohup &", "Start maximized"},
    {"start /wait", "wait", "Start and wait"},
    {"start /low", "nice -n 19", "Start low priority"},
    {"start /high", "nice -n -20", "Start high priority"},
    {"runas", "sudo", "Run as administrator"},
    {"runas /user", "sudo -u", "Run as specific user"},
    {"qprocess", "lsof -i", "Query processes"},
    {"qappsrv", "ss -tuln", "Query application servers"},
    {"qwinsta", "loginctl list-sessions", "Query sessions"},
    {"rwinsta", "loginctl terminate-session", "Reset session"},
    {"tsdiscon", "loginctl terminate-user", "Disconnect session"},
    {"tskill", "pkill", "Terminate session"},
    {"shadow", "ssh", "Shadow session"},
    
    // Network Commands (EXPANDED)
    {"ipconfig", "ip a || ifconfig", "Network configuration"},
    {"ipconfig /all", "ip a", "Detailed network config"},
    {"ipconfig /release", "dhclient -r", "Release IP"},
    {"ipconfig /renew", "dhclient", "Renew IP"},
    {"ipconfig /flushdns", "resolvectl flush-caches", "Flush DNS"},
    {"ipconfig /displaydns", "resolvectl statistics", "Display DNS cache"},
    {"ipconfig /registerdns", "resolvectl revert", "Register DNS"},
    {"ipconfig /showclassid", "ip a show", "Show class ID"},
    {"ipconfig /setclassid", "ip a set", "Set class ID"},
    {"ping", "ping", "Ping host"},
    {"ping -t", "ping", "Ping until interrupted"},
    {"ping -n", "ping -c", "Ping count"},
    {"ping -l", "ping -s", "Ping buffer size"},
    {"tracert", "traceroute", "Trace route"},
    {"tracert -d", "traceroute -n", "No resolution"},
    {"tracert -h", "traceroute -m", "Max hops"},
    {"tracert -w", "traceroute -w", "Timeout"},
    {"pathping", "mtr", "Path ping"},
    {"pathping -n", "mtr -n", "No resolution"},
    {"pathping -h", "mtr -m", "Max hops"},
    {"pathping -w", "mtr -w", "Timeout"},
    {"nslookup", "nslookup", "DNS lookup"},
    {"nslookup -type=mx", "dig mx", "MX record lookup"},
    {"nslookup -type=ns", "dig ns", "NS record lookup"},
    {"netstat", "ss -tuln", "Network statistics"},
    {"netstat -a", "ss -a", "All connections"},
    {"netstat -an", "ss -tuln", "All numeric"},
    {"netstat -b", "ss -p", "With programs"},
    {"netstat -e", "ss -i", "Ethernet stats"},
    {"netstat -f", "ss -f", "FQDN"},
    {"netstat -n", "ss -n", "Numeric"},
    {"netstat -o", "ss -p", "PID"},
    {"netstat -p", "ss -p", "Protocol"},
    {"netstat -r", "ip route", "Route table"},
    {"netstat -s", "ss -s", "Stats"},
    {"netstat -t", "ss -t", "TCP only"},
    {"netstat -u", "ss -u", "UDP only"},
    {"route", "ip route", "View route table"},
    {"route print", "ip route show", "Print routes"},
    {"route add", "ip route add", "Add route"},
    {"route delete", "ip route del", "Delete route"},
    {"route change", "ip route replace", "Change route"},
    {"route -f", "ip route flush", "Flush routes"},
    {"route -p", "ip route add permanent", "Persistent route"},
    {"arp", "ip neigh", "ARP table"},
    {"arp -a", "ip neigh show", "ARP cache"},
    {"arp -d", "ip neigh del", "Delete ARP entry"},
    {"arp -s", "ip neigh add", "Add static ARP"},
    {"arp -g", "ip neigh show", "Same as -a"},
    {"getmac", "ip link show", "Get MAC address"},
    {"getmac /v", "ip -d link show", "Verbose MAC info"},
    {"getmac /fo", "ip -o link show", "Formatted output"},
    {"hostname", "hostname", "Show hostname"},
    {"hostname /f", "hostname -f", "FQDN hostname"},
    {"nbtstat", "nmblookup", "NetBIOS stats"},
    {"nbtstat -a", "nmblookup -A", "Adapter status"},
    {"nbtstat -c", "nmblookup -c", "Cache"},
    {"nbtstat -n", "nmblookup -n", "Local names"},
    {"nbtstat -r", "nmblookup -r", "Resolved names"},
    {"nbtstat -R", "nmblookup -R", "Reload cache"},
    {"nbtstat -S", "nmblookup -S", "Sessions"},
    {"ftp", "ftp", "FTP client"},
    {"ftp -s", "ftp -n <", "FTP script"},
    {"telnet", "telnet", "Telnet client"},
    {"telnet -l", "telnet -l", "Login user"},
    {"tftp", "tftp", "TFTP client"},
    {"tftp -i", "tftp -b", "Binary mode"},
    {"rcp", "scp", "Remote copy"},
    {"rexec", "ssh", "Remote execute"},
    {"rsh", "ssh", "Remote shell"},
    {"finger", "finger", "Finger protocol"},
    {"whois", "whois", "Whois query"},
    
    // Services & Daemons (EXPANDED)
    {"sc query", "systemctl status", "Query service"},
    {"sc queryex", "systemctl show", "Extended query"},
    {"sc query type= driver", "lsmod", "Query drivers"},
    {"sc query type= service", "systemctl list-units", "Query services"},
    {"sc query state= all", "systemctl --all", "All services"},
    {"sc query state= inactive", "systemctl list-units --inactive", "Inactive services"},
    {"sc start", "systemctl start", "Start service"},
    {"sc stop", "systemctl stop", "Stop service"},
    {"sc pause", "systemctl kill -s STOP", "Pause service"},
    {"sc continue", "systemctl kill -s CONT", "Continue service"},
    {"sc config", "systemctl enable", "Configure service"},
    {"sc config start= auto", "systemctl enable", "Auto-start"},
    {"sc config start= demand", "systemctl disable", "Manual start"},
    {"sc config start= disabled", "systemctl disable", "Disabled"},
    {"sc create", "systemctl create", "Create service"},
    {"sc delete", "systemctl disable --now", "Delete service"},
    {"sc description", "systemctl set-description", "Set description"},
    {"sc failure", "systemctl set-failure", "Set failure action"},
    {"sc sdshow", "systemctl show", "Show security descriptor"},
    {"sc sdset", "systemctl set", "Set security descriptor"},
    {"sc qc", "systemctl cat", "Query config"},
    {"sc qdescription", "systemctl show", "Query description"},
    {"sc qfailure", "systemctl show", "Query failure"},
    {"net start", "systemctl start", "Start service"},
    {"net stop", "systemctl stop", "Stop service"},
    {"net pause", "systemctl kill -s STOP", "Pause service"},
    {"net continue", "systemctl kill -s CONT", "Continue service"},
    {"net use", "mount -t cifs", "Use network share"},
    {"net use /d", "umount", "Delete share"},
    {"net use /p", "mount -a", "Persistent connection"},
    {"net share", "exportfs", "Share resources"},
    {"net share /d", "exportfs -u", "Delete share"},
    {"net view", "smbtree", "View shares"},
    {"net view /domain", "smbtree -D", "View domain"},
    {"net session", "smbstatus", "View sessions"},
    {"net session /d", "smbcontrol close-share", "Delete session"},
    {"net file", "lsof /shared", "Open files"},
    {"net file /c", "fuser -k", "Close file"},
    {"net statistics", "smbstatus", "Share stats"},
    {"net statistics workstation", "smbstatus", "Workstation stats"},
    {"net statistics server", "smbstatus", "Server stats"},
    {"net accounts", "chage -l", "Account policies"},
    {"net accounts /minpwlen", "chage -m", "Min password length"},
    {"net accounts /maxpwage", "chage -M", "Max password age"},
    {"net accounts /minpwage", "chage -m", "Min password age"},
    {"net accounts /uniquepw", "chage -u", "Unique password"},
    {"net accounts /domain", "realm list", "Domain accounts"},
    {"net localgroup", "cat /etc/group", "Local groups"},
    {"net localgroup /add", "groupadd", "Add group"},
    {"net localgroup /delete", "groupdel", "Delete group"},
    {"net user", "cat /etc/passwd", "List users"},
    {"net user /add", "useradd", "Add user"},
    {"net user /delete", "userdel", "Delete user"},
    {"net user /active", "usermod -e", "Set active"},
    {"net user /fullname", "usermod -c", "Set full name"},
    {"net user /homedir", "usermod -d", "Set home dir"},
    {"net user /profilepath", "usermod -d", "Set profile path"},
    {"net user /logonscript", "usermod -s", "Set logon script"},
    {"net user /homedirreq", "usermod -d", "Require home dir"},
    {"net user /passwordreq", "passwd -l", "Require password"},
    {"net user /times", "usermod -e", "Logon hours"},
    {"net user /workstations", "usermod -h", "Workstation logon"},
    {"net user /domain", "realm list", "Domain users"},
    {"net user /expires", "chage -E", "Account expires"},
    {"net user /passwordchg", "passwd -n", "Password change"},
    {"net user /passwordlog", "passwd -w", "Password logon"},
    {"net config", "systemctl show", "Network config"},
    {"net config server", "smbstatus", "Server config"},
    {"net config workstation", "hostnamectl", "Workstation config"},
    {"net time", "timedatectl", "Network time"},
    {"net time /set", "timedatectl set-time", "Set time"},
    {"net time /querysntp", "timedatectl show-timesync", "Query NTP"},
    {"net time /setsntp", "timedatectl set-ntp", "Set NTP"},
    {"net print", "lpq", "Print queue"},
    {"net print /d", "lprm", "Delete print job"},
    {"net name", "hostname", "NetBIOS name"},
    {"net name /add", "hostnamectl set-hostname", "Add name"},
    {"net name /delete", "hostnamectl set-hostname", "Delete name"},
    {"net send", "wall", "Send message"},
    {"net send /users", "wall", "Send to users"},
    {"net send /domain", "wall", "Send to domain"},
    {"services.msc", "systemctl list-unit-files --type=service", "Service manager"},
    {"compmgmt.msc", "sudo -i", "Computer management"},
    {"devmgmt.msc", "ls /dev", "Device manager"},
    {"diskmgmt.msc", "lsblk", "Disk management"},
    {"fsmgmt.msc", "df -h", "Shared folders"},
    {"gpedit.msc", "visudo", "Group policy"},
    {"lusrmgr.msc", "vipw", "Local users"},
    {"secpol.msc", "visudo", "Security policy"},
    {"perfmon.msc", "htop", "Performance monitor"},
    {"eventvwr.msc", "journalctl", "Event viewer"},
    {"taskschd.msc", "systemctl list-timers", "Task scheduler"},
    
    // Printing (EXPANDED)
    {"print", "lp", "Print file"},
    {"lpr", "lpr", "Print file"},
    {"lpq", "lpq", "Print queue"},
    {"lprm", "lprm", "Remove print job"},
    {"cupsctl", "cupsctl", "CUPS control"},
    {"cupsaccept", "cupsaccept", "Accept jobs"},
    {"cupsreject", "cupsreject", "Reject jobs"},
    {"cupsdisable", "cupsdisable", "Disable queue"},
    {"cupsenable", "cupsenable", "Enable queue"},
    {"cancel", "cancel", "Cancel print job"},
    {"cancel -a", "cancel -a", "Cancel all jobs"},
    {"lpstat", "lpstat", "Printer status"},
    {"lpstat -p", "lpstat -p", "Printer list"},
    {"lpstat -s", "lpstat -s", "Default printer"},
    {"lpstat -a", "lpstat -a", "Accepting jobs"},
    {"lpstat -o", "lpstat -o", "Output jobs"},
    {"lpstat -t", "lpstat -t", "All status"},
    {"lpstat -d", "lpstat -d", "Default printer"},
    {"lpstat -r", "lpstat -r", "CUPS daemon"},
    {"lpstat -c", "lpstat -c", "Classes"},
    {"lpstat -v", "lpstat -v", "Printers"},
    {"lpoptions", "lpoptions", "Printer options"},
    {"lpoptions -d", "lpoptions -d", "Set default"},
    {"lpoptions -l", "lpoptions -l", "List options"},
    {"lpadmin", "lpadmin", "Printer admin"},
    {"lpadmin -p", "lpadmin -p", "Add printer"},
    {"lpadmin -d", "lpadmin -d", "Set default"},
    {"lpadmin -x", "lpadmin -x", "Remove printer"},
    {"lpadmin -c", "lpadmin -c", "Add to class"},
    {"lpadmin -r", "lpadmin -r", "Remove from class"},
    {"lpadmin -v", "lpadmin -v", "Set device"},
    {"lpadmin -m", "lpadmin -m", "Set model"},
    {"lpadmin -o", "lpadmin -o", "Set option"},
    {"lpadmin -u", "lpadmin -u", "Set policy"},
    {"lpmove", "lpmove", "Move job"},
    
    // File Comparison & Search (EXPANDED)
    {"comp", "diff", "Compare files"},
    {"fc", "diff", "File compare"},
    {"fc /b", "cmp -b", "Binary compare"},
    {"fc /l", "diff", "ASCII compare"},
    {"fc /lb", "diff --speed-large-files", "Large binary"},
    {"fc /n", "diff -n", "Line numbers"},
    {"fc /t", "diff -t", "Don't expand tabs"},
    {"fc /u", "diff -u", "Unicode compare"},
    {"fc /w", "diff -w", "Ignore whitespace"},
    {"find", "find", "Find files"},
    {"find /v", "grep -v", "Find non-matching"},
    {"find /c", "grep -c", "Count matches"},
    {"find /n", "grep -n", "Line numbers"},
    {"find /i", "grep -i", "Case insensitive"},
    {"where", "which -a", "Find command"},
    {"where /r", "find / -name", "Recursive find"},
    {"where /t", "which -a", "Show paths"},
    {"which", "which", "Find command"},
    {"tree", "tree", "Show directory tree"},
    {"tree /f", "tree", "Show files"},
    {"tree /a", "tree", "ASCII characters"},
    {"tree /d", "tree -d", "Directories only"},
    {"robocopy", "rsync -av", "Robust copy"},
    {"robocopy /s", "rsync -av", "Subdirectories"},
    {"robocopy /e", "rsync -av", "Empty subdirs"},
    {"robocopy /mir", "rsync -av --delete", "Mirror"},
    {"robocopy /mov", "rsync -av --remove-source-files", "Move files"},
    {"robocopy /move", "rsync -av --remove-source-files", "Move dirs"},
    {"robocopy /z", "rsync -av --partial", "Restartable mode"},
    {"robocopy /b", "rsync -av", "Backup mode"},
    {"robocopy /zb", "rsync -av --partial", "Restartable backup"},
    {"robocopy /copyall", "rsync -av --perms --times --owner --group", "Copy all info"},
    {"robocopy /copy:datso", "rsync -av --perms --times --owner --group", "Copy flags"},
    {"robocopy /dcopy:dat", "rsync -av --perms --times", "Copy dir flags"},
    {"robocopy /sec", "rsync -av --perms", "Copy security"},
    {"robocopy /secfix", "rsync -av --perms", "Fix security"},
    {"robocopy /timfix", "rsync -av --times", "Fix times"},
    {"robocopy /create", "rsync -av --dry-run", "Create only"},
    {"xcopy", "cp -r", "Extended copy"},
    {"xcopy /s", "cp -r", "Subdirectories"},
    {"xcopy /e", "cp -r", "Empty subdirs"},
    {"xcopy /i", "mkdir -p", "Assume directory"},
    {"xcopy /y", "cp -f", "Suppress prompt"},
    {"xcopy /-y", "cp -i", "Prompt confirm"},
    {"xcopy /d", "cp -u", "Copy newer only"},
    {"xcopy /c", "cp --ignore-errors", "Continue on error"},
    {"xcopy /f", "cp -v", "Display full source/dest"},
    {"xcopy /l", "cp -n", "List only"},
    {"xcopy /g", "cp --preserve", "Copy encrypted"},
    {"xcopy /h", "cp -a", "Copy hidden/system"},
    {"xcopy /k", "cp --preserve", "Copy attributes"},
    {"xcopy /r", "cp -r", "Overwrite read-only"},
    {"xcopy /u", "cp -u", "Copy newer only"},
    {"xcopy /v", "cp --verify", "Verify after copy"},
    {"xcopy /w", "cp --interactive", "Wait for key before copy"},
    {"xcopy /x", "cp --preserve", "Copy audit settings"},
    {"xcopy /exclude", "cp --exclude", "Exclude files"},
    {"xcopy /archive", "cp -a", "Archive attribute"},
    {"xcopy /compress", "cp --sparse", "Compress files"},
    {"xcopy /hardlink", "cp -l", "Hard link"},
    {"xcopy /junction", "ln -s", "Junction"},
    {"xcopy /link", "ln -s", "Symbolic link"},
    {"xcopy /move", "mv", "Move files"},
    {"xcopy /p", "cp -i", "Prompt before copy"},
    {"xcopy /q", "cp -q", "Quiet mode"},
    {"xcopy /t", "cp --preserve", "Preserve timestamps"},
    {"xcopy /u", "rsync -u", "Update files"},
    {"xcopy /v", "cp --verify", "Verify files"},
    {"xcopy /w", "cp --interactive", "Wait for confirmation"},
    {"xcopy /x", "cp --preserve", "Preserve audit settings"},
    
    // Archiving & Compression (EXPANDED)
    {"compact", "gzip", "Compress files"},
    {"compact /c", "gzip", "Compress"},
    {"compact /u", "gunzip", "Uncompress"},
    {"compact /s", "gzip -r", "Compress subdirs"},
    {"compact /a", "gzip --best", "High compression"},
    {"compact /i", "gzip --force", "Force compression"},
    {"compact /f", "gzip --force", "Force compression"},
    {"compact /q", "gzip -q", "Quiet"},
    {"makecab", "tar czf", "Make cabinet"},
    {"makecab /d", "tar --options", "Set options"},
    {"makecab /f", "tar -T", "Use file list"},
    {"makecab /v", "tar -v", "Verbose"},
    {"extrac32", "tar xzf", "Extract cabinet"},
    {"extrac32 /y", "tar -f", "Yes to all"},
    {"extrac32 /a", "tar -a", "Process all cabinets"},
    {"extrac32 /c", "tar -t", "Copy to stdout"},
    {"extrac32 /d", "tar -d", "Display directory"},
    {"extrac32 /e", "tar -x", "Extract"},
    {"extrac32 /l", "tar -l", "Location"},
    {"tar", "tar", "Tape archive"},
    {"tar -xvf", "tar xvf", "Extract verbose"},
    {"tar -cvf", "tar cvf", "Create verbose"},
    {"tar -tvf", "tar tvf", "List verbose"},
    {"tar -zxvf", "tar zxvf", "Gzip extract"},
    {"tar -zcvf", "tar zcvf", "Gzip create"},
    {"tar -jxvf", "tar jxvf", "Bzip2 extract"},
    {"tar -jcvf", "tar jcvf", "Bzip2 create"},
    {"zip", "zip", "Create zip"},
    {"zip -r", "zip -r", "Recursive zip"},
    {"zip -e", "zip -e", "Encrypt zip"},
    {"zip -9", "zip -9", "Best compression"},
    {"unzip", "unzip", "Extract zip"},
    {"unzip -l", "unzip -l", "List zip"},
    {"unzip -t", "unzip -t", "Test zip"},
    {"unzip -o", "unzip -o", "Overwrite"},
    {"unzip -q", "unzip -q", "Quiet"},
    {"unzip -v", "unzip -v", "Verbose"},
    
    // Batch & Scripting (EXPANDED)
    {"call", "source", "Call script"},
    {"call /b", "source &", "Branch to call"},
    {"cmd", "bash", "Command prompt"},
    {"cmd /c", "bash -c", "Run command"},
    {"cmd /k", "bash -c", "Run and keep"},
    {"cmd /s", "bash --posix", "Strip quotes"},
    {"cmd /q", "bash --noprofile", "Quiet"},
    {"cmd /d", "bash --norc", "Disable autoexec"},
    {"cmd /a", "bash --ascii", "ASCII output"},
    {"cmd /u", "bash --utf8", "Unicode output"},
    {"cmd /t", "script", "Timer"},
    {"cmd /e", "set -e", "Enable extensions"},
    {"cmd /f", "set -f", "Disable extensions"},
    {"cmd /v", "set -v", "Delayed expansion"},
    {"cmd /x", "set -x", "Enable extensions"},
    {"doskey", "alias", "Command aliases"},
    {"doskey /reinstall", "unalias -a", "Reinstall aliases"},
    {"doskey /listsize", "alias | wc -l", "List size"},
    {"doskey /macros", "alias", "Show macros"},
    {"doskey /macrofile", "source", "Load macros from file"},
    {"doskey /exename", "alias -p", "Set exename"},
    {"doskey /history", "history", "Command history"},
    {"doskey /insert", "bind", "Insert mode"},
    {"doskey /overstrike", "bind", "Overstrike mode"},
    {"echo", "echo", "Print text"},
    {"echo on", "set -x", "Echo on"},
    {"echo off", "set +x", "Echo off"},
    {"echo /?", "help echo", "Echo help"},
    {"for", "for", "Loop command"},
    {"for %i in", "for i in", "Loop variable"},
    {"for /f", "for", "File parsing loop"},
    {"for /d", "for i in */", "Directory loop"},
    {"for /r", "for", "Recursive loop"},
    {"for /l", "for i in {1..10}", "Numeric loop"},
    {"goto", "goto", "Jump to label"},
    {"goto /?", "help goto", "Goto help"},
    {"if", "if", "Conditional"},
    {"if exist", "if [ -f", "If file exists"},
    {"if not exist", "if [ ! -f", "If file not exists"},
    {"if errorlevel", "if [ $? -eq", "If error level"},
    {"if /i", "if", "Case insensitive"},
    {"if /c", "if", "Cmdextversion"},
    {"if /cmdextversion", "if", "Cmd extension version"},
    {"if /defined", "if [ -n", "If defined"},
    {"pause", "read -p", "Pause script"},
    {"pause /?", "help pause", "Pause help"},
    {"rem", "#", "Comment"},
    {"rem /?", "help rem", "Rem help"},
    {"set", "export", "Set variable"},
    {"set /a", "export $((", "Arithmetic set"},
    {"set /p", "read -p", "Prompt set"},
    {"set /x", "set", "Extended set"},
    {"setlocal", "local", "Local variables"},
    {"endlocal", "endlocal", "End local"},
    {"setx", "export", "Set env variable"},
    {"setx /m", "export", "Set system env"},
    {"setx /s", "ssh export", "Set remote env"},
    {"setx /u", "export", "Set user env"},
    {"shift", "shift", "Shift arguments"},
    {"shift /?", "help shift", "Shift help"},
    {"timeout", "sleep", "Delay execution"},
    {"timeout /t", "sleep", "Timeout seconds"},
    {"timeout /nobreak", "sleep", "No break timeout"},
    {"timeout /?", "help sleep", "Timeout help"},
    {"waitfor", "wait", "Wait for signal"},
    {"waitfor /s", "wait", "Send signal"},
    {"waitfor /u", "wait", "UTF8 signal"},
    {"waitfor /t", "timeout", "Timeout"},
    {"waitfor /?", "help wait", "Wait help"},
    {"choice", "select", "Choose option"},
    {"choice /c", "select", "Choices"},
    {"choice /n", "select", "No prompt"},
    {"choice /cs", "select", "Case sensitive"},
    {"choice /t", "select", "Timeout choose"},
    {"choice /d", "select", "Default choice"},
    {"choice /m", "select", "Message"},
    {"goto", "goto", "Goto label"},
    {"call", "source", "Call script"},
    {"exit", "exit", "Exit shell"},
    {"exit /b", "exit", "Exit batch"},
    {"exit /?", "help exit", "Exit help"},
    
    // System File Checker (EXPANDED)
    {"sfc", "debsums", "System file checker"},
    {"sfc /scannow", "debsums -c", "Scan now"},
    {"sfc /verifyfile", "debsums", "Verify file"},
    {"sfc /scanfile", "debsums -s", "Scan file"},
    {"sfc /offbootdir", "debsums --root", "Offline boot dir"},
    {"sfc /offwindir", "debsums --root", "Offline win dir"},
    {"dism", "apt-get install --reinstall", "DISM tool"},
    {"dism /online", "apt-get install", "Online repair"},
    {"dism /image", "dpkg-deb", "Image repair"},
    {"dism /cleanup-image", "apt-get clean", "Cleanup image"},
    {"dism /restorehealth", "apt-get install --reinstall", "Restore health"},
    {"dism /scanhealth", "dpkg --verify", "Scan health"},
    {"dism /checkhealth", "dpkg --audit", "Check health"},
    {"dism /get-drivers", "dpkg -l", "Get drivers"},
    {"dism /add-driver", "dpkg -i", "Add driver"},
    {"dism /remove-driver", "dpkg -r", "Remove driver"},
    {"dism /get-packages", "dpkg -l", "Get packages"},
    {"dism /add-package", "dpkg -i", "Add package"},
    {"dism /remove-package", "dpkg -r", "Remove package"},
    {"dism /get-features", "apt-cache search", "Get features"},
    {"dism /enable-feature", "apt-get install", "Enable feature"},
    {"dism /disable-feature", "apt-get remove", "Disable feature"},
    {"dism /apply-image", "tar -xf", "Apply image"},
    {"dism /capture-image", "tar -cf", "Capture image"},
    {"dism /append-image", "tar -Af", "Append image"},
    {"dism /delete-image", "rm", "Delete image"},
    {"dism /export-image", "tar -cf", "Export image"},
    {"dism /get-wiminfo", "tar -tf", "Get WIM info"},
    {"dism /mount-wim", "mount -o loop", "Mount WIM"},
    {"dism /unmount-wim", "umount", "Unmount WIM"},
    
    // Boot & Recovery (EXPANDED)
    {"bcdedit", "grub-mkconfig", "Boot configuration"},
    {"bcdedit /enum", "grub-mkconfig -o", "Enumerate entries"},
    {"bcdedit /default", "grub-set-default", "Set default"},
    {"bcdedit /timeout", "grub-set-timeout", "Set timeout"},
    {"bcdedit /bootsequence", "grub-reboot", "Boot sequence"},
    {"bcdedit /displayorder", "grub-set-display", "Display order"},
    {"bcdedit /toolsdisplayorder", "grub-set-tools", "Tools order"},
    {"bcdedit /copy", "cp /boot/grub", "Copy entry"},
    {"bcdedit /create", "grub-mkconfig -o", "Create entry"},
    {"bcdedit /delete", "rm /boot/grub", "Delete entry"},
    {"bcdedit /set", "grub-editenv set", "Set parameter"},
    {"bcdedit /deletevalue", "grub-editenv unset", "Delete value"},
    {"bcdedit /export", "tar -cf /boot", "Export config"},
    {"bcdedit /import", "tar -xf /boot", "Import config"},
    {"bcdedit /cleanup", "grub-mkconfig -o", "Cleanup"},
    {"bcdedit /bootems", "grub-set-ems", "Boot EMS"},
    {"bcdedit /ems", "grub-set-ems", "EMS"},
    {"bcdedit /emssettings", "grub-set-ems", "EMS settings"},
    {"bcdedit /bootdebug", "grub-set-debug", "Boot debug"},
    {"bcdedit /dbgsettings", "grub-set-debug", "Debug settings"},
    {"bcdedit /debug", "grub-set-debug", "Debug"},
    {"bcdedit /hypervisorsettings", "grub-set-hypervisor", "Hypervisor"},
    {"bcdedit /set hypervisorlaunchtype", "grub-set-hypervisor", "Hypervisor launch"},
    {"bootcfg", "grub-editenv", "Boot config"},
    {"bootrec", "grub-install", "Boot recovery"},
    {"bootrec /fixmbr", "grub-install --target=i386-pc", "Fix MBR"},
    {"bootrec /fixboot", "grub-install", "Fix boot"},
    {"bootrec /scanos", "os-prober", "Scan OS"},
    {"bootrec /rebuildbcd", "grub-mkconfig -o", "Rebuild BCD"},
    {"diskpart", "parted", "Disk partition"},
    {"diskpart /s", "parted -s", "Scripted partition"},
    {"diskpart /l", "parted -l", "List partitions"},
    {"diskpart /add", "parted mkpart", "Add partition"},
    {"diskpart /delete", "parted rm", "Delete partition"},
    {"diskpart /active", "parted set", "Set active"},
    {"diskpart /extend", "parted resizepart", "Extend partition"},
    {"diskpart /shrink", "parted resizepart", "Shrink partition"},
    {"diskpart /format", "mkfs", "Format partition"},
    {"diskpart /clean", "dd if=/dev/zero", "Clean disk"},
    {"bootsect", "dd if=/boot", "Boot sector"},
    {"bootsect /nt52", "grub-install", "NT 5.2 boot"},
    {"bootsect /nt60", "grub-install", "NT 6.0 boot"},
    {"bootsect /mbr", "grub-install --target=i386-pc", "MBR boot"},
    {"bootsect /force", "grub-install --force", "Force install"},
    
    // Remote Access (EXPANDED)
    {"mstsc", "rdesktop", "Remote desktop"},
    {"mstsc /v", "rdesktop", "Connect to server"},
    {"mstsc /admin", "rdesktop -0", "Admin session"},
    {"mstsc /f", "rdesktop -f", "Full screen"},
    {"mstsc /w", "rdesktop -g", "Width"},
    {"mstsc /h", "rdesktop -g", "Height"},
    {"mstsc /public", "rdesktop -P", "Public mode"},
    {"mstsc /span", "rdesktop -X", "Span monitors"},
    {"mstsc /multimon", "rdesktop -x", "Multimonitor"},
    {"mstsc /edit", "vim ~/.rdesktop", "Edit config"},
    {"mstsc /migrate", "cp ~/.rdesktop", "Migrate config"},
    {"tsdiscon", "loginctl terminate-user", "Disconnect session"},
    {"tsdiscon /v", "loginctl terminate-user", "Verbose disconnect"},
    {"tskill", "pkill", "Terminate session"},
    {"tskill /v", "pkill", "Verbose kill"},
    {"qwinsta", "loginctl list-sessions", "Query sessions"},
    {"qwinsta /server", "loginctl -H", "Query remote"},
    {"qwinsta /mode", "loginctl -p", "Query mode"},
    {"qwinsta /flow", "loginctl -o", "Query flow"},
    {"qwinsta /connect", "loginctl -c", "Query connect"},
    {"qwinsta /counter", "loginctl -C", "Query counter"},
    {"rwinsta", "loginctl terminate-session", "Reset session"},
    {"rwinsta /server", "loginctl -H", "Reset remote"},
    {"rwinsta /v", "loginctl terminate-session", "Verbose reset"},
    {"shadow", "ssh", "Shadow session"},
    {"shadow /server", "ssh -J", "Shadow remote"},
    {"shadow /v", "ssh -v", "Verbose shadow"},
    
    // Share & Permissions (EXPANDED)
    {"net share", "exportfs", "Share resources"},
    {"net share /users", "exportfs -o users", "Share with users"},
    {"net share /unlimited", "exportfs -o unlimited", "Unlimited users"},
    {"net share /remark", "exportfs -o comment", "Add remark"},
    {"net share /cache", "exportfs -o cache", "Cache settings"},
    {"net share /grant", "exportfs -o rw", "Grant permissions"},
    {"net use", "mount -t cifs", "Use network share"},
    {"net use /d", "umount", "Delete share"},
    {"net use /p", "mount -a", "Persistent connection"},
    {"net use /savecred", "mount -o credentials", "Save credentials"},
    {"net use /smartcard", "mount -o sec", "Smartcard auth"},
    {"net use /user", "mount -o user", "Specify user"},
    {"net use /uid", "mount -o uid", "Specify UID"},
    {"net use /gid", "mount -o gid", "Specify GID"},
    {"net use /umask", "mount -o umask", "Specify umask"},
    {"net use /sec", "mount -o sec", "Security mode"},
    {"net use /savecreds", "mount -o credentials", "Save credentials"},
    {"net view", "smbtree", "View shares"},
    {"net view /domain", "smbtree -D", "View domain"},
    {"net view /network", "smbtree -N", "View network"},
    {"net view /all", "smbtree -a", "View all"},
    {"net session", "smbstatus", "View sessions"},
    {"net session /d", "smbcontrol close-share", "Delete session"},
    {"net file", "lsof /shared", "Open files"},
    {"net file /c", "fuser -k", "Close file"},
    {"net statistics", "smbstatus", "Share stats"},
    {"net statistics workstation", "smbstatus", "Workstation stats"},
    {"net statistics server", "smbstatus", "Server stats"},
    {"icacls", "setfacl", "Change ACLs"},
    {"icacls /grant", "setfacl -m u", "Grant ACL"},
    {"icacls /deny", "setfacl -m u", "Deny ACL"},
    {"icacls /remove", "setfacl -x", "Remove ACL"},
    {"icacls /remove:a", "setfacl -x", "Remove all"},
    {"icacls /inheritance", "setfacl -n", "Inheritance"},
    {"icacls /reset", "setfacl -b", "Reset ACLs"},
    {"icacls /replace", "setfacl -m", "Replace ACLs"},
    {"icacls /substitute", "setfacl -m", "Substitute ACLs"},
    {"cacls", "chmod", "Change ACLs"},
    {"cacls /e", "chmod", "Edit ACLs"},
    {"cacls /t", "chmod -R", "Tree"},
    {"cacls /c", "chmod --continue", "Continue on error"},
    {"cacls /g", "chmod", "Grant"},
    {"cacls /r", "chmod", "Revoke"},
    {"cacls /p", "chmod", "Replace"},
    {"cacls /d", "chmod", "Deny"},
    
    // Firewall & Security (EXPANDED)
    {"netsh advfirewall", "iptables", "Firewall config"},
    {"netsh advfirewall show", "iptables -L", "Show firewall"},
    {"netsh advfirewall set", "iptables", "Set firewall"},
    {"netsh advfirewall add", "iptables -A", "Add rule"},
    {"netsh advfirewall delete", "iptables -D", "Delete rule"},
    {"netsh advfirewall export", "iptables-save", "Export rules"},
    {"netsh advfirewall import", "iptables-restore", "Import rules"},
    {"netsh advfirewall reset", "iptables -F", "Reset firewall"},
    {"netsh", "ipset", "Network shell"},
    {"netsh interface", "ip link", "Network interface"},
    {"netsh interface show", "ip link show", "Show interfaces"},
    {"netsh interface set", "ip link set", "Set interface"},
    {"netsh interface add", "ip link add", "Add interface"},
    {"netsh interface delete", "ip link del", "Delete interface"},
    {"netsh dnsclient", "resolvectl", "DNS client"},
    {"netsh wins", "nmblookup", "WINS"},
    {"netsh winhttp", "curl", "WinHTTP"},
    {"netsh firewall", "iptables", "Firewall"},
    {"netsh firewall show", "iptables -L", "Show firewall"},
    {"netsh firewall set", "iptables", "Set firewall"},
    {"netsh firewall add", "iptables -A", "Add rule"},
    {"netsh firewall delete", "iptables -D", "Delete rule"},
    {"auditpol", "auditctl", "Audit policy"},
    {"auditpol /get", "auditctl -l", "Get policy"},
    {"auditpol /set", "auditctl", "Set policy"},
    {"auditpol /list", "auditctl -s", "List policy"},
    {"auditpol /backup", "auditctl -w", "Backup policy"},
    {"auditpol /restore", "auditctl -R", "Restore policy"},
    {"auditpol /clear", "auditctl -D", "Clear policy"},
    {"auditpol /remove", "auditctl -d", "Remove policy"},
    {"gpresult", "getfacl", "Group policy result"},
    {"gpresult /r", "getfacl", "RSoP"},
    {"gpresult /h", "getfacl", "HTML report"},
    {"gpresult /x", "getfacl", "XML report"},
    {"gpresult /scope", "getfacl", "Scope"},
    {"gpresult /user", "getfacl -u", "User policy"},
    {"gpresult /computer", "getfacl -c", "Computer policy"},
    
    // Miscellaneous (EXPANDED)
    {"color", "echo -e", "Change colors"},
    {"color /?", "help echo", "Color help"},
    {"date", "date", "Show date"},
    {"date /t", "date +%D", "Date only"},
    {"date /d", "date -d", "Set date"},
    {"time", "date +%T", "Show time"},
    {"time /t", "date +%T", "Time only"},
    {"time /s", "date -s", "Set time"},
    {"title", "echo -ne \"]0;\"", "Set title"},
    {"title /?", "help echo", "Title help"},
    {"prompt", "PS1=", "Change prompt"},
    {"prompt $p$g", "PS1='\\w>'", "Prompt format"},
    {"prompt /?", "help PS1", "Prompt help"},
    {"verifier", "verify", "Driver verifier"},
    {"verifier /standard", "verify standard", "Standard verifier"},
    {"verifier /all", "verify all", "All drivers"},
    {"verifier /reset", "verify reset", "Reset verifier"},
    {"verifier /query", "verify query", "Query verifier"},
    {"verifier /volatile", "verify volatile", "Volatile settings"},
    {"verifier /log", "verify log", "Log verifier"},
    {"vol", "df -h", "Volume info"},
    {"vol /?", "help df", "Volume help"},
    {"label", "e2label", "Volume label"},
    {"label /?", "help e2label", "Label help"},
    {"subst", "mount --bind", "Substitute path"},
    {"subst /d", "umount", "Delete substitution"},
    {"assoc", "file", "File associations"},
    {"ftype", "xdg-mime", "File types"},
    {"mklink", "ln -s", "Make link"},
    {"mklink /d", "ln -s", "Directory link"},
    {"mklink /h", "ln", "Hard link"},
    {"mklink /j", "mount --bind", "Junction"},
    {"mode", "stty", "Set device mode"},
    {"mode con", "stty", "Console mode"},
    {"mode lpt", "stty", "Printer mode"},
    {"mode com", "stty", "COM port mode"},
    {"mode /?", "help stty", "Mode help"},
    {"print", "lp", "Print file"},
    {"print /d", "lp -d", "Print to device"},
    {"recover", "ddrescue", "Recover files"},
    {"recover /?", "help ddrescue", "Recover help"},
    {"replace", "mv -f", "Replace files"},
    {"replace /a", "cp -n", "Add files"},
    {"replace /p", "mv -i", "Prompt replace"},
    {"replace /r", "mv -f", "Replace read-only"},
    {"replace /w", "mv -w", "Wait replace"},
    {"replace /s", "mv -r", "Replace subdirs"},
    {"replace /u", "mv -u", "Replace newer"},
    {"diskcopy", "dd", "Copy disk"},
    {"diskcopy /v", "dd conv=fdatasync", "Verify copy"},
    {"diskcomp", "cmp", "Compare disks"},
    {"diskcomp /v", "cmp -v", "Verbose compare"},
    {"fciv", "sha256sum", "File checksum"},
    {"fciv -md5", "md5sum", "MD5 checksum"},
    {"fciv -sha1", "sha1sum", "SHA1 checksum"},
    {"fciv -sha256", "sha256sum", "SHA256 checksum"},
    {"fciv -sha384", "sha384sum", "SHA384 checksum"},
    {"fciv -sha512", "sha512sum", "SHA512 checksum"},
    {"fciv -list", "cat checksums", "List checksums"},
    {"fciv -v", "sha256sum -c", "Verify checksums"},
    {"fciv -bp", "sha256sum -b", "Base path"},
    {"fciv -xml", "sha256sum -x", "XML output"},
    {"sigverif", "rpm -V", "Verify signatures"},
    {"sigverif /a", "rpm -Va", "All signatures"},
    {"sigverif /v", "rpm -Vv", "Verbose verify"},
    {"sigverif /q", "rpm -Vq", "Quiet verify"},
    {"sigverif /r", "rpm -Vr", "Recurse verify"},
    {"sigverif /p", "rpm -Vp", "Package verify"},
    {"sysdm.cpl", "systemctl", "System properties"},
    {"intl.cpl", "localectl", "Regional settings"},
    {"timedate.cpl", "timedatectl", "Date/time settings"},
    {"ncpa.cpl", "nmtui", "Network settings"},
    {"desk.cpl", "xrandr", "Display settings"},
    {"main.cpl", "systemctl", "Main control panel"},
    {"mmsys.cpl", "alsamixer", "Multimedia"},
    {"joy.cpl", "jstest", "Joystick"},
    {"inetcpl.cpl", "networkctl", "Internet properties"},
    {"firewall.cpl", "iptables", "Firewall"},
    {"odbccp32.cpl", "odbcinst", "ODBC"},
    {"powercfg.cpl", "powertop", "Power settings"},
    {"telephon.cpl", "modem-manager", "Telephony"},
    
    // DOSKEY macros & common usage (EXPANDED)
    {"dir /s", "find . -type f", "Recursive dir"},
    {"dir /a", "ls -la", "All files"},
    {"dir /b", "ls -1", "Bare format"},
    {"dir /od", "ls -lt", "Sort by date"},
    {"dir /os", "ls -lS", "Sort by size"},
    {"dir /o-n", "ls -lr", "Reverse sort"},
    {"dir /q", "ls -o", "Owner info"},
    {"dir /r", "ls -lR", "Read-only files"},
    {"dir /t:c", "ls -lc", "Creation time"},
    {"dir /t:w", "ls -l", "Write time"},
    {"dir /t:a", "ls -lu", "Access time"},
    {"dir /x", "ls -l", "Short names"},
    {"dir /4", "ls -lh", "Four-digit years"},
    {"dir /c", "ls", "Compressed"},
    {"dir /d", "ls -C", "Column format"},
    {"dir /l", "ls", "Lowercase"},
    {"dir /n", "ls", "Long format"},
    {"dir /p", "ls --pager", "Pause"},
    {"dir /w", "ls -x", "Wide format"},
    {"dir /-c", "ls --nocolor", "No color"},
    {"dir /-n", "ls -i", "No long names"},
    {"dir /-w", "ls", "No wide"},
    {"dir /-p", "ls", "No pause"},
    {"mem", "free -h", "Memory usage"},
    {"mem /c", "free -h", "Condense prog list"},
    {"mem /d", "free -h", "Device status"},
    {"mem /f", "free -h", "Free memory"},
    {"mem /m", "free -h", "Module usage"},
    {"mem /p", "free -h", "Pause after each"},
    {"mem /s", "free -h", "Summary only"},
    {"doskey", "alias", "Command aliases"},
    {"doskey /reinstall", "unalias -a", "Reinstall aliases"},
    {"doskey /listsize", "alias | wc -l", "List size"},
    {"doskey /macros", "alias", "Show macros"},
    {"doskey /macros:all", "alias", "All macros"},
    {"doskey /macros:exename", "alias -p", "Macros for exe"},
    {"doskey /history", "history", "Command history"},
    {"doskey /insert", "bind", "Insert mode"},
    {"doskey /overstrike", "bind", "Overstrike mode"},
    {"doskey /exename", "alias -p", "Set exename"},
    {"doskey /macrofile", "source", "Load macros"},
    {"doskey /bufsize", "HISTSIZE", "Buffer size"},
    {"doskey /reboot", "reboot", "Reboot"},
    {"help", "man", "Show help"},
    {"help /?", "man", "Help help"},
    {"edit", "nano", "Text editor"},
    {"edit /b", "nano -b", "Binary mode"},
    {"edit /h", "nano -h", "Help"},
    {"edit /r", "nano -r", "Read-only"},
    {"edit /s", "nano -s", "Search"},
    {"edit /?", "nano --help", "Edit help"},
    {"notepad", "gedit || nano || vim", "Notepad"},
    {"notepad /p", "lpr", "Print"},
    {"notepad /pt", "lpr", "Print to term"},
    {"calc", "bc", "Calculator"},
    {"clip", "xclip || xsel", "Clipboard"},
    {"clip /?", "help xclip", "Clip help"},
    {"mode", "stty", "Set device mode"},
    {"mode con cols", "stty cols", "Set columns"},
    {"mode con lines", "stty rows", "Set lines"},
    {"mode con rate", "stty speed", "Set rate"},
    {"mode con delay", "stty", "Set delay"},
    {"mode lpt", "stty", "Printer mode"},
    {"mode com", "stty", "COM mode"},
    {"mode /status", "stty -a", "Status"},
    {"mode /?", "help stty", "Mode help"},
    {"break", "stty intr ^C", "Break signal"},
    {"verify", "set -e", "Verify commands"},
    {"verify on", "set -e", "Verify on"},
    {"verify off", "set +e", "Verify off"},
    {"prompt $p$g", "PS1='\\w>'", "Prompt format"},
    {"prompt /?", "help PS1", "Prompt help"},
    {"path", "echo $PATH", "Show path"},
    {"set path", "export PATH=", "Set path"},
    {"date /t", "date +%D", "Date only"},
    {"date /d", "date -d", "Set date"},
    {"time /t", "date +%T", "Time only"},
    {"time /s", "date -s", "Set time"},
    {"ver", "uname -r", "Version only"},
    {"vol", "df -h", "Volume info"},
    
    // PowerShell equivalents (EXPANDED)
    {"Get-ChildItem", "ls", "List items"},
    {"Get-Content", "cat", "Get content"},
    {"Set-Content", "echo >", "Set content"},
    {"Copy-Item", "cp", "Copy item"},
    {"Move-Item", "mv", "Move item"},
    {"Remove-Item", "rm", "Remove item"},
    {"Get-Process", "ps aux", "Get processes"},
    {"Stop-Process", "kill", "Stop process"},
    {"Get-Service", "systemctl status", "Get services"},
    {"Start-Service", "systemctl start", "Start service"},
    {"Stop-Service", "systemctl stop", "Stop service"},
    {"Restart-Service", "systemctl restart", "Restart service"},
    {"Get-Command", "which -a", "Get command"},
    {"Get-Help", "man", "Get help"},
    {"Clear-Host", "clear", "Clear screen"},
    {"Get-Date", "date", "Get date"},
    {"Set-Date", "date -s", "Set date"},
    {"Get-Item", "ls -d", "Get item"},
    {"Get-ItemProperty", "ls -l", "Get item property"},
    {"Set-ItemProperty", "chmod", "Set item property"},
    {"New-Item", "touch", "New item"},
    {"New-Item -ItemType Directory", "mkdir", "New directory"},
    {"New-Item -ItemType File", "touch", "New file"},
    {"New-Item -ItemType SymbolicLink", "ln -s", "New symlink"},
    {"New-Item -ItemType HardLink", "ln", "New hardlink"},
    {"Test-Path", "test -e", "Test path"},
    {"Join-Path", "realpath", "Join path"},
    {"Resolve-Path", "realpath", "Resolve path"},
    {"Split-Path", "dirname", "Split path"},
    {"Convert-Path", "readlink -f", "Convert path"},
    {"Get-Location", "pwd", "Get location"},
    {"Set-Location", "cd", "Set location"},
    {"Push-Location", "pushd", "Push location"},
    {"Pop-Location", "popd", "Pop location"},
    {"Get-Content -Path", "cat", "Get content"},
    {"Set-Content -Path", "echo >", "Set content"},
    {"Add-Content -Path", "echo >>", "Add content"},
    {"Clear-Content -Path", "truncate", "Clear content"},
    {"Get-Content -Tail", "tail", "Get tail"},
    {"Get-Content -Wait", "tail -f", "Wait for content"},
    {"Get-ChildItem -Path", "ls", "Get child items"},
    {"Get-ChildItem -Filter", "ls | grep", "Filter items"},
    {"Get-ChildItem -Include", "ls", "Include pattern"},
    {"Get-ChildItem -Exclude", "ls --ignore", "Exclude pattern"},
    {"Get-ChildItem -Recurse", "ls -R", "Recurse"},
    {"Get-ChildItem -Depth", "ls -R", "Depth"},
    {"Get-ChildItem -Name", "ls -1", "Names only"},
    {"Get-ChildItem -Force", "ls -a", "Show hidden"},
    {"Get-ChildItem -Attributes", "ls -l", "Show attributes"},
    {"Get-Item -Force", "ls -la", "Force get item"},
    {"Get-Item -Stream", "lsattr", "Get streams"},
    {"Set-Item -Stream", "chattr", "Set streams"},
    {"Clear-Item -Stream", "chattr -r", "Clear streams"},
    {"Remove-Item -Stream", "chattr -d", "Remove streams"},
    {"Get-Acl", "getfacl", "Get ACL"},
    {"Set-Acl", "setfacl", "Set ACL"},
    {"Remove-Acl", "setfacl -x", "Remove ACL"},
    {"Get-AuditRule", "auditctl -l", "Get audit rule"},
    {"Set-AuditRule", "auditctl", "Set audit rule"},
    {"Remove-AuditRule", "auditctl -d", "Remove audit rule"},
    {"Get-AuthenticodeSignature", "gpg --verify", "Get signature"},
    {"Set-AuthenticodeSignature", "gpg --sign", "Set signature"},
    {"Get-ChildItem -Recurse -File", "find -type f", "Find all files"},
    {"Get-ChildItem -Recurse -Directory", "find -type d", "Find all directories"},
    {"Get-ChildItem -Hidden", "ls -d .", "Hidden files"},
    {"Get-ChildItem -System", "ls -l", "System files"},
    {"Get-ChildItem -Archive", "ls -l", "Archive files"},
    {"Get-ChildItem -ReadOnly", "ls -l", "Read-only files"},
    {"Get-ChildItem -Compressed", "lsattr", "Compressed files"},
    {"Get-ChildItem -Encrypted", "lsattr", "Encrypted files"},
    
    {NULL, NULL, NULL}
};

// 500+ common commands for auto-correct
static const char* common_commands[] = {
    "ls", "cd", "pwd", "echo", "cat", "grep", "find", "chmod", "chown", "rm", "cp", "mv",
    "mkdir", "rmdir", "touch", "man", "apt", "yum", "dnf", "pacman", "git", "vim", "nano",
    "make", "gcc", "g++", "python", "python3", "bash", "exit", "clear", "history", "ps",
    "top", "kill", "sudo", "whoami", "uname", "df", "du", "tar", "zip", "unzip", "wget",
    "curl", "ssh", "scp", "ping", "ifconfig", "systemctl", "journalctl", "sed", "awk",
    "cut", "sort", "uniq", "head", "tail", "less", "more", "which", "whereis", "locate",
    "updatedb", "free", "uptime", "who", "w", "last", "users", "groups", "id", "passwd",
    "su", "chroot", "mount", "umount", "fdisk", "mkfs", "fsck", "blkid", "lsblk", "lsof",
    "netstat", "ss", "iptables", "ufw", "route", "traceroute", "dig", "nslookup", "host",
    "rsync", "diff", "cmp", "comm", "patch", "ftp", "sftp", "lpr", "lpq", "lprm", "cupsctl",
    "lp", "cancel", "lpstat", "lpoptions", "lpadmin", "cupsdisable", "cupsenable", "alias",
    "unalias", "source", "export", "set", "unset", "env", "printenv", "eval", "exec", "trap",
    "wait", "jobs", "fg", "bg", "disown", "nohup", "screen", "tmux", "script", "tty", "stty",
    "tput", "reset", "clear", "exit", "logout", "suspend", "sh", "bash", "zsh", "fish", "dash",
    "ksh", "csh", "tcsh", "ion", "elvish", "xonsh", "oil", "es", "rc", "mksh", "yash", "sash",
    "posh", "v7sh", "wish", "expect", "dejagnu", "runtest", "tclsh", "wishx", "tkcon", "rvedit",
    "page", "tkinspect", "spectcl", "tk", "wish8.6", "wish8.5", "wish8.4", "node", "npm", "yarn",
    "pnpm", "npx", "node", "ruby", "gem", "bundle", "irb", "python", "pip", "pip3", "pipenv",
    "poetry", "conda", "jupyter", "ipython", "php", "composer", "pear", "go", "cargo", "rustc",
    "git", "svn", "hg", "bzr", "cvs", "fossil", "git-lfs", "git-flow", "tig", "lazygit",
    "docker", "docker-compose", "docker-machine", "kubectl", "helm", "k9s", "lens", "minikube",
    "vagrant", "packer", "terraform", "ansible", "ansible-playbook", "ansible-vault",
    "ansible-galaxy", "ansible-config", "ansible-inventory", "terraform-plan", "terraform-apply",
    "terraform-destroy", "terraform-show", "terraform-init", "terraform-validate", "terraform-fmt",
    "consul", "nomad", "vault", "boundary", "waypoint", "packer", "vagrant", "vagrant-up",
    "vagrant-ssh", "vagrant-halt", "vagrant-destroy", "vagrant-reload", "vagrant-provision",
    "vagrant-status", "vagrant-global-status", "vagrant-box", "vagrant-plugin", "vagrant-cloud",
    "make", "cmake", "autoconf", "automake", "ninja", "meson", "scons", "bazel", "gradle",
    "maven", "ant", "rake", "rakefile", "makefile", "Makefile", "CMakeLists.txt", "configure",
    "build.sh", "install.sh", "setup.py", "package.json", "Cargo.toml", "go.mod", "composer.json",
    "Gemfile", "requirements.txt", "Pipfile", "pyproject.toml", "setup.cfg", "tox.ini",
    "pytest.ini", "karma.conf.js", "webpack.config.js", "rollup.config.js", "vite.config.js",
    "vue.config.js", "next.config.js", "nuxt.config.js", "gatsby-config.js", "jest.config.js",
    "cypress.json", "tsconfig.json", "jsconfig.json", "babel.config.js", "postcss.config.js",
    "tailwind.config.js", "webpack.mix.js", "gulpfile.js", "Gruntfile.js", "protractor.conf.js",
    "nightwatch.conf.js", "wdio.conf.js", "selenium.conf.js", "karma.conf.js", "mocha.opts",
    "jasmine.json", "protractor.conf.js", "cypress.config.js", "playwright.config.js",
    "vite.config.ts", "vitest.config.ts", "jest.config.ts", "tsup.config.ts", "dts.config.js",
    "snowpack.config.js", "parcelrc", "skypack.config.js", "wmr.config.js", "preact.config.js",
    "svelte.config.js", "sapper.config.js", "sapper.config.js", "rollup.config.ts",
    "ng-packagr.json", "angular.json", "ionic.config.json", "stencil.config.ts",
    "ember-cli-build.js", "broccoli.js", "fastify-cli", "express-generator", "koa-generator",
    "nestjs-cli", "typeorm", "prisma", "drizzle-kit", "knex", "sequelize-cli", "mikro-orm",
    "waterline", "bookshelf", "objection", "mongoose", "mongo", "mongosh", "mongod", "mongos",
    "redis-cli", "redis-server", "redis-sentinel", "redis-benchmark", "redis-check-aof",
    "redis-check-rdb", "postgres", "psql", "pg_dump", "pg_restore", "pg_basebackup",
    "pg_controldata", "pg_ctl", "pg_isready", "mysql", "mysqld", "mysqldump", "mysqladmin",
    "mysqlimport", "mysqlshow", "mysqlcheck", "Percona", "mariadb", "sqlite3", "sqlcipher",
    "sqlite", "sqlmap", "sqlplus", "sqlcmd", "bcp", "sqlfluff", "sqitch", "liquibase",
    "flyway", "dbmate", "pg_migrate", "alembic", "flask-migrate", "django-migrate",
    "rails-generate", "rails-migrate", "rails-db", "schema.rb", "structure.sql", "seeds.rb",
    "docker", "dockerd", "docker-init", "docker-proxy", "docker-containerd", "docker-runc",
    "docker-compose", "docker-machine", "docker-buildx", "docker-scan", "docker-hub",
    "docker-registry", "docker-context", "docker-swarm", "docker-stack", "docker-bundle",
    "docker-app", "docker-template", "docker-init", "docker-slim", "dive", "buildah",
    "podman", "skopeo", "umoci", "crun", "runc", "youki", "containerd", "ctr", "nerdctl",
    "k3s", "k3d", "microk8s", "minikube", "kind", "kubeadm", "kubelet", "kube-proxy",
    "kube-apiserver", "kube-controller-manager", "kube-scheduler", "etcd", "flannel",
    "calico", "cilium", "weave", "antrea", "multus", "istio", "linkerd", "consul", "vault",
    "nomad", "boundary", "waypoint", "packer", "vagrant", "terraform", "pulumi", "cdk",
    "ansible", "salt", "puppet", "chef", "inspec", "serverspec", "goss", "testinfra",
    "molecule", "kitchen", "tox", "pytest", "unittest", "nose", "behave", "lettuce",
    "cucumber", "rspec", "serverspec", "capybara", "selenium", "cypress", "puppeteer",
    "playwright", "webdriver", "soapui", "postman", "k6", "locust", "jmeter", "gatling",
    "wrk", "ab", "siege", "httperf", "vegeta", "fortio", "ghz", "eva", "stress", "stress-ng",
    "fio", "iozone", "bonnie++", "dbench", "tiobench", "filebench", "spew", "memtester",
    "memtest86", "stressapptest", "mprime", "prime95", "linpack", "stream", "lmbench",
    "unixbench", "phoronix-test-suite", "geekbench", "passmark", "fmark", "iofetch",
    "ioping", "latencytop", "perf", "strace", "ltrace", "gdb", "lldb", "valgrind",
    "callgrind", "cachegrind", "massif", "helgrind", "drd", "memcheck", "dhat", "sgcheck",
    "bbv", "strace", "ltrace", "dtrace", "systemtap", "bpftrace", "perf", "ftrace",
    "kprobes", "uprobes", "trace-cmd", "kernelshark", "lttng", "lttng-ust", "babeltrace",
    "lttv", "tracecompass", "xystrace", "ftrace", "sysdig", "sysdig-inspect", "csysdig",
    "inspektor-gadget", "kubectl-gadget", "kubectl-debug", "kubectl-trace", "kubectl-directpv",
    "kubectl-krew", "kubectl-warp", "kubectl-sniff", "kubectl-capture", "kubectl-logs",
    "kubectl-exec", "kubectl-run", "kubectl-attach", "kubectl-port-forward", "kubectl-proxy",
    "kubectl-top", "kubectl-describe", "kubectl-get", "kubectl-apply", "kubectl-delete",
    "kubectl-create", "kubectl-patch", "kubectl-replace", "kubectl-edit", "kubectl-label",
    "kubectl-annotate", "kubectl-scale", "kubectl-autoscale", "kubectl-rollout", "kubectl-set",
    "kubectl-expose", "kubectl-convert", "kubectl-api-resources", "kubectl-api-versions",
    "kubectl-cluster-info", "kubectl-config", "kubectl-cordon", "kubectl-uncordon", "kubectl-drain",
    "kubectl-taint", "kubectl-logs", "kubectl-events", "kubectl-top", "kubectl-diff",
    "kubectl-kustomize", "kubectl-kustomize", "helm", "helm-repo", "helm-search", "helm-install",
    "helm-upgrade", "helm-rollback", "helm-uninstall", "helm-list", "helm-history", "helm-status",
    "helm-show", "helm-template", "helm-lint", "helm-package", "helm-push", "helm-pull",
    "helm-verify", "helm-sign", "helm-repo-add", "helm-repo-update", "helm-repo-remove",
    "helm-repo-index", "helm-repo-list", "helm-repo-info", "helm-search-hub", "helm-search-repo",
    "helm-plugin", "helm-plugin-install", "helm-plugin-uninstall", "helm-plugin-list",
    "helm-plugin-update", "helm-env", "helm-get", "helm-get-values", "helm-get-manifest",
    "helm-get-hooks", "helm-get-notes", "helm-get-all", "helm-test", "helm-test-run",
    "helm-completion", "helm-create", "helm-dependency", "helm-dependency-update",
    "helm-dependency-build", "helm-dependency-list", "helm-dependency-list", "helm-chart",
    "helm-chart-list", "helm-chart-show", "helm-chart-save", "helm-chart-export",
    "helm-chart-pull", "helm-chart-push", "helm-registry", "helm-registry-login",
    "helm-registry-logout", "helm-registry-list", "helm-clean", "helm-version", "helm-diff",
    "helm-diff-upgrade", "helm-diff-release", "helm-diff-revision", "helm-diff-rollback",
    "helm-secrets", "helm-secrets-encrypt", "helm-secrets-decrypt", "helm-secrets-view",
    "helm-secrets-edit", "helm-secrets-clean", "helm-git", "helm-git-init", "helm-git-update",
    "helm-git-status", "helm-git-diff", "helm-git-log", "helm-git-branch", "helm-git-merge",
    "helm-git-rebase", "helm-git-clone", "helm-git-fetch", "helm-git-pull", "helm-git-push",
    "helm-git-checkout", "helm-git-reset", "helm-git-clean", "helm-git-stash", "helm-git-tag",
    "helm-git-remote", "helm-git-config", "helm-git-lfs", "helm-git-submodule", "helm-git-subtree",
    "helm-git-worktree", "helm-git-bisect", "helm-git-blame", "helm-git-show", "helm-git-whatchanged",
    "helm-git-archive", "helm-git-bundle", "helm-git-daemon", "helm-git-http-backend",
    "helm-git-instaweb", "helm-git-send-email", "helm-git-request-pull", "helm-git-cvsexportcommit",
    "helm-git-cvsimport", "helm-git-svn", "helm-git-p4", "helm-git-quiltimport", "helm-git-applymbox",
    "helm-git-am", "helm-git-apply", "helm-git-chERRY-pick", "helm-git-rebase", "helm-git-merge",
    "helm-git-branch", "helm-git-tag", "helm-git-config", "helm-git-remote", "helm-git-ls-remote",
    "helm-git-push", "helm-git-pull", "helm-git-fetch", "helm-git-clone", "helm-git-checkout",
    "helm-git-reset", "helm-git-clean", "helm-git-stash", "helm-git-bisect", "helm-git-blame",
    "helm-git-show", "helm-git-whatchanged", "helm-git-archive", "helm-git-bundle", "helm-git-daemon",
    "helm-git-http-backend", "helm-git-instaweb", "helm-git-send-email", "helm-git-request-pull",
    "helm-git-cvsexportcommit", "helm-git-cvsimport", "helm-git-svn", "helm-git-p4", "helm-git-quiltimport",
    "helm-git-applymbox", "helm-git-am", "helm-git-apply", "helm-git-chERRY-pick", "helm-git-rebase",
    "helm-git-merge"
};


static const KeyMapping persian_to_english[] = {
    {"ض", 'q'}, {"ص", 'w'}, {"ث", 'e'}, {"ق", 'r'}, {"ف", 't'},
    {"غ", 'y'}, {"ع", 'u'}, {"ه", 'i'}, {"خ", 'o'}, {"ح", 'p'},
    {"ج", '['}, {"چ", ']'}, {"ش", 'a'}, {"س", 's'}, {"ی", 'd'},
    {"ب", 'f'}, {"ل", 'g'}, {"ا", 'h'}, {"ت", 'j'}, {"ن", 'k'},
    {"م", 'l'}, {"ک", ';'}, {"گ", '\''}, {"ظ", 'z'}, {"ط", 'x'},
    {"ز", 'c'}, {"ر", 'v'}, {"ذ", 'b'}, {"د", 'n'}, {"پ", 'm'},
    {"و", ','}, {NULL, 0}
};

// Signal handler
static void sigchld_handler(int sig) {
    (void)sig;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// Helper: min of 3
static int min3(int a, int b, int c) {
    int min = a;
    if (b < min) min = b;
    if (c < min) min = c;
    return min;
}

// Terminal raw mode
static void enable_raw_mode(void) {
    if (raw_mode_enabled) return;
    tcgetattr(STDIN_FILENO, &orig_termios);
    struct termios raw = orig_termios;
    raw.c_lflag &= ~(ECHO | ICANON);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    raw_mode_enabled = 1;
}

static void disable_raw_mode(void) {
    if (!raw_mode_enabled) return;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
    raw_mode_enabled = 0;
}

// History management
static void init_history(void) {
    history.commands = malloc(FSH_MAX_HISTORY * sizeof(char*));
    history.capacity = FSH_MAX_HISTORY;
    history.count = 0;
    history.current_index = -1;
    
    char history_path[PATH_MAX];
    snprintf(history_path, sizeof(history_path), "%s/.fsh_history", getenv("HOME") ?: ".");
    FILE* fp = fopen(history_path, "r");
    if (fp) {
        char line[FSH_MAX_INPUT];
        while (fgets(line, sizeof(line), fp) && history.count < FSH_MAX_HISTORY) {
            line[strcspn(line, "\n")] = 0;
            if (strlen(line) > 0) {
                history.commands[history.count++] = strdup(line);
            }
        }
        fclose(fp);
    }
}

static void save_history(void) {
    char history_path[PATH_MAX];
    snprintf(history_path, sizeof(history_path), "%s/.fsh_history", getenv("HOME") ?: ".");
    FILE* fp = fopen(history_path, "w");
    if (fp) {
        int start = (history.count > 500) ? history.count - 500 : 0;
        for (int i = start; i < history.count; i++) {
            fprintf(fp, "%s\n", history.commands[i]);
        }
        fclose(fp);
    }
}

static void add_to_history(const char* command) {
    if (strlen(command) == 0 || strcmp(command, "cd") == 0) return;
    if (history.count > 0 && strcmp(history.commands[history.count - 1], command) == 0) return;
    
    char* cmd_copy = strdup(command);
    if (!cmd_copy) return;
    
    if (history.count < history.capacity) {
        history.commands[history.count++] = cmd_copy;
    } else {
        free(history.commands[0]);
        for (int i = 1; i < history.capacity; i++) {
            history.commands[i - 1] = history.commands[i];
        }
        history.commands[history.capacity - 1] = cmd_copy;
    }
    history.current_index = history.count;
}

static const char* history_up(void) {
    if (history.current_index > 0) {
        history.current_index--;
        return history.commands[history.current_index];
    }
    return NULL;
}

static const char* history_down(void) {
    if (history.current_index < history.count - 1) {
        history.current_index++;
        return history.commands[history.current_index];
    }
    return NULL;
}

static void reset_history_position(void) {
    history.current_index = history.count;
}

// Command database scanning
static void scan_directory(const char* path, SystemCommands* cmd_list) {
    if (!cmd_list->commands) {
        cmd_list->commands = malloc(FSH_MAX_BIN_CMDS * sizeof(char*));
        cmd_list->capacity = FSH_MAX_BIN_CMDS;
        cmd_list->count = 0;
    }
    
    DIR* dir = opendir(path);
    if (!dir) return;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL && cmd_list->count < cmd_list->capacity) {
        if (entry->d_name[0] == '.') continue;
        
        char full_path[PATH_MAX];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) == 0 && (st.st_mode & S_IXUSR)) {
            int exists = 0;
            for (int i = 0; i < cmd_list->count; i++) {
                if (strcmp(cmd_list->commands[i], entry->d_name) == 0) {
                    exists = 1;
                    break;
                }
            }
            if (!exists) {
                cmd_list->commands[cmd_list->count++] = strdup(entry->d_name);
            }
        }
    }
    closedir(dir);
}

// UTF-8 handling
static int is_utf8_start_byte(unsigned char c) {
    return (c >= 0xC0 && c <= 0xFD);
}

static int utf8_char_length(unsigned char c) {
    if ((c & 0x80) == 0) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

static int contains_persian(const char* input) {
    for (int i = 0; input[i]; i++) {
        if (is_utf8_start_byte(input[i])) {
            return 1;
        }
    }
    return 0;
}

static void persian_to_english_layout(char* input) {
    char buffer[FSH_MAX_INPUT];
    strcpy(buffer, input);
    
    int i = 0, out_idx = 0;
    while (buffer[i] && out_idx < FSH_MAX_INPUT - 4) {
        int found = 0;
        
        for (int j = 0; persian_to_english[j].persian; j++) {
            int persian_len = strlen(persian_to_english[j].persian);
            if (strncmp(&buffer[i], persian_to_english[j].persian, persian_len) == 0) {
                input[out_idx++] = persian_to_english[j].english;
                i += persian_len;
                found = 1;
                break;
            }
        }
        
        if (!found) {
            int char_len = utf8_char_length(buffer[i]);
            if (char_len > 1) {
                i += char_len;
                input[out_idx++] = ' ';
            } else {
                input[out_idx++] = buffer[i++];
            }
        }
    }
    input[out_idx] = '\0';
}

static void cleanup_system_commands(void) {
    for (int i = 0; i < bin_cmds.count; i++) free(bin_cmds.commands[i]);
    free(bin_cmds.commands);
    for (int i = 0; i < sbin_cmds.count; i++) free(sbin_cmds.commands[i]);
    free(sbin_cmds.commands);
    for (int i = 0; i < all_cmds.count; i++) free(all_cmds.commands[i]);
    free(all_cmds.commands);
}

static void init_command_database(void) {
    scan_directory("/bin", &bin_cmds);
    scan_directory("/sbin", &sbin_cmds);
    scan_directory("/usr/bin", &bin_cmds);
    scan_directory("/usr/sbin", &sbin_cmds);
    scan_directory("/usr/local/bin", &bin_cmds);
    scan_directory("/usr/local/sbin", &sbin_cmds);
    
    all_cmds.commands = malloc(FSH_MAX_BIN_CMDS * sizeof(char*));
    all_cmds.capacity = FSH_MAX_BIN_CMDS;
    all_cmds.count = 0;
    
    for (int i = 0; i < bin_cmds.count && all_cmds.count < all_cmds.capacity; i++) {
        all_cmds.commands[all_cmds.count++] = strdup(bin_cmds.commands[i]);
    }
    for (int i = 0; i < sbin_cmds.count && all_cmds.count < all_cmds.capacity; i++) {
        int exists = 0;
        for (int j = 0; j < all_cmds.count; j++) {
            if (strcmp(all_cmds.commands[j], sbin_cmds.commands[i]) == 0) {
                exists = 1;
                break;
            }
        }
        if (!exists) {
            all_cmds.commands[all_cmds.count++] = strdup(sbin_cmds.commands[i]);
        }
    }
    
    for (int i = 0; i < all_cmds.count - 1; i++) {
        for (int j = i + 1; j < all_cmds.count; j++) {
            if (strcmp(all_cmds.commands[i], all_cmds.commands[j]) > 0) {
                char* temp = all_cmds.commands[i];
                all_cmds.commands[i] = all_cmds.commands[j];
                all_cmds.commands[j] = temp;
            }
        }
    }
}

// Levenshtein distance
static int levenshtein_distance(const char* s1, const char* s2) {
    int len1 = strlen(s1);
    int len2 = strlen(s2);
    
    if (len1 == 0) return len2;
    if (len2 == 0) return len1;
    
    int* prev_row = calloc(len2 + 1, sizeof(int));
    int* curr_row = calloc(len2 + 1, sizeof(int));
    
    if (!prev_row || !curr_row) {
        free(prev_row); free(curr_row);
        return 999;
    }
    
    for (int j = 0; j <= len2; j++) prev_row[j] = j;
    
    for (int i = 1; i <= len1; i++) {
        curr_row[0] = i;
        for (int j = 1; j <= len2; j++) {
            int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            curr_row[j] = min3(
                prev_row[j] + 1,
                curr_row[j - 1] + 1,
                prev_row[j - 1] + cost
            );
        }
        int* tmp = prev_row;
        prev_row = curr_row;
        curr_row = tmp;
    }
    
    int distance = prev_row[len2];
    free(prev_row); free(curr_row);
    return distance;
}

// Auto-correct
static const char* find_best_suggestion(const char* input) {
    char cmd_copy[FSH_MAX_INPUT];
    strncpy(cmd_copy, input, FSH_MAX_INPUT - 1);
    cmd_copy[FSH_MAX_INPUT - 1] = '\0';
    
    char* first_arg = strtok(cmd_copy, " \t");
    if (!first_arg) return NULL;
    
    int best_distance = 999;
    static char best_match[FSH_MAX_INPUT];
    best_match[0] = '\0';
    
    for (int i = 0; i < all_cmds.count; i++) {
        int distance = levenshtein_distance(first_arg, all_cmds.commands[i]);
        if (distance < best_distance && distance <= 3) {
            best_distance = distance;
            strncpy(best_match, all_cmds.commands[i], sizeof(best_match) - 1);
            best_match[sizeof(best_match) - 1] = '\0';
        }
    }
    
    for (int i = 0; common_commands[i]; i++) {
        int distance = levenshtein_distance(first_arg, common_commands[i]);
        if (distance < best_distance && distance <= 3) {
            best_distance = distance;
            strncpy(best_match, common_commands[i], sizeof(best_match) - 1);
            best_match[sizeof(best_match) - 1] = '\0';
        }
    }
    
    if (best_match[0] && best_distance <= 2 && best_distance < (int)(strlen(first_arg) / 2)) {
        const char* rest = input + strlen(first_arg);
        static char suggestion[FSH_MAX_INPUT];
        snprintf(suggestion, sizeof(suggestion), "%s%s", best_match, rest);
        return suggestion;
    }
    return NULL;
}

// CMD translation
static const char* translate_cmd(const char* input) {
    char cmd_copy[FSH_MAX_INPUT];
    strncpy(cmd_copy, input, FSH_MAX_INPUT - 1);
    cmd_copy[FSH_MAX_INPUT - 1] = '\0';
    
    char* first_arg = strtok(cmd_copy, " \t");
    if (!first_arg) return NULL;
    
    for (int i = 0; cmd_mappings[i].windows_cmd; i++) {
        if (strcasecmp(first_arg, cmd_mappings[i].windows_cmd) == 0) {
            static char translated[FSH_MAX_INPUT];
            const char* rest = input + strlen(first_arg);
            snprintf(translated, sizeof(translated), "%s%s", cmd_mappings[i].linux_cmd, rest);
            stats.commands_translated++;
            stats.windows_cmds_used++;
            return translated;
        }
    }
    return NULL;
}

// Dangerous command detection
static int is_dangerous_command(char** args) {
    if (!args[0]) return 0;
    
    if (strcmp(args[0], "rm") == 0) {
        for (int i = 1; args[i]; i++) {
            if (strcmp(args[i], "-rf") == 0 || strcmp(args[i], "-fr") == 0) {
                if (args[i+1] && strcmp(args[i+1], "/") == 0) return 1;
            }
        }
    }
    
    if (strcmp(args[0], "dd") == 0) {
        for (int i = 1; args[i]; i++) {
            if (strncmp(args[i], "of=/dev/sd", 10) == 0 ||
                strncmp(args[i], "of=/dev/nvme", 12) == 0) {
                return 1;
            }
        }
    }
    
    return 0;
}

static int confirm_dangerous_command(char** args) {
    printf("\n%s╔═══════════════════════════════════════════════════════════════════════════════╗%s\n", COLOR_RED, COLOR_RESET);
    printf("%s║  ⚠️  CRITICAL DANGEROUS COMMAND DETECTED! ⚠️                                 ║%s\n", COLOR_RED, COLOR_RESET);
    printf("%s╚═══════════════════════════════════════════════════════════════════════════════╝%s\n", COLOR_RED, COLOR_RESET);
    printf("%sYou are about to execute:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  ");
    for (int i = 0; args[i]; i++) printf("%s ", args[i]);
    printf("\n\n%sThis can PERMANENTLY DAMAGE your system!%s\n", COLOR_RED, COLOR_RESET);
    printf("Are you absolutely sure? Type 'yes' to continue: ");
    fflush(stdout);
    
    char response[20];
    if (fgets(response, sizeof(response), stdin) != NULL) {
        int confirmed = (strcasecmp(response, "yes\n") == 0 || strcasecmp(response, "y\n") == 0);
        if (!confirmed) {
            stats.dangerous_commands_blocked++;
        }
        return confirmed;
    }
    stats.dangerous_commands_blocked++;
    return 0;
}

// Pipe execution
static void exec_pipe_commands(char*** pipe_args, int pipe_count) {
    int pipefd[2];
    int prev_pipe_read = -1;
    
    for (int i = 0; i < pipe_count; i++) {
        if (i < pipe_count - 1 && pipe(pipefd) == -1) {
            fprintf(stderr, COLOR_RED "Pipe failed: %s\n" COLOR_RESET, strerror(errno));
            return;
        }
        
        pid_t pid = fork();
        if (pid == -1) {
            fprintf(stderr, COLOR_RED "Fork failed: %s\n" COLOR_RESET, strerror(errno));
            return;
        }
        
        if (pid == 0) {
            if (prev_pipe_read != -1) {
                dup2(prev_pipe_read, STDIN_FILENO);
                close(prev_pipe_read);
            }
            
            if (i < pipe_count - 1) {
                close(pipefd[0]);
                dup2(pipefd[1], STDOUT_FILENO);
                close(pipefd[1]);
            }
            
            execvp(pipe_args[i][0], pipe_args[i]);
            fprintf(stderr, COLOR_RED "Command not found: %s\n" COLOR_RESET, pipe_args[i][0]);
            exit(127);
        } else {
            if (prev_pipe_read != -1) close(prev_pipe_read);
            if (i < pipe_count - 1) {
                close(pipefd[1]);
                prev_pipe_read = pipefd[0];
            }
            
            int status;
            waitpid(pid, &status, 0);
            last_exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        }
    }
    
    if (prev_pipe_read != -1) close(prev_pipe_read);
    stats.pipes_executed++;
}

// Keyboard input with UTF-8
static char* read_input_with_history(void) {
    static char buffer[FSH_MAX_INPUT];
    size_t pos = 0;
    int escape_state = 0;
    
    enable_raw_mode();
    
    while (1) {
        int c = getchar();
        
        if (c == EOF) {
            disable_raw_mode();
            return NULL;
        }
        
        if (escape_state == 0 && c == '\033') {
            escape_state = 1;
            continue;
        }
        
        if (escape_state == 1) {
            if (c == '[') {
                escape_state = 2;
                continue;
            } else {
                escape_state = 0;
            }
        }
        
        if (escape_state == 2) {
            switch (c) {
                case 'A': {
                    const char* hist = history_up();
                    if (hist) {
                        printf("\r\033[K%s", hist);
                        fflush(stdout);
                        strncpy(buffer, hist, FSH_MAX_INPUT - 1);
                        pos = strlen(buffer);
                    }
                    escape_state = 0;
                    continue;
                }
                case 'B': {
                    const char* hist = history_down();
                    if (hist) {
                        printf("\r\033[K%s", hist);
                        fflush(stdout);
                        strncpy(buffer, hist, FSH_MAX_INPUT - 1);
                        pos = strlen(buffer);
                    } else {
                        printf("\r\033[K");
                        fflush(stdout);
                        buffer[0] = '\0';
                        pos = 0;
                    }
                    escape_state = 0;
                    continue;
                }
                case 'C':
                case 'D':
                    escape_state = 0;
                    continue;
            }
            escape_state = 0;
        }
        
        if (c == 127 || c == '\b') {
            if (pos > 0) {
                pos--;
                buffer[pos] = '\0';
                printf("\b \b");
                fflush(stdout);
            }
            continue;
        }
        
        if (c == '\n' || c == '\r') {
            printf("\n");
            disable_raw_mode();
            buffer[pos] = '\0';
            return buffer;
        }
        
        if (is_utf8_start_byte(c)) {
            int char_len = utf8_char_length(c);
            if (pos + char_len < FSH_MAX_INPUT - 1) {
                buffer[pos++] = c;
                for (int i = 1; i < char_len; i++) {
                    int next_c = getchar();
                    if (next_c == EOF) break;
                    buffer[pos++] = next_c;
                }
                buffer[pos] = '\0';
                for (int i = 0; i < char_len; i++) {
                    putchar(buffer[pos - char_len + i]);
                }
                fflush(stdout);
            }
        } else if (pos < FSH_MAX_INPUT - 1 && c >= 32 && c < 127) {
            buffer[pos++] = c;
            buffer[pos] = '\0';
            putchar(c);
            fflush(stdout);
        }
    }
    
    disable_raw_mode();
    buffer[pos] = '\0';
    return buffer;
}

// Execute single command
static void execute_single_command(char* cmd_line) {
    char* args[FSH_MAX_ARGS];
    int arg_count = 0;
    
    char* saveptr;
    char* token = strtok_r(cmd_line, " \t\n\r", &saveptr);
    while (token && arg_count < FSH_MAX_ARGS - 1) {
        args[arg_count++] = token;
        token = strtok_r(NULL, " \t\n\r", &saveptr);
    }
    args[arg_count] = NULL;
    
    if (arg_count == 0) return;
    
    const BuiltinCommand* builtin = find_builtin(args[0]);
    if (builtin) {
        last_exit_status = builtin->func(args);
        stats.commands_executed++;
        return;
    }
    
    if (is_dangerous_command(args)) {
        if (!confirm_dangerous_command(args)) {
            printf("%sCommand cancelled.%s\n", COLOR_GREEN, COLOR_RESET);
            last_exit_status = 0;
            return;
        }
    }
    
    pid_t pid = fork();
    if (pid == -1) {
        fprintf(stderr, COLOR_RED "Failed to fork: %s\n" COLOR_RESET, strerror(errno));
        last_exit_status = 1;
        return;
    }
    
    if (pid == 0) {
        execvp(args[0], args);
        fprintf(stderr, COLOR_RED "Command not found: %s\n" COLOR_RESET, args[0]);
        exit(127);
    } else {
        int status;
        waitpid(pid, &status, 0);
        last_exit_status = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        stats.commands_executed++;
    }
}

// Execute piped commands wrapper
static void execute_piped_commands(char* cmd_line) {
    char* pipe_cmds[FSH_MAX_PIPE_CMDS];
    int pipe_count = 0;
    
    char* saveptr;
    char* token = strtok_r(cmd_line, "|", &saveptr);
    while (token && pipe_count < FSH_MAX_PIPE_CMDS) {
        pipe_cmds[pipe_count++] = token;
        token = strtok_r(NULL, "|", &saveptr);
    }
    
    if (pipe_count == 1) {
        execute_single_command(pipe_cmds[0]);
        return;
    }
    
    char*** all_args = malloc(pipe_count * sizeof(char**));
    int* arg_counts = calloc(pipe_count, sizeof(int));
    
    for (int i = 0; i < pipe_count; i++) {
        all_args[i] = malloc(FSH_MAX_ARGS * sizeof(char*));
        char* saveptr2;
        char* token2 = strtok_r(pipe_cmds[i], " \t\n\r", &saveptr2);
        while (token2 && arg_counts[i] < FSH_MAX_ARGS - 1) {
            all_args[i][arg_counts[i]++] = token2;
            token2 = strtok_r(NULL, " \t\n\r", &saveptr2);
        }
        all_args[i][arg_counts[i]] = NULL;
    }
    
    exec_pipe_commands(all_args, pipe_count);
    
    for (int i = 0; i < pipe_count; i++) {
        free(all_args[i]);
    }
    free(all_args);
    free(arg_counts);
}

// Execute command line
static int execute_command_line(char* input) {
    char cmd_copy[FSH_MAX_INPUT];
    strcpy(cmd_copy, input);
    cmd_copy[strcspn(cmd_copy, "\n")] = 0;
    
    char* trimmed = cmd_copy;
    while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
    if (strlen(trimmed) == 0) return 0;
    
    char* and_pos = strstr(trimmed, "&&");
    if (and_pos) {
        *and_pos = '\0';
        char* second_cmd = and_pos + 2;
        execute_piped_commands(trimmed);
        if (last_exit_status == 0) {
            execute_piped_commands(second_cmd);
        }
        return last_exit_status;
    }
    
    char* amp_pos = strrchr(trimmed, '&');
    int background = 0;
    if (amp_pos && amp_pos[1] == '\0') {
        *amp_pos = '\0';
        background = 1;
        trimmed = cmd_copy;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
    }
    
    int persian_detected = contains_persian(trimmed);
    if (persian_detected) {
        printf("%s[Persian keyboard detected - converted]%s\n", COLOR_YELLOW, COLOR_RESET);
        persian_to_english_layout(trimmed);
        stats.persian_converted++;
    }
    
    const char* translated_cmd = translate_cmd(trimmed);
    if (translated_cmd && strcmp(translated_cmd, trimmed) != 0) {
        printf("\n╔══════════════════════════════════════════════════════════════╗\n");
        printf("║  WINDOWS/MS-DOS : %s%-46s%s║\n", COLOR_RED, trimmed, COLOR_RESET);
        printf("║  LINUX/POSIX    : %s%-46s%s║\n", COLOR_GREEN, translated_cmd, COLOR_RESET);
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        printf("  → Command translated and executed !\n\n");
        strncpy(cmd_copy, translated_cmd, FSH_MAX_INPUT - 1);
        trimmed = cmd_copy;
    }
    
    const char* suggestion = find_best_suggestion(trimmed);
    if (suggestion && strcmp(suggestion, trimmed) != 0) {
        printf("%sDid you mean '%s' instead of '%s'?%s (yes/no): ", 
               COLOR_YELLOW, suggestion, trimmed, COLOR_RESET);
        fflush(stdout);
        
        char response[10];
        if (fgets(response, sizeof(response), stdin) != NULL) {
            if (strcasecmp(response, "yes\n") == 0 || strcasecmp(response, "y\n") == 0) {
                strncpy(cmd_copy, suggestion, FSH_MAX_INPUT - 1);
                trimmed = cmd_copy;
                stats.typos_corrected++;
                printf("\n");
            }
        }
    }
    
    if (background) {
        pid_t pid = fork();
        if (pid == 0) {
            setsid();
            execute_piped_commands(trimmed);
            exit(last_exit_status);
        } else if (pid > 0) {
            printf("[%d] %d\n", ++stats.background_jobs, pid);
            last_exit_status = 0;
        } else {
            fprintf(stderr, COLOR_RED "Background fork failed: %s\n" COLOR_RESET, strerror(errno));
            last_exit_status = 1;
        }
    } else {
        execute_piped_commands(trimmed);
    }
    
    return last_exit_status;
}

static void print_help(const char* program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -c COMMAND    Execute COMMAND and exit\n");
    printf("  --help        Show this help message\n");
    printf("  --version     Show version information\n");
    printf("\nExamples:\n");
    printf("  %s                    # Start interactive shell\n", program_name);
    printf("  %s -c \"ls -la\"        # Execute command and exit\n", program_name);
    printf("  %s --help             # Show help\n", program_name);
}

static void print_version(void) {
    printf("Fsh - The Friendly Shell v3.3.3\n");
    printf("Copyright (C) 2026 FarazOS Project\n");
}

// Banner
static void print_banner(void) {
    printf("\n╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                              ║\n");
    printf("║   %sFsh - The Friendly Shell v3.3.3%s                                      ║\n", COLOR_MAGENTA, COLOR_RESET);
    printf("║   %s500+ CMD | Persian UTF-8 | Pipe | &&/& | Enhanced Safety%s           ║\n", COLOR_CYAN, COLOR_RESET);
    printf("║                                                                              ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════════╝\n\n");
}

// Built-in implementations
int builtin_cd(char** args) {
    if (args[1] == NULL) {
        const char* home = getenv("HOME");
        if (home && chdir(home) != 0) {
            perror("cd");
            return 1;
        }
    } else {
        if (chdir(args[1]) != 0) {
            perror("cd");
            return 1;
        }
    }
    return 0;
}

int builtin_pwd(char** args) {
    (void)args;
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("%s\n", cwd);
    } else {
        perror("pwd");
        return 1;
    }
    return 0;
}

int builtin_exit(char** args) {
    (void)args;
    exit(0);
    return 0;
}

int builtin_export(char** args) {
    if (args[1] == NULL) {
        extern char **environ;
        for (char **env = environ; *env; env++) {
            printf("%s\n", *env);
        }
    } else {
        char* var = strdup(args[1]);
        char* eq = strchr(var, '=');
        if (eq) {
            *eq = '\0';
            if (setenv(var, eq + 1, 1) != 0) {
                perror("export");
                free(var);
                return 1;
            }
        }
        free(var);
    }
    return 0;
}

int builtin_history(char** args) {
    (void)args;
    printf("\n══════════════════════════════════════════════════════════════════════════════\n");
    printf("%s                         Command History%s\n", COLOR_MAGENTA, COLOR_RESET);
    printf("══════════════════════════════════════════════════════════════════════════════\n\n");
    for (int i = 0; i < history.count; i++) {
        printf("  %s%4d%s  %s\n", COLOR_BLUE, i + 1, COLOR_RESET, history.commands[i]);
    }
    printf("\n══════════════════════════════════════════════════════════════════════════════\n\n");
    return 0;
}

int builtin_alias(char** args) {
    if (!args[1]) {
        if (alias_count == 0) {
            printf("No aliases defined\n");
        } else {
            for (int i = 0; i < alias_count; i++) {
                printf("%s='%s'\n", aliases[i].name, aliases[i].value);
            }
        }
        return 0;
    }
    
    char* alias_def = strdup(args[1]);
    char* eq = strchr(alias_def, '=');
    if (eq) {
        *eq = '\0';
        char* value = eq + 1;
        if (*value == '\'' || *value == '"') {
            value++;
            value[strlen(value) - 1] = '\0';
        }
        
        for (int i = 0; i < alias_count; i++) {
            if (strcmp(aliases[i].name, alias_def) == 0) {
                free(aliases[i].value);
                aliases[i].value = strdup(value);
                printf("Alias '%s' updated → '%s'\n", alias_def, value);
                free(alias_def);
                return 0;
            }
        }
        
        if (alias_count < FSH_MAX_ALIASES) {
            aliases[alias_count].name = strdup(alias_def);
            aliases[alias_count].value = strdup(value);
            alias_count++;
            printf("Alias '%s' → '%s' added\n", alias_def, value);
        }
    } else {
        for (int i = 0; i < alias_count; i++) {
            if (strcmp(aliases[i].name, alias_def) == 0) {
                printf("%s='%s'\n", aliases[i].name, aliases[i].value);
                free(alias_def);
                return 0;
            }
        }
        printf("Alias '%s' not found\n", alias_def);
    }
    free(alias_def);
    return 0;
}

int builtin_unalias(char** args) {
    if (!args[1]) {
        printf("Usage: unalias name\n");
        return 1;
    }
    
    for (int i = 0; i < alias_count; i++) {
        if (strcmp(aliases[i].name, args[1]) == 0) {
            free(aliases[i].name);
            free(aliases[i].value);
            for (int j = i; j < alias_count - 1; j++) {
                aliases[j] = aliases[j + 1];
            }
            alias_count--;
            printf("Alias '%s' removed\n", args[1]);
            return 0;
        }
    }
    printf("Alias '%s' not found\n", args[1]);
    return 1;
}

int builtin_clear(char** args) {
    (void)args;
    printf("\033[H\033[J");
    return 0;
}

int builtin_stats(char** args) {
    (void)args;
    time_t now = time(NULL);
    double elapsed = difftime(now, stats.start_time);
    int hours = (int)elapsed / 3600;
    int minutes = ((int)elapsed % 3600) / 60;
    int seconds = (int)elapsed % 60;
    
    printf("\n══════════════════════════════════════════════════════════════════════════════\n");
    printf("%s                         Session Statistics%s\n", COLOR_MAGENTA, COLOR_RESET);
    printf("══════════════════════════════════════════════════════════════════════════════\n\n");
    printf("  %sDuration:%s        %02d:%02d:%02d\n", COLOR_WHITE, COLOR_RESET, hours, minutes, seconds);
    printf("  %sCommands:%s        %d executed\n", COLOR_GREEN, COLOR_RESET, stats.commands_executed);
    printf("  %sTranslated:%s      %d CMD→Linux\n", COLOR_CYAN, COLOR_RESET, stats.commands_translated);
    printf("  %sWindows Cmds:%s    %d used\n", COLOR_MAGENTA, COLOR_RESET, stats.windows_cmds_used);
    printf("  %sPersian:%s         %d conversions\n", COLOR_YELLOW, COLOR_RESET, stats.persian_converted);
    printf("  %sTypos Fixed:%s     %d corrections\n", COLOR_RED, COLOR_RESET, stats.typos_corrected);
    printf("  %sPipes:%s           %d executed\n", COLOR_BLUE, COLOR_RESET, stats.pipes_executed);
    printf("  %sBackground:%s      %d jobs\n", COLOR_MAGENTA, COLOR_RESET, stats.background_jobs);
    printf("  %sDanger Blocked:%s  %d commands\n", COLOR_RED, COLOR_RESET, stats.dangerous_commands_blocked);
    printf("  %sHistory:%s         %d commands\n", COLOR_BLUE, COLOR_RESET, history.count);
    printf("  %sAliases:%s         %d defined\n", COLOR_MAGENTA, COLOR_RESET, alias_count);
    printf("  %sSystem Cmds:%s     %d available\n", COLOR_CYAN, COLOR_RESET, all_cmds.count);
    printf("\n══════════════════════════════════════════════════════════════════════════════\n\n");
    return 0;
}

int builtin_echo(char** args) {
    for (int i = 1; args[i]; i++) {
        printf("%s ", args[i]);
    }
    printf("\n");
    return 0;
}

int builtin_set(char** args) {
    (void)args;
    extern char **environ;
    for (char **env = environ; *env; env++) {
        printf("%s\n", *env);
    }
    return 0;
}

int builtin_unset(char** args) {
    if (!args[1]) {
        printf("Usage: unset variable\n");
        return 1;
    }
    unsetenv(args[1]);
    return 0;
}

int builtin_umask(char** args) {
    if (!args[1]) {
        mode_t mask = umask(0);
        umask(mask);
        printf("%04o\n", mask);
    } else {
        mode_t mask = strtol(args[1], NULL, 8);
        umask(mask);
    }
    return 0;
}

int builtin_jobs(char** args) {
    (void)args;
    printf("Background jobs: %d active\n", stats.background_jobs);
    return 0;
}

int builtin_kill(char** args) {
    if (!args[1]) {
        printf("Usage: kill [-signal] pid\n");
        return 1;
    }
    int sig = SIGTERM;
    int pid_idx = 1;
    
    if (args[1][0] == '-') {
        sig = atoi(args[1] + 1);
        pid_idx = 2;
    }
    
    if (!args[pid_idx]) {
        printf("Usage: kill [-signal] pid\n");
        return 1;
    }
    
    pid_t pid = atoi(args[pid_idx]);
    if (kill(pid, sig) != 0) {
        perror("kill");
        return 1;
    }
    return 0;
}

static const BuiltinCommand* find_builtin(const char* cmd) {
    static const BuiltinCommand builtins[] = {
        {"cd", builtin_cd}, {"pwd", builtin_pwd}, {"exit", builtin_exit},
        {"quit", builtin_exit}, {"export", builtin_export}, {"history", builtin_history},
        {"alias", builtin_alias}, {"unalias", builtin_unalias}, {"clear", builtin_clear},
        {"cls", builtin_clear}, {"stats", builtin_stats}, {"echo", builtin_echo},
        {"set", builtin_set}, {"unset", builtin_unset}, {"umask", builtin_umask},
        {"jobs", builtin_jobs}, {"kill", builtin_kill}, {"type", builtin_type},
        {NULL, NULL}
    };
    
    for (int i = 0; builtins[i].name; i++) {
        if (strcmp(cmd, builtins[i].name) == 0) {
            return &builtins[i];
        }
    }
    return NULL;
}

// Main
int main(int argc, char *argv[]) {
    
    
    stats.start_time = time(NULL);
    init_history();
    init_command_database();
    signal(SIGCHLD, sigchld_handler);
    signal(SIGINT, SIG_IGN);
    detect_distro_name();
    int opt;
    int execute_mode = 0;  // 0 = interactive, 1 = -c command, 2 = script file
    char *command_string = NULL;
    
    // Support both -c and long options
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "c:hv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                execute_mode = 1;
                command_string = optarg;
                break;
            case 'h':
                print_help(argv[0]);
                return EXIT_SUCCESS;
            case 'v':
                print_version();
                return EXIT_SUCCESS;
            default:
                fprintf(stderr, COLOR_RED "Unknown option. Use --help for usage.\n" COLOR_RESET);
                return EXIT_FAILURE;
        }
    }
    if (execute_mode == 1 && command_string) {
        init_command_database();
        
        // Execute command and exit immediately
        execute_command_line(command_string);
        
        // Cleanup and exit with command's status
        cleanup_system_commands();
        return last_exit_status;
    }
    scan_directory("/bin", &bin_cmds);
    scan_directory("/sbin", &sbin_cmds);
    scan_directory("/usr/bin", &bin_cmds);
    scan_directory("/usr/sbin", &sbin_cmds);
    scan_directory("/usr/local/bin", &bin_cmds);
    scan_directory("/usr/local/sbin", &sbin_cmds);
    print_banner();
    char input[FSH_MAX_INPUT];
    while (1) {
        char cwd[PATH_MAX];
        const char* user = getenv("USER") ?: "user";
        if (getcwd(cwd, sizeof(cwd)) == NULL) strcpy(cwd, "~");
        
        const char* home = getenv("HOME");
        if (home && strncmp(cwd, home, strlen(home)) == 0) {
            char temp[PATH_MAX];
            snprintf(temp, sizeof(temp), "~%s", cwd + strlen(home));
            strcpy(cwd, temp);
        }
        
        printf("%s[%s@%s %s]$%s ", COLOR_GREEN, user, distro_name, cwd, COLOR_RESET);
        fflush(stdout);
        
        char* input_line = read_input_with_history();
        if (!input_line) {
            printf("\n");
            fflush(stdout);
            continue;
        }
        
        strcpy(input, input_line);
        if (strlen(input) == 0) {
            reset_history_position();
            continue;
        }
        
        char* trimmed = input;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (strcmp(trimmed, "exit") == 0 || strcmp(trimmed, "quit") == 0) {
            break;
        }
        
        execute_command_line(trimmed);
        add_to_history(trimmed);
        if (!strstr(trimmed, "&&")) {
            add_to_history(trimmed);
        }
        reset_history_position();
    }
    
    printf("\n%sGoodbye! Session time: %ld seconds%s\n", 
           COLOR_GREEN, (long)(time(NULL) - stats.start_time), COLOR_RESET);
    save_history();
    
    for (int i = 0; i < history.count; i++) free(history.commands[i]);
    free(history.commands);
    cleanup_system_commands();
    
    return EXIT_SUCCESS;
}

#pragma GCC diagnostic pop
