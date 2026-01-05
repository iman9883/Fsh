/*
 * Fsh - The Friendly Shell v3.3.6
 * Features: 800+ CMD Translations | Persian UTF-8 | Pipe | &&/& | Enhanced Safety
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
#include <stdbool.h>
#include <fnmatch.h>

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
#define FSH_MAX_CASE_PATTERNS 20
#define FSH_MAX_SHOPT_OPTIONS 50

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

typedef struct {
    char* pattern[FSH_MAX_CASE_PATTERNS];
    int pattern_count;
    char* commands;
} CaseStatement;

typedef struct {
    bool allexport;        // -a
    bool notify;           // -b
    bool errexit;          // -e
    bool noglob;           // -f
    bool hashall;          // -h
    bool keyword;          // -k
    bool monitor;          // -m
    bool noexec;           // -n
    bool privileged;       // -p
    bool onecmd;           // -t
    bool nounset;          // -u
    bool verbose;          // -v
    bool xtrace;           // -x
    bool braceexpand;      // -B
    bool noclobber;        // -C
    bool errtrace;         // -E
    bool histexpand;       // -H
    bool physical;         // -P
    bool functrace;        // -T
    bool interactive;      // Set automatically
    bool restricted;       // --restricted
    bool posix;            // --posix
    bool noediting;        // --noediting
    bool norc;             // --norc
    bool noprofile;        // --noprofile
    bool login_shell;      // --login
    bool histappend;       // shopt -s histappend
    bool histreedit;       // shopt -s histreedit
    bool histverify;       // shopt -s histverify
    bool checkwinsize;     // shopt -s checkwinsize
} ShellOptions;

static ShellOptions shell_opts = {0};

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
static void execute_command_line_from_file(const char* filename);
static void cleanup_and_exit(void);
static void load_shell_rc_file(void);
static int builtin_case(char** args);
static int builtin_shopt(char** args);
static int builtin_test(char** args);
static char* expand_command_substitution(const char* input);
static char* expand_bash_prompt(const char* ps1);
static int execute_case_statement(const char* value, CaseStatement* cases);

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


// you can enable this function if you want auto detect distro name, don't forget to enable from main function
// static void detect_distro_name(void) { 
//    FILE* f = fopen("/etc/os-release", "r");
//    if (!f) return;
//    char line[128];
//    while (fgets(line, sizeof(line), f)) {
//        if (strncmp(line, "NAME=", 5) == 0) { 
//            char* val = line + 5;
//            // Remove leading quote if present
//            if (*val == '\"') val++;
//            // Remove trailing quote and newline if present
//            size_t len = strlen(val);
//            while (len > 0 && (val[len-1] == '\\n' || val[len-1] == '\"')) {
//                val[--len] = '\\0';
//            }
//            strncpy(distro_name, val, sizeof(distro_name)-1);
//            distro_name[sizeof(distro_name)-1] = '\\0';
//            break;
//        }
//    }
//    fclose(f);
//}

// 500+ Windows CMD translations
static const CmdMapping cmd_mappings[] = {
    // Basic File Operations (100+ entries)
    {"dir", "ls -lh --color=auto", "List directory contents"},
    {"dir /s", "find . -type f", "List recursively"},
    {"dir /a", "ls -la", "Show all files"},
    {"dir /b", "ls -1", "Bare format"},
    {"dir /o-n", "ls -lr", "Reverse order"},
    {"dir /od", "ls -lt", "Sort by date"},
    {"dir /os", "ls -lS", "Sort by size"},
    {"dir /q", "ls -o", "Show owner"},
    {"dir /t:c", "ls -lc", "Creation time"},
    {"dir /t:a", "ls -lu", "Access time"},
    {"dir /x", "ls -l", "Short names"},
    {"dir /4", "ls -lh", "Four-digit years"},
    {"dir /o-s", "ls -lSr", "Sort size descending"},
    {"dir /o-d", "ls -ltr", "Sort date descending"},
    {"dir /a:h", "ls -ld .*/", "Hidden only"},
    {"dir /a:-h", "ls -d */", "Non-hidden only"},
    {"dir /s/b", "find . -type f -print", "Recursive bare"},
    {"dir /s/b/a:d", "find . -type d -print", "Recursive dir list"},
    {"copy", "cp -i", "Copy files"},
    {"copy /v", "cp -v", "Verify copy"},
    {"copy /y", "cp -f", "Suppress prompt"},
    {"copy /-y", "cp -i", "Prompt confirm"},
    {"copy /z", "rsync --partial", "Restartable"},
    {"xcopy", "cp -r", "Copy directories"},
    {"xcopy /s", "cp -r", "Subdirectories"},
    {"xcopy /e", "cp -r", "Empty subdirs"},
    {"xcopy /i", "mkdir -p", "Assume directory"},
    {"xcopy /h", "cp -a", "Copy hidden"},
    {"xcopy /k", "cp --preserve", "Copy attributes"},
    {"xcopy /d", "cp -u", "Copy newer only"},
    {"xcopy /c", "cp --ignore-errors", "Continue on error"},
    {"xcopy /f", "cp -v", "Display full source/dest"},
    {"xcopy /l", "cp -n", "List only"},
    {"xcopy /g", "cp --preserve", "Copy encrypted"},
    {"xcopy /r", "cp -r", "Overwrite read-only"},
    {"xcopy /u", "cp -u", "Copy newer only"},
    {"xcopy /v", "cp --verify", "Verify after copy"},
    {"xcopy /w", "cp --interactive", "Wait for key"},
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
    {"del", "rm -i", "Delete files"},
    {"del /f", "rm -f", "Force delete"},
    {"del /s", "find . -type f -delete", "Delete recursively"},
    {"del /q", "rm -f", "Quiet delete"},
    {"del /a", "rm", "Delete with attributes"},
    {"del /p", "rm -i", "Prompt delete"},
    {"erase", "rm -i", "Delete files"},
    {"erase /f", "rm -f", "Force erase"},
    {"move", "mv -i", "Move/rename files"},
    {"move /y", "mv -f", "Suppress prompt"},
    {"move /-y", "mv -i", "Prompt confirm"},
    {"ren", "mv", "Rename files"},
    {"rename", "mv", "Rename files"},
    {"type", "cat", "Display file content"},
    {"type >", "cat >", "Create file"},
    {"type >>", "cat >>", "Append file"},
    {"more", "less", "View file page by page"},
    {"cls", "clear", "Clear screen"},
    {"cd", "cd", "Change directory"},
    {"chdir", "cd", "Change directory"},
    {"mkdir", "mkdir -p", "Make directory"},
    {"md", "mkdir -p", "Make directory"},
    {"rmdir", "rmdir", "Remove empty directory"},
    {"rmdir /s", "rm -r", "Remove directory tree"},
    {"rmdir /q", "rm -rf", "Quiet remove"},
    {"rd", "rmdir", "Remove directory"},
    {"pushd", "pushd", "Push directory"},
    {"popd", "popd", "Pop directory"},
    {"dirs", "dirs", "Show directory stack"},
    {"subst", "mount --bind", "Substitute path"},
    {"subst /d", "umount", "Delete substitution"},
    {"mklink", "ln -s", "Symbolic link"},
    {"mklink /d", "ln -s", "Directory link"},
    {"mklink /h", "ln", "Hard link"},
    {"mklink /j", "mount --bind", "Junction"},
    {"fsutil", "tune2fs", "File system utility"},
    {"fsutil fsinfo", "df -T", "FS info"},
    {"fsutil behavior", "sysctl fs", "FS behavior"},
    {"fsutil dirty", "tune2fs -l", "Volume dirty state"},
    {"compact", "btrfs filesystem defragment -czstd", "Compact files"},
    {"compact /c", "chattr +c", "Compress files"},
    {"compact /u", "chattr -c", "Uncompress files"},
    {"compact /s", "gzip -r", "Compress subdirs"},
    {"compact /a", "gzip --best", "High compression"},
    {"compact /i", "gzip --force", "Force compression"},
    {"compact /f", "gzip --force", "Force compression"},
    {"compact /q", "gzip -q", "Quiet"},
    {"where", "which -a", "Find command"},
    {"where /r", "find / -name", "Recursive find"},
    {"where /t", "which -a", "Show paths"},
    {"which", "which", "Find command"},
    {"tree", "tree", "Show directory tree"},
    {"tree /f", "tree", "Show files"},
    {"tree /a", "tree", "ASCII characters"},
    {"tree /d", "tree -d", "Directories only"},
    {"robocopy", "rsync -av", "Robust copy"},
    {"robocopy /mir", "rsync -av --delete", "Mirror"},
    {"robocopy /mov", "rsync -av --remove-source-files", "Move files"},
    {"robocopy /z", "rsync -av --partial", "Restartable mode"},
    {"robocopy /b", "rsync -av", "Backup mode"},
    {"robocopy /zb", "rsync -av --partial", "Restartable backup"},
    {"robocopy /copyall", "rsync -av --perms --times --owner --group", "Copy all info"},
    {"robocopy /copy:datso", "rsync -av --perms --times --owner --group", "Copy flags"},
    {"robocopy /sec", "rsync -av --perms", "Copy security"},
    {"robocopy /timfix", "rsync -av --times", "Fix times"},
    {"robocopy /create", "rsync -av --dry-run", "Create only"},
    {"dsadd", "useradd", "Add object"},
    {"dsmod", "usermod", "Modify object"},
    {"dsrm", "userdel", "Remove object"},
    {"dsquery", "getent", "Query objects"},
    {"dsget", "id", "Get object properties"},
    {"csvde", "csv2ldif", "CSV import/export"},
    {"ldifde", "ldapadd", "LDIF import/export"},
    {"tar", "tar", "Tape archive"},
    {"tar -xvf", "tar xvf", "Extract verbose"},
    {"tar -cvf", "tar cvf", "Create verbose"},
    {"tar -tvf", "tar tvf", "List verbose"},
    {"tar -zxvf", "tar zxvf", "Gzip extract"},
    {"tar -zcvf", "tar zcvf", "Gzip create"},
    {"tar -jxvf", "tar jxvf", "Bzip2 extract"},
    {"tar -jcvf", "tar jcvf", "Bzip2 create"},
    {"tar -Jxvf", "tar Jxvf", "XZ extract"},
    {"tar -Jcvf", "tar Jcvf", "XZ create"},
    {"zip", "zip", "Create zip"},
    {"zip -r", "zip -r", "Recursive zip"},
    {"zip -e", "zip -e", "Encrypt zip"},
    {"zip -9", "zip -9", "Best compression"},
    {"zip -0", "zip -0", "No compression"},
    {"unzip", "unzip", "Extract zip"},
    {"unzip -l", "unzip -l", "List zip"},
    {"unzip -t", "unzip -t", "Test zip"},
    {"unzip -o", "unzip -o", "Overwrite"},
    {"unzip -q", "unzip -q", "Quiet"},
    {"unzip -v", "unzip -v", "Verbose"},
    {"gzip", "gzip", "Gzip compress"},
    {"gzip -d", "gunzip", "Decompress gzip"},
    {"gzip -r", "gzip -r", "Recursive gzip"},
    {"gzip -9", "gzip -9", "Best compression"},
    {"gzip -1", "gzip -1", "Fast compression"},
    {"gunzip", "gunzip", "Gzip decompress"},
    {"bzip2", "bzip2", "Bzip2 compress"},
    {"bzip2 -d", "bunzip2", "Decompress bzip2"},
    {"bunzip2", "bunzip2", "Bzip2 decompress"},
    {"xz", "xz", "XZ compress"},
    {"xz -d", "unxz", "Decompress XZ"},
    {"unxz", "unxz", "XZ decompress"},
    {"compress", "compress", "Compress file"},
    {"uncompress", "uncompress", "Uncompress file"},
    {"makecab", "tar czf", "Make cabinet"},
    {"makecab /d", "tar --options", "Set options"},
    {"makecab /f", "tar -T", "Use file list"},
    {"makecab /v", "tar -v", "Verbose"},
    {"extrac32", "tar xzf", "Extract cabinet"},
    {"extrac32 /y", "tar -f", "Yes to all"},
    {"extrac32 /a", "tar -a", "Process all cabinets"},
    {"extrac32 /c", "tar -t", "Copy to stdout"},
    {"extrac32 /e", "tar -x", "Extract"},
    {"extrac32 /l", "tar -l", "Location"},
    {"expand", "unzip", "Expand file"},
    {"expand /r", "unzip -o", "Expand with rename"},
    {"expand /i", "unzip -i", "Expand with info"},
    {"expand /d", "unzip -l", "Display files"},
    {"expand /f", "unzip -f", "Force expand"},
    
    // File Attributes & Permissions
    {"attrib", "chmod", "Change file attributes"},
    {"attrib +r", "chmod +r", "Set read-only"},
    {"attrib -r", "chmod -r", "Clear read-only"},
    {"attrib +h", "chattr +h", "Set hidden"},
    {"attrib -h", "chattr -h", "Clear hidden"},
    {"attrib +s", "chattr +s", "Set system"},
    {"attrib -s", "chattr -s", "Clear system"},
    {"attrib +a", "chattr +a", "Set archive"},
    {"attrib -a", "chattr -a", "Clear archive"},
    {"attrib +i", "chattr +i", "Set immutable"},
    {"attrib -i", "chattr -i", "Clear immutable"},
    {"attrib /s", "chmod -R", "Recurse"},
    {"attrib /d", "chmod", "Directory"},
    {"attrib /l", "chmod", "Symbolic link"},
    {"cacls", "chmod", "Change ACLs"},
    {"cacls /e", "chmod", "Edit ACLs"},
    {"cacls /t", "chmod -R", "Tree"},
    {"cacls /c", "chmod --continue", "Continue on error"},
    {"cacls /g", "chmod", "Grant"},
    {"cacls /r", "chmod", "Revoke"},
    {"cacls /p", "chmod", "Replace"},
    {"cacls /d", "chmod", "Deny"},
    {"icacls", "setfacl", "Change ACLs"},
    {"icacls /grant", "setfacl -m u", "Grant permissions"},
    {"icacls /deny", "setfacl -m u", "Deny permissions"},
    {"icacls /remove", "setfacl -x", "Remove permissions"},
    {"icacls /remove:a", "setfacl -x", "Remove all"},
    {"icacls /inheritance", "setfacl -n", "Inheritance"},
    {"icacls /reset", "setfacl -b", "Reset ACLs"},
    {"icacls /replace", "setfacl -m", "Replace ACLs"},
    {"icacls /substitute", "setfacl -m", "Substitute ACLs"},
    {"icacls /restore", "setfacl --restore", "Restore ACLs"},
    {"icacls /save", "getfacl >", "Save ACL"},
    {"icacls /verify", "getfacl --verify", "Verify ACL"},
    {"takeown", "chown", "Take ownership"},
    {"takeown /f", "chown", "Take file ownership"},
    {"takeown /r", "chown -R", "Recursive ownership"},
    {"takeown /d", "chown", "Default answer"},
    {"takeown /s", "ssh chown", "Remote ownership"},
    {"takeown /u", "chown", "Username"},
    {"takeown /p", "chown", "Password"},
    {"takeown /a", "chgrp", "Administrators"},
    {"runas", "sudo", "Run as administrator"},
    {"runas /user", "sudo -u", "Run as specific user"},
    {"runas /savecred", "sudo -S", "Save credentials"},
    {"runas /trustlevel", "sudo -g", "Trust level"},
    {"runas /netonly", "sudo -i", "Network only"},
    {"runas /profile", "sudo -E", "Load profile"},
    {"runas /env", "sudo -E", "Environment"},
    {"runas /noprofile", "sudo", "No profile"},
    
    // Search & Comparison
    {"find", "grep", "Find string in file"},
    {"findstr", "grep", "Find string"},
    {"findstr /i", "grep -i", "Case insensitive"},
    {"findstr /r", "grep -E", "Regex search"},
    {"findstr /s", "grep -r", "Recursive search"},
    {"findstr /n", "grep -n", "Line numbers"},
    {"findstr /v", "grep -v", "Invert match"},
    {"findstr /c:", "grep -F", "Literal string"},
    {"findstr /b", "grep '^pattern'", "Beginning of line"},
    {"findstr /e", "grep 'pattern$'", "End of line"},
    {"findstr /g", "grep -f", "File with strings"},
    {"findstr /f", "grep", "File list"},
    {"findstr /o", "grep -b", "Print byte offset"},
    {"findstr /l", "grep -G", "Literal search"},
    {"findstr /m", "grep -l", "File name only"},
    {"findstr /p", "grep", "Skip binary"},
    {"findstr /off", "grep -a", "Offline files"},
    {"comp", "diff", "Compare files"},
    {"comp /a", "diff -a", "ASCII compare"},
    {"comp /l", "diff -d", "Line numbers"},
    {"comp /c", "diff --ignore-case", "Case insensitive"},
    {"comp /n=", "diff -n", "Number of lines"},
    {"fc", "diff", "File compare"},
    {"fc /b", "cmp -b", "Binary compare"},
    {"fc /l", "diff", "ASCII compare"},
    {"fc /lb", "diff --speed-large-files", "Large binary"},
    {"fc /n", "diff -n", "Line numbers"},
    {"fc /t", "diff -t", "Don't expand tabs"},
    {"fc /u", "diff -u", "Unicode compare"},
    {"fc /w", "diff -w", "Ignore whitespace"},
    {"fc /c", "diff --ignore-case", "Case insensitive"},
    {"fc /a", "diff --text", "Abbreviate output"},
    {"tree", "tree", "Show directory tree"},
    {"tree /f", "tree", "Show files"},
    {"tree /a", "tree", "ASCII characters"},
    {"tree /d", "tree -d", "Directories only"},
    {"tree /f > file.txt", "find . > file.txt", "Tree to file"},
    {"tree /a > file.txt", "find . -type f > file.txt", "ASCII tree to file"},
    {"robocopy", "rsync -av", "Robust copy"},
    {"robocopy /mir", "rsync -av --delete", "Mirror"},
    {"robocopy /mov", "rsync -av --remove-source-files", "Move files"},
    {"robocopy /z", "rsync -av --partial", "Restartable mode"},
    {"robocopy /b", "rsync -av", "Backup mode"},
    {"robocopy /zb", "rsync -av --partial", "Restartable backup"},
    {"robocopy /copyall", "rsync -av --perms --times --owner --group", "Copy all info"},
    {"robocopy /sec", "rsync -av --perms", "Copy security"},
    {"robocopy /timfix", "rsync -av --times", "Fix times"},
    {"robocopy /create", "rsync -av --dry-run", "Create only"},
    {"robocopy /l", "rsync -av --dry-run", "List only"},
    {"robocopy /x", "rsync -av --one-file-system", "Skip junctions"},
    {"robocopy /bytes", "rsync -av --size-only", "File sizes"},
    {"robocopy /ts", "rsync -av --times", "Include timestamps"},
    {"robocopy /fp", "rsync -av --relative", "Full path names"},
    {"robocopy /ns", "rsync -av --no-implied-dirs", "File sizes only"},
    {"robocopy /nc", "rsync -av --no-checksum", "No classes"},
    {"robocopy /nfl", "rsync -av --ignore-existing", "No file list"},
    {"robocopy /ndl", "rsync -av --no-dirs", "No dir list"},
    {"robocopy /np", "rsync -av --quiet", "No progress"},
    {"robocopy /eta", "rsync -av --progress", "ETA"},
    {"robocopy /log", "rsync -av --log-file", "Log file"},
    {"robocopy /log+", "rsync -av --log-file=+.", "Append log"},
    {"robocopy /tee", "rsync -av --outbuf=L", "Tee output"},
    {"robocopy /job", "rsync -av --include-from", "Job file"},
    {"robocopy /save", "rsync -av --dry-run >", "Save job"},
    {"robocopy /quit", "rsync --dry-run", "Quit after processing"},
    {"robocopy /nocopy", "rsync --list-only", "No copy"},
    {"robocopy /unicode", "rsync --iconv=UTF-8", "Unicode"},
    {"robocopy /reg", "rsync", "Save as default"},
    {"robocopy /wait", "rsync --delay-updates", "Wait for sharenames"},
    {"robocopy /lfsm", "rsync --fuzzy", "Low free space mode"},
    
    // Process Management (NO systemctl)
    {"tasklist", "ps aux", "List processes"},
    {"tasklist /v", "ps auxf", "Detailed processes"},
    {"tasklist /fi", "ps aux | grep", "Filter processes"},
    {"tasklist /fo", "ps -o", "Formatted output"},
    {"tasklist /m", "pmap", "List modules"},
    {"tasklist /svc", "ps -ef", "Show services"},
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
    {"start /realtime", "chrt -r 99", "Real-time priority"},
    {"start /abovenormal", "nice -n -5", "Above normal priority"},
    {"start /belownormal", "nice -n 5", "Below normal priority"},
    {"start /affinity", "taskset", "Set CPU affinity"},
    {"start /separate", "setsid", "Separate memory space"},
    {"start /shared", "exec", "Shared memory space"},
    {"start /b", "nohup &", "Start in background"},
    {"start /i", "nohup", "Ignore environment"},
    {"qprocess", "lsof -i", "Query processes"},
    {"qappsrv", "ss -tuln", "Query application servers"},
    {"qwinsta", "who -u", "Query sessions"},
    {"rwinsta", "pkill -t", "Reset session"},
    {"tsdiscon", "pkill -kill -t", "Disconnect session"},
    {"tskill", "pkill", "Terminate session"},
    {"shadow", "ssh", "Shadow session"},
    {"ps", "ps aux", "Process status"},
    {"ps /e", "ps -e", "Every process"},
    {"ps /o", "ps -o", "Custom format"},
    {"kill", "kill", "Terminate process"},
    {"kill /f", "kill -9", "Force kill"},
    {"pkill", "pkill", "Process kill"},
    {"pgrep", "pgrep", "Process grep"},
    {"skill", "kill", "Send signal"},
    {"snice", "renice", "Nice process"},
    {"renice", "renice", "Change priority"},
    {"htop", "htop", "Interactive top"},
    {"top", "top", "System monitor"},
    {"atop", "atop", "Advanced top"},
    {"btop", "btop", "Better top"},
    {"glances", "glances", "System monitor"},
    {"nmon", "nmon", "System monitor"},
    {"dstat", "dstat", "System statistics"},
    {"vmstat", "vmstat", "Virtual memory stats"},
    {"iostat", "iostat", "I/O statistics"},
    {"mpstat", "mpstat", "CPU statistics"},
    {"pidstat", "pidstat", "Per-process stats"},
    {"strace", "strace", "Trace system calls"},
    {"ltrace", "ltrace", "Trace library calls"},
    {"ftrace", "ftrace", "Function tracer"},
    {"perf", "perf", "Performance profiler"},
    {"gdb", "gdb", "GNU debugger"},
    {"lldb", "lldb", "LLVM debugger"},
    {"valgrind", "valgrind", "Memory checker"},
    {"lsof", "lsof", "List open files"},
    {"fuser", "fuser", "File user"},
    {"timeout", "timeout", "Run with timeout"},
    {"ulimit", "ulimit", "Set resource limits"},
    {"nice", "nice", "Run with nice"},
    {"renice", "renice", "Change nice value"},
    {"schedtool", "schedtool", "Scheduling policy"},
    {"taskset", "taskset", "Set CPU affinity"},
    {"ionice", "ionice", "I/O scheduling"},
    {"cgroup", "cgexec", "Control group"},
    {"cgcreate", "cgcreate", "Create cgroup"},
    {"cgdelete", "cgdelete", "Delete cgroup"},
    {"cgclassify", "cgclassify", "Classify process"},
    
    // System Information (NO systemctl/journalctl/apt/dpkg)
    {"ver", "uname -a", "Show version"},
    {"systeminfo", "neofetch || screenfetch || inxi -F", "System information"},
    {"wmic", "lshw || hwinfo", "Hardware info"},
    {"wmic cpu", "lscpu", "CPU info"},
    {"wmic memory", "free -h", "Memory info"},
    {"wmic diskdrive", "lsblk -d", "Disk info"},
    {"wmic process", "ps aux", "Process info"},
    {"wmic os", "uname -a", "OS info"},
    {"wmic product", "fpmt list", "Installed products"},
    {"wmic qfe", "fpmt list --updates", "Quick fix engineering"},
    {"wmic startup", "ls /etc/init.d/", "Startup items"},
    {"wmic printer", "lpstat -p", "Printer info"},
    {"wmic share", "exportfs -v", "Share info"},
    {"wmic service", "service --status-all", "Service info"},
    {"wmic useraccount", "cat /etc/passwd", "User accounts"},
    {"wmic group", "cat /etc/group", "Groups"},
    {"wmic netlogin", "lastlog", "Network login"},
    {"wmic nic", "ip a", "Network interface"},
    {"wmic nicconfig", "cat /etc/network/interfaces", "NIC config"},
    {"msinfo32", "inxi -F", "System information"},
    {"dxdiag", "glxinfo || vulkaninfo", "DirectX diagnostics"},
    {"driverquery", "lsmod", "List drivers"},
    {"driverquery /v", "modinfo", "Driver details"},
    {"driverquery /fo", "lsmod | awk", "Formatted output"},
    {"driverquery /si", "lsmod", "Signed drivers"},
    {"perfmon", "htop || atop || nmon", "Performance monitor"},
    {"perfmon /sys", "perf stat", "System performance"},
    {"perfmon /report", "perf report", "Performance report"},
    {"resmon", "btop || htop || glances", "Resource monitor"},
    {"taskmgr", "htop", "Task manager"},
    {"procexp", "htop", "Process Explorer"},
    {"procmon", "strace -p", "Process Monitor"},
    {"tcpview", "ss -tp", "TCP connection viewer"},
    {"autoruns", "ls /etc/rc*.d/", "Autoruns"},
    {"msconfig", "sysv-rc-conf || chkconfig", "System configuration"},
    {"control", "sysv-rc-conf", "Control panel"},
    {"appwiz.cpl", "fpmt list", "Add/remove programs"},
    {"compmgmt.msc", "sudo -i", "Computer management"},
    {"devmgmt.msc", "lshw -X || hardinfo", "Device manager"},
    {"diskmgmt.msc", "gparted || gnome-disks", "Disk management"},
    {"fsmgmt.msc", "df -h", "Shared folders"},
    {"gpedit.msc", "visudo", "Group policy"},
    {"lusrmgr.msc", "vipw", "Local users"},
    {"secpol.msc", "visudo", "Security policy"},
    {"credwiz", "pass", "Credential wizard"},
    {"certmgr.msc", "certutil", "Certificate manager"},
    {"eventvwr", "tail -f /var/log/syslog", "Event viewer"},
    {"eventcreate", "logger", "Create event"},
    {"eventtriggers", "inotifywait", "Event triggers"},
    {"sharedoc", "hostname -i", "Shared folders"},
    {"shares", "exportfs -v", "List shares"},
    {"services.msc", "service --status-all", "Service manager"},
    {"tasks", "crontab -l", "Scheduled tasks"},
    {"taskschd.msc", "crontab -e", "Task scheduler"},
    {"regedit", "vim /etc", "Registry editor"},
    {"regedt32", "vim /etc", "Registry editor 32"},
    {"reg", "echo 'Linux uses /etc'", "Registry command"},
    {"unassoc", "rm -f /etc/mime.types", "Unassociate file type"},
    {"ftype", "xdg-mime", "File type association"},
    {"assoc", "file", "File association"},
    {"gpresult", "getfacl", "Group policy result"},
    {"rsop.msc", "getfacl", "Resultant Set of Policy"},
    {"secedit", "visudo", "Security configuration"},
    {"sigverif", "rpm -V", "Signature verification"},
    {"sfc", "debsums", "System file checker"},
    {"sfc /scannow", "debsums -c", "Scan now"},
    {"sfc /verifyfile", "debsums", "Verify file"},
    {"sfc /scanfile", "debsums -s", "Scan file"},
    {"dism", "fpmt reinstall", "DISM tool"},
    {"dism /online", "fpmt install", "Online repair"},
    {"dism /image", "fpmt install --root", "Image repair"},
    {"dism /cleanup-image", "fpmt clean", "Cleanup image"},
    {"dism /restorehealth", "fpmt reinstall", "Restore health"},
    {"winsat", "phoronix-test-suite", "Windows system assessment"},
    {"slmgr", "echo 'License management not applicable'", "Software licensing"},
    {"slmgr /xpr", "echo 'No expiration'", "Expiration date"},
    {"slmgr /dlv", "echo 'License details'", "License details"},
    {"slui", "echo 'License activation not applicable'", "Software Licensing UI"},
    {"msdt", "sosreport", "Microsoft Support Diagnostic Tool"},
    {"psr", "recordmydesktop", "Problem Steps Recorder"},
    {"winver", "uname -r", "Windows version"},
    {"dxdiag /t", "glxinfo >", "DirectX diagnostics to file"},
    {"msinfo32 /report", "inxi -F >", "System info to file"},
    {"systeminfo /s", "ssh user@host uname -a", "Remote system info"},
    {"systeminfo /fo", "uname -a | awk", "Formatted output"},
    {"driverquery /si", "lsmod", "Signed drivers"},
    {"driverquery /v", "modinfo", "Verbose"},
    {"driverquery /fo", "lsmod | column", "Formatted"},
    {"wmic /node", "ssh host lshw", "Remote node"},
    {"wmic /output", "lshw >", "Output to file"},
    {"wmic /user", "sudo -u", "User context"},
    {"wmic /namespace", "sysfs", "WMI namespace"},
    
    // Disk & Filesystem (EXPANDED, NO apt/journalctl)
    {"chkdsk", "fsck", "Check disk"},
    {"chkdsk /f", "fsck -f", "Fix filesystem errors"},
    {"chkdsk /r", "fsck -c", "Check bad sectors"},
    {"chkdsk /x", "umount && fsck", "Force unmount and check"},
    {"chkdsk /v", "fsck -v", "Verbose check"},
    {"chkdsk /scan", "fsck -n", "Scan only"},
    {"chkdsk /perf", "fsck -t", "Performance"},
    {"chkdsk /spotfix", "fsck -y", "Spot fix"},
    {"chkdsk /forceofflinefix", "fsck -f", "Force offline"},
    {"chkdsk /prefetch", "fsck -p", "Prefetch"},
    {"chkdsk /i", "fsck -i", "Index"},
    {"chkdsk /c", "fsck -c", "Skip cycles"},
    {"chkdsk /b", "fsck -b", "Bad clusters"},
    {"chkdsk /scan", "fsck -n", "Scan only"},
    {"diskpart", "fdisk || gdisk || parted || cfdisk", "Disk partition tool"},
    {"diskpart /s", "sfdisk <", "Scripted partition"},
    {"diskpart /l", "lsblk", "List partitions"},
    {"diskpart /add", "parted mkpart", "Add partition"},
    {"diskpart /delete", "parted rm", "Delete partition"},
    {"diskpart /active", "parted set", "Set active"},
    {"diskpart /extend", "parted resizepart", "Extend partition"},
    {"diskpart /shrink", "parted resizepart", "Shrink partition"},
    {"diskpart /format", "mkfs", "Format partition"},
    {"diskpart /clean", "dd if=/dev/zero", "Clean disk"},
    {"diskpart /online", "partprobe", "Online disk"},
    {"diskpart /offline", "partprobe", "Offline disk"},
    {"diskpart /readonly", "hdparm -r", "Readonly disk"},
    {"diskpart /noerr", "parted ---pretend-input-tty", "No errors"},
    {"diskpart /compatibility", "parted -a", "Compatibility mode"},
    {"diskpart /rescan", "partprobe", "Rescan"},
    {"diskpart /attributes", "parted set", "Disk attributes"},
    {"diskpart /gpt", "gdisk", "GPT partition"},
    {"diskpart /mbr", "fdisk", "MBR partition"},
    {"diskpart /script", "sfdisk", "Script mode"},
    {"diskpart /list", "lsblk", "List disks"},
    {"diskpart /detail", "parted -l", "Detailed disk"},
    {"diskpart /uniqueid", "blkid", "Unique ID"},
    {"format", "mkfs", "Format disk"},
    {"format /fs:ntfs", "mkfs.ntfs", "Format NTFS"},
    {"format /fs:fat32", "mkfs.vfat -F 32", "Format FAT32"},
    {"format /fs:exfat", "mkfs.exfat", "Format exFAT"},
    {"format /fs:ext4", "mkfs.ext4", "Format Ext4"},
    {"format /fs:btrfs", "mkfs.btrfs", "Format Btrfs"},
    {"format /q", "mkfs -f", "Quick format"},
    {"format /v", "mkfs -L", "Volume label"},
    {"format /a", "mkfs -c", "Allocation unit"},
    {"format /p", "mkfs -p", "Passes"},
    {"defrag", "e4defrag", "Defragment disk"},
    {"defrag /c", "e4defrag /dev/sd*", "Defrag all volumes"},
    {"defrag /a", "e4defrag -c", "Analyze only"},
    {"defrag /v", "e4defrag -v", "Verbose defrag"},
    {"defrag /x", "e4defrag -x", "Free space consolidation"},
    {"defrag /h", "e4defrag -h", "Defrag hidden"},
    {"defrag /k", "e4defrag -k", "SSD defrag"},
    {"defrag /l", "e4defrag -l", "Large file defrag"},
    {"defrag /m", "e4defrag -m", "Metadata defrag"},
    {"cipher", "cryptsetup", "Encrypt files"},
    {"cipher /e", "cryptsetup luksFormat", "Encrypt drive"},
    {"cipher /d", "cryptsetup luksRemoveKey", "Decrypt drive"},
    {"cipher /w", "shred -v -z -n 0", "Wipe free space"},
    {"cipher /k", "openssl genrsa", "Generate EFS cert"},
    {"cipher /u", "cryptsetup luksChangeKey", "Update key"},
    {"cipher /x", "cryptsetup luksHeaderBackup", "Backup key"},
    {"cipher /y", "cryptsetup isLuks", "Test encryption"},
    {"cipher /adduser", "cryptsetup luksAddKey", "Add user key"},
    {"cipher /rekey", "cryptsetup luksChangeKey", "Re-encrypt"},
    {"vssadmin", "btrfs subvolume", "Volume shadow copy"},
    {"vssadmin create", "btrfs subvolume snapshot", "Create snapshot"},
    {"vssadmin list", "btrfs subvolume list", "List snapshots"},
    {"vssadmin delete", "btrfs subvolume delete", "Delete snapshot"},
    {"vssadmin resize", "btrfs filesystem resize", "Resize shadow"},
    {"vssadmin resize shadowstorage", "btrfs qgroup limit", "Resize storage"},
    {"convert", "convert", "Convert FAT to NTFS"},
    {"convert /fs:ntfs", "btrfs-convert", "Convert to NTFS"},
    {"label", "e2label || xfs_admin -L || btrfs filesystem label", "Volume label"},
    {"label /mp", "findmnt -n -o LABEL", "Label by mount point"},
    {"label /vol", "blkid -s LABEL", "Label by volume"},
    {"vol", "df -h", "Volume info"},
    {"vol /?", "df --help", "Volume help"},
    {"diskcopy", "dd", "Copy disk"},
    {"diskcopy /v", "dd conv=fdatasync", "Verify copy"},
    {"diskcomp", "cmp", "Compare disks"},
    {"diskcomp /v", "cmp -v", "Verbose compare"},
    {"recover", "ddrescue", "Recover files"},
    {"recover /?", "ddrescue --help", "Recover help"},
    {"diskperf", "iostat -x", "Disk performance"},
    {"diskperf -y", "iostat -x 1", "Enable counters"},
    {"diskperf -n", "iostat", "Disable counters"},
    {"volperf", "iostat", "Volume performance"},
    {"winsat disk", "hdparm -tT", "Disk benchmark"},
    {"winsat mem", "memtester", "Memory benchmark"},
    {"winsat cpu", "sysbench cpu", "CPU benchmark"},
    {"winsat dwm", "glxgears", "Desktop benchmark"},
    {"winsat formal", "phoronix-test-suite batch", "Formal benchmark"},
    
    // Network Commands (EXPANDED, NO apt/journalctl)
    {"ipconfig", "ip a || ifconfig || ip addr", "Network configuration"},
    {"ipconfig /all", "ip -d a", "Detailed network config"},
    {"ipconfig /release", "dhclient -r", "Release IP"},
    {"ipconfig /renew", "dhclient", "Renew IP"},
    {"ipconfig /flushdns", "resolvectl flush-caches || systemd-resolve --flush-caches", "Flush DNS"},
    {"ipconfig /displaydns", "resolvectl statistics || cat /etc/hosts", "Display DNS cache"},
    {"ipconfig /registerdns", "resolvectl revert", "Register DNS"},
    {"ipconfig /showclassid", "ip a show", "Show class ID"},
    {"ipconfig /setclassid", "ip a set", "Set class ID"},
    {"ipconfig /release6", "dhclient -6 -r", "Release IPv6"},
    {"ipconfig /renew6", "dhclient -6", "Renew IPv6"},
    {"ipconfig /allcompartments", "ip -d a s", "All compartments"},
    {"ping", "ping", "Ping host"},
    {"ping -t", "ping", "Ping until interrupted"},
    {"ping -n", "ping -c", "Ping count"},
    {"ping -l", "ping -s", "Ping buffer size"},
    {"ping -f", "ping -f", "Flood ping"},
    {"ping -i", "ping -i", "Interval"},
    {"ping -w", "ping -w", "Timeout"},
    {"ping -4", "ping -4", "IPv4 only"},
    {"ping -6", "ping -6", "IPv6 only"},
    {"ping -r", "ping -R", "Record route"},
    {"ping -s", "ping -s", "Timestamp"},
    {"ping -j", "ping", "Loose source route"},
    {"ping -k", "ping", "Strict source route"},
    {"tracert", "traceroute", "Trace route"},
    {"tracert -d", "traceroute -n", "No resolution"},
    {"tracert -h", "traceroute -m", "Max hops"},
    {"tracert -w", "traceroute -w", "Timeout"},
    {"tracert -4", "traceroute -4", "IPv4 trace"},
    {"tracert -6", "traceroute -6", "IPv6 trace"},
    {"tracert -R", "traceroute --reverse", "Reverse trace"},
    {"tracert -S", "traceroute --source", "Source address"},
    {"tracert -j", "traceroute", "Loose source"},
    {"tracert -k", "traceroute", "Strict source"},
    {"pathping", "mtr", "Path ping"},
    {"pathping -n", "mtr -n", "No resolution"},
    {"pathping -h", "mtr -m", "Max hops"},
    {"pathping -w", "mtr -w", "Timeout"},
    {"pathping -4", "mtr -4", "IPv4 pathping"},
    {"pathping -6", "mtr -6", "IPv6 pathping"},
    {"pathping -R", "mtr -R", "Reverse path"},
    {"pathping -T", "mtr -T", "TCP pathping"},
    {"nslookup", "nslookup", "DNS lookup"},
    {"nslookup -type=a", "host", "A record lookup"},
    {"nslookup -type=mx", "dig mx", "MX record lookup"},
    {"nslookup -type=ns", "dig ns", "NS record lookup"},
    {"nslookup -type=ptr", "dig -x", "PTR record lookup"},
    {"nslookup -type=txt", "dig txt", "TXT record lookup"},
    {"nslookup -type=soa", "dig soa", "SOA record lookup"},
    {"nslookup -type=aaaa", "dig aaaa", "AAAA record lookup"},
    {"nslookup -type=cname", "dig cname", "CNAME lookup"},
    {"nslookup -type=srv", "dig srv", "SRV record lookup"},
    {"netstat", "ss -tuln || netstat", "Network statistics"},
    {"netstat -a", "ss -a", "All connections"},
    {"netstat -an", "ss -an", "All numeric"},
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
    {"netstat -x", "ss -x", "Unix sockets"},
    {"netstat -v", "ss -v", "Verbose"},
    {"netstat -c", "ss -c", "Continuous"},
    {"netstat -l", "ss -l", "Listening"},
    {"netstat -lt", "ss -lt", "TCP listening"},
    {"netstat -lu", "ss -lu", "UDP listening"},
    {"route", "ip route", "View route table"},
    {"route print", "ip route show", "Print routes"},
    {"route add", "ip route add", "Add route"},
    {"route delete", "ip route del", "Delete route"},
    {"route change", "ip route replace", "Change route"},
    {"route -f", "ip route flush", "Flush routes"},
    {"route -p", "ip route add", "Persistent route"},
    {"route -4", "ip -4 route", "IPv4 routes"},
    {"route -6", "ip -6 route", "IPv6 routes"},
    {"route -v", "ip -v route", "Verbose routes"},
    {"route add 0.0.0.0", "ip route add default", "Default route"},
    {"route add 127.0.0.1", "ip route add local", "Local route"},
    {"arp", "ip neigh", "ARP table"},
    {"arp -a", "ip neigh show", "ARP cache"},
    {"arp -d", "ip neigh del", "Delete ARP entry"},
    {"arp -s", "ip neigh add", "Add static ARP"},
    {"arp -g", "ip neigh show", "Same as -a"},
    {"arp -v", "ip -v neigh", "Verbose"},
    {"arp -n", "ip neigh", "Numeric"},
    {"arp -i", "ip neigh show dev", "Interface"},
    {"getmac", "ip link show", "Get MAC address"},
    {"getmac /v", "ip -d link show", "Verbose MAC info"},
    {"getmac /fo", "ip -o link show", "Formatted output"},
    {"getmac /nh", "ip link | grep -v ^$", "No header"},
    {"hostname", "hostname", "Show hostname"},
    {"hostname /f", "hostname -f", "FQDN hostname"},
    {"hostname /s", "hostname -s", "Short hostname"},
    {"hostname /i", "hostname -i", "IP address"},
    {"nbtstat", "nmblookup", "NetBIOS stats"},
    {"nbtstat -a", "nmblookup -A", "Adapter status"},
    {"nbtstat -c", "nmblookup -c", "Cache"},
    {"nbtstat -n", "nmblookup -n", "Local names"},
    {"nbtstat -r", "nmblookup -r", "Resolved names"},
    {"nbtstat -R", "nmblookup -R", "Reload cache"},
    {"nbtstat -S", "nmblookup -S", "Sessions"},
    {"nbtstat -s", "nmblookup -s", "Statistics"},
    {"netsh", "ip", "Network shell"},
    {"netsh interface", "ip link", "Network interface"},
    {"netsh interface show", "ip link show", "Show interfaces"},
    {"netsh interface set", "ip link set", "Set interface"},
    {"netsh interface add", "ip link add", "Add interface"},
    {"netsh interface delete", "ip link del", "Delete interface"},
    {"netsh interface ipv4", "ip -4", "IPv4 interface"},
    {"netsh interface ipv6", "ip -6", "IPv6 interface"},
    {"netsh interface portproxy", "iptables -t nat", "Port proxy"},
    {"netsh interface ipv6 add v6v4tunnel", "ip -6 tunnel add", "IPv6 tunnel"},
    {"netsh interface ipv6 add route", "ip -6 route add", "IPv6 route"},
    {"netsh interface tcp", "sysctl net.ipv4.tcp", "TCP settings"},
    {"netsh interface tcp set", "sysctl -w", "Set TCP"},
    {"netsh interface tcp show", "sysctl net.ipv4.tcp", "Show TCP"},
    {"netsh interface udp", "sysctl net.ipv4.udp", "UDP settings"},
    {"netsh winsock", "ss -l", "Winsock"},
    {"netsh winsock reset", "netplan apply", "Reset winsock"},
    {"netsh http", "curl", "HTTP"},
    {"netsh http show", "ss -tuln", "Show HTTP"},
    {"netsh http add", "iptables -A INPUT", "Add HTTP urlacl"},
    {"netsh http delete", "iptables -D INPUT", "Delete HTTP urlacl"},
    {"netsh http flush", "iptables -F INPUT", "Flush HTTP"},
    {"netsh dnsclient", "resolvectl", "DNS client"},
    {"netsh dnsclient show", "resolvectl status", "Show DNS"},
    {"netsh dnsclient add", "resolvectl dns", "Add DNS"},
    {"netsh dnsclient delete", "resolvectl revert", "Delete DNS"},
    {"netsh dnsclient flush", "resolvectl flush-caches", "Flush DNS"},
    {"netsh advfirewall", "iptables", "Advanced firewall"},
    {"netsh advfirewall show", "iptables -L", "Show firewall"},
    {"netsh advfirewall set", "iptables", "Set firewall"},
    {"netsh advfirewall add", "iptables -A", "Add rule"},
    {"netsh advfirewall delete", "iptables -D", "Delete rule"},
    {"netsh advfirewall export", "iptables-save", "Export rules"},
    {"netsh advfirewall import", "iptables-restore", "Import rules"},
    {"netsh advfirewall reset", "iptables -F", "Reset firewall"},
    {"netsh advfirewall set allprofiles", "iptables", "Set all profiles"},
    {"netsh advfirewall show allprofiles", "iptables -L", "Show all profiles"},
    {"netsh advfirewall firewall add rule", "iptables -A", "Add firewall rule"},
    {"netsh advfirewall firewall delete rule", "iptables -D", "Delete firewall rule"},
    {"netsh advfirewall firewall show rule", "iptables -L", "Show firewall rule"},
    {"netsh advfirewall firewall set rule", "iptables -R", "Set firewall rule"},
    {"netsh advfirewall monitor", "conntrack -L", "Monitor firewall"},
    {"netsh advfirewall monitor show", "conntrack -L", "Show connections"},
    {"netsh advfirewall consec", "iptables -A", "Connection security"},
    {"netsh advfirewall consec show", "iptables -L", "Show connection security"},
    {"netsh advfirewall consec add", "iptables -A", "Add connection security"},
    {"netsh advfirewall consec delete", "iptables -D", "Delete connection security"},
    {"netsh firewall", "iptables", "Firewall"},
    {"netsh firewall show", "iptables -L", "Show firewall"},
    {"netsh firewall set", "iptables", "Set firewall"},
    {"netsh firewall add", "iptables -A", "Add firewall rule"},
    {"netsh firewall delete", "iptables -D", "Delete firewall rule"},
    {"netsh firewall reset", "iptables -F", "Reset firewall"},
    {"netsh trace", "tcpdump", "Network trace"},
    {"netsh trace start", "tcpdump -w", "Start trace"},
    {"netsh trace stop", "killall tcpdump", "Stop trace"},
    {"ftp", "ftp", "FTP client"},
    {"ftp -s", "ftp -n <", "FTP script"},
    {"ftp -v", "ftp -v", "Verbose FTP"},
    {"ftp -n", "ftp -n", "No auto-login"},
    {"ftp -i", "ftp -i", "No interactive"},
    {"ftp -d", "ftp -d", "Debug FTP"},
    {"ftp -g", "ftp -g", "No globbing"},
    {"telnet", "telnet", "Telnet client"},
    {"telnet -l", "telnet -l", "Login user"},
    {"telnet -a", "telnet -a", "Automatic login"},
    {"telnet -f", "telnet -f", "Log to file"},
    {"tftp", "tftp", "TFTP client"},
    {"tftp -i", "tftp -b", "Binary mode"},
    {"tftp -b", "tftp -b", "Block size"},
    {"tftp -v", "tftp -v", "Verbose TFTP"},
    {"rcp", "scp", "Remote copy"},
    {"rcp -r", "scp -r", "Recursive copy"},
    {"rcp -p", "scp -p", "Preserve permissions"},
    {"rcp -a", "scp -r", "Archive mode"},
    {"rexec", "ssh", "Remote execute"},
    {"rexec -a", "ssh -A", "Agent forwarding"},
    {"rexec -l", "ssh -l", "Login name"},
    {"rsh", "ssh", "Remote shell"},
    {"rsh -l", "ssh -l", "Remote shell login"},
    {"rsh -n", "ssh -n", "Null input"},
    {"finger", "finger", "Finger protocol"},
    {"finger -l", "finger -l", "Long format"},
    {"finger -p", "finger -p", "No plan"},
    {"finger -s", "finger -s", "Short format"},
    {"whois", "whois", "Whois query"},
    {"whois -h", "whois -h", "Whois host"},
    {"whois -p", "whois -p", "Whois port"},
    {"nsupdate", "nsupdate", "Dynamic DNS update"},
    {"nsupdate -l", "nsupdate -l", "Local update"},
    {"nsupdate -v", "nsupdate -v", "Verbose update"},
    {"nmap", "nmap", "Network mapper"},
    {"nmap -sS", "nmap -sS", "SYN scan"},
    {"nmap -sT", "nmap -sT", "TCP scan"},
    {"nmap -sU", "nmap -sU", "UDP scan"},
    {"nmap -Pn", "nmap -Pn", "No ping"},
    {"nmap -A", "nmap -A", "Aggressive scan"},
    {"nmap -O", "nmap -O", "OS detection"},
    {"nmap -sV", "nmap -sV", "Version detection"},
    {"nmap -p", "nmap -p", "Port scan"},
    {"nmap -F", "nmap -F", "Fast scan"},
    {"nmap -T", "nmap -T", "Timing"},
    {"nmap -iL", "nmap -iL", "Input list"},
    {"nmap -oN", "nmap -oN", "Normal output"},
    {"nmap -oX", "nmap -oX", "XML output"},
    {"nmap -oG", "nmap -oG", "Grepable output"},
    {"nmap -sP", "nmap -sn", "Ping scan"},
    {"nmap -PR", "nmap -PR", "ARP ping"},
    {"nmap -PS", "nmap -PS", "TCP SYN ping"},
    {"nmap -PA", "nmap -PA", "TCP ACK ping"},
    {"nmap -PU", "nmap -PU", "UDP ping"},
    {"nmap -PE", "nmap -PE", "ICMP echo"},
    {"nmap -PP", "nmap -PP", "ICMP timestamp"},
    {"nmap -PM", "nmap -PM", "ICMP netmask"},
    {"nmap -PO", "nmap -PO", "IP protocol ping"},
    {"nmap -n", "nmap -n", "No DNS"},
    {"nmap -R", "nmap -R", "Reverse DNS"},
    {"nmap -6", "nmap -6", "IPv6"},
    {"nmap -4", "nmap -4", "IPv4"},
    {"nmap -S", "nmap -S", "Source spoof"},
    {"nmap -e", "nmap -e", "Interface"},
    {"nmap -g", "nmap -g", "Source port"},
    {"nmap --source-port", "nmap --source-port", "Source port"},
    {"nmap -f", "nmap -f", "Fragment"},
    {"nmap -mtu", "nmap -mtu", "MTU"},
    {"nmap -D", "nmap -D", "Decoy"},
    {"nmap -S", "nmap -S", "Source"},
    {"nmap -g", "nmap -g", "Port"},
    {"nmap -f", "nmap -f", "Frag"},
    {"nmap --scanflags", "nmap --scanflags", "Scan flags"},
    {"nmap -sZ", "nmap -sZ", "SCTP scan"},
    {"wget", "wget", "Web get"},
    {"wget -O", "wget -O", "Output file"},
    {"wget -P", "wget -P", "Directory prefix"},
    {"wget -q", "wget -q", "Quiet"},
    {"wget -v", "wget -v", "Verbose"},
    {"wget -c", "wget -c", "Continue download"},
    {"wget -r", "wget -r", "Recursive download"},
    {"wget -np", "wget -np", "No parent"},
    {"wget -nc", "wget -nc", "No clobber"},
    {"wget -nd", "wget -nd", "No directories"},
    {"wget -N", "wget -N", "Timestamping"},
    {"wget -S", "wget -S", "Server response"},
    {"wget -T", "wget -T", "Timeout"},
    {"wget -w", "wget -w", "Wait"},
    {"wget -Y", "wget -Y", "Proxy"},
    {"wget --no-proxy", "wget --no-proxy", "No proxy"},
    {"wget --proxy", "wget --proxy", "Proxy"},
    {"wget --proxy-user", "wget --proxy-user", "Proxy user"},
    {"wget --proxy-password", "wget --proxy-password", "Proxy password"},
    {"wget -A", "wget -A", "Accept"},
    {"wget -R", "wget -R", "Reject"},
    {"wget -I", "wget -I", "Include"},
    {"wget -X", "wget -X", "Exclude"},
    {"wget -D", "wget -D", "Domains"},
    {"wget -H", "wget -H", "Span hosts"},
    {"wget -L", "wget -L", "Relative"},
    {"wget -k", "wget -k", "Convert links"},
    {"wget -p", "wget -p", "Page requisites"},
    {"wget --convert-links", "wget --convert-links", "Convert links"},
    {"wget --adjust-extension", "wget --adjust-extension", "Adjust ext"},
    {"wget --page-requisites", "wget --page-requisites", "Page reqs"},
    {"wget --no-clobber", "wget --no-clobber", "No clobber"},
    {"wget --random-wait", "wget --random-wait", "Random wait"},
    {"wget --waitretry", "wget --waitretry", "Wait retry"},
    {"wget --retry-connrefused", "wget --retry-connrefused", "Retry refused"},
    {"wget --user", "wget --user", "User"},
    {"wget --password", "wget --password", "Password"},
    {"wget --no-check-certificate", "wget --no-check-certificate", "No check"},
    {"wget --certificate", "wget --certificate", "Certificate"},
    {"wget --private-key", "wget --private-key", "Private key"},
    {"wget --ca-certificate", "wget --ca-certificate", "CA cert"},
    {"wget --ca-directory", "wget --ca-directory", "CA dir"},
    {"wget --random-file", "wget --random-file", "Random file"},
    {"wget --egd-file", "wget --egd-file", "EGD file"},
    {"curl", "curl", "cURL"},
    {"curl -O", "curl -O", "Remote name"},
    {"curl -o", "curl -o", "Output file"},
    {"curl -L", "curl -L", "Follow redirects"},
    {"curl -s", "curl -s", "Silent"},
    {"curl -v", "curl -v", "Verbose"},
    {"curl -I", "curl -I", "Headers only"},
    {"curl -k", "curl -k", "Insecure"},
    {"curl -u", "curl -u", "User authentication"},
    {"curl -X", "curl -X", "Custom method"},
    {"curl -d", "curl -d", "POST data"},
    {"curl -H", "curl -H", "Custom header"},
    {"curl -A", "curl -A", "User agent"},
    {"curl -e", "curl -e", "Referer"},
    {"curl -x", "curl -x", "Proxy"},
    {"curl --resolve", "curl --resolve", "Resolve"},
    {"curl --connect-timeout", "curl --connect-timeout", "Timeout"},
    {"curl --max-time", "curl --max-time", "Max time"},
    {"curl --retry", "curl --retry", "Retry"},
    {"curl --retry-delay", "curl --retry-delay", "Retry delay"},
    {"curl --retry-max-time", "curl --retry-max-time", "Max retry time"},
    {"curl -w", "curl -w", "Write-out"},
    {"curl --trace", "curl --trace", "Trace"},
    {"curl --trace-ascii", "curl --trace-ascii", "ASCII trace"},
    {"curl --trace-time", "curl --trace-time", "Trace time"},
    {"curl --cookie", "curl --cookie", "Cookie"},
    {"curl --cookie-jar", "curl --cookie-jar", "Cookie jar"},
    {"curl --data-binary", "curl --data-binary", "Binary data"},
    {"curl --data-urlencode", "curl --data-urlencode", "URL encode"},
    {"curl --form", "curl --form", "Form data"},
    {"curl --form-string", "curl --form-string", "Form string"},
    {"curl --compressed", "curl --compressed", "Compressed"},
    {"curl --referer", "curl --referer", "Referer"},
    {"curl --user-agent", "curl --user-agent", "User agent"},
    {"curl --ftp-pasv", "curl --ftp-pasv", "FTP PASV"},
    {"curl --ftp-port", "curl --ftp-port", "FTP PORT"},
    {"curl --ftp-skip-pasv-ip", "curl --ftp-skip-pasv-ip", "Skip PASV IP"},
    {"curl --ftp-ssl", "curl --ftp-ssl", "FTP SSL"},
    {"curl --ssl", "curl --ssl", "SSL"},
    {"curl --sslv2", "curl --sslv2", "SSLv2"},
    {"curl --sslv3", "curl --sslv3", "SSLv3"},
    {"curl --tlsv1", "curl --tlsv1", "TLSv1"},
    {"curl --tlsv1.0", "curl --tlsv1.0", "TLSv1.0"},
    {"curl --tlsv1.1", "curl --tlsv1.1", "TLSv1.1"},
    {"curl --tlsv1.2", "curl --tlsv1.2", "TLSv1.2"},
    {"curl --tlsv1.3", "curl --tlsv1.3", "TLSv1.3"},
    {"curl --socks4", "curl --socks4", "SOCKS4"},
    {"curl --socks4a", "curl --socks4a", "SOCKS4A"},
    {"curl --socks5", "curl --socks5", "SOCKS5"},
    {"curl --socks5-hostname", "curl --socks5-hostname", "SOCKS5 hostname"},
    {"curl --socks5-gssapi", "curl --socks5-gssapi", "SOCKS5 GSSAPI"},
    {"curl --socks5-gssapi-service", "curl --socks5-gssapi-service", "SOCKS5 service"},
    {"curl --socks5-gssapi-nec", "curl --socks5-gssapi-nec", "SOCKS5 NEC"},
    {"curl -K", "curl -K", "Config file"},
    {"curl --config", "curl --config", "Config"},
    {"curl -Q", "curl -Q", "Quote command"},
    {"curl --quote", "curl --quote", "Quote"},
    {"curl -0", "curl -0", "HTTP/1.0"},
    {"curl --http1.0", "curl --http1.0", "HTTP/1.0"},
    {"curl --http1.1", "curl --http1.1", "HTTP/1.1"},
    {"curl --http2", "curl --http2", "HTTP/2"},
    {"curl --http3", "curl --http3", "HTTP/3"},
    {"curl --version", "curl --version", "Version"},
    {"curl --libcurl", "curl --libcurl", "Libcurl"},
    {"curl --limit-rate", "curl --limit-rate", "Limit rate"},
    {"curl --max-filesize", "curl --max-filesize", "Max filesize"},
    {"curl --max-redirs", "curl --max-redirs", "Max redirects"},
    {"curl --post301", "curl --post301", "POST 301"},
    {"curl --post302", "curl --post302", "POST 302"},
    {"curl --post303", "curl --post303", "POST 303"},
    {"curl --ftp-ssl-reqd", "curl --ftp-ssl-reqd", "FTP SSL required"},
    {"curl --ftp-ssl-control", "curl --ftp-ssl-control", "FTP SSL control"},
    {"curl --ftp-ssl-ccc", "curl --ftp-ssl-ccc", "FTP SSL CCC"},
    {"curl --ftp-ssl-ccc-mode", "curl --ftp-ssl-ccc-mode", "FTP SSL CCC mode"},
    {"curl --ssl-reqd", "curl --ssl-reqd", "SSL required"},
    {"curl --ssl-allow-beast", "curl --ssl-allow-beast", "SSL allow BEAST"},
    {"curl --ssl-no-revoke", "curl --ssl-no-revoke", "SSL no revoke"},
    {"curl --crlfile", "curl --crlfile", "CRL file"},
    {"curl --ciphers", "curl --ciphers", "Ciphers"},
    {"curl --digest", "curl --digest", "Digest auth"},
    {"curl --negotiate", "curl --negotiate", "Negotiate auth"},
    {"curl --ntlm", "curl --ntlm", "NTLM auth"},
    {"curl --ntlm-wb", "curl --ntlm-wb", "NTLM web"},
    {"curl --aws-sigv4", "curl --aws-sigv4", "AWS SIGv4"},
    {"curl --haproxy-protocol", "curl --haproxy-protocol", "HAProxy protocol"},
    {"curl --haproxy-clientip", "curl --haproxy-clientip", "HAProxy client IP"},
    {"curl --hsts", "curl --hsts", "HSTS"},
    {"curl --hsts-file", "curl --hsts-file", "HSTS file"},
    {"curl --proto", "curl --proto", "Protocol"},
    {"curl --proto-default", "curl --proto-default", "Default protocol"},
    {"curl --proto-redir", "curl --proto-redir", "Redirect protocol"},
    {"curl --http2-prior-knowledge", "curl --http2-prior-knowledge", "HTTP2 prior"},
    {"curl --http3-only", "curl --http3-only", "HTTP3 only"},
    {"curl --abstract-unix-socket", "curl --abstract-unix-socket", "Abstract socket"},
    {"curl --unix-socket", "curl --unix-socket", "Unix socket"},
    {"curl --local-port", "curl --local-port", "Local port"},
    {"curl --doh-url", "curl --doh-url", "DoH URL"},
    {"curl --doh-insecure", "curl --doh-insecure", "DoH insecure"},
    {"curl --alt-svc", "curl --alt-svc", "Alt-Svc"},
    {"curl --ech", "curl --ech", "ECH"},
    {"scp", "scp", "Secure copy"},
    {"scp -r", "scp -r", "Recursive copy"},
    {"scp -p", "scp -p", "Preserve times"},
    {"scp -q", "scp -q", "Quiet"},
    {"scp -v", "scp -v", "Verbose"},
    {"scp -P", "scp -P", "Port"},
    {"scp -i", "scp -i", "Identity file"},
    {"scp -B", "scp -B", "Batch mode"},
    {"scp -C", "scp -C", "Compression"},
    {"scp -F", "scp -F", "Config file"},
    {"scp -J", "scp -J", "Jump host"},
    {"scp -l", "scp -l", "Limit"},
    {"scp -o", "scp -o", "Option"},
    {"scp -S", "scp -S", "Program"},
    {"sftp", "sftp", "Secure FTP"},
    {"sftp -b", "sftp -b", "Batch"},
    {"sftp -v", "sftp -v", "Verbose"},
    {"sftp -P", "sftp -P", "Port"},
    {"sftp -C", "sftp -C", "Compression"},
    {"sftp -D", "sftp -D", "Sftp server"},
    {"sftp -F", "sftp -F", "Config file"},
    {"sftp -I", "sftp -I", "Interactive"},
    {"sftp -J", "sftp -J", "Jump host"},
    {"sftp -o", "sftp -o", "Option"},
    {"sftp -R", "sftp -R", "Requests"},
    {"sftp -S", "sftp -S", "Program"},
    {"ssh", "ssh", "Secure shell"},
    {"ssh -p", "ssh -p", "Port"},
    {"ssh -v", "ssh -v", "Verbose"},
    {"ssh -i", "ssh -i", "Identity"},
    {"ssh -l", "ssh -l", "Login"},
    {"ssh -X", "ssh -X", "X11 forwarding"},
    {"ssh -Y", "ssh -Y", "Trusted X11"},
    {"ssh -A", "ssh -A", "Agent forwarding"},
    {"ssh -t", "ssh -t", "Force TTY"},
    {"ssh -T", "ssh -T", "Disable TTY"},
    {"ssh -o", "ssh -o", "Option"},
    {"ssh -C", "ssh -C", "Compression"},
    {"ssh -N", "ssh -N", "No command"},
    {"ssh -f", "ssh -f", "Background"},
    {"ssh -L", "ssh -L", "Local forward"},
    {"ssh -R", "ssh -R", "Remote forward"},
    {"ssh -D", "ssh -D", "Dynamic forward"},
    {"ssh -J", "ssh -J", "Jump host"},
    {"ssh -b", "ssh -b", "Bind address"},
    {"ssh -c", "ssh -c", "Cipher"},
    {"ssh -m", "ssh -m", "MAC"},
    {"ssh -s", "ssh -s", "Subsystem"},
    {"ssh -w", "ssh -w", "Tunnel"},
    {"ssh -E", "ssh -E", "Log file"},
    {"ssh -F", "ssh -F", "Config file"},
    {"ssh -G", "ssh -G", "Config dump"},
    {"ssh -O", "ssh -O", "Control"},
    {"ssh -Q", "ssh -Q", "Query"},
    {"ssh key", "ssh-keygen", "Key generation"},
    {"ssh-keygen", "ssh-keygen", "Key generation"},
    {"ssh-keygen -t", "ssh-keygen -t", "Key type"},
    {"ssh-keygen -b", "ssh-keygen -b", "Key bits"},
    {"ssh-keygen -f", "ssh-keygen -f", "Key file"},
    {"ssh-keygen -C", "ssh-keygen -C", "Comment"},
    {"ssh-copy-id", "ssh-copy-id", "Copy key"},
    {"ssh-agent", "ssh-agent", "SSH agent"},
    {"ssh-add", "ssh-add", "Add key to agent"},
    {"ssh-keyscan", "ssh-keyscan", "Scan host keys"},
    {"ssh-keyscan -t", "ssh-keyscan -t", "Key type"},
    {"ssh-keyscan -p", "ssh-keyscan -p", "Port"},
    {"ssh-keyscan -f", "ssh-keyscan -f", "File"},
    {"ssh-keyscan -v", "ssh-keyscan -v", "Verbose"},
    {"ssh-keyscan -4", "ssh-keyscan -4", "IPv4"},
    {"ssh-keyscan -6", "ssh-keyscan -6", "IPv6"},
    {"ssh-keygen -l", "ssh-keygen -l", "Fingerprint"},
    {"ssh-keygen -F", "ssh-keygen -F", "Find host"},
    {"ssh-keygen -R", "ssh-keygen -R", "Remove host"},
    {"ssh-keygen -y", "ssh-keygen -y", "Read private"},
    {"ssh-keygen -c", "ssh-keygen -c", "Change comment"},
    {"ssh-keygen -B", "ssh-keygen -B", "Bubble wrap"},
    {"ssh-keygen -D", "ssh-keygen -D", "Download"},
    {"ssh-keygen -U", "ssh-keygen -U", "Upload"},
    {"ssh-keygen -r", "ssh-keygen -r", "Hash"},
    {"ssh-keygen -G", "ssh-keygen -G", "Generate candidates"},
    {"ssh-keygen -T", "ssh-keygen -T", "Test candidates"},
    {"ssh-keygen -M", "ssh-keygen -M", "Memory"},
    {"ssh-keygen -S", "ssh-keygen -S", "Start"},
    {"ssh-keygen -j", "ssh-keygen -j", "Screen"},
    {"ssh-keygen -J", "ssh-keygen -J", "Num lines"},
    {"ssh-keygen -j", "ssh-keygen -j", "Screen"},
    {"ssh-keygen -v", "ssh-keygen -v", "Verbose"},
    {"ssh-add -l", "ssh-add -l", "List keys"},
    {"ssh-add -L", "ssh-add -L", "List public"},
    {"ssh-add -d", "ssh-add -d", "Delete key"},
    {"ssh-add -D", "ssh-add -D", "Delete all"},
    {"ssh-add -x", "ssh-add -x", "Lock"},
    {"ssh-add -X", "ssh-add -X", "Unlock"},
    {"ssh-add -t", "ssh-add -t", "Lifetime"},
    {"ssh-add -c", "ssh-add -c", "Confirm"},
    {"ssh-add -s", "ssh-add -s", "Add from smartcard"},
    {"ssh-add -e", "ssh-add -e", "Remove from smartcard"},
    {"ssh-agent -a", "ssh-agent -a", "Bind"},
    {"ssh-agent -k", "ssh-agent -k", "Kill"},
    {"ssh-agent -s", "ssh-agent -s", "Shell"},
    {"ssh-agent -c", "ssh-agent -c", "Csh"},
    {"ssh-agent -d", "ssh-agent -d", "Debug"},
    {"ssh-agent -D", "ssh-agent -D", "Foreground"},
    {"ssh-agent -t", "ssh-agent -t", "Lifetime"},
    
    // Printing
    {"print", "lp", "Print file"},
    {"print /d", "lp -d", "Print to device"},
    {"lpr", "lpr", "Print file"},
    {"lpr -P", "lpr -P", "Print to printer"},
    {"lpr -#", "lpr -#", "Number of copies"},
    {"lpr -r", "lpr -r", "Remove file after print"},
    {"lpq", "lpq", "Print queue"},
    {"lpq -P", "lpq -P", "Queue for printer"},
    {"lpq -l", "lpq -l", "Long queue"},
    {"lprm", "lprm", "Remove print job"},
    {"lprm -P", "lprm -P", "Remove from printer"},
    {"lprm -", "lprm -", "Remove all jobs"},
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
    {"cupsfilter", "cupsfilter", "CUPS filter"},
    {"cupsd", "cupsd", "CUPS daemon"},
    {"cupsd -f", "cupsd -f", "Foreground"},
    {"cupsd -c", "cupsd -c", "Config file"},
    {"cupsd -t", "cupsd -t", "Test config"},
    {"cupsd -h", "cupsd -h", "Help"},
    {"cups-browsed", "cups-browsed", "CUPS browsing"},
    {"cups-browsed -d", "cups-browsed -d", "Debug"},
    {"cups-browsed -v", "cups-browsed -v", "Verbose"},
    
    // Batch & Scripting
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
    {"doskey /bufsize", "export HISTSIZE", "Buffer size"},
    {"echo", "echo", "Print text"},
    {"echo on", "set -x", "Echo on"},
    {"echo off", "set +x", "Echo off"},
    {"echo /?", "help echo", "Echo help"},
    {"echo.", "echo", "Empty line"},
    {"for", "for", "Loop command"},
    {"for %i in", "for i in", "Loop variable"},
    {"for /f", "while read", "File parsing loop"},
    {"for /f \"tokens=*\"", "while IFS= read", "Read entire line"},
    {"for /f \"delims=\"", "while IFS= read", "Read with delimiters"},
    {"for /f \"skip=\"", "tail -n +", "Skip lines"},
    {"for /f \"eol=\"", "grep -v", "End of line"},
    {"for /r", "find", "Recursive loop"},
    {"for /l", "for i in {1..10}", "Numeric loop"},
    {"for /d", "for i in */", "Directory loop"},
    {"for /d /r", "find -type d", "Recursive directory loop"},
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
    {"if /lss", "if [ -lt", "If less than"},
    {"if /leq", "if [ -le", "If less or equal"},
    {"if /equ", "if [ -eq", "If equal"},
    {"if /neq", "if [ -ne", "If not equal"},
    {"if /gtr", "if [ -gt", "If greater"},
    {"if /geq", "if [ -ge", "If greater or equal"},
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
    {"exit", "exit", "Exit shell"},
    {"exit /b", "exit", "Exit batch"},
    {"exit /?", "help exit", "Exit help"},
    
    // System File Checker (NO DISM/apt)
    {"sfc", "debsums || md5sum -c", "System file checker"},
    {"sfc /scannow", "debsums -c", "Scan now"},
    {"sfc /verifyfile", "debsums", "Verify file"},
    {"sfc /scanfile", "debsums -s", "Scan file"},
    {"sfc /offbootdir", "md5sum --root", "Offline boot dir"},
    {"sfc /offwindir", "md5sum --root", "Offline win dir"},
    {"dism", "fpmt", "DISM tool"},
    {"dism /online", "fpmt", "Online repair"},
    {"dism /image", "fpmt --root", "Image repair"},
    {"dism /cleanup-image", "fpmt clean", "Cleanup image"},
    {"dism /restorehealth", "fpmt reinstall", "Restore health"},
    {"dism /scanhealth", "fpmt verify", "Scan health"},
    {"dism /checkhealth", "fpmt check", "Check health"},
    
    // PowerShell Equivalents (EXPANDED, NO apt/systemctl)
    {"Get-ChildItem", "ls", "List items"},
    {"Get-Content", "cat", "Get content"},
    {"Set-Content", "echo >", "Set content"},
    {"Add-Content", "echo >>", "Add content"},
    {"Clear-Content", "truncate", "Clear content"},
    {"Copy-Item", "cp", "Copy item"},
    {"Move-Item", "mv", "Move item"},
    {"Remove-Item", "rm", "Remove item"},
    {"Get-Process", "ps aux", "Get processes"},
    {"Stop-Process", "kill", "Stop process"},
    {"Wait-Process", "wait", "Wait process"},
    {"Debug-Process", "gdb attach", "Debug process"},
    {"Get-Service", "service --status-all", "Get services"},
    {"Start-Service", "service start", "Start service"},
    {"Stop-Service", "service stop", "Stop service"},
    {"Restart-Service", "service restart", "Restart service"},
    {"Suspend-Service", "kill -STOP", "Suspend service"},
    {"Resume-Service", "kill -CONT", "Resume service"},
    {"Set-Service", "chkconfig", "Set service"},
    {"Get-Command", "which -a", "Get command"},
    {"Get-Help", "man", "Get help"},
    {"Clear-Host", "clear", "Clear screen"},
    {"Get-Date", "date", "Get date"},
    {"Set-Date", "date -s", "Set date"},
    {"Get-Item", "ls -d", "Get item"},
    {"Get-ItemProperty", "lsattr", "Get item property"},
    {"Set-ItemProperty", "chattr", "Set item property"},
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
    {"Get-Content -Tail", "tail", "Tail content"},
    {"Get-Content -Wait", "tail -f", "Wait for content"},
    {"Get-ChildItem -Path", "ls", "List items"},
    {"Get-ChildItem -Filter", "ls | grep", "Filter items"},
    {"Get-ChildItem -Recurse", "ls -R", "Recurse"},
    {"Get-ChildItem -Force", "ls -a", "Show hidden"},
    {"Get-ChildItem -Attributes", "lsattr", "Attributes"},
    {"Get-Item -Force", "ls -la", "Force item"},
    {"Get-Item -Stream", "lsattr", "Streams"},
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
    {"Get-ChildItem -Recurse -File", "find -type f", "Find files"},
    {"Get-ChildItem -Recurse -Directory", "find -type d", "Find directories"},
    {"Get-ChildItem -Hidden", "ls -d .*/", "Hidden files"},
    {"Get-ChildItem -System", "ls -l", "System files"},
    {"Get-ChildItem -Archive", "ls -l", "Archive files"},
    {"Get-ChildItem -ReadOnly", "ls -l", "Read-only files"},
    {"Get-ChildItem -Compressed", "lsattr", "Compressed files"},
    {"Get-ChildItem -Encrypted", "lsattr", "Encrypted files"},
    {"Get-WmiObject", "lshw", "Get WMI object"},
    {"Get-CimInstance", "dmidecode", "Get CIM instance"},
    {"Invoke-Command", "ssh command", "Remote command"},
    {"Enter-PSSession", "ssh", "Enter remote session"},
    {"Exit-PSSession", "exit", "Exit remote session"},
    {"Get-Job", "jobs", "Get background jobs"},
    {"Receive-Job", "jobs -l", "Receive job output"},
    {"Remove-Job", "kill %job", "Remove job"},
    {"Start-Job", "command &", "Start background job"},
    {"Stop-Job", "kill %job", "Stop job"},
    {"Wait-Job", "wait %job", "Wait for job"},
    {"Suspend-Job", "kill -STOP %job", "Suspend job"},
    {"Resume-Job", "kill -CONT %job", "Resume job"},
    {"Get-Module", "lsmod", "Get modules"},
    {"Import-Module", "modprobe", "Import module"},
    {"Remove-Module", "rmmod", "Remove module"},
    {"Get-Variable", "set", "Get variables"},
    {"Set-Variable", "export", "Set variable"},
    {"Clear-Variable", "unset", "Clear variable"},
    {"Remove-Variable", "unset", "Remove variable"},
    {"Get-Alias", "alias", "Get aliases"},
    {"Set-Alias", "alias name=command", "Set alias"},
    {"Export-Alias", "alias > file", "Export aliases"},
    {"Import-Alias", "source file", "Import aliases"},
    {"Get-History", "history", "Command history"},
    {"Add-History", "history -s", "Add to history"},
    {"Clear-History", "history -c", "Clear history"},
    {"Invoke-History", "!number", "Run history item"},
    {"Get-EventLog", "tail -f /var/log/syslog", "Get event log"},
    {"Clear-EventLog", "truncate -s 0 /var/log/syslog", "Clear event log"},
    {"Write-EventLog", "logger", "Write event log"},
    {"Limit-EventLog", "logrotate", "Limit event log"},
    {"Show-EventLog", "tail -f /var/log/syslog", "Show event log"},
    {"Get-Service", "service --status-all", "Get services"},
    {"New-Service", "update-rc.d", "Create service"},
    {"Remove-Service", "update-rc.d remove", "Remove service"},
    {"Restart-Service", "service restart", "Restart service"},
    {"Suspend-Service", "kill -STOP", "Suspend service"},
    {"Resume-Service", "kill -CONT", "Resume service"},
    {"Set-Service", "chkconfig", "Set service"},
    {"Get-Process", "ps aux", "Get processes"},
    {"Stop-Process", "kill -9", "Stop process"},
    {"Wait-Process", "wait", "Wait for process"},
    {"Debug-Process", "gdb attach", "Debug process"},
    {"Get-NetIPConfiguration", "ip a", "Get network config"},
    {"Get-NetIPAddress", "ip addr show", "Get IP addresses"},
    {"Get-NetRoute", "ip route show", "Get routes"},
    {"New-NetRoute", "ip route add", "Add route"},
    {"Remove-NetRoute", "ip route del", "Remove route"},
    {"Test-NetConnection", "ping && ss -tuln", "Test connectivity"},
    {"Get-NetFirewallRule", "iptables -L", "Get firewall rules"},
    {"New-NetFirewallRule", "iptables -A", "Add firewall rule"},
    {"Remove-NetFirewallRule", "iptables -D", "Remove firewall rule"},
    {"Enable-NetFirewallRule", "iptables -I", "Enable firewall rule"},
    {"Disable-NetFirewallRule", "iptables -D", "Disable firewall rule"},
    {"Get-ItemProperty", "lsattr", "Get file attributes"},
    {"Set-ItemProperty", "chattr", "Set file attributes"},
    {"Test-Connection", "ping", "Test connection"},
    {"Convert-Path", "realpath", "Convert path"},
    {"Join-Path", "realpath -m", "Join paths"},
    {"Resolve-Path", "readlink -f", "Resolve path"},
    {"Get-Content -Tail", "tail", "Tail file"},
    {"Get-Content -Wait", "tail -f", "Follow file"},
    {"Write-Output", "echo", "Write output"},
    {"Write-Host", "echo", "Write to host"},
    {"Write-Error", "echo 'Error:' >&2", "Write error"},
    {"Write-Warning", "echo 'Warning:' >&2", "Write warning"},
    {"Write-Debug", "echo 'Debug:' >&2", "Write debug"},
    {"Write-Verbose", "echo 'Verbose:'", "Write verbose"},
    {"Write-Information", "echo 'Info:'", "Write information"},
    {"Out-File", ">", "Output to file"},
    {"Out-Null", "> /dev/null", "Output to null"},
    {"Out-String", "cat", "Output to string"},
    {"Out-GridView", "column -t", "Output to grid"},
    {"ConvertTo-Json", "jq -R", "Convert to JSON"},
    {"ConvertFrom-Json", "jq .", "Convert from JSON"},
    {"ConvertTo-Csv", "csvtool", "Convert to CSV"},
    {"ConvertFrom-Csv", "csvtool", "Convert from CSV"},
    {"ConvertTo-Html", "lynx -dump", "Convert to HTML"},
    {"Export-Csv", ">", "Export CSV"},
    {"Import-Csv", "<", "Import CSV"},
    {"Select-Object", "awk", "Select object"},
    {"Where-Object", "grep", "Filter object"},
    {"Sort-Object", "sort", "Sort object"},
    {"Group-Object", "uniq -c", "Group object"},
    {"Measure-Object", "wc", "Measure object"},
    {"Format-Table", "column -t", "Format table"},
    {"Format-List", "column -l", "Format list"},
    {"Format-Wide", "column -w", "Format wide"},
    {"Format-Custom", "column -c", "Format custom"},
    {"Select-String", "grep", "Select string"},
    {"ForEach-Object", "for", "For each object"},
    {"Tee-Object", "tee", "Tee object"},
    {"Compare-Object", "diff", "Compare object"},
    {"New-Object", "new", "New object"},
    {"Get-Member", "type", "Get member"},
    {"Add-Member", "echo", "Add member"},
    {"Set-Member", "echo", "Set member"},
    {"Remove-Member", "echo", "Remove member"},
    {"Invoke-Expression", "eval", "Invoke expression"},
    {"Invoke-Item", "xdg-open", "Invoke item"},
    {"Start-Process", "nohup", "Start process"},
    {"Stop-Process", "kill", "Stop process"},
    {"Get-ItemProperty", "lsattr", "Get property"},
    {"Set-ItemProperty", "chattr", "Set property"},
    {"Clear-ItemProperty", "chattr -r", "Clear property"},
    {"Remove-ItemProperty", "chattr -d", "Remove property"},
    {"New-ItemProperty", "chattr +", "New property"},
    {"Rename-ItemProperty", "chattr -r", "Rename property"},
    {"Move-ItemProperty", "chattr -m", "Move property"},
    {"Copy-ItemProperty", "chattr -c", "Copy property"},
    {"Get-Property", "lsattr", "Get property"},
    {"Set-Property", "chattr", "Set property"},
    {"Test-ItemProperty", "lsattr", "Test property"},
    {"Get-ACL", "getfacl", "Get ACL"},
    {"Set-ACL", "setfacl", "Set ACL"},
    {"Remove-ACL", "setfacl -x", "Remove ACL"},
    {"Get-PfxCertificate", "openssl pkcs12", "Get PFX cert"},
    {"Get-Credential", "sudo -A", "Get credential"},
    {"Get-Culture", "locale", "Get culture"},
    {"Set-Culture", "locale-gen", "Set culture"},
    {"Get-UICulture", "echo $LANG", "Get UI culture"},
    {"Get-Random", "shuf", "Get random"},
    {"Set-Random", "shuf", "Set random"},
    {"Get-Unique", "uniq", "Get unique"},
    {"Select-Unique", "uniq -u", "Select unique"},
    {"Get-Sort", "sort", "Get sort"},
    {"Set-Sort", "sort", "Set sort"},
    {"Get-Content -Raw", "cat -A", "Raw content"},
    {"Set-Content -Raw", "cat >", "Raw set"},
    {"Add-Content -Raw", "cat >>", "Raw add"},
    {"Clear-Content -Raw", "truncate", "Raw clear"},
    {"Get-PSSnapin", "echo 'PSSnapin not applicable'", "Get PS snapin"},
    {"Add-PSSnapin", "echo 'PSSnapin not applicable'", "Add PS snapin"},
    {"Remove-PSSnapin", "echo 'PSSnapin not applicable'", "Remove PS snapin"},
    {"Get-PSSession", "echo 'PSSession not applicable'", "Get PS session"},
    {"New-PSSession", "ssh", "New PS session"},
    {"Remove-PSSession", "exit", "Remove PS session"},
    {"Enter-PSSession", "ssh", "Enter PS session"},
    {"Exit-PSSession", "exit", "Exit PS session"},
    {"Receive-PSSession", "echo 'PSSession not applicable'", "Receive PS session"},
    {"Disconnect-PSSession", "exit", "Disconnect PS session"},
    {"Connect-PSSession", "ssh", "Connect PS session"},
    {"Export-PSSession", "echo 'PSSession not applicable'", "Export PS session"},
    {"Import-PSSession", "echo 'PSSession not applicable'", "Import PS session"},
    {"Invoke-Command", "ssh", "Invoke command"},
    {"Enable-PSRemoting", "echo 'PSRemoting not applicable'", "Enable PS remoting"},
    {"Disable-PSRemoting", "echo 'PSRemoting not applicable'", "Disable PS remoting"},
    {"Test-WSMan", "echo 'WSMan not applicable'", "Test WSMan"},
    {"Connect-WSMan", "echo 'WSMan not applicable'", "Connect WSMan"},
    {"Disconnect-WSMan", "echo 'WSMan not applicable'", "Disconnect WSMan"},
    {"Get-WSManCredSSP", "echo 'WSMan not applicable'", "Get WSMan CredSSP"},
    {"Set-WSManCredSSP", "echo 'WSMan not applicable'", "Set WSMan CredSSP"},
    {"Disable-WSManCredSSP", "echo 'WSMan not applicable'", "Disable WSMan CredSSP"},
    {"Enable-WSManCredSSP", "echo 'WSMan not applicable'", "Enable WSMan CredSSP"},
    {"New-WSManSessionOption", "echo 'WSMan not applicable'", "New WSMan session option"},
    {"Get-WSManInstance", "echo 'WSMan not applicable'", "Get WSMan instance"},
    {"Set-WSManInstance", "echo 'WSMan not applicable'", "Set WSMan instance"},
    {"Invoke-WSManAction", "echo 'WSMan not applicable'", "Invoke WSMan action"},
    {"Remove-WSManInstance", "echo 'WSMan not applicable'", "Remove WSMan instance"},
    
    // Security & Firewall
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
    {"gpresult /v", "getfacl", "Verbose"},
    {"gpresult /x", "getfacl", "XML report"},
    {"gpresult /scope", "getfacl", "Scope"},
    {"gpresult /user", "getfacl -u", "User policy"},
    {"gpresult /computer", "getfacl -c", "Computer policy"},
    {"gpupdate", "echo 'Policy updated'", "Group policy update"},
    {"gpupdate /force", "echo 'Policy forced'", "Force update"},
    {"gpupdate /target", "echo 'Target updated'", "Targeted update"},
    {"gpupdate /logoff", "echo 'Logoff required'", "Logoff after update"},
    {"gpupdate /boot", "echo 'Reboot required'", "Reboot after update"},
    {"secedit", "visudo", "Security configuration"},
    {"secedit /export", "visudo -c >", "Export security config"},
    {"secedit /import", "visudo -f", "Import security config"},
    {"secedit /configure", "visudo", "Configure security"},
    {"secedit /validate", "visudo -c", "Validate config"},
    {"secedit /db", "visudo -f", "Security database"},
    {"secedit /log", "visudo -c >", "Security log"},
    {"secedit /areas", "visudo", "Security areas"},
    {"icacls", "setfacl", "ICACLS"},
    {"icacls /grant", "setfacl -m u", "Grant"},
    {"icacls /deny", "setfacl -m u", "Deny"},
    {"icacls /remove", "setfacl -x", "Remove"},
    {"icacls /remove:a", "setfacl -x", "Remove all"},
    {"icacls /inheritance", "setfacl -n", "Inheritance"},
    {"icacls /reset", "setfacl -b", "Reset"},
    {"icacls /replace", "setfacl -m", "Replace"},
    {"icacls /substitute", "setfacl -m", "Substitute"},
    {"icacls /restore", "setfacl --restore", "Restore"},
    {"icacls /save", "getfacl >", "Save ACL"},
    {"icacls /verify", "getfacl --verify", "Verify ACL"},
    {"cacls", "chmod", "CACLS"},
    {"cacls /e", "chmod", "Edit"},
    {"cacls /t", "chmod -R", "Tree"},
    {"cacls /c", "chmod --continue", "Continue"},
    {"cacls /g", "chmod", "Grant"},
    {"cacls /r", "chmod", "Revoke"},
    {"cacls /p", "chmod", "Replace"},
    {"cacls /d", "chmod", "Deny"},
    
    // Miscellaneous (FINAL EXPANSION)
    {"color", "echo -e", "Change colors"},
    {"color /?", "help echo", "Color help"},
    {"color 0a", "echo -e '\\033[32m'", "Green text"},
    {"color 0b", "echo -e '\\033[34m'", "Blue text"},
    {"color 0c", "echo -e '\\033[31m'", "Red text"},
    {"color 0d", "echo -e '\\033[35m'", "Purple text"},
    {"color 0e", "echo -e '\\033[33m'", "Yellow text"},
    {"color 0f", "echo -e '\\033[37m'", "White text"},
    {"color 1a", "echo -e '\\033[42;30m'", "Green background"},
    {"color 1b", "echo -e '\\033[44;30m'", "Blue background"},
    {"color 1c", "echo -e '\\033[41;30m'", "Red background"},
    {"color 1d", "echo -e '\\033[45;30m'", "Purple background"},
    {"color 1e", "echo -e '\\033[43;30m'", "Yellow background"},
    {"color 1f", "echo -e '\\033[47;30m'", "White background"},
    {"date", "date", "Show date"},
    {"date /t", "date +%D", "Date only"},
    {"date /d", "date -d", "Set date"},
    {"date /?", "date --help", "Date help"},
    {"time", "date +%T", "Show time"},
    {"time /t", "date +%T", "Time only"},
    {"time /s", "date -s", "Set time"},
    {"time /?", "date --help", "Time help"},
    {"title", "echo -ne '\\033]0;'", "Set title"},
    {"title /?", "help echo", "Title help"},
    {"prompt", "PS1=", "Change prompt"},
    {"prompt $p$g", "export PS1='\\w>'", "Prompt format"},
    {"prompt /?", "help PS1", "Prompt help"},
    {"prompt $$", "export PS1='$$'", "PID prompt"},
    {"prompt $t", "export PS1='\\t'", "Time prompt"},
    {"prompt $d", "export PS1='\\d'", "Date prompt"},
    {"prompt $v", "export PS1='\\v'", "Version prompt"},
    {"prompt $g", "export PS1='>'", "Greater than prompt"},
    {"prompt $l", "export PS1='<'", "Less than prompt"},
    {"prompt $b", "export PS1='|'", "Pipe prompt"},
    {"prompt $_", "export PS1='\\n'", "Newline prompt"},
    {"prompt $e", "export PS1='\\e'", "Escape prompt"},
    {"prompt $h", "export PS1='\\b'", "Backspace prompt"},
    {"prompt $a", "export PS1='&'", "Ampersand prompt"},
    {"prompt $c", "export PS1='('", "Left paren prompt"},
    {"prompt $f", "export PS1=')'", "Right paren prompt"},
    {"prompt $s", "export PS1=' '", "Space prompt"},
    {"verifier", "verify", "Driver verifier"},
    {"verifier /standard", "verify standard", "Standard verifier"},
    {"verifier /all", "verify all", "All drivers"},
    {"verifier /reset", "verify reset", "Reset verifier"},
    {"verifier /query", "verify query", "Query verifier"},
    {"verifier /volatile", "verify volatile", "Volatile settings"},
    {"verifier /log", "verify log", "Log verifier"},
    {"verifier /driver", "verify driver", "Driver"},
    {"verifier /flags", "verify flags", "Flags"},
    {"verifier /rule", "verify rule", "Rule"},
    {"verifier /standard", "verify standard", "Standard"},
    {"verifier /querysettings", "verify query", "Query settings"},
    {"vol", "df -h", "Volume info"},
    {"vol /?", "df --help", "Volume help"},
    {"assoc", "file", "File associations"},
    {"assoc .txt", "file -i", "Text association"},
    {"assoc .log", "file -i", "Log association"},
    {"ftype", "xdg-mime", "File types"},
    {"ftype txtfile", "xdg-mime query", "Text file type"},
    {"ftype logfile", "xdg-mime query", "Log file type"},
    {"ftype /?", "xdg-mime --help", "Ftype help"},
    {"assoc /?", "file --help", "Assoc help"},
    {"mode", "stty", "Set device mode"},
    {"mode con", "stty", "Console mode"},
    {"mode con cols", "stty cols", "Set columns"},
    {"mode con lines", "stty rows", "Set lines"},
    {"mode con rate", "stty speed", "Set rate"},
    {"mode con delay", "stty", "Set delay"},
    {"mode lpt", "stty", "Printer mode"},
    {"mode com", "stty", "COM port mode"},
    {"mode /status", "stty -a", "Status"},
    {"mode /?", "stty --help", "Mode help"},
    {"print", "lp", "Print file"},
    {"print /d", "lp -d", "Print to device"},
    {"recover", "ddrescue", "Recover files"},
    {"recover /?", "ddrescue --help", "Recover help"},
    {"replace", "mv -f", "Replace files"},
    {"replace /a", "cp -n", "Add files"},
    {"replace /p", "mv -i", "Prompt replace"},
    {"replace /r", "mv -f", "Replace read-only"},
    {"replace /w", "mv -w", "Wait replace"},
    {"replace /s", "mv -r", "Replace subdirs"},
    {"replace /u", "mv -u", "Replace newer only"},
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
    {"sysdm.cpl", "sysctl", "System properties"},
    {"intl.cpl", "localectl", "Regional settings"},
    {"timedate.cpl", "timedatectl", "Date/time settings"},
    {"ncpa.cpl", "nmtui", "Network settings"},
    {"desk.cpl", "xrandr", "Display settings"},
    {"main.cpl", "sysctl", "Main control panel"},
    {"mmsys.cpl", "alsamixer", "Multimedia"},
    {"joy.cpl", "jstest", "Joystick"},
    {"inetcpl.cpl", "networkctl", "Internet properties"},
    {"firewall.cpl", "iptables", "Firewall"},
    {"odbccp32.cpl", "odbcinst", "ODBC"},
    {"powercfg.cpl", "powertop", "Power settings"},
    {"telephon.cpl", "modem-manager", "Telephony"},
    {"sticpl.cpl", "scanimage -L", "Scanners"},
    {"wscui.cpl", "firewall-cmd", "Security center"},
    {"appwiz.cpl", "fpmt list", "Programs and features"},
    {"hdwwiz.cpl", "lshw", "Hardware wizard"},
    {"irprops.cpl", "bluetoothctl", "Infrared"},
    {"access.cpl", "xkbset", "Accessibility"},
    {"sysdm.cpl", "echo 'System properties'", "System panel"},
    {"dccw.cpl", "xcalib", "Display color"},
    {"desk.cpl", "xrandr", "Display properties"},
    {"main.cpl keyboard", "setxkbmap", "Keyboard panel"},
    {"main.cpl mouse", "xinput", "Mouse panel"},
    {"inetcpl.cpl", "networkctl", "Internet panel"},
    {"mmsys.cpl sounds", "alsamixer", "Sounds panel"},
    {"ncpa.cpl", "nmtui", "Network panel"},
    {"powercfg.cpl", "powertop", "Power panel"},
    {"sysdm.cpl", "sysctl", "System panel"},
    {"timedate.cpl", "timedatectl", "Date/time panel"},
    {"desk", "xrandr", "Desktop settings"},
    {"control", "gnome-control-center", "Control Panel"},
    {"control /name Microsoft.WindowsUpdate", "fpmt update", "Windows Update"},
    {"control /name Microsoft.NetworkAndSharing", "nmtui", "Network"},
    {"control /name Microsoft.PowerOptions", "powertop", "Power"},
    {"control /name Microsoft.System", "inxi -F", "System"},
    {"control /name Microsoft.ProgramsAndFeatures", "fpmt list", "Programs"},
    {"control /name Microsoft.DeviceManager", "lshw", "Device Manager"},
    {"control /name Microsoft.Fonts", "fc-list", "Fonts"},
    {"control /name Microsoft.DateAndTime", "timedatectl", "Date/Time"},
    {"control /name Microsoft.Region", "localectl", "Region"},
    {"control /name Microsoft.Keyboard", "setxkbmap", "Keyboard"},
    {"control /name Microsoft.Mouse", "xinput", "Mouse"},
    {"control /name Microsoft.Sound", "alsamixer", "Sound"},
    {"control /name Microsoft.DevicesAndPrinters", "system-config-printer", "Printers"},
    {"control /name Microsoft.ColorManagement", "colormgr", "Color"},
    {"control /name Microsoft.InternetOptions", "networkctl", "Internet"},
    {"control /name Microsoft.SecurityCenter", "firewall-cmd", "Security"},
    {"control /name Microsoft.TaskbarAndStartMenu", "gnome-tweaks", "Taskbar"},
    {"control /name Microsoft.FolderOptions", "nautilus", "Folder Options"},
    {"control /name Microsoft.UserAccounts", "vipw", "User Accounts"},
    {"control admintools", "sudo -i", "Admin Tools"},
    {"control schedtasks", "crontab -e", "Scheduled Tasks"},
    {"control netconnections", "nmtui", "Network Connections"},
    {"control printers", "system-config-printer", "Printers"},
    {"control folders", "nautilus", "Folder options"},
    {"control desktop", "gnome-control-center display", "Desktop settings"},
    {"control keyboard", "gnome-control-center keyboard", "Keyboard settings"},
    {"control mouse", "gnome-control-center mouse", "Mouse settings"},
    {"control printers", "system-config-printer", "Printer settings"},
    {"control userpasswords", "gnome-control-center user-accounts", "User accounts"},
    {"control userpasswords2", "sudo passwd", "User passwords"},
    {"control admintools", "sudo -i", "Admin tools"},
    {"control schedtasks", "crontab -e", "Scheduled tasks"},
    {"control netconnections", "nmtui", "Network connections"},
    {"control telephony", "modem-manager", "Telephony"},
    {"control intl.cpl", "gnome-control-center region", "International"},
    {"control timedate.cpl", "gnome-control-center datetime", "Date/Time"},
    {"control ncpa.cpl", "gnome-control-center network", "Network"},
    {"control powercfg.cpl", "gnome-control-center power", "Power"},
    {"control mmsys.cpl", "gnome-control-center sound", "Sound"},
    {"control desk.cpl", "gnome-control-center display", "Display"},
    {"control appwiz.cpl", "gnome-software", "Programs"},
    {"control sysdm.cpl", "gnome-control-center info", "System"},
    {"control firewall.cpl", "gufw", "Firewall"},
    {"control inetcpl.cpl", "firefox about:preferences", "Internet"},
    {"control joy.cpl", "gnome-control-center joysticks", "Joystick"},
    {"control main.cpl", "gnome-control-center", "Main Control Panel"},
    {"control access.cpl", "gnome-control-center accessibility", "Accessibility"},
    {"control telephon.cpl", "gnome-control-center modem", "Telephony"},
    {"control powercfg.cpl", "gnome-control-center power", "Power"},
    {"control sticpl.cpl", "gnome-control-center scanners", "Scanners"},
    {"control wscui.cpl", "gnome-control-center security", "Security"},
    {"control odbc", "odbcinst", "ODBC"},
    
    // Power Management
    {"powercfg", "powertop", "Power configuration"},
    {"powercfg /list", "powertop --html", "List power schemes"},
    {"powercfg /query", "powertop --dump", "Query power scheme"},
    {"powercfg /change", "powertop --calibrate", "Change setting"},
    {"powercfg /changename", "powertop", "Change scheme name"},
    {"powercfg /create", "powertop", "Create scheme"},
    {"powercfg /delete", "powertop", "Delete scheme"},
    {"powercfg /setactive", "powertop --auto-tune", "Set active"},
    {"powercfg /getactivescheme", "powertop", "Get active scheme"},
    {"powercfg /setdcvalueindex", "powertop", "Set DC value"},
    {"powercfg /setacvalueindex", "powertop", "Set AC value"},
    {"powercfg /hibernate", "systemctl hibernate", "Hibernate"},
    {"powercfg /devicequery", "powertop", "Device query"},
    {"powercfg /deviceenablewake", "powertop", "Enable wake"},
    {"powercfg /devicedisablewake", "powertop", "Disable wake"},
    {"powercfg /globalpowerflag", "powertop", "Global flag"},
    {"powercfg /energy", "powertop --calibrate", "Energy report"},
    {"powercfg /batteryreport", "upower -i", "Battery report"},
    {"powercfg /sleepstudy", "echo 'Sleep study not applicable'", "Sleep study"},
    {"powercfg /srumutil", "echo 'SRUM not applicable'", "SRUM utility"},
    {"powercfg /systemsleepdiagnostics", "journalctl -b", "Sleep diagnostics"},
    {"powercfg /systempowerreport", "powertop --html", "Power report"},
    {"powercfg /setsecuritydescriptor", "echo 'Security descriptor not applicable'", "Set SD"},
    {"powercfg /getsecuritydescriptor", "echo 'Security descriptor not applicable'", "Get SD"},
    {"powercfg /aliases", "powertop --help", "Aliases"},
    {"powercfg /wake", "echo 'Wake on LAN'", "Wake timers"},
    {"powercfg /requests", "echo 'Power requests not applicable'", "Power requests"},
    {"powercfg /requestsoverride", "echo 'Override not applicable'", "Override requests"},
    {"powercfg /lastwake", "echo 'Last wake not applicable'", "Last wake"},
    {"powercfg /waketimers", "echo 'Wake timers not applicable'", "Wake timers"},
    {"powercfg /monitor", "xset dpms", "Monitor timeout"},
    {"powercfg /disk", "hdparm -S", "Disk timeout"},
    {"powercfg /standby", "xset dpms", "Standby timeout"},
    {"powercfg /hibernate", "echo 'Hibernate'", "Hibernate timeout"},
    {"powercfg /processor", "cpufreq-set", "Processor throttle"},
    {"powercfg /cooling", "sensors", "Cooling policy"},
    {"shutdown", "shutdown -h now", "Shutdown system"},
    {"shutdown /s", "poweroff", "Shutdown"},
    {"shutdown /r", "reboot", "Restart"},
    {"shutdown /h", "systemctl hibernate", "Hibernate"},
    {"shutdown /l", "pkill -KILL -u $USER", "Log off"},
    {"shutdown /a", "shutdown -c", "Abort shutdown"},
    {"shutdown /t", "shutdown -t", "Shutdown with timeout"},
    {"shutdown /f", "shutdown -f", "Force shutdown"},
    {"shutdown /m", "ssh host shutdown", "Remote shutdown"},
    {"shutdown /c", "shutdown -k", "Comment"},
    {"shutdown /p", "poweroff", "Power off"},
    {"shutdown /hybrid", "pm-hibernate", "Hybrid shutdown"},
    {"shutdown /e", "echo 'Document reason'", "Document shutdown"},
    {"shutdown /o", "echo 'Advanced boot options'", "Advanced boot"},
    {"shutdown /fw", "echo 'Firmware menu'", "Firmware boot"},
    {"shutdown /s /t 0", "poweroff", "Immediate shutdown"},
    {"shutdown /r /t 0", "reboot", "Immediate restart"},
    {"shutdown /h /t 0", "systemctl hibernate", "Immediate hibernate"},
    {"logoff", "pkill -KILL -u $USER", "Log off user"},
    {"logoff /f", "pkill -9 -u $USER", "Force logoff"},
    {"shtdwn", "shutdown", "Legacy shutdown"},
    {"tsshutdn", "shutdown", "Terminal Services shutdown"},
    {"slui", "echo 'License activation not applicable'", "Software Licensing UI"},
    
    // Time & Date
    {"time", "date +%T", "Show time"},
    {"time /t", "date +%T", "Time only"},
    {"time /s", "date -s", "Set time"},
    {"date", "date", "Show date"},
    {"date /t", "date +%D", "Date only"},
    {"date /d", "date -d", "Set date"},
    {"timedate.cpl", "gnome-control-center datetime", "Date/Time control panel"},
    {"w32tm", "chronyc", "Windows Time"},
    {"w32tm /query", "chronyc sources", "Query time source"},
    {"w32tm /config", "chronyc sourcestats", "Configure time"},
    {"w32tm /resync", "chronyc -a makestep", "Resynchronize"},
    {"w32tm /stripchart", "chronyc tracking", "Display statistics"},
    {"w32tm /monitor", "chronyc activity", "Monitor time servers"},
    {"w32tm /ntte", "date +%s", "NT time epoch"},
    {"w32tm /ntpte", "date -d @", "NTP time epoch"},
    {"w32tm /register", "echo 'Time service registered'", "Register service"},
    {"w32tm /unregister", "echo 'Time service unregistered'", "Unregister service"},
    {"w32tm /debug", "chronyc -v", "Debug time"},
    {"w32tm /trace", "chronyc -t", "Trace time"},
    {"w32tm /tz", "timedatectl", "Time zone"},
    {"w32tm /dumpreg", "timedatectl show", "Dump registry"},
    {"tzutil", "timedatectl", "Time zone utility"},
    {"tzutil /s", "timedatectl set-timezone", "Set time zone"},
    {"tzutil /g", "timedatectl", "Get time zone"},
    {"tzutil /l", "timedatectl list-timezones", "List time zones"},
    
    // Performance & Monitoring
    {"perfmon", "perf top || nmon || atop", "Performance Monitor"},
    {"perfmon /sys", "perf stat", "System performance"},
    {"perfmon /report", "perf report", "Performance report"},
    {"perfmon /res", "perf stat -a", "Resource view"},
    {"perfmon /rel", "perf stat --no-merge", "Reliability"},
    {"resmon", "btop || htop || glances", "Resource Monitor"},
    {"resmon /?", "btop --help", "Resource help"},
    {"resmon /perf", "perf stat", "Performance"},
    {"resmon /mem", "free -h", "Memory"},
    {"resmon /disk", "iostat", "Disk"},
    {"resmon /net", "ss -i", "Network"},
    {"resmon /cpu", "mpstat", "CPU"},
    {"typeperf", "perf stat", "Performance counters"},
    {"typeperf /?", "perf --help", "Typeperf help"},
    {"logman", "perf record", "Log manager"},
    {"logman create", "perf record -o", "Create log"},
    {"logman query", "perf script", "Query log"},
    {"logman start", "perf record", "Start log"},
    {"logman stop", "killall perf", "Stop log"},
    {"logman delete", "rm perf.data", "Delete log"},
    {"logman update", "perf record", "Update log"},
    {"logman import", "perf import", "Import log"},
    {"logman export", "perf archive", "Export log"},
    {"tracelog", "trace-cmd", "Trace logging"},
    {"tracelog -start", "trace-cmd start", "Start trace"},
    {"tracelog -stop", "trace-cmd stop", "Stop trace"},
    {"tracelog -enable", "trace-cmd enable", "Enable trace"},
    {"tracelog -disable", "trace-cmd disable", "Disable trace"},
    {"tracelog -flush", "trace-cmd extract", "Flush trace"},
    {"wpr", "perf record", "Windows Performance Recorder"},
    {"wpr -start", "perf record -e", "Start recording"},
    {"wpr -stop", "perf report", "Stop recording"},
    {"wpr -cancel", "rm perf.data", "Cancel recording"},
    {"wpr -profile", "perf record -p", "Profile"},
    {"wpr -profiles", "perf list", "List profiles"},
    {"xperf", "perf", "Xperf tool"},
    {"xperf -on", "perf record -e", "Turn on"},
    {"xperf -off", "perf report", "Turn off"},
    {"xperf -start", "perf record", "Start"},
    {"xperf -stop", "perf report", "Stop"},
    {"xperf -flush", "perf script", "Flush"},
    {"adplus", "gdb -p", "Debug process"},
    {"adplus -hang", "gdb -p", "Hang mode"},
    {"adplus -crash", "gdb -p", "Crash mode"},
    {"adplus -quiet", "gdb -p -q", "Quiet mode"},
    {"gflags", "sysctl", "Global flags editor"},
    {"gflags /p", "sysctl -p", "Process flag"},
    {"gflags /r", "sysctl", "Registry flag"},
    {"gflags /k", "sysctl", "Kernel flag"},
    {"gflags /i", "sysctl", "Image flag"},
    {"poolmon", "slabtop", "Memory pool monitor"},
    {"poolmon /g", "slabtop -s", "Poolmon with GUI"},
    {"poolmon /t", "slabtop -o", "Poolmon TSS"},
    {"poolmon /s", "slabtop -s", "Poolmon seconds"},
    {"poolmon /c", "slabtop", "Poolmon continuous"},
    {"poolmon /a", "slabtop -a", "Poolmon all"},
    {"poolmon /n", "slabtop -n", "Poolmon no totals"},
    {"poolmon /b", "slabtop -b", "Poolmon by bytes"},
    {"rammap", "smem", "RAM mapping tool"},
    {"rammap /?", "smem --help", "RAM help"},
    {"rammap /et", "smem -t", "Empty working sets"},
    {"rammap /er", "smem -r", "Process working sets"},
    {"rammap /es", "smem -s", "System working sets"},
    {"rammap /eb", "smem -b", "Process bytes"},
    {"rammap /ew", "smem -w", "Process WS"},
    {"rammap /et", "smem -T", "Physical pages"},
    {"rammap /ep", "smem -P", "Physical ranges"},
    {"rammap /ef", "smem -F", "File summary"},
    {"rammap /em", "smem -M", "File details"},
    {"vmmap", "pmap", "Virtual memory map"},
    {"vmmap /?", "pmap --help", "VM map help"},
    {"vmmap -p", "pmap -p", "VM map process"},
    {"vmmap -f", "pmap -x", "VM map file"},
    {"vmmap -o", "pmap -d", "VM map offsets"},
    {"procexp", "htop", "Process Explorer"},
    {"procexp /?", "htop --help", "Process explorer help"},
    {"procexp /t", "htop -t", "Tree view"},
    {"procexp /c", "htop -C", "CPU view"},
    {"procexp /m", "htop -M", "Memory view"},
    {"procexp /d", "htop -d", "DLL view"},
    {"procexp /h", "htop -H", "Handle view"},
    {"procexp /p", "htop -p", "Process view"},
    {"procexp /s", "htop -s", "System view"},
    {"procexp /n", "htop -n", "Network view"},
    {"procmon", "strace -p", "Process Monitor"},
    {"procmon /?", "strace --help", "Procmon help"},
    {"procmon /n", "strace -n", "Network events"},
    {"procmon /p", "strace -p", "Process events"},
    {"procmon /r", "strace -r", "Registry events"},
    {"procmon /f", "strace -f", "File events"},
    {"procmon /m", "strace -m", "Memory events"},
    {"procmon /d", "strace -d", "Debug output"},
    {"procmon /s", "strace -s", "Summary"},
    {"pagedfrg", "e4defrag", "Page defrag"},
    {"pagedfrg /?", "e4defrag --help", "Page defrag help"},
    {"pagedfrg /c", "e4defrag -c", "Consolidate"},
    {"pagedfrg /a", "e4defrag -c", "Analyze"},
    {"pagedfrg /v", "e4defrag -v", "Verbose"},
    {"pagedfrg /d", "e4defrag -d", "Defrag"},
    {"handle", "lsof -p", "Handle viewer"},
    {"handle /?", "lsof --help", "Handle help"},
    {"handle -a", "lsof -p", "All handles"},
    {"handle -c", "lsof -c", "Close handle"},
    {"handle -p", "lsof -p", "Process handles"},
    {"handle -n", "lsof -n", "No network"},
    {"handle -s", "lsof -s", "System handles"},
    {"handle -u", "lsof -u", "User handles"},
    {"handle -y", "lsof -y", "Type handles"},
    {"handle -f", "lsof -f", "File handles"},
    {"tcpview", "ss -tp", "TCP connection viewer"},
    {"tcpview /?", "ss --help", "TCP view help"},
    {"tcpview -c", "ss -c", "Continuous"},
    {"tcpview -n", "ss -n", "Numeric"},
    {"tcpview -p", "ss -p", "Process"},
    {"tcpview -s", "ss -s", "Summary"},
    {"tcpview -t", "ss -t", "TCP only"},
    {"tcpview -u", "ss -u", "UDP only"},
    {"tcpview -w", "ss -w", "Windows"},
    {"tcpview -x", "ss -x", "Unix"},
    {"tcpview -l", "ss -l", "Listening"},
    {"tcpview -a", "ss -a", "All"},
    {"tcpview -r", "ss -r", "Routing"},
    {"tcpview -i", "ss -i", "Info"},
    {"tcpview -m", "ss -m", "Memory"},
    
    // DOSKEY Macros & Common Usage
    {"dir /s", "find . -type f", "Recursive dir"},
    {"dir /s/b", "find . -type f -print", "Recursive bare list"},
    {"dir /s/b/a:d", "find . -type d -print", "Recursive dir list"},
    {"dir /o-s", "ls -lSr", "Sort size descending"},
    {"dir /o-d", "ls -ltr", "Sort date descending"},
    {"dir /a:h", "ls -ld .*/", "Hidden files only"},
    {"dir /a:-h", "ls -d */", "Non-hidden only"},
    {"dir /t:w/o-d", "ls -lt", "Last write time"},
    {"dir /t:a/o-d", "ls -ltu", "Last access time"},
    {"dir /t:c/o-d", "ls -ltc", "Creation time"},
    {"tree /f > file.txt", "find . > file.txt", "Tree to file"},
    {"tree /a > file.txt", "find . -type f > file.txt", "ASCII tree to file"},
    {"mem /c", "free -h", "Condense prog list"},
    {"mem /d", "free -h", "Device status"},
    {"mem /f", "free -h", "Free memory"},
    {"mem /m", "free -h", "Module usage"},
    {"mem /p", "free -h", "Pause after each"},
    {"mem /s", "free -h", "Summary only"},
    {"ipconfig | findstr IPv4", "ip a | grep inet", "IPv4 only"},
    {"netstat -ano | findstr", "ss -tulnp | grep", "Netstat with filter"},
    {"tasklist /fi", "ps aux | grep", "Tasklist filter"},
    {"driverquery /v", "modinfo", "Verbose drivers"},
    {"systeminfo | findstr", "inxi -F | grep", "System info filter"},
    {"wmic process list brief", "ps -ef", "Brief process list"},
    {"wmic qfe list", "fpmt list --updates", "Installed updates"},
    {"wmic startup list", "ls /etc/rc*.d/", "Startup items"},
    {"wmic printer list", "lpstat -p", "Printers"},
    {"wmic diskdrive list", "lsblk", "Disk drives"},
    {"wmic logicaldisk list", "df -h", "Logical disks"},
    {"wmic volume list", "lsblk -f", "Volumes"},
    {"wmic share list", "exportfs -v", "Shares"},
    {"wmic service list", "service --status-all", "Services"},
    {"wmic useraccount list", "cat /etc/passwd", "User accounts"},
    {"wmic group list", "cat /etc/group", "Groups"},
    {"wmic nic list", "ip a", "Network adapters"},
    {"wmic path", "find", "WMI path"},
    {"wmic /output", ">", "WMI output"},
    {"wmic /append", ">>", "WMI append"},
    {"wmic /format", "| awk", "WMI format"},
    {"wmic /namespace", "sysfs", "WMI namespace"},
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
    {"doskey /bufsize", "export HISTSIZE", "Buffer size"},
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
    {"clip /?", "xclip --help", "Clip help"},
    {"verify", "set -e", "Verify commands"},
    {"verify on", "set -e", "Verify on"},
    {"verify off", "set +e", "Verify off"},
    {"path", "echo $PATH", "Show path"},
    {"set path", "export PATH=", "Set path"},
    {"set path=%path%;new", "export PATH=$PATH:new", "Append path"},
    {"ver", "uname -r", "Version only"},
    {"vol", "df -h", "Volume info"},
    {"label", "e2label", "Volume label"},
    {"subst", "mount --bind", "Substitute path"},
    {"subst /d", "umount", "Delete substitution"},
    
    // Final block to ensure 800+ entries
    {"empty line", "echo", "Empty placeholder"},
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

// NEW: Test parser for [[ ]] and [ ]
static int parse_and_execute_test(const char* expression) {
    // Handle [[ expression ]] or [ expression ]
    char* expr_copy = strdup(expression);
    char* saveptr;
    char* token = strtok_r(expr_copy, " ", &saveptr);
    
    // Simplified test parsing
    if (!token) return 1; // false
    
    // Handle -z, -n, -f, -d, -e, etc.
    if (strcmp(token, "-z") == 0) {
        char* next = strtok_r(NULL, " ", &saveptr);
        int result = (next && strlen(next) > 0) ? 0 : 1;
        free(expr_copy);
        return result;
    }
    if (strcmp(token, "-n") == 0) {
        char* next = strtok_r(NULL, " ", &saveptr);
        int result = (next && strlen(next) > 0) ? 1 : 0;
        free(expr_copy);
        return result;
    }
    if (strcmp(token, "-f") == 0) {
        char* next = strtok_r(NULL, " ", &saveptr);
        int result = (next && access(next, F_OK) == 0) ? 1 : 0;
        free(expr_copy);
        return result;
    }
    if (strcmp(token, "-d") == 0) {
        char* next = strtok_r(NULL, " ", &saveptr);
        struct stat st;
        int result = (next && stat(next, &st) == 0 && S_ISDIR(st.st_mode)) ? 1 : 0;
        free(expr_copy);
        return result;
    }
    
    // Handle string comparisons
    char* op = strtok_r(NULL, " ", &saveptr);
    if (op && saveptr) {
        char* right = strtok_r(NULL, " ", &saveptr);
        if (right) {
            if (strcmp(op, "=") == 0) {
                int result = strcmp(token, right) == 0;
                free(expr_copy);
                return result;
            }
            if (strcmp(op, "!=") == 0) {
                int result = strcmp(token, right) != 0;
                free(expr_copy);
                return result;
            }
        }
    }
    
    free(expr_copy);
    return 0;
}

// NEW: Command substitution $(...)
static char* expand_command_substitution(const char* input) {
    static char output[FSH_MAX_INPUT];
    char* out_ptr = output;
    const char* in_ptr = input;
    
    while (*in_ptr && out_ptr - output < FSH_MAX_INPUT - 1) {
        if (*in_ptr == '$' && *(in_ptr + 1) == '(') {
            // Found $(command)
            in_ptr += 2;
            char cmd[FSH_MAX_INPUT];
            int depth = 1;
            char* cmd_ptr = cmd;
            
            while (*in_ptr && cmd_ptr - cmd < FSH_MAX_INPUT - 1 && depth > 0) {
                if (*in_ptr == '(') depth++;
                else if (*in_ptr == ')') depth--;
                if (depth > 0) *cmd_ptr++ = *in_ptr;
                in_ptr++;
            }
            *cmd_ptr = '\0';
            
            // Execute command and capture output
            FILE* fp = popen(cmd, "r");
            if (fp) {
                char result[FSH_MAX_INPUT];
                if (fgets(result, sizeof(result), fp)) {
                    result[strcspn(result, "\n")] = 0; // Remove newline
                    strcpy(out_ptr, result);
                    out_ptr += strlen(result);
                }
                pclose(fp);
            }
        } else {
            *out_ptr++ = *in_ptr++;
        }
    }
    *out_ptr = '\0';
    return output;
}

// Variable assignment support (VAR=VAL, PS1=..., etc)
static int handle_variable_assignment(const char* line) {
    const char* eq = strchr(line, '=');
    if (!eq || eq == line) return 0;
    // Only allow if before first space
    for (const char* p = line; p < eq; ++p) {
        if (*p == ' ' || *p == '\t') return 0;
    }
    char var[256], val[FSH_MAX_INPUT];
    size_t varlen = eq - line;
    if (varlen >= sizeof(var)) return 0;
    strncpy(var, line, varlen);
    var[varlen] = '\0';
    strncpy(val, eq + 1, sizeof(val) - 1);
    val[sizeof(val) - 1] = '\0';
    setenv(var, val, 1);
    return 1;
}

// NEW: Bash PS1 prompt expansion
static char* expand_bash_prompt(const char* ps1) {
    static char prompt[FSH_MAX_INPUT];
    char* out = prompt;
    const char* in = ps1;
    
    while (*in && out - prompt < FSH_MAX_INPUT - 1) {
        if (*in == '\\' && *(in + 1)) {
            in++;
            switch (*in) {
                case 'u': strcpy(out, getenv("USER") ?: "user"); out += strlen(out); break;
                case 'h': 
                    gethostname(out, FSH_MAX_INPUT - (out - prompt)); 
                    char* dot = strchr(out, '.');
                    if (dot) *dot = '\0';
                    out += strlen(out);
                    break;
                case 'w': {
                    char cwd[PATH_MAX];
                    if (getcwd(cwd, sizeof(cwd))) {
                        const char* home = getenv("HOME");
                        if (home && strncmp(cwd, home, strlen(home)) == 0) {
                            sprintf(out, "~%s", cwd + strlen(home));
                        } else {
                            strcpy(out, cwd);
                        }
                        out += strlen(out);
                    }
                    break;
                }
                case 'W': {
                    char cwd[PATH_MAX];
                    if (getcwd(cwd, sizeof(cwd))) {
                        char* basename = strrchr(cwd, '/');
                        strcpy(out, basename ? basename + 1 : cwd);
                        out += strlen(out);
                    }
                    break;
                }
                case '$': *out++ = (geteuid() == 0) ? '#' : '$'; break;
                case '[': *out++ = '\033'; break; // Start non-printing
                case ']': *out++ = '\033'; break; // End non-printing
                default: *out++ = *in; break;
            }
            in++;
        } else if (*in == '$' && *(in + 1) == '{') {
            // Handle ${var} substitution
            in += 2;
            char var[256];
            char* var_ptr = var;
            while (*in && *in != '}' && var_ptr - var < 255) {
                *var_ptr++ = *in++;
            }
            *var_ptr = '\0';
            if (*in == '}') in++;
            
            const char* value = getenv(var);
            if (value) {
                strcpy(out, value);
                out += strlen(value);
            }
        } else {
            *out++ = *in++;
        }
    }
    *out = '\0';
    return prompt;
}

// NEW: Built-in case implementation
static int builtin_case(char** args) {
    // Usage: case value in pattern) commands ;; esac
    if (!args[1] || strcmp(args[1], "in") != 0) {
        fprintf(stderr, "case: invalid syntax\n");
        return 1;
    }
    
    char* value = args[0] + 5; // Skip "case" and space
    value[strlen(value) - 3] = '\0'; // Remove " in"
    
    // Simple implementation - just execute the first matching pattern
    int found = 0;
    for (int i = 2; args[i]; i++) {
        if (strcmp(args[i], "esac") == 0) break;
        
        // Check if this is a pattern
        if (strstr(args[i], ")")) {
            char* pattern = strtok(args[i], ")");
            if (fnmatch(pattern, value, 0) == 0) {
                found = 1;
                // Execute commands after ) until ;;
                while (args[++i] && strcmp(args[i], ";;") != 0) {
                    // Execute each command
                    execute_command_line(args[i]);
                }
                break;
            }
        }
    }
    
    return found ? 0 : 1;
}

// NEW: Built-in shopt implementation
static int builtin_shopt(char** args) {
    if (!args[1]) {
        printf("shopt: no option specified\n");
        return 1;
    }
    
    const char* option = args[1];
    bool current_value = false;
    
    // Map shopt options to shell_opts
    if (strcmp(option, "histappend") == 0) current_value = shell_opts.histappend;
    else if (strcmp(option, "histreedit") == 0) current_value = shell_opts.histreedit;
    else if (strcmp(option, "histverify") == 0) current_value = shell_opts.histverify;
    else if (strcmp(option, "checkwinsize") == 0) current_value = shell_opts.checkwinsize;
    else {
        printf("shopt: unknown option '%s'\n", option);
        return 1;
    }
    
    // Handle -s (set) or -u (unset)
    if (args[0][0] == '-' && args[0][1] == 's') {
        current_value = true;
    } else if (args[0][0] == '-' && args[0][1] == 'u') {
        current_value = false;
    }
    
    // Set the option
    if (strcmp(option, "histappend") == 0) shell_opts.histappend = current_value;
    else if (strcmp(option, "histreedit") == 0) shell_opts.histreedit = current_value;
    else if (strcmp(option, "histverify") == 0) shell_opts.histverify = current_value;
    else if (strcmp(option, "checkwinsize") == 0) shell_opts.checkwinsize = current_value;
    
    return 0;
}

// NEW: Built-in [ ] and [[ ]] test
static int builtin_test(char** args) {
    // Skip [ or [[
    int i = 0;
    if (strcmp(args[0], "[") == 0 || strcmp(args[0], "[[") == 0) i = 1;
    
    // Build the expression
    char expr[FSH_MAX_INPUT] = "";
    for (; args[i] && strcmp(args[i], "]") != 0 && strcmp(args[i], "]]") != 0; i++) {
        if (i > 0) strcat(expr, " ");
        strcat(expr, args[i]);
    }
    
    return parse_and_execute_test(expr) ? 0 : 1;
}

// ADD TO find_builtin() in the builtins array:
static const BuiltinCommand builtins[] = {
    // ... existing builtins ...
    {"case", builtin_case},
    {"shopt", builtin_shopt},
    {"[", builtin_test},
    {"[[", builtin_test},
    {NULL, NULL}
};

// MODIFY main() - Add PS1 expansion

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

static void load_shell_rc_file(void) {
    if (shell_opts.norc || !shell_opts.interactive) {
        return; // Don't load rc files if --norc or non-interactive
    }
    
    char rc_path[PATH_MAX];
    const char* home = getenv("HOME");
    
    if (!home) {
        fprintf(stderr, COLOR_YELLOW "Warning: HOME not set, skipping rc file\n" COLOR_RESET);
        return;
    }
    
    // Try .fshrc first (primary)
    snprintf(rc_path, sizeof(rc_path), "%s/.fshrc", home);
    if (access(rc_path, R_OK) == 0) {
        if (shell_opts.verbose || shell_opts.xtrace) {
            printf("+ loading %s\n", rc_path);
        }
        execute_command_line_from_file(rc_path);
        return;
    }
    
    // Optional: look for .fshrc in current directory
    if (access(".fshrc", R_OK) == 0) {
        if (shell_opts.verbose || shell_opts.xtrace) {
            printf("+ loading ./.fshrc\n");
        }
        execute_command_line_from_file(".fshrc");
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
        // Ignore common shell keywords and grouping tokens
    // Ignore common shell keywords and grouping tokens
    if (
        strcmp(trimmed, "{") == 0 || strcmp(trimmed, "}") == 0 ||
        strcmp(trimmed, "(") == 0 || strcmp(trimmed, ")") == 0 ||
        strcmp(trimmed, ".") == 0 || strcmp(trimmed, "fi") == 0 ||
        strcmp(trimmed, "esac") == 0 || strcmp(trimmed, "then") == 0 ||
        strcmp(trimmed, "do") == 0 || strcmp(trimmed, "done") == 0 ||
        strcmp(trimmed, "elif") == 0 || strcmp(trimmed, "else") == 0 ||
        strcmp(trimmed, ";;") == 0 ||
        strcmp(trimmed, "*)") == 0 ||
        (trimmed[0] == '*' && trimmed[1] == ')' && trimmed[2] == 0) ||
        (strlen(trimmed) > 1 && trimmed[strlen(trimmed)-1] == ')' &&
            (trimmed[0] == '*' || trimmed[0] == ')'))
    ) {
        return 0;
    }
    if (handle_variable_assignment(trimmed)) return 0;

    // Built-in: case ... in ... esac (stub)
    if (strncmp(trimmed, "case ", 5) == 0) {
        printf("[case/esac not fully supported yet]\n");
        return 0;
    }
    // Built-in: if ...; then ...; fi (stub)
    if (strncmp(trimmed, "if ", 3) == 0) {
        printf("[if/then/fi not fully supported yet]\n");
        return 0;
    }
    // Built-in: shopt stub
    if (strncmp(trimmed, "shopt", 5) == 0) {
        printf("[shopt stub: no effect]\n");
        return 0;
    }
    // Built-in: eval stub
    if (strncmp(trimmed, "eval", 4) == 0) {
        printf("[eval stub: no effect]\n");
        return 0;
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
static void execute_command_line_from_file(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, COLOR_RED "Cannot open init file: %s - %s\n" COLOR_RESET, filename, strerror(errno));
        return;
    }
    
    char line[FSH_MAX_INPUT];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip empty lines and comments
        char* trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        
        if (*trimmed == '\0' || *trimmed == '#') continue;
        
        if (shell_opts.verbose) {
            printf("+ %s\n", trimmed);
        }
        
        execute_command_line(trimmed);
        
        // Exit on error if errexit is set
        if (shell_opts.errexit && last_exit_status != 0) {
            fprintf(stderr, COLOR_RED "Init file error at line %d: command failed with status %d\n" COLOR_RESET, 
                    line_num, last_exit_status);
            break;
        }
    }
    
    fclose(fp);
}

static void cleanup_and_exit(void) {
    save_history();
    
    // Cleanup history
    for (int i = 0; i < history.count; i++) {
        free(history.commands[i]);
    }
    free(history.commands);
    
    // Cleanup command database
    cleanup_system_commands();
    
    // Exit with last command status
    exit(last_exit_status);
}

static void print_help(const char* program_name) {
    printf("Fsh - The Friendly Shell v3.3.6\n\n");
    printf("Usage: %s [options] [file]\n", program_name);
    printf("\nOptions:\n");
    printf("  -c COMMAND    Execute COMMAND and exit\n");
    printf("  --help        Show this help message\n");
    printf("  --version     Show version information\n");
    printf("  --login       Run as login shell\n");
    printf("  --noprofile   Don't load profile on login\n");
    printf("  --norc        Don't load rc file\n");
    printf("  --restricted  Run in restricted mode\n");
    printf("  --posix       POSIX mode (limited implementation)\n");
    printf("  --noediting   Disable command line editing\n");
    printf("\nShell Flags (like bash set builtin):\n");
    printf("  -a  Mark modified variables for export\n");
    printf("  -b  Notify of job termination immediately\n");
    printf("  -e  Exit immediately on non-zero status\n");
    printf("  -f  Disable filename generation (globbing)\n");
    printf("  -h  Remember command locations\n");
    printf("  -k  All assignment args go to environment\n");
    printf("  -m  Enable job control\n");
    printf("  -n  Read commands but don't execute\n");
    printf("  -u  Treat unset variables as error\n");
    printf("  -v  Print shell input lines as read\n");
    printf("  -x  Print commands and args as executed\n");
    printf("  -C  Disallow overwriting files via redirection\n");
    printf("  -H  Enable ! style history substitution\n");
    printf("\nExamples:\n");
    printf("  %s                    # Interactive shell\n", program_name);
    printf("  %s -c \"ls | grep sh\"  # Execute command\n", program_name);
    printf("  %s script.sh          # Run script file\n", program_name);
}

static int parse_o_option(const char* optname) {
    if (strcmp(optname, "allexport") == 0) shell_opts.allexport = true;
    else if (strcmp(optname, "errexit") == 0) shell_opts.errexit = true;
    else if (strcmp(optname, "noglob") == 0) shell_opts.noglob = true;
    else if (strcmp(optname, "verbose") == 0) shell_opts.verbose = true;
    else if (strcmp(optname, "xtrace") == 0) shell_opts.xtrace = true;
    else if (strcmp(optname, "nounset") == 0) shell_opts.nounset = true;
    else if (strcmp(optname, "noexec") == 0) shell_opts.noexec = true;
    else if (strcmp(optname, "history") == 0) {/* placeholder */}
    else if (strcmp(optname, "posix") == 0) shell_opts.posix = true;
    else if (strcmp(optname, "restricted") == 0) shell_opts.restricted = true;
    else {
        fprintf(stderr, COLOR_RED "Unknown option: -o %s\n" COLOR_RESET, optname);
        return 1;
    }
    return 0;
}

static void init_restricted_mode(void) {
    if (shell_opts.restricted) {
        printf("%s[Restricted mode enabled]%s\n", COLOR_YELLOW, COLOR_RESET);
        // In restricted mode, would disable:
        // - cd command
        // - Setting PATH
        // - Redirects with >
        // - exec command
        // These require more architectural changes to implement fully
    }
}

static void print_version(void) {
    printf("Fsh - The Friendly Shell v3.3.6\n");
    printf("Copyright (C) 2026 FarazOS Project\n");
}

// Banner
static void print_banner(void) {
    printf("\n╔══════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                                                                              ║\n");
    printf("║   %sFsh - The Friendly Shell v3.3.6%s                                      ║\n", COLOR_MAGENTA, COLOR_RESET);
    printf("║   %s800+ CMD | Persian UTF-8 | Pipe | &&/& | Enhanced Safety%s           ║\n", COLOR_CYAN, COLOR_RESET);
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
    // detect_distro_name(); // here is, thats function auto detect your distro name
    shell_opts.interactive = isatty(STDIN_FILENO);
    
    int opt;
    int execute_mode = 0;
    char *command_string = NULL;
    char *init_file = NULL;
    char *rc_file = NULL;
    // Support long options

    static struct option long_options[] = {
        {"debug", no_argument, 0, 1000},
        {"debugger", no_argument, 0, 1001},
        {"dump-po-strings", no_argument, 0, 1002},
        {"dump-strings", no_argument, 0, 1003},
        {"help", no_argument, 0, 'h'},
        {"init-file", required_argument, 0, 1004},
        {"login", no_argument, 0, 'l'},
        {"noediting", no_argument, 0, 1005},
        {"noprofile", no_argument, 0, 1006},
        {"norc", no_argument, 0, 1007},
        {"posix", no_argument, 0, 1008},
        {"pretty-print", no_argument, 0, 1009},
        {"rcfile", required_argument, 0, 1010},
        {"restricted", no_argument, 0, 1011},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 1012},
        {0, 0, 0, 0}
    };


    while ((opt = getopt_long(argc, argv, "+abefhkmnop:tc:tuUvxC:E:HPT", long_options, NULL)) != -1) {
        switch (opt) {
            // Short options
            case 'a': shell_opts.allexport = true; break;
            case 'b': shell_opts.notify = true; break;
            case 'c': execute_mode = 1; command_string = optarg; break;
            case 'e': shell_opts.errexit = true; break;
            case 'f': shell_opts.noglob = true; break;
            case 'h': print_help(argv[0]); return EXIT_SUCCESS;
            case 'k': shell_opts.keyword = true; break;
            case 'm': shell_opts.monitor = true; break;
            case 'n': shell_opts.noexec = true; break;
            case 'p': shell_opts.privileged = true; break;
            case 't': shell_opts.onecmd = true; break;
            case 'u': shell_opts.nounset = true; break;
            case 'v': shell_opts.verbose = true; break;
            case 'x': shell_opts.xtrace = true; break;
            case 'C': shell_opts.noclobber = true; break;
            case 'E': shell_opts.errtrace = true; break;
            case 'H': shell_opts.histexpand = true; break;
            case 'P': shell_opts.physical = true; break;
            case 'T': shell_opts.functrace = true; break;
            
            // Long options
            case 1000: printf("Debug mode: not implemented\n"); break;
            case 1001: printf("Debugger mode: not implemented\n"); break;
            case 1002: printf("Dump po strings: not implemented\n"); break;
            case 1003: printf("Dump strings: not implemented\n"); break;
            case 1004: init_file = optarg; break;
            case 'l': shell_opts.login_shell = true; break;
            case 1005: shell_opts.noediting = true; break;
            case 1006: shell_opts.noprofile = true; break;
            case 1007: shell_opts.norc = true; break;
            case 1008: shell_opts.posix = true; shell_opts.noprofile = true; shell_opts.norc = true; break;
            case 1009: printf("Pretty print: not implemented\n"); break;
            case 1010: rc_file = optarg; (void)rc_file; break;
            case 1011: shell_opts.restricted = true; break;
            case 1012: print_version(); return EXIT_SUCCESS;
            
            default:
                fprintf(stderr, COLOR_RED "Unknown option. Use --help for usage.\n" COLOR_RESET);
                return EXIT_FAILURE;
        }
    }
    init_restricted_mode();
    load_shell_rc_file();
    if (init_file && !shell_opts.noprofile) {
        if (access(init_file, R_OK) == 0) {
            execute_command_line_from_file(init_file); // Would need implementation
        }
    }


    if (execute_mode == 1 && command_string) {
        init_command_database();
        if (shell_opts.verbose) printf("+ %s\n", command_string);
        execute_command_line(command_string);
        if (shell_opts.onecmd) cleanup_and_exit();
        cleanup_system_commands();
        return last_exit_status;
    }
    
    // Script file mode
    if (optind < argc) {
        FILE* script_file = fopen(argv[optind], "r");
        if (!script_file) {
            fprintf(stderr, COLOR_RED "Cannot open script: %s\n" COLOR_RESET, argv[optind]);
            return EXIT_FAILURE;
        }
        fclose(script_file);
        // execute_script_file(argv[optind]); // Would need implementation
        return last_exit_status;
    }
    
    // Interactive mode
    if (!shell_opts.interactive) {
        // Non-interactive: read from stdin
        char input[FSH_MAX_INPUT];
        while (fgets(input, sizeof(input), stdin)) {
            execute_command_line(input);
        }
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

        // EXPANDED PROMPT with bash PS1 support
        const char* ps1 = getenv("PS1");
        if (ps1) {
            char* expanded = expand_bash_prompt(ps1);
            printf("%s", expanded);
        } else {
            printf("%s[%s@%s %s]$%s ", COLOR_GREEN, user, distro_name, cwd, COLOR_RESET);
        }
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
        if (shell_opts.xtrace) {
            printf("+ %s\n", trimmed);
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
