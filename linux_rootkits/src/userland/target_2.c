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