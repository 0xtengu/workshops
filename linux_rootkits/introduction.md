```text

  ____            _   _                                              __
 |  _ \ ___  ___ | |_(_)_ __   __ _     __ _ _ __ ___  _   _ _ __ __|  |
 | |_) / _ \/ _ \| __| | '_ \ / _` |   / _` | '__/ _ \| | | | '_ \ / _`|
 |  _ < (_) | (_) | |_| | | | | (_| | | (_| | | | (_) | |_| | | | | (_||
 |_| \_\___/ \___/ \__|_|_| |_|\__, |  \__,_|_|  \___/ \__,_|_| |_|\__,|
                               |___/   
                                  
                    A LINUX ROOTKIT WORKSHOP

==============================================================================
                            INTRODUCTION
==============================================================================

[ https://github.com/0xtengu/workshops/tree/main/linux_rootkits ]

----[ Welcome ]---------------------------------------------------------------

Welcome. This workshop is focused on getting you started building Linux Rootkits.

You will leave this workshop with:
    - Working C code 
    - A deeper understanding of Linux internals
    - Practical experience with offensive kernel techniques 
    - The ability to crash your VM :D

This is technically focused. Compilation errors, segmentation faults, and 
kernel panics are not failures here; they are part of the learning process.

> NOTE: This repository is a living document. It will be updated 
> with new techniques, fixes, and kernel compatibility updates.

----[ The Kill Chain ]--------------------------------------------------------

Where does this fit?
We are assuming **Initial Access** has already been achieved. 
This workshop focuses on persistence, privilege escalation, and 
defense evasion.

TARGET KERNEL: 6.17.10+kali-amd64 (x86_64)

----[ Curriculum ]------------------------------------------------------------

We will move from userland tricks to advanced kernel manipulation:

1. FOUNDATIONS
   Setting up the environment, compiling LKMs, and understanding kernel space.

2. USERLAND MANIPULATION
   Hijacking shared libraries with LD_PRELOAD and PLT/GOT hooks.

3. FTRACE
   Using the function tracer to hook kernel syscalls.

4. KPROBES
   Placing breakpoints on internal kernel instructions.

5. eBPF
   Modern, "safe" kernel observability turned offensive.

6. PERSISTENCE & EVASION
   Surviving reboots and scrubbing footprints.

----[ Prerequisites ]---------------------------------------------------------

This workshop assumes you are ready to get your hands dirty.

    SKILL LEVEL:
    - Intermediate C programming 
    - Comfort with the Linux CLI
    - Basic understanding of Operating System concepts (Memory, Pointers)

    ENVIRONMENT:
    - A Linux Virtual Machine [ Kali Linux Highly Recommended to Follow Along ]
    - Root/Sudo access is MANDATORY
    - Internet access (for downloading headers)

    [ !!! WARNING !!! ]
    Do NOT run this workshop on your host machine or a production server.
    We are writing code that intentionally alters system behavior at the
    lowest level. Data loss or system instability is guaranteed.
    
    ALWAYS USE A VM.

----[ Environment Setup ]-----------------------------------------------------

1. Ensure your VM is updated and you have a terminal open. 

2. Install the necessary build tools and headers:

   sudo apt update && sudo apt install -y \
   bpftool \
   clang \
   llvm \
   libbpf-dev \
   linux-tools-$(uname -r) \
   gdb \
   binutils-dev \
   build-essential \
   linux-headers-$(uname -r)

3. Verify your kernel version matches your headers:
   uname -r
   ls /usr/src/linux-headers-$(uname -r)

----[ Resources & References ]------------------------------------------------

Big thanks to every author below for sharing their fantastic work.

# Detection Tools, Rootkits, and More
    detect-lkm-rootkit-cheatsheet: https://github.com/MatheuZSecurity/detect-lkm-rootkit-cheatsheet
    nitara2: https://github.com/ksen-lin/nitara2
    ModTracer: https://github.com/MatheuZSecurity/ModTracer
    Rootkit Examples (Educational)
    MatheuZSecurity/Rootkit: https://github.com/MatheuZSecurity/Rootkit
    MatheuZSecurity/Imperius: https://github.com/MatheuZSecurity/Imperius
    Diamorphine: https://github.com/m0nad/Diamorphine
    KoviD: https://github.com/carloslack/KoviD
    blackpill: https://github.com/DualHorizon/blackpill
    sad0p/venom: https://github.com/sad0p/venom/tree/main
    Trevohack/Venom: https://github.com/Trevohack/Venom

# eBPF Resources
    eBPF Cheatsheet: https://rezaduty-1685945445294.hashnode.dev/ebpf-cheatsheet
    evilBPF: https://github.com/rphang/evilBPF
    bpfhacks: https://github.com/hackerschoice/bpfhacks
    eunomia-bpf: https://github.com/eunomia-bpf/eunomia-bpf

# Learning Resources
    xcellerator's Rootkit Series: https://xcellerator.github.io/tags/rootkit/
    Inferi Club - Linux Kernel Rootkits: https://inferi.club/post/the-art-of-linux-kernel-rootkits
    Kyntra.io - Singularity Rootkit: https://blog.kyntra.io/Singularity-A-final-boss-linux-kernel-rootkit
    Phrack Issue 71/12: https://phrack.org/issues/71/12
    LKM HACKING: http://www.ouah.org/LKM_HACKING.html
    Conviso AppSec - Hooking Syscalls: https://blog.convisoappsec.com/linux-rootkits-hooking-syscalls/
    h0mbre - Creating A Rootkit: https://h0mbre.github.io/Learn-C-By-Creating-A-Rootkit/

# Security Tools
    kernel-hardening-checker: https://github.com/a13xp0p0v/kernel-hardening-checker
    libprocesshider: https://github.com/gianlucaborello/libprocesshider
    Official Documentation
    Kernel.org - Tracing: https://www.kernel.org/doc/html/v6.5/trace/index.html
    Kernel.org - Tainted Kernels: https://docs.kernel.org/admin-guide/tainted-kernels.html
    Kernel.org - Kprobes: https://www.kernel.org/doc/html/latest/trace/kprobes.html
    Kernel.org - Ftrace: https://www.kernel.org/doc/html/latest/trace/ftrace.html

# Community
    Join the rootkit security research community: Discord: https://discord.gg/66N5ZQppU7

    MAN PAGES TO LOVE:
    * man syscalls
    * man insmod
    * man ld.so

----[ Ready? ]----------------------------------------------------------------

Open `foundations.md`. 
We begin by setting up our dev environment and compiling our first kernel module.

Good luck, and happy hacking.

... RTFM

.EOF

```
