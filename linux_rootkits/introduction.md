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

[ https://github.com/0xtengu/cc14_workshop ]

----[ Welcome ]---------------------------------------------------------------

Welcome! This workshop is focused on getting you started building Linux Rootkits!

You will leave this workshop with:
    - Working C code 
    - Using Linux internals for rootkit development
    - Practical experience with offensive techniques 
    - The ability to crash your VM :D

This is technically focused. Compilation errors, segmentation
faults, and kernel panics are not failures here; they are part of the learning
process.

# Points to consider

- Nothing here is FUD
- My goal here is to get you up and running
- Kill chain, where are we?

----[ What You Will Learn ]---------------------------------------------------

We will move from userland tricks to advanced kernel manipulation, covering:

1. FOUNDATIONS

2. USERLAND MANIPULATION

3. FTRACE

4. KPROBES

5. eBPF

6. PERSISTENCE & EVASION

----[ Prerequisites ]---------------------------------------------------------

This workshop assumes you are ready to get your hands dirty.

    SKILL LEVEL:
    * Intermediate C programming 
    * Comfort with the Linux 
    * Basic understanding of operating system concepts

    ENVIRONMENT:
    * A Linux Virtual Machine [ Kali ]
    * Root/Sudo access is MANDATORY
    * Internet access for downloading headers/packages 
            [ if not already installed ]

    WARNING:
    Do NOT run this workshop on your host machine or a production server.
    We are writing code that intentionally alters system behavior at the
    lowest level. Data loss or system instability is possible.

#   ALWAYS USE A VM    #
#   x86_64


----[ Getting Started ]-------------------------------------------------------

1. Ensure your VM is spun up and you have a terminal open. 

[ sudo apt update && sudo apt install bpftool clang llvm libbpf-dev linux-tools-$(uname -r) gdb binutils-dev build-essential linux-headers-$(uname -r) ]

2. Have the .md file(s) open

3. We begin with
    Part I: Foundations, where we will set up our dev environment and compile
    our first kernel module.

Good luck, and happy hacking.

... RTFM

.EOF
