#include <windows.h>
#include <stdio.h>

// ---[ Shellcode Here ]---
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90 // NOP sled 
};

// ---[ target proc's PID ]---
#define TARGET_PID 0000

int main(void)
{
    // STEP 1: Open the target process
    HANDLE hProcess = NULL;
    // hProcess = OpenProcess();

    // STEP 2: Allocate memory in the remote process
    PVOID remoteAddr = NULL;
    // remoteAddr = VirtualAllocEx();

    // STEP 3: Write the shellcode
    // WriteProcessMemory();

    // STEP 4: Change memory protection to executable
    DWORD oldProtect;
    // VirtualProtectEx();

    // STEP 5: Create a remote thread to execute the shellcode
    HANDLE hThread = NULL;
    // hThread = CreateRemoteThread();

    // STEP 6: Cleanup
    // CloseHandle(hThread); 
    // CloseHandle(hProcess);

    return 0;
}
