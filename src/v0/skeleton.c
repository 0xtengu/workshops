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
    // STEP 1: open the target process
    HANDLE hProcess = NULL;
    // hProcess = OpenProcess();

    // STEP 2: allocate memory in the target process
    PVOID remoteAddr = NULL;
    // remoteAddr = VirtualAllocEx();

    // STEP 3: write the shellcode
    // WriteProcessMemory();

    // STEP 4: change memory protection to executable (optional)
    DWORD oldProtect;
    // VirtualProtectEx();

    // STEP 5: create a remote thread to execute the shellcode
    HANDLE hThread = NULL;
    // hThread = CreateRemoteThread();

    // STEP 6: cleanup
    // CloseHandle(hThread); 
    // CloseHandle(hProcess);

    return 0;
}
