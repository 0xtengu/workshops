#include <Windows.h>
#include <stdio.h>
#include <string.h>

int main()
{
    // 1) Allocate and copy
    PVOID heapBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);
    const char* message = "You Found Me! :D";
    size_t length = strlen(message) + 1;  // include null

    memcpy(heapBuf, message, length);

    // print heap info and dump
    printf("[INFO] HeapAlloc() returned buffer (heap region): %p\n", heapBuf);
    printf("[INFO] This is the actual runtime memory location of the buffer allocated");
    printf("\n\n[INFO] Bytes copied (including null terminator): %zu\n\n", length);

    printf("[DUMP] Heap buffer contents:\n");
    for (size_t i = 0; i < length; i++)
    {
        unsigned char byte = ((unsigned char*)heapBuf)[i];

        printf("  %p : 0x%02x  '%c'\n",
            (unsigned char*)heapBuf + i,
            byte,
            (byte >= 32 && byte < 127) ? byte : '.');
    }

    printf("\n[INFO] You have hit the breakpoint\n");
    HeapFree(GetProcessHeap(), 0, heapBuf); // <-- breakpoint here
    return 0;
}
