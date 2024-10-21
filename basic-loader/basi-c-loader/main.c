#include <Windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    // define a suspicious string
    const char definitely_not_a_shellcode[] = "";

    LPVOID mm_region =
        VirtualAlloc(0, sizeof(definitely_not_a_shellcode),
                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // just checking if the allocation went ok
    if (NULL == mm_region) {
        puts("You are cooked, cause you can't alloc memory");
        return -1;
    }

    RtlCopyMemory(mm_region, definitely_not_a_shellcode,
                  sizeof(definitely_not_a_shellcode));

    // create a thread and make it run what's in our allocated memory
    DWORD thread_id;
    HANDLE thread_handle = CreateThread(
        NULL, 0, (PTHREAD_START_ROUTINE)mm_region, NULL, 0, &thread_id);

    WaitForSingleObject(thread_handle, INFINITE);
}
