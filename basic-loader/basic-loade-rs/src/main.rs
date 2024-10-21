use std::{
    mem::transmute,
    ptr::{self, copy},
};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        },
        Threading::{CreateThread, WaitForSingleObject, INFINITE},
    },
};

fn main() {
    let shellcode = [];

    unsafe {
        let mm_region = VirtualAlloc(
            ptr::null_mut(), // address to start allocating, null if no preferences
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE, // The allocation is effective immediatly
            PAGE_EXECUTE_READWRITE,   // memo protection flag: we can read and write to this region.
        );

        copy(shellcode.as_ptr(), mm_region as *mut u8, shellcode.len());

        let function_ptr = transmute(mm_region);

        let thread_handle = CreateThread(
            ptr::null_mut(), // optional security attribues
            0, // stack size, 0 means the default size for the executable. This can be useful if
            // you know you thread will need a bigger stack
            function_ptr, // the start point of the routine (routine means thread code here)
            ptr::null_mut(), // optional parameters for our thread
            0,            // creation flag, 0 = run immediatly
            ptr::null_mut(), // a variable to store the thread id. If null, it wont store the
                          // thread ID
        );

        // prevent the program from closing before the shellcode ends (tl;dr, parent wait for its
        // child)
        WaitForSingleObject(thread_handle, INFINITE);

        // Not sure why we free the memory. But, as it's unsafe WinAPI stuff, I accept it
        VirtualFree(mm_region, 0, MEM_RELEASE);

        CloseHandle(thread_handle);
    }
}
