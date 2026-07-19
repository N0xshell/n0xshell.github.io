---
title: "Process-Enumeration"
date: 2026-07-19 00:00:00 +0100
categories: [Malware, Development]
tags:
  - malware
  - development
---

# Process-Enumeration


## main.rs

```rust
#![allow(dead_code)]

use std::ffi::OsStr;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;

use winapi::shared::minwindef::{DWORD, FALSE, HMODULE};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::{
    EnumProcessModules,
    EnumProcesses,
    GetModuleBaseNameW,
};
use winapi::um::winnt::{HANDLE,PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};


const TARGET_PROCESS: &str = "Notepad.exe";
const MAX_PATH: usize = 260;



// Converts a normal Rust UTF-8 string into a Windows UTF-16 string.
fn to_widestring(s: &str) -> Vec<u16> {

    OsStr::new(s)
        // Convert Rust string into UTF-16 code units.
        .encode_wide()

        // Windows strings require a NULL terminator.
        .chain(std::iter::once(0))

        // Store the UTF-16 values in a vector.
        .collect()
}



// Searches all running processes for a specific executable name.
unsafe fn get_remote_process_handle(
    proc_name: &[u16],
    pid: &mut u32,
    process: &mut HANDLE,
) -> bool {


    // Buffer that receives process IDs from Windows.
    let mut processes: [u32; 2048] = [0; 2048];


    // Number of bytes actually written by EnumProcesses.
    let mut cb_needed: DWORD = 0;



    // Get all running process IDs.
    if EnumProcesses(processes.as_mut_ptr(), std::mem::size_of_val(&processes) as DWORD, &mut cb_needed) == 0 {
        println!(
            "[!] EnumProcesses failed. Error: {}",
            GetLastError()
        );

        return false;
    }



    // Convert returned bytes into number of valid PID entries.
    let num_processes =
        cb_needed / std::mem::size_of::<u32>() as DWORD;
    println!(
        "[i] Number of processes detected: {}",
        num_processes
    );



    // Loop only over the processes returned by Windows.
    for index in 0..num_processes as usize {
        let current_pid = processes[index];
        // Skip empty entries.
        if current_pid == 0 {
            continue;
        }

        // Open the process so we can query information about it.
        let h_process = OpenProcess(
            PROCESS_ALL_ACCESS,
            FALSE,
            current_pid,
        );

        // OpenProcess returns NULL on failure.
        if h_process.is_null() {
            continue;
        }

        // Stores the first module of the process.
        let mut h_module: HMODULE = null_mut();
        let mut cb_needed2: DWORD = 0;

        // Retrieve the process modules.
        if EnumProcessModules(h_process, &mut h_module,  std::mem::size_of::<HMODULE>() as DWORD, &mut cb_needed2,) == 0 {
            println!(
                "[!] EnumProcessModules failed [PID: {}] Error: {}",
                current_pid,
                GetLastError()
            );


            CloseHandle(h_process);
            continue;
        }



        // Buffer that receives the executable name.
        let mut process_name_buffer: [u16; MAX_PATH] =
            [0; MAX_PATH];



        // Retrieve executable name.
        if GetModuleBaseNameW(
            h_process,
            h_module,
            process_name_buffer.as_mut_ptr(),
            MAX_PATH as DWORD,
        ) == 0 {

            println!(
                "[!] GetModuleBaseNameW failed [PID: {}] Error: {}",
                current_pid,
                GetLastError()
            );


            CloseHandle(h_process);
            continue;
        }



        // Find the NULL terminator added by Windows.
        let length = process_name_buffer
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(MAX_PATH);



        // Convert UTF-16 process name into Rust String.
        let current_name =
            String::from_utf16_lossy(
                &process_name_buffer[..length]
            );



        // Convert Rust target name into UTF-16 comparison format.
        let target_name =
            String::from_utf16_lossy(
                &proc_name[..proc_name.len() - 1]
            );



        if current_name.eq_ignore_ascii_case(&target_name) {


            println!(
                "[+] Found {} with PID {}",
                current_name,
                current_pid
            );


            *pid = current_pid;
            *process = h_process;


            return true;
        }



        // Close handle before checking next process.
        CloseHandle(h_process);
    }



    false
}

// Prints every running process and PID.
unsafe fn print_processes() -> bool {


    let mut processes: [DWORD; 2048] =
        [0; 2048];


    let mut cb_needed: DWORD = 0;



    if EnumProcesses(
        processes.as_mut_ptr(),
        std::mem::size_of_val(&processes) as DWORD,
        &mut cb_needed,
    ) == 0 {


        println!(
            "[!] EnumProcesses failed. Error: {}",
            GetLastError()
        );


        return false;
    }



    let num_processes =
        cb_needed / std::mem::size_of::<DWORD>() as DWORD;



    println!(
        "[i] Number of processes: {}",
        num_processes
    );



    for (index, &pid) in processes
        .iter()
        .enumerate()
        .take(num_processes as usize)
    {


        if pid == 0 {
            continue;
        }



        let h_process = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pid,
        );



        if h_process.is_null() {
            continue;
        }



        let mut h_module: HMODULE = null_mut();

        let mut cb_needed2: DWORD = 0;



        if EnumProcessModules(
            h_process,
            &mut h_module,
            std::mem::size_of::<HMODULE>() as DWORD,
            &mut cb_needed2,
        ) != 0 {


            let mut name_buffer: [u16; MAX_PATH] =
                [0; MAX_PATH];



            if GetModuleBaseNameW(
                h_process,
                h_module,
                name_buffer.as_mut_ptr(),
                MAX_PATH as DWORD,
            ) != 0 {


                let length = name_buffer
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(MAX_PATH);



                let name =
                    String::from_utf16_lossy(
                        &name_buffer[..length]
                    );



                println!(
                    "[{:03}] {} - PID {}",
                    index,
                    name,
                    pid
                );
            }
        }



        CloseHandle(h_process);
    }


    true
}



fn main() {


    unsafe {


        let mut pid: u32 = 0;


        let mut process_handle: HANDLE =
            null_mut();



        // Convert target process name to UTF-16
        // because Windows APIs require wide strings.
        let target =
            to_widestring(TARGET_PROCESS);



        if !get_remote_process_handle(
            &target,
            &mut pid,
            &mut process_handle,
        ) {


            println!(
                "[!] Target process not found"
            );


            std::process::exit(-1);
        }



        println!(
            "[+] FOUND \"{}\" - PID {}",
            TARGET_PROCESS,
            pid
        );



        // Always release Windows handles.
        CloseHandle(process_handle);



        println!(
            "[#] Press Enter to quit..."
        );


        let _ =
            std::io::stdin()
                .read(&mut [0u8; 1]);
    }
}
```

