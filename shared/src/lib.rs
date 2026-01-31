use std::ops::Deref;
use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;

use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessId};
use windows::core::BOOL;
use windows::core::PWSTR;
use windows::core::{s, w};

pub fn inject_dll_into_process(target: Process) -> windows::core::Result<()> {
    let host = Process::current();
    let is_host_64_bit = host.is_64_bit()?;
    let is_target_64_bit = target.is_64_bit()?;

    if is_host_64_bit == is_target_64_bit {
        println!("[INJECT] Using direct injection for same-bitness injection");
        inject_dll(*target, is_target_64_bit, true)?;
    } else {
        println!("[INJECT] Using pipe for cross-bitness injection");
        inject_via_pipe(target.pid())?;
    }

    Ok(())
}

pub async fn inject_dll_into_process_async(target: Process) -> windows::core::Result<()> {
    let host = Process::current();
    let is_host_64_bit = host.is_64_bit()?;
    let is_target_64_bit = target.is_64_bit()?;

    if is_host_64_bit == is_target_64_bit {
        println!("[INJECT] Using direct injection for same-bitness injection");
        inject_dll(*target, is_target_64_bit, true)?;
    } else {
        println!("[INJECT] Using pipe for cross-bitness injection");
        inject_via_pipe_async(target.pid()).await?;
    }

    Ok(())
}

pub const PIPE_NAME: &str = r"\\.\pipe\sandbox_inject";

fn inject_via_pipe(pid: u32) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { inject_via_pipe_async(pid).await })
}

async fn inject_via_pipe_async(pid: u32) -> std::io::Result<()> {
    let mut attempt = 0;

    loop {
        let Ok(mut client) = ClientOptions::new().open(PIPE_NAME) else {
            attempt += 1;
            if attempt >= 5 {
                let err = format!("Failed to open pipe {PIPE_NAME}");
                println!("[INJECT] {err}");
                return Err(std::io::Error::other(err));
            }

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            continue;
        };

        println!("[INJECT] Connected to pipe {PIPE_NAME}");
        println!("[INJECT] Sending PID {pid} for injection...");

        let pid_bytes = pid.to_le_bytes();
        client.write_all(&pid_bytes).await?;
        client.flush().await?;

        println!("[INJECT] Waiting for injection response...");
        let mut resp = [0u8; 1];
        client.read_exact(&mut resp).await?;

        println!("[INJECT] Received injection response: {}", resp[0]);
        if resp[0] != 0 {
            let err = format!("Injection failed with status code {}", resp[0]);
            return Err(std::io::Error::other(err));
        }

        break;
    }

    Ok(())
}

pub fn inject_dll(process: HANDLE, is_64_bit: bool, verbose: bool) -> windows::core::Result<()> {
    let current_module = get_current_module_path()?;
    let current_module_dir = current_module.parent().unwrap();

    let dll_path = if is_64_bit {
        current_module_dir.join("sandbox_hooks_64.dll")
    } else {
        current_module_dir.join("sandbox_hooks_32.dll")
    };

    if verbose {
        println!("[INJECT] Injecting DLL: {}", dll_path.display());
    }

    unsafe {
        let pid = GetProcessId(process);
        let injection_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

        let dll_path_wide = encode_wide(dll_path.to_str().unwrap());
        let dll_path_size = dll_path_wide.len() * std::mem::size_of::<u16>();

        let remote_mem = VirtualAllocEx(
            injection_handle,
            None,
            dll_path_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_mem.is_null() {
            if verbose {
                let err = GetLastError();
                println!("[INJECT] VirtualAllocEx failed: {:?}", err);
            }

            CloseHandle(injection_handle)?;
            return Err(E_FAIL.into());
        }

        let mut bytes_written = 0;
        if let Err(e) = WriteProcessMemory(
            injection_handle,
            remote_mem,
            dll_path_wide.as_ptr() as *const _,
            dll_path_size,
            Some(&mut bytes_written),
        ) {
            if verbose {
                println!("[INJECT] WriteProcessMemory failed: {:?}", e);
            }

            VirtualFreeEx(injection_handle, remote_mem, 0, MEM_RELEASE)?;
            CloseHandle(injection_handle)?;
            return Err(E_FAIL.into());
        }

        let h_kernel32 = GetModuleHandleW(w!("kernel32.dll"))?;
        let load_library_addr = GetProcAddress(h_kernel32, s!("LoadLibraryW"));

        if let Some(load_library) = load_library_addr {
            let h_thread = CreateRemoteThread(
                injection_handle,
                None,
                0,
                Some(std::mem::transmute(load_library)),
                Some(remote_mem),
                0,
                None,
            )?;
            WaitForSingleObject(h_thread, INFINITE);
            CloseHandle(h_thread)?;
        } else {
            if verbose {
                let err = GetLastError();
                println!("[INJECT] GetProcAddress(LoadLibraryW) failed: {:?}", err);
            }

            VirtualFreeEx(injection_handle, remote_mem, 0, MEM_RELEASE)?;
            CloseHandle(injection_handle)?;
            return Err(E_FAIL.into());
        }

        VirtualFreeEx(injection_handle, remote_mem, 0, MEM_RELEASE)?;
        CloseHandle(injection_handle)?;
    }

    Ok(())
}

#[unsafe(no_mangle)]
fn get_current_module_path() -> windows::core::Result<PathBuf> {
    unsafe {
        let mut module_handle = HMODULE::default();
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            w!("get_current_module_path"),
            &mut module_handle,
        )?;

        let mut path_buf = vec![0u16; 260];
        GetModuleFileNameW(Some(module_handle), &mut path_buf);

        let path = String::from_utf16_lossy(&path_buf);
        Ok(PathBuf::from(path))
    }
}

pub struct Process {
    handle: HANDLE,
    close_on_drop: bool,
    pid: u32,
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Process {
    pub fn open(pid: u32) -> windows::core::Result<Process> {
        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }?;
        Ok(Process {
            handle: process,
            close_on_drop: true,
            pid,
        })
    }

    pub fn current() -> Process {
        let process = unsafe { GetCurrentProcess() };
        Process {
            handle: process,
            close_on_drop: false,
            pid: unsafe { GetProcessId(process) },
        }
    }

    pub fn from_raw_handle(handle: HANDLE) -> Process {
        Process {
            handle,
            close_on_drop: false,
            pid: unsafe { GetProcessId(handle) },
        }
    }

    pub fn raw_handle(&self) -> HANDLE {
        self.handle
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_64_bit(&self) -> windows::core::Result<bool> {
        unsafe {
            let mut is_wow64 = BOOL(0);
            IsWow64Process(self.handle, &mut is_wow64)?;
            Ok(is_wow64.as_bool() == false)
        }
    }

    pub fn exe_path(&self) -> windows::core::Result<String> {
        let mut buf = vec![0u16; 260];
        let mut size = buf.len() as u32;

        unsafe {
            QueryFullProcessImageNameW(
                self.handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut size,
            )
        }?;

        let path = String::from_utf16_lossy(&buf[..size as usize]);
        Ok(path)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.close_on_drop {
            let _ = unsafe { CloseHandle(self.handle) };
        }
    }
}

impl Deref for Process {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

pub fn encode_wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
