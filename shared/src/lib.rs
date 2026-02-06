use std::ops::Deref;
use std::path::PathBuf;

use windows::Win32::Foundation::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Threading::*;
use windows::core::PWSTR;

pub fn inject_dll(process: Process, hinstance: HINSTANCE) -> windows::core::Result<()> {
    let current_module = get_current_module_path(hinstance)?;
    let current_module_dir = current_module.parent().unwrap();

    let dll_path_32 = current_module_dir.join("sandbox_hooks_32.dll");
    let dll_path_64 = current_module_dir.join("sandbox_hooks_64.dll");

    let dll_path_32 = encode_wide(&dll_path_32.to_string_lossy());
    let dll_path_64 = encode_wide(&dll_path_64.to_string_lossy());

    unsafe { dllinject::InjectDll((*process).0, dll_path_32.as_ptr(), dll_path_64.as_ptr()) };

    Ok(())
}

#[unsafe(no_mangle)]
fn get_current_module_path(hinstance: HINSTANCE) -> windows::core::Result<PathBuf> {
    unsafe {
        let mut path_buf = vec![0u16; 260];
        GetModuleFileNameW(Some(HMODULE(hinstance.0)), &mut path_buf);

        let path = String::from_utf16_lossy(&path_buf);
        Ok(PathBuf::from(path))
    }
}

pub struct Process {
    handle: HANDLE,
    close_on_drop: bool,
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Process {
    pub fn open(pid: u32) -> windows::core::Result<Process> {
        let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) }?;
        let process = Process {
            handle: process,
            close_on_drop: true,
        };
        Ok(process)
    }

    pub fn from_raw_handle(handle: HANDLE) -> Process {
        Process {
            handle,
            close_on_drop: false,
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
