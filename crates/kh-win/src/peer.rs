// apps/desktop/src-tauri/src/peer.rs
use std::path::PathBuf;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{PWSTR, Result};

/// Who is really on the other end of a pipe connection: asked of Windows, not of the client.
pub struct Peer {
    pub pid: u32,
    pub exe: PathBuf,
    pub ancestors: Vec<PathBuf>, // parent, grandparent, ... for example claude.exe or WindowsTerminal.exe
}

pub fn identify(pipe: HANDLE) -> Result<Peer> {
    let mut pid = 0u32;
    // SAFETY: `pipe` is a server-end pipe handle owned by the caller for the duration of this call, and
    // `pid` is a live, writable u32 that the function fills in.
    unsafe { GetNamedPipeClientProcessId(pipe, &mut pid)? };
    let exe = exe_path(pid)?;
    let parents = parent_map()?;
    let mut ancestors = Vec::new();
    let mut current = pid;
    while let Some(&(_, parent)) = parents.iter().find(|(child, _)| *child == current) {
        if parent == 0 || ancestors.len() >= 8 {
            break;
        }
        if let Ok(path) = exe_path(parent) {
            ancestors.push(path);
        }
        current = parent;
    }
    Ok(Peer { pid, exe, ancestors })
}

fn exe_path(pid: u32) -> Result<PathBuf> {
    // SAFETY: plain FFI call with no pointer arguments; failure (for example, the process has exited) is an Err.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? };
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `process` was just opened with PROCESS_QUERY_LIMITED_INFORMATION, which this call requires.
    // `buf` is a writable buffer of `len` UTF-16 units; on success Windows sets `len` to the number written
    // (never more than the buffer size), so the slice below stays in bounds.
    let named = unsafe { QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len) };
    // SAFETY: `process` is a handle we own, closed exactly once and not used afterwards.
    unsafe { CloseHandle(process)? };
    named?;
    Ok(PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
}

fn parent_map() -> Result<Vec<(u32, u32)>> {
    // SAFETY: plain FFI call with no pointer arguments; failure is an Err.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };
    let mut entry = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    let mut pairs = Vec::new();
    // SAFETY: `snapshot` is a live Toolhelp32 snapshot handle, and `entry` is a writable PROCESSENTRY32W whose
    // dwSize is set to its own size, as both functions require.
    if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
        loop {
            pairs.push((entry.th32ProcessID, entry.th32ParentProcessID));
            // SAFETY: same handle and buffer as above, still valid.
            if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    // SAFETY: `snapshot` is a handle we own, closed exactly once and not used afterwards.
    unsafe { CloseHandle(snapshot)? };
    Ok(pairs)
}
