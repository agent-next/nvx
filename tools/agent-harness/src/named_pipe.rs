use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_MODE,
    OPEN_EXISTING,
};
#[cfg(windows)]
use windows::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
#[cfg(windows)]
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
#[cfg(windows)]
use windows::core::PCWSTR;

#[derive(Debug)]
pub struct NamedPipeError {
    pub message: String,
}

impl core::fmt::Display for NamedPipeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for NamedPipeError {}

pub fn validate_local_pipe_path(path: &str) -> Result<(), NamedPipeError> {
    if !path.starts_with(r"\\.\pipe\") {
        return Err(NamedPipeError {
            message: format!("pipe path must start with \\\\.\\pipe\\, got {path:?}"),
        });
    }
    if path.len() > 240 {
        return Err(NamedPipeError {
            message: "pipe path exceeds conservative bound".to_string(),
        });
    }
    Ok(())
}

#[cfg(windows)]
pub struct NamedPipeClient {
    handle: OwnedHandle,
}

#[cfg(windows)]
impl NamedPipeClient {
    pub fn connect(
        path: &str,
        deadline: Duration,
        expected_server_image: Option<&str>,
    ) -> Result<Self, NamedPipeError> {
        validate_local_pipe_path(path)?;
        let deadline_at = Instant::now() + deadline;
        let wide = wide_null(path);
        loop {
            // SAFETY: Win32 call with stable UTF-16 buffer.
            let handle = unsafe {
                CreateFileW(
                    PCWSTR(wide.as_ptr()),
                    FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                    FILE_SHARE_MODE(0),
                    None,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    None,
                )
            };
            if let Ok(handle) = handle {
                // SAFETY: handle is owned because CreateFileW succeeded.
                let client = Self {
                    handle: unsafe { OwnedHandle::from_raw_handle(handle.0 as *mut _) },
                };
                if let Some(expected) = expected_server_image {
                    client.verify_server_image_path(expected)?;
                }
                return Ok(client);
            }
            let remaining = deadline_at.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(NamedPipeError {
                    message: format!("timed out connecting to control pipe {path}"),
                });
            }
            let wait_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
            // SAFETY: stable path pointer and bounded timeout value.
            let waited = unsafe { WaitNamedPipeW(PCWSTR(wide.as_ptr()), wait_ms) };
            if !waited.as_bool() && Instant::now() >= deadline_at {
                return Err(NamedPipeError {
                    message: format!("control pipe wait deadline reached for {path}"),
                });
            }
        }
    }

    pub fn verify_server_image_path(&self, expected_path: &str) -> Result<(), NamedPipeError> {
        let mut pid = 0_u32;
        // SAFETY: valid pipe handle and out pointer.
        let ok =
            unsafe { GetNamedPipeServerProcessId(HANDLE(self.handle.as_raw_handle()), &mut pid) };
        if ok.is_err() || pid == 0 {
            return Err(NamedPipeError {
                message: "failed to resolve named-pipe server process id".to_string(),
            });
        }
        // SAFETY: OpenProcess returns owned process handle or null.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
        let Ok(process) = process else {
            return Err(NamedPipeError {
                message: format!("failed to open named-pipe server process pid={pid}"),
            });
        };
        let mut buffer = vec![0_u16; 4096];
        let mut len = buffer.len() as u32;
        // SAFETY: valid process handle, writable UTF-16 buffer.
        let query_ok = unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_FORMAT(0),
                windows::core::PWSTR(buffer.as_mut_ptr()),
                &mut len,
            )
        };
        // SAFETY: close temporary process handle.
        let _ = unsafe { CloseHandle(process) };
        if query_ok.is_err() {
            return Err(NamedPipeError {
                message: format!("failed querying image path for named-pipe server pid={pid}"),
            });
        }
        let actual = String::from_utf16_lossy(&buffer[..len as usize]);
        if !actual.eq_ignore_ascii_case(expected_path) {
            return Err(NamedPipeError {
                message: format!(
                    "named-pipe server image mismatch: actual={actual:?} expected={expected_path:?}"
                ),
            });
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Read for NamedPipeClient {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::fs::File::from(self.handle.try_clone()?).read(buf)
    }
}

#[cfg(windows)]
impl Write for NamedPipeClient {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::fs::File::from(self.handle.try_clone()?).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(not(windows))]
pub struct NamedPipeClient;

#[cfg(not(windows))]
impl NamedPipeClient {
    pub fn connect(
        path: &str,
        _deadline: Duration,
        _expected_server_image: Option<&str>,
    ) -> Result<Self, NamedPipeError> {
        validate_local_pipe_path(path)?;
        Err(NamedPipeError {
            message: "named pipe transport is only available on Windows".to_string(),
        })
    }
}

#[cfg(windows)]
fn wide_null(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_local_pipe_paths() {
        assert!(validate_local_pipe_path("tcp://127.0.0.1:9999").is_err());
        assert!(validate_local_pipe_path(r"\\?\C:\temp\pipe").is_err());
    }

    #[test]
    fn accepts_local_pipe_paths() {
        assert!(validate_local_pipe_path(r"\\.\pipe\nvx-control-test").is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_connect_reports_platform_requirement() {
        let result =
            NamedPipeClient::connect(r"\\.\pipe\nvx-control-test", Duration::from_millis(5), None);
        assert!(result.is_err());
        let message = result.expect_err("expected error").to_string();
        assert!(message.contains("Windows"));
    }
}
