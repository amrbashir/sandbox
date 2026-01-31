use std::io::{Read, Write};
use std::process::Command;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::ServerOptions;

const MAX_BUFFER_SIZE: u32 = 4 * 1024;

struct DaemonChild {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
}

#[derive(Default)]
struct State {
    daemon_32: Option<DaemonChild>,
}

fn ensure_daemon_32<'a>(
    state: &'a mut State,
    daemon_32_path: &std::path::Path,
) -> std::io::Result<&'a mut DaemonChild> {
    // Start the 32-bit daemon if not already running
    if state.daemon_32.is_none() {
        let mut child = Command::new(daemon_32_path)
            .stdout(std::process::Stdio::piped())
            .stdin(std::process::Stdio::piped())
            .spawn()?;

        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();

        state.daemon_32 = Some(DaemonChild {
            child,
            stdin,
            stdout,
        });
    }

    // If was started, check if it's still running
    if let Some(status) = state.daemon_32.as_mut().unwrap().child.try_wait()? {
        println!("[DAEMON] 32-bit daemon exited with status: {}", status);
        state.daemon_32 = None;
        return ensure_daemon_32(state, daemon_32_path);
    }

    Ok(state.daemon_32.as_mut().unwrap())
}

async fn inject_via_32_daemon(
    state: &mut State,
    pid: u32,
    daemon_32_path: &std::path::Path,
) -> std::io::Result<u8> {
    let daemon_32 = ensure_daemon_32(state, daemon_32_path)?;
    let stdin = &mut daemon_32.stdin;
    let stdout = &mut daemon_32.stdout;

    println!("[DAEMON] sending PID {pid} to 32-bit daemon");
    let pid_bytes = pid.to_le_bytes();
    stdin.write_all(&pid_bytes)?;
    stdin.flush()?;

    let mut resp = [0u8; 1];
    stdout.read_exact(&mut resp)?;
    println!("[DAEMON] Received injection response: {}", resp[0]);

    Ok(resp[0])
}

pub fn start() -> tokio::task::JoinHandle<()> {
    let mut state = State::default();

    tokio::spawn(async move {
        let current_exe = std::env::current_exe().unwrap();
        let current_exe_dir = current_exe.parent().unwrap();
        let daemon_32_path = current_exe_dir.join("sandbox_daemon32.exe");

        let pipe_name = shared::PIPE_NAME;

        loop {
            let Ok(mut server) = ServerOptions::new()
                .in_buffer_size(MAX_BUFFER_SIZE)
                .out_buffer_size(MAX_BUFFER_SIZE)
                .create(pipe_name)
            else {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            };

            if server.connect().await.is_err() {
                continue;
            }

            println!("[DAEMON] Client connected to pipe.");

            let mut buf = [0u8; 4];

            if let Err(e) = server.read_exact(&mut buf).await {
                println!("[DAEMON] Failed to read from pipe: {:?}", e);
                continue;
            }

            let pid = u32::from_le_bytes(buf);

            println!("[DAEMON] Received injection request for PID: {}", pid);

            let process = shared::Process::open(pid).unwrap();
            let is_target_64 = process.is_64_bit().unwrap_or_default();

            let status = if is_target_64 {
                println!("[DAEMON] Injecting into 64-bit process.");
                match shared::inject_dll(*process, is_target_64, true) {
                    Ok(_) => 0u8,
                    Err(_) => 1u8,
                }
            } else {
                println!("[DAEMON] Injecting into 32-bit process via 32-bit daemon.");
                inject_via_32_daemon(&mut state, pid, &daemon_32_path)
                    .await
                    .unwrap_or(1)
            };

            if let Err(e) = server.write_all(&[status]).await {
                println!("[DAEMON] Failed to write status to pipe: {:?}", e);
            }

            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
}
