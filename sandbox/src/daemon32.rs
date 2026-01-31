use std::io::{Read, Write};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();

    loop {
        let mut in_lock = stdin.lock();
        let mut out_lock = stdout.lock();

        let mut pid_bytes = [0u8; 4];

        if in_lock.read_exact(&mut pid_bytes).is_err() {
            continue;
        };

        let pid = u32::from_le_bytes(pid_bytes);

        let process = shared::Process::open(pid);

        let status = match process {
            Ok(p) => match shared::inject_dll(*p, false, false) {
                Ok(_) => 0u8,
                Err(_) => 1u8,
            },
            Err(_) => 1u8,
        };
        let _ = out_lock.write_all(&[status]);
        let _ = out_lock.flush();
    }
}
