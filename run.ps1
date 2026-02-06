$targetDir = $env:CARGO_TARGET_DIR
if (-not $targetDir) {
    $targetDir = Join-Path $PSScriptRoot "target"
}

$SANDBOX_DIR = Join-Path $targetDir "debug"
$X64_DIR = Join-Path $targetDir "x86_64-pc-windows-msvc\debug"
$X32_DIR = Join-Path $targetDir "i686-pc-windows-msvc\debug"

cargo build -p sandbox_hooks --target x86_64-pc-windows-msvc
cargo build -p sandbox_hooks --target i686-pc-windows-msvc

Move-Item "$X64_DIR/sandbox_hooks.dll" "$SANDBOX_DIR/sandbox_hooks_64.dll" -Force
Move-Item "$X32_DIR/sandbox_hooks.dll" "$SANDBOX_DIR/sandbox_hooks_32.dll" -Force

icacls "$SANDBOX_DIR/sandbox_hooks_64.dll" /grant everyone:RX
icacls "$SANDBOX_DIR/sandbox_hooks_64.dll" /grant *S-1-15-2-1:RX
icacls "$SANDBOX_DIR/sandbox_hooks_64.dll" /grant *S-1-15-2-2:RX
icacls "$SANDBOX_DIR/sandbox_hooks_32.dll" /grant everyone:RX
icacls "$SANDBOX_DIR/sandbox_hooks_32.dll" /grant *S-1-15-2-1:RX
icacls "$SANDBOX_DIR/sandbox_hooks_32.dll" /grant *S-1-15-2-2:RX

# Run the sandbox
# cargo run --bin sandbox -- coreutils.exe cat ./test/secret.txt
# cargo run --bin sandbox -- powershell.exe -Command  coreutils.exe cat ./test/secret.txt
# cargo run --bin sandbox -- cat.exe ./test/secret.txt
# cargo run --bin sandbox -- powershell.exe -Command cat.exe ./test/secret.txt
# cargo run --bin sandbox -- notepad.exe ./test/secret.txt
cargo run --bin sandbox -- pwsh.exe
