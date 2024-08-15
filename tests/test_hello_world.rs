use cargo_shellcode::{App, Cmd, ShellcodeCmd};
use cargo_subcommand::Args;
use nix::{
    libc::{fflush, STDOUT_FILENO},
    sys::mman::{mmap_anonymous, MapFlags, ProtFlags},
    unistd::{close, dup, dup2, pipe},
};
use std::{
    fs::read,
    io::Read,
    num::NonZero,
    os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    path::PathBuf,
};

const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

#[test]
fn test_hello_world() {
    let hello_world_path = PathBuf::from(CARGO_MANIFEST_DIR).join("examples/hello-world");
    let cmd = Cmd {
        shellcode: ShellcodeCmd::Shellcode {
            args: Args {
                manifest_path: Some(hello_world_path.join("Cargo.toml")),
                quiet: false,
                package: vec![],
                workspace: false,
                exclude: vec![],
                lib: false,
                bin: vec![],
                bins: false,
                example: vec![],
                examples: false,
                release: false,
                profile: None,
                features: vec![],
                all_features: false,
                no_default_features: false,
                target: None,
                target_dir: None,
            },
        },
    };
    App::run(cmd).unwrap();
    let shellcode = read(&hello_world_path.join("target").join("shellcode.bin")).unwrap();
    let mapping = unsafe {
        mmap_anonymous(
            None,
            NonZero::new(shellcode.len()).unwrap(),
            ProtFlags::PROT_EXEC | ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
            MapFlags::MAP_PRIVATE | MapFlags::MAP_EXECUTABLE,
        )
        .unwrap()
    };
    // Copy shellcode into the mapping
    unsafe {
        std::ptr::copy(
            shellcode.as_ptr(),
            mapping.as_ptr() as *mut u8,
            shellcode.len(),
        );
    }

    // Execute the shellcode
    let f: fn() = unsafe { std::mem::transmute(mapping.as_ptr()) };

    // Capture stdout by using dup/dup2 and pipe

    let (pipe_read, pipe_write) = pipe().unwrap();
    let saved_stdout = dup(STDOUT_FILENO).unwrap();
    dup2(pipe_write.as_raw_fd(), STDOUT_FILENO).unwrap();
    close(pipe_write.into_raw_fd()).unwrap();

    f();

    unsafe { fflush(std::ptr::null_mut()) };

    dup2(saved_stdout, STDOUT_FILENO).unwrap();
    close(saved_stdout).unwrap();

    let mut output = Vec::new();
    eprintln!("Reading from pipe");
    let mut pipe_read_file = unsafe { std::fs::File::from_raw_fd(pipe_read.into_raw_fd()) };
    std::io::Read::by_ref(&mut pipe_read_file)
        .read_to_end(&mut output)
        .unwrap();
    eprintln!("Read from pipe: {:?}", String::from_utf8_lossy(&output));

    unsafe {
        nix::sys::mman::munmap(mapping, NonZero::new(shellcode.len()).unwrap().into()).unwrap();
    }

    assert_eq!(String::from_utf8(output).unwrap(), "Hello, World!\n");
}
