use std::{
    env::var,
    fs::{create_dir_all, read, write},
    path::PathBuf,
    process::{Command, Stdio},
};

use cargo_subcommand::{Args, Subcommand};
use goblin::Object;

const LIB_SHELLCODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/lib/libShellcode.so"));

#[derive(Debug, thiserror::Error)]
/// An error raised during build
pub enum Error {
    #[error(transparent)]
    /// A wrapped std::io::Error
    IoError(#[from] std::io::Error),
    #[error(transparent)]
    /// A wrapped std::env::VarError
    VarError(#[from] std::env::VarError),
    #[error(transparent)]
    /// A wrapped subcommand error
    SubcommandError(#[from] cargo_subcommand::Error),
    #[error(transparent)]
    /// A wrapped goblin::error::Error
    GoblinError(#[from] goblin::error::Error),
    #[error("Failed to build shellcode")]
    /// An error raised when the shellcode build fails
    BuildFailed,
    #[error("Expected exactly 1 build artifact")]
    /// An error raised when the number of build artifacts is not 1
    ExpectedOneArtifact,
    #[error("Expected exactly 1 executable section")]
    /// An error raised when the number of executable sections is not 1
    ExpectedOneExecutableSection,
    #[error("Section containing entry or code was not found in build artifact {path}")]
    /// An error raised when the shellcode is not found in the build artifact
    ShellcodeNotFound { path: PathBuf },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(clap::Parser, Debug, Clone)]
pub struct Cmd {
    #[clap(subcommand)]
    pub shellcode: ShellcodeCmd,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum ShellcodeCmd {
    /// Build to shellcode
    Shellcode {
        #[clap(flatten)]
        args: Args,
    },
}

pub struct App;

impl App {
    pub fn run(cmd: Cmd) -> Result<()> {
        let ShellcodeCmd::Shellcode { args } = cmd.shellcode;

        let subcommand = Subcommand::new(args)?;

        if !subcommand.quiet() {
            println!("Building shellcode for package {}", subcommand.package());
        }

        let cargo = var("CARGO")?;

        if !subcommand.target_dir().exists() {
            create_dir_all(subcommand.target_dir())?;
        }

        // Write LIB_SHELLCODE into the package's target directory
        let lib_shellcode_path = subcommand.target_dir().join("libShellcode.so");
        write(&lib_shellcode_path, LIB_SHELLCODE)?;

        // let link_x_path = subcommand.target_dir().join("link.x");
        // write(&link_x_path, include_bytes!("link.x"))?;

        let plugin_path_arg = format!("-Zllvm-plugins={}", lib_shellcode_path.display());
        // let link_x_arg = format!("-Clink-arg=-T{}", link_x_path.display());

        let mut cmd = Command::new(&cargo);
        cmd.arg("rustc");
        subcommand.args().apply(&mut cmd);
        cmd.args([
            "--",
            &plugin_path_arg,
            // &link_x_arg,
            // "-Ccode-model=small",
            "-Ccodegen-units=1",
            "-Cdebug-assertions=false",
            "-Cdebuginfo=none",
            // "-Cdefault-linker-libraries=false",
            // "-Cforce-frame-pointers=false",
            "-Clink-dead-code=false",
            // "-Clto=true",
            "-Cno-redzone=true",
            "-Cno-vectorize-loops",
            "-Cno-vectorize-slp",
            "-Copt-level=z",
            "-Coverflow-checks=false",
            "-Cpanic=abort",
            "-Cpasses=InlineFunctions InlineGlobals",
            "-Cprefer-dynamic=false",
            "-Crelocation-model=pic",
            "-Crelro-level=off",
            "-Crpath=false",
            // "-Csoft-float=true",
            "-Cstrip=symbols",
            "-Clink-arg=-nostartfiles",
            "--emit=llvm-bc",
        ]);

        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        let res = cmd.spawn()?.wait()?;

        if !res.success() {
            eprintln!("Failed to build shellcode");
            return Err(Error::BuildFailed);
        }

        if !subcommand.quiet() {
            println!("Shellcode built successfully!");
        }

        let artifact_path = subcommand
            .artifacts()
            .map(|a| subcommand.build_dir(subcommand.target()).join(&a.name))
            .next()
            .ok_or(Error::ExpectedOneArtifact)?;

        let artifact_contents = read(&artifact_path)?;

        let object = Object::parse(&artifact_contents)?;

        let shellcode = match object {
            Object::Elf(elf) => {
                let entry = elf.entry;
                elf.section_headers.iter().find_map(|section| {
                    let name = elf.strtab.get_at(section.sh_name);
                    if name.is_some_and(|n| n == ".text")
                        || section.vm_range().contains(&(entry as usize))
                    {
                        section.file_range().map(|range| &artifact_contents[range])
                    } else {
                        None
                    }
                })
            }
            _ => unimplemented!(),
        };

        let shellcode_path = subcommand.target_dir().join("shellcode.bin");

        if let Some(shellcode) = shellcode {
            write(&shellcode_path, shellcode)?;
            if !subcommand.quiet() {
                println!("Shellcode written to {}", shellcode_path.display());
            }
        } else {
            eprintln!("No shellcode found in artifact");
            return Err(Error::ShellcodeNotFound {
                path: artifact_path,
            });
        }

        Ok(())
    }
}
