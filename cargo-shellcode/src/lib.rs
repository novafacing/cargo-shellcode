use std::{
    env::var,
    fs::{create_dir_all, read, write},
    num::NonZero,
    path::PathBuf,
    process::{Command, Stdio},
};

use cargo_subcommand::{Args, Subcommand};
use goblin::Object;
use nix::sys::mman::{mmap_anonymous, MapFlags, ProtFlags};

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
    #[error("Error no {0}")]
    /// An error raised when the shellcode is not found in the build artifact
    ErrorNo(#[from] nix::errno::Errno),
    #[error("Shellcode was empty")]
    /// An error raised when the shellcode is empty
    ShellcodeEmpty,
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
    Shellcode(ShellcodeCmdInner),
}

#[derive(clap::Parser, Debug, Clone)]
pub struct ShellcodeCmdInner {
    #[clap(subcommand)]
    pub cmds: ShellcodeCmds,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub enum ShellcodeCmds {
    /// Build crate into shellcode
    Build {
        #[clap(flatten)]
        args: Args,
        #[clap(short, long)]
        /// Optional path to write shellcode to. If not specified, shellcode will be output to the
        /// target directory as `shellcode.bin`
        output: Option<PathBuf>,
    },
    /// Run shellcode
    Run {
        #[clap(short, long)]
        /// Optional path to the manifest file. If not specified, the default manifest path
        /// `Cargo.toml` in the current directory will be used.
        manifest_path: Option<PathBuf>,
        /// Optional path to shellcode to run. If not specified, the default shellcode output path
        /// `shellcode.bin` in the `target` directory will be used.
        shellcode: Option<PathBuf>,
    },
}

pub struct App;

impl App {
    fn build_cmd(args: Args, output: Option<PathBuf>) -> Result<()> {
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

        let shellcode_path = output.unwrap_or(subcommand.target_dir().join("shellcode.bin"));

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

    pub fn run_cmd(manifest_path: Option<PathBuf>, shellcode: Option<PathBuf>) -> Result<()> {
        let args = Args {
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
            manifest_path,
        };
        let subcommand = Subcommand::new(args)?;

        let shellcode_path = shellcode.unwrap_or(subcommand.target_dir().join("shellcode.bin"));

        let shellcode = read(&shellcode_path)?;

        let mapping = unsafe {
            mmap_anonymous(
                None,
                NonZero::new(shellcode.len()).ok_or(Error::ShellcodeEmpty)?,
                ProtFlags::PROT_EXEC | ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANON | MapFlags::MAP_PRIVATE | MapFlags::MAP_EXECUTABLE,
            )?
        };

        unsafe {
            std::ptr::copy(
                shellcode.as_ptr(),
                mapping.as_ptr() as *mut u8,
                shellcode.len(),
            )
        };

        let entry = unsafe { std::mem::transmute::<_, fn()>(mapping.as_ptr()) };

        entry();

        Ok(())
    }

    pub fn run(cmd: Cmd) -> Result<()> {
        let ShellcodeCmd::Shellcode(ShellcodeCmdInner { cmds }) = cmd.shellcode;

        match cmds {
            ShellcodeCmds::Build { args, output } => Self::build_cmd(args, output)?,
            ShellcodeCmds::Run {
                manifest_path,
                shellcode,
            } => Self::run_cmd(manifest_path, shellcode)?,
        }

        Ok(())
    }
}
