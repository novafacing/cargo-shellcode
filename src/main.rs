use cargo_shellcode::{App, Cmd, Result};
use clap::Parser;

fn main() -> Result<()> {
    let cmd = Cmd::parse();
    App::run(cmd)?;
    Ok(())
}
