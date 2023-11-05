use std::{ffi::CString, path::PathBuf};

use clap::{Parser, Subcommand};

use crate::params::ContainerParams;
mod params;

#[derive(Parser)]
struct Cli {
    /// Command to execute
    command: String,

    /// Optional pid for child process
    #[arg(short, long)]
    pid: Option<u32>,

    /// Memory limit (megabytes)
    #[arg(short, long)]
    memory: Option<u32>,
}

fn main() {
    let cli = Cli::parse();

    let split_command = cli.command.split(" ").collect::<Vec<&str>>();
    assert!(split_command.len() > 0);
    let params = ContainerParams {
        pid: 0,
        exec_path: CString::new(split_command[0]).unwrap(),
        args: split_command
            .iter()
            .map(|c| CString::new(*c).unwrap())
            .collect(),
        memory: Some(10),
    };
    println!("Params: {:?}", params);
}
