use std::{
    ffi::CString,
    os::fd::{AsRawFd, RawFd},
    path::PathBuf,
    process::Child,
};

use clap::{Parser, Subcommand};
use errors::{ContainerError, ContainerResult};
use nix::{
    sched::{clone, CloneFlags},
    sys::{
        signal::Signal,
        socket::{socketpair, AddressFamily, SockFlag, SockType},
        wait::waitpid,
    },
    unistd::{execve, Pid},
};
use std::process::exit;

mod errors;

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

#[derive(Debug)]
pub struct ChildConfig {
    // The pid of the child process
    pub pid: u32,

    // Path to executable file
    pub exec_path: CString,

    // Arguments for the command
    pub args: Vec<CString>,

    // Memory limit of container (megabytes)
    pub memory: Option<u32>,

    // File descriptor of the socket
    pub socket_fd: i32,
}

const STACK_SIZE: usize = 1024 * 1024;

// Creates a child process with clone and runs the executable file
// with execve in the child process.
fn create_child_process(config: &ChildConfig) -> Result<Pid, ContainerError> {
    println!("creating child process");

    let mut flags = CloneFlags::empty();
    flags.insert(CloneFlags::CLONE_NEWNS);
    flags.insert(CloneFlags::CLONE_NEWCGROUP);
    flags.insert(CloneFlags::CLONE_NEWPID);
    flags.insert(CloneFlags::CLONE_NEWIPC);
    flags.insert(CloneFlags::CLONE_NEWNET);
    flags.insert(CloneFlags::CLONE_NEWUTS);
    let mut stack = [0; STACK_SIZE];
    let clone_res = unsafe {
        clone(
            Box::new(|| match child(config) {
                Ok(_) => 0,
                Err(_) => -1,
            }),
            &mut stack,
            flags,
            Some(Signal::SIGCHLD as i32),
            // If the signal SIGCHLD is ignored, waitpid will hang until the
            // child exits and then fail with code ECHILD.
        )
    };

    match clone_res {
        Ok(pid) => Ok(pid),
        Err(_) => Err(ContainerError::CloneErr),
    }
}

fn child(config: &ChildConfig) -> ContainerResult {
    set_hostname()?;
    mounts(config)?;
    user_ns(config)?;
    capabilities()?;
    syscalls()?;
    match execve::<CString, CString>(&config.exec_path, &config.args, &[]) {
        Ok(_) => Ok(()),
        Err(_) => {
            println!("Error!");
            Err(ContainerError::ExecveErr)
        }
    }
}

fn set_hostname() -> ContainerResult {
    Ok(())
}

fn mounts(config: &ChildConfig) -> ContainerResult {
    Ok(())
}

fn user_ns(config: &ChildConfig) -> ContainerResult {
    Ok(())
}

fn capabilities() -> ContainerResult {
    Ok(())
}

fn syscalls() -> ContainerResult {
    Ok(())
}

fn handle_child_uid_map(pid: Pid, fd: i32) -> ContainerResult {
    Ok(())
}

fn resources(config: &ChildConfig) {}

fn create_socketpair() -> Result<(RawFd, RawFd), ContainerError> {
    match socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    ) {
        Ok((first, second)) => Ok((first.as_raw_fd(), second.as_raw_fd())),
        Err(_) => Err(ContainerError::CreateSocketErr),
    }
}

fn run() -> ContainerResult {
    let cli = Cli::parse();

    let split_command = cli.command.split(" ").collect::<Vec<&str>>();
    assert!(split_command.len() > 0);

    let (parent_socket, child_socket) = create_socketpair()?;

    let config = ChildConfig {
        pid: 0,
        exec_path: CString::new(split_command[0]).unwrap(),
        args: split_command
            .iter()
            .map(|c| CString::new(*c).unwrap())
            .collect(),
        memory: Some(10),
        socket_fd: child_socket,
    };
    println!("Config: {:?}", config);

    resources(&config);
    let child_pid = create_child_process(&config)?;
    handle_child_uid_map(child_pid, parent_socket)?;
    if let Err(e) = waitpid(child_pid, None) {
        println!("Error waiting for pid: {:?}", e);
        return Err(ContainerError::WaitPidErr);
    };
    Ok(())
}

fn main() {
    if let Err(_) = run() {
        exit(-1);
    }
}
