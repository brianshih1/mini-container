use std::os::fd::OwnedFd;
use std::os::unix::io::RawFd;
use std::{
    ffi::CString,
    fs::{create_dir_all, remove_dir, File},
    io::Write,
    os::fd::AsRawFd,
    path::PathBuf,
};

use caps::Capability;
use cgroups_rs::{
    cgroup_builder::CgroupBuilder,
    hierarchies::V2,
    CgroupPid,
};
use clap::{Parser};
use errors::{ContainerError, ContainerResult};


use nix::{
    mount::{mount, umount2, MntFlags, MsFlags},
    sched::unshare,
    sys::{socket::MsgFlags, stat::Mode},
    unistd::{chdir, pivot_root, setresuid, Uid},
};
use nix::{
    sched::{clone, CloneFlags},
    sys::{
        signal::Signal,
        socket::{recv, send, socketpair, AddressFamily, SockFlag, SockType},
        wait::waitpid,
    },
    unistd::{execve, sethostname, Pid},
};

use phf::phf_map;
use rand::{distributions::Alphanumeric, Rng};
use std::process::exit;
use syscallz::{Action, Cmp, Comparator, Context, Syscall};

mod errors;

#[derive(Parser)]
struct Cli {
    /// Command to execute
    command: String,

    /// Absolute path to new root filesystem
    root_filesystem_path: String,

    /// Optional pid for child process
    #[arg(short, long)]
    pid: Option<u32>,

    /// Memory limit (megabytes)
    #[arg(short, long)]
    memory: Option<i64>,

    /// Memory limit (megabytes)
    #[arg(long)]
    nproc: Option<i64>,

    /// Memory limit (megabytes)
    #[arg(short, long)]
    user: Option<u32>,

    // Add capabilities to the bounding set
    #[clap(long, value_parser, num_args = 1.., value_delimiter = ' ')]
    cap_add: Option<Vec<String>>,

    // Remove capabilities to the bounding set, or all if the String provided is "ALL"
    #[clap(long, value_parser, num_args = 1.., value_delimiter = ' ')]
    cap_drop: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct ChildConfig {
    // The pid of the child process
    pub pid: i64,

    // Path to executable file
    pub exec_path: CString,

    // Arguments for the command
    pub args: Vec<CString>,

    // Memory limit of container (megabytes)
    pub memory: Option<i64>,

    // Maximum number of pids the child process can create
    pub max_pids: Option<i64>,

    // File descriptor of the socket
    pub socket_fd: i32,

    // TODO: root filesystem image directory
    pub root_filesystem_directory: String,

    // Hostname for the container
    pub hostname: String,

    // The user ID that runs the child process
    pub user_id: Option<u32>,

    // Add a capability to the bounding set
    pub cap_add: Option<Vec<String>>,

    // Remove a capability to the bounding set, or all if the String provided is "ALL"
    pub cap_drop: Option<Vec<String>>,
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
        Ok(pid) => {
            println!("Child pid: {:?}", pid);
            Ok(pid)
        }
        Err(_) => Err(ContainerError::Clone),
    }
}

// setup the namespaces, capabilities, syscall restrictions before running the executable
fn child(config: &ChildConfig) -> ContainerResult {
    set_hostname(config)?;
    isolate_filesystem(config)?;
    user_ns(config)?;
    println!("Finished user namespace");
    capabilities(config)?;
    syscalls()?;
    println!("Executing!");
    match execve::<CString, CString>(&config.exec_path, &config.args, &[]) {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("Failed to execute!: {:?}", e);
            Err(ContainerError::Execve)
        }
    }
}

fn generate_random_hostname() -> String {
    let s: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();
    let hostname = format!("mini-{s}");
    hostname
}

fn set_hostname(config: &ChildConfig) -> ContainerResult {
    match sethostname(&config.hostname) {
        Ok(_) => {
            println!("Set hostname to: {:?}", &config.hostname);
            Ok(())
        }
        Err(err) => {
            println!("Error setting hostname: {:?}", err);
            Err(ContainerError::CreateSocketErr)
        }
    }
}

fn isolate_filesystem(config: &ChildConfig) -> ContainerResult {
    println!("isolating filesystem!");
    mount_filesystem(
        None,
        &PathBuf::from("/"),
        vec![MsFlags::MS_REC, MsFlags::MS_PRIVATE],
    )?;
    let filesystem_path = PathBuf::from("/home/brianshih/alpine");
    mount_filesystem(
        Some(&filesystem_path),
        &filesystem_path,
        vec![MsFlags::MS_BIND, MsFlags::MS_PRIVATE],
    )?;
    let root_filesystem_path = &config.root_filesystem_directory;
    let old_root_path = "oldrootfs";
    let old_root_absolute_path = PathBuf::from(format!("{root_filesystem_path}/{old_root_path}"));
    if let Err(e) = create_dir_all(&old_root_absolute_path) {
        println!("Failed to create directory to hold old root: {:?}", e);
        return Err(ContainerError::CreateDir);
    }

    if let Err(e) = pivot_root(&filesystem_path, &PathBuf::from(old_root_absolute_path)) {
        println!("Failed to pivot root: {:?}", e);
        return Err(ContainerError::PivotRoot);
    };
    if let Err(e) = umount2(
        &PathBuf::from(format!("/{old_root_path}")),
        MntFlags::MNT_DETACH,
    ) {
        println!("Failed to unmount: {:?}", e);
        return Err(ContainerError::Umount);
    }
    if let Err(e) = remove_dir(&PathBuf::from(format!("/{old_root_path}"))) {
        println!("Failed to remove directory: {:?}", e);
        return Err(ContainerError::RemoveDir);
    };

    if let Err(e) = chdir(&PathBuf::from("/")) {
        println!("Failed to change directory to: /. Error: {:?}", e);
        return Err(ContainerError::ChangeDir);
    };
    println!("Finished isolating filesystem!");
    Ok(())
}

// Wrapper around the mount syscall
fn mount_filesystem(
    filesystem_path: Option<&PathBuf>,
    target_directory: &PathBuf,
    flags: Vec<MsFlags>,
) -> ContainerResult {
    let mut mountflags = MsFlags::empty();
    for flag in flags {
        mountflags.insert(flag);
    }
    match mount::<PathBuf, PathBuf, PathBuf, PathBuf>(
        filesystem_path,
        target_directory,
        None,
        mountflags,
        None,
    ) {
        Ok(_) => Ok(()),
        Err(err) => {
            println!("Failed to mount directory. Error: {:?}", err);
            return Err(ContainerError::MountSysCall);
        }
    }
}

fn user_ns(config: &ChildConfig) -> ContainerResult {
    if let Err(e) = unshare(CloneFlags::CLONE_NEWUSER) {
        println!("Failed to unshare with new user namespace: {:?}", e);
        return Err(ContainerError::UnshareNewUser);
    }

    // Notifies the parent process that the child process has created a new user namespace
    socket_send(config.socket_fd)?;

    // Wait for the parent process to update the uid_map before setting the uid

    socket_recv(config.socket_fd)?;

    if let Some(user_id) = config.user_id {
        println!("Setting UID to: {:?}", config.user_id);
        if let Err(e) = setresuid(
            Uid::from_raw(user_id),
            Uid::from_raw(user_id),
            Uid::from_raw(user_id),
        ) {
            println!("Failed to set uid. Error: {:?}", e);
            return Err(ContainerError::SetResuid);
        };
    }

    Ok(())
}

static CAPABILITIES: phf::Map<&'static str, Capability> = phf_map! {
    "NET_BIND_SERVICE" => caps::Capability::CAP_NET_BIND_SERVICE,
    "SETUID" => caps::Capability::CAP_SETUID,
    "CAP_SYS_TIME" => caps::Capability::CAP_SYS_TIME,
};

fn capabilities(config: &ChildConfig) -> ContainerResult {
    println!("Setting capabilities");

    // compute the list of capabilities to add
    let caps_add: Vec<Capability> = match &config.cap_add {
        Some(cap_add) => {
            let mut res = vec![];
            for c in cap_add.iter() {
                println!("Adding c: {:?}", c);
                match CAPABILITIES.get(c) {
                    Some(c) => {
                        res.push(c.clone());
                    }
                    None => {
                        println!("Invalid capabiliy to raise: {:?}", c);
                        return Err(ContainerError::CapabilityAdd);
                    }
                }
            }
            res
        }
        None => vec![],
    };

    // if ALL is inside the capabilities to drop, then drop all capabilities except
    // for the ones inside capabilities to add
    if let Some(caps) = &config.cap_drop {
        if caps.contains(&String::from("ALL")) {
            let bounding_caps = caps::read(None, caps::CapSet::Bounding).unwrap();
            for cap in bounding_caps.iter() {
                if !caps_add.contains(cap) {
                    if let Err(e) = caps::drop(None, caps::CapSet::Bounding, *cap) {
                        println!("Failed to clear all capabilities. Error: {:?}", e);
                        return Err(ContainerError::CapabilityDrop);
                    }
                }
            }
        } else {
            for c in caps.iter() {
                match CAPABILITIES.get(c) {
                    Some(c) => {
                        if let Err(e) = caps::drop(None, caps::CapSet::Bounding, *c) {
                            println!("Failed to drop Capability: {:?}. Error: {:?}", *c, e);
                            return Err(ContainerError::CapabilityDrop);
                        }

                        if let Err(e) = caps::drop(None, caps::CapSet::Inheritable, *c) {
                            println!("Failed to drop Capability: {:?}. Error: {:?}", *c, e);
                            return Err(ContainerError::CapabilityDrop);
                        }
                    }
                    None => {
                        println!("Invalid capabiliy to drop: {:?}", c);
                        return Err(ContainerError::CapabilityDrop);
                    }
                }
            }
        }
    }

    for cap in caps_add.iter() {
        println!("Adding c: {:?}", cap);
        if let Err(e) = caps::raise(None, caps::CapSet::Inheritable, *cap) {
            println!("Failed to add Capability: {:?}. Error: {:?}", *cap, e);
            return Err(ContainerError::CapabilityAdd);
        }
        if let Err(e) = caps::raise(None, caps::CapSet::Ambient, *cap) {
            println!("Failed to add Capability: {:?}. Error: {:?}", *cap, e);
            return Err(ContainerError::CapabilityAdd);
        }
    }

    println!("Finished setting capabilities");

    Ok(())
}

const DISABLED_SYSCALLS: [Syscall; 9] = [
    Syscall::keyctl,
    Syscall::add_key,
    Syscall::request_key,
    Syscall::ptrace,
    Syscall::mbind,
    Syscall::migrate_pages,
    Syscall::set_mempolicy,
    Syscall::userfaultfd,
    Syscall::perf_event_open,
];

fn syscalls() -> ContainerResult {
    println!("Disabling syscalls!");

    let s_isuid: u64 = Mode::S_ISUID.bits().into();
    let s_isgid: u64 = Mode::S_ISGID.bits().into();
    let clone_newuser = CloneFlags::CLONE_NEWUSER.bits() as u64;

    // Each tuple: (SysCall, argument_idx, value). 0 would be the first argument index.
    let conditional_syscalls = [
        (Syscall::fchmod, 1, s_isuid),
        (Syscall::fchmod, 1, s_isgid),
        (Syscall::fchmodat, 2, s_isuid),
        (Syscall::fchmodat, 2, s_isgid),
        (Syscall::unshare, 0, clone_newuser),
        (Syscall::clone, 0, clone_newuser),
        // TODO: ioctl causes an error when running /bin/ash somehow...
        // (Syscall::ioctl, 1, TIOCSTI),
    ];
    match Context::init_with_action(Action::Allow) {
        Ok(mut ctx) => {
            for syscall in DISABLED_SYSCALLS {
                if let Err(err) = ctx.set_action_for_syscall(Action::Errno(0), syscall) {
                    println!("Failed to disable syscall: {:?}. Error: {:?}", syscall, err);
                    return Err(ContainerError::DisableSyscall);
                };
            }

            for (syscall, arg_idx, bit) in conditional_syscalls {
                if let Err(err) = ctx.set_rule_for_syscall(
                    Action::Errno(1000),
                    syscall,
                    &[Comparator::new(arg_idx, Cmp::MaskedEq, bit, Some(bit))],
                ) {
                    println!("Failed to disable syscall: {:?}. Error: {:?}", syscall, err);
                    return Err(ContainerError::DisableSyscall);
                }
            }

            if let Err(err) = ctx.load() {
                println!("Failed to load syscall disabling: {:?}", err);
                return Err(ContainerError::DisableSyscall);
            };
        }
        Err(err) => {
            println!("Failed to open seccomp context: {:?}", err);
            return Err(ContainerError::DisableSyscall);
        }
    }

    println!("Finished disabling syscalls!");
    Ok(())
}

fn handle_child_uid_map(pid: Pid, fd: i32, user_id: Option<u32>) -> ContainerResult {
    // Wait for the user to create a user namespace
    socket_recv(fd)?;

    let _user_id = match user_id {
        Some(id) => id,
        None => 0, // default to run as root if no user ID is provided
    };

    println!("Updating uid_map");
    match File::create(format!("/proc/{}/{}", pid.as_raw(), "uid_map")) {
        Ok(mut uid_map) => {
            if let Err(e) = uid_map.write_all(format!("0 {} {}", 1000, 1000).as_bytes()) {
                println!("Failed to write to uid_map. Error: {:?}", e);
                return Err(ContainerError::UidMap);
            }
        }
        Err(e) => {
            println!("Failed to create uid_map. Error: {:?}", e);
            return Err(ContainerError::UidMap);
        }
    }

    match File::create(format!("/proc/{}/{}", pid.as_raw(), "gid_map")) {
        Ok(mut uid_map) => {
            if let Err(e) = uid_map.write_all(format!("0 {} {}", 1000, 1000).as_bytes()) {
                println!("Failed to write to uid_map. Error: {:?}", e);
                return Err(ContainerError::UidMap);
            }
        }
        Err(e) => {
            println!("Failed to create uid_map. Error: {:?}", e);
            return Err(ContainerError::UidMap);
        }
    }

    println!("Finished updating uid_map. Notifying child process");

    // Notify the user that the uid_map is updated
    socket_send(fd)?;
    Ok(())
}

fn resources(config: &ChildConfig, pid: Pid) -> ContainerResult {
    println!("Restricting resource!");
    let mut cg_builder = CgroupBuilder::new(&config.hostname);
    if let Some(memory_limit) = config.memory {
        println!("Setting memory limit to: {:?}", memory_limit);

        cg_builder = cg_builder.memory().memory_hard_limit(memory_limit).done();
    }
    if let Some(max_pids) = config.max_pids {
        println!("Setting max pids to: {:?}", max_pids);
        cg_builder = cg_builder
            .pid()
            .maximum_number_of_processes(cgroups_rs::MaxValue::Value(max_pids))
            .done();
    }

    let cg = cg_builder.build(Box::new(V2::new()));

    let pid: u64 = pid.as_raw() as u64;

    if let Err(e) = cg.add_task(CgroupPid::from(pid)) {
        println!("Failed to add task to cgroup. Error: {:?}", e);
        return Err(ContainerError::CgroupPidErr);
    };

    Ok(())
}

fn create_socketpair() -> Result<(OwnedFd, OwnedFd), ContainerError> {
    match socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    ) {
        Ok((first, second)) => Ok((first, second)),
        Err(_) => Err(ContainerError::CreateSocketErr),
    }
}

pub fn socket_send(fd: RawFd) -> ContainerResult {
    if let Err(e) = send(fd, &vec![], MsgFlags::empty()) {
        println!("Socket failed to send. Error: {:?}", e);
        return Err(ContainerError::SocketSend);
    };
    Ok(())
}

pub fn socket_recv(fd: RawFd) -> ContainerResult {
    if let Err(e) = recv(fd, &mut vec![0, 0], MsgFlags::empty()) {
        println!("Socket failed to receive. Error: {:?}", e);
        return Err(ContainerError::SocketRecv);
    }
    Ok(())
}

fn run() -> ContainerResult {
    let cli = Cli::parse();

    let split_command = cli.command.split(" ").collect::<Vec<&str>>();
    assert!(split_command.len() > 0);

    let (child_socket, parent_socket) = create_socketpair()?;
    println!(
        "Parent socket: {:?}. Child socket: {:?}",
        parent_socket, child_socket
    );
    let config = ChildConfig {
        pid: 0,
        exec_path: CString::new(split_command[0]).unwrap(),
        args: split_command
            .iter()
            .map(|c| CString::new(*c).unwrap())
            .collect(),
        memory: cli.memory,
        socket_fd: child_socket.as_raw_fd(),
        root_filesystem_directory: cli.root_filesystem_path,
        hostname: generate_random_hostname(),
        max_pids: cli.nproc,
        user_id: cli.user,
        cap_add: cli.cap_add,
        cap_drop: cli.cap_drop,
    };
    println!("Config: {:?}", config);

    let child_pid = create_child_process(&config)?;
    resources(&config, child_pid)?;

    handle_child_uid_map(child_pid, parent_socket.as_raw_fd(), config.user_id.clone())?;
    if let Err(e) = waitpid(child_pid, None) {
        println!("Error waiting for pid: {:?}", e);
        return Err(ContainerError::WaitPid);
    };
    Ok(())
}

fn cleanup() {
    todo!()
}

fn main() {
    if let Err(_) = run() {
        cleanup();
        exit(-1);
    }
}
