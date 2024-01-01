# Project Overview

Here is the higher-level setup for this project:

- parse the command line argument
- create the child process
- setup the namespaces, capabilities, and syscalls restrictions
- executing the program

### Parse the command line argument

To parse the command line arguments, we use the [clap crate](https://crates.io/crates/clap). Here is the struct representation of the parsed arguments:

```rust
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
```

The entry point of the project is the `run` method. All we have to do is call `Cli::parse()` to parse the arguments

```rust
fn main() {
    if let Err(_) = run() {
        cleanup();
        exit(-1);
    }
}

fn run() -> ContainerResult {
    let cli = Cli::parse();
	  ...
}
```

### Create the child process

Since a container is just a process, we need to create the child process for the container. The `create_child_process` function is responsible for that.

```rust
fn run() -> ContainerResult {
    let cli = Cli::parse();

	  ...
    let child_pid = create_child_process(&config)?;
    if let Err(e) = waitpid(child_pid, None) {
        return Err(ContainerError::WaitPid);
    };
    Ok(())
}
```

After creating the child process, we need to make sure the parent process doesn't terminate until the child process completes. We use the [waitpid](https://linux.die.net/man/2/waitpid) call to make sure of that.

Here is the implementation for `create_child_process`:

```rust
// Creates a child process with clone and runs the executable file
// with execve in the child process.
fn create_child_process(config: &ChildConfig) -> Result<Pid, ContainerError> {
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
```

It uses `clone` to create the child process. It clones with a bunch of flags such as `CLONE_NEWNS`, `CLONE_NEWPID`, etc in order to create the different namespaces (user, mount, pid, etc) necessary for isolation. We will cover these namespaces in more detail later.

The Linux [clone](https://man7.org/linux/man-pages/man2/clone.2.html) method takes a function argument. When the function returns, the child process terminates. The function we pass to clone is the `child` method whose responsibility is to set up the container environment and execute the user-provided program.

### Setup the namespaces, capabilities, and syscalls restrictions & Executing the program

Here is the implementation of `child`:

```rust
// setup the namespaces, capabilities, syscall restrictions before running the executable
fn child(config: &ChildConfig) -> ContainerResult {
    set_hostname(config)?;
    isolate_filesystem(config)?;
    user_ns(config)?;
    capabilities(config)?;
    syscalls()?;
    match execve::<CString, CString>(&config.exec_path, &config.args, &[]) {
        Ok(_) => Ok(()),
        Err(e) => {
            println!("Failed to execute!: {:?}", e);
            Err(ContainerError::Execve)
        }
    }
}
```

Before using `execve` to execute the user-provided program, we set up the container environment for the execution by isolating the filesystem, setting up the user namespace, granting and taking away capabilities, and restricting syscalls.

### Summary

To summarize, the project contains these core methods:

- **run**: parses the command line arguments. Creates the child process and waits until the child process terminates
- **create_child_process**: uses clone to create the child process. Pass in the `child` as the function argument to `clone`
- **child**: sets up the container environment before executing the user-provided program with `execve`

For the rest of this blog, we will focus on learning how we can set up the container environment for the process. For each component of the container environment, we will break it down into:

- Goal
- Theory
- Demo
- Implementation
- Testing the Implementation
