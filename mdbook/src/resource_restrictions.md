# Resource Restrictions

### Goal

We want to limit and isolate resource usage such as CPU, memory, disk I/O, network, etc in a container.

### Theory

[Cgroups](https://man7.org/linux/man-pages/man7/cgroups.7.html) is a Linux kernel feature that allows developers to control how much of a given key resource (CPU, memory, etc) a process or a set of processes can access.

According to the [Linux doc](https://man7.org/linux/man-pages/man7/cgroups.7.html), the grouping of processes is provided through a pseudo-filesystem called `cgroupfs`. A cgroup is a collection of processes bound to a set of limits defined via the cgroup filesystem.

Each cgroup has a kernel component called a *subsystem*, also known as a resource controller.

Different subsystems limit different resources, such as the CPU time and memory available to a cgroup. To create a cgroup, you create a directory inside the `cgroup` filesystem:

```
mkdir /sys/fs/cgroup/cg1
```

Each file inside the `cgroup` directory corresponds to a different resource that can be limited. For example, the `cgroup` below contains files such as `memory.max` which limits the memory a cgroup can access.

```bash
ls /sys/fs/cgroup/cg1
# cgroup.controllers      cpuset.cpus.partition  memory.max
# cgroup.events           cpuset.mems            memory.min
# cgroup.freeze           cpuset.mems.effective  memory.numa_stat
# cgroup.kill             cpu.stat               memory.oom.group
# cgroup.max.depth        cpu.uclamp.max         memory.peak
# cgroup.max.descendants  cpu.uclamp.min         memory.pressure
# cgroup.pressure         cpu.weight             memory.reclaim
# ... many more
```

### Demo

In this demo (inspired by Michael Kerrisk’s [tech talk](https://man7.org/conf/ndctechtown2021/cgroups-v2-part-1-intro-NDC-TechTown-2021-Kerrisk.pdf)), we will create a cgroup and set `pids.max` to 5 and confirm that the process can only run 5 tasks at max.

```bash
sudo bash
cd /sys/fs/cgroup/
# we create a cgroup called foo
mkdir foo

# add the current process to the created cgroup
echo $$ > foo/cgroup.procs

# confirm that the current process belongs to the foo cgroup
cat /proc/$$/cgroup
# 0::/foo

# set the maximum number of tasks at once
echo 5 > /sys/fs/cgroup/foo/pids.max

for i in {1..5}; do sleep 1 & done
# [1] 8379
# [2] 8380
# [3] 8381
# [4] 8382
# bash: fork: retry: Resource temporarily unavailable
```

After creating a new `cgroup` called `foo` and adding the process into that cgroup, we set `pids.max` to `5`. Next, we execute `for i in {1..5}; do sleep 1 & done` and see that when the process tries to run the 5th `sleep 1`, it errors out as the process cannot create 5 processes.

### Implementation

There are many resources that we can choose to limit. For my toy container implementation, I will only limit the `memory` and `max_pids`. In the implementation, we will use the [cgroup-rs](https://crates.io/crates/cgroups-rs) crate, a Rust library for managing cgroups.

Note that limiting the resources is performed by the parent process after the child process is created. This is because we need the child process’s `pid` so that we can add it to the `cgroup`.

```rust
fn run() -> ContainerResult {
    ...
    let child_pid = create_child_process(&config)?;
    resources(&config, child_pid)?;
    ...
}
```

The code for limiting resources is simple. We create a new `cgroup` with the `config.hostname` as its name. We then write to the corresponding resource’s file before adding the `pid` to the created `cgroup`.

```rust
fn resources(config: &ChildConfig, pid: Pid) -> ContainerResult {
    println!("Restricting resource!");
    let mut cg_builder = CgroupBuilder::new(&config.hostname);
    if let Some(memory_limit) = config.memory {
        println!("Setting memory limit to: {:?}", memory_limit);

        cg_builder = cg_builder.memory().memory_hard_limit(memory_limit).done();
    }
    if let Some(max_pids) = config.max_pids {
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
```

### Testing the Implementation

This is the code snippet we will use to test whether limiting the number of pids in a cgroup works. This is basically a Rust implementation of our demo earlier: `for i in {1..5}; do sleep 1 & done`.

```rust
use std::thread;
use std::time::Duration;

fn main() {
    for i in 1..=5 {
        thread::spawn(move || {
            println!("Thread {} started", i);
            thread::sleep(Duration::from_secs(1));
            println!("Thread {} completed", i);
        });
    }

    // Sleep for a while to allow threads to finish.
    thread::sleep(Duration::from_secs(2));
}
```

When we run the executable, we get a `Resource temporarily unavailable` message. If we examine the hostname and check `/sys/fs/cgroup/mini-JoYUGNc/pids.max`, we can see that it’s `5`. We can also check which `cgroup` the child process is to verify that it’s added to the `cgroup` correctly.

```bash
sudo target/debug/mini-container /sleep_test /home/brianshih/alpine 
		--nproc 5
# thread 'main' panicked at 'failed to spawn thread: Os 
# { code: 11, kind: WouldBlock, message: "Resource temporarily unavailable" }

hostname
# hostname of child process: mini-JoYUGNc

# host system
cat /sys/fs/cgroup/mini-JoYUGNc/pids.max
# 5

# pid of child process is 8428
cat /proc/8428/cgroup
# 0::/mini-OhMDCDW
```

Next, we run the same command without the `--nproc 5` option:

```rust
sudo target/debug/mini-container /sleep_test /home/brianshih/alpine 
```

This time, it ran successfully, confirming that our cgroup implementation worked.

### Additional Resources

[Blog: What are Namespaces and cgroups?](https://www.nginx.com/blog/what-are-namespaces-cgroups-how-do-they-work/)

[Blog: Deep into Containers (Namespace & CGroups)](https://faun.pub/kubernetes-story-linux-namespaces-and-cgroups-what-are-containers-made-from-d544ac9bd622)
