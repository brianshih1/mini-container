# API

Before we talk about the theory of and implementation behind containers, let’s first look at the API for my toy container.

At the core, the `mini-container` program takes two arguments: an executable program and a directory that points to a root filesystem. It creates a process, sets up the container environment for the process, and executes the executable program in this container.

Here are the arguments and options to execute my toy container.

```
mini-container [OPTIONS] <PATH_TO_EXECUTABLE> <ROOT_FILESYSTEM_PATH>
```

**Arguments:**

- `<COMMAND>`                           Command to execute
- `<ROOT_FILESYSTEM_PATH>`  Absolute path to the new root filesystem

**Options:** 

`-p, --pid <PID>`                   Set the pid for child process 

`-m, --memory <MEMORY>`       Memory limit (megabytes)

 `--nproc <NPROC>`                 Max pids allowed 

`-u, --user <USER>`              Set the User ID for child process 

`--cap-add <CAP_ADD>`          Add Linux capabilities to the container environment

`--cap-drop <CAP_DROP>`      Drop Linux capabilities to the container environment. Specify “ALL” to drop all

`-h, --help` 

## Examples

### **Running an interactive bash shell**

To run an interactive bash shell in the container environment, you first need to set up a directory that will serve as the root filesystem for the container. This is equivalent to an image in Docker, which contains a minimal OS. For all my demos, I will be using [Alpine’s Mini Root Filesystem image](https://alpinelinux.org/downloads/).

First, we download the image and extract it into the `alpine` directory.

```bash
cd /home/brianshih
# download the alpine image
wget <https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.0-aarch64.tar.gz>
# create the new_root directory
mkdir alpine
# extract the alpine image into the new_root directory
tar -xvf alpine-minirootfs-3.19.0-aarch64.tar.gz -C alpine
```

Next, we can launch the container and execute `/bin/ash`. Note that the `alpine` directory will become the new root filesystem.

```bash
sudo target/debug/mini-container /bin/ash /home/brianshih/alpine
```

Here is the rough equivalent command in docker:

```bash
docker exec -it alpine bash
```

### **Limiting resources in the container**

You can run a container with limited memory and limited process capacity via the `--nproc` and `--memory` options.

```bash
sudo target/debug/mini-container /bin/ash /home/brianshih/alpine 
	--nproc 5 --memory 1048
```

Here is the rough equivalent command in docker - though unlike my implementation, `nproc` in Docker sets the maximum number of processes available to a user, not to a container.

```bash
docker run --memory="1048m" --ulimit nproc=5 IMAGE
```

### **Dropping and Adding Linux Capabilities**

Here is how you can drop all the Linux capabilities and add the `NET_BIND_SERVICE` capability. Note that for my toy implementation, I only support 3 capabilities (so far). It’s extremely trivial to add them but my goal isn’t to build a production-level container so I stopped whenever I felt like I understood how they work.

```bash
sudo target/debug/mini-container /bin/ash /home/brianshih/alpine 
	--cap-drop ALL 
	--cap-add NET_BIND_SERVICE
```

Here is the rough equivalent command in docker:

```bash
docker run --cap-drop all --cap-add NET_BIND_SERVICE alpine
```

### **Setting the User ID**

Here is how you can set the user ID for the process.

```bash
sudo target/debug/mini-container /bin/ash /home/brianshih/alpine --user 0
```

Here is the rough equivalent command in docker:

```bash
docker run --rm --user $UID:$GID alpine ash
```
