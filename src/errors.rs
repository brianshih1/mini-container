pub type ContainerResult = Result<(), ContainerError>;

pub enum ContainerError {
    CreateSocketErr,
    Clone,
    Execve,
    WaitPid,
    DisableSyscall,
    MountSysCall,
    PivotRoot,
    Umount,
    CreateDir,
    RemoveDir,
    ChangeDir,
    CgroupPidErr,
    UnshareNewUser,
    SocketSend,
    SocketRecv,
    UidMap,
    SetResuid,
    CapabilityDrop,
    CapabilityAdd,
}
