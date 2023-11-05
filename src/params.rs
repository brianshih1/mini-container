use std::ffi::{CStr, CString};

#[derive(Debug)]
pub struct ContainerParams {
    // The pid of the child process
    pub pid: u32,

    // Path to executable file
    pub exec_path: CString,

    // Arguments for the command
    pub args: Vec<CString>,

    // Memory limit of container (megabytes)
    pub memory: Option<u32>,
}
