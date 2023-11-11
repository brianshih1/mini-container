pub type ContainerResult = Result<(), ContainerError>;

pub enum ContainerError {
    CreateSocketErr,
    CloneErr,
}
