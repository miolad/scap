use thiserror::Error;

#[derive(Error, Debug)]
pub enum InitError {
    #[error("Libbpf error")]
    Libbpf(#[from] libbpf_rs::Error),

    // #[error("Error reading from the BPF iterator: {}", .0)]
    // BpfIterRead(std::io::Error),

    #[error("Error retrieving the Cgroup mount point: {}", .0)]
    Cgroup(String),

    #[error("Error instantiating async runtime")]
    AsyncRuntime(std::io::Error)
}
