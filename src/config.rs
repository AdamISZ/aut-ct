use serde_derive::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct AutctConfig {
    pub version: u8,
    pub keyset: String,
    pub context_label: String,
    pub depth: i32,
    pub branching_factor: i32,
    pub generators_length_log_2: u8,
    pub rpc_port: i32
}

impl ::std::default::Default for AutctConfig {
    fn default() -> Self { Self {
    version: 0, keyset: "default".to_string(),
    context_label: "autct-default".to_string(),
    depth: 2,
    branching_factor: 256, // currently not used, TODO
    generators_length_log_2: 11,
    rpc_port: 23333 } }
}
