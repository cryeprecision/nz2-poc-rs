use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Nz2 {
    pub nz2_version: String,
    pub encryption: Encryption,
    pub files: Vec<File>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum Algorithm {
    #[serde(rename = "ChaCha20-Poly1305-IETF")]
    ChaCha20Poly1305,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Encryption {
    pub algorithm: Algorithm,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct File {
    pub path: String,
    pub key: String,
    pub last_modified: Option<u64>,
    pub file_size: u64,
    pub segment_size: u64,
}
