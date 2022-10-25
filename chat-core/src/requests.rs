use derive_getters::Getters;
use orion::kex::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Getters)]
pub struct Register {
    username: String,
    public_key: PublicKey,
}

impl Register {
    pub fn new(username: String, public_key: PublicKey) -> Self {
        Register {
            username,
            public_key,
        }
    }
}

#[derive(Serialize, Deserialize, Getters)]
pub struct RegisterResponse {
    id: String,
    server_public_key: PublicKey,
}

impl RegisterResponse {
    pub fn new(id: String, server_public_key: PublicKey) -> Self {
        RegisterResponse {
            id,
            server_public_key,
        }
    }
}
