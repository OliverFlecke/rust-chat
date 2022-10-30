use derive_getters::Getters;
use serde::{Deserialize, Serialize};

use crate::x3dh::PublishingKey;

#[derive(Serialize, Deserialize, Getters)]
pub struct Register {
    username: String,
    key_info: PublishingKey,
}

impl Register {
    pub fn new(username: String, key_info: PublishingKey) -> Self {
        Register { username, key_info }
    }
}

#[derive(Serialize, Deserialize, Getters)]
pub struct RegisterResponse {
    id: String,
}

impl RegisterResponse {
    pub fn new(id: String) -> Self {
        RegisterResponse { id }
    }
}
