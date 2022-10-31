use derive_getters::Getters;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
    id: Uuid,
}

impl RegisterResponse {
    pub fn new(id: Uuid) -> Self {
        RegisterResponse { id }
    }
}
