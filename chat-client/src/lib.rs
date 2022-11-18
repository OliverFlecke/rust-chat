use chat_core::x3dh::KeyStore;
use derive_getters::Getters;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

pub mod chat;
pub mod setup;
pub mod user_data;
mod server_api;

/// Represents the local side of the user.
#[derive(Debug, Getters, Serialize, Deserialize)]
pub struct User {
    id: Uuid,
    username: String,
    keystore: KeyStore,
}

impl User {
    pub fn keystore_mut(&mut self) -> &mut KeyStore {
        &mut self.keystore
    }
}

#[derive(Debug, Getters)]
pub struct Server {
    pub host: String,
}
