use chat_core::x3dh::KeyStore;
use derive_getters::Getters;
use uuid::Uuid;

pub mod chat;
pub mod setup;

/// Represents the local side of the user.
#[derive(Debug, Getters)]
pub struct User {
    id: Uuid,
    username: String,
    keystore: KeyStore,
}

#[derive(Debug, Getters)]
pub struct Server {
    pub host: String,
}
