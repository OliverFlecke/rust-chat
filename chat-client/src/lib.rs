use chat_core::x3dh::KeyStore;
use derive_getters::Getters;

pub mod chat;
pub mod setup;

/// Represents the local side of the user.
#[derive(Debug, Getters)]
pub struct User {
    id: String,
    username: String,
    session: KeyStore,
}

#[derive(Debug, Getters)]
pub struct Server {
    host: String,
}
