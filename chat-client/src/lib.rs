use derive_getters::Getters;
use orion::kex::{EphemeralClientSession, PublicKey};

pub mod chat;
pub mod setup;

/// Represents the local side of the user.
#[derive(Debug, Getters)]
pub struct User {
    id: String,
    username: String,
    session: EphemeralClientSession,
}
#[derive(Debug, Getters)]
pub struct Server {
    host: String,
    public_key: PublicKey,
}
