use std::{collections::HashMap, sync::Arc};

use chat_core::{requests::ProfileResponse, x3dh::PublishingKey};
use derive_getters::Getters;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;
use warp::ws::Message;

pub mod chat;
pub mod login;
pub mod services;

pub type Users = Arc<RwLock<HashMap<Uuid, User>>>;

#[derive(Debug, Clone, Getters)]
pub struct User {
    id: Uuid,
    username: String,
    key_info: PublishingKey,
    tx: Option<mpsc::UnboundedSender<Message>>,
}

impl User {
    pub fn new(id: Uuid, username: String, key_info: PublishingKey) -> Self {
        User {
            id,
            username,
            key_info,
            tx: None,
        }
    }

    /// Sent the transmit channel for this user.
    pub fn set_tx(&mut self, tx: mpsc::UnboundedSender<Message>) {
        self.tx = Some(tx);
    }

    /// Get this users key info as mutable.
    pub fn key_info_mut(&mut self) -> &mut PublishingKey {
        &mut self.key_info
    }
}

impl From<&User> for ProfileResponse {
    fn from(user: &User) -> Self {
        ProfileResponse::new(
            user.id().to_owned(),
            user.username().to_owned(),
            Vec::from(*user.key_info().get_public_identity_key_as_slice()),
        )
    }
}
