use chat_core::LoginMessage;
use dryoc::rng::randombytes_buf;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use uuid::Uuid;
use warp::ws::{Message, WebSocket};

use crate::Users;

#[derive(Debug)]
pub enum LoginError {
    UnableToSentNonce,
    UserNotFound,
    InvalidSignature,
    InvalidNonce,
}

pub async fn handle_login(
    users: &Users,
    user_tx: &mut SplitSink<WebSocket, Message>,
    user_rx: &mut SplitStream<WebSocket>,
) -> Result<Uuid, LoginError> {
    const NONCE_SIZE: usize = 24;
    let nonce = randombytes_buf(NONCE_SIZE);
    user_tx
        .send(Message::binary(nonce.clone()))
        .await
        .map_err(|_| LoginError::UnableToSentNonce)?;

    println!("Wating for login message");
    // Read messages from user channel until a valid auth message has been received.
    // Maybe this should only listen for one message or timeout after a short while.
    while let Some(Ok(msg)) = user_rx.next().await {
        if let Ok(msg) = serde_json::from_slice::<LoginMessage>(msg.as_bytes()) {
            if let Some(user) = users.read().await.get(msg.id()) {
                match user.key_info.verify(msg.signature()) {
                    Ok(msg) if nonce.eq(&msg[..NONCE_SIZE]) => return Ok(*user.id()),
                    Ok(_) => return Err(LoginError::InvalidNonce),
                    Err(_) => return Err(LoginError::InvalidSignature),
                }
            } else {
                return Err(LoginError::UserNotFound);
            }
        }
    }

    unreachable!()
}
