use chat_core::Msg;
use uuid::Uuid;
use warp::ws::Message;

use crate::{User, Users};

/// Broadcast a message to every other user in the `Users` group.
pub async fn broadcast_message(sender_id: Uuid, message: Message, users: &Users) {
    let text = match message.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };
    println!("Broadcasting message: {text}");

    users
        .read()
        .await
        .iter()
        .filter(|(&id, _)| id != sender_id)
        .for_each(|(_, user)| send_text(text.to_string(), user))
}

/// Forward a message to its intended receiver.
/// TODO: Implement concret error type
pub async fn forward_message(message: Message, users: &Users) -> Result<(), String> {
    // Convert message to internal `Msg` to get intended receiver
    let msg = serde_json::from_slice::<Msg>(message.as_bytes())
        .map_err(|_| "received message to be `Msg`")?;
    println!("Message for {}", msg.receiver());

    if let Some(user) = users.read().await.get(msg.receiver()) {
        if let Some(tx) = &user.tx() {
            tx.send(message)
                .map_err(|_| "failed to send message".to_string())
        } else {
            Err("Unable to send message".to_string())
        }
    } else {
        Err("User not found".to_string())
    }
}

pub async fn _send_message_text(receiver: Uuid, message: Message, users: &Users) {
    let text = match message.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };

    if let Some(user) = users.read().await.get(&receiver) {
        send_text(text.to_string(), user);
    }
}

pub fn send_text(text: String, user: &User) {
    if let Some(tx) = &user.tx() {
        if let Err(_disconnected) = tx.send(Message::text(text)) {}
    } else {
        eprintln!("Unable to send message: No socket to client");
    }
}
