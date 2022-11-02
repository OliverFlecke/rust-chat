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
        .for_each(|(_, user)| send(text.to_string(), user))
}

pub async fn _send_message(receiver: Uuid, message: Message, users: &Users) {
    let text = match message.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };

    if let Some(user) = users.read().await.get(&receiver) {
        send(text.to_string(), user);
    }
}

pub fn send(text: String, user: &User) {
    if let Some(tx) = &user.tx() {
        if let Err(_disconnected) = tx.send(Message::text(text)) {}
    } else {
        eprintln!("Unable to send message: No socket to client");
    }
}
