use std::{collections::HashMap, sync::Arc};

use futures_util::{SinkExt, StreamExt, TryFutureExt};
use tokio::{
    sync::{mpsc, RwLock},
    task::spawn,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;
use warp::{
    ws::{Message, WebSocket},
    Filter,
};

type Users = Arc<RwLock<HashMap<Uuid, mpsc::UnboundedSender<Message>>>>;

#[tokio::main]
async fn main() {
    let users = Users::default();
    let users = warp::any().map(move || users.clone());

    let server = warp::path("stream")
        .and(warp::ws())
        .and(users)
        .map(|ws: warp::ws::Ws, users| ws.on_upgrade(move |socket| on_connection(socket, users)));

    println!("Starting server at 127.0.0.1:3030");
    warp::serve(server).run(([127, 0, 0, 1], 3030)).await;
}

async fn on_connection(ws: WebSocket, users: Users) {
    let id = Uuid::new_v4();
    println!("User {id} connected");

    let (mut user_tx, mut user_rx) = ws.split();
    let (tx, rx) = mpsc::unbounded_channel();
    let mut rx = UnboundedReceiverStream::new(rx);

    spawn(async move {
        while let Some(message) = rx.next().await {
            user_tx
                .send(message)
                .unwrap_or_else(|e| eprintln!("Websocket send error: {}", e))
                .await;
        }
    });

    users.write().await.insert(id, tx);

    // Broadcast messages from this user to everyone else
    while let Some(result) = user_rx.next().await {
        let msg = match result {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("websocket error(uid={id}): {e}");
                break;
            }
        };
        broadcast_message(id, msg, &users).await;
    }

    user_disconnected(id, &users).await;
}

/// Handles disconnection of users. Ensures they are removed from the list
/// of active users.
async fn user_disconnected(id: Uuid, users: &Users) {
    eprintln!("User disconnected: {id}");

    users.write().await.remove(&id);
}

/// Broadcast a message to every other user in the `Users` group.
async fn broadcast_message(sender_id: Uuid, message: Message, users: &Users) {
    let text = match message.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };
    println!("Broadcasting message: {text}");

    // let new_msg = format!("<user#{sender_id}>: {text}");

    users
        .read()
        .await
        .iter()
        .filter(|(&id, _)| id != sender_id)
        .for_each(
            |(_, tx)| {
                if let Err(_disconnected) = tx.send(Message::text(text.clone())) {}
            },
        )
}
