use derive_getters::Getters;
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use orion::kex::PublicKey;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio::{
    sync::{mpsc, RwLock},
    task::spawn,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;
use warp::{
    hyper::StatusCode,
    ws::{Message, WebSocket},
    Filter,
};

type Users = Arc<RwLock<HashMap<Uuid, User>>>;

#[derive(Serialize, Deserialize)]
struct Register {
    username: String,
    public_key: [u8; 32],
}

#[tokio::main]
async fn main() {
    let users = Users::default();
    let user_filter = warp::any().map(move || users.clone());

    // POST /register
    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::json())
        .and(user_filter.clone())
        .and_then(register_user);

    let stream = warp::path("stream")
        .and(warp::ws())
        .and(user_filter.clone())
        .map(|ws: warp::ws::Ws, users| ws.on_upgrade(move |socket| on_connection(socket, users)));

    let server = register.or(stream);

    println!("Starting server at 127.0.0.1:3030");
    warp::serve(server).run(([127, 0, 0, 1], 3030)).await;
}

async fn register_user(register: Register, users: Users) -> Result<impl warp::Reply, Infallible> {
    match PublicKey::from_slice(&register.public_key) {
        Ok(public_key) => {
            let id = Uuid::new_v4();
            users.write().await.insert(
                id,
                User {
                    id,
                    public_key,
                    tx: None,
                },
            );

            println!("User {} registered", id);

            Ok(warp::reply::with_status(id.to_string(), StatusCode::OK))
        }
        Err(_) => Ok(warp::reply::with_status(
            "public_key must be a 32 byte array".to_string(),
            StatusCode::BAD_REQUEST,
        )),
    }
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

    if let Some(user) = users.write().await.get_mut(&id) {
        user.tx = Some(tx);
    }

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

    users
        .read()
        .await
        .iter()
        .filter(|(&id, _)| id != sender_id)
        .for_each(|(_, user)| send(text.to_string(), user))
}

async fn _send_message(receiver: Uuid, message: Message, users: &Users) {
    let text = match message.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };

    if let Some(user) = users.read().await.get(&receiver) {
        send(text.to_string(), user);
    }
}

fn send(text: String, user: &User) {
    if let Some(tx) = &user.tx {
        if let Err(_disconnected) = tx.send(Message::text(text)) {}
    } else {
        eprintln!("No socket to client");
    }
}

#[derive(Debug, Getters)]
pub struct User {
    id: Uuid,
    public_key: PublicKey,
    tx: Option<mpsc::UnboundedSender<Message>>,
}
