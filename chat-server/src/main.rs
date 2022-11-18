use chat_core::requests::PreKeyBundleRequest;
use chat_server::{
    chat::forward_message,
    login::handle_login,
    services::{
        get_pre_key_bundle_for_user, response_error_handler,
        user::{get_user_profile_by_id, register_user},
    },
    Users,
};
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use listenfd::ListenFd;
use std::convert::Infallible;
use tokio::{
    sync::mpsc::{self, UnboundedReceiver},
    task::spawn,
};
use tokio_stream::wrappers::UnboundedReceiverStream;
use uuid::Uuid;
use warp::{
    hyper::{self, Server},
    ws::{Message, WebSocket},
    Filter,
};

#[tokio::main]
async fn main() {
    let users = Users::default();
    let user_filter = warp::any().map(move || users.clone());

    // POST /register
    let register = warp::post()
        .and(warp::path("register"))
        .and(warp::body::content_length_limit(16384)) // 2^14
        .and(warp::body::json())
        .and(user_filter.clone())
        .and_then(register_user);

    // POST /keys/user
    let get_user_key = warp::post()
        .and(warp::path!("keys" / "user"))
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::json())
        .and(user_filter.clone())
        .and_then(|request: PreKeyBundleRequest, users| async move {
            match get_pre_key_bundle_for_user(request, users).await {
                Ok(x) => Ok(warp::reply::json(&x)),
                Err(x) => Err(warp::reject::custom(x)),
            }
        });

    // GET /user/:id
    let get_user_by_id_filter = warp::get()
        .and(warp::path("user"))
        .and(warp::path::param::<Uuid>())
        .and(user_filter.clone())
        .and_then(|id, users| async move {
            match get_user_profile_by_id(users, id).await {
                Ok(x) => Ok(warp::reply::json(&x)),
                Err(x) => Err(warp::reject::custom(x)),
            }
        });

    let chat = warp::path("chat")
        .and(warp::ws())
        .and(user_filter.clone())
        .map(|ws: warp::ws::Ws, users| ws.on_upgrade(move |socket| on_connection(socket, users)));

    let routes = chat
        .or(register)
        .or(get_user_key)
        .or(get_user_by_id_filter)
        .recover(response_error_handler);

    let service = warp::service(routes);
    let address = [127, 0, 0, 1];
    let port = 3030;
    // warp::serve(routes).run((address, port)).await;

    // Setup auto reload of server
    let make_svc = hyper::service::make_service_fn(|_: _| {
        let service = service.clone();
        async move { Ok::<_, Infallible>(service) }
    });
    let mut listenfd = ListenFd::from_env();
    let server = if let Some(l) = listenfd.take_tcp_listener(0).unwrap() {
        Server::from_tcp(l).unwrap()
    } else {
        Server::bind(&(address, port).into())
    };

    println!("Starting server at {address:?}:{port}");
    server.serve(make_svc).await.unwrap();
}

async fn on_connection(ws: WebSocket, users: Users) {
    let (mut user_tx, mut user_rx) = ws.split();
    let (tx, rx): (_, UnboundedReceiver<Message>) = mpsc::unbounded_channel();
    let mut rx = UnboundedReceiverStream::new(rx);

    let id = handle_login(&users, &mut user_tx, &mut user_rx)
        .await
        .expect("login to succeed");
    println!("User {id} connected and authorized!");

    // TODO: It should be possible to avoid spawning a new task.
    // Maybe this is a use case for `select!`
    spawn(async move {
        while let Some(message) = rx.next().await {
            user_tx
                .send(message)
                .unwrap_or_else(|e| eprintln!("Websocket send error: {}", e))
                .await;
        }
    });

    if let Some(user) = users.write().await.get_mut(&id) {
        user.set_tx(tx);
    }

    // Broadcast messages from this user to everyone else
    while let Some(result) = user_rx.next().await {
        // println!("Got message from {id}: {result:?}");
        let msg = match result {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("websocket error(uid={id}): {e}");
                break;
            }
        };

        if let Err(e) = forward_message(msg, &users).await {
            eprintln!("Failed to forward message: {e:?}");
        }
    }

    user_disconnected(id, &users).await;
}

/// Handles disconnection of users. Ensures they are removed from the list
/// of active users.
async fn user_disconnected(id: Uuid, users: &Users) {
    eprintln!("User disconnected: {id}");

    users.write().await.remove(&id);
}
