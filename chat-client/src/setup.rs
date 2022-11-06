use std::sync::Arc;

use chat_core::{
    requests::{PreKeyBundleRequest, Register, RegisterResponse},
    x3dh::{KeyStore, PreKeyBundle, PublishingKey},
    LoginMessage,
};
use tokio::sync::Mutex;
use uuid::Uuid;
use websockets::{WebSocket, WebSocketReadHalf, WebSocketWriteHalf};

use crate::{Server, User};

/// Connect through a websocket and authenticate the given user.
pub async fn connect_and_authenticate(
    server: &Server,
    user: &User,
) -> Result<
    (
        Arc<Mutex<WebSocketReadHalf>>,
        Arc<Mutex<WebSocketWriteHalf>>,
    ),
    (),
> {
    let (rx, tx) = WebSocket::connect(&format!("ws://{server}/chat", server = server.host()))
        .await
        .unwrap()
        .split();
    let tx = Arc::new(Mutex::new(tx));
    let rx = Arc::new(Mutex::new(rx));

    if let Ok(frame) = rx.lock().await.receive().await {
        let (nonce, _, _) = frame.as_binary().expect("nonce to be sent first by server");

        // Must be a better way to combine these two slices
        let mut content = Vec::new();
        content.extend_from_slice(nonce);
        content.extend_from_slice(user.username().as_bytes());

        let msg = LoginMessage::new(user.id().clone(), user.keystore().sign(&content));
        tx.lock()
            .await
            .send_binary(serde_json::to_vec(&msg).unwrap())
            .await
            .expect("login message to be sent");
    } else {
        unreachable!()
    }

    Ok((rx, tx))
}

// TODO: Write test for the register method.
//  - How can `reqwest` be mocked to generate responses during test?

/// Register the user at the server with the given username.
pub async fn register(username: String, server: &String) -> Result<User, ()> {
    let keystore = KeyStore::gen();
    let res_body = post_register(&username, PublishingKey::from(keystore.clone()), server)
        .await
        .expect("register to succeed");

    let res: RegisterResponse =
        serde_json::from_str(res_body.as_str()).expect("response to be valid");

    let user = User {
        id: res.id().to_owned(),
        username,
        keystore,
    };

    Ok(user)
}

/// Register a user on the server.
async fn post_register(
    username: &String,
    publishing_key: PublishingKey,
    server: &String,
) -> Result<String, ()> {
    match reqwest::Client::new()
        .post(format!("http://{server}/register"))
        .body(serde_json::to_string(&Register::new(username.to_owned(), publishing_key)).unwrap())
        .send()
        .await
    {
        Ok(r) => match r.text().await {
            Ok(id) => Ok(id),
            Err(_) => {
                eprintln!("No user id");
                Err(())
            }
        },
        Err(e) => {
            eprintln!("{:?}", e);
            Err(())
        }
    }
}

/// POST a request for a pre-key bundle for another user.
pub async fn post_request_pre_bundle_for_user(
    server: &String,
    user_id: Uuid,
) -> Result<PreKeyBundle, ()> {
    match reqwest::Client::new()
        .post(format!("http://{server}/keys/user"))
        .body(serde_json::to_string(&PreKeyBundleRequest::new(user_id)).unwrap())
        .send()
        .await
    {
        Ok(res) => serde_json::from_slice::<PreKeyBundle>(
            &res.bytes()
                .await
                .expect("response could not be deserialized"),
        )
        .map_err(|_| ()),
        Err(e) => {
            eprintln!("{e:?}");
            todo!()
        }
    }
}
