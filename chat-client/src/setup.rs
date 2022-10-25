use std::sync::Arc;

use chat_core::{
    encrypt_msg,
    requests::{Register, RegisterResponse},
    LoginMessage,
};
use orion::kex::{EphemeralClientSession, PublicKey};
use tokio::sync::Mutex;
use websockets::{WebSocket, WebSocketReadHalf, WebSocketWriteHalf};

use crate::{Server, User};

/// Connect through a websocket and authenticate the given user.
pub async fn connect_and_authenticate(
    server: &Server,
    user: &User,
) -> Result<(WebSocketReadHalf, Arc<Mutex<WebSocketWriteHalf>>), ()> {
    let (rx, tx) = WebSocket::connect(&format!("ws://{server}/chat", server = server.host()))
        .await
        .unwrap()
        .split();
    let tx = Arc::new(Mutex::new(tx));

    let login_msg = LoginMessage::new(user.id().to_owned());
    // let shared_secret = user
    //     .session()
    //     .establish_with_server(&server.public_key)
    //     .expect("shared secret to be computed");

    todo!();

    // let payload = encrypt_msg(shared_secret, &login_msg);
    // tx.lock()
    //     .await
    //     .send_binary(payload)
    //     .await
    //     .expect("message to be send successfully");

    Ok((rx, tx))
}

// TODO: Write test for the register method.
//  - How can `reqwest` be mocked to generate responses during test?

/// Register the user at the server with the given username.
pub async fn register(username: String, server: &String) -> Result<(User, PublicKey), ()> {
    let session = EphemeralClientSession::new().unwrap();
    let res_body = post_register(&username, session.public_key(), server)
        .await
        .expect("register to succeed");

    let res: RegisterResponse =
        serde_json::from_str(res_body.as_str()).expect("response to be valid");

    let user = User {
        id: res.id().to_owned(),
        username,
        session,
    };

    Ok((user, res.server_public_key().to_owned()))
}

async fn post_register(
    username: &String,
    public_key: &PublicKey,
    server: &String,
) -> Result<String, ()> {
    match reqwest::Client::new()
        .post(format!("http://{server}/register"))
        .body(serde_json::to_string(&Register::new(username.clone(), public_key.clone())).unwrap())
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
