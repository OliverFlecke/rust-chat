use std::{
    collections::HashMap,
    io::{self, Write},
    str::FromStr,
    sync::Arc,
};

use chat_core::{
    x3dh::{InitialMessage, PreKeyBundle},
    ChatMessage, Msg,
};
use tokio::{
    spawn,
    sync::{Mutex, RwLock},
};
use uuid::Uuid;
use websockets::{Frame, WebSocketReadHalf, WebSocketWriteHalf};

use crate::{setup::post_request_pre_bundle_for_user, Server, User};

#[derive(Debug)]
pub struct Client {
    server: Server,
    others: RwLock<HashMap<Uuid, PreKeyBundle>>,
}

#[derive(Debug)]
pub struct Chat {
    client: Arc<Client>,
    user: Arc<RwLock<User>>,
    rx: Arc<Mutex<WebSocketReadHalf>>,
    tx: Arc<Mutex<WebSocketWriteHalf>>,
}

impl Chat {
    pub fn new(
        server: Server,
        user: Arc<RwLock<User>>,
        rx: Arc<Mutex<WebSocketReadHalf>>,
        tx: Arc<Mutex<WebSocketWriteHalf>>,
    ) -> Self {
        let client = Arc::new(Client {
            server,
            others: RwLock::new(HashMap::default()),
        });

        Chat {
            client,
            user,
            rx,
            tx,
        }
    }

    /// Main run loop for the chat.
    pub async fn run(&self) {
        Chat::spawn_interactive_terminal(self.client.clone(), self.user.clone(), self.tx.clone());

        // Setup thread to listen for new messages
        while let Ok(frame) = self.rx.lock().await.receive().await {
            // Handle basic text messages
            match frame {
                Frame::Text { payload, .. } => {
                    let msg = ChatMessage::deserialize(payload);
                    println!("{}", msg);
                }
                Frame::Binary { payload, .. } => {
                    let msg = serde_json::from_slice::<Msg>(payload.as_slice())
                        .expect("`Msg` could not be deserialized");
                    println!("Received message from {}", msg.sender());
                    let initial_msg: InitialMessage = serde_json::from_slice(msg.content())
                        .expect("initial message to be deserialized");
                    let decrypted_msg = self.user.write().await.keystore_mut().receive(initial_msg);
                    let s = String::from_utf8(decrypted_msg).expect("valid message");
                    println!("Got msg: {s}");
                }
                _ => {
                    println!("Received frame: {frame:?}");
                }
            }
        }
    }

    fn spawn_interactive_terminal(
        client: Arc<Client>,
        user: Arc<RwLock<User>>,
        tx: Arc<Mutex<WebSocketWriteHalf>>,
    ) {
        spawn(async move {
            let mut user_input = String::new();
            let stdin = io::stdin();
            let mut receiver: Option<Uuid> = None;
            let username = user.read().await.username().clone();

            Chat::write_prompt(&username);
            while let Ok(_) = stdin.read_line(&mut user_input) {
                if user_input.starts_with('/') {
                    let mut splits = user_input.trim_end().split(' ');
                    match splits.next() {
                        Some("/exit") => {
                            Chat::disconnect(&tx).await;
                            break;
                        }
                        // Sets the current receiver of messages
                        Some("/receiver") => {
                            if let Some(r) = splits.next().map(|x| x.trim_end().to_string()) {
                                match Uuid::from_str(r.as_str()) {
                                    Ok(id) => {
                                        match post_request_pre_bundle_for_user(
                                            client.server.host(),
                                            id,
                                        )
                                        .await
                                        {
                                            Ok(b) => {
                                                client.others.write().await.insert(id, b);
                                                receiver = Some(id);
                                            }
                                            Err(_) => eprintln!("User not found"),
                                        };
                                    }
                                    Err(_) => {
                                        println!("Receiver has to be a uuid");
                                    }
                                }
                            }
                        }

                        // Unknown commads
                        Some(x) => eprintln!("Unknown command {x}"),
                        None => eprintln!("No command"),
                    };
                } else {
                    if let Some(receiver) = receiver.clone() {
                        if let Some(bundle) = client.others.write().await.remove(&receiver) {
                            let initial_msg = InitialMessage::create_from(
                                user.read().await.keystore().get_identity_key(),
                                bundle,
                                user_input.trim_end().as_bytes(),
                            )
                            .expect("initial message could not be created");

                            let initial_msg = serde_json::to_vec(&initial_msg)
                                .expect("initial message to be serialized");
                            let msg = Msg::new(user.read().await.id, receiver, initial_msg);

                            // Send message to server
                            let mut tx = tx.lock().await;
                            println!("Sending msg");
                            match tx
                                .send_binary(
                                    serde_json::to_vec(&msg).expect("message to be serialized"),
                                )
                                .await
                            {
                                Ok(()) => {}
                                Err(e) => {
                                    eprintln!("Failed to send message: {e}");
                                    break;
                                }
                            };
                        }
                    }
                }
                user_input.clear();
                Chat::write_prompt(&username);
            }
        });
    }

    // TODO: This should be a `self` in some way, as to not interfer with other chats.
    /// Clone the websocket properly.
    pub async fn disconnect(tx: &Arc<Mutex<WebSocketWriteHalf>>) {
        let mut tx = tx.lock().await;
        match tx.close(None).await {
            Ok(()) => {
                println!("Disconnected");
                return;
            }
            Err(e) => eprintln!("Unable to disconnect: {e}"),
        };
    }

    /// Write a prompt to indicate the user can type a message or a command
    /// in the chat.
    fn write_prompt(username: &String) {
        print!("{username}> ");
        io::stdout().flush().unwrap();
    }
}
