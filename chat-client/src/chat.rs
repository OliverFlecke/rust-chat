use std::{
    collections::HashMap,
    io::{self, Write},
    str::FromStr,
    sync::Arc,
};

use chat_core::{
    x3dh::{decrypt, encrypt_data, InitialMessage, PreKeyBundle, NONCE_SIZE},
    ChatMessage, Msg, MsgType,
};
use serde::{Deserialize, Serialize};
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
    others: RwLock<HashMap<Uuid, ChatContext>>,
}

#[derive(Debug)]
enum ChatContext {
    Initial(PreKeyBundle),
    General(ChatState),
}

/// Represents a context for a chat with another user.
#[derive(Debug)]
struct ChatState {
    shared_secret: [u8; 32],
    // TODO: This should be migrated to use the Double Racket algorithm
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
        self.receive_loop().await
    }

    /// Setup thread to listen for new messages
    async fn receive_loop(&self) {
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

                    match msg.content_type() {
                        MsgType::Initial => {
                            let initial_msg: InitialMessage = serde_json::from_slice(msg.content())
                                .expect("initial message to be deserialized");
                            let (decrypted_msg, shared_secret) =
                                self.user.write().await.keystore_mut().receive(initial_msg);

                            // Create chat context with the sender
                            self.client.others.write().await.insert(
                                *msg.sender(),
                                ChatContext::General(ChatState { shared_secret }),
                            );

                            let content = String::from_utf8(decrypted_msg).expect("valid message");
                            println!("{sender} - Initial msg: {content}", sender = msg.sender());
                        }
                        MsgType::Text => {
                            let parsed: TextMsg = serde_json::from_slice(msg.content())
                                .expect("message content is invalid type");
                            if let Some(context) = self.client.others.read().await.get(msg.sender())
                            {
                                match context {
                                    ChatContext::Initial(_) => unreachable!(),
                                    ChatContext::General(state) => {
                                        let content = match decrypt(
                                            &state.shared_secret,
                                            &parsed.cipher_text,
                                            &parsed.nonce,
                                        ) {
                                            Ok(c) => c,
                                            Err(_) => {
                                                eprintln!("Unable to decrypt received message");
                                                continue;
                                            }
                                        };

                                        let content = String::from_utf8(content)
                                            .expect("text message was not valid utf8");
                                        println!("{sender}: {content}", sender = msg.sender());
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {
                    println!("Received frame: {frame:?}");
                }
            }
        }
    }

    /// Send loop
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
                    // TODO: It would be nice to split this out to its own function
                    let mut splits = user_input.trim_end().split(' ');
                    match splits.next() {
                        Some("/exit") => {
                            Chat::disconnect(&tx).await;
                            break;
                        }
                        // Connect to a user
                        Some("/connect") => {
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
                                                client
                                                    .others
                                                    .write()
                                                    .await
                                                    .insert(id, ChatContext::Initial(b));
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
                        // The state should not be removed here, as an error can happen inside the statement,
                        // causing the state to become lost. It would be better to only remove it when it has been used,
                        // but the value has to be owned in order to be consumed during decryption.
                        let mut others = client.others.write().await;
                        if let Some(state) = others.get(&receiver) {
                            let text = user_input.trim_end().as_bytes();
                            let (content, msg_type) = match state {
                                ChatContext::Initial(bundle) => {
                                    let (initial_msg, shared_secret) = InitialMessage::create_from(
                                        user.read().await.keystore().get_identity_key(),
                                        bundle.clone(),
                                        text,
                                    )
                                    .expect("initial message could not be created");

                                    // Reinsert the calculated shared secret for future messages
                                    others.insert(
                                        receiver,
                                        ChatContext::General(ChatState { shared_secret }),
                                    );

                                    (
                                        serde_json::to_vec(&initial_msg)
                                            .expect("initial message to be serialized"),
                                        MsgType::Initial,
                                    )
                                }
                                ChatContext::General(context) => {
                                    let (cipher_text, nonce) =
                                        encrypt_data(&context.shared_secret.into(), text, None);
                                    let text_msg = TextMsg { nonce, cipher_text };
                                    (
                                        serde_json::to_vec(&text_msg)
                                            .expect("text message to be serialized"),
                                        MsgType::Text,
                                    )
                                }
                            };

                            let msg = Msg::new(user.read().await.id, receiver, msg_type, content);

                            // Send message to server
                            let mut tx = tx.lock().await;
                            println!("Sending msg to server");
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
                        } else {
                            eprintln!("No state");
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

#[derive(Debug, Serialize, Deserialize)]
struct TextMsg {
    nonce: [u8; NONCE_SIZE],
    cipher_text: Vec<u8>,
}
