use std::{
    io::{self, Write},
    sync::Arc,
};

use chat_core::ChatMessage;
use tokio::{spawn, sync::Mutex};
use websockets::{Frame, WebSocketReadHalf, WebSocketWriteHalf};

use crate::User;

#[derive(Debug)]
pub struct Chat {
    user: Arc<User>,
    rx: Arc<Mutex<WebSocketReadHalf>>,
    tx: Arc<Mutex<WebSocketWriteHalf>>,
}

impl Chat {
    pub fn new(
        user: Arc<User>,
        rx: Arc<Mutex<WebSocketReadHalf>>,
        tx: Arc<Mutex<WebSocketWriteHalf>>,
    ) -> Self {
        Chat { user, rx, tx }
    }

    /// Main run loop for the chat.
    pub async fn run(&self) {
        Chat::spawn_interactive_terminal(self.user.username().clone(), self.tx.clone());

        // Setup thread to listen for new messages
        while let Ok(frame) = self.rx.lock().await.receive().await {
            if let Frame::Text { payload: msg, .. } = frame {
                let msg = ChatMessage::deserialize(msg);
                println!("{}", msg);
            }
        }
    }

    fn spawn_interactive_terminal(username: String, tx: Arc<Mutex<WebSocketWriteHalf>>) {
        spawn(async move {
            let mut user_input = String::new();
            let stdin = io::stdin();

            Chat::write_prompt(&username);
            while let Ok(_) = stdin.read_line(&mut user_input) {
                if user_input.starts_with('/') {
                    match user_input.trim_end() {
                        "/exit" => {
                            Chat::disconnect(&tx).await;
                            break;
                        }
                        _ => eprintln!("Unknown command"),
                    };
                } else {
                    let msg = ChatMessage::new(username.clone(), user_input.trim_end().to_string());

                    // Send message to server
                    let mut tx = tx.lock().await;
                    match tx.send_text(msg.serialize()).await {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("Failed to send message: {e}");
                            break;
                        }
                    };
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
