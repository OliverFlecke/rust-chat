use std::{io, sync::Arc};

use chat_core::ChatMessage;
use tokio::{spawn, sync::Mutex};
use websockets::{Frame, WebSocketReadHalf, WebSocketWriteHalf};

use crate::User;

/// Main run loop for the chat.
pub async fn run_chat(user: &User, mut rx: WebSocketReadHalf, tx: Arc<Mutex<WebSocketWriteHalf>>) {
    let mut user_input = String::new();
    let stdin = io::stdin();

    // Setup thread to listen for new messages
    spawn(async move {
        while let Ok(frame) = rx.receive().await {
            if let Frame::Text { payload: msg, .. } = frame {
                let msg = ChatMessage::deserialize(msg);
                println!("{}", msg);
            }
        }
    });

    while let Ok(_) = stdin.read_line(&mut user_input) {
        if user_input.starts_with('/') {
            match user_input.trim_end() {
                "/exit" => {
                    disconnect(&tx).await;
                    break;
                }
                _ => eprintln!("Unknown command"),
            };
        } else {
            let msg = ChatMessage::new(user.username().clone(), user_input.trim_end().to_string());

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
    }
}

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
