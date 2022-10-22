use std::io;
use tokio::spawn;
use websockets::{Frame, WebSocket};

#[tokio::main]
async fn main() {
    let host = "ws://localhost:3030/stream";

    let (mut rx, mut tx) = WebSocket::connect(host).await.unwrap().split();

    let mut user_input = String::new();
    let stdin = io::stdin();

    // Setup thread to listen for new messages
    spawn(async move {
        while let Ok(frame) = rx.receive().await {
            if let Frame::Text { payload: msg, .. } = frame {
                println!("{}", msg);
            }
        }
    });

    while let Ok(_) = stdin.read_line(&mut user_input) {
        if user_input.starts_with('/') {
            match user_input.trim_end() {
                "/exit" => {
                    match tx.close(None).await {
                        Ok(()) => {
                            println!("Disconnected");
                            break;
                        }
                        Err(e) => eprintln!("Unable to disconnect: {e}"),
                    };
                }
                _ => eprintln!("Unknown command"),
            };
        } else {
            // Send message to server
            match tx
                .send_text(user_input.clone().trim_end().to_string())
                .await
            {
                Ok(()) => {}
                Err(e) => eprintln!("Failed to send message: {e}"),
            };
        }
        user_input.clear();
    }
}
