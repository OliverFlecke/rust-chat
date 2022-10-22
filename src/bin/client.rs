use futures::stream::StreamExt;
use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM};
use signal_hook_tokio::Signals;
use std::{
    io::{self, Error},
    sync::Arc,
};
use tokio::{spawn, sync::Mutex};
use websockets::{Frame, WebSocket, WebSocketReadHalf, WebSocketWriteHalf};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let host = "ws://localhost:3030/stream";
    let (rx, tx) = WebSocket::connect(host).await.unwrap().split();
    let tx = Arc::new(Mutex::new(tx));

    let signals = Signals::new(&[SIGINT, SIGTERM, SIGQUIT])?;
    let handle = signals.handle();
    let signals_task = spawn(handle_signals(signals, tx.clone()));

    run_chat(rx, tx).await;

    _ = handle.clone();
    _ = signals_task;

    Ok(())
}

async fn handle_signals(mut signals: Signals, tx: Arc<Mutex<WebSocketWriteHalf>>) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGTERM | SIGINT | SIGQUIT => {
                disconnect(&tx).await;
                return;
            }
            _ => unreachable!(),
        }
    }
}

async fn run_chat(mut rx: WebSocketReadHalf, tx: Arc<Mutex<WebSocketWriteHalf>>) {
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
                    disconnect(&tx).await;
                    break;
                }
                _ => eprintln!("Unknown command"),
            };
        } else {
            // Send message to server
            let mut tx = tx.lock().await;
            match tx
                .send_text(user_input.clone().trim_end().to_string())
                .await
            {
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

async fn disconnect(tx: &Arc<Mutex<WebSocketWriteHalf>>) {
    let mut tx = tx.lock().await;
    match tx.close(None).await {
        Ok(()) => {
            println!("Disconnected");
            return;
        }
        Err(e) => eprintln!("Unable to disconnect: {e}"),
    };
}
