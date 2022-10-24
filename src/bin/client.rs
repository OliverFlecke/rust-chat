use chat_server::ChatMessage;
use clap::Parser;
use futures::stream::StreamExt;
use orion::kex::EphemeralClientSession;
use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM};
use signal_hook_tokio::Signals;
use std::{
    io::{self, Error},
    process::exit,
    sync::Arc,
};
use tokio::{spawn, sync::Mutex};
use uuid::Uuid;
use websockets::{Frame, WebSocket, WebSocketReadHalf, WebSocketWriteHalf};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 'H', long)]
    host: String,
    #[arg(short, long)]
    username: Option<String>,
}

struct User {
    username: String,
    session: EphemeralClientSession,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    let user = User {
        username: args.username.unwrap_or_else(|| Uuid::new_v4().to_string()),
        session: EphemeralClientSession::new().unwrap(),
    };

    let (rx, tx) = WebSocket::connect(&args.host).await.unwrap().split();
    let tx = Arc::new(Mutex::new(tx));

    let signals = Signals::new(&[SIGINT, SIGTERM, SIGQUIT])?;
    let handle = signals.handle();
    let signals_task = spawn(handle_signals(signals, tx.clone()));

    run_chat(&user, rx, tx).await;

    _ = handle.clone();
    _ = signals_task;

    Ok(())
}

async fn handle_signals(mut signals: Signals, tx: Arc<Mutex<WebSocketWriteHalf>>) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGTERM | SIGINT | SIGQUIT => {
                disconnect(&tx).await;
                exit(0);
            }
            _ => unreachable!(),
        }
    }
}

async fn run_chat(user: &User, mut rx: WebSocketReadHalf, tx: Arc<Mutex<WebSocketWriteHalf>>) {
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
            let msg = ChatMessage::new(user.username.clone(), user_input.trim_end().to_string());

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
