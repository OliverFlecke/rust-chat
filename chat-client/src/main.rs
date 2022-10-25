use chat_client::{
    chat::{disconnect, run_chat},
    setup::register,
};

use clap::Parser;
use futures::stream::StreamExt;
use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM};
use signal_hook_tokio::Signals;
use std::{io::Error, process::exit, sync::Arc};
use tokio::{spawn, sync::Mutex};
use uuid::Uuid;
use websockets::{WebSocket, WebSocketWriteHalf};

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    server: String,
    #[arg(short, long)]
    username: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = Args::parse();

    let (user, _server_public_key) = register(
        args.username.unwrap_or_else(|| Uuid::new_v4().to_string()),
        &args.server,
    )
    .await
    .expect("user to be registered");

    let (rx, tx) = WebSocket::connect(&format!("ws://{server}/chat", server = &args.server))
        .await
        .unwrap()
        .split();
    let tx = Arc::new(Mutex::new(tx));

    let signals = Signals::new(&[SIGINT, SIGTERM, SIGQUIT])?;
    let handle = signals.handle();
    let signals_task = spawn(handle_signals(signals, tx.clone()));

    run_chat(&user, rx, tx).await;

    _ = handle.clone();
    _ = signals_task;

    Ok(())
}

/// Handler for process terminal signals.
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
