use chat_client::{
    chat::Chat,
    setup::{connect_and_authenticate, register},
    user_data::{read_user_data, write_user},
    Server, User,
};

use clap::Parser;
use futures::stream::StreamExt;
use signal_hook::consts::{SIGINT, SIGQUIT, SIGTERM};
use signal_hook_tokio::Signals;
use std::{error::Error, process::exit, sync::Arc};
use tokio::{
    spawn,
    sync::{Mutex, RwLock},
};
use uuid::Uuid;
use websockets::WebSocketWriteHalf;

#[derive(Debug, Parser, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    server: String,
    #[arg(short, long)]
    username: Option<String>,
    #[arg(short, long)]
    config: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    let server = Server {
        host: args.server.clone(),
    };

    let user = get_user(args).await?;

    let (rx, tx) = connect_and_authenticate(&server, &user).await.unwrap();

    // Setup keyboard event handlers for TERM signals
    let signals = Signals::new(&[SIGINT, SIGTERM, SIGQUIT])?;
    let handle = signals.handle();
    let signals_task = spawn(handle_signals(signals, tx.clone()));

    let user = Arc::new(RwLock::new(user));
    Chat::new(server, user, rx, tx).run().await;

    _ = handle.clone();
    _ = signals_task;

    Ok(())
}

async fn get_user(args: Args) -> Result<User, Box<dyn Error>> {
    if let Some(config) = args.config {
        read_user_data(config).await
    } else {
        let username = args.username.unwrap_or_else(|| Uuid::new_v4().to_string());
        let user = register(username.clone(), &args.server)
            .await
            .expect("user to be registered");

        write_user(format!("{}.json", username).as_str(), &user).await?;

        Ok(user)
    }
}

/// Handler for process terminal signals.
async fn handle_signals(mut signals: Signals, tx: Arc<Mutex<WebSocketWriteHalf>>) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGTERM | SIGINT | SIGQUIT => {
                Chat::disconnect(&tx).await;
                exit(0);
            }
            _ => unreachable!(),
        }
    }
}
