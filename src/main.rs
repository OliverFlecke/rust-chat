use futures_util::{SinkExt, StreamExt, TryFutureExt};
use warp::{ws::WebSocket, Filter};

#[tokio::main]
async fn main() {
    let hello = warp::path!("hello" / String).map(|name| format!("Hello, {}!", name));

    let stream = warp::path("stream")
        .and(warp::ws())
        .map(|ws: warp::ws::Ws| ws.on_upgrade(move |socket| handler(socket)));

    let server = warp::get().and(hello).or(stream);

    warp::serve(server).run(([127, 0, 0, 1], 3030)).await;
}

async fn handler(ws: WebSocket) {
    let (mut tx, mut rx) = ws.split();
    tokio::task::spawn(async move {
        while let Some(message) = rx.next().await {
            match message {
                Ok(msg) => {
                    println!("Got message: {msg:?}");
                    tx.send(msg)
                        .unwrap_or_else(|e| {
                            eprintln!("websocket send error: {e}");
                        })
                        .await;
                }
                Err(e) => eprintln!("socket error: {e:?}"),
            }
        }
    });
}
