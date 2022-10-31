# Chat application in Rust! 🚀🚀🚀

A chat application consisting of a server and client (cli) application, for end-to-end encrypted and secure communication between parties.


## Build

Tested and verified to work with `cargo` and `rustc` version 1.64.
All parts of the project can be build and compiled with the usual `cargo` commands: `cargo check` and `cargo test`.

### Project structure

The project is divided into three parts:

- `chat-core`: shared code and structs between the server and client.
- `chat-server`: A server to send the messages through.
- `chat-client`: CLI client application to interact with the user, and for sending E2E message to other clients connected to the same server.

Both the server and client project will generate a `bin` file.
To run either of them, use `cargo run --bin <project-name>`, e.g. `cargo run --bin chat-client`

### Development

To ease development of the server part, the server can be run in hot-reload mode.
This means it will recompile and restart each time a code change is detected.
To enable this, use the `run_server.sh` script in the projects root.

## Features

- [ ] Connect and authenticate as a client against the server
- [ ] Send encrypted messages to other clients in the network
- [ ] Encrypted group messages
    - [ ] Sharing previous messages with new members joining a group

## Why

This is just a hoppy project, build to pratice my knowledge around [the rust programming language](https://rust-lang.org) and learning how to use the [warp](https://github.com/seanmonstar/warp) framework for building web application.
I have always been interested in cryptograph and believe privacy should be central in every application, and therefore took this as an opportunity to learn more about [Signal](https://www.signal.org/docs/)'s protocol by reimplementing it myself.
As this is just has just been done as a academic exercise and has not been reviewed or audited, please do **not** assume it is implemented correctly.
