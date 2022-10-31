#!/usr/bin/env sh
systemfd --no-pid -s http::3030 -- cargo watch -x 'run --bin chat-server'