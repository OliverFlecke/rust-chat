#!/usr/bin/env sh
systemfd --no-pid -s http::3030 -- cargo watch --ignore chat-client -x 'run --bin chat-server'