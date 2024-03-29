#![warn(rust_2018_idioms)]
// #![warn(missing_docs)]

pub mod requests;
pub mod x3dh;

use std::fmt::Display;

use derive_getters::Getters;
use derive_new::new;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

type UserId = String;

#[derive(Debug, Serialize, Deserialize, new, Getters)]
pub struct Msg {
    sender: Uuid,
    receiver: Uuid,
    content_type: MsgType,
    content: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MsgType {
    Initial,
    Text,
}

#[derive(Debug, Getters, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    sender: UserId,
    receiver: Option<String>,
    text: String,
}

impl ChatMessage {
    /// Create a new chat message
    ///
    /// Example:
    /// ```
    /// use chat_core::ChatMessage;
    ///
    /// let msg = ChatMessage::new("username".to_string(), "Hello there!".to_string());
    /// assert_eq!(msg.sender(), "username");
    /// assert_eq!(msg.text(), "Hello there!");
    /// ```
    pub fn new(sender: UserId, text: String) -> Self {
        ChatMessage {
            sender,
            text,
            receiver: None,
        }
    }

    pub fn to(sender: UserId, receiver: String, text: String) -> Self {
        ChatMessage {
            sender,
            receiver: Some(receiver),
            text,
        }
    }

    pub fn deserialize(text: impl AsRef<str>) -> Self {
        serde_json::from_str(text.as_ref()).unwrap()
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl Display for ChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}>: {}", self.sender, self.text)
    }
}

#[cfg(test)]
mod chat_msg_test {
    use super::*;

    #[test]
    fn new() {
        let msg = ChatMessage::new("username".to_string(), "Hello there!".to_string());

        assert_eq!(msg.sender(), "username");
        assert_eq!(msg.text(), "Hello there!");
    }
}

#[derive(Debug, Serialize, Deserialize, Getters)]
pub struct LoginMessage {
    id: Uuid,
    signature: Vec<u8>,
}

impl LoginMessage {
    pub fn new(id: Uuid, signature: Vec<u8>) -> Self {
        LoginMessage { id, signature }
    }
}
