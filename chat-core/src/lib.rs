#![warn(rust_2018_idioms)]
// #![warn(missing_docs)]

pub mod requests;
pub mod x3dh;

use std::fmt::Display;

use derive_getters::Getters;
use serde::{Deserialize, Serialize};

type UserId = String;

#[derive(Debug, Getters, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatMessage {
    sender: UserId,
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
        ChatMessage { sender, text }
    }

    pub fn deserialize(text: impl AsRef<str>) -> Self {
        serde_json::from_str(text.as_ref()).unwrap()
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    // pub fn encrypt(&self, secret_key: &SecretKey) -> Vec<u8> {
    //     todo!()
    // }

    // pub fn decrypt(secret_key: &SecretKey, cipher_text: &[u8]) -> Self {
    //     todo!()
    // }
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

#[derive(Debug, Serialize)]
pub struct LoginMessage {
    user_id: UserId,
}

impl LoginMessage {
    pub fn new(user_id: UserId) -> Self {
        LoginMessage { user_id }
    }
}
