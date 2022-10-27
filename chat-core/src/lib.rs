#![warn(rust_2018_idioms)]
// #![warn(missing_docs)]

pub mod requests;
pub mod x3dh;

use std::fmt::Display;

use derive_getters::Getters;
use orion::{aead, kex::SecretKey};
use serde::{Deserialize, Serialize};

/// Encrypt a `Serialize`able msg and encrypt it with a given key.
/// The idea is here that the client and server can generate their shared
/// secret and pass that to this method. See [orion's documentation for computing shared secrets](https://docs.rs/orion/latest/orion/kex/index.html#example).
pub fn encrypt_msg(secret_key: &SecretKey, msg: &impl Serialize) -> Vec<u8> {
    let serialized = serde_json::to_vec(msg).expect("struct to be serialized");
    aead::seal(secret_key, &serialized).expect("serialized value to be encrypted")
}

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

    pub fn encrypt(&self, secret_key: &SecretKey) -> Vec<u8> {
        aead::seal(secret_key, self.serialize().as_bytes()).unwrap()
    }

    pub fn decrypt(secret_key: &SecretKey, cipher_text: &[u8]) -> Self {
        serde_json::from_slice(aead::open(secret_key, cipher_text).unwrap().as_slice()).unwrap()
    }
}

impl Display for ChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}>: {}", self.sender, self.text)
    }
}

#[cfg(test)]
mod chat_msg_test {
    use orion::aead;

    use super::*;

    #[test]
    fn new() {
        let msg = ChatMessage::new("username".to_string(), "Hello there!".to_string());

        assert_eq!(msg.sender(), "username");
        assert_eq!(msg.text(), "Hello there!");
    }

    #[test]
    fn encryption() {
        let secret_key = aead::SecretKey::default();
        let msg = ChatMessage::new("sender".to_string(), "message".to_string());

        let encrypted_msg = msg.encrypt(&secret_key);

        assert!(!encrypted_msg.is_empty());

        // Decrypt
        let decrypted = ChatMessage::decrypt(&secret_key, &encrypted_msg);

        assert_eq!(msg, decrypted);
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
