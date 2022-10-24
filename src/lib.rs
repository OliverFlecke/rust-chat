pub mod requests;

use std::fmt::Display;

use derive_getters::Getters;
use orion::{aead, kex::SecretKey};
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
    /// use chat_server::ChatMessage;
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
mod test {
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
