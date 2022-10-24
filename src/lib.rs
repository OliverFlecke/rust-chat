use std::fmt::Display;

use serde::{Deserialize, Serialize};

type UserId = String;

#[derive(Debug, Serialize, Deserialize)]
pub struct Message {
    sender: UserId,
    text: String,
}

impl Message {
    pub fn new(sender: UserId, text: String) -> Self {
        Message { sender, text }
    }

    pub fn deserialize(text: impl AsRef<str>) -> Self {
        serde_json::from_str(text.as_ref()).unwrap()
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}>: {}", self.sender, self.text)
    }
}
