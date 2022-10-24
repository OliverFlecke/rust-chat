use derive_getters::Getters;
use orion::kex::PublicKey;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Getters)]
pub struct Register {
    username: String,
    public_key: [u8; 32],
}

impl Register {
    pub fn new(username: String, public_key: &PublicKey) -> Self {
        Register {
            username,
            public_key: public_key.to_bytes(),
        }
    }
}
