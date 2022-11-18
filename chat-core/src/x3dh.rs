/// Implementation of [Signal's X3DH protocol](https://www.signal.org/docs/specifications/x3dh) to exchange public keys to compute
/// a shared secret between two parties. Note that this is just done as an exercise and there are no guaranties for correctness.
use std::collections::VecDeque;

use derive_getters::Getters;
use dryoc::{
    classic::crypto_kdf::Key,
    constants::{
        CRYPTO_SCALARMULT_BYTES, CRYPTO_SCALARMULT_SCALARBYTES, CRYPTO_SECRETBOX_NONCEBYTES,
    },
    dryocbox::{KeyPair, PublicKey},
    dryocsecretbox::DryocSecretBox,
    generichash::GenericHash,
    kdf::{self, Kdf},
    sign::{self, Message, Signature, SignedMessage, SigningKeyPair},
    types::{ByteArray, Bytes, NewByteArray},
};
use serde::{Deserialize, Serialize};

const KEY_LENGTH: usize = 32;
pub const NONCE_SIZE: usize = CRYPTO_SECRETBOX_NONCEBYTES;

pub use dryoc::types::StackByteArray;

pub type Nonce = [u8; CRYPTO_SECRETBOX_NONCEBYTES];
pub type SharedSecret = [u8; KEY_LENGTH];

pub fn encrypt_data(
    secret_key: &SharedSecret,
    message: &[u8],
    _associated_data: Option<Vec<u8>>, // TODO: Is this needed?
) -> (Vec<u8>, Nonce) {
    let nonce = dryoc::dryocsecretbox::Nonce::gen();
    (
        DryocSecretBox::encrypt_to_vecbox(message, &nonce, secret_key).to_vec(),
        *nonce.as_array(),
    )
}

#[derive(Debug)]
pub enum DecryptionError {
    FailedToReadCipherText,
    InvalidSecret,
}

/// Decrypt a cipher text, given a shared secret and a nonce.
pub fn decrypt(
    shared_secret: &SharedSecret,
    cipher_text: &[u8],
    nonce: &Nonce,
) -> Result<Vec<u8>, DecryptionError> {
    DryocSecretBox::from_bytes(cipher_text)
        .map_err(|_| DecryptionError::FailedToReadCipherText)?
        .decrypt_to_vec(nonce, shared_secret)
        .map_err(|_| DecryptionError::InvalidSecret)
}

/// Helper method to compute Diffie-Hellman
fn diffie_hellman(
    secret: &[u8; CRYPTO_SCALARMULT_SCALARBYTES],
    public: &[u8; CRYPTO_SCALARMULT_BYTES],
) -> DHArray {
    use dryoc::classic::crypto_core::crypto_scalarmult;

    let mut dh4: DHArray = [0; KEY_LENGTH];
    crypto_scalarmult(&mut dh4, secret, public);
    dh4
}

fn kdf(
    main_key: Vec<u8>,
    subkey: u64,
    context: Option<kdf::Context>,
) -> (StackByteArray<KEY_LENGTH>, kdf::Context) {
    let main_key: [u8; KEY_LENGTH] =
        *GenericHash::hash_with_defaults_to_vec::<_, Key>(&main_key, None)
            .expect("hashing main key failed")
            .as_array();

    let key = kdf::Key::from(main_key);
    let context = context.unwrap_or_else(kdf::Context::gen);
    (
        Kdf::from_parts(key, context.clone())
            .derive_subkey::<StackByteArray<KEY_LENGTH>>(subkey)
            .expect("subkey could not be derived"),
        context,
    )
}

// TODO:
// - [ ] serde for the different structs. These will likely have to be send
//       over networks and therefore have to be serialized.

/// Identity key pair which can be used to identify a given entity.
/// These use the `SigningKeyPair` instead of the `dryocbox::KeyPair`, as they
/// are required for signing messages published to the server. They should
/// **never** be used for actual encryption.
/// These are Ed25519 keys, NOT X25519 which is used everywhere else for
/// public key encryption and authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityKey {
    key: SigningKeyPair<sign::PublicKey, sign::SecretKey>,
}

impl IdentityKey {
    /// Generate a new identity key with a random secret/public key pair.
    pub fn gen() -> Self {
        IdentityKey {
            key: SigningKeyPair::gen(),
        }
    }

    pub fn get_public_key(&self) -> &sign::PublicKey {
        &self.key.public_key
    }

    /// Get the secret key for this `IdentityKey`.
    pub fn get_secret_key_as_slice(&self) -> &[u8; KEY_LENGTH] {
        // The underlying implementation of `sign::SecretKey` stores both the
        // public and secret key in one slice, as secret_key || public key.
        // Hence the secret key can be extracted by only getting the first KEY_LENGTH
        // bytes of the secret key property.
        self.key.secret_key[..KEY_LENGTH].as_array()
    }

    /// Converts this ED25519 key to a x25519 key pair. This allows to use the
    /// same key for signing and encryption.
    pub fn get_x25519_key_pair(&self) -> KeyPair {
        use dryoc::classic::crypto_sign_ed25519::crypto_sign_ed25519_sk_to_curve25519;

        let mut secret: [u8; KEY_LENGTH] = [0; KEY_LENGTH];
        crypto_sign_ed25519_sk_to_curve25519(&mut secret, self.key.secret_key.as_array());

        KeyPair::from_secret_key(dryoc::dryocbox::StackByteArray::from(secret))
    }

    /// Convert a public signing ed25519 key to a public x25519 key.
    pub fn convert_public_ed25519_to_x25519(public_key: &sign::PublicKey) -> PublicKey {
        use dryoc::classic::crypto_sign_ed25519::crypto_sign_ed25519_pk_to_curve25519;

        let mut x25519_public_key: [u8; KEY_LENGTH] = [0; KEY_LENGTH];
        crypto_sign_ed25519_pk_to_curve25519(&mut x25519_public_key, public_key.as_array())
            .expect("public key could not be converted");

        x25519_public_key.into()
    }

    /// Sign a message (array of bytes) with the identity key.
    pub fn sign<M>(&self, message: M) -> Vec<u8>
    where
        M: Bytes,
    {
        self.key
            .sign_with_defaults(message)
            .expect("message could not be signed")
            .to_vec()
    }
}

/// Represents a public pre-key, along with its signature, which can be verified
/// by supplying the public part of the signing key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPreKey {
    public_key: PublicKey,
    signature: Vec<u8>,
}

impl SignedPreKey {
    pub fn new(identity_key: &IdentityKey, pre_public_key: PublicKey) -> Self {
        let signature = identity_key.sign(pre_public_key.clone());

        SignedPreKey {
            public_key: pre_public_key,
            signature,
        }
    }

    pub fn verify(&self, public_sign_key: &sign::PublicKey) -> bool {
        SignedMessage::<Signature, Message>::from_bytes(&self.signature)
            .expect("signature cannot be created from bytes")
            .verify(public_sign_key)
            .is_ok()
    }
}

/// Key store to represent the all the relevant data for communicating securely
/// for a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyStore {
    identity_key: IdentityKey,
    pre_key: KeyPair,
    one_time_keys: VecDeque<KeyPair>,
}

impl KeyStore {
    /// Generate a key store for a user
    pub fn gen() -> Self {
        let number_of_one_time_keys = 100; // TODO: should this be an argument?

        KeyStore {
            identity_key: IdentityKey::gen(),
            pre_key: KeyPair::gen(),
            one_time_keys: (0..number_of_one_time_keys)
                .map(|_| KeyPair::gen())
                .collect(),
        }
    }

    pub fn get_identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    /// Sign a message with this keystore.
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.identity_key.sign(message)
    }

    pub fn get_and_consume_one_time_key_from_public_key(
        &mut self,
        public_key: &PublicKey,
    ) -> Option<KeyPair> {
        if let Some(position) = self
            .one_time_keys
            .iter()
            .position(|k| k.public_key == *public_key)
        {
            return self.one_time_keys.remove(position);
        }

        None
    }

    /// Receive a `InitialMessage` intended for this store
    /// This will calculate the shared secret between the two parties and
    /// decrypt the cipher text stored in `message`.
    pub fn receive(&mut self, msg: InitialMessage) -> (Vec<u8>, [u8; KEY_LENGTH]) {
        if msg.receiver_used_pre_key != self.pre_key.public_key {
            unreachable!()
        }

        let context = self.compute_diffie_hellman_receive_side(&msg);

        let (shared_secret, _) = kdf(context, msg.subkey, Some(msg.kdf_context));

        (
            decrypt(shared_secret.as_array(), &msg.cipher_text, &msg.nonce)
                .expect("decryption failed"),
            *shared_secret.as_array(),
        )
    }

    fn compute_diffie_hellman_receive_side(&mut self, msg: &InitialMessage) -> Vec<u8> {
        let dh1 = diffie_hellman(
            self.pre_key.secret_key.as_array(),
            IdentityKey::convert_public_ed25519_to_x25519(&msg.sender_identity_key).as_array(),
        );
        let dh2 = diffie_hellman(
            self.identity_key
                .get_x25519_key_pair()
                .secret_key
                .as_array(),
            msg.sender_ephemeral_public_key.as_array(),
        );
        let dh3 = diffie_hellman(
            self.pre_key.secret_key.as_array(),
            msg.sender_ephemeral_public_key.as_array(),
        );
        let mut context = Vec::with_capacity(3 * KEY_LENGTH);
        context.extend(dh1);
        context.extend(dh2);
        context.extend(dh3);

        // Include one_time_key if present
        if let Some(dh4) = msg
            .receiver_used_one_time_key
            .as_ref()
            .and_then(|key| self.get_and_consume_one_time_key_from_public_key(key))
            .map(|key| {
                diffie_hellman(
                    key.secret_key.as_array(),
                    msg.sender_ephemeral_public_key.as_array(),
                )
            })
        {
            context.extend(dh4);
        }

        context
    }
}

pub enum PublishingKeyError {
    CorruptBytes,
    InvalidSignature,
}
/// Represents the set of public keys for a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishingKey {
    public_identity_key: sign::PublicKey,
    signed_pre_key: SignedPreKey,
    one_time_pre_keys: VecDeque<PublicKey>,
}

impl PublishingKey {
    pub fn get_public_identity_key(&self) -> &sign::PublicKey {
        &self.public_identity_key
    }

    pub fn one_time_pre_keys_len(&self) -> usize {
        self.one_time_pre_keys.len()
    }

    /// Verify a slice of signed bytes by the public identity key in self.
    pub fn verify(&self, signed_bytes: &[u8]) -> Result<Message, PublishingKeyError> {
        let msg = SignedMessage::<Signature, Message>::from_bytes(signed_bytes)
            .map_err(|_| PublishingKeyError::CorruptBytes)?;

        match msg.verify(&self.public_identity_key) {
            Ok(()) => Ok(msg.into_parts().1),
            Err(_) => Err(PublishingKeyError::InvalidSignature),
        }
    }

    // #[cfg(test)] // TODO: Can this be hidden to only be included when running tests?
    pub fn gen_fake() -> Self {
        let id_key = IdentityKey::gen();
        let pre_key = KeyPair::gen();

        PublishingKey {
            public_identity_key: id_key.get_public_key().to_owned(),
            signed_pre_key: SignedPreKey::new(&id_key, pre_key.public_key),
            one_time_pre_keys: VecDeque::new(),
        }
    }
}

impl From<KeyStore> for PublishingKey {
    fn from(store: KeyStore) -> Self {
        PublishingKey {
            public_identity_key: store.identity_key.get_public_key().to_owned(),
            signed_pre_key: SignedPreKey::new(&store.identity_key, store.pre_key.public_key),
            one_time_pre_keys: store
                .one_time_keys
                .iter()
                .map(|k| k.public_key.to_owned())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreKeyBundle {
    identity_public_key: sign::PublicKey,
    signed_pre_key: SignedPreKey,
    one_time_key: Option<PublicKey>,
}

impl PreKeyBundle {
    pub fn create_from(published_keys: &mut PublishingKey) -> Self {
        let one_time_key = published_keys.one_time_pre_keys.pop_front();

        PreKeyBundle {
            identity_public_key: published_keys.public_identity_key.clone(),
            signed_pre_key: published_keys.signed_pre_key.clone(),
            one_time_key,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Getters)]
pub struct InitialMessage {
    sender_identity_key: sign::PublicKey,
    sender_ephemeral_public_key: PublicKey,
    receiver_used_pre_key: PublicKey,
    receiver_used_one_time_key: Option<PublicKey>,
    cipher_text: Vec<u8>,
    nonce: Nonce,
    kdf_context: kdf::Context,
    subkey: u64,
}

type DHArray = [u8; KEY_LENGTH];

impl InitialMessage {
    /// Create an initial message from a `PreKeyBundle`.
    /// This will validate the bundle and compute the shared secret between
    /// the sender and the provided `IdentityKey`.
    pub fn create_from(
        identity_key: &IdentityKey,
        bundle: PreKeyBundle,
        message: &[u8],
    ) -> Result<(Self, [u8; KEY_LENGTH]), InitialMessageTryFromError> {
        if !bundle.signed_pre_key.verify(&bundle.identity_public_key) {
            return Err(InitialMessageTryFromError::InvalidPreKeySignature);
        }

        let ephemeral_key = KeyPair::gen();
        let context = Self::compute_dh_context(identity_key, &bundle, &ephemeral_key);

        let subkey = 0;
        let (shared_secret, kdf_context) = kdf(context, subkey, None);
        let (cipher_text, nonce) = encrypt_data(shared_secret.as_array(), message, None);

        Ok((
            InitialMessage {
                sender_identity_key: identity_key.get_public_key().to_owned(),
                sender_ephemeral_public_key: ephemeral_key.public_key,
                receiver_used_pre_key: bundle.signed_pre_key.public_key,
                receiver_used_one_time_key: bundle.one_time_key,
                cipher_text,
                nonce,
                kdf_context,
                subkey,
            },
            *shared_secret.as_array(),
        ))
    }

    /// Computes the Diffe Hellman context as required for the x3dh exchange.
    fn compute_dh_context(
        identity_key: &IdentityKey,
        bundle: &PreKeyBundle,
        ephemeral_key: &KeyPair,
    ) -> Vec<u8> {
        let dh1 = diffie_hellman(
            identity_key.get_x25519_key_pair().secret_key.as_array(),
            bundle.signed_pre_key.public_key.as_array(),
        );
        let dh2 = diffie_hellman(
            ephemeral_key.secret_key.as_array(),
            IdentityKey::convert_public_ed25519_to_x25519(&bundle.identity_public_key).as_array(),
        );
        let dh3 = diffie_hellman(
            ephemeral_key.secret_key.as_array(),
            bundle.signed_pre_key.public_key.as_array(),
        );

        let mut v = Vec::with_capacity(3 * KEY_LENGTH);
        v.extend(dh1);
        v.extend(dh2);
        v.extend(dh3);

        // Include one_time_key if present
        if let Some(dh4) = bundle
            .one_time_key
            .as_ref()
            .map(|key| diffie_hellman(ephemeral_key.secret_key.as_array(), key.as_array()))
        {
            v.extend(dh4);
        }

        v
    }
}

#[derive(Debug)]
pub enum InitialMessageTryFromError {
    InvalidPreKeySignature,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn full_flow() {
        // The idea is to test the full x3dh algorithm in one long flow with
        // this test - implemented one step at a time, so not yet completed.
        // Other tests in this module will provide more "unit" level tests of
        // the individual structs and methods.

        // Scenario: Bob has registered on the server and then gone offline.
        // Alice wants to establish a connection and send an initial message.

        // Step 1 - Publishing keys
        // Acted by Bob
        let mut bob_store = KeyStore::gen();

        // Bob's information published to the server
        let mut published_keys = PublishingKey::from(bob_store.clone());

        // Step 2 - Sending the initial message
        // Acted by Alice
        // Simulate getting this info from the trusted server.
        let message = b"hello world";
        let alice_identity_key = IdentityKey::gen();

        let pre_key_bundle = PreKeyBundle::create_from(&mut published_keys);
        let (initial_msg, _) =
            InitialMessage::create_from(&alice_identity_key, pre_key_bundle, message)
                .expect("message to have been sent");

        // After generating the initial message, one OTK should have been consumed
        assert_eq!(published_keys.one_time_pre_keys.len(), 99);

        // Step 3 - Bob receives the initial message from Alice
        let (decrypted_msg, _) = bob_store.receive(initial_msg);
        assert_eq!(decrypted_msg, message);
    }

    #[test]
    fn new_signed_pre_key() {
        let identity_key = IdentityKey::gen();
        let pre_key = PublicKey::gen();

        let signed = SignedPreKey::new(&identity_key, pre_key.clone());

        assert_eq!(signed.public_key, pre_key);
        assert_eq!(signed.signature, identity_key.sign(pre_key));
    }

    #[test]
    fn publish_keys() {
        let store = KeyStore::gen();

        let published = PublishingKey::from(store.clone());

        assert_eq!(published.one_time_pre_keys.len(), 100);
        assert_eq!(
            published.signed_pre_key.public_key,
            store.pre_key.public_key
        );
    }

    #[test]
    fn identity_key() {
        let id = IdentityKey::gen();

        println!("{:?}", id);
        println!("public main:        {:?}", &id.key.public_key[..]);
        println!("public from secret: {:?}", &id.key.secret_key[32..]);
        println!("secret:             {:?}", &id.key.secret_key[..]);
        println!("secret from secret: {:?}", &id.key.secret_key[..32]);
        assert_eq!(id.get_public_key(), &id.key.public_key);
        assert_eq!(id.get_secret_key_as_slice(), &id.key.secret_key[..32]);
    }
}
