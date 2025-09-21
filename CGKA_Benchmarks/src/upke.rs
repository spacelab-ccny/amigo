// We'll need an allocator
extern crate alloc;
extern crate std;
extern crate rand;




use alloc::{vec::Vec, borrow::ToOwned};

use curve25519_dalek::{constants, ristretto::{CompressedRistretto, RistrettoPoint}, scalar::Scalar};
use ed25519_compact::KeyPair;
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use rand::rngs::OsRng;

use sha2::{digest::typenum::U12, Digest, Sha256, Sha512};
use ed25519_compact::*;
use hex_literal::hex;
use aes_gcm::{
    aead::{ AeadCore, KeyInit, OsRng as AESRng, generic_array::GenericArray},
    Aes256Gcm, Key, AeadInPlace // Or `Aes128Gcm`
};

use rsa::{RsaPrivateKey, RsaPublicKey};


/// Implements generation and decryption functionality of a private key in a UPKE scheme
pub struct SecretKey(Scalar);
impl Copy for SecretKey {}

impl Clone for SecretKey {
    fn clone(&self) -> Self {
        SecretKey(self.0)
    }
}

/// Implements generation and encryption functionality of a public key in a UPKE scheme
pub struct PublicKey(RistrettoPoint);
// Implement the `Copy` trait for `PublicKey`
impl<'a> Copy for PublicKey {}

// Implement the `Clone` trait for `PublicKey`
impl<'a> Clone for PublicKey {
    fn clone(&self) -> Self {
        PublicKey(self.0)
    }
}

/// Ciphertext is composed of ristretto point and byte vector
 #[derive(Clone)]
pub struct Ciphertext(RistrettoPoint, Vec<u8>);

impl Ciphertext {
    /// Serializes the `Ciphertext` into two byte vectors.
    pub fn serialize(&self) -> ([u8;32], Vec<u8>) {
        let point_serialized = self.0.compress().to_bytes();
        let byte_vector = self.1.clone();
        (point_serialized, byte_vector)
    }
    pub fn deserialize(serialized_point: [u8;32], byte_vector: Vec<u8>) -> Ciphertext {
        let deserialized_point = CompressedRistretto::from_slice(&serialized_point).decompress().unwrap();
        Ciphertext(deserialized_point, byte_vector)
    }
}
/// Generates material for the updatepath of a leaf in the tree
pub struct PathSecret();
/// Every occupied node has a node secret which is a combination of their public and private key material
pub struct NodeSecret();
/// Implements symmetric encryption/decryption operations including generating a symmetric key from a node secret
pub struct SymmetricKey();

/// Implements UPKE functionality
pub struct UPKEMaterial {
    pub public_key: PublicKey,
    pub private_key: SecretKey,
}

/// Implements signing functionality
pub struct SignatureMaterial {
    pub signing_key: KeyPair,
}

#[derive(Clone)]

pub struct RSAKeyPair {
    pub rsa_pub: RsaPublicKey,
    pub rsa_priv: RsaPrivateKey
}


impl RSAKeyPair {
    pub fn new() -> RSAKeyPair{
        let mut rng = aes_gcm::aead::OsRng;
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pub_key = RsaPublicKey::from(&priv_key);
        // let unserialized = RsaPublicKey::from_public_key_der(&pub_key);
        
        RSAKeyPair {
           rsa_pub: pub_key,
           rsa_priv: priv_key 
        }

    }
}

impl PublicKey {
    /// Generates new public key using the private key (a scalar value) and multiplying it with a basepoint on the curve to generate a new point (the public key)
    pub fn new(sk: &SecretKey) -> PublicKey {
        let g = &constants::RISTRETTO_BASEPOINT_TABLE;
        PublicKey(&sk.0 * g)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
    
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> PublicKey {
        let compressed = CompressedRistretto::from_slice(&bytes);
        PublicKey(compressed.decompress().unwrap())

    }
    // We don't want this to take ownership of self.  Just reference it so we can take ownership in other functions
    // That way this method doesn't consume the key and we can unwrap it for when we want to traverse the tree
    /// Encryption results in ciphertext and a new public key
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        message: [u8; 32],
        rng: &mut R,
    ) -> (Ciphertext, PublicKey) {
        let r = Scalar::random(rng);
        let g = &constants::RISTRETTO_BASEPOINT_TABLE;
        let c1 = &r * g;

        let delta = Scalar::random(rng);
        let mut message = message.to_vec();
        message.extend_from_slice(delta.as_bytes());

        let mut hasher = Sha512::new();
        hasher.update((&r * &self.0).compress().as_bytes());
        let hashed = hasher.finalize().to_vec();

        let c2: Vec<_> = hashed
            .iter()
            .zip(message.iter())
            .map(|(h, m)| h ^ m)
            .collect();

        (Ciphertext(c1, c2), PublicKey(self.0 + (g * &delta)))
    }
}

impl SecretKey {
    /// Generates secret key by generating a random scalar
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> SecretKey {
        SecretKey(Scalar::random(rng))
    }
    /// Need this for when we encrypt the secret key information to send the updatepath information
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    
    pub fn from_bytes_mod_order(bytes: [u8; 32]) -> SecretKey {
        SecretKey(Scalar::from_bytes_mod_order(bytes))
    }
    // We don't want this to take ownership of self.  Just reference it so we can take ownership in other functions
    // That way this method doesn't consume the key and we can unwrap it for when we want to traverse the tree

    /// Decryption results in a new secret key and the plaintext message
    pub fn decrypt(&self, c: &Ciphertext) -> ([u8; 32], SecretKey) {
        let mut hasher = Sha512::new();
        hasher.update((&self.0 * c.0).compress().as_bytes());
        let hashed = hasher.finalize().to_vec();

        // TODO: Unwrap
        let m: [u8; 32] = hashed[0..32]
            .iter()
            .zip(&c.1[0..32])
            .map(|(h, x)| h ^ x)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // TODO: Unwrap
        let delta: [u8; 32] = hashed[32..]
            .iter()
            .zip(&c.1[32..])
            .map(|(h, x)| h ^ x)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let delta = Scalar::from_bytes_mod_order(delta);

        (m, SecretKey(self.0 + delta))
    }
}

impl UPKEMaterial {
    /// Initializes public and private UPKE material
    pub fn generate() -> UPKEMaterial {
        let mut rng: OsRng = OsRng;
        let sk = SecretKey::new(&mut rng);
        let pk = PublicKey::new(&sk);
        let material = UPKEMaterial {
            private_key: sk,
            public_key: pk,
        };
        return material;
    }

    pub fn update_public(new_pk: &PublicKey, old_pk: &PublicKey) -> PublicKey{
        PublicKey(new_pk.0 + old_pk.0)
    }
    /// Updates just the secret key information
    pub fn update_private(new_sk: &SecretKey, old_sk: &SecretKey) -> SecretKey {
        SecretKey(new_sk.0 + old_sk.0)
    }
}

impl SignatureMaterial {
    /// Generates keypair for ed25519 signature scheme
    pub fn generate() -> SignatureMaterial {
        let key_pair = KeyPair::from_seed(Seed::default());
        let s = SignatureMaterial {
            signing_key: key_pair,
        };
        return s;
    }
}



impl PathSecret {
    /// New update path secrets are a UPKE keypair
    pub fn new() -> UPKEMaterial{
        let secrets = UPKEMaterial::generate();
        return secrets;
    }

    pub fn new_path_secret() -> [u8; 32] {
        // generate random bitstring
        let mut rng = OsRng;
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        secret  
    }

    pub fn update_with_path_secret(path_secret: &[u8;32], old_public_key: &PublicKey, old_private_key: &SecretKey) -> UPKEMaterial {
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let hk = Hkdf::<Sha256>::from_prk(path_secret).expect("Should be large enough");
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("32 is a valid length for Sha256 to output"); 
        let private_key = SecretKey::from_bytes_mod_order(okm);
        let public_key = PublicKey::new(&private_key);

        let sk = private_key.0;
        let pk = public_key.0;

        let new_sk = sk + old_private_key.0;
        let new_pk = pk + old_public_key.0;
        let new_keys = UPKEMaterial {
            private_key: SecretKey(new_sk),
            public_key: PublicKey(new_pk)
        };
        return new_keys;

    }
    //derive keypair from path secret
    pub fn derive_key_pair(path_secret: [u8;32]) -> UPKEMaterial {
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let hk = Hkdf::<Sha256>::from_prk(&path_secret).expect("Should be large enough");
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("32 is a valid length for Sha256 to output"); 
        let private_key = SecretKey::from_bytes_mod_order(okm);
        let public_key = PublicKey::new(&private_key);
        let new_keys = UPKEMaterial {
            private_key: private_key,
            public_key: public_key
        };
        return new_keys;
    }

    /// Updating keys of ancestors along the path requires combining the old and new public and private key material
    pub fn update(path_secrets: &UPKEMaterial, old_public_key: &PublicKey, old_private_key: &SecretKey) -> UPKEMaterial {
        let sk = path_secrets.private_key.0;
        let pk = path_secrets.public_key.0;

        let new_sk = sk + old_private_key.0;
        let new_pk = pk + old_public_key.0; 
        let new_keys = UPKEMaterial {
            private_key: SecretKey(new_sk),
            public_key: PublicKey(new_pk)
        };
        return new_keys;
    }

    /// Updates just the public key information
    pub fn update_public(new_pk: &PublicKey, old_pk: &PublicKey) -> PublicKey{
        PublicKey(new_pk.0 + old_pk.0)
    }
    /// Updates just the secret key information
    pub fn update_private(new_sk: &SecretKey, old_sk: &SecretKey) -> SecretKey {
        SecretKey(new_sk.0 + old_sk.0)
    }
}

impl NodeSecret {
    /// Public and private key bytes are combined to create node secret
    pub fn derive(pk: &PublicKey, sk: &SecretKey) -> Vec<u8> {
        let pk_bytes = pk.0.compress().to_bytes();
        let sk_bytes = sk.0.as_bytes();
        let node_secret: Vec<u8> = [&pk_bytes[..], &sk_bytes[..]].concat();
        return node_secret;
    }
}

impl SymmetricKey {
    /// Node secret is used as input to a kdf to obtain an AES GCM key
    pub fn derive_message_key(node_secret: Vec<u8>, message_counter: u16) -> [u8; 32] {
        // ratchet forward key
        let mut hasher = Sha512::new();
        hasher.update(&node_secret);
        let mut key = hasher.finalize().to_vec();
        
        for _ in 0..message_counter {
            let mut ratchet = Sha512::new();
            ratchet.update(&key);
            key = ratchet.finalize().to_vec();
        }
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        //no salt because we want the same node secret to produce the same key
        let hk = Hkdf::<Sha512>::from_prk(&key).expect("Should be large enough");
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("32 is a valid length for Sha256 to output"); 
        okm     
    }
    pub fn derive(node_secret: Vec<u8>) -> [u8; 32] {
        // ratchet forward key
        let mut hasher = Sha512::new();
        hasher.update(&node_secret);
        let key = hasher.finalize().to_vec();
        
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");

        //no salt because we want the same node secret to produce the same key
        let hk = Hkdf::<Sha512>::from_prk(&key).expect("Should be large enough");
        let mut okm = [0u8; 32];
        hk.expand(&info, &mut okm).expect("32 is a valid length for Sha256 to output"); 
        okm     
    }
    /// AES_GCM encryption produces ciphertext and nonce from plaintext byte vector
    pub fn encrypt(message: &mut Vec<u8>, key: [u8; 32]) -> (Vec<u8>, GenericArray<u8, U12>) {
        let okm: &GenericArray<u8, _> = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(&okm);
        // We create a new instance of the message we own so when we update the encryption buffer we don't overwrite the original message.
        let mut owned_message = message.to_owned();
        // nonce needs to be passed to the decrypt function
        let nonce = Aes256Gcm::generate_nonce(&mut AESRng); // 96-bits; unique per message
        cipher.encrypt_in_place(&nonce, b"", &mut owned_message).unwrap();
        (owned_message.to_vec(), nonce)

    }
    /// AES_GCM decryption requires ciphertext and same nonce used in encryption to produce plaintext byte vector
    pub fn decrypt(message: Vec<u8>, key: [u8; 32], nonce: GenericArray<u8, U12>) -> Vec<u8> {
        let okm: &GenericArray<u8, _> = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(&okm);
        let mut ciphertext = Vec::new();
        ciphertext.extend_from_slice(&message);
        let nonce = nonce;
        cipher.decrypt_in_place(&nonce, b"", &mut ciphertext);
        ciphertext
    }

}

#[cfg(test)]
mod tests {
    

    use super::*;

    use rand::rngs::OsRng;

    #[test]
    fn test_encrypt_decrypt_loop() {
        let mut rng: OsRng = OsRng;

        let mut sk = SecretKey::new(&mut rng);
        let mut pk = PublicKey::new(&sk);

        for i in 0u8..=255 {
            let message = [i; 32];
            let sk_bytes = sk.0.to_bytes();
            let pk_bytes = pk.0.compress().to_bytes();

            let (c, new_pk) = pk.encrypt(message, &mut rng);

            // We want to make sure the public key has changed
            assert_ne!(new_pk.0.compress().to_bytes(), pk_bytes);
            pk = new_pk;

            let (m, new_sk) = sk.decrypt(&c);

            // We want to make sure the secret key has changed
            assert_ne!(new_sk.0.to_bytes(), sk_bytes);
            sk = new_sk;

            // We want to make sure the message is decrypted
            assert_eq!(m, message);
        }
    }
    
    #[test]
    fn test_key_gen() {
        let mut rng: OsRng = OsRng;

        // We want to make sure different keys are generated
        let mut keys1 = UPKEMaterial::generate();
        let keys2 = UPKEMaterial::generate();
        let pk1 = keys1.public_key;
        let sk1 = keys1.private_key;
        let pk2 = keys2.public_key;
        let sk2 = keys2.private_key;

        let pk1_bytes = pk1.0.compress().to_bytes();
        let sk1_bytes = sk1.0.to_bytes();

        assert_ne!(pk1.0.compress().to_bytes(), pk2.0.compress().to_bytes());
        assert_ne!(sk1.0.to_bytes(), sk2.0.to_bytes());

        // We want to make sure the keys are valid and can be used to encrypt and decrypt correctly
        let message = [5; 32];
        let (c, new_pk1) = pk1.encrypt(message, &mut rng);
        let (m, new_sk1) = sk1.decrypt(&c);
        assert_eq!(message, m);

        // We want to make sure the keys can be updated correctly
        keys1.private_key = new_sk1;
        keys1.public_key = new_pk1;
        assert_ne!(keys1.public_key.0.compress().to_bytes(), pk1_bytes);
        assert_ne!(keys1.private_key.0.to_bytes(), sk1_bytes);


    }

    #[test]
    fn test_signatures() {
        // We want to check if the correct signature is valid
        let signing_material: SignatureMaterial = SignatureMaterial::generate();
        let message: &[u8] = b"This is the ultimate test.";
        let signature = signing_material.signing_key.sk.sign(message, Some(Noise::default()));
        assert!(signing_material.signing_key.pk.verify(message, &signature).is_ok());

        // We want to check if only the correct public key can verify a signature
        let new_signing_material: SignatureMaterial = SignatureMaterial::generate();
        assert!(new_signing_material.signing_key.pk.verify(message, &signature).is_err());
    }



    #[test]

    fn test_path_secret_updates() {
        let mut rng: OsRng = OsRng;

        let path_secret = PathSecret::new();
        let old_keys = UPKEMaterial::generate();
        let new_keys = PathSecret::update(&path_secret, &old_keys.public_key, &old_keys.private_key);

        // We want to see if the new keys are valid
        let message = [5; 32];
        let (c, _new_pk) = new_keys.public_key.encrypt(message, &mut rng);
        let (m, _new_sk) = new_keys.private_key.decrypt(&c);

        assert_eq!(m, message);

        // We want to test that the same pathsecret evaluates to the same new keypair and can decrypt
        // the same ciphertext
        let new_keys1 = PathSecret::update(&path_secret, &old_keys.public_key, &old_keys.private_key);
        let (m1, _new_sk) = new_keys1.private_key.decrypt(&c);
        assert_eq!(m1, m);




    }
    #[test]
    fn test_node_secret() {
        // We want to test that the node secret is the concatenated bytes of the keymaterial
        let key = UPKEMaterial::generate();
        let node_secret = NodeSecret::derive(&key.public_key, &key.private_key);
        let sk_bytes = key.private_key.0.to_bytes();
        let pk_bytes = key.public_key.0.compress().to_bytes();
        let concatenated_keys = [&pk_bytes[..], &sk_bytes[..]].concat();
        assert_eq!(node_secret, concatenated_keys);
    }

    #[test]
    fn test_symmetric_key_aes_encryption() {
        //We want to test if we have created a valid AES_GCM key by encrypting and decrypting correctly
        let key = UPKEMaterial::generate();
        let node_secret = NodeSecret::derive(&key.public_key, &key.private_key);
        let message_counter = 1;
        let s_key = SymmetricKey::derive_message_key(node_secret, message_counter);
        // The node converts the symmetric key to the correct type for the AES_GCM library
        let okm: &GenericArray<u8, _> = Key::<Aes256Gcm>::from_slice(&s_key);
        // Encrypt and decrypt
        let nonce = Aes256Gcm::generate_nonce(&mut AESRng); // 96-bits; unique per message
        let mut buffer: Vec<u8> = Vec::new();
        let cipher = Aes256Gcm::new(&okm);
        buffer.extend_from_slice(b"This is the ultimate test!");
        cipher.encrypt_in_place(&nonce, b"", &mut buffer).unwrap();
        assert_ne!(&buffer, b"This is the ultimate test!");
        cipher.decrypt_in_place(&nonce, b"", &mut buffer);
        assert_eq!(&buffer, b"This is the ultimate test!");

    }

    #[test]
    fn test_symmetric_encrypt_decrypt_loop() {
        let message_counter = 1;
        let key = UPKEMaterial::generate();
        let node_secret = NodeSecret::derive(&key.public_key, &key.private_key);
        let key = SymmetricKey::derive_message_key(node_secret, message_counter);
        let mut message = b"This is a test".to_vec();
        let (ciphertext, nonce) = SymmetricKey::encrypt(&mut message, key);

        let plaintext = SymmetricKey::decrypt(ciphertext, key, nonce);
        assert_eq!(message, plaintext);
    }


}
