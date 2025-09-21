extern crate alloc;
extern crate std;
use std::{collections::HashMap, eprintln, fs::OpenOptions};

use aes_gcm::aead::generic_array::GenericArray;
use alloc::{string::String, vec::Vec, fmt::format};
use ed25519_compact::Noise;
use rand_core::OsRng;
use rsa::{pkcs8::{DecodePublicKey, EncodePublicKey}, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::digest::typenum::U12;
use rand::AsByteSliceMut;

use std::io::Write;
use serde::{Serialize, Deserialize};


use crate::{tree::BinaryTree, upke::{Ciphertext, NodeSecret, PathSecret, PublicKey as UPKEPub, RSAKeyPair, SignatureMaterial, SymmetricKey, UPKEMaterial}};


/// Implements functionality a member of a group can take in casual treekem
 #[derive( Clone)]

pub struct Member {
    pub pseudonym: String,
    pub rsa_pub: RsaPublicKey,
    pub rsa_priv: RsaPrivateKey,
    // tree: Option<BinaryTree>,
    pub groups: HashMap<String, Group>,
    pub id: Option<u16>,
    pub credential: Credentials,
    pub signing_key: ed25519_compact::SecretKey,
    pub message_counter: u16
}

#[derive(Debug, Clone)]
#[derive(Serialize, Deserialize)]
pub struct Credentials {
    pub verification_key: Vec<u8>,
    pub pseudonym: String,
    pub signature: Vec<u8>,
    pub rsa_pub: Vec<u8>
}

#[derive(Clone)]
pub struct Group {
    pub threshold: u16,
    pub admins: Vec<u16>,
    pub ratchet_tree: BinaryTree,
}
#[derive(Serialize, Deserialize)]
pub struct BlankMessage {
    pub blanked_node: u16,
    pub encrypt_under: u16,
    pub public: Option<([u8;32], Vec<u8>)>,
    pub private: Option<([u8;32], Vec<u8>)>
}
#[derive(Serialize, Deserialize)]
pub struct SerializedTree {
    pub group_name: String,
    pub public_keys: HashMap<u16, [u8; 32]>,
    pub private_keys: HashMap<u16,[u8; 32]>,
    pub credentials: HashMap<u16, Credentials>,
    pub capacity: u16,
    pub threshold: u16,
    pub admins: Vec<u16>,
    pub action_member_cred: Credentials
}

/// Includes encrypted group symmetric key and encrypted serialized tree information
pub struct WelcomeMessage {
    pub key: Vec<u8>,
    pub update_message: UpdateMessage
}

/// Generic struct for holding encrypted information
pub struct UpdateMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: GenericArray<u8, U12>,
}

#[derive(Clone)]
#[derive(Serialize, Deserialize)]
/// Serializable update material
pub struct UpdateMaterial {
    pub ancestors: Vec<u16>,
    pub public_path_material: Vec<[u8;32]>,
    pub priv_path_material: Vec<([u8;32], Vec<u8>)>,
    pub public_key: [u8;32],
    pub creds: Credentials,
}

impl Credentials {
    /// Combines a public key and pseudonym to generate a credential
    pub fn new(signing_material: &SignatureMaterial, pseudo: String, public_key: RsaPublicKey) -> Credentials {
        let mut vk: ed25519_compact::PublicKey = signing_material.signing_key.pk;
        let sig = signing_material.signing_key.sk.sign(vk.as_byte_slice_mut(), Some(Noise::default()));
        let creds = Credentials {
            verification_key: vk.to_vec(),
            pseudonym: pseudo,
            signature: sig.to_vec(),
            rsa_pub: public_key.to_public_key_der().unwrap().to_vec()
        };
        creds
    }
}

impl Group {
    pub fn new(threshold:u16, tree:BinaryTree) -> Self {
        let admins:Vec<u16> = Vec::new();
        Group {
            threshold: threshold,
            admins: admins,
            ratchet_tree: tree,
        }
    }
}

impl BlankMessage {
    pub fn new() -> Self {
        BlankMessage {
            blanked_node: 0,
            encrypt_under: 0,
            public: None,
            private: None
        }
    }
}




impl Member {
    /// *** Not fully implemented ***  Logs actions a member takes and outputs it to a text file named with the members pseudonym.  Need discussion on what exactly to log
    pub fn logger(action: String, comment: String, pseudonym: &String) {
        // create the file and the entry
        let filename = format(format_args!("{}.txt", pseudonym));
        let mut file = OpenOptions::new().create(true).append(true).open(&filename).expect("Can't create the log file");
        let entry = format(format_args!("Action: {} -- Comment: {}", action, comment));
        // write to the file
        if let Err(_e) = writeln!(file, "{}", entry) {
            eprintln!("Error writing to the file");
        }


        
    }

    /// Generates UPKE and signing material for a member.
    pub fn new(pseudo: String) -> Self {
        let rsa_material = RSAKeyPair::new();
        let signing_material = SignatureMaterial::generate();
        let creds = Credentials::new(&signing_material, pseudo.clone(), rsa_material.rsa_pub.clone());
        // Member::logger(String::from("new"), String::from("Generated UPKE public/private keypair"), &pseudo);
        // Member::logger(String::from("new"), String::from("Generated verification/signing keypair"), &pseudo);
        let groups = HashMap::new();
        let sk = signing_material.signing_key.sk;
        let member = Member {
            pseudonym: pseudo,
            rsa_pub: rsa_material.rsa_pub,
            rsa_priv: rsa_material.rsa_priv,
            groups: groups,
            id: None,
            credential: creds,
            signing_key: sk,
            message_counter: 1
        };
        member
    }

    pub fn automate_group_creation(group_name: String, size: u8, group_capacity: u16) -> Vec<Member>{
        // create all the members
        let mut members = Vec::new();
        for i in 1..=size {
            let member_name = String::from(format(format_args!("Member{}", i)));
            members.push(Member::new(member_name));

        }
        let mut synchronized_group: Vec<Member> = Vec::new();
        // create the group
        members[0].create_group(group_capacity, group_name.clone(), 1);
        members[0].add_to_group(group_name.clone());
        let founding_member = members.remove(0);
        synchronized_group.push(founding_member.clone());
        // loop through to add each member to the group
        let mut count = 0;
        while !members.is_empty() {
            let mut joining_member: Member = members.remove(0);
            let initiator = &mut synchronized_group[count];
            let welcome_message = initiator.send_welcome_message(joining_member.credential.clone(), group_name.clone());
            let path_update_message = joining_member.join_group(welcome_message);
            for member in &mut synchronized_group {
                member.apply_update_path(path_update_message.ciphertext.clone(), path_update_message.nonce, group_name.clone(), joining_member.id.unwrap());
            }
            synchronized_group.push(joining_member.clone());
            count = count + 1;

        }
        synchronized_group

        // let welcome_message= member.send_welcome_message(member2.credential.clone(), group_name.clone());
        // let path_update_message = member2.join_group(welcome_message);
        // member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), member2.id.unwrap());


    }
 
    /// Creates a group with a given name and size and threshold of admins.  Creates the corresponding ratchet tree and adds the group to the members state
    pub fn create_group(&mut self, size: u16, name: String, threshold:u16){
        // let rand_num = rand::thread_rng().gen_range(0, 255);
        let tree = BinaryTree::generate(size);
        let mut group = Group::new(threshold, tree);
        // node that created the group is by default an admin
        group.admins.push(size);
        self.groups.insert(name, group);
    }
    // may want to add funtion to list all groups present for a member

    /// Given a group name, a member is added to the group by placing them in the left-most open node in the tree.  The ancestor key material is updated as well
    pub fn add_to_group(&mut self, group_name: String) -> UpdateMessage {
        // access tree corresponding to group and open node
        let group = self.groups.get_mut(&group_name).unwrap();
        let mut tree =  &mut group.ratchet_tree;
        let open_node_id = tree.get_leftmost_open_leaf(tree.height).unwrap();
        self.id = Some(open_node_id);
        //generate key material for self
        let upke_material = UPKEMaterial::generate();
        // Member::logger(String::from("add_to_group"), String::from("Generated UPKE public/private keypair"), &self.pseudonym);
        let pk = upke_material.public_key;
        let sk = upke_material.private_key;
        let node_secret = NodeSecret::derive(&pk, &sk);
        // Member::logger(String::from("add_to_group"), String::from("Derived node secret"), &self.pseudonym);
        let signature_material = SignatureMaterial::generate();
        // let creds = Credentials::new(&signature_material, self.pseudonym.clone(), pk);
        self.signing_key = signature_material.signing_key.sk;

        //insert key material into tree
        let open_node = tree.get_node_by_id(tree.height, open_node_id).unwrap();
        open_node.public_key = Some(pk);
        open_node.private_key = Some(sk);
        open_node.node_secret = Some(node_secret);
        open_node.credential = Some(self.credential.clone());

        // update path
        Member::update_path(&mut tree, open_node_id, self.pseudonym.clone(), self.message_counter)
    }

    /// Generates an encrypted (using group symetric key) serialized tree and returns the ciphertext along with the nonce
    pub fn serialize(&mut self, group_name: String, key: [u8; 32], cred: Credentials) -> UpdateMessage {
        let group = self.groups.get_mut(&group_name).unwrap();
        let group_name = group_name;
        let public_keys;
        let private_keys;
        let credentials;
        let capacity = group.ratchet_tree.capacity;
        let threshold = group.threshold;
        let admins = group.admins.clone();
        let neighbor_id = group.ratchet_tree.get_leftmost_open_leaf(group.ratchet_tree.height).unwrap();
        {
            let ancestors = group.ratchet_tree.get_ancestor_ids(self.id.unwrap());
            let neighbor_ancestors = group.ratchet_tree.get_ancestor_ids(neighbor_id);
            let serialized_tree = BinaryTree::serialize_tree(&mut self.groups.get_mut(&group_name).unwrap().ratchet_tree, self.id.unwrap(), &ancestors, &neighbor_ancestors);
            public_keys = serialized_tree.0;
            private_keys = serialized_tree.1;
            credentials = serialized_tree.2;
        }
        let serialized_tree = SerializedTree {
            group_name,
            public_keys,
            private_keys,
            credentials,
            capacity,
            threshold,
            admins,
            action_member_cred: cred
        };

        let mut message = serde_json::to_vec(&serialized_tree).expect("Serialization Failed");
        let (ciphertext, nonce) = SymmetricKey::encrypt(&mut message, key);
        UpdateMessage {
            ciphertext,
            nonce,
        }
        
    }

    /// Generates a message containing the encrypted group key (sent under a joining members public key), an encrypted serialized tree, and an associated nonce
    pub fn send_welcome_message(&mut self, cred: Credentials, group_name: String) -> WelcomeMessage{
        let mut rng = aes_gcm::aead::OsRng;
        let group = self.groups.get_mut(&group_name).unwrap();
        let tree = &mut group.ratchet_tree;
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        // Get symmetric key and create AES_GMC cipher
        let node_secret = NodeSecret::derive(&root.public_key.unwrap(), &root.private_key.unwrap());
        let key = SymmetricKey::derive(node_secret.to_vec());
        let serialized_pub = cred.clone().rsa_pub;
        let rsa_pub = RsaPublicKey::from_public_key_der(&serialized_pub).unwrap();
        let c = rsa_pub.encrypt(&mut rng, Pkcs1v15Encrypt, &key).unwrap();
        let tree_info  = self.serialize(group_name, key, cred.clone());
        WelcomeMessage {
            key: c,
            update_message: tree_info
        }
    }



    /// Given a welcome message, a joining member generates the current tree and adds themselves to the left-most open node
    pub fn join_group(&mut self, welcome_message: WelcomeMessage) -> UpdateMessage {
        // deserialize tree and insert into member state
        let mut decrypted_symmetric_key = [0u8; 32]; // Create an array of 0s
        let key_slice = self.rsa_priv.decrypt(Pkcs1v15Encrypt, &welcome_message.key).unwrap();
        decrypted_symmetric_key.copy_from_slice(&key_slice);
        let decrypted_tree = SymmetricKey::decrypt(welcome_message.update_message.ciphertext, decrypted_symmetric_key, welcome_message.update_message.nonce);
        let mut tree_info: SerializedTree = serde_json::from_slice(&decrypted_tree).expect("Deserialization Failed");
        let tree = BinaryTree::deserialize_tree(&mut tree_info.public_keys, &mut tree_info.private_keys, &mut tree_info.credentials, tree_info.capacity);
        let mut group = Group::new(tree_info.threshold, tree);
        group.admins = tree_info.admins.clone();
        self.groups.insert(tree_info.group_name.clone(), group);
        // add yourself to the left most open leaf with newly generated keys and update the path to the root
        self.add_to_group(tree_info.group_name.clone())

    }

    // Takes in the pseudo of the member who called it only for logging purposes and updates key material for its ancestors.  It also returns the new key material so other nodes can update their path
    pub fn update_path(tree: &mut BinaryTree, node_id: u16, _pseudo: String, _message_counter: u16) -> UpdateMessage {
        let mut rng: OsRng = OsRng;
        let mut key: [u8; 32] = [0;32];
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        // Get symmetric key and create AES_GMC cipher
        if root.public_key.is_some() {
            let node_secret = NodeSecret::derive(&root.public_key.unwrap(), &root.private_key.unwrap());
            key = SymmetricKey::derive(node_secret.to_vec());
        }

        // Need to send public key of node along with update
        let public_key = tree.get_node_by_id(tree.height, node_id).unwrap().public_key.unwrap();
        // generate key material for ancestor nodes and put it into tree
        // this only derives key material for the update path.  Not the node itself.  Node can update their own key material separately
        let nodes = tree.get_ancestors(tree.height, node_id);
        let mut ancestors: Vec<u16> = Vec::new();
        for x in nodes {
            ancestors.push(x.id);
        }
        
        let mut ancestors_new_public_material: Vec<[u8;32]> = Vec::new();
        //let mut ancestors_new_private_material: Vec<([u8;32], Vec<u8>)> = Vec::new();
        let mut update_path: Vec<([u8;32], Vec<u8>)> = Vec::new();
        for ancestor in &ancestors {
            // let key_material = PathSecret::new();
            let secret = PathSecret::new_path_secret();
            let new_key_material = PathSecret::derive_key_pair(secret);
            // Member::logger(String::from("updatePath"), String::from("Generated UPKE public/private keypair"), &pseudo);
            let ancestor = tree.get_node_by_id(tree.height, *ancestor).unwrap();
            // store update path key material
            ancestors_new_public_material.push(new_key_material.public_key.to_bytes());
            // check if ancestor is open.  if it is, then combine the key material.  Need to know ancestor material
            if ancestor.public_key.is_some() && ancestor.private_key.is_some() {
                // update secret should first be encrypted under previous public key
                let previous_ancestor_public_key = ancestor.public_key.unwrap();
                let (c, _new_pk) = previous_ancestor_public_key.encrypt(secret, &mut rng);
                // Member::logger(String::from("updatePath"), String::from("Encrypted secret update path material under previous private key"), &pseudo);
                update_path.push(c.serialize());
                let path_key_material = PathSecret::update_with_path_secret(&secret, &ancestor.public_key.as_mut().unwrap(), &ancestor.private_key.as_mut().unwrap());
                // Member::logger(String::from("updatePath"), String::from("Combined old & new key material to derive updatePath key material for ancestor"), &pseudo);
                ancestor.public_key = Some(path_key_material.public_key);
                ancestor.private_key = Some(path_key_material.private_key);
                ancestor.node_secret = Some(NodeSecret::derive(&ancestor.public_key.as_mut().unwrap(), &ancestor.private_key.as_mut().unwrap()));
                // Member::logger(String::from("updatePath"), String::from("Derived node secret for ancestor"), &pseudo);
            } else {
                ancestor.public_key = Some(new_key_material.public_key);
                ancestor.private_key = Some(new_key_material.private_key);
                ancestor.node_secret = Some(NodeSecret::derive(&ancestor.public_key.as_mut().unwrap(), &ancestor.private_key.as_mut().unwrap()));
                // Member::logger(String::from("updatePath"), String::from("Derived node secret for ancestor"), &pseudo);
            }
        }
        let creds = tree.get_node_by_id(tree.height, node_id).unwrap().credential.as_mut().unwrap().clone();
        // update members personal key material


        // Encrypt and send path update message along with nonce
    

        let path_update_message = UpdateMaterial{
            ancestors: ancestors,
            public_path_material: ancestors_new_public_material,
            priv_path_material: update_path,
            public_key: public_key.to_bytes(),
            creds: creds
        };
        
        let mut message = serde_json::to_vec(&path_update_message).expect("Serialization Failed");
        let (ciphertext, nonce) = SymmetricKey::encrypt(&mut message, key);
        UpdateMessage {
            ciphertext,
            nonce,
        }
    }

    pub fn key_refresh(&mut self, group_name: String, node_id: u16, _pseudo: String) -> UpdateMessage {
        let mut rng: OsRng = OsRng;
        let mut key: [u8; 32] = [0;32];
        let group = self.groups.get_mut(&group_name).unwrap();
        let tree = &mut group.ratchet_tree;
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        // Get symmetric key and create AES_GMC cipher
        if root.public_key.is_some() {
            let node_secret = NodeSecret::derive(&root.public_key.unwrap(), &root.private_key.unwrap());
            key = SymmetricKey::derive(node_secret.to_vec());
        }

        // Need to send public key of node along with update
        let new_member_key_material = UPKEMaterial::generate();
        let public_key = new_member_key_material.public_key;
        // generate key material for ancestor nodes and put it into tree
        // this only derives key material for the update path.  Not the node itself.  Node can update their own key material separately
        let nodes = tree.get_ancestors(tree.height, node_id);
        let mut ancestors: Vec<u16> = Vec::new();
        for x in nodes {
            ancestors.push(x.id);
        }
        
        let mut ancestors_new_public_material: Vec<[u8;32]> = Vec::new();
        // let mut ancestors_new_private_material: Vec<([u8;32], Vec<u8>)> = Vec::new();
        let mut ancestors_path_update: Vec<([u8;32], Vec<u8>)> = Vec::new();
        for ancestor in &ancestors {
            let path_secret = PathSecret::new_path_secret();
            let new_key_material = PathSecret::derive_key_pair(path_secret);
            // Member::logger(String::from("updatePath"), String::from("Generated UPKE public/private keypair"), &pseudo);
            let ancestor = tree.get_node_by_id(tree.height, *ancestor).unwrap();
            // store update path key material
            ancestors_new_public_material.push(new_key_material.public_key.to_bytes());
            // check if ancestor is open.  if it is, then combine the key material
            if ancestor.public_key.is_some() {
                // private material should first be encrypted under previous public key
                let previous_ancestor_public_key = ancestor.public_key.unwrap();
                let (c, _new_pk) = previous_ancestor_public_key.encrypt(path_secret, &mut rng);
                // Member::logger(String::from("updatePath"), String::from("Encrypted secret update path material under previous private key"), &pseudo);
                ancestors_path_update.push(c.serialize());
                let path_key_material = PathSecret::update_with_path_secret(&path_secret, &ancestor.public_key.as_mut().unwrap(), &ancestor.private_key.as_mut().unwrap());
                // Member::logger(String::from("updatePath"), String::from("Combined old & new key material to derive updatePath key material for ancestor"), &pseudo);
                ancestor.public_key = Some(path_key_material.public_key);
                ancestor.private_key = Some(path_key_material.private_key);
                ancestor.node_secret = Some(NodeSecret::derive(&ancestor.public_key.as_mut().unwrap(), &ancestor.private_key.as_mut().unwrap()));
                // Member::logger(String::from("updatePath"), String::from("Derived node secret for ancestor"), &pseudo);
            } else {
                ancestor.public_key = Some(new_key_material.public_key);
                ancestor.private_key = Some(new_key_material.private_key);
                ancestor.node_secret = Some(NodeSecret::derive(&ancestor.public_key.as_mut().unwrap(), &ancestor.private_key.as_mut().unwrap()));
                // Member::logger(String::from("updatePath"), String::from("Derived node secret for ancestor"), &pseudo);
            }
        }
        let creds = tree.get_node_by_id(tree.height, node_id).unwrap().credential.as_mut().unwrap().clone();
        let member = tree.get_node_by_id(tree.height, node_id).unwrap();
        member.public_key = Some(public_key);
        member.private_key = Some(new_member_key_material.private_key);
        
        // Encrypt and send path update message along with nonce
    

        let path_update_message = UpdateMaterial{
            ancestors: ancestors,
            public_path_material: ancestors_new_public_material,
            priv_path_material: ancestors_path_update,
            public_key: public_key.to_bytes(),
            creds: creds
        };
        
        let mut message = serde_json::to_vec(&path_update_message).expect("Serialization Failed");
        let (ciphertext, nonce) = SymmetricKey::encrypt(&mut message, key);
        UpdateMessage {
            ciphertext,
            nonce,
        }
    }

    /// This updatepath information needs to be properly decrypted and parsed so it can be applied by other members of the tree
    pub fn apply_update_path(&mut self, path_update_message: Vec<u8>, nonce: GenericArray<u8, U12>, group_name: String, updating_node: u16){
        let group = self.groups.get_mut(&group_name).unwrap();
        let tree = &mut group.ratchet_tree;
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        // Get symmetric key and create AES_GMC cipher
        let node_secret = NodeSecret::derive(&root.public_key.unwrap(), &root.private_key.unwrap());
        let key = SymmetricKey::derive(node_secret.to_vec());
        let decrypted_serialized_tree = SymmetricKey::decrypt(path_update_message, key, nonce);
        let mut path_update_message: UpdateMaterial  = serde_json::from_slice(&decrypted_serialized_tree).expect("Deserialization Failed");

        while !path_update_message.ancestors.is_empty() {
            let current_ancestor = path_update_message.ancestors.pop().unwrap();
            // we get the ancestor node by id and apply public key material
            {
                let public_update = UPKEPub::from_bytes_mod_order(path_update_message.public_path_material.pop().unwrap());
                let current_ancestor_node = tree.get_node_by_id(tree.height, current_ancestor).unwrap();
                if current_ancestor_node.public_key.is_some() {
                    let new_public_key = PathSecret::update_public(&public_update, &current_ancestor_node.public_key.unwrap());
                    current_ancestor_node.public_key = Some(new_public_key);
                } else {
                    current_ancestor_node.public_key = Some(public_update);
                }
            }
            // if ancestor, we apply the secret key material
            let ancestors = tree.get_ancestors(tree.height, self.id.unwrap());
            let mut ancestor_ids: Vec<u16> = Vec::new();
            for x in ancestors {
                ancestor_ids.push(x.id);
            }
            if ancestor_ids.contains(&current_ancestor) {
                let current_ancestor_node = tree.get_node_by_id(tree.height, current_ancestor).unwrap();
                let serialized_path_secret = path_update_message.priv_path_material.pop();
                if serialized_path_secret.is_some() {
                    let opened_value = serialized_path_secret.unwrap();
                    let ciphertext = Ciphertext::deserialize(opened_value.0, opened_value.1);
                    let (path_secret, _new_sk) = current_ancestor_node.private_key.unwrap().decrypt(&ciphertext);
                    let update_keypair = PathSecret::derive_key_pair(path_secret);
                    if current_ancestor_node.private_key.is_some() {
                        let new_secret_key = PathSecret::update_private(&update_keypair.private_key, &current_ancestor_node.private_key.unwrap());
                        current_ancestor_node.private_key = Some(new_secret_key);
                    } else {
                        current_ancestor_node.private_key = Some(update_keypair.private_key);
                    }
                }
            }
            // if not we don't change the secret key material
        }
        let updating_node = tree.get_node_by_id(tree.height, updating_node).unwrap();
        updating_node.public_key = Some(UPKEPub::from_bytes_mod_order(path_update_message.public_key));
        updating_node.credential = Some(path_update_message.creds);
        
    }

    pub fn blank_node(&mut self, group_name: String, id: u16) -> UpdateMessage{
        let mut rng: OsRng = OsRng;
        let mut messages: Vec<BlankMessage> = Vec::new();
        // let blank_key_material = UPKEMaterial::generate();
        let path_secret = PathSecret::new_path_secret();
        let blank_key_material = PathSecret::derive_key_pair(path_secret);
        let group = self.groups.get_mut(&group_name).unwrap();
        let tree = &mut group.ratchet_tree;
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        // Get symmetric key and create AES_GMC cipher
        let node_secret = NodeSecret::derive(&root.public_key.unwrap(), &root.private_key.unwrap());
        let key = SymmetricKey::derive(node_secret.to_vec());

        {
            let group = self.groups.get_mut(&group_name).unwrap();
            let tree = &mut group.ratchet_tree;
            // get info on node we want to remove.  Need their ancestors to get the correct nodes to encrypt under
            let ancestors_id = tree.get_ancestor_ids(id);
            let nodes = tree.get_blank_node_path(tree.height, id, ancestors_id);
            let mut nodes_encrypt_under = Vec::new();
            for x in nodes {
                nodes_encrypt_under.push(x.id);
            }
            // get public keys of each node in the blank path and encrypt key material with them
            for i in nodes_encrypt_under {
                let mut message = BlankMessage::new();
                message.encrypt_under = i;
                message.blanked_node = id;
                let  current_node = tree.get_node_by_id(tree.height, i);
                if current_node.as_ref().unwrap().public_key.is_some() {
                    let (public, _new_sk) = current_node.as_ref().unwrap().public_key.unwrap().encrypt(blank_key_material.public_key.to_bytes(), &mut rng);
                    message.public = Some(public.serialize());
                    let (private, _new_pk) = current_node.as_ref().unwrap().public_key.unwrap().encrypt(path_secret, &mut rng);
                    message.private = Some(private.serialize());
                    // add each separately encrypted blanking message to the list to send
                    messages.push(message);

                }
            }
            self.blank(group_name.clone(), id);
        }
        // update all nodes in your tree with the update material you generated
        let group = self.groups.get_mut(&group_name).unwrap();
        let tree = &mut group.ratchet_tree;
        let nodes_in_tree = tree.get_all_nodes(tree.height);
        for node_id in nodes_in_tree {
            // edit the key material
            let node = tree.get_node_by_id(tree.height, node_id).unwrap();
            if node.public_key.is_some() {
                let updated_pub = UPKEMaterial::update_public(&blank_key_material.public_key, &node.public_key.unwrap());
                node.public_key = Some(updated_pub);
                if node.private_key.is_some(){
                    let updated_priv = UPKEMaterial::update_private(&blank_key_material.private_key, &node.private_key.unwrap());
                    node.private_key = Some(updated_priv);
                }
            }
        }
        // generate encrypted message so other members can remove nodes
        let mut blank_update = serde_json::to_vec(&messages).expect("Serialization Failed");
        let (ciphertext, nonce) = SymmetricKey::encrypt(&mut blank_update, key);
        UpdateMessage {
            ciphertext,
            nonce,
        }
    }

    pub fn apply_blank_message(&mut self, group_name: String, blank_message: UpdateMessage) {
        // initialise key material.  will be overwritten
        let init_key_material = UPKEMaterial::generate();
        let mut blank_public_material = init_key_material.public_key;
        let mut blank_private_material = init_key_material.private_key;
        // generate key needed for decryption of update message
        let group = self.groups.get_mut(&group_name).unwrap();
        let tree = &mut group.ratchet_tree;
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        // Get symmetric key and create AES_GMC cipher
        let node_secret = NodeSecret::derive(&root.public_key.unwrap(), &root.private_key.unwrap());
        let key = SymmetricKey::derive(node_secret.to_vec());
        let decrypted_blank_message = SymmetricKey::decrypt(blank_message.ciphertext, key, blank_message.nonce);
        let blank_message: Vec<BlankMessage> =  serde_json::from_slice(&decrypted_blank_message).expect("Deserialization Failed");
        {
            let group = self.groups.get_mut(&group_name).unwrap();
            let tree = &mut group.ratchet_tree;
            let ancestor_ids = tree.get_ancestor_ids(self.id.unwrap());
 

            // find the right message that was intended for you
            for message in blank_message {
                if ancestor_ids.contains(&message.encrypt_under) || message.encrypt_under == self.id.unwrap() {
                    let (public_material, _new_sk) = tree.get_node_by_id(tree.height, message.encrypt_under).unwrap().private_key.unwrap().decrypt(&Ciphertext::deserialize(message.public.clone().unwrap().0, message.public.unwrap().1));
                    blank_public_material = UPKEPub::from_bytes_mod_order(public_material);
                    let (private_material, _new_sk) = tree.get_node_by_id(tree.height, message.encrypt_under).unwrap().private_key.unwrap().decrypt(&Ciphertext::deserialize(message.private.clone().unwrap().0, message.private.unwrap().1));
                    blank_private_material = PathSecret::derive_key_pair(private_material).private_key;
                    // blank_private_material = UPKEPriv::from_bytes_mod_order(private_material);
                    self.blank(group_name.clone(), message.blanked_node);
                    break;
                }
            }
        }
        // apply the key material to every applicable node in the tree
        {
            let group = self.groups.get_mut(&group_name).unwrap();
            let tree = &mut group.ratchet_tree;
            let nodes_in_tree = tree.get_all_nodes(tree.height);
            for node_id in nodes_in_tree {
                // edit the key material
                let node = tree.get_node_by_id(tree.height, node_id).unwrap();
                if node.public_key.is_some() {
                    let updated_pub = UPKEMaterial::update_public(&blank_public_material, &node.public_key.unwrap());
                    node.public_key = Some(updated_pub);
                    if node.private_key.is_some(){
                        let updated_priv = UPKEMaterial::update_private(&blank_private_material, &node.private_key.unwrap());
                        node.private_key = Some(updated_priv);
                    }
                }
            }
        }



    }

    pub fn blank(&mut self, group_name: String, id: u16) {
        let group = self.groups.get_mut(&group_name).unwrap();
        let tree = &mut group.ratchet_tree;
        let node_to_be_blanked = tree.get_node_by_id(tree.height, id).unwrap();
        // blank all key material
        node_to_be_blanked.node_secret = None;
        node_to_be_blanked.private_key = None;
        node_to_be_blanked.public_key = None;
        node_to_be_blanked.credential = None;
    }

    /// Encryption messages sent under the group symmetric key
    pub fn encrypt_application_message(&mut self, mut message: Vec<u8>, group_name: String) -> (Vec<u8>, GenericArray<u8, U12>, u16){    
    //get root node
    let group = self.groups.get_mut(&group_name).unwrap();
    let tree = &mut group.ratchet_tree;
    let root = tree.get_node_by_id(tree.height, 1).unwrap();
    // Get symmetric key and create AES_GMC cipher
    let node_secret = NodeSecret::derive(&root.public_key.unwrap(), &root.private_key.unwrap());
    let key = SymmetricKey::derive_message_key(node_secret.to_vec(), self.message_counter);
    // Member::logger(String::from("encrypt_application_message"), String::from("Derive symmetric group key"), &self.pseudonym);
    // encrypt message under root symettric key
    // let mut message = message.into_bytes();
    let (ciphertext, nonce) = SymmetricKey::encrypt(&mut message, key);
    // Member::logger(String::from("encrypt_application_message"), String::from(format(format_args!("Ciphertext is {} bytes", ciphertext.len()))), &self.pseudonym);
    let message_counter = self.message_counter;
    self.message_counter += 1;
    return (ciphertext, nonce, message_counter);
    }

    /// Decrypts messages sent under the group symmetric key
    pub fn decrypt_application_message(&mut self, ciphertext: Vec<u8>, group_name: String, nonce: GenericArray<u8, U12>, message_counter: u16) -> Vec<u8>{
        // update message counter
        let group = self.groups.get_mut(&group_name).unwrap();
        let tree = &mut group.ratchet_tree;        
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        // Get symmetric key and create AES_GMC cipher
        let node_secret = NodeSecret::derive(&root.public_key.unwrap(), &root.private_key.unwrap());
        let key = SymmetricKey::derive_message_key(node_secret.to_vec(), message_counter);
        // Member::logger(String::from("decrypt_application_message"), String::from("Derive symmetric group key"), &self.pseudonym);
        // decrypt message under root symettric key
        let plaintext = SymmetricKey::decrypt(ciphertext, key, nonce);
        // Member::logger(String::from("derypt_application_message"), String::from(format(format_args!("Plaintext is {} bytes", plaintext.len()))), &self.pseudonym);
        if message_counter < self.message_counter {
            self.message_counter = self.message_counter + 1;
        } else {
            self.message_counter = message_counter + 1;
        }
        return plaintext;
    }

    






        

}
    

#[cfg(test)]
mod tests {
    extern crate alloc;
    use core::str::FromStr;

    use alloc::{string::String, vec::Vec};
    use ed25519_compact::{Noise, Signature};
    use rand_core::OsRng;
    use rsa::Pkcs1v15Encrypt;
    use sha2::digest::{consts::U12, generic_array::GenericArray};

    use crate::{member::{Credentials, UpdateMessage, UpdateMaterial}, tree::{BinaryTree, Node}, upke::{Ciphertext, NodeSecret, PathSecret, PublicKey, RSAKeyPair, SecretKey, SignatureMaterial, SymmetricKey, UPKEMaterial}};

    use super::{Group, Member};


    #[test]
    //We want to test the attributes of a member a valid.  Key material and pseudonym
    pub fn test_new_member() {
        let mut rng = aes_gcm::aead::OsRng;
        // Testing valid pseudonym
        let member = Member::new(String::from("bob"));
        assert_eq!(member.pseudonym, "bob");
        // Testing valid rsa key material
        let test_message = b"Created a new member.  Lets see!";
        let c = member.rsa_pub.encrypt(&mut rng, Pkcs1v15Encrypt, test_message).unwrap();
        let decrypted_message = member.rsa_priv.decrypt(Pkcs1v15Encrypt, &c).unwrap();
        assert_eq!(decrypted_message, test_message);
        // Testing valid signature material
        let signature = member.signing_key.sign(test_message, Some(Noise::default()));
        let serialized_pk = member.credential.verification_key;
        let pk = ed25519_compact::PublicKey::from_slice(&serialized_pk).unwrap();
        assert!(pk.verify(test_message, &signature).is_ok());
        // Groups map should be empty. Hasn't been intialized yet because a group hasn't been created
        assert_eq!(member.groups.len(), 0);        
    }

    #[test]
    fn test_credentials() {
        // We want to test if a cred can be used to verify the identity of someone
        // use the verification key on the credential to verify the signature
        let rsa_material = RSAKeyPair::new();
        let signing_material = SignatureMaterial::generate();
        let creds = Credentials::new(&signing_material, String::from_str("alice").unwrap(), rsa_material.rsa_pub);
        let signature = Signature::from_slice(&creds.signature).unwrap();
        let serialized_vk = creds.verification_key;
        let vk = ed25519_compact::PublicKey::from_slice(&serialized_vk).unwrap();
        assert!((vk.verify(serialized_vk, &signature)).is_ok());
    }

    #[test]
    pub fn test_member_credentials() {
        // Credentials should be taken from the state of the member
        let member = Member::new(String::from("Alice"));
        // test the validity of the credentials
        let serialized_sig = member.credential.signature;
        let serialized_vk = member.credential.verification_key;
        let sig = Signature::from_slice(&serialized_sig).unwrap();
        let vk = ed25519_compact::PublicKey::from_slice(&serialized_vk).unwrap();
        assert!(vk.verify(serialized_vk, &sig).is_ok());
        
    }

    // #[test]
    // pub fn welcome_message_serialization() {
    //     let mut member = Member::new(String::from("Alice"));
    //         let mut member2 = Member::new(String::from("Bob"));
    //         let group_name = String::from("anonymous");
    
    //         // First generate two members, and a group
    //         member.create_group(4, String::from("anonymous"), 1);
    //         member.add_to_group(String::from("anonymous"));
    //         {
    //             // synchronize the the individuals members ratchet trees
    //             let alice_group = member.groups.get_mut("anonymous").unwrap();
    //             let mut alice_tree = &mut alice_group.ratchet_tree;
    //             let (welcome, key) = member.send_welcome_message(member2.credential, group_name);
    //             let (serialized_tree, nonce) = member.serialize(group_name, key);
    //             let message = serde_json::to_vec(&serialized_tree).expect("Serialization Failed");
    //             let mut welcome_message = member.send_welcome_message(serialized_tree, member2.credential.clone());
    //             let decrypted_welcome_message = member2.rsa_priv.decrypt(Pkcs1v15Encrypt, &welcome_message.ciphertext).unwrap();
    //             assert_eq!(message, decrypted_welcome_message);
    //         }
    // }

    #[test]
    pub fn test_create_group() {
        // Test to see if the group is initialized in the members stored state
        let mut member = Member::new(String::from("Bob"));
        member.create_group(2, String::from("anonymous"), 1);
        assert_eq!(member.groups.len(), 1);
        // Test to see if the tree has the correct number of leaves
        if member.groups.contains_key("anonymous") {
            let group = member.groups.get_mut("anonymous").unwrap();
            let tree = &mut group.ratchet_tree;
            assert_eq!(tree.get_leaves(tree.height).len(), 2);
            // the admin threshold should be 1
            assert_eq!(group.threshold, 1);
        } else {
            assert!(false);
        }
        

    }
    
    #[test]
    pub fn test_automate_group_creation() {
        let group_name = String::from("anonymous");
        let size = 40;
        let group_capacity = 128;
        let mut members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
        let message = String::from("This is a test!").into_bytes();
        // assert thet we have 40 members
        assert_eq!(members.len(), 40);

        // assert that they all have the correct group key.  
        // test by encrypting to arbitrary members
        let (encrypted_message, nonce, message_counter) = members[4].encrypt_application_message(message.clone(), group_name.clone());
        let decrypted_message = members[35].decrypt_application_message(encrypted_message, group_name.clone(), nonce, message_counter);
        assert_eq!(message, decrypted_message);

        let group_name = String::from("anonymous");
        let size = 127;
        let group_capacity = 128;
        let mut members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
        let message = String::from("This is a test!").into_bytes();
        // assert thet we have 127 members
        assert_eq!(members.len(), 127);
        // assert that they all have the correct group key.  
        // test by encrypting to arbitrary members
        let (encrypted_message, nonce, message_counter) = members[4].encrypt_application_message(message.clone(), group_name.clone());
        let decrypted_message = members[35].decrypt_application_message(encrypted_message, group_name.clone(), nonce, message_counter);
        assert_eq!(message, decrypted_message);
        // assert we can add a member manually
        let mut alice = Member::new(String::from("alice"));
        let welcome_message= members[10].send_welcome_message(alice.credential.clone(), group_name.clone());
        let path_update_message = alice.join_group(welcome_message);
        members[10].apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());





    }

    #[test]
    pub fn test_add_to_group() {
        let mut rng: OsRng = OsRng;
        // We want to test the functionality of adding a member to the leftmost open node
        // Here we added Alice. We want to check that she is in position 2 and her key material is valid.
        //  This should be reflected in her tree state
        let mut member = Member::new(String::from("Alice"));
        member.create_group(2, String::from("anonymous"), 1);
        member.add_to_group(String::from("anonymous"));
        let group = member.groups.get_mut("anonymous").unwrap();
        let tree = &mut group.ratchet_tree;
        let node = tree.get_node_by_id(tree.height, 2).unwrap();
        let pk = node.public_key.as_mut().unwrap();
        let sk = node.private_key.as_mut().unwrap();
        let node_secret = node.node_secret.as_mut();
        let message = [5; 32];
        let (c, _new_pk1) = pk.encrypt(message, &mut rng);
        let (m, _new_sk1) = sk.decrypt(&c);
        assert_eq!(message, m);
        // Test the node secret is there
        assert!(node_secret.is_some());
        // Test that alice has information about admins
        assert_eq!(group.threshold, 1);
        assert_eq!(group.admins.len(), 1);
        assert_eq!(group.admins[0], 2);

    }

    #[test]
    pub fn test_blank_node() {
        {
            // We want to test that a member can remove someone themself and the tree is updated accordingly
            // New key material on every node with the node that is removed no longer in the tree
            let mut member = Member::new(String::from("Alice"));
            let mut member2 = Member::new(String::from("Bob"));
            let group_name = String::from("anonymous");
    
            // First generate two members, and a group
            member.create_group(4, String::from("anonymous"), 1);
            member.add_to_group(String::from("anonymous"));
            {
                // invite a member new member
                // synchronize the the individuals members ratchet trees
                let welcome_message= member.send_welcome_message(member2.credential.clone(), group_name.clone());
                let path_update_message = member2.join_group(welcome_message);
                member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), member2.id.unwrap());
                // check that Alice has Bob in her tree.  Bob occupies the node with id of 5
                let alice_tree = member.groups.get_mut("anonymous").unwrap();
                assert!(alice_tree.ratchet_tree.get_node_by_id(alice_tree.ratchet_tree.height, 5).unwrap().public_key.is_some());
            }
            {
                // Now we remove Bob and we check that every leaf is empty.  Should be three empty leaves
                member.blank_node(group_name.clone(), 5);
                let alice_group = member.groups.get_mut("anonymous").unwrap();
                let alice_tree = &mut alice_group.ratchet_tree;
                assert!(alice_tree.get_node_by_id(alice_tree.height, 5).unwrap().public_key.is_none());
                assert!(alice_tree.get_node_by_id(alice_tree.height, 5).unwrap().credential.is_none());
                assert!(alice_tree.get_node_by_id(alice_tree.height, 6).unwrap().public_key.is_none());
                assert!(alice_tree.get_node_by_id(alice_tree.height, 7).unwrap().public_key.is_none());



            }

        }
    }

    #[test]
    pub fn test_apply_blank_message() {
        {
            // We want to test that a member can remove someone themself and the tree is updated accordingly
            // New key material on every node with the node that is removed no longer in the tree
            let mut member = Member::new(String::from("Alice"));
            let mut member2 = Member::new(String::from("Bob"));
            let mut member3 = Member::new(String::from("Mike"));

            // Generate a group and add the founding member
            let group_name = String::from("anonymous");
            let test_message = String::from("Well, lets see if it works!").into_bytes();
            member.create_group(4, String::from("anonymous"), 1);
            member.add_to_group(String::from("anonymous"));
            {
                // synchronize the the individuals members ratchet trees
                let welcome_message= member.send_welcome_message(member2.credential.clone(), group_name.clone());
                let path_update_message = member2.join_group(welcome_message);
                member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), member2.id.unwrap());
                // check that Alice has Bob in her tree.  Bob occupies the node with id of 5
                let alice_group = member.groups.get_mut("anonymous").unwrap();
                let alice_tree = &mut alice_group.ratchet_tree;
                assert!(alice_tree.get_node_by_id(alice_tree.height, 5).unwrap().public_key.is_some());
            }
            {
                // add a third member Mike and make sure Alice and Bob have him in the group
                let welcome_message= member.send_welcome_message(member3.credential.clone(), group_name.clone());
                let path_update_message = member3.join_group(welcome_message);
                member.apply_update_path(path_update_message.ciphertext.clone(), path_update_message.nonce, group_name.clone(), member3.id.unwrap());
                member2.apply_update_path(path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), member3.id.unwrap());
            }
            {
                // check that alice and bob have mike now
                let alice_group = member.groups.get_mut("anonymous").unwrap();
                let alice_tree = &mut alice_group.ratchet_tree;                
                let bob_group = member2.groups.get_mut("anonymous").unwrap();
                let bob_tree = &mut bob_group.ratchet_tree;
                assert!(alice_tree.get_node_by_id(alice_tree.height, 6).unwrap().public_key.is_some());
                assert!(bob_tree.get_node_by_id(bob_tree.height, 6).unwrap().public_key.is_some());
                // Just making sure Alice and Bob's key material for their ancestors is the same
                let bobs_ancestor_secret = bob_tree.get_node_by_id(bob_tree.height, 2).unwrap().private_key.unwrap().to_bytes();
                let alice_ancestor_secret = alice_tree.get_node_by_id(alice_tree.height, 2).unwrap().private_key.unwrap().to_bytes();
                assert_eq!(bobs_ancestor_secret, alice_ancestor_secret);
                let bobs_ancestor_secret = bob_tree.get_node_by_id(bob_tree.height, 1).unwrap().private_key.unwrap().to_bytes();
                let alice_ancestor_secret = alice_tree.get_node_by_id(alice_tree.height, 1).unwrap().private_key.unwrap().to_bytes();
                assert_eq!(bobs_ancestor_secret, alice_ancestor_secret);
            }
            {
                // now we remove Mike and check to see that he no longer appears in Alice tree.  Mike has an id of 6
                let blank_message = member.blank_node(group_name.clone(), member3.id.unwrap());
                let alice_group = member.groups.get_mut("anonymous").unwrap();
                let alice_tree = &mut alice_group.ratchet_tree;
                assert!(alice_tree.get_node_by_id(alice_tree.height, member3.id.unwrap()).unwrap().public_key.is_none());
                // bob should still have Mike in his tree
                let bob_group = member2.groups.get_mut("anonymous").unwrap();
                let bob_tree = &mut bob_group.ratchet_tree;
                assert!(bob_tree.get_node_by_id(bob_tree.height, member3.id.unwrap()).unwrap().public_key.is_some());
                // now lets update Bob since he is a current member and needs the update
                member2.apply_blank_message(group_name.clone(), blank_message);

            }
            {
                let bob_group = member2.groups.get_mut("anonymous").unwrap();
                let bob_tree = &mut bob_group.ratchet_tree;
                let alice_group = member.groups.get_mut("anonymous").unwrap();
                let alice_tree = &mut alice_group.ratchet_tree;

                // compare keys (their direct ancestor which is node 2 should have the same keys.  Do this with node 1 as well, the root node)
                let bobs_ancestor_secret = bob_tree.get_node_by_id(bob_tree.height, 1).unwrap().public_key.unwrap().to_bytes();
                let alice_ancestor_secret = alice_tree.get_node_by_id(alice_tree.height, 1).unwrap().public_key.unwrap().to_bytes();
                assert_eq!(bobs_ancestor_secret, alice_ancestor_secret);
                // now we check again to see that Bob no longer has Mike in his tree
                assert!(bob_tree.get_node_by_id(bob_tree.height, member3.id.unwrap()).unwrap().public_key.is_none());
                // additionally if Bob encrypts to group alice should be able to decrypt since they updated by the same material
                // since the group key is derived from public and private root keys, if this succeeds, they were updated correctly by both members
                let (ciphertext, nonce, message_counter) = member2.encrypt_application_message(test_message.clone(), group_name.clone());
                let plaintext = member.decrypt_application_message(ciphertext.clone(), group_name.clone(), nonce, message_counter);
                assert_eq!(test_message.clone(), plaintext);
                // However, Mike should be left out.  He is no longer part of the group.  He can't decrypt correctly
                let plaintext_mike = member3.decrypt_application_message(ciphertext, group_name, nonce, message_counter);
                assert_ne!(test_message, plaintext_mike);
                



            }

        }
    }

    #[test]
    pub fn test_update_path() {
        let c: Ciphertext;
        let mut m: [u8; 32];
        let new_pk1: PublicKey;
        let new_sk1: SecretKey;
        let _new_sk2: SecretKey;
        let message: [u8; 32] = [5; 32];
        let old_ancestor_public_key: PublicKey;
        let old_ancestor_private_key: SecretKey;
        let mut rng: OsRng = OsRng;
        let update_path_message: UpdateMessage;
        let ancestor: &mut Node;
        let tree: &mut BinaryTree;
        let group: &mut Group;

        let mut member: Member = Member::new(String::from("Bob"));
        member.create_group(4, String::from("anonymous"), 1);
        member.add_to_group(String::from("anonymous"));
        group = member.groups.get_mut("anonymous").unwrap();
        {
            // We want to test that the ancestor nodes are occupied with key material
            tree = &mut group.ratchet_tree;
            
            let nodes = tree.get_ancestors(tree.height, 4);
            let mut ancestors= Vec::new();
            for x in nodes {
                ancestors.push(x.id);
            }
            for ancestor in ancestors {
                let x = tree.get_node_by_id(tree.height, ancestor);
                assert!(x.unwrap().public_key.is_some());
            }
            // We want to test that a node that doesn't share intermediate ancestors has no key material.  With a tree of 4 leaves and the root starting at 1, 
            //we can test that node 3 is empty
            let node3 = tree.get_node_by_id(tree.height, 3).unwrap();
            assert!(node3.public_key.is_none());
            // Let's update the key material and see that the keys have changed.  We want to update this for the member node again.  The id is 4.
            // The old key material should successfully decrypt the message, but the new key material should fail to decrypt the outdated message.
            {
                // Get the root ancestor of node 4
                let root = tree.get_node_by_id(tree.height, 1).unwrap();
                old_ancestor_public_key = root.public_key.unwrap();
                old_ancestor_private_key = root.private_key.unwrap();
                c = root.public_key.as_mut().unwrap().encrypt(message, &mut rng).0;
                m = root.private_key.as_mut().unwrap().decrypt(&c).0;
                assert_eq!(message, m);
            }
          
        
            {
                new_pk1 = tree.get_node_by_id(tree.height, 1).unwrap().public_key.unwrap();
                new_sk1 = tree.get_node_by_id(tree.height, 1).unwrap().private_key.unwrap();
                update_path_message = Member::update_path( tree, 4, member.pseudonym.clone(), member.message_counter);
                ancestor = tree.get_node_by_id(tree.height, 1).unwrap();
                (m, _new_sk2) = ancestor.private_key.as_mut().unwrap().decrypt(&c);
                assert_ne!(message, m);
            }
        }
  

        // We want to test that this function returns the updating key material for each ancestor along the path
        // There should be two ancestors for node 4
        
        // Get symmetric key and create AES_GMC cipher
        {
            let node_secret = NodeSecret::derive(&new_pk1, &new_sk1);
            let _message_counter: u16 = 1;
            let key = SymmetricKey::derive(node_secret);
            let decrypted_path_update = SymmetricKey::decrypt(update_path_message.ciphertext, key, update_path_message.nonce);
            let mut deserialized_update_path: UpdateMaterial =  serde_json::from_slice(&decrypted_path_update).expect("Deserialization Failed");
            assert_eq!(deserialized_update_path.public_path_material.len(), 2);
            // We should be able to get the update path secret keys of its ancestors nodes by decrypting using the previous keys
            // We can manually combine the update key material and show we can successfully decrypt
            let mut encrypted_private_update_path_material= c;
            let mut public_update_path_material = new_pk1;
            while deserialized_update_path.ancestors.len()> 0 {
                let id = deserialized_update_path.ancestors.pop().unwrap();
                let serialized_priv_material = deserialized_update_path.priv_path_material.pop().unwrap();
                encrypted_private_update_path_material = Ciphertext::deserialize(serialized_priv_material.0, serialized_priv_material.1);
                public_update_path_material = PublicKey::from_bytes_mod_order(deserialized_update_path.public_path_material.pop().unwrap());
                if id == 1 {
                    break;
                }
            }
            // check that the correct ancestor is using the correct key material to update their path.  Here we are checking ancestor 2.  Applying the update
            // on the old keys for ancestor 2 should result key material that ends in correct encryption and decryption
            let (decrypted_private_update_path_material, _sk) = ancestor.private_key.as_mut().unwrap().decrypt(&encrypted_private_update_path_material);
            let path_secrets = UPKEMaterial {public_key: public_update_path_material, private_key:SecretKey::from_bytes_mod_order(decrypted_private_update_path_material) };
            let node_key_material: UPKEMaterial = PathSecret::update(&path_secrets, &old_ancestor_public_key, &old_ancestor_private_key);
            let (c, _new_pub) = node_key_material.public_key.encrypt(message, &mut rng);
            let (m, _new_priv) = ancestor.private_key.unwrap().decrypt(&c);
            assert_eq!(message, m); 
        }
        


    }

    #[test]
    pub fn test_apply_update_path() {
        // We want to test that a new member can get an update path message and successfully update their tree
        let mut rng: OsRng = OsRng;
        let message: [u8; 32] = [5; 32];
        let mut member = Member::new(String::from("Alice"));
        let mut member2 = Member::new(String::from("Bob"));
        let group_name = String::from("anonymous");

        // First generate a member, group, and a tree
        member.create_group(4, String::from("anonymous"), 1);
        member.add_to_group(String::from("anonymous"));
        // Get serialized tree, create new member, and add new member to group with ratchet tree
        {
            let welcome_message= member.send_welcome_message(member2.credential.clone(), group_name.clone());
            let path_update_message = member2.join_group(welcome_message);
            // The current member applies the update and we check if both can successfully encrypt and decrypt to eachother
            member.apply_update_path(path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), member2.id.unwrap());
            // We want to test that both Alice and Bob have the same view of the ratchet tree
            // In this scenario, Alice and Bob occupy two leaf nodes of the tree with an id of 4 and 5.  After Bob has joined,
            // and shared his path updates with Alice, they should both have the same root key material
        
            let alice_group = member.groups.get_mut("anonymous").unwrap();
            let alice_tree = &mut alice_group.ratchet_tree;
            let bob_group = member2.groups.get_mut("anonymous").unwrap();
            let bob_tree = &mut bob_group.ratchet_tree;
            let (c, _new_pk) = alice_tree.get_node_by_id(alice_tree.height, 1).unwrap().public_key.unwrap().encrypt(message, &mut rng);
            let (m, _new_sk) = bob_tree.get_node_by_id(bob_tree.height, 1).unwrap().private_key.unwrap().decrypt(&c);
            assert_eq!(message, m);
            // Let's check the keys of their direct ancestor.  They should be able to each encrypt and decrypt with them
            let (c, _new_pk) = alice_tree.get_node_by_id(alice_tree.height, 2).unwrap().public_key.unwrap().encrypt(message, &mut rng);
            let (m, _new_sk) = bob_tree.get_node_by_id(bob_tree.height, 2).unwrap().private_key.unwrap().decrypt(&c);
            assert_eq!(message, m);
            // update should also contain information about the joining node itself so it can be added to the tree of other members
            // the recently joined member should occupy node 5 but nodes 6 and 7 and their ancestor 3 should be empty
            assert!(alice_tree.get_node_by_id(alice_tree.height, 5).unwrap().public_key.is_some());
            assert!(alice_tree.get_node_by_id(alice_tree.height, 5).unwrap().credential.is_some());
            assert_eq!(alice_tree.get_node_by_id(alice_tree.height, 5).unwrap().credential.as_mut().unwrap().pseudonym, String::from("Bob"));
            assert!(alice_tree.get_node_by_id(alice_tree.height, 6).unwrap().public_key.is_none());
            assert!(alice_tree.get_node_by_id(alice_tree.height, 7).unwrap().public_key.is_none());
            assert!(alice_tree.get_node_by_id(alice_tree.height, 3).unwrap().public_key.is_none());
        }
        // Lets try this with more members
        let mut member3 = Member::new(String::from("Mike"));
        let welcome_message= member2.send_welcome_message(member3.credential.clone(), group_name.clone());
        let path_update_message = member3.join_group(welcome_message);
        member.apply_update_path(path_update_message.ciphertext.clone(), path_update_message.nonce, group_name.clone(),member3.id.unwrap());
        member2.apply_update_path(path_update_message.ciphertext, path_update_message.nonce, group_name.clone(),member3.id.unwrap());
        let mike_group = member3.groups.get_mut("anonymous").unwrap();
        let mike_tree = &mut mike_group.ratchet_tree;
        let alice_group = member.groups.get_mut("anonymous").unwrap();
        let alice_tree = &mut alice_group.ratchet_tree;
        let bob_group = member2.groups.get_mut("anonymous").unwrap();
        let bob_tree = &mut bob_group.ratchet_tree;
        // Lets check that Mike has the correct credentials for everyone.  lets check alice has Mike's credentials
        assert_eq!(mike_tree.get_node_by_id(mike_tree.height, 4).unwrap().credential.as_mut().unwrap().pseudonym, String::from("Alice"));
        assert_eq!(mike_tree.get_node_by_id(mike_tree.height, 5).unwrap().credential.as_mut().unwrap().pseudonym, String::from("Bob"));
        assert_eq!(alice_tree.get_node_by_id(mike_tree.height, 6).unwrap().credential.as_mut().unwrap().pseudonym, String::from("Mike"));




        // Lets check that the root key material is the same for newly added Mike and the rest of the members
        let (c, _new_pk) = alice_tree.get_node_by_id(alice_tree.height, 1).unwrap().public_key.unwrap().encrypt(message, &mut rng);
        let (m, _new_sk) = mike_tree.get_node_by_id(mike_tree.height, 1).unwrap().private_key.unwrap().decrypt(&c);
        assert_eq!(message, m);
        let (m, _new_sk) = bob_tree.get_node_by_id(bob_tree.height, 1).unwrap().private_key.unwrap().decrypt(&c);
        assert_eq!(message, m);
        // Let's check that Mike is populated in Alice and Bob's trees
        assert!(alice_tree.get_node_by_id(alice_tree.height, 6).unwrap().public_key.is_some());
        assert!(bob_tree.get_node_by_id(bob_tree.height, 6).unwrap().public_key.is_some());
        // Let's also check that Alice and Bob don't know the secret key to Mike's direct ancestor.  They aren't in the same subtrees
        // This would be node 3 but they do know the public key
        assert!(alice_tree.get_node_by_id(alice_tree.height, 3).unwrap().public_key.is_some());
        assert!(alice_tree.get_node_by_id(alice_tree.height, 3).unwrap().private_key.is_none());
        assert!(bob_tree.get_node_by_id(bob_tree.height, 3).unwrap().public_key.is_some());
        assert!(bob_tree.get_node_by_id(bob_tree.height, 3).unwrap().private_key.is_none());
        // Let's test that Alice and Bob have the same admin information
        assert_eq!(alice_group.threshold, 1);
        assert_eq!(bob_group.threshold, 1);
        assert_eq!(bob_group.admins.len(), 1);
        assert_eq!(bob_group.admins.pop().unwrap(), 4);
        assert_eq!(alice_group.admins.len(), 1);
        assert_eq!(alice_group.admins.pop().unwrap(), 4);


    }

    #[test]
    // We want to test that a node can refresh their keys along with ancestors keys to generate new key material
    pub fn test_key_refresh() {
        let message = String::from("Hello to the group!").into_bytes();
        let mut member = Member::new(String::from("Alice"));
        let mut member2 = Member::new(String::from("Bob"));
        let group_name = String::from("anonymous");
        let mut ciphertext: Vec<u8>;
        let mut nonce: GenericArray<u8, U12>;
        let alice_public_key: [u8;32];
        let mut message_counter: u16;
        

        // First generate a member, group, and a tree
        member.create_group(4, String::from("anonymous"), 1);
        member.add_to_group(String::from("anonymous"));
        // Get serialized tree, create new member, and add new member to group with ratchet tree
        {
            let welcome_message= member.send_welcome_message(member2.credential.clone(), group_name.clone());
            let path_update_message = member2.join_group(welcome_message);
            // The current member applies the update and we check if both can successfully encrypt and decrypt to eachother
            member.apply_update_path(path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), member2.id.unwrap());
        }
        // Now let's test that they can correctly decrypt a message with the group key.  Let's also save Alice's old public key
        {
            (ciphertext, nonce, message_counter) = member.encrypt_application_message(message.clone(), group_name.clone());
            let plaintext = member2.decrypt_application_message(ciphertext.clone(), group_name.clone(), nonce, message_counter);
            let alice_group = member.groups.get_mut("anonymous").unwrap();
            let alice_tree = &mut alice_group.ratchet_tree;
            alice_public_key = alice_tree.get_node_by_id(alice_tree.height, member.id.unwrap()).unwrap().public_key.unwrap().to_bytes();
            assert_eq!(message, plaintext);
        }
        // Now lets update the keys of member ("Alice") we should see that the group secret is different as well as Alice's keys since she updated
        // her own material and her ancestors all the way to the root
        {
            let path_update_message = member.key_refresh(String::from("anonymous"), member.id.unwrap(), member.pseudonym.clone());
            member2.apply_update_path(path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), member.id.unwrap());
            // Lets test to make sure there is valid new key material for the ratchet tree
            // The new group secret should fail to decrypt the previously encrypted material
            let plaintext = member2.decrypt_application_message(ciphertext.clone(), group_name.clone(), nonce, message_counter);
            assert_ne!(message, plaintext);
            // Alice's old public key should not be the same as her new one
            let alice_group = member.groups.get_mut("anonymous").unwrap();
            let alice_tree = &mut alice_group.ratchet_tree;
            assert_ne!(alice_public_key, alice_tree.get_node_by_id(alice_tree.height, member.id.unwrap()).unwrap().public_key.unwrap().to_bytes());
            // The synchronized members should have a correct view of the tree
            (ciphertext, nonce, message_counter) = member.encrypt_application_message(message.clone(), group_name.clone());
            let plaintext = member2.decrypt_application_message(ciphertext.clone(), group_name.clone(), nonce, message_counter);
            assert_eq!(message, plaintext);
        }



    }

    #[test]
    pub fn test_encrypt_application_message() {
        // We want to generate a message using group symmetric key
        let mut member = Member::new(String::from("Alice"));
        member.create_group(2, String::from("anonymous"), 1);
        member.add_to_group(String::from("anonymous"));
        let message = String::from("Hello to the group!").into_bytes();
        let (ciphertext, nonce, message_counter) = member.encrypt_application_message(message, String::from("anonymous"));     
        // Test that the message can be decrypted using the group symmetric key
        let group = member.groups.get_mut("anonymous").unwrap();
        let tree = &mut group.ratchet_tree;
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        let group_symmetric_key = SymmetricKey::derive_message_key(root.node_secret.as_mut().unwrap().to_vec(), message_counter);
        let plaintext = SymmetricKey::decrypt(ciphertext, group_symmetric_key, nonce);
        assert_eq!(String::from("Hello to the group!").as_bytes(), plaintext);
    }

    #[test]
    pub fn test_decrypt_application_message() {
        // We want to generate the group key and encrypt a message
        let mut member = Member::new(String::from("Bob"));
        member.create_group(2, String::from("anonymous"), 1);
        member.add_to_group(String::from("anonymous"));
        let mut message = b"Hello to the group!".to_vec();
        let group = member.groups.get_mut("anonymous").unwrap();
        let tree = &mut group.ratchet_tree;
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        let group_symmetric_key = SymmetricKey::derive_message_key(root.node_secret.as_mut().unwrap().to_vec(), 1);
        let (ciphertext, nonce) = SymmetricKey::encrypt(&mut message, group_symmetric_key);
        let plaintext = member.decrypt_application_message(ciphertext, String::from("anonymous"), nonce, 1);
        assert_eq!(message, plaintext);
    }

    #[test]
    pub fn test_join_group() {
        // We want to create a group and add the founding member.  Then add another member and test that the group state is updated for the joining member and is correct
        let mut member = Member::new(String::from("Bob"));
        let mut member2 = Member::new(String::from("Alice"));
        member.create_group(2, String::from("anonymous"), 1);
        member.add_to_group(String::from("anonymous"));
        let group_name = String::from("anonymous");
        {
            let welcome_message= member.send_welcome_message(member2.credential.clone(), group_name.clone());
            let _path_update_message = member2.join_group(welcome_message);
        }
        // Test that there are two members there.  We should also add pseudonymns to the node info
        let alice_group = member2.groups.get_mut("anonymous").unwrap();
        let alice_tree = &mut alice_group.ratchet_tree;
        assert_eq!(alice_tree.get_leaves(alice_tree.height).len(), 2);
        // Test that bobs key material is in Alice's tree
        assert!(alice_tree.get_node_by_id(alice_tree.height, 2).unwrap().public_key.is_some());
        // Test that alice key material is in Alice's tree
        assert!(alice_tree.get_node_by_id(alice_tree.height, 3).unwrap().public_key.is_some());
        // Test that the root key material is in Alice's tree
        assert!(alice_tree.get_node_by_id(alice_tree.height, 1).unwrap().public_key.is_some());
        // Test that Bobs original key material is correct in Alice's tree
        let message: [u8;32] = [5; 32];
        let mut rng: OsRng = OsRng;
        let bob_group = member.groups.get_mut("anonymous").unwrap();
        let bob_tree = &mut bob_group.ratchet_tree;
        let (c, _new_pk) = alice_tree.get_node_by_id(alice_tree.height, 2).unwrap().public_key.unwrap().encrypt(message, &mut rng);
        let (m, _new_sk) = bob_tree.get_node_by_id(alice_tree.height, 2).unwrap().private_key.unwrap().decrypt(&c);
        assert_eq!(message, m);
        // Test that Bob's tree doesn't yet have Alice's key info.  It needs to be shared after Alice adds herself to the tree.  Bob should still have his
        // own key material however
        assert!(bob_tree.get_node_by_id(bob_tree.height, 3).unwrap().public_key.is_none());
        assert!(bob_tree.get_node_by_id(bob_tree.height, 2).unwrap().public_key.is_some());
        // Test that Bob has correct info about the admins
        assert_eq!(bob_group.admins.len(), 1);
        assert_eq!(bob_group.admins[0], 2);
        assert_eq!(bob_group.threshold, 1);




    }

    
    

}