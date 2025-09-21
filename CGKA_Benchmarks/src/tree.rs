extern crate alloc;
extern crate std;


use std::collections::HashMap;


use alloc::{boxed::Box, vec::Vec};
use crate::upke::{ PublicKey as UPKEPub, SecretKey as UPKEPriv};
use crate::member::Credentials;

/// Stores  member data in the ratchet tree
#[derive(Clone)]
pub struct Node {
    pub id: u16,
    pub left: Option<Box<Node>>,
    pub right: Option<Box<Node>>,
    pub public_key: Option<UPKEPub>,
    pub private_key: Option<UPKEPriv>,
    pub node_secret: Option<Vec<u8>>,
    pub credential: Option<Credentials>

}

/// Underlying data structure for the ratchet tree
#[derive(Clone)]
pub struct BinaryTree {
    pub root: Option<Box<Node>>,
    pub members: u16,
    pub capacity: u16,
    pub height: u16,
}

impl Node {
    /// Every node has a unique id with the root starting at 1.  Nodes hold UPKE material as well as the node secret
    fn create(id: u16) -> Self {
        // let rand_num = rand::thread_rng().gen_range(0, 100);
        let node = Node {
            id: id,
            left: None,
            right: None,
            public_key: None,
            private_key: None,
            node_secret: None,
            credential: None,
        };
        return node;
    }
}

impl BinaryTree {
    /// Generates a balanced binary tree with a 'capacity' number of leaves
    pub fn generate(capacity: u16) -> Self {
        let height = (capacity as f64).log2() as u16 + 1;
        let root_id = 1; 
        let mut tree = BinaryTree {
            root: None,
            members: 0,
            capacity: capacity,
            height: height,
        };
        tree.root = tree.populate_tree(height, root_id);
        // tree.print_tree();
        tree
    }

    /// Helper function to generate a tree with the 'capacity' number of leaf nodes
    pub fn populate_tree(&mut self, height: u16, root_id: u16) -> Option<Box<Node>> {
        if height > 0 {
            let mut node = Box::new(Node::create(root_id));
            if height > 1 {
                let left_id = 2 * root_id;
                let right_id = 2 * root_id + 1;
                node.left = self.populate_tree(height - 1, left_id);
                node.right = self.populate_tree(height - 1, right_id);
            }
            Some(node)
        } else {
            None
        }
    }

    /// Returns a vector of leaf nodes.  Enables you to determine who are the members of the tree
    pub fn get_leaves(&mut self, height: u16) -> Vec<&Box<Node>> {
        let mut leaves: Vec<&Box<Node>> = Vec::new();
        let root = self.get_root();
        BinaryTree::get_leaves_helper(root, height, &mut leaves);
        return leaves;
    }

    /// Determine leaf node by traversing each level of the tree
    pub fn get_leaves_helper<'a>(current_node: &'a Option<Box<Node>>, height: u16, leaves: &mut Vec<&'a Box<Node>>) {
        let node: &Box<Node> = current_node.as_ref().unwrap();
        if height > 1 {
            BinaryTree::get_leaves_helper(&node.left, height - 1, leaves);
            BinaryTree::get_leaves_helper(&node.right, height - 1, leaves);
        } else {
            leaves.push(node);
        }
    }

    /// Returns the neighbor of a node given a specific node id.  Useful for creating the update path
    pub fn get_neighbor(&mut self, height: u16, id: u16) -> Option<&Box<Node>> {
        if let Some(root) = &self.root {
            return BinaryTree::get_neighbor_helper(root, height, id);
        }
        None
    }

    /// Helper for get_neighbor function
    pub fn get_neighbor_helper(current_node: &Box<Node>, height: u16, id: u16) -> Option<&Box<Node>>{
        if height > 1 {
            let node = current_node.as_ref();
            if node.left.as_ref().unwrap().id == id {
                return node.right.as_ref();
            } else if node.right.as_ref().unwrap().id == id {
                return node.left.as_ref();
            } else {
                if let Some(found_left) = BinaryTree::get_neighbor_helper(&node.left.as_ref().unwrap(), height - 1, id) {
                    return Some(&found_left);
                }
                if let Some(found_right) = BinaryTree::get_neighbor_helper(&node.right.as_ref().unwrap(), height - 1, id) {
                    return Some(&found_right);
                }
            }
        }
        None
    }

    pub fn get_ancestor_ids(&mut self, id: u16) -> Vec<u16>{
        let nodes = self.get_ancestors(self.height, id);
        let mut ancestors= Vec::new();
        for x in nodes {
            ancestors.push(x.id);
        }
        return ancestors;
    }

    /// Returns the nodes to encrypt remove message under
    pub fn get_blank_node_path(&mut self, height: u16, id: u16, ancestors: Vec<u16>) -> Vec<&Box<Node>> {
        let mut blank_path: Vec<&Box<Node>> = Vec::new();
        let root = self.get_root();
        // pass in the ancestors of the nodes to be removed
        BinaryTree::get_blank_node_path_helper(root, height, id, &mut blank_path, &ancestors);
        return blank_path;
    }

    pub fn get_blank_node_path_helper<'a>(current_node: &'a Option<Box<Node>>, height: u16, id: u16, blank_path: &mut Vec<&'a Box<Node>>, ancestors: &Vec<u16>) -> bool {
        let node: &Box<Node> = current_node.as_ref().unwrap();
        let node_id = node.id;
        if !ancestors.contains(&node_id) {
                if node.id != id {
                    blank_path.push(node);
                    return true;
                }
        }
        if height > 1 {
            let found_in_left = BinaryTree::get_blank_node_path_helper(&node.left, height - 1, id, blank_path, ancestors);
            let found_in_right = BinaryTree::get_blank_node_path_helper(&node.right, height - 1, id, blank_path, ancestors);

            if found_in_left{
                // If a valid node is found in any subtree, return true
                return true;
            }

            if found_in_right {
                return true;
            }
        }
        false

    }

    /// Returns all nodes on the direct path to the root including the root.  Useful for creating the update path
    pub fn get_ancestors(&mut self, height: u16, id: u16) -> Vec<&Box<Node>> {
        let mut ancestors: Vec<&Box<Node>> = Vec::new();
        let root = self.get_root();
        BinaryTree::get_ancestors_helper(root, height, id, &mut ancestors);
        return ancestors;
        
    }

    /// Get ancestors helper
    pub fn get_ancestors_helper<'a>(current_node: &'a Option<Box<Node>>, height: u16, id: u16, ancestors: &mut Vec<&'a Box<Node>>) -> bool {
        let node: &Box<Node> = current_node.as_ref().unwrap();
        if node.id == id {
            return true;
        }
        if height > 1 {
            if BinaryTree::get_ancestors_helper(&node.left, height - 1, id, ancestors){
                ancestors.push(node);
                return true;
            }

            if BinaryTree::get_ancestors_helper(&node.right, height - 1, id, ancestors) {
                ancestors.push(node);
                return true;
            }
        }
        return false;
    }

    /// Returns node based on it's id in the tree
    pub fn get_node_by_id(&mut self, height: u16, id: u16) -> Option<&mut Node> {
        // need a mutable reference to the pointer so we can update nodes in the tree
        if let Some(root) = &mut self.root {
            return BinaryTree::get_node_by_id_helper(root.as_mut(), height, id);
        }
        None
    }

    /// Helper function to return node based on id
    pub fn get_node_by_id_helper(current_node: &mut Node, height: u16, id: u16) -> Option<&mut Node>{
        let node = current_node;
        if height == 1 && node.id == id {
            return Some(node);
        }
        else if  height > 1 {
            if node.id == id {
                return Some(node);
            } else {
                if let Some(found_node) = BinaryTree::get_node_by_id_helper(node.left.as_mut().unwrap(), height - 1, id) {
                    return Some(found_node);
                }
                if let Some(found_node) = BinaryTree::get_node_by_id_helper(node.right.as_mut().unwrap(), height - 1, id) {
                    return Some(found_node);
                }
            }
        }
        None
    }

    /// Returns the open leaf that can be used to store a joining member
    pub fn get_leftmost_open_leaf(&mut self, height: u16) -> Option<u16>{
        let leaves = self.get_leaves(height);
        let mut ids: Vec<u16> = Vec::new();
        for x in leaves {
            ids.push(x.id);
        }
        // let minValue = ids.iter().min();
        // match minValue {
        //     Some(min) => Some(*min),
        //     None      => None,
        // }
        while ids.len() > 0 {
            let minimum = ids.iter().min().unwrap();
            let de_ref_minimum = *minimum;
            if self.get_node_by_id(self.height, *minimum).unwrap().public_key.is_none() {
                return Some(*minimum);
            } else {
                ids.retain(|value| *value != de_ref_minimum);

            }
        }
        None
    }

    /// To allow members to join, the tree needs to be shared.  This function returns the public and private key material as individual maps with the id of the node as the key
    pub fn serialize_tree(&mut self, _initiating_id: u16, ancestors: &Vec<u16>, neighbor_ancestors: &Vec<u16>)  -> (HashMap<u16, [u8; 32]>, HashMap<u16, [u8; 32]>, HashMap<u16, Credentials>){
        let mut nodes_public_material:HashMap<u16, [u8; 32]> = HashMap::new();
        let mut nodes_private_material:HashMap<u16,[u8; 32]> = HashMap::new();
        let mut nodes_credentials: HashMap<u16, Credentials> = HashMap::new();
        let height = self.height;
        let root = self.get_root();
        BinaryTree::serialize_tree_helper(root, height, &mut nodes_public_material, &mut nodes_private_material, &mut nodes_credentials, ancestors, neighbor_ancestors);
        return (nodes_public_material, nodes_private_material, nodes_credentials)
    }

    /// Helper function for serialization
    pub fn serialize_tree_helper(current_node: &Option<Box<Node>>, height: u16, public_material: &mut HashMap< u16, [u8; 32]>, private_material: &mut HashMap< u16, [u8; 32]>, credentials: &mut HashMap<u16, Credentials>, ancestors: &Vec<u16>, neighbor_ancestors: &Vec<u16>) {
        let node: &Box<Node> = current_node.as_ref().unwrap();
        if node.public_key.is_some() {
                let pk = node.public_key.unwrap().to_bytes();
                public_material.insert(node.id, pk);
                // only leaf nodes have credentials
                if let Some(_cred) = node.credential.clone() {
                    let cred = node.credential.clone().unwrap();
                    credentials.insert(node.id, cred);
                }
                // the secret key may not be known or desired to be shared
                if let Some(_sk) = node.private_key {
                    if ancestors.contains(&node.id) && neighbor_ancestors.contains(&node.id) {
                        let sk = node.private_key.unwrap().to_bytes();
                        private_material.insert(node.id, sk);
                    }
                }
        }
        if height > 1 {
            // We need to check this isn't a reference to the keys.  We don't want to be able to change them in two places
                BinaryTree::serialize_tree_helper(&node.left, height -1 , public_material, private_material, credentials, ancestors, neighbor_ancestors);
                BinaryTree::serialize_tree_helper(&node.right, height -1 , public_material, private_material, credentials, ancestors, neighbor_ancestors);     
        }
    }

    /// Given a tree capacity and the serialized tree contents, a joining member can generate a current view of the tree
    pub fn deserialize_tree(public_material: &mut HashMap< u16, [u8; 32]>, private_material: &mut HashMap< u16, [u8; 32]>, credentials: &mut HashMap<u16, Credentials>, capacity: u16) -> BinaryTree{
        let mut tree = BinaryTree::generate(capacity);
        for (id, public_key) in public_material.into_iter() {
            let node = tree.get_node_by_id(tree.height, *id);
            node.unwrap().public_key = Some(UPKEPub::from_bytes_mod_order(*public_key));
        }
        for (id, credential) in credentials.into_iter() {
            let node = tree.get_node_by_id(tree.height, *id);
            node.unwrap().credential = Some(credential.clone());
        }
        for (id, private_key) in private_material.into_iter() {
            let node = tree.get_node_by_id(tree.height, *id);
            node.unwrap().private_key = Some(UPKEPriv::from_bytes_mod_order(*private_key));
        }
        return tree;
    }

    pub fn get_all_nodes(&mut self, height: u16) -> Vec<u16>{
        let mut nodes: Vec<u16> = Vec::new();
        let root = self.get_root();
        BinaryTree::get_all_nodes_helper(root, height, &mut nodes);
        nodes

    }

    pub fn get_all_nodes_helper (current_node: &Option<Box<Node>>, height: u16, nodes: &mut Vec<u16>) {
        let node: &Box<Node> = current_node.as_ref().unwrap();
        nodes.push(node.id);
        if height > 1 {
            BinaryTree::get_all_nodes_helper(&node.left, height - 1, nodes);
            BinaryTree::get_all_nodes_helper(&node.right, height - 1, nodes);
        }
    }


    // fn print_tree(&self) {
    //     self.print_ascii(&self.root, 0);
    // }

    // // Recursive function to print the tree as ASCII art
    // fn print_ascii(&self, node: &Option<Box<Node>>, depth: usize) {
    //     if let Some(n) = node {
    //         self.print_ascii(&n.right, depth + 1);
    //         println!("{:width$}{}", "", n.id, width = depth * 4);
    //         self.print_ascii(&n.left, depth + 1);
    //     }
    // }

    /// Returns root of the tree
    pub fn get_root(&mut self) -> &Option<Box<Node>> {
        if let Some(_root) = &self.root {
            return &self.root;
        }
        &None
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;
    use rand_core::OsRng;

    use crate::upke::{SecretKey, UPKEMaterial};

    use super::BinaryTree;


    #[test]
    pub fn test_tree_generation() {
        // capacity needs to be a fully complete tree.  For example, 2,4,8... and so on
        // to print out the tree visually run cargo test -- --nocapture
        let capacity = 128;
        let mut tree = BinaryTree::generate(capacity);
        let leaves = tree.get_leaves(tree.height);
        assert_eq!(leaves.len(), 128);

        //Lets try a smaller tree with a capacity of 32
        let new_capacity: u16 = 32;
        let tree_2 = BinaryTree::generate(new_capacity);
        let leaves_2 = tree.get_leaves(tree_2.height);
        assert_eq!(leaves_2.len(), 32);
    }

    #[test]
    pub fn test_get_root() {
        //We want to test returning the node at the root.  The id of the root node should be 1
        let capacity = 4;
        let mut tree = BinaryTree::generate(capacity);
        let root = tree.get_root().as_ref().unwrap();
        let root_id = root.id;
        assert_eq!(root_id, 1);
        // We want to test with a higher capacity tree
        let new_capacity: u16 = 128;
        let mut tree_2 = BinaryTree::generate(new_capacity);
        let root_2 = tree_2.get_root().as_ref().unwrap();
        assert_eq!(root_2.id, 1);
    }

    #[test] 
    pub fn test_get_all_nodes() {
        // We want to be able to gather all the node ids in a particular tree so we can access each node
        {
            let capacity = 4;
            let mut tree = BinaryTree::generate(capacity);
            let all_nodes = tree.get_all_nodes(tree.height);
            assert_eq!(all_nodes.len(), 7);
        }
        {
            let capacity = 8;
            let mut tree = BinaryTree::generate(capacity);
            let all_nodes = tree.get_all_nodes(tree.height);
            assert_eq!(all_nodes, [1,2,4,8,9,5,10,11,3,6,12,13,7,14,15]);
        }


    }

    #[test]
    pub fn test_get_leaves() {
        let capacity = 4;
        let mut tree = BinaryTree::generate(capacity);
        let height = tree.height;
        let leaves = tree.get_leaves(height);
        let mut ids_compare = Vec::new();
        // generate the test ids
        ids_compare.push(4);
        ids_compare.push(5);
        ids_compare.push(6);
        ids_compare.push(7);
        let mut ids: Vec<u16> = Vec::new();
        for x in leaves {
            ids.push(x.id);
        }
        assert_eq!(ids, ids_compare);

        // We want to test with a bigger tree.  Should return 128 leaves or members of the tree
        let new_capacity = 128;
        let mut new_tree = BinaryTree::generate(new_capacity);
        let leaves = new_tree.get_leaves(new_tree.height);
        assert_eq!(leaves.len(), 128);
    }

    #[test]
    pub fn test_get_neighbor() {
        let capacity = 8;
        let mut tree = BinaryTree::generate(capacity);
        let height = tree.height;
        let neighbor = tree.get_neighbor(height, 6);
        assert_eq!(neighbor.as_ref().unwrap().id, 7);

        // We want to test with a bigger tree
        let new_capacity = 16;
        let mut new_tree = BinaryTree::generate(new_capacity);
        let neighbor = new_tree.get_neighbor(new_tree.height, 17);
        assert_eq!(neighbor.as_ref().unwrap().id, 16);
    }

    #[test]
    pub fn test_get_blank_node_path() {
        { 
            let capacity = 2;
            let mut tree = BinaryTree::generate(capacity);
            let ancestors = tree.get_ancestor_ids(3);
            let blank_node_path = tree.get_blank_node_path(tree.height, 3, ancestors.clone());
            let mut blank_node_ids = Vec::new();
            for x in blank_node_path {
                blank_node_ids.push(x.id);
            }
            assert!(ancestors.clone().contains(&1));
            assert_eq!(ancestors.clone().len(), 1);
            assert_eq!(blank_node_ids.len(), 1);
            assert_eq!(blank_node_ids[0], 2);
        }

        // lets try with a bigger tree
        { 
            let capacity = 4;
            let mut tree = BinaryTree::generate(capacity);
            let ancestors = tree.get_ancestor_ids(6);
            let blank_node_path = tree.get_blank_node_path(tree.height, 6, ancestors.clone());
            let mut blank_node_ids = Vec::new();
            for x in blank_node_path {
                blank_node_ids.push(x.id);
            }
            assert_eq!(blank_node_ids.len(), 2);
            assert_eq!(blank_node_ids[0], 2);
            assert_eq!(blank_node_ids[1], 7);
        }
        // test with even bigger tree
        { 
            let capacity = 8;
            let mut tree = BinaryTree::generate(capacity);
            let ancestors = tree.get_ancestor_ids(15);
            let blank_node_path = tree.get_blank_node_path(tree.height, 15, ancestors.clone());
            let mut blank_node_ids = Vec::new();
            for x in blank_node_path {
                blank_node_ids.push(x.id);
            }
            assert_eq!(blank_node_ids.len(), 3);
            assert_eq!(blank_node_ids[0], 2);
            assert_eq!(blank_node_ids[1], 6);
            assert_eq!(blank_node_ids[2], 14);
        }
    }

    #[test]
    pub fn test_get_ancestors() {
        let capacity = 8;
        let mut tree = BinaryTree::generate(capacity);
        let height = tree.height;
        let ancestors = tree.get_ancestors(height, 8);
        let mut ids_compare = Vec::new();
        let mut ids= Vec::new();

        // generate the test ids
        ids_compare.push(4);
        ids_compare.push(2);
        ids_compare.push(1);
        for x in ancestors {
            ids.push(x.id);
        }
        assert_eq!(ids, ids_compare);

        // We want to try with a bigger tree
        let new_capacity = 16;
        let mut new_tree = BinaryTree::generate(new_capacity);
        let new_height = new_tree.height;
        let new_ancestors = new_tree.get_ancestors(new_height, 19);
        let mut new_ids_compare = Vec::new();
        let mut new_ids= Vec::new();

        // generate the test ids
        new_ids_compare.push(9);
        new_ids_compare.push(4);
        new_ids_compare.push(2);
        new_ids_compare.push(1);
        for x in new_ancestors {
            new_ids.push(x.id);
        }
        assert_eq!(new_ids, new_ids_compare);
    }

    #[test]
    pub fn test_get_node_by_id() {
        // Root node id starts at 1
        let capacity = 4;
        let mut tree = BinaryTree::generate(capacity);
        let id = 7;
        let node = tree.get_node_by_id(tree.height, id).unwrap();
        assert_eq!(node.id, id);
        // Test that if we update the node, the update is reflected in the tree.
        node.id = 42;
        let node = tree.get_node_by_id(tree.height, 42).unwrap();
        assert_eq!(node.id, 42);
    }

    #[test]
    pub fn test_get_leftmost_open_leaf() {
        // Leftmost node with root id starting at one and capacity of 4 leaves should be 4
        let capacity = 4;
        let mut tree = BinaryTree::generate(capacity);
        let x = tree.get_leftmost_open_leaf(tree.height).unwrap();
        assert_eq!(x, 4);

        let upke_material = UPKEMaterial::generate();
        let node = tree.get_node_by_id(tree.height, x).unwrap();
        node.public_key = Some(upke_material.public_key);
        // Now the leftmost leaf should return 5 since 4 is populated
        let y = tree.get_leftmost_open_leaf(tree.height).unwrap();
        assert_eq!(y, 5);
    }

    #[test]
    pub fn test_serialize_tree() {
        let mut rng: OsRng = OsRng;

        // We want to test that the tree serialization function returns key material in each node according to the correct id
        // This function will help create a very simple delivery service so we can share the ratchet tree with other members
        let capacity = 2;
        let initiating_id: u16 = 2;
        let mut ancestors:Vec<u16> = Vec::new();
        ancestors.push(1);
        let mut neighbor_ancestors:Vec<u16> = Vec::new();
        neighbor_ancestors.push(1);
        let mut tree = BinaryTree::generate(capacity);
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        let upke_material = UPKEMaterial::generate();
        let message: [u8;32] = [5;32];
        let node2_public_key = Some(upke_material.public_key);
        let node2_private_key = Some(upke_material.private_key);
        root.public_key = node2_public_key;
        root.private_key = node2_private_key;
        let (c, _newpk) =  node2_public_key.unwrap().encrypt(message, &mut rng);
        let mut tree_serialization = tree.serialize_tree(initiating_id, &ancestors, &neighbor_ancestors);
        assert_eq!(tree_serialization.0.len(), 1);
        // the key of the node should be an of 2 and the key material should work
        let private_key = tree_serialization.1.get_mut(&1);
        let retrieved_private_key = SecretKey::from_bytes_mod_order(*private_key.unwrap());
        let (m, _new_sk) = retrieved_private_key.decrypt(&c);
        assert_eq!(message, m);
        // now lets test that the recursion isn't missing the root node
        // let capacity = 2;
        // let mut tree2 = BinaryTree::generate(capacity);
        // let node2: &mut Node;
        // {
        //     let node_material = UPKEMaterial::generate();
        //     node2 = tree2.get_node_by_id(tree2.height, 2).unwrap();
        //     node2.public_key = Some(node_material.public_key);

        // }
        // let initiating_id: u16 = 1;
        // let mut ancestors:Vec<u16> = Vec::new();
        // ancestors.push(0);
        // let mut neighbor_ancestors:Vec<u16> = Vec::new();
        // neighbor_ancestors.push(0);
        // let root = tree2.get_node_by_id(tree2.height, 1).unwrap();
        // let root_material = UPKEMaterial::generate();
        // root.public_key = Some(root_material.public_key);
        // let updated_tree_serialization = tree2.serialize_tree(initiating_id, &ancestors, &neighbor_ancestors);
        // assert_eq!(updated_tree_serialization.0.len(), 2);

        // add test to test the key is the correct id of the node
    }

    #[test]
    pub fn test_deserialize_function() {
        let mut rng: OsRng = OsRng;

        // We want to test that the tree deserialize generates the same tree for another node when they join.
        let capacity = 2;
        let initiating_id: u16 = 3;
        let mut ancestors:Vec<u16> = Vec::new();
        ancestors.push(1);
        let mut neighbor_ancestors:Vec<u16> = Vec::new();
        neighbor_ancestors.push(1);
        let mut tree = BinaryTree::generate(capacity);
        let root = tree.get_node_by_id(tree.height, 1).unwrap();
        let upke_material = UPKEMaterial::generate();
        let message: [u8;32] = [5;32];
        let node2_public_key = Some(upke_material.public_key);
        let node2_private_key = Some(upke_material.private_key);
        root.public_key = node2_public_key;
        root.private_key = node2_private_key;
        // We take the serialized tree and pass the output to the deserialize function.  
        let mut serialized_tree = tree.serialize_tree(initiating_id, &ancestors, &neighbor_ancestors);
        let mut tree2 = BinaryTree::deserialize_tree(&mut serialized_tree.0, &mut serialized_tree.1, &mut serialized_tree.2, 2);
        // Now we can check the trees are the same by looking at their parameters and key material
        assert_eq!(tree.capacity, tree2.capacity);
        assert_eq!(tree.height, tree2.height);
        assert_eq!(tree.get_leaves(tree.height).len(), tree.get_leaves(tree.height).len());
        // check that encrypting with the public key in tree can be decrypted with the secret key in tree2
        let (c, _new_pk) = upke_material.public_key.encrypt(message, &mut rng);
        let tree2_node = tree2.get_node_by_id(tree2.height, 1).unwrap();
        let (m, _new_sk) = tree2_node.private_key.unwrap().decrypt(&c);
        assert_eq!(message, m);

    }
}