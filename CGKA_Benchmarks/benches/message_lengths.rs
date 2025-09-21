extern crate alloc;

use alloc::string::String;

use dark_matter::member::Member;

fn setup_10() {
    let group_name = String::from("test");
    let size = 10;
    let group_capacity = 16;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[9].clone();
    let tmp2 = members[2].clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (_tmp_ciphertext, _tmp_nonce, _message_counter) = tmp1.encrypt_application_message(byte_vec, group_name.clone());
    println!("Group size of 10 -------------------------------");
    println!();

    //benchmarks go here
    add_to_group(&tmp1, &members, &mut alice, &group_name);
    remove_from_group(&members, &tmp1, &tmp2, &group_name);
    key_refresh(&members, &tmp1, &tmp2, &group_name);
    encrypt_group_message(&members, &tmp1, &group_name);
}

fn setup_25() {
    let group_name = String::from("test");
    let size = 25;
    let group_capacity = 32;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[24].clone();
    let tmp2 = members[10].clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (_tmp_ciphertext, _tmp_nonce, _message_counter) = tmp1.encrypt_application_message(byte_vec, group_name.clone());
    println!("Group size of 25 -------------------------------");
    println!();

    //benchmarks go here
    add_to_group(&tmp1, &members, &mut alice, &group_name);
    remove_from_group(&members, &tmp1, &tmp2, &group_name);
    key_refresh(&members, &tmp1, &tmp2, &group_name);
    encrypt_group_message(&members, &tmp1, &group_name);
}

fn setup_50() {
    let group_name = String::from("test");
    let size = 50;
    let group_capacity = 64;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[49].clone();
    let tmp2 = members[10].clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (_tmp_ciphertext, _tmp_nonce, _message_counter) = tmp1.encrypt_application_message(byte_vec, group_name.clone());
    println!("Group size of 50 -------------------------------");
    println!();

    //benchmarks go here
    add_to_group(&tmp1, &members, &mut alice, &group_name);
    remove_from_group(&members, &tmp1, &tmp2, &group_name);
    key_refresh(&members, &tmp1, &tmp2, &group_name);
    encrypt_group_message(&members, &tmp1, &group_name);
}

fn setup_75() {
    let group_name = String::from("test");
    let size = 75;
    let group_capacity = 128;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[74].clone();
    let tmp2 = members[10].clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (_tmp_ciphertext, _tmp_nonce, _message_counter) = tmp1.encrypt_application_message(byte_vec, group_name.clone());
    println!("Group size of 75 -------------------------------");
    println!();

    //benchmarks go here
    add_to_group(&tmp1, &members, &mut alice, &group_name);
    remove_from_group(&members, &tmp1, &tmp2, &group_name);
    key_refresh(&members, &tmp1, &tmp2, &group_name);
    encrypt_group_message(&members, &tmp1, &group_name);
}

fn setup_100() {
    let group_name = String::from("test");
    let size = 100;
    let group_capacity = 128;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[99].clone();
    let tmp2 = members[10].clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (_tmp_ciphertext, _tmp_nonce, _message_counter) = tmp1.encrypt_application_message(byte_vec, group_name.clone());
    println!("Group size of 100 -------------------------------");
    println!();

    add_to_group(&tmp1, &members, &mut alice, &group_name);
    remove_from_group(&members, &tmp1, &tmp2, &group_name);
    key_refresh(&members, &tmp1, &tmp2, &group_name);
    encrypt_group_message(&members, &tmp1, &group_name);
}

fn setup_125() {
    let group_name = String::from("test");
    let size = 125;
    let group_capacity = 128;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[124].clone();
    let tmp2 = members[10].clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (_tmp_ciphertext, _tmp_nonce, _message_counter) = tmp1.encrypt_application_message(byte_vec, group_name.clone());
    println!("Group size of 125 -------------------------------");
    println!();

    //benchmarks go here
    add_to_group(&tmp1, &members, &mut alice, &group_name);
    remove_from_group(&members, &tmp1, &tmp2, &group_name);
    key_refresh(&members, &tmp1, &tmp2, &group_name);
    encrypt_group_message(&members, &tmp1, &group_name);
}

fn setup_150() {
    let group_name = String::from("test");
    let size = 150;
    let group_capacity = 256;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[149].clone();
    let tmp2 = members[10].clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (_tmp_ciphertext, _tmp_nonce, _message_counter) = tmp1.encrypt_application_message(byte_vec, group_name.clone());
    println!("Group size of 150 -------------------------------");
    println!();

    //benchmarks go here
    add_to_group(&tmp1, &members, &mut alice, &group_name);
    remove_from_group(&members, &tmp1, &tmp2, &group_name);
    key_refresh(&members, &tmp1, &tmp2, &group_name);
    encrypt_group_message(&members, &tmp1, &group_name);
}

fn setup_175() {
    let group_name = String::from("test");
    let size = 175;
    let group_capacity = 256;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[174].clone();
    let tmp2 = members[10].clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (_tmp_ciphertext, _tmp_nonce, _message_counter) = tmp1.encrypt_application_message(byte_vec, group_name.clone());
    println!("Group size of 175 -------------------------------");
    println!();

    //benchmarks go here
    add_to_group(&tmp1, &members, &mut alice, &group_name);
    remove_from_group(&members, &tmp1, &tmp2, &group_name);
    key_refresh(&members, &tmp1, &tmp2, &group_name);
    encrypt_group_message(&members, &tmp1, &group_name);
}

fn setup_200() {
    let group_name = String::from("test");
    let size = 200;
    let group_capacity = 256;
    let members = Member::automate_group_creation(group_name.clone(), size, group_capacity);
    let mut alice = Member::new(String::from("alice"));
    let mut tmp1 = members[199].clone();
    let tmp2 = members[10].clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (_tmp_ciphertext, _tmp_nonce, _message_counter) = tmp1.encrypt_application_message(byte_vec, group_name.clone());
    println!("Group size of 200 -------------------------------");
    println!();

    add_to_group(&tmp1, &members, &mut alice, &group_name);
    remove_from_group(&members, &tmp1, &tmp2, &group_name);
    key_refresh(&members, &tmp1, &tmp2, &group_name);
    encrypt_group_message(&members, &tmp1, &group_name);
}  
    

fn add_to_group(initiating_member: &Member, _members: &Vec<Member>, alice: &mut Member, group_name: &String) {
    // Code to benchmark goes here
    println!("Benchmark: Add to group -------------------------------");
    let mut member = initiating_member.clone();
    let welcome_message= member.send_welcome_message(alice.credential.clone(), group_name.clone());
    println!("Welcome message length (bytes): {}", welcome_message.key.len() + welcome_message.update_message.ciphertext.len() + welcome_message.update_message.nonce.len());
    let path_update_message = alice.join_group(welcome_message);
    println!("Path update message length (bytes): {}", path_update_message.ciphertext.len() + path_update_message.nonce.len());
    member.apply_update_path( path_update_message.ciphertext, path_update_message.nonce, group_name.clone(), alice.id.unwrap());
    println!();

}

fn remove_from_group(members: &Vec<Member>, tmp1: &Member, tmp2: &Member, group_name: &String) {
    // Code to benchmark goes here
    println!("Benchmark: Remove from group -------------------------------");
    let mut initiating_member = tmp1.clone();
    let mut applying_member = tmp2.clone();
    let blank_message = initiating_member.blank_node(group_name.clone(), members[3].id.unwrap());
    println!("Path update message length (bytes): {}", blank_message.ciphertext.len() + blank_message.nonce.len());
    applying_member.apply_blank_message(group_name.clone(), blank_message);
    println!();

}
fn key_refresh(_members: &Vec<Member>, tmp1: &Member, tmp2: &Member, group_name: &String) {
    // Code to benchmark goes here
    println!("Benchmark: Key refresh -------------------------------");
    let mut initiating_member = tmp1.clone();
    let mut applying_member = tmp2.clone();
    let key_refresh_message = initiating_member.key_refresh(group_name.clone(), initiating_member.id.unwrap(), initiating_member.pseudonym.clone());
    println!("Path update message length (bytes): {}", key_refresh_message.ciphertext.len() + key_refresh_message.nonce.len());
    applying_member.apply_update_path( key_refresh_message.ciphertext, key_refresh_message.nonce, group_name.clone(), initiating_member.id.unwrap());
    println!();

}
fn encrypt_group_message(_members: &Vec<Member>, tmp1: &Member, group_name: &String) {
    // Code to benchmark goes here
    println!("Benchmark: Encrypt group message -------------------------------");
    let mut initiating_member = tmp1.clone();
    let byte_vec: Vec<u8> = (0..560).map(|i| (i % 128) as u8).collect();
    let (ciphertext, nonce, _message_counter) = initiating_member.encrypt_application_message(byte_vec, group_name.clone());
    println!("Message (bytes): {}", ciphertext.len() + nonce.len());
    println!();


}

fn main() {
    setup_10();
    setup_25();
    setup_50();
    setup_75();
    setup_100();
    setup_125();
    setup_150();
    setup_175();
    setup_200();
}



